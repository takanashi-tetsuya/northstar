use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use rand::Rng;
use sqlx::{PgPool, Postgres, Row, Transaction};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    time::Duration,
};
use uuid::Uuid;

mod bosh_transport;
mod offline_delivery;
mod presence_policy;

use self::bosh_transport::bind_bosh_transport_response_inner;
pub use self::bosh_transport::{
    acknowledge_bosh_transport_responses, release_bosh_transport_fences,
    renew_bosh_transport_fences,
};
#[cfg(test)]
use self::offline_delivery::{acknowledge_durable_deliveries, claim_offline_replay_page_retrying};
pub(crate) use self::offline_delivery::{
    acknowledge_durable_deliveries_observed, lock_recovery_replay_authorization,
    RecoveryReplayAuthorizationGuard,
};
pub use self::offline_delivery::{
    acknowledge_durable_delivery, acquire_offline_replay_lease, claim_offline_replay_page,
    fence_durable_socket_write, release_offline_replay_lease, release_untransferred_offline_claims,
    renew_offline_replay_before_send,
};
pub use self::presence_policy::pending_presence_replay_page_filtered;
#[cfg(test)]
use self::presence_policy::pending_presence_replay_page_in_transaction;
use self::presence_policy::{replay_policy_denies, replay_policy_snapshot};

const REPLAY_PAGE_SIZE: i64 = 64;
const CLAIM_LEASE_SECONDS: i64 = 60;
const BOSH_FENCE_MAX_AGE_SECONDS: i64 = 300;
// The resource owner outlives every page claim. If a process crashes after
// claiming a page, takeover cannot occur until those row claims are already
// eligible in the same pass; otherwise the replacement would observe an
// apparently empty queue and messages would wait for another login.
pub(crate) use crate::services::replay::OWNER_LEASE_SECONDS as REPLAY_OWNER_LEASE_SECONDS;

pub use crate::services::replay::{
    OfflineReplayBusyUntil, OfflineReplayLease, OfflineReplayLeaseAcquire, PendingPresenceCursor,
    PendingPresenceReplay, PendingPresenceReplayPage,
};

#[cfg(test)]
impl OfflineReplayLeaseAcquire {
    fn into_acquired(self) -> Option<OfflineReplayLease> {
        match self {
            Self::Acquired(lease) => Some(lease),
            Self::BusyUntil(_) => None,
        }
    }

    fn is_acquired(&self) -> bool {
        matches!(self, Self::Acquired(_))
    }
}

#[derive(Clone, Debug)]
pub struct ClaimedOfflineMessage {
    pub id: Uuid,
    pub sender_jid: String,
    pub stanza: String,
}

#[derive(Debug)]
pub struct ClaimedOfflinePage {
    pub claim_token: Uuid,
    pub messages: Vec<ClaimedOfflineMessage>,
}

#[derive(Debug)]
pub enum OfflineReplayPageOutcome {
    Claimed(ClaimedOfflinePage),
    Empty,
    PendingClaims,
    LeaseLost,
}

#[cfg(test)]
pub async fn pending_presence_replay_page(
    pool: &PgPool,
    recipient_id: Uuid,
    local_domain: &str,
    after: Option<&PendingPresenceCursor>,
) -> Result<Vec<PendingPresenceReplay>> {
    let mut transaction = pool.begin().await?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        .execute(&mut *transaction)
        .await?;
    let page = pending_presence_replay_page_in_transaction(
        &mut transaction,
        recipient_id,
        local_domain,
        after,
    )
    .await?;
    transaction.commit().await?;
    Ok(page)
}

#[cfg(test)]
struct ReplayClaimTestHook {
    snapshot_fixed: std::sync::Arc<tokio::sync::Barrier>,
    resume_after_competing_commit: std::sync::Arc<tokio::sync::Barrier>,
    fired: std::sync::atomic::AtomicBool,
    serialization_retries: std::sync::atomic::AtomicUsize,
}

#[cfg(test)]
impl ReplayClaimTestHook {
    async fn pause_once_after_snapshot(&self) {
        if !self.fired.swap(true, std::sync::atomic::Ordering::AcqRel) {
            self.snapshot_fixed.wait().await;
            self.resume_after_competing_commit.wait().await;
        }
    }
}

#[cfg(test)]
type ReplayClaimHookRef<'a> = Option<&'a ReplayClaimTestHook>;
#[cfg(not(test))]
type ReplayClaimHookRef<'a> = ();

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
async fn claim_offline_replay_page_with_test_hook(
    pool: &PgPool,
    lease: &OfflineReplayLease,
    ttl_days: i64,
    owner_bare_jid: &str,
    owner_full_jid: &str,
    active_privacy_list: Option<&str>,
    bind2_mam_catchup: bool,
    lease_seconds: i64,
    test_hook: &ReplayClaimTestHook,
) -> Result<OfflineReplayPageOutcome> {
    claim_offline_replay_page_retrying(
        pool,
        lease,
        ttl_days,
        owner_bare_jid,
        owner_full_jid,
        active_privacy_list,
        bind2_mam_catchup,
        lease_seconds,
        Some(test_hook),
    )
    .await
}

/// Test-only compatibility drain used by repository regression fixtures. The
/// production protocol owns all network awaits through ReplayService.
#[cfg(test)]
pub async fn deliver_offline_leased(
    pool: &PgPool,
    recipient_id: Uuid,
    ttl_days: i64,
    outbound: &crate::xmpp::outbound::OutboundSender,
    bind2_mam_catchup: bool,
    active_privacy_list: Option<&str>,
) -> Result<usize> {
    deliver_offline_leased_before(
        pool,
        recipient_id,
        ttl_days,
        outbound,
        bind2_mam_catchup,
        active_privacy_list,
        sqlx::query_scalar::<_, DateTime<Utc>>("SELECT clock_timestamp()")
            .fetch_one(pool)
            .await?,
    )
    .await
}

/// Replay only rows that existed at the semantic availability transition.
/// Callers which perform other awaited work before starting the replay pass a
/// database-clock cutoff captured at that transition.
#[cfg(test)]
pub async fn deliver_offline_leased_before(
    pool: &PgPool,
    recipient_id: Uuid,
    ttl_days: i64,
    outbound: &crate::xmpp::outbound::OutboundSender,
    bind2_mam_catchup: bool,
    active_privacy_list: Option<&str>,
    replay_started_at: DateTime<Utc>,
) -> Result<usize> {
    let owner_token = Uuid::new_v4();
    let lease = match acquire_offline_replay_lease(
        pool,
        recipient_id,
        "test-replay",
        owner_token,
        Some(replay_started_at),
        REPLAY_OWNER_LEASE_SECONDS,
    )
    .await?
    {
        OfflineReplayLeaseAcquire::Acquired(lease) => lease,
        OfflineReplayLeaseAcquire::BusyUntil(_) => return Ok(0),
    };
    let username: String = sqlx::query_scalar("SELECT username FROM users WHERE id=$1")
        .bind(recipient_id)
        .fetch_one(pool)
        .await?;
    let result = deliver_offline_pages_for_test(
        pool,
        &lease,
        ttl_days,
        outbound,
        bind2_mam_catchup,
        active_privacy_list,
        &format!("{username}@localhost"),
    )
    .await;
    let release = release_offline_replay_lease(pool, &lease).await;
    anyhow::ensure!(
        release?,
        "offline replay owner lease was lost before release"
    );
    result
}

#[cfg(test)]
async fn deliver_offline_pages_for_test(
    pool: &PgPool,
    lease: &OfflineReplayLease,
    ttl_days: i64,
    outbound: &crate::xmpp::outbound::OutboundSender,
    bind2_mam_catchup: bool,
    active_privacy_list: Option<&str>,
    owner_bare_jid: &str,
) -> Result<usize> {
    let owner_full_jid = format!("{owner_bare_jid}/{}", lease.resource);
    let mut delivered = 0usize;
    loop {
        let page = match claim_offline_replay_page(
            pool,
            lease,
            ttl_days,
            owner_bare_jid,
            &owner_full_jid,
            active_privacy_list,
            bind2_mam_catchup,
            REPLAY_OWNER_LEASE_SECONDS,
        )
        .await?
        {
            OfflineReplayPageOutcome::Claimed(page) => page,
            OfflineReplayPageOutcome::Empty | OfflineReplayPageOutcome::PendingClaims => break,
            OfflineReplayPageOutcome::LeaseLost => {
                anyhow::bail!("offline replay owner lease was lost")
            }
        };
        if page.messages.is_empty() {
            continue;
        }
        for (index, row) in page.messages.iter().enumerate() {
            let suffix = page.messages[index..]
                .iter()
                .map(|row| row.id)
                .collect::<Vec<_>>();
            if !renew_offline_replay_before_send(
                pool,
                lease,
                page.claim_token,
                &suffix,
                REPLAY_OWNER_LEASE_SECONDS,
            )
            .await?
            {
                anyhow::bail!("offline replay ownership was lost before transport send");
            }
            match tokio::time::timeout(
                std::time::Duration::from_secs(5),
                outbound.send_durable(
                    row.stanza.clone(),
                    crate::xmpp::outbound::DurableDelivery {
                        recipient_id: lease.recipient_id,
                        message_id: row.id,
                        claim_id: Some(page.claim_token),
                    },
                ),
            )
            .await
            {
                // Queue acceptance is not delivery. The TCP/WebSocket
                // transport owns the fenced delete after a recoverable write.
                Ok(Ok(())) => delivered += 1,
                Ok(Err(_)) => {
                    release_untransferred_offline_claims(
                        pool,
                        lease.recipient_id,
                        page.claim_token,
                        &suffix,
                    )
                    .await?;
                    return Ok(delivered);
                }
                Err(_) => {
                    outbound.disconnect_backpressured_transport();
                    release_untransferred_offline_claims(
                        pool,
                        lease.recipient_id,
                        page.claim_token,
                        &suffix,
                    )
                    .await?;
                    return Ok(delivered);
                }
            }
        }
    }
    Ok(delivered)
}

/// Bind all durable sources carried by one BOSH response in one transaction.
///
/// C2S offline rows are transferred directly at response construction, while
/// MIX sources were transferred to a pending BOSH fence before entering the
/// actor FIFO. Binding both source families atomically means an HTTP response
/// is either recoverably owned in full or not exposed at all.
// Compatibility fixture for existing database tests. Production carries
// the actual closed request through the observed entry below.
#[cfg(test)]
pub async fn bind_bosh_transport_response(
    pool: &PgPool,
    session_id: Uuid,
    response_rid: u64,
    sources: &[crate::xmpp::outbound::TransportOwnershipSource],
    ttl_seconds: u64,
) -> Result<crate::xmpp::outbound::BoshResponseOwnership> {
    bind_bosh_transport_response_inner(pool, session_id, response_rid, sources, ttl_seconds, None)
        .await
}

pub(crate) async fn bind_bosh_transport_response_observed(
    pool: &PgPool,
    request: &northstar_delivery_core::bosh_ownership::response::BindRequest,
) -> Result<crate::xmpp::outbound::BoshResponseOwnership> {
    request.validate_for_io()?;
    bind_bosh_transport_response_inner(
        pool,
        request.session_id(),
        request.rid(),
        request.sources(),
        request.ttl_seconds(),
        Some(request),
    )
    .await
}

/// Transfer durable C2S rows to the exact BOSH response which will carry
/// them. This commits before the HTTP response bytes are exposed to the peer.
///
/// The production BOSH coordinator uses the typed transport variant below so
/// one response can own both C2S and MIX rows.  This C2S-only surface remains
/// a test fixture for independently exercising legacy response semantics.
#[cfg(test)]
pub async fn bind_bosh_delivery_response(
    pool: &PgPool,
    session_id: Uuid,
    response_rid: u64,
    deliveries: &[crate::xmpp::outbound::DurableDelivery],
    ttl_seconds: u64,
) -> Result<()> {
    let response_rid = i64::try_from(response_rid).context("BOSH RID exceeds bigint")?;
    let ttl_seconds = i64::try_from(ttl_seconds.clamp(1, 86_400))
        .context("BOSH delivery-fence TTL is too large")?;
    let mut unique = std::collections::BTreeMap::new();
    for delivery in deliveries {
        anyhow::ensure!(
            unique.insert(delivery.message_id, *delivery).is_none(),
            "duplicate durable delivery in one BOSH response"
        );
    }
    anyhow::ensure!(unique.len() <= 512, "BOSH response fence limit exceeded");
    let mut transaction = pool.begin().await?;
    let existing_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM bosh_delivery_fences
          WHERE session_id=$1 AND first_owned_at>clock_timestamp()-INTERVAL '5 minutes'",
    )
    .bind(session_id)
    .fetch_one(&mut *transaction)
    .await?;
    anyhow::ensure!(
        existing_count.saturating_add(i64::try_from(unique.len()).unwrap_or(i64::MAX)) <= 512,
        "BOSH unacknowledged fence limit exceeded"
    );
    let response_rows = sqlx::query(
        "SELECT COUNT(DISTINCT response_rid) AS response_count,
                BOOL_OR(response_rid=$2) AS already_bound
           FROM bosh_delivery_fences WHERE session_id=$1",
    )
    .bind(session_id)
    .bind(response_rid)
    .fetch_one(&mut *transaction)
    .await?;
    let response_count: i64 = response_rows.try_get("response_count")?;
    let already_bound: Option<bool> = response_rows.try_get("already_bound")?;
    anyhow::ensure!(
        response_count < 2 || already_bound == Some(true),
        "BOSH unacknowledged response limit exceeded"
    );
    for delivery in unique.values() {
        // All binders acquire the offline row first and in UUID order, so two
        // concurrent resources cannot form a fence lock cycle.
        let offline = sqlx::query(
            "SELECT delivery_claim_id FROM offline_messages
              WHERE recipient_id=$1 AND id=$2 FOR UPDATE",
        )
        .bind(delivery.recipient_id)
        .bind(delivery.message_id)
        .fetch_optional(&mut *transaction)
        .await?;
        let Some(offline) = offline else {
            return Err(crate::xmpp::outbound::DurableDeliverySuperseded {
                message_id: delivery.message_id,
            }
            .into());
        };
        let sm_owned: bool = sqlx::query_scalar(
            "SELECT EXISTS(
                 SELECT 1 FROM sm_resume_stanzas WHERE delivery_message_id=$1
             )",
        )
        .bind(delivery.message_id)
        .fetch_one(&mut *transaction)
        .await?;
        if sm_owned {
            return Err(crate::xmpp::outbound::DurableDeliverySuperseded {
                message_id: delivery.message_id,
            }
            .into());
        }
        let existing = sqlx::query(
            "SELECT session_id,response_rid,expires_at>clock_timestamp() AS active
               FROM bosh_delivery_fences WHERE message_id=$1 FOR UPDATE",
        )
        .bind(delivery.message_id)
        .fetch_optional(&mut *transaction)
        .await?;
        if let Some(existing) = existing {
            let owner: Uuid = existing.try_get("session_id")?;
            let rid: i64 = existing.try_get("response_rid")?;
            if owner == session_id && rid == response_rid {
                if offline
                    .try_get::<Option<Uuid>, _>("delivery_claim_id")?
                    .is_some()
                {
                    return Err(crate::xmpp::outbound::DurableDeliverySuperseded {
                        message_id: delivery.message_id,
                    }
                    .into());
                }
                let renewed = sqlx::query(
                    "UPDATE bosh_delivery_fences
                        SET expires_at=LEAST(clock_timestamp()+($2*INTERVAL '1 second'),
                                             first_owned_at+INTERVAL '5 minutes')
                      WHERE message_id=$1 AND first_owned_at>clock_timestamp()-INTERVAL '5 minutes'",
                )
                .bind(delivery.message_id)
                .bind(ttl_seconds)
                .execute(&mut *transaction)
                .await?
                .rows_affected();
                anyhow::ensure!(
                    renewed == 1,
                    "BOSH response exceeded maximum acknowledgement age"
                );
                continue;
            }
            if existing.try_get::<bool, _>("active")? {
                return Err(crate::xmpp::outbound::DurableDeliverySuperseded {
                    message_id: delivery.message_id,
                }
                .into());
            }
            sqlx::query("DELETE FROM bosh_delivery_fences WHERE message_id=$1")
                .bind(delivery.message_id)
                .execute(&mut *transaction)
                .await?;
        }
        let stored_claim: Option<Uuid> = offline.try_get("delivery_claim_id")?;
        if stored_claim != delivery.claim_id {
            return Err(crate::xmpp::outbound::DurableDeliverySuperseded {
                message_id: delivery.message_id,
            }
            .into());
        }
        sqlx::query(
            "UPDATE offline_messages
                SET delivery_claim_id=NULL,delivery_claim_expires_at=NULL
              WHERE recipient_id=$1 AND id=$2",
        )
        .bind(delivery.recipient_id)
        .bind(delivery.message_id)
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            "INSERT INTO bosh_delivery_fences(
                message_id,recipient_id,session_id,response_rid,expires_at,first_owned_at
             ) VALUES($1,$2,$3,$4,
                LEAST(clock_timestamp()+($5*INTERVAL '1 second'),clock_timestamp()+INTERVAL '5 minutes'),
                clock_timestamp())",
        )
        .bind(delivery.message_id)
        .bind(delivery.recipient_id)
        .bind(session_id)
        .bind(response_rid)
        .bind(ttl_seconds)
        .execute(&mut *transaction)
        .await?;
    }
    transaction.commit().await?;
    Ok(())
}

/// C2S-only test fixture; runtime renewal uses `renew_bosh_transport_fences`.
#[cfg(test)]
pub async fn renew_bosh_delivery_fences(
    pool: &PgPool,
    session_id: Uuid,
    expected_response: Option<(u64, &[Uuid])>,
    ttl_seconds: u64,
) -> Result<()> {
    let ttl_seconds = i64::try_from(ttl_seconds.clamp(1, 86_400))
        .context("BOSH delivery-fence TTL is too large")?;
    let mut transaction = pool.begin().await?;
    let leases = sqlx::query(
        "SELECT message_id,response_rid,
                expires_at>clock_timestamp() AND first_owned_at>clock_timestamp()-INTERVAL '5 minutes' AS active
           FROM bosh_delivery_fences
          WHERE session_id=$1 ORDER BY message_id FOR UPDATE",
    )
    .bind(session_id)
    .fetch_all(&mut *transaction)
    .await?;
    for lease in &leases {
        anyhow::ensure!(
            lease.try_get::<bool, _>("active")?,
            "BOSH durable delivery lease expired before renewal"
        );
    }
    anyhow::ensure!(
        leases.len() <= 512,
        "BOSH unacknowledged fence limit exceeded"
    );
    let response_count = leases
        .iter()
        .filter_map(|lease| lease.try_get::<i64, _>("response_rid").ok())
        .collect::<std::collections::BTreeSet<_>>()
        .len();
    anyhow::ensure!(
        response_count <= 2,
        "BOSH unacknowledged response limit exceeded"
    );
    if let Some((response_rid, expected_message_ids)) = expected_response {
        let response_rid =
            i64::try_from(response_rid).context("BOSH response RID exceeds bigint")?;
        let expected = expected_message_ids
            .iter()
            .copied()
            .collect::<std::collections::BTreeSet<_>>();
        anyhow::ensure!(
            expected.len() == expected_message_ids.len(),
            "duplicate durable delivery in cached BOSH response"
        );
        let mut actual = std::collections::BTreeSet::new();
        for lease in &leases {
            if lease.try_get::<i64, _>("response_rid")? == response_rid {
                anyhow::ensure!(
                    actual.insert(lease.try_get::<Uuid, _>("message_id")?),
                    "duplicate durable delivery fence in one BOSH response"
                );
            }
        }
        anyhow::ensure!(
            actual == expected,
            "cached BOSH response no longer owns its exact durable delivery fences"
        );
    }
    let renewed = sqlx::query(
        "UPDATE bosh_delivery_fences
            SET expires_at=LEAST(clock_timestamp()+($2*INTERVAL '1 second'),
                                 first_owned_at+INTERVAL '5 minutes')
          WHERE session_id=$1 AND first_owned_at>clock_timestamp()-INTERVAL '5 minutes'",
    )
    .bind(session_id)
    .bind(ttl_seconds)
    .execute(&mut *transaction)
    .await?
    .rows_affected();
    anyhow::ensure!(
        renewed as usize == leases.len(),
        "BOSH acknowledgement-age fence was lost during renewal"
    );
    transaction.commit().await?;
    Ok(())
}

/// Complete all durable messages covered by a valid XEP-0124 client response
/// acknowledgement. Deleting each offline row cascades its BOSH fence.
///
/// This is the C2S-only test fixture. Runtime acknowledgement goes through
/// the typed transport owner so MIX rows cannot be skipped.
#[cfg(test)]
pub async fn acknowledge_bosh_delivery_responses(
    pool: &PgPool,
    session_id: Uuid,
    acknowledged_rid: u64,
) -> Result<usize> {
    let acknowledged_rid =
        i64::try_from(acknowledged_rid).context("BOSH acknowledgement exceeds bigint")?;
    let mut transaction = pool.begin().await?;
    let mut rows = sqlx::query(
        "SELECT recipient_id,message_id FROM bosh_delivery_fences
          WHERE session_id=$1 AND response_rid<=$2
          ORDER BY message_id",
    )
    .bind(session_id)
    .bind(acknowledged_rid)
    .fetch_all(&mut *transaction)
    .await?;
    rows.sort_unstable_by_key(|row| row.get::<Uuid, _>("message_id"));
    for row in &rows {
        let recipient_id: Uuid = row.try_get("recipient_id")?;
        let message_id: Uuid = row.try_get("message_id")?;
        let offline = sqlx::query_scalar::<_, bool>(
            "SELECT TRUE FROM offline_messages
              WHERE recipient_id=$1 AND id=$2 FOR UPDATE",
        )
        .bind(recipient_id)
        .bind(message_id)
        .fetch_optional(&mut *transaction)
        .await?;
        anyhow::ensure!(offline.is_some(), "BOSH-owned durable delivery disappeared");
        let still_owned = sqlx::query_scalar::<_, bool>(
            "SELECT expires_at>clock_timestamp()
               FROM bosh_delivery_fences
              WHERE message_id=$1 AND session_id=$2 AND response_rid<=$3
              FOR UPDATE",
        )
        .bind(message_id)
        .bind(session_id)
        .bind(acknowledged_rid)
        .fetch_optional(&mut *transaction)
        .await?;
        anyhow::ensure!(
            still_owned == Some(true),
            "BOSH durable delivery lease was lost before acknowledgement"
        );
        let deleted = sqlx::query("DELETE FROM offline_messages WHERE recipient_id=$1 AND id=$2")
            .bind(recipient_id)
            .bind(message_id)
            .execute(&mut *transaction)
            .await?
            .rows_affected();
        anyhow::ensure!(deleted == 1, "BOSH-owned durable delivery disappeared");
    }
    transaction.commit().await?;
    Ok(rows.len())
}

/// C2S-only test fixture; runtime release uses `release_bosh_transport_fences`.
#[cfg(test)]
pub async fn release_bosh_delivery_fences(pool: &PgPool, session_id: Uuid) -> Result<()> {
    sqlx::query("DELETE FROM bosh_delivery_fences WHERE session_id=$1")
        .bind(session_id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Production source of this module: the file itself followed by each
/// production child module file, so source-contract tests keep reading the
/// whole module after code moves between them. The children are listed in
/// the order their code had in the former single file, because some
/// contracts split the source on a marker that occurs in more than one child.
/// `module_source_lists_every_child_module` keeps this list in step with the
/// non-test `mod` declarations above.
#[cfg(test)]
const MODULE_SOURCE: &[(&str, &str)] = &[
    ("replay", include_str!("replay.rs")),
    ("presence_policy", include_str!("replay/presence_policy.rs")),
    (
        "offline_delivery",
        include_str!("replay/offline_delivery.rs"),
    ),
    ("bosh_transport", include_str!("replay/bosh_transport.rs")),
];

#[cfg(test)]
fn module_source() -> String {
    MODULE_SOURCE
        .iter()
        .map(|(_, text)| *text)
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
mod bosh_ack_bound_schema_tests;

#[cfg(test)]
#[path = "replay_tests.rs"]
mod tests;

#[cfg(test)]
mod module_source_tests;
