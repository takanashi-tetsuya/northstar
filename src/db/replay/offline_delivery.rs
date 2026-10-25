//! Manage C2S offline replay authorization, leases, page claims and durable delivery ownership.

use super::*;

pub(super) fn validate_replay_lease_seconds(lease_seconds: i64) -> Result<()> {
    anyhow::ensure!(
        (75..=300).contains(&lease_seconds),
        "offline replay owner lease must be between 75 and 300 seconds"
    );
    Ok(())
}

/// Acquire the logical XEP-0160 replay owner for one bound resource. Distinct
/// resources of the same account may replay concurrently, while the composite
/// `(recipient_id, resource, owner_token)` fence keeps each resource
/// single-flight. This is deliberately a bounded PostgreSQL row lease rather
/// than a session advisory lock: a slow socket never retains a pool connection,
/// and a crashed process becomes recoverable after `expires_at`.
pub async fn acquire_offline_replay_lease(
    pool: &PgPool,
    recipient_id: Uuid,
    owner_resource: &str,
    owner_token: Uuid,
    explicit_cutoff: Option<DateTime<Utc>>,
    lease_seconds: i64,
) -> Result<OfflineReplayLeaseAcquire> {
    validate_replay_lease_seconds(lease_seconds)?;
    anyhow::ensure!(
        (1..=1023).contains(&owner_resource.len()),
        "offline replay resource must be between 1 and 1023 bytes"
    );
    // A conflicting INSERT can disappear between statements if its owner
    // releases immediately. Retry that narrow race with a new transaction;
    // every returned wait duration is still measured by PostgreSQL.
    for race_attempt in 0..2 {
        let mut transaction = pool.begin().await?;
        let database_now: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
            .fetch_one(&mut *transaction)
            .await?;
        let acquired = sqlx::query_scalar::<_, DateTime<Utc>>(
            "INSERT INTO offline_replay_leases(
                 recipient_id,resource,owner_token,acquired_at,renewed_at,expires_at
             ) VALUES(
                 $1,$2,$3,$4,$4,
                 $4+($5::DOUBLE PRECISION*INTERVAL '1 second')
             )
             ON CONFLICT(recipient_id,resource) DO UPDATE
                SET owner_token=EXCLUDED.owner_token,
                    acquired_at=EXCLUDED.acquired_at,
                    renewed_at=EXCLUDED.renewed_at,
                    expires_at=EXCLUDED.expires_at
              WHERE offline_replay_leases.expires_at<=$4
             RETURNING acquired_at",
        )
        .bind(recipient_id)
        .bind(owner_resource)
        .bind(owner_token)
        .bind(database_now)
        .bind(lease_seconds)
        .fetch_optional(&mut *transaction)
        .await?;
        if acquired.is_some() {
            transaction.commit().await?;
            return Ok(OfflineReplayLeaseAcquire::Acquired(OfflineReplayLease {
                recipient_id,
                resource: owner_resource.to_owned(),
                owner_token,
                // Explicit cutoffs are captured with PostgreSQL clock at an
                // earlier availability transition. Clamp defensively so an
                // accidental application-clock value cannot widen the epoch.
                replay_started_at: explicit_cutoff
                    .map_or(database_now, |cutoff| cutoff.min(database_now)),
            }));
        }

        let busy = sqlx::query_as::<_, (DateTime<Utc>, i64)>(
            "SELECT expires_at,
                    GREATEST(
                      0,
                      CEIL(EXTRACT(EPOCH FROM
                        (expires_at-clock_timestamp()))*1000)
                    )::BIGINT AS retry_after_ms
               FROM offline_replay_leases
              WHERE recipient_id=$1 AND resource=$2",
        )
        .bind(recipient_id)
        .bind(owner_resource)
        .fetch_optional(&mut *transaction)
        .await?;
        if let Some((expires_at, retry_after_ms)) = busy {
            transaction.commit().await?;
            return Ok(OfflineReplayLeaseAcquire::BusyUntil(
                OfflineReplayBusyUntil {
                    expires_at,
                    retry_after: Duration::from_millis(
                        u64::try_from(retry_after_ms).unwrap_or(u64::MAX),
                    ),
                },
            ));
        }
        transaction.rollback().await?;
        if race_attempt == 1 {
            anyhow::bail!("offline replay lease conflict disappeared twice during acquisition");
        }
    }
    unreachable!("bounded replay-lease acquisition loop always returns")
}

/// Release only the exact logical owner. A stale process can never delete a
/// lease acquired by its replacement.
pub async fn release_offline_replay_lease(
    pool: &PgPool,
    lease: &OfflineReplayLease,
) -> Result<bool> {
    Ok(sqlx::query(
        "DELETE FROM offline_replay_leases
          WHERE recipient_id=$1 AND resource=$2 AND owner_token=$3",
    )
    .bind(lease.recipient_id)
    .bind(&lease.resource)
    .bind(lease.owner_token)
    .execute(pool)
    .await?
    .rows_affected()
        == 1)
}

/// Keep the exact account incarnation authorized until a recovery replay
/// claim or bounded transport enqueue has crossed its boundary. Credential
/// revocation updates the same users row and therefore waits for this guard.
pub(crate) struct RecoveryReplayAuthorizationGuard {
    pub(super) transaction: Transaction<'static, Postgres>,
}

impl RecoveryReplayAuthorizationGuard {
    pub(crate) async fn release(self) -> Result<()> {
        self.transaction.rollback().await?;
        Ok(())
    }
}

pub(crate) async fn lock_recovery_replay_authorization(
    pool: &PgPool,
    user_id: Uuid,
    expected_auth_generation: i64,
) -> Result<Option<RecoveryReplayAuthorizationGuard>> {
    let mut transaction = pool.begin().await?;
    let authorized = sqlx::query_scalar::<_, bool>(
        "SELECT TRUE FROM users
          WHERE id=$1 AND auth_generation=$2 AND NOT is_disabled
          FOR SHARE",
    )
    .bind(user_id)
    .bind(expected_auth_generation)
    .fetch_optional(&mut *transaction)
    .await?
    .is_some();
    if !authorized {
        transaction.rollback().await?;
        return Ok(None);
    }
    Ok(Some(RecoveryReplayAuthorizationGuard { transaction }))
}

#[derive(Clone, Debug)]
pub(super) struct ClaimedOfflineCandidate {
    pub(super) message: ClaimedOfflineMessage,
    pub(super) mam_backed: bool,
    pub(super) created_at: DateTime<Utc>,
}

pub(super) const SERIALIZATION_RETRY_ATTEMPTS: usize = 3;
pub(super) const SERIALIZATION_RETRY_BASE_MILLIS: u64 = 8;
pub(super) const SERIALIZATION_RETRY_MAX_MILLIS: u64 = 96;

pub(super) fn postgres_serialization_failure(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause
            .downcast_ref::<sqlx::Error>()
            .and_then(sqlx::Error::as_database_error)
            .and_then(|database| database.code())
            .as_deref()
            == Some("40001")
    })
}

pub(super) fn serialization_retry_delay(attempt: usize) -> Duration {
    let shift = u32::try_from(attempt.min(4)).unwrap_or(4);
    let base = SERIALIZATION_RETRY_BASE_MILLIS
        .saturating_mul(1_u64 << shift)
        .min(SERIALIZATION_RETRY_MAX_MILLIS / 2);
    let jitter = rand::thread_rng().gen_range(0..=base);
    Duration::from_millis(
        base.saturating_add(jitter)
            .min(SERIALIZATION_RETRY_MAX_MILLIS),
    )
}

/// Claim one bounded page and apply XEP-0191/XEP-0016 policy in the same
/// repeatable-read write transaction.  Suppressed rows are consumed before
/// commit; no unfiltered DTO can escape an authorization snapshot.
#[allow(clippy::too_many_arguments)]
pub async fn claim_offline_replay_page(
    pool: &PgPool,
    lease: &OfflineReplayLease,
    ttl_days: i64,
    owner_bare_jid: &str,
    owner_full_jid: &str,
    active_privacy_list: Option<&str>,
    bind2_mam_catchup: bool,
    lease_seconds: i64,
) -> Result<OfflineReplayPageOutcome> {
    #[cfg(test)]
    let test_hook = None;
    #[cfg(not(test))]
    let test_hook = ();
    claim_offline_replay_page_retrying(
        pool,
        lease,
        ttl_days,
        owner_bare_jid,
        owner_full_jid,
        active_privacy_list,
        bind2_mam_catchup,
        lease_seconds,
        test_hook,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn claim_offline_replay_page_retrying(
    pool: &PgPool,
    lease: &OfflineReplayLease,
    ttl_days: i64,
    owner_bare_jid: &str,
    owner_full_jid: &str,
    active_privacy_list: Option<&str>,
    bind2_mam_catchup: bool,
    lease_seconds: i64,
    test_hook: ReplayClaimHookRef<'_>,
) -> Result<OfflineReplayPageOutcome> {
    for attempt in 0..=SERIALIZATION_RETRY_ATTEMPTS {
        let result = claim_offline_replay_page_once(
            pool,
            lease,
            ttl_days,
            owner_bare_jid,
            owner_full_jid,
            active_privacy_list,
            bind2_mam_catchup,
            lease_seconds,
            test_hook,
        )
        .await;
        match result {
            Err(error)
                if attempt < SERIALIZATION_RETRY_ATTEMPTS
                    && postgres_serialization_failure(&error) =>
            {
                #[cfg(test)]
                if let Some(hook) = test_hook {
                    hook.serialization_retries
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
                // `claim_offline_replay_page_once` has returned and dropped
                // its aborted Transaction before this await. The next pass
                // therefore obtains a fresh PostgreSQL snapshot.
                tokio::time::sleep(serialization_retry_delay(attempt)).await;
            }
            other => return other,
        }
    }
    unreachable!("bounded serialization retry loop always returns")
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn claim_offline_replay_page_once(
    pool: &PgPool,
    lease: &OfflineReplayLease,
    ttl_days: i64,
    owner_bare_jid: &str,
    owner_full_jid: &str,
    active_privacy_list: Option<&str>,
    bind2_mam_catchup: bool,
    lease_seconds: i64,
    _test_hook: ReplayClaimHookRef<'_>,
) -> Result<OfflineReplayPageOutcome> {
    validate_replay_lease_seconds(lease_seconds)?;
    let owner_bare_jid = northstar_xmpp_types::jid::canonicalize_bare(owner_bare_jid)?;
    let raw_owner_full_jid = owner_full_jid;
    let owner_full_jid = northstar_xmpp_types::jid::canonical_session_key(raw_owner_full_jid)?;
    anyhow::ensure!(
        owner_full_jid == raw_owner_full_jid,
        "offline replay resource must already be canonical"
    );
    let owner_full = northstar_xmpp_types::jid::CanonicalJid::parse(&owner_full_jid)?;
    anyhow::ensure!(
        owner_full.bare() == owner_bare_jid,
        "offline replay resource does not belong to replay owner"
    );
    let owner_resource = owner_full
        .resourcepart()
        .expect("canonical_session_key requires a resourcepart")
        .to_owned();
    anyhow::ensure!(
        owner_resource == lease.resource,
        "lease resource does not match owner_full_jid resource"
    );
    let claim_token = Uuid::new_v4();
    let mut transaction = pool.begin().await?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
        .execute(&mut *transaction)
        .await?;
    let lease_renewed = sqlx::query(
        "UPDATE offline_replay_leases
            SET renewed_at=clock_timestamp(),
                expires_at=clock_timestamp()+($4::DOUBLE PRECISION*INTERVAL '1 second')
          WHERE recipient_id=$1 AND resource=$2 AND owner_token=$3
            AND expires_at>clock_timestamp()",
    )
    .bind(lease.recipient_id)
    .bind(&lease.resource)
    .bind(lease.owner_token)
    .bind(lease_seconds)
    .execute(&mut *transaction)
    .await?
    .rows_affected();
    if lease_renewed != 1 {
        transaction.rollback().await?;
        return Ok(OfflineReplayPageOutcome::LeaseLost);
    }

    #[cfg(test)]
    if let Some(hook) = _test_hook {
        hook.pause_once_after_snapshot().await;
    }

    // Retention runs before an expired BOSH response is handed off. Thus an
    // old row remains protected by any response fence until this transaction
    // atomically takes responsibility for retrying it.
    sqlx::query(
        "WITH expired AS MATERIALIZED (
             SELECT message.id FROM offline_messages message
              WHERE message.recipient_id=$1
                AND COALESCE(
                    (SELECT retention.offline_message_days
                       FROM user_retention_policies retention
                      WHERE retention.user_id=$1),NULLIF($2::BIGINT,0)
                ) IS NOT NULL
                AND message.created_at < clock_timestamp()-(
                    COALESCE(
                        (SELECT retention.offline_message_days
                           FROM user_retention_policies retention
                          WHERE retention.user_id=$1),NULLIF($2::BIGINT,0)
                    )::BIGINT*INTERVAL '1 day')
                AND (message.delivery_claim_id IS NULL
                     OR message.delivery_claim_expires_at<=clock_timestamp())
                AND NOT EXISTS (
                    SELECT 1 FROM sm_resume_stanzas sm
                     WHERE sm.delivery_message_id=message.id
                )
                AND NOT EXISTS (
                    SELECT 1 FROM bosh_delivery_fences bosh
                     WHERE bosh.message_id=message.id
                )
                AND NOT EXISTS (
                    SELECT 1 FROM legal_holds hold
                     WHERE hold.released_at IS NULL AND (
                         EXISTS (SELECT 1 FROM legal_hold_offline_messages link
                                  WHERE link.hold_id=hold.id AND link.message_id=message.id)
                         OR EXISTS (SELECT 1 FROM legal_hold_scopes scope_link
                                    WHERE scope_link.hold_id=hold.id
                                      AND scope_link.scope_type='offline_message_recipient'
                                      AND scope_link.subject_id=message.recipient_id)
                     )
                )
              ORDER BY message.created_at,message.id
              FOR UPDATE OF message SKIP LOCKED LIMIT 256
         )
         DELETE FROM offline_messages message USING expired
          WHERE message.id=expired.id",
    )
    .bind(lease.recipient_id)
    .bind(ttl_days)
    .execute(&mut *transaction)
    .await?;

    // Expiry is a lease hand-off, not merely a timestamp predicate.  Every
    // binder uses the offline-row -> response-fence lock order.
    sqlx::query(
        "WITH expired AS (
             SELECT message.id
               FROM offline_messages message
               JOIN bosh_delivery_fences fence ON fence.message_id=message.id
              WHERE message.recipient_id=$1
                AND fence.expires_at<=clock_timestamp()
              ORDER BY fence.expires_at,message.id
              FOR UPDATE OF message SKIP LOCKED LIMIT 256
         )
         DELETE FROM bosh_delivery_fences fence USING expired
          WHERE fence.message_id=expired.id
            AND fence.expires_at<=clock_timestamp()",
    )
    .bind(lease.recipient_id)
    .execute(&mut *transaction)
    .await?;

    let rows = sqlx::query(
        "WITH candidates AS (
             SELECT id FROM offline_messages
              WHERE recipient_id=$1
                AND created_at <= $5
                AND (target_resource IS NULL OR target_resource=$6)
                AND NOT EXISTS (
                    SELECT 1 FROM sm_resume_stanzas sm
                     WHERE sm.delivery_message_id=offline_messages.id
                )
                AND NOT EXISTS (
                    SELECT 1 FROM bosh_delivery_fences bosh
                     WHERE bosh.message_id=offline_messages.id
                )
                AND (delivery_claim_id IS NULL
                     OR delivery_claim_expires_at<=clock_timestamp())
              ORDER BY created_at,id FOR UPDATE SKIP LOCKED LIMIT $3
         )
         UPDATE offline_messages AS message
            SET delivery_claim_id=$2,
                delivery_claim_expires_at=clock_timestamp()+($4*INTERVAL '1 second')
           FROM candidates WHERE message.id=candidates.id
         RETURNING message.id,message.sender_jid,message.stanza,message.mam_backed,
                   message.created_at",
    )
    .bind(lease.recipient_id)
    .bind(claim_token)
    .bind(REPLAY_PAGE_SIZE)
    .bind(CLAIM_LEASE_SECONDS)
    .bind(lease.replay_started_at)
    .bind(&owner_resource)
    .fetch_all(&mut *transaction)
    .await?;
    if rows.is_empty() {
        // SKIP LOCKED and unexpired claim leases can hide a cutoff-eligible
        // row from this page. Only mark the replay high-water complete when
        // no eligible row exists even without those temporary claim filters.
        // Keep privacy-denied and Bind2 MAM-backed rows in this conservative
        // probe: suppression consumes their projection only after this claim
        // transaction owns the row, and a different resource/policy may later
        // be eligible if an earlier claim expires without that consumption.
        let pending: bool = sqlx::query_scalar(
            "SELECT EXISTS(
                 SELECT 1 FROM offline_messages message
                  WHERE message.recipient_id=$1
                    AND message.created_at<=$2
                    AND (message.target_resource IS NULL OR message.target_resource=$3)
                    AND NOT EXISTS(
                        SELECT 1 FROM sm_resume_stanzas sm
                         WHERE sm.delivery_message_id=message.id
                    )
                    AND NOT EXISTS(
                        SELECT 1 FROM bosh_delivery_fences bosh
                         WHERE bosh.message_id=message.id
                    )
             )",
        )
        .bind(lease.recipient_id)
        .bind(lease.replay_started_at)
        .bind(&owner_resource)
        .fetch_one(&mut *transaction)
        .await?;
        transaction.commit().await?;
        return Ok(if pending {
            OfflineReplayPageOutcome::PendingClaims
        } else {
            OfflineReplayPageOutcome::Empty
        });
    }
    let mut candidates = rows
        .into_iter()
        .map(|row| {
            Ok(ClaimedOfflineCandidate {
                message: ClaimedOfflineMessage {
                    id: row.try_get("id")?,
                    sender_jid: row.try_get("sender_jid")?,
                    stanza: row.try_get("stanza")?,
                },
                mam_backed: row.try_get("mam_backed")?,
                created_at: row.try_get("created_at")?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    candidates.sort_by_key(|row| (row.created_at, row.message.id));
    let senders = candidates
        .iter()
        .map(|row| row.message.sender_jid.clone())
        .collect::<Vec<_>>();
    let (blocked_patterns, privacy, roster) = replay_policy_snapshot(
        &mut transaction,
        lease.recipient_id,
        active_privacy_list,
        &senders,
    )
    .await?;
    let mut suppressed = Vec::new();
    let mut messages = Vec::with_capacity(candidates.len());
    for row in candidates {
        let denied = replay_policy_denies(
            &owner_bare_jid,
            &row.message.sender_jid,
            super::super::PrivacyStanzaKind::Message,
            &blocked_patterns,
            &privacy,
            &roster,
        )?;
        if (bind2_mam_catchup && row.mam_backed) || denied {
            suppressed.push(row.message.id);
        } else {
            messages.push(row.message);
        }
    }
    if !suppressed.is_empty() {
        let removed = sqlx::query(
            "DELETE FROM offline_messages
              WHERE recipient_id=$1 AND delivery_claim_id=$2 AND id=ANY($3::UUID[])",
        )
        .bind(lease.recipient_id)
        .bind(claim_token)
        .bind(&suppressed)
        .execute(&mut *transaction)
        .await?
        .rows_affected();
        anyhow::ensure!(
            removed == suppressed.len() as u64,
            "offline suppression lost its exact page claim"
        );
    }
    transaction.commit().await?;
    if messages.is_empty() {
        // The page contained only policy/MAM-suppressed projections.  Report
        // an empty claimed page so the caller continues to the next page
        // rather than treating this as the high-water end.
        return Ok(OfflineReplayPageOutcome::Claimed(ClaimedOfflinePage {
            claim_token,
            messages,
        }));
    }
    Ok(OfflineReplayPageOutcome::Claimed(ClaimedOfflinePage {
        claim_token,
        messages,
    }))
}

/// Atomically renew both the resource-scoped coordinator and the exact unsent
/// page suffix immediately before another stanza can enter the transport queue.
/// A stale owner gets `false` and must not send.
pub async fn renew_offline_replay_before_send(
    pool: &PgPool,
    lease: &OfflineReplayLease,
    page_claim_token: Uuid,
    pending_ids: &[Uuid],
    lease_seconds: i64,
) -> Result<bool> {
    validate_replay_lease_seconds(lease_seconds)?;
    anyhow::ensure!(
        !pending_ids.is_empty(),
        "offline replay renewal suffix is empty"
    );
    let mut unique = pending_ids.to_vec();
    unique.sort_unstable();
    unique.dedup();
    anyhow::ensure!(
        unique.len() == pending_ids.len(),
        "offline replay renewal suffix contains duplicates"
    );
    let mut transaction = pool.begin().await?;
    let owner = sqlx::query(
        "UPDATE offline_replay_leases
            SET renewed_at=clock_timestamp(),
                expires_at=clock_timestamp()+($4::DOUBLE PRECISION*INTERVAL '1 second')
          WHERE recipient_id=$1 AND resource=$2 AND owner_token=$3
            AND expires_at>clock_timestamp()",
    )
    .bind(lease.recipient_id)
    .bind(&lease.resource)
    .bind(lease.owner_token)
    .bind(lease_seconds)
    .execute(&mut *transaction)
    .await?
    .rows_affected();
    if owner != 1 {
        transaction.rollback().await?;
        return Ok(false);
    }
    let rows = sqlx::query(
        "UPDATE offline_messages
            SET delivery_claim_expires_at=clock_timestamp()+($4*INTERVAL '1 second')
          WHERE recipient_id=$1 AND delivery_claim_id=$2 AND id=ANY($3::UUID[])",
    )
    .bind(lease.recipient_id)
    .bind(page_claim_token)
    .bind(&unique)
    .bind(CLAIM_LEASE_SECONDS)
    .execute(&mut *transaction)
    .await?
    .rows_affected();
    if rows != unique.len() as u64 {
        transaction.rollback().await?;
        return Ok(false);
    }
    transaction.commit().await?;
    Ok(true)
}

/// Clear only claims which have not crossed queue acceptance.  Earlier rows
/// from the same page retain their exact transport fence and are never made
/// concurrently replayable by suffix cleanup.
pub async fn release_untransferred_offline_claims(
    pool: &PgPool,
    recipient_id: Uuid,
    page_claim_token: Uuid,
    message_ids: &[Uuid],
) -> Result<u64> {
    if message_ids.is_empty() {
        return Ok(0);
    }
    let mut unique = message_ids.to_vec();
    unique.sort_unstable();
    unique.dedup();
    anyhow::ensure!(
        unique.len() == message_ids.len(),
        "offline replay release suffix contains duplicates"
    );
    let released = sqlx::query(
        "UPDATE offline_messages
            SET delivery_claim_id=NULL,delivery_claim_expires_at=NULL
          WHERE recipient_id=$1 AND delivery_claim_id=$2 AND id=ANY($3::UUID[])",
    )
    .bind(recipient_id)
    .bind(page_claim_token)
    .bind(&unique)
    .execute(pool)
    .await?
    .rows_affected();
    anyhow::ensure!(
        released == unique.len() as u64,
        "offline replay unsent suffix lost its exact page claim"
    );
    Ok(released)
}

/// Complete a live (unclaimed) or replay (fenced) C2S delivery only after the
/// transport has crossed its write/recovery boundary. A missing live row is
/// an idempotent acknowledgement; a missing claimed row means the replay
/// worker lost its fence and must be reported.
pub async fn acknowledge_durable_delivery(
    pool: &PgPool,
    delivery: crate::xmpp::outbound::DurableDelivery,
) -> Result<()> {
    acknowledge_durable_deliveries(pool, std::slice::from_ref(&delivery)).await
}

/// Atomically acknowledge a complete transport boundary. Every claimed/live
/// ownership fence is validated before any row is deleted; the batch commits
/// atomically. A lost COMMIT response leaves the entire outcome unknown, and
/// a returned error alone does not prove that the prefix was retained.
pub async fn acknowledge_durable_deliveries(
    pool: &PgPool,
    deliveries: &[crate::xmpp::outbound::DurableDelivery],
) -> Result<()> {
    acknowledge_durable_deliveries_observed(pool, deliveries, None).await
}

pub(crate) async fn acknowledge_durable_deliveries_observed(
    pool: &PgPool,
    deliveries: &[crate::xmpp::outbound::DurableDelivery],
    observation: Option<&northstar_delivery_core::native_write::AckRequest>,
) -> Result<()> {
    use northstar_delivery_core::native_write::{commit_observed, AckDisposition};
    if let Some(observation) = observation {
        anyhow::ensure!(
            deliveries.len() == 1,
            "native ACK observation requires its one exact source"
        );
        observation.validate_source(crate::xmpp::outbound::TransportOwnershipSource::C2s(
            deliveries[0],
        ))?;
    }
    if deliveries.is_empty() {
        return Ok(());
    }
    let mut deliveries = deliveries.to_vec();
    deliveries.sort_unstable_by_key(|delivery| (delivery.recipient_id, delivery.message_id));
    anyhow::ensure!(
        deliveries
            .windows(2)
            .all(|window| window[0].message_id != window[1].message_id),
        "duplicate durable delivery in one acknowledgement batch"
    );
    let mut transaction = pool.begin().await?;
    let mut present = Vec::with_capacity(deliveries.len());
    for delivery in &deliveries {
        let row = sqlx::query(
            "SELECT delivery_claim_id FROM offline_messages
              WHERE recipient_id=$1 AND id=$2 FOR UPDATE",
        )
        .bind(delivery.recipient_id)
        .bind(delivery.message_id)
        .fetch_optional(&mut *transaction)
        .await?;
        match (row, delivery.claim_id) {
            (None, None) => present.push(false),
            (None, Some(_)) => {
                anyhow::bail!("offline delivery claim was lost before acknowledgement")
            }
            (Some(row), Some(expected_claim)) => {
                anyhow::ensure!(
                    northstar_delivery_core::native_write::claimed_c2s_ack_matches(
                        expected_claim,
                        row.try_get::<Option<Uuid>, _>("delivery_claim_id")?,
                    ),
                    "offline delivery claim was lost before acknowledgement"
                );
                present.push(true);
            }
            (Some(row), None) => {
                anyhow::ensure!(
                    row.try_get::<Option<Uuid>, _>("delivery_claim_id")?
                        .is_none(),
                    "live transport acknowledgement does not own the offline replay claim"
                );
                let transport_owned: bool = sqlx::query_scalar(
                    "SELECT EXISTS(
                         SELECT 1 FROM sm_resume_stanzas WHERE delivery_message_id=$1
                     ) OR EXISTS(
                         SELECT 1 FROM bosh_delivery_fences WHERE message_id=$1
                     )",
                )
                .bind(delivery.message_id)
                .fetch_one(&mut *transaction)
                .await?;
                anyhow::ensure!(
                    !transport_owned,
                    "live transport acknowledgement does not own the durable delivery"
                );
                present.push(true);
            }
        }
    }
    let observed_disposition = observation.map(|_| {
        if present[0] {
            AckDisposition::Deleted
        } else {
            AckDisposition::AbsentUnclaimed
        }
    });
    for (delivery, present) in deliveries.iter().zip(present) {
        if !present {
            continue;
        }
        let removed = sqlx::query(
            "DELETE FROM offline_messages
              WHERE recipient_id=$1 AND id=$2 AND delivery_claim_id IS NOT DISTINCT FROM $3",
        )
        .bind(delivery.recipient_id)
        .bind(delivery.message_id)
        .bind(delivery.claim_id)
        .execute(&mut *transaction)
        .await?
        .rows_affected();
        anyhow::ensure!(
            removed == 1,
            "durable delivery disappeared during acknowledgement"
        );
    }
    if let Some((observation, disposition)) = observation.zip(observed_disposition) {
        commit_observed(transaction.commit(), observation, disposition).await?;
    } else {
        transaction.commit().await?;
    }
    tracing::debug!(
        deliveries = deliveries.len(),
        "atomically acknowledged durable C2S delivery batch"
    );
    Ok(())
}

/// Fence one non-SM TCP/WebSocket write immediately before bytes are exposed
/// to the peer.  A live delivery enters routing without a replay claim, while
/// an offline replay can wait in the bounded transport queue long enough for
/// its original claim lease to approach expiry.  Taking or renewing the exact
/// claim here closes both windows: retention and another replay worker must
/// wait until the bounded socket write either acknowledges this claim or its
/// lease expires after a crash/timeout.
pub async fn fence_durable_socket_write(
    pool: &PgPool,
    delivery: crate::xmpp::outbound::DurableDelivery,
) -> Result<crate::xmpp::outbound::DurableDelivery> {
    // A newly committed clustered live row is reserved with its message UUID
    // until the primary route reaches a transport. Rotate that initial token
    // under the exact row lock: a concurrent no-route/degradation cleanup may
    // release only the initial reservation, never this socket's write fence.
    let claim_id = if delivery.claim_id == Some(delivery.message_id) {
        loop {
            let fresh = Uuid::new_v4();
            if fresh != delivery.message_id {
                break fresh;
            }
        }
    } else {
        delivery.claim_id.unwrap_or_else(Uuid::new_v4)
    };
    let mut transaction = pool.begin().await?;
    let row = sqlx::query(
        "SELECT delivery_claim_id FROM offline_messages
          WHERE recipient_id=$1 AND id=$2 FOR UPDATE",
    )
    .bind(delivery.recipient_id)
    .bind(delivery.message_id)
    .fetch_optional(&mut *transaction)
    .await?;
    let Some(row) = row else {
        return Err(crate::xmpp::outbound::DurableDeliverySuperseded {
            message_id: delivery.message_id,
        }
        .into());
    };
    let stored_claim: Option<Uuid> = row.try_get("delivery_claim_id")?;
    if stored_claim != delivery.claim_id {
        return Err(crate::xmpp::outbound::DurableDeliverySuperseded {
            message_id: delivery.message_id,
        }
        .into());
    }
    let transport_owned: bool = sqlx::query_scalar(
        "SELECT EXISTS(
             SELECT 1 FROM sm_resume_stanzas WHERE delivery_message_id=$1
         ) OR EXISTS(
             SELECT 1 FROM bosh_delivery_fences WHERE message_id=$1
         )",
    )
    .bind(delivery.message_id)
    .fetch_one(&mut *transaction)
    .await?;
    if transport_owned {
        return Err(crate::xmpp::outbound::DurableDeliverySuperseded {
            message_id: delivery.message_id,
        }
        .into());
    }
    let updated = sqlx::query(
        "UPDATE offline_messages
            SET delivery_claim_id=$3,
                delivery_claim_expires_at=clock_timestamp()+($4*INTERVAL '1 second')
          WHERE recipient_id=$1 AND id=$2",
    )
    .bind(delivery.recipient_id)
    .bind(delivery.message_id)
    .bind(claim_id)
    .bind(CLAIM_LEASE_SECONDS)
    .execute(&mut *transaction)
    .await?
    .rows_affected();
    anyhow::ensure!(
        updated == 1,
        "durable delivery disappeared during socket write fencing"
    );
    transaction.commit().await?;
    Ok(crate::xmpp::outbound::DurableDelivery {
        claim_id: Some(claim_id),
        ..delivery
    })
}
