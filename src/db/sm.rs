use crate::xmpp::outbound;
use anyhow::{Context, Result};
use sqlx::{PgPool, Row};
use std::{
    collections::{HashMap, HashSet},
    net::IpAddr,
};
use uuid::Uuid;

mod lifecycle;
mod persistence;

pub use self::lifecycle::*;
pub use self::persistence::*;

const U32_MODULUS: i64 = 4_294_967_296;

pub use northstar_session_core::SmMucMembership;

#[derive(Clone, Debug)]
pub struct SmSessionSnapshot {
    pub inbound_h: u32,
    pub outbound_h: u32,
    pub acked_h: u32,
    pub available: bool,
    pub carbons: bool,
    pub priority: i16,
    pub blocklist_requested: bool,
    pub roster_requested: bool,
    pub active_privacy_list: Option<String>,
    pub privacy_requested: bool,
    pub peer_ip: IpAddr,
    pub user_agent_id: Option<Uuid>,
    pub joined_rooms: Vec<SmMucMembership>,
    pub directed_presence: Vec<String>,
    pub last_presence: Option<String>,
    pub unacked: Vec<outbound::SmUnackedStanza>,
}

#[derive(Clone, Debug)]
pub struct SmResumeClaim {
    pub session_id: Uuid,
    pub claim_token: Uuid,
    /// Conservative process-clock deadline for the exact database claim. It
    /// is measured after acquiring the pool connection and immediately before
    /// invoking the authority function, so local waiters cannot outlive the
    /// persisted `claimed_until` lease or lose time to pool acquisition.
    pub claim_deadline: std::time::Instant,
    pub full_jid: String,
    pub resource: String,
    pub resume_timeout_seconds: u64,
    pub inbound_h: u32,
    pub acked_h: u32,
    pub available: bool,
    pub carbons: bool,
    pub priority: i16,
    pub blocklist_requested: bool,
    pub roster_requested: bool,
    pub active_privacy_list: Option<String>,
    pub privacy_requested: bool,
    pub user_agent_id: Option<Uuid>,
    pub joined_rooms: Vec<SmMucMembership>,
    pub directed_presence: Vec<String>,
    pub last_presence: Option<String>,
    pub unacked: Vec<outbound::SmUnackedStanza>,
}

#[derive(Debug)]
pub enum SmClaimStatus {
    Claimed(Box<SmResumeClaim>),
    /// The bearer, account and binding are valid, but the old connection's
    /// bounded disconnect suspension (or another claim) has not completed.
    Pending(SmResumePending),
    Rejected,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SmPendingReason {
    Live,
    Claim,
    LiveAndClaim,
}

#[derive(Clone, Debug)]
pub struct SmResumePending {
    pub session_id: Uuid,
    pub old_connection_id: Uuid,
    pub full_jid: String,
    pub state_version: i64,
    /// Process-clock translation of the database's exact next possible state
    /// boundary. It is anchored before the authority statement, so query and
    /// network latency can only make the wake conservative (early), never
    /// extend the durable lease guessed by the application.
    pub retry_at: std::time::Instant,
    pub reason: SmPendingReason,
}

#[derive(Clone, Debug)]
pub struct ActivatedSmSession {
    pub outbound_h: u32,
    pub unacked: Vec<outbound::SmUnackedStanza>,
}

/// One MIX lease capability rotated while it crosses into durable XEP-0198
/// ownership.  The input token names the worker's one-shot hand-off lease;
/// the replacement token is private to the persisted SM queue.  Keeping both
/// values explicit lets the live protocol FIFO replace its stale capability
/// only after the transaction commits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SmMixLeaseRotation {
    pub previous: outbound::MixDelivery,
    pub current: outbound::MixDelivery,
}

/// Exact source rewrites committed by one SM queue replacement.
///
/// C2S sources are transferred by clearing their replay claim and retain the
/// same identity.  MIX sources are deliberately rotated, so only this result
/// may update the in-memory XEP-0198 FIFO after successful persistence.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SmQueueOwnershipResolution {
    pub mix_rotations: Vec<SmMixLeaseRotation>,
}

#[derive(Clone, Debug)]
pub struct CreatedSmSession {
    pub id: Uuid,
    pub ownership: SmQueueOwnershipResolution,
}

#[derive(Clone, Debug)]
pub struct SmCheckpointOutcome {
    pub updated: bool,
    pub ownership: SmQueueOwnershipResolution,
}

pub use crate::platform::config::SmIpPolicy;

#[cfg(test)]
pub fn peer_ip_matches(policy: SmIpPolicy, expected: IpAddr, actual: IpAddr) -> bool {
    match policy {
        SmIpPolicy::None => true,
        SmIpPolicy::Exact => expected == actual,
        SmIpPolicy::Subnet => match (expected, actual) {
            (IpAddr::V4(a), IpAddr::V4(b)) => {
                (u32::from(a) & 0xffff_ff00) == (u32::from(b) & 0xffff_ff00)
            }
            (IpAddr::V6(a), IpAddr::V6(b)) => {
                let a = u128::from_be_bytes(a.octets());
                let b = u128::from_be_bytes(b.octets());
                (a >> 64) == (b >> 64)
            }
            _ => false,
        },
    }
}

/// Result-only fixture API. Runtime callers require ownership rotations and
/// therefore use `create_sm_session_with_ownership_resolution` directly.
#[cfg(test)]
#[allow(clippy::too_many_arguments)]
pub async fn create_sm_session(
    pool: &PgPool,
    token_hash: &[u8; 32],
    user_id: Uuid,
    auth_generation: i64,
    full_jid: &str,
    resource: &str,
    server_domain: &str,
    connection_id: Uuid,
    snapshot: &SmSessionSnapshot,
    ttl_seconds: u64,
    live_lease_seconds: u64,
    _max_per_account: usize,
    _max_global: usize,
) -> Result<Uuid> {
    Ok(create_sm_session_with_ownership_resolution(
        pool,
        token_hash,
        user_id,
        auth_generation,
        full_jid,
        resource,
        server_domain,
        connection_id,
        snapshot,
        ttl_seconds,
        live_lease_seconds,
        _max_per_account,
        _max_global,
    )
    .await?
    .id)
}

/// Create a resumable SM row and report any MIX capability rotations committed
/// while its initial queue becomes the recoverability owner.
#[allow(clippy::too_many_arguments)]
pub async fn create_sm_session_with_ownership_resolution(
    pool: &PgPool,
    token_hash: &[u8; 32],
    user_id: Uuid,
    auth_generation: i64,
    full_jid: &str,
    resource: &str,
    server_domain: &str,
    connection_id: Uuid,
    snapshot: &SmSessionSnapshot,
    ttl_seconds: u64,
    live_lease_seconds: u64,
    _max_per_account: usize,
    _max_global: usize,
) -> Result<CreatedSmSession> {
    validate_snapshot(snapshot, usize::MAX, usize::MAX)?;
    let (joined_rooms, directed_presence) = canonical_snapshot_identities(snapshot)?;
    let full_jid = northstar_xmpp_types::jid::canonical_session_key(full_jid)?;
    let resource = northstar_xmpp_types::jid::prepare_resourcepart(resource)?;
    anyhow::ensure!(
        northstar_xmpp_types::jid::CanonicalJid::parse(&full_jid)?.resourcepart()
            == Some(resource.as_str()),
        "SM resource does not match full JID"
    );
    let server_domain = northstar_xmpp_types::jid::prepare_domainpart(server_domain)?;
    let ttl = seconds_i64(ttl_seconds, "SM resume TTL")?;
    let live_lease = seconds_i64(live_lease_seconds, "SM live lease")?;
    let mut transaction = pool.begin().await?;
    // The bound route normally owns this lease already. Direct/internal SM
    // callers reserve it here as an idempotent safety net. Deployment-wide and
    // per-account SM state are admitted by the INSERT trigger below; neither
    // path scans or serializes the complete session table.
    match super::reserve_live_session_in_transaction(
        &mut transaction,
        connection_id,
        user_id,
        &full_jid,
        live_lease_seconds,
        false,
    )
    .await?
    {
        super::LiveSessionReservation::Reserved => {}
        super::LiveSessionReservation::CapacityExhausted => {
            anyhow::bail!("deployment live-session capacity exhausted")
        }
        super::LiveSessionReservation::Conflict
        | super::LiveSessionReservation::ReplacedResumable => {
            anyhow::bail!("durable SM live-session reservation conflicts")
        }
    }
    let authorized = sqlx::query_scalar::<_, String>(
        "SELECT username FROM users
         WHERE id=$1 AND auth_generation=$2 AND NOT is_disabled
         FOR KEY SHARE",
    )
    .bind(user_id)
    .bind(auth_generation)
    .fetch_optional(&mut *transaction)
    .await?;
    let Some(username) = authorized else {
        transaction.rollback().await?;
        anyhow::bail!("durable SM authorization changed");
    };
    anyhow::ensure!(
        northstar_xmpp_types::jid::canonical_bare_key(&full_jid)?
            == northstar_xmpp_types::jid::canonicalize_bare(&format!(
                "{username}@{server_domain}"
            ))?,
        "durable SM full JID does not belong to its account on this server"
    );
    let id = Uuid::new_v4();
    let created: bool = sqlx::query_scalar(
        "SELECT northstar_sm_create(
            $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,
            $18,$19,$20::inet,$21,$22,$23,$24,$25,$26)",
    )
    .bind(id)
    .bind(token_hash.as_slice())
    .bind(user_id)
    .bind(auth_generation)
    .bind(&full_jid)
    .bind(&resource)
    .bind(&server_domain)
    .bind(connection_id)
    .bind(ttl)
    .bind(i64::from(snapshot.inbound_h))
    .bind(i64::from(snapshot.outbound_h))
    .bind(i64::from(snapshot.acked_h))
    .bind(snapshot.available)
    .bind(snapshot.carbons)
    .bind(snapshot.priority)
    .bind(snapshot.blocklist_requested)
    .bind(snapshot.roster_requested)
    .bind(&snapshot.active_privacy_list)
    .bind(snapshot.privacy_requested)
    .bind(snapshot.peer_ip.to_string())
    .bind(snapshot.user_agent_id)
    .bind(joined_rooms)
    .bind(directed_presence)
    .bind(&snapshot.last_presence)
    .bind(live_lease)
    .bind(ttl)
    .fetch_one(&mut *transaction)
    .await?;
    anyhow::ensure!(created, "durable SM creation authority rejected");
    let ownership = replace_queue(&mut transaction, id, &snapshot.unacked, &[]).await?;
    transaction.commit().await?;
    Ok(CreatedSmSession { id, ownership })
}

#[allow(clippy::too_many_arguments)]
pub async fn checkpoint_sm_session_with_ownership_resolution(
    pool: &PgPool,
    id: Uuid,
    connection_id: Uuid,
    snapshot: &SmSessionSnapshot,
    ttl_seconds: u64,
    live_lease_seconds: u64,
    max_stanzas: usize,
    max_bytes: usize,
) -> Result<SmCheckpointOutcome> {
    checkpoint_sm_session_and_acknowledge_with_ownership_resolution(
        pool,
        id,
        connection_id,
        snapshot,
        &[],
        ttl_seconds,
        live_lease_seconds,
        max_stanzas,
        max_bytes,
    )
    .await
}

/// Result-only fixture API. Runtime checkpointing consumes the ownership
/// outcome from `checkpoint_sm_session_and_acknowledge_with_ownership_resolution`.
#[cfg(test)]
#[allow(clippy::too_many_arguments)]
pub async fn checkpoint_sm_session_and_acknowledge(
    pool: &PgPool,
    id: Uuid,
    connection_id: Uuid,
    snapshot: &SmSessionSnapshot,
    acknowledged: &[outbound::SmUnackedStanza],
    ttl_seconds: u64,
    live_lease_seconds: u64,
    max_stanzas: usize,
    max_bytes: usize,
) -> Result<bool> {
    Ok(
        checkpoint_sm_session_and_acknowledge_with_ownership_resolution(
            pool,
            id,
            connection_id,
            snapshot,
            acknowledged,
            ttl_seconds,
            live_lease_seconds,
            max_stanzas,
            max_bytes,
        )
        .await?
        .updated,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn checkpoint_sm_session_and_acknowledge_observed(
    pool: &PgPool,
    id: Uuid,
    connection_id: Uuid,
    snapshot: &SmSessionSnapshot,
    acknowledged: &[outbound::SmUnackedStanza],
    ttl_seconds: u64,
    live_lease_seconds: u64,
    max_stanzas: usize,
    max_bytes: usize,
    observation: Option<&northstar_delivery_core::sm_ownership::Request>,
) -> Result<SmCheckpointOutcome> {
    if let Some(request) = observation {
        let binding = request.binding();
        anyhow::ensure!(
            binding.session_id == Some(id)
                && binding.connection_id == connection_id
                && binding.inbound_h == snapshot.inbound_h
                && binding.outbound_h == snapshot.outbound_h
                && binding.acked_h == snapshot.acked_h
                && binding
                    .acknowledged
                    .iter()
                    .copied()
                    .eq(acknowledged.iter().map(|entry| entry.source))
                && binding
                    .remaining
                    .iter()
                    .copied()
                    .eq(snapshot.unacked.iter().map(|entry| entry.source)),
            "SM database projection changed its bound cut"
        );
        request.validate_binding(binding)?;
    }
    validate_snapshot(snapshot, max_stanzas, max_bytes)?;
    let ttl = seconds_i64(ttl_seconds, "SM resume TTL")?;
    let live_lease = seconds_i64(live_lease_seconds, "SM live lease")?;
    let mut transaction = pool.begin().await?;
    let updated = update_snapshot(
        &mut transaction,
        id,
        connection_id,
        snapshot,
        ttl,
        live_lease,
        false,
    )
    .await?;
    if !updated {
        if let Some(request) = observation {
            northstar_delivery_core::sm_ownership::rollback_observed(
                transaction.rollback(),
                request,
            )
            .await?;
        } else {
            transaction.rollback().await?;
        }
        return Ok(SmCheckpointOutcome {
            updated: false,
            ownership: SmQueueOwnershipResolution::default(),
        });
    }
    let mut settled = observation.map(|_| Vec::new());
    let ownership = replace_queue_inner(
        &mut transaction,
        id,
        &snapshot.unacked,
        acknowledged,
        settled.as_mut(),
    )
    .await?;
    if let Some(request) = observation {
        let fact = northstar_delivery_core::sm_ownership::CommitFact::Checkpoint {
            rotations: ownership
                .mix_rotations
                .iter()
                .map(
                    |rotation| northstar_delivery_core::sm_ownership::MixRotation {
                        previous: rotation.previous,
                        current: rotation.current,
                    },
                )
                .collect(),
            settled: settled.expect("observed checkpoint owns settlement facts"),
        };
        // Transaction atomicity is unchanged. A lost COMMIT response leaves
        // this entire prepared outcome unknown; it does not prove rollback.
        northstar_delivery_core::sm_ownership::commit_observed(transaction.commit(), request, fact)
            .await?;
    } else {
        transaction.commit().await?;
    }
    Ok(SmCheckpointOutcome {
        updated: true,
        ownership,
    })
}

#[cfg(test)]
pub async fn suspend_sm_session(
    pool: &PgPool,
    id: Uuid,
    connection_id: Uuid,
    snapshot: &SmSessionSnapshot,
    ttl_seconds: u64,
    max_stanzas: usize,
    max_bytes: usize,
) -> Result<bool> {
    validate_snapshot(snapshot, max_stanzas, max_bytes)?;
    let ttl = seconds_i64(ttl_seconds, "SM resume TTL")?;
    let mut transaction = pool.begin().await?;
    let updated =
        update_snapshot(&mut transaction, id, connection_id, snapshot, ttl, 0, true).await?;
    if !updated {
        transaction.rollback().await?;
        return Ok(false);
    }
    anyhow::ensure!(
        super::extend_live_session_lease_in_transaction(
            &mut transaction,
            connection_id,
            ttl_seconds,
        )
        .await?,
        "suspended SM session lost its deployment capacity lease"
    );
    replace_queue(&mut transaction, id, &snapshot.unacked, &[]).await?;
    transaction.commit().await?;
    Ok(true)
}

/// Persist an exact activated resume after route publication aborts or its
/// transport is lost. The exact SM epoch, connection incarnation, account and
/// authorization generation must still agree, and the account's credential
/// generation must remain current. A revocation or newer owner therefore wins
/// instead of being overwritten by this delayed suspension.
#[allow(clippy::too_many_arguments)]
pub async fn suspend_activated_sm_resume_exact(
    pool: &PgPool,
    id: Uuid,
    connection_id: Uuid,
    user_id: Uuid,
    expected_auth_generation: i64,
    snapshot: &SmSessionSnapshot,
    ttl_seconds: u64,
    max_stanzas: usize,
    max_bytes: usize,
) -> Result<bool> {
    validate_snapshot(snapshot, max_stanzas, max_bytes)?;
    let ttl = seconds_i64(ttl_seconds, "SM resume TTL")?;
    let mut transaction = pool.begin().await?;
    let exact_owner: String =
        sqlx::query_scalar("SELECT northstar_sm_exact_owner_state($1,$2,$3,$4)")
            .bind(id)
            .bind(connection_id)
            .bind(user_id)
            .bind(expected_auth_generation)
            .fetch_one(&mut *transaction)
            .await?;
    if exact_owner == "missing" {
        transaction.rollback().await?;
        return Ok(false);
    }
    // A transport connection UUID is never reused. Therefore an already
    // resumable row with this exact (session, connection, account, credential
    // generation) tuple can only be the committed result of this suspension.
    // Treat it as an idempotent replay so a lost COMMIT response does not make
    // cleanup discard or indefinitely seal the associated MUC FIFO.
    if exact_owner == "resumable" {
        transaction.rollback().await?;
        return Ok(true);
    }
    anyhow::ensure!(
        update_snapshot(&mut transaction, id, connection_id, snapshot, ttl, 0, true,).await?,
        "exact activated SM owner disappeared during compensation"
    );
    anyhow::ensure!(
        super::extend_live_session_lease_in_transaction(
            &mut transaction,
            connection_id,
            ttl_seconds,
        )
        .await?,
        "exact SM suspension lost its deployment capacity lease"
    );
    sqlx::query(
        "DELETE FROM privacy_active_sessions
          WHERE owner_id=$1 AND connection_id=$2",
    )
    .bind(user_id)
    .bind(connection_id)
    .execute(&mut *transaction)
    .await?;
    replace_queue(&mut transaction, id, &snapshot.unacked, &[]).await?;
    transaction.commit().await?;
    Ok(true)
}

#[allow(clippy::too_many_arguments)]
#[cfg(test)]
pub async fn claim_sm_session(
    pool: &PgPool,
    token_hash: &[u8; 32],
    user_id: Uuid,
    claimant_ip: IpAddr,
    claimant_device: Option<Uuid>,
    ip_policy: SmIpPolicy,
    require_same_device: bool,
    claim_lease_seconds: u64,
) -> Result<Option<SmResumeClaim>> {
    Ok(
        match claim_sm_session_status(
            pool,
            token_hash,
            user_id,
            claimant_ip,
            claimant_device,
            ip_policy,
            require_same_device,
            claim_lease_seconds,
        )
        .await?
        {
            SmClaimStatus::Claimed(claim) => Some(*claim),
            SmClaimStatus::Pending(_) | SmClaimStatus::Rejected => None,
        },
    )
}

#[allow(clippy::too_many_arguments)]
pub async fn activate_claimed_sm_session_in_transaction(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    session_id: Uuid,
    claim_token: Uuid,
    connection_id: Uuid,
    client_h: u32,
    acknowledged_count: usize,
    peer_ip: IpAddr,
    user_agent_id: Option<Uuid>,
    ttl_seconds: u64,
    live_lease_seconds: u64,
    max_stanzas: usize,
    max_bytes: usize,
) -> Result<Option<ActivatedSmSession>> {
    let ttl = seconds_i64(ttl_seconds, "SM resume TTL")?;
    let lease = seconds_i64(live_lease_seconds, "SM live lease")?;
    let authorized = sqlx::query("SELECT * FROM northstar_sm_claim_authority($1,$2)")
        .bind(session_id)
        .bind(claim_token)
        .fetch_optional(&mut **transaction)
        .await?;
    if authorized.is_none() {
        return Ok(None);
    }
    let authorized = authorized.expect("checked above");
    let old_connection_id: Uuid = authorized.try_get("old_connection_id")?;
    let user_id: Uuid = authorized.try_get("user_id")?;
    let full_jid: String = authorized.try_get("full_jid")?;
    if matches!(
        super::transfer_claimed_sm_live_session_in_transaction(
            transaction,
            session_id,
            claim_token,
            old_connection_id,
            connection_id,
            user_id,
            &full_jid,
            live_lease_seconds,
        )
        .await?,
        super::LiveSessionReservation::Conflict | super::LiveSessionReservation::CapacityExhausted
    ) {
        return Ok(None);
    }
    let updated: Option<i64> =
        sqlx::query_scalar("SELECT northstar_sm_activate($1,$2,$3,$4,$5::inet,$6,$7,$8)")
            .bind(session_id)
            .bind(claim_token)
            .bind(connection_id)
            .bind(i64::from(client_h))
            .bind(peer_ip.to_string())
            .bind(user_agent_id)
            .bind(lease)
            .bind(ttl)
            .fetch_optional(&mut **transaction)
            .await?;
    let Some(outbound_h) = updated else {
        return Ok(None);
    };
    let queue = fetch_queue(transaction, session_id).await?;
    if acknowledged_count > queue.len() {
        return Ok(None);
    }
    let acknowledged = queue
        .iter()
        .take(acknowledged_count)
        .cloned()
        .collect::<Vec<_>>();
    let remaining = queue
        .into_iter()
        .skip(acknowledged_count)
        .collect::<Vec<_>>();
    validate_queue(&remaining, max_stanzas, max_bytes)?;
    replace_queue(transaction, session_id, &remaining, &acknowledged).await?;
    let outbound_h = u32::try_from(outbound_h).context("invalid durable SM outbound counter")?;
    Ok(Some(ActivatedSmSession {
        outbound_h,
        unacked: remaining,
    }))
}

#[cfg(test)]
pub async fn take_sm_sessions_for_full_jid_teardown(
    pool: &PgPool,
    full_jid: &str,
    lease_seconds: u64,
) -> Result<SmTeardownBatch> {
    let full_jid = northstar_xmpp_types::jid::canonical_session_key(full_jid)?;
    take_sm_teardown_scope(
        pool,
        "full",
        None,
        None,
        None,
        Some(&full_jid),
        lease_seconds,
    )
    .await
}

/// Lock one freshly claimed MIX recipient and turn the worker lease into an
/// SM-private capability.  The fixed source -> BOSH-fence order matches the
/// BOSH hand-off path, so neither transport can form a reverse lock cycle.
async fn rotate_new_mix_source_for_sm_transfer(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    previous: outbound::MixDelivery,
) -> Result<outbound::MixDelivery> {
    let row = sqlx::query(
        "SELECT lease_token,lease_until>clock_timestamp() AS active
           FROM mix_delivery_recipients
          WHERE delivery_id=$1 FOR UPDATE",
    )
    .bind(previous.delivery_id)
    .fetch_optional(&mut **transaction)
    .await?;
    let Some(row) = row else {
        anyhow::bail!("MIX delivery disappeared before SM ownership transfer");
    };
    let lease_token: Option<Uuid> = row.try_get("lease_token")?;
    anyhow::ensure!(
        lease_token == Some(previous.lease_token),
        "MIX delivery lease changed before SM ownership transfer"
    );
    let active: Option<bool> = row.try_get("active")?;
    anyhow::ensure!(
        active == Some(true),
        "MIX delivery lease expired before SM ownership transfer"
    );
    lock_mix_bosh_fence_for_sm_transfer(transaction, previous.delivery_id).await?;
    let sm_owned: bool = sqlx::query_scalar(
        "SELECT EXISTS(
             SELECT 1 FROM sm_resume_stanzas WHERE mix_delivery_id=$1
         )",
    )
    .bind(previous.delivery_id)
    .fetch_one(&mut **transaction)
    .await?;
    anyhow::ensure!(
        !sm_owned,
        "MIX delivery is already owned by another SM queue"
    );
    // A remote-node hand-off carries this exact rotated token. Consume its
    // bounded cluster fence before recording the next SM owner so a target
    // node which later exits cannot release a source now owned by XEP-0198.
    super::mix::consume_mix_cluster_delivery_fence_tx(transaction, previous).await?;
    let current = outbound::MixDelivery {
        delivery_id: previous.delivery_id,
        lease_token: Uuid::new_v4(),
    };
    let updated = sqlx::query(
        "UPDATE mix_delivery_recipients
            SET lease_token=$3
          WHERE delivery_id=$1 AND lease_token=$2",
    )
    .bind(previous.delivery_id)
    .bind(previous.lease_token)
    .bind(current.lease_token)
    .execute(&mut **transaction)
    .await?
    .rows_affected();
    anyhow::ensure!(
        updated == 1,
        "MIX delivery lease changed during SM ownership transfer"
    );
    Ok(current)
}

pub(crate) async fn acknowledge_transport_sources_observed(
    pool: &PgPool,
    sources: &[outbound::TransportOwnershipSource],
    observation: Option<&northstar_delivery_core::sm_ownership::Request>,
) -> Result<()> {
    if let Some(request) = observation {
        anyhow::ensure!(
            request.binding().session_id.is_none()
                && sources.iter().copied().eq(request
                    .binding()
                    .acknowledged
                    .iter()
                    .flatten()
                    .copied()),
            "SM database acknowledgement sources changed"
        );
        request.validate_binding(request.binding())?;
    }
    if sources.is_empty() {
        if let Some(request) = observation {
            request.no_persistence()?;
        }
        return Ok(());
    }

    let mut seen = HashSet::with_capacity(sources.len());
    for source in sources {
        anyhow::ensure!(
            seen.insert(durable_source_key(*source)),
            "duplicate durable transport source in one acknowledgement batch"
        );
    }

    // This is the same global order used by queue replacement: C2S source
    // rows first, then MIX source rows.  Both paths inspect their BOSH/SM
    // owners only after holding the source row, so an ownership hand-off
    // cannot slip between validation and deletion.
    let mut c2s = sources
        .iter()
        .filter_map(|source| (*source).c2s())
        .collect::<Vec<_>>();
    c2s.sort_unstable_by_key(|delivery| (delivery.recipient_id, delivery.message_id));
    let mut mix = sources
        .iter()
        .filter_map(|source| (*source).mix())
        .collect::<Vec<_>>();
    mix.sort_unstable_by_key(|delivery| delivery.delivery_id);

    let mut transaction = pool.begin().await?;
    let mut present_c2s = Vec::with_capacity(c2s.len());
    for delivery in &c2s {
        let row = sqlx::query(
            "SELECT delivery_claim_id FROM offline_messages
              WHERE recipient_id=$1 AND id=$2 FOR UPDATE",
        )
        .bind(delivery.recipient_id)
        .bind(delivery.message_id)
        .fetch_optional(&mut *transaction)
        .await?;
        match (row, delivery.claim_id) {
            // The legacy live C2S path treats a missing unclaimed row as an
            // idempotent completion.  Preserve that established behaviour;
            // a claimed row must never be silently accepted as missing.
            (None, None) => present_c2s.push(false),
            (None, Some(_)) => {
                anyhow::bail!("offline delivery claim was lost before acknowledgement")
            }
            (Some(row), Some(expected_claim)) => {
                anyhow::ensure!(
                    row.try_get::<Option<Uuid>, _>("delivery_claim_id")? == Some(expected_claim),
                    "offline delivery claim was lost before acknowledgement"
                );
                present_c2s.push(true);
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
                present_c2s.push(true);
            }
        }
    }

    for delivery in &mix {
        let row = sqlx::query(
            "SELECT lease_token FROM mix_delivery_recipients
              WHERE delivery_id=$1 FOR UPDATE",
        )
        .bind(delivery.delivery_id)
        .fetch_optional(&mut *transaction)
        .await?;
        let Some(row) = row else {
            anyhow::bail!("MIX delivery lease was lost before acknowledgement");
        };
        anyhow::ensure!(
            row.try_get::<Option<Uuid>, _>("lease_token")? == Some(delivery.lease_token),
            "MIX delivery lease was lost before acknowledgement"
        );
        let transport_owned: bool = sqlx::query_scalar(
            "SELECT EXISTS(
                 SELECT 1 FROM sm_resume_stanzas WHERE mix_delivery_id=$1
             ) OR EXISTS(
                 SELECT 1 FROM mix_bosh_delivery_fences WHERE delivery_id=$1
             )",
        )
        .bind(delivery.delivery_id)
        .fetch_one(&mut *transaction)
        .await?;
        anyhow::ensure!(
            !transport_owned,
            "direct transport acknowledgement does not own the MIX delivery"
        );
    }

    let mut deleted = observation.map(|_| Vec::new());
    let mut absent_unclaimed = observation.map(|_| Vec::new());
    for (delivery, present) in c2s.iter().zip(present_c2s) {
        if !present {
            if let Some(absent) = absent_unclaimed.as_mut() {
                absent.push(*delivery);
            }
            continue;
        }
        let removed = sqlx::query(
            "DELETE FROM offline_messages
              WHERE recipient_id=$1 AND id=$2
                AND delivery_claim_id IS NOT DISTINCT FROM $3",
        )
        .bind(delivery.recipient_id)
        .bind(delivery.message_id)
        .bind(delivery.claim_id)
        .execute(&mut *transaction)
        .await?
        .rows_affected();
        anyhow::ensure!(
            removed == 1,
            "durable C2S delivery disappeared during acknowledgement"
        );
        if let Some(deleted) = deleted.as_mut() {
            deleted.push(outbound::TransportOwnershipSource::C2s(*delivery));
        }
    }
    for delivery in &mix {
        let removed = sqlx::query(
            "DELETE FROM mix_delivery_recipients
              WHERE delivery_id=$1 AND lease_token=$2",
        )
        .bind(delivery.delivery_id)
        .bind(delivery.lease_token)
        .execute(&mut *transaction)
        .await?
        .rows_affected();
        anyhow::ensure!(
            removed == 1,
            "MIX delivery lease changed during acknowledgement"
        );
        if let Some(deleted) = deleted.as_mut() {
            deleted.push(outbound::TransportOwnershipSource::Mix(*delivery));
        }
    }
    if let Some(request) = observation {
        let fact = northstar_delivery_core::sm_ownership::CommitFact::UnpersistedAck {
            deleted: deleted.expect("observed acknowledgement owns deletion facts"),
            absent_unclaimed: absent_unclaimed
                .expect("observed acknowledgement owns absent-row facts"),
        };
        northstar_delivery_core::sm_ownership::commit_observed(transaction.commit(), request, fact)
            .await?;
    } else {
        transaction.commit().await?;
    }
    tracing::debug!(
        c2s = c2s.len(),
        mix = mix.len(),
        "atomically acknowledged durable transport source batch"
    );
    Ok(())
}

fn counter(row: &sqlx::postgres::PgRow, column: &str) -> Result<u32> {
    let value: i64 = row.try_get(column)?;
    if !(0..U32_MODULUS).contains(&value) {
        anyhow::bail!("invalid durable SM counter");
    }
    Ok(value as u32)
}

fn seconds_i64(seconds: u64, name: &str) -> Result<i64> {
    i64::try_from(seconds).with_context(|| format!("{name} is too large"))
}

#[cfg(test)]
#[path = "sm_tests.rs"]
mod tests;
