use anyhow::{Context, Result};
use sqlx::{PgPool, Row};
use std::{
    collections::{HashMap, HashSet},
    net::IpAddr,
};
use uuid::Uuid;

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
    pub unacked: Vec<crate::outbound::SmUnackedStanza>,
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
    pub unacked: Vec<crate::outbound::SmUnackedStanza>,
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

/// The durable presence/MUC state leased for teardown. The row remains until
/// `finalize_sm_teardown` succeeds, so a process crash can retry the
/// idempotent side effects after the bounded lease expires.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SmTeardownSnapshot {
    pub session_id: Uuid,
    pub teardown_token: Uuid,
    pub user_id: Uuid,
    pub username: String,
    pub full_jid: String,
    pub available: bool,
    pub active_privacy_list: Option<String>,
    pub joined_rooms: Vec<SmMucMembership>,
    pub directed_presence: Vec<String>,
}

#[derive(Debug, Default)]
pub struct SmTeardownBatch {
    pub snapshots: Vec<SmTeardownSnapshot>,
    /// Rows owned by a still-live resume/teardown claim. Callers must retry;
    /// an empty snapshot list is not completion while this is non-zero.
    pub pending: usize,
}

#[derive(Clone, Debug)]
pub struct ActivatedSmSession {
    pub outbound_h: u32,
    pub unacked: Vec<crate::outbound::SmUnackedStanza>,
}

/// One MIX lease capability rotated while it crosses into durable XEP-0198
/// ownership.  The input token names the worker's one-shot hand-off lease;
/// the replacement token is private to the persisted SM queue.  Keeping both
/// values explicit lets the live protocol FIFO replace its stale capability
/// only after the transaction commits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SmMixLeaseRotation {
    pub previous: crate::outbound::MixDelivery,
    pub current: crate::outbound::MixDelivery,
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

pub use crate::services::sm::SmIpPolicy;

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
    let full_jid = crate::jid::canonical_session_key(full_jid)?;
    let resource = crate::jid::prepare_resourcepart(resource)?;
    anyhow::ensure!(
        crate::jid::CanonicalJid::parse(&full_jid)?.resourcepart() == Some(resource.as_str()),
        "SM resource does not match full JID"
    );
    let server_domain = crate::jid::prepare_domainpart(server_domain)?;
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
        crate::jid::canonical_bare_key(&full_jid)?
            == crate::jid::canonicalize_bare(&format!("{username}@{server_domain}"))?,
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

/// Remove only the named MUC memberships from one exact live SM owner.  This
/// narrow reconciliation primitive is used after a post-replay local ABA
/// check: filtering the current JSON value in PostgreSQL preserves any newer
/// acknowledgement, outbound queue update, or MUC join committed by the same
/// transport while the post-action task was scheduled.
pub async fn remove_live_sm_muc_memberships(
    pool: &PgPool,
    id: Uuid,
    connection_id: Uuid,
    memberships: &[SmMucMembership],
) -> Result<bool> {
    if memberships.is_empty() {
        return Ok(true);
    }
    anyhow::ensure!(memberships.len() <= 256, "too many SM MUC memberships");
    let mut canonical = Vec::with_capacity(memberships.len());
    let mut rooms = std::collections::BTreeSet::new();
    for membership in memberships {
        let room_jid = crate::jid::canonicalize_bare(&membership.room_jid)?;
        let nick = crate::xmpp::xml_util::prepare_muc_nick(&membership.nick)?;
        anyhow::ensure!(
            rooms.insert((room_jid.clone(), nick.clone())),
            "duplicate SM MUC membership"
        );
        canonical.push(SmMucMembership { room_jid, nick });
    }
    let removals = serde_json::to_value(canonical)?;
    Ok(
        sqlx::query_scalar("SELECT northstar_sm_remove_memberships($1,$2,$3)")
            .bind(id)
            .bind(connection_id)
            .bind(removals)
            .fetch_one(pool)
            .await?,
    )
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
    acknowledged: &[crate::outbound::SmUnackedStanza],
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
pub async fn checkpoint_sm_session_and_acknowledge_with_ownership_resolution(
    pool: &PgPool,
    id: Uuid,
    connection_id: Uuid,
    snapshot: &SmSessionSnapshot,
    acknowledged: &[crate::outbound::SmUnackedStanza],
    ttl_seconds: u64,
    live_lease_seconds: u64,
    max_stanzas: usize,
    max_bytes: usize,
) -> Result<SmCheckpointOutcome> {
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
        transaction.rollback().await?;
        return Ok(SmCheckpointOutcome {
            updated: false,
            ownership: SmQueueOwnershipResolution::default(),
        });
    }
    let ownership = replace_queue(&mut transaction, id, &snapshot.unacked, acknowledged).await?;
    transaction.commit().await?;
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
pub async fn claim_sm_session_status(
    pool: &PgPool,
    token_hash: &[u8; 32],
    user_id: Uuid,
    claimant_ip: IpAddr,
    claimant_device: Option<Uuid>,
    ip_policy: SmIpPolicy,
    require_same_device: bool,
    claim_lease_seconds: u64,
) -> Result<SmClaimStatus> {
    let lease = seconds_i64(claim_lease_seconds, "SM claim lease")?;
    let mut transaction = pool.begin().await?;
    let claim_token = Uuid::new_v4();
    // Anchor database wall-clock durations to a monotonic point captured
    // before the authority statement. Query/commit latency therefore consumes
    // the lease instead of accidentally extending it in process time.
    let authority_probe_started = std::time::Instant::now();
    let row = sqlx::query("SELECT * FROM northstar_sm_claim($1,$2,$3::inet,$4,$5,$6,$7,$8)")
        .bind(token_hash.as_slice())
        .bind(user_id)
        .bind(claimant_ip.to_string())
        .bind(claimant_device)
        .bind(match ip_policy {
            SmIpPolicy::None => "none",
            SmIpPolicy::Exact => "exact",
            SmIpPolicy::Subnet => "subnet",
        })
        .bind(require_same_device)
        .bind(claim_token)
        .bind(lease)
        .fetch_one(&mut *transaction)
        .await?;
    match row.try_get::<String, _>("status")?.as_str() {
        "rejected" => {
            transaction.commit().await?;
            return Ok(SmClaimStatus::Rejected);
        }
        "pending" => {
            let session_id: Uuid = row.try_get("session_id")?;
            let old_connection_id: Uuid = row.try_get("old_connection_id")?;
            let full_jid: String = row.try_get("full_jid")?;
            let state_version: i64 = row.try_get("state_version")?;
            let authority_now: chrono::DateTime<chrono::Utc> = row.try_get("authority_now")?;
            let retry_at: chrono::DateTime<chrono::Utc> = row.try_get("retry_at")?;
            anyhow::ensure!(
                !session_id.is_nil()
                    && !old_connection_id.is_nil()
                    && state_version > 0
                    && retry_at >= authority_now,
                "invalid pending SM authority projection"
            );
            let retry_after = retry_at
                .signed_duration_since(authority_now)
                .to_std()
                .context("invalid pending SM retry boundary")?;
            let retry_at = authority_probe_started
                .checked_add(retry_after)
                .context("pending SM retry boundary overflow")?;
            let reason = match row.try_get::<String, _>("pending_reason")?.as_str() {
                "live-owner" => SmPendingReason::Live,
                "claim-owner" => SmPendingReason::Claim,
                "live-and-claim-owner" => SmPendingReason::LiveAndClaim,
                other => anyhow::bail!("unknown pending SM authority reason: {other}"),
            };
            transaction.commit().await?;
            return Ok(SmClaimStatus::Pending(SmResumePending {
                session_id,
                old_connection_id,
                full_jid,
                state_version,
                retry_at,
                reason,
            }));
        }
        "claimed" => {}
        other => anyhow::bail!("unknown SM claim capability outcome: {other}"),
    }
    let session_id: Uuid = row.try_get("session_id")?;
    if session_id.is_nil() {
        transaction.commit().await?;
        return Ok(SmClaimStatus::Rejected);
    }
    let unacked = fetch_queue(&mut transaction, session_id).await?;
    let memberships = serde_json::from_value(row.try_get::<serde_json::Value, _>("joined_rooms")?)
        .context("invalid durable SM MUC membership JSON")?;
    let directed_presence =
        serde_json::from_value(row.try_get::<serde_json::Value, _>("directed_presence")?)
            .context("invalid durable SM directed-presence JSON")?;
    let authority_now: chrono::DateTime<chrono::Utc> = row.try_get("authority_now")?;
    let claimed_until: chrono::DateTime<chrono::Utc> = row.try_get("claimed_until")?;
    anyhow::ensure!(
        claimed_until > authority_now,
        "invalid claimed SM ownership deadline"
    );
    let claim_deadline = authority_probe_started
        .checked_add(
            claimed_until
                .signed_duration_since(authority_now)
                .to_std()
                .context("invalid claimed SM ownership duration")?,
        )
        .context("claimed SM ownership deadline overflow")?;
    let claim = SmResumeClaim {
        session_id,
        claim_token,
        claim_deadline,
        full_jid: row.try_get("full_jid")?,
        resource: row.try_get("resource")?,
        resume_timeout_seconds: u64::try_from(row.try_get::<i64, _>("resume_timeout_seconds")?)
            .context("invalid durable SM timeout")?,
        inbound_h: counter(&row, "inbound_h")?,
        acked_h: counter(&row, "acked_h")?,
        available: row.try_get("available")?,
        carbons: row.try_get("carbons")?,
        priority: row.try_get("priority")?,
        blocklist_requested: row.try_get("blocklist_requested")?,
        roster_requested: row.try_get("roster_requested")?,
        active_privacy_list: row.try_get("active_privacy_list")?,
        privacy_requested: row.try_get("privacy_requested")?,
        user_agent_id: row.try_get("user_agent_id")?,
        joined_rooms: memberships,
        directed_presence,
        last_presence: row.try_get("last_presence")?,
        unacked,
    };
    transaction.commit().await?;
    Ok(SmClaimStatus::Claimed(Box::new(claim)))
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

pub async fn release_sm_claim(pool: &PgPool, id: Uuid, claim_token: Uuid) -> Result<()> {
    sqlx::query_scalar::<_, bool>("SELECT northstar_sm_release_claim($1,$2)")
        .bind(id)
        .bind(claim_token)
        .fetch_one(pool)
        .await?;
    Ok(())
}

pub async fn revoke_sm_session(pool: &PgPool, id: Uuid) -> Result<()> {
    // A non-resumable connection can finish concurrently with an explicit
    // account-wide teardown.  It must not delete a row whose teardown lease
    // is currently owned by that operation; the lease holder needs the row
    // until its presence/MUC side effects are finalized.
    sqlx::query_scalar::<_, bool>("SELECT northstar_sm_revoke($1)")
        .bind(id)
        .fetch_one(pool)
        .await?;
    Ok(())
}

pub async fn take_sm_session_for_teardown(
    pool: &PgPool,
    id: Uuid,
    lease_seconds: u64,
) -> Result<Option<SmTeardownSnapshot>> {
    let mut batch =
        take_sm_teardown_scope(pool, "single", Some(id), None, None, None, lease_seconds).await?;
    Ok(batch.snapshots.pop())
}

pub async fn take_user_sm_sessions_for_teardown(
    pool: &PgPool,
    user_id: Uuid,
    lease_seconds: u64,
) -> Result<SmTeardownBatch> {
    take_sm_teardown_scope(pool, "user", None, Some(user_id), None, None, lease_seconds).await
}

/// Lease only resumable sessions authenticated before an authorization
/// rotation.  This makes a delayed/replayed teardown harmless to a browser
/// which has already logged in at the replacement generation.
pub async fn take_user_sm_sessions_before_auth_generation_for_teardown(
    pool: &PgPool,
    user_id: Uuid,
    auth_generation_exclusive: i64,
    lease_seconds: u64,
) -> Result<SmTeardownBatch> {
    anyhow::ensure!(
        auth_generation_exclusive > 0,
        "invalid SM authorization-generation teardown fence"
    );
    take_sm_teardown_scope(
        pool,
        "before_generation",
        None,
        Some(user_id),
        Some(auth_generation_exclusive),
        None,
        lease_seconds,
    )
    .await
}

pub async fn count_user_sm_rows_before_auth_generation(
    pool: &PgPool,
    user_id: Uuid,
    auth_generation_exclusive: i64,
) -> Result<i64> {
    anyhow::ensure!(
        auth_generation_exclusive > 0,
        "invalid SM authorization-generation count fence"
    );
    Ok(
        sqlx::query_scalar("SELECT northstar_sm_count('before_generation',$1,$2,NULL)")
            .bind(user_id)
            .bind(auth_generation_exclusive)
            .fetch_one(pool)
            .await?,
    )
}

#[cfg(test)]
pub async fn take_sm_sessions_for_full_jid_teardown(
    pool: &PgPool,
    full_jid: &str,
    lease_seconds: u64,
) -> Result<SmTeardownBatch> {
    let full_jid = crate::jid::canonical_session_key(full_jid)?;
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

pub async fn take_all_sm_sessions_for_teardown(
    pool: &PgPool,
    lease_seconds: u64,
) -> Result<SmTeardownBatch> {
    take_sm_teardown_scope(pool, "all", None, None, None, None, lease_seconds).await
}

pub async fn count_user_sm_rows(pool: &PgPool, user_id: Uuid) -> Result<i64> {
    Ok(
        sqlx::query_scalar("SELECT northstar_sm_count('user',$1,NULL,NULL)")
            .bind(user_id)
            .fetch_one(pool)
            .await?,
    )
}

pub async fn count_all_sm_rows(pool: &PgPool) -> Result<i64> {
    Ok(
        sqlx::query_scalar("SELECT northstar_sm_count('all',NULL,NULL,NULL)")
            .fetch_one(pool)
            .await?,
    )
}

pub async fn cleanup_expired_sm_sessions(
    pool: &PgPool,
    lease_seconds: u64,
) -> Result<Vec<SmTeardownSnapshot>> {
    // A claim acquired before expiry owns the row until its short claim lease
    // ends.  Skipping it here lets activation either extend the session or
    // fail before a later maintenance pass atomically acquires teardown.
    Ok(
        take_sm_teardown_scope(pool, "expired", None, None, None, None, lease_seconds)
            .await?
            .snapshots,
    )
}

pub async fn finalize_sm_teardown(
    pool: &PgPool,
    session_id: Uuid,
    teardown_token: Uuid,
) -> Result<bool> {
    // A live connection cancelled by this teardown can concurrently run its
    // own idempotent disconnect cleanup and delete the same durable row.  An
    // already-absent row is therefore success, while an existing row owned by
    // a different lease must still fail closed.
    Ok(
        sqlx::query_scalar("SELECT northstar_sm_finalize_teardown($1,$2)")
            .bind(session_id)
            .bind(teardown_token)
            .fetch_one(pool)
            .await?,
    )
}

#[allow(clippy::too_many_arguments)]
async fn take_sm_teardown_scope(
    pool: &PgPool,
    scope: &str,
    session_id: Option<Uuid>,
    user_id: Option<Uuid>,
    auth_generation: Option<i64>,
    full_jid: Option<&str>,
    lease_seconds: u64,
) -> Result<SmTeardownBatch> {
    let lease = seconds_i64(lease_seconds, "SM teardown lease")?;
    let token = Uuid::new_v4();
    let mut transaction = pool.begin().await?;
    let rows = sqlx::query("SELECT * FROM northstar_sm_take_teardown($1,$2,$3,$4,$5,$6,$7)")
        .bind(scope)
        .bind(session_id)
        .bind(user_id)
        .bind(auth_generation)
        .bind(full_jid)
        .bind(token)
        .bind(lease)
        .fetch_all(&mut *transaction)
        .await?;
    let pending: i64 =
        sqlx::query_scalar("SELECT northstar_sm_teardown_pending($1,$2,$3,$4,$5,$6)")
            .bind(scope)
            .bind(session_id)
            .bind(user_id)
            .bind(auth_generation)
            .bind(full_jid)
            .bind(token)
            .fetch_one(&mut *transaction)
            .await?;
    transaction.commit().await?;
    Ok(SmTeardownBatch {
        snapshots: rows
            .iter()
            .map(sm_teardown_snapshot)
            .collect::<Result<_>>()?,
        pending: usize::try_from(pending).context("SM pending count overflow")?,
    })
}

pub(crate) fn sm_teardown_snapshot(row: &sqlx::postgres::PgRow) -> Result<SmTeardownSnapshot> {
    Ok(SmTeardownSnapshot {
        session_id: row.try_get("id")?,
        teardown_token: row.try_get("teardown_token")?,
        user_id: row.try_get("user_id")?,
        username: row.try_get("username")?,
        full_jid: row.try_get("full_jid")?,
        available: row.try_get("available")?,
        active_privacy_list: row.try_get("active_privacy_list")?,
        joined_rooms: serde_json::from_value(row.try_get("joined_rooms")?)
            .context("invalid durable SM MUC membership JSON")?,
        directed_presence: serde_json::from_value(row.try_get("directed_presence")?)
            .context("invalid durable SM directed-presence JSON")?,
    })
}

pub async fn append_suspended_sm_stanza(
    pool: &PgPool,
    id: Uuid,
    volatile_source_id: Uuid,
    stanza: &str,
    max_stanzas: usize,
    max_bytes: usize,
) -> Result<bool> {
    if volatile_source_id.is_nil() || stanza.is_empty() || stanza.len() > 1024 * 1024 {
        return Ok(false);
    }
    let mut transaction = pool.begin().await?;
    let locked: Option<i64> = sqlx::query_scalar("SELECT northstar_sm_lock_suspended($1)")
        .bind(id)
        .fetch_optional(&mut *transaction)
        .await?;
    let Some(outbound) = locked else {
        transaction.rollback().await?;
        return Ok(false);
    };
    let already_stored: Option<String> = sqlx::query_scalar(
        "SELECT stanza FROM sm_resume_stanzas
          WHERE session_id=$1 AND volatile_source_id=$2",
    )
    .bind(id)
    .bind(volatile_source_id)
    .fetch_optional(&mut *transaction)
    .await?;
    if let Some(already_stored) = already_stored {
        let identical = already_stored == stanza;
        transaction.rollback().await?;
        return Ok(identical);
    }
    let (count, bytes): (i64, i64) = sqlx::query_as(
        "SELECT COUNT(*), COALESCE(SUM(byte_count), 0) FROM sm_resume_stanzas WHERE session_id=$1",
    )
    .bind(id)
    .fetch_one(&mut *transaction)
    .await?;
    if count >= i64::try_from(max_stanzas).unwrap_or(i64::MAX)
        || bytes.saturating_add(i64::try_from(stanza.len()).unwrap_or(i64::MAX))
            > i64::try_from(max_bytes).unwrap_or(i64::MAX)
    {
        transaction.rollback().await?;
        return Ok(false);
    }
    let position: i32 = sqlx::query_scalar(
        "SELECT COALESCE(MAX(position), -1) + 1 FROM sm_resume_stanzas WHERE session_id=$1",
    )
    .bind(id)
    .fetch_one(&mut *transaction)
    .await?;
    sqlx::query(
        "INSERT INTO sm_resume_stanzas(
             session_id,position,stanza,volatile_source_id
         ) VALUES($1,$2,$3,$4)",
    )
    .bind(id)
    .bind(position)
    .bind(stanza)
    .bind(volatile_source_id)
    .execute(&mut *transaction)
    .await?;
    let outbound = u32::try_from(outbound).context("invalid suspended SM outbound counter")?;
    let advanced: bool = sqlx::query_scalar("SELECT northstar_sm_advance_suspended($1,$2,$3)")
        .bind(id)
        .bind(i64::from(outbound))
        .bind(i64::from(outbound.wrapping_add(1)))
        .fetch_one(&mut *transaction)
        .await?;
    anyhow::ensure!(
        advanced,
        "suspended SM authority changed while appending stanza"
    );
    transaction.commit().await?;
    Ok(true)
}

async fn update_snapshot(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    id: Uuid,
    connection_id: Uuid,
    snapshot: &SmSessionSnapshot,
    ttl: i64,
    live_lease: i64,
    suspend: bool,
) -> Result<bool> {
    let (joined_rooms, directed_presence) = canonical_snapshot_identities(snapshot)?;
    Ok(sqlx::query_scalar(
        "SELECT northstar_sm_update_snapshot(
            $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13::inet,$14,$15,$16,
            $17,$18,$19,$20)",
    )
    .bind(id)
    .bind(connection_id)
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
    .bind(suspend)
    .bind(live_lease)
    .bind(ttl)
    .fetch_one(&mut **transaction)
    .await?)
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum SmDurableSourceKey {
    // `offline_messages.id` is globally primary-keyed.  Keying the queue by
    // that value also makes a malformed duplicate which names the same row
    // with a different recipient fail before any acknowledgement can commit.
    C2s(Uuid),
    Mix(Uuid),
}

fn durable_source_key(source: crate::outbound::TransportOwnershipSource) -> SmDurableSourceKey {
    match source {
        crate::outbound::TransportOwnershipSource::C2s(delivery) => {
            SmDurableSourceKey::C2s(delivery.message_id)
        }
        crate::outbound::TransportOwnershipSource::Mix(delivery) => {
            SmDurableSourceKey::Mix(delivery.delivery_id)
        }
    }
}

fn durable_source_from_columns(
    recipient_id: Option<Uuid>,
    message_id: Option<Uuid>,
    claim_id: Option<Uuid>,
    mix_delivery_id: Option<Uuid>,
    mix_delivery_lease_token: Option<Uuid>,
) -> Result<Option<crate::outbound::TransportOwnershipSource>> {
    match (
        (recipient_id, message_id, claim_id),
        (mix_delivery_id, mix_delivery_lease_token),
    ) {
        ((None, None, None), (None, None)) => Ok(None),
        ((Some(recipient_id), Some(message_id), claim_id), (None, None)) => Ok(Some(
            crate::outbound::TransportOwnershipSource::C2s(crate::outbound::DurableDelivery {
                recipient_id,
                message_id,
                claim_id,
            }),
        )),
        ((None, None, None), (Some(delivery_id), Some(lease_token))) => Ok(Some(
            crate::outbound::TransportOwnershipSource::Mix(crate::outbound::MixDelivery {
                delivery_id,
                lease_token,
            }),
        )),
        _ => anyhow::bail!("invalid mutually-exclusive durable source shape in SM queue"),
    }
}

fn source_map(
    entries: &[crate::outbound::SmUnackedStanza],
    context: &str,
) -> Result<HashMap<SmDurableSourceKey, crate::outbound::TransportOwnershipSource>> {
    let mut sources = HashMap::new();
    for entry in entries {
        let Some(source) = entry.source else {
            continue;
        };
        anyhow::ensure!(
            sources.insert(durable_source_key(source), source).is_none(),
            "duplicate durable source in {context}"
        );
    }
    Ok(sources)
}

async fn lock_new_c2s_source_for_sm_transfer(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    delivery: crate::outbound::DurableDelivery,
) -> Result<()> {
    let row = sqlx::query(
        "SELECT delivery_claim_id FROM offline_messages
          WHERE recipient_id=$1 AND id=$2 FOR UPDATE",
    )
    .bind(delivery.recipient_id)
    .bind(delivery.message_id)
    .fetch_optional(&mut **transaction)
    .await?;
    let Some(row) = row else {
        anyhow::bail!("durable delivery row disappeared before SM ownership transfer");
    };
    let stored_claim: Option<Uuid> = row.try_get("delivery_claim_id")?;
    anyhow::ensure!(
        stored_claim == delivery.claim_id,
        "durable delivery claim changed before SM ownership transfer"
    );
    let bosh_owned: bool = sqlx::query_scalar(
        "SELECT EXISTS(
             SELECT 1 FROM bosh_delivery_fences WHERE message_id=$1
         )",
    )
    .bind(delivery.message_id)
    .fetch_one(&mut **transaction)
    .await?;
    anyhow::ensure!(
        !bosh_owned,
        "durable delivery is already owned by a BOSH response"
    );
    let sm_owned: bool = sqlx::query_scalar(
        "SELECT EXISTS(
             SELECT 1 FROM sm_resume_stanzas WHERE delivery_message_id=$1
         )",
    )
    .bind(delivery.message_id)
    .fetch_one(&mut **transaction)
    .await?;
    anyhow::ensure!(
        !sm_owned,
        "durable delivery is already owned by another SM queue"
    );
    sqlx::query(
        "UPDATE offline_messages
            SET delivery_claim_id=NULL,delivery_claim_expires_at=NULL
          WHERE recipient_id=$1 AND id=$2",
    )
    .bind(delivery.recipient_id)
    .bind(delivery.message_id)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

async fn lock_mix_bosh_fence_for_sm_transfer(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    delivery_id: Uuid,
) -> Result<()> {
    let fence = sqlx::query(
        "SELECT lease_token,expires_at>clock_timestamp() AS active
           FROM mix_bosh_delivery_fences
          WHERE delivery_id=$1 FOR UPDATE",
    )
    .bind(delivery_id)
    .fetch_optional(&mut **transaction)
    .await?;
    let Some(fence) = fence else {
        return Ok(());
    };
    let active: bool = fence.try_get("active")?;
    anyhow::ensure!(
        !active,
        "MIX delivery is already owned by an active BOSH response"
    );
    let lease_token: Uuid = fence.try_get("lease_token")?;
    let removed = sqlx::query(
        "DELETE FROM mix_bosh_delivery_fences
          WHERE delivery_id=$1 AND lease_token=$2",
    )
    .bind(delivery_id)
    .bind(lease_token)
    .execute(&mut **transaction)
    .await?
    .rows_affected();
    anyhow::ensure!(
        removed == 1,
        "expired MIX BOSH fence changed during SM ownership transfer"
    );
    Ok(())
}

/// Lock one freshly claimed MIX recipient and turn the worker lease into an
/// SM-private capability.  The fixed source -> BOSH-fence order matches the
/// BOSH hand-off path, so neither transport can form a reverse lock cycle.
async fn rotate_new_mix_source_for_sm_transfer(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    previous: crate::outbound::MixDelivery,
) -> Result<crate::outbound::MixDelivery> {
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
    let current = crate::outbound::MixDelivery {
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

async fn delete_completed_mix_source_from_sm(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    delivery: crate::outbound::MixDelivery,
) -> Result<()> {
    let row = sqlx::query(
        "SELECT lease_token FROM mix_delivery_recipients
          WHERE delivery_id=$1 FOR UPDATE",
    )
    .bind(delivery.delivery_id)
    .fetch_optional(&mut **transaction)
    .await?;
    let Some(row) = row else {
        anyhow::bail!("SM acknowledged MIX delivery row was not present");
    };
    anyhow::ensure!(
        row.try_get::<Option<Uuid>, _>("lease_token")? == Some(delivery.lease_token),
        "SM acknowledgement lost the exact MIX delivery lease"
    );
    lock_mix_bosh_fence_for_sm_transfer(transaction, delivery.delivery_id).await?;
    let sm_owned: bool = sqlx::query_scalar(
        "SELECT EXISTS(
             SELECT 1 FROM sm_resume_stanzas WHERE mix_delivery_id=$1
         )",
    )
    .bind(delivery.delivery_id)
    .fetch_one(&mut **transaction)
    .await?;
    anyhow::ensure!(
        !sm_owned,
        "SM acknowledgement would consume a MIX source owned by another queue"
    );
    let removed = sqlx::query(
        "DELETE FROM mix_delivery_recipients
          WHERE delivery_id=$1 AND lease_token=$2",
    )
    .bind(delivery.delivery_id)
    .bind(delivery.lease_token)
    .execute(&mut **transaction)
    .await?
    .rows_affected();
    anyhow::ensure!(
        removed == 1,
        "SM acknowledged MIX delivery lease changed before deletion"
    );
    Ok(())
}

/// Atomically acknowledge the exact source set which crossed a non-resumable
/// transport boundary.
///
/// XEP-0198 persistence uses [`replace_queue`] instead: it first transfers a
/// source into its queue and later consumes it together with the matching
/// client acknowledgement.  This function is deliberately for the opposite
/// boundary only, where bytes were written without an SM owner.  Validate
/// every capability before deleting any projection, so a later stale MIX
/// lease cannot partially consume an earlier C2S prefix.
pub async fn acknowledge_transport_sources(
    pool: &PgPool,
    sources: &[crate::outbound::TransportOwnershipSource],
) -> Result<()> {
    if sources.is_empty() {
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

    for (delivery, present) in c2s.iter().zip(present_c2s) {
        if !present {
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
    }
    transaction.commit().await?;
    tracing::debug!(
        c2s = c2s.len(),
        mix = mix.len(),
        "atomically acknowledged durable transport source batch"
    );
    Ok(())
}

async fn replace_queue(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    id: Uuid,
    queue: &[crate::outbound::SmUnackedStanza],
    acknowledged: &[crate::outbound::SmUnackedStanza],
) -> Result<SmQueueOwnershipResolution> {
    // First lock the current SM queue.  All later source locks are ordered
    // C2S offline rows, then MIX recipient rows, then their BOSH fence rows.
    // Every queue replacement follows this order, so a mixed snapshot cannot
    // create a C2S/MIX inversion while preserving XEP-0198 FIFO semantics.
    let existing_rows = sqlx::query(
        "SELECT delivery_recipient_id,delivery_message_id,delivery_claim_id,
                mix_delivery_id,mix_delivery_lease_token
           FROM sm_resume_stanzas
          WHERE session_id=$1
            AND (delivery_message_id IS NOT NULL OR mix_delivery_id IS NOT NULL)
          FOR UPDATE",
    )
    .bind(id)
    .fetch_all(&mut **transaction)
    .await?;
    let mut existing = HashMap::new();
    for row in existing_rows {
        let source = durable_source_from_columns(
            row.try_get("delivery_recipient_id")?,
            row.try_get("delivery_message_id")?,
            row.try_get("delivery_claim_id")?,
            row.try_get("mix_delivery_id")?,
            row.try_get("mix_delivery_lease_token")?,
        )?
        .context("persisted SM durable row has no source")?;
        anyhow::ensure!(
            existing
                .insert(durable_source_key(source), source)
                .is_none(),
            "duplicate durable source in persisted SM queue"
        );
    }

    let mut next = source_map(queue, "SM snapshot")?;
    let completed = source_map(acknowledged, "SM acknowledgement")?;
    anyhow::ensure!(
        completed
            .iter()
            .all(|(key, completed)| { existing.get(key).is_some_and(|owned| owned == completed) }),
        "SM acknowledgement does not own the durable source fence"
    );
    anyhow::ensure!(
        next.iter()
            .all(|(key, source)| { existing.get(key).is_none_or(|owned| owned == source) }),
        "SM snapshot changed an existing durable source fence"
    );
    anyhow::ensure!(
        existing
            .keys()
            .all(|key| { next.contains_key(key) || completed.contains_key(key) }),
        "SM snapshot attempted to drop a durable source without client acknowledgement"
    );
    anyhow::ensure!(
        completed.keys().all(|key| !next.contains_key(key)),
        "SM acknowledgement retained the same durable source"
    );

    let mut new_c2s = next
        .values()
        .filter_map(|source| match *source {
            crate::outbound::TransportOwnershipSource::C2s(delivery)
                if !existing.contains_key(&durable_source_key(*source)) =>
            {
                Some(delivery)
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    new_c2s.sort_unstable_by_key(|delivery| (delivery.recipient_id, delivery.message_id));
    for delivery in new_c2s {
        lock_new_c2s_source_for_sm_transfer(transaction, delivery).await?;
    }

    let mut new_mix = next
        .values()
        .filter_map(|source| match *source {
            crate::outbound::TransportOwnershipSource::Mix(delivery)
                if !existing.contains_key(&durable_source_key(*source)) =>
            {
                Some(delivery)
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    new_mix.sort_unstable_by_key(|delivery| delivery.delivery_id);
    let mut ownership = SmQueueOwnershipResolution::default();
    for previous in new_mix {
        let current = rotate_new_mix_source_for_sm_transfer(transaction, previous).await?;
        let key = durable_source_key(crate::outbound::TransportOwnershipSource::Mix(previous));
        let replaced = next.insert(key, crate::outbound::TransportOwnershipSource::Mix(current));
        anyhow::ensure!(
            replaced == Some(crate::outbound::TransportOwnershipSource::Mix(previous)),
            "MIX source changed while rotating into SM ownership"
        );
        ownership
            .mix_rotations
            .push(SmMixLeaseRotation { previous, current });
    }

    sqlx::query("DELETE FROM sm_resume_stanzas WHERE session_id=$1")
        .bind(id)
        .execute(&mut **transaction)
        .await?;
    for (position, entry) in queue.iter().enumerate() {
        let source = entry
            .source
            .map(|source| {
                next.get(&durable_source_key(source))
                    .copied()
                    .context("SM snapshot source disappeared during replacement")
            })
            .transpose()?;
        let c2s = source.and_then(crate::outbound::TransportOwnershipSource::c2s);
        let mix = source.and_then(crate::outbound::TransportOwnershipSource::mix);
        sqlx::query(
            "INSERT INTO sm_resume_stanzas(
                session_id,position,stanza,delivery_recipient_id,
                delivery_message_id,delivery_claim_id,
                mix_delivery_id,mix_delivery_lease_token
             ) VALUES($1,$2,$3,$4,$5,$6,$7,$8)",
        )
        .bind(id)
        .bind(i32::try_from(position).context("SM queue position overflow")?)
        .bind(&entry.stanza)
        .bind(c2s.map(|delivery| delivery.recipient_id))
        .bind(c2s.map(|delivery| delivery.message_id))
        .bind(c2s.and_then(|delivery| delivery.claim_id))
        .bind(mix.map(|delivery| delivery.delivery_id))
        .bind(mix.map(|delivery| delivery.lease_token))
        .execute(&mut **transaction)
        .await?;
    }
    let mut completed_c2s = completed
        .values()
        .filter_map(|source| source.c2s())
        .collect::<Vec<_>>();
    completed_c2s.sort_unstable_by_key(|delivery| (delivery.recipient_id, delivery.message_id));
    for delivery in completed_c2s {
        let deleted = sqlx::query("DELETE FROM offline_messages WHERE recipient_id=$1 AND id=$2")
            .bind(delivery.recipient_id)
            .bind(delivery.message_id)
            .execute(&mut **transaction)
            .await?
            .rows_affected();
        anyhow::ensure!(
            deleted == 1,
            "SM acknowledged durable delivery row was not present"
        );
    }
    let mut completed_mix = completed
        .values()
        .filter_map(|source| source.mix())
        .collect::<Vec<_>>();
    completed_mix.sort_unstable_by_key(|delivery| delivery.delivery_id);
    for delivery in completed_mix {
        delete_completed_mix_source_from_sm(transaction, delivery).await?;
    }
    Ok(ownership)
}

async fn fetch_queue(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    id: Uuid,
) -> Result<Vec<crate::outbound::SmUnackedStanza>> {
    sqlx::query(
        "SELECT stanza,delivery_recipient_id,delivery_message_id,delivery_claim_id,
                mix_delivery_id,mix_delivery_lease_token
           FROM sm_resume_stanzas WHERE session_id=$1 ORDER BY position",
    )
    .bind(id)
    .fetch_all(&mut **transaction)
    .await?
    .into_iter()
    .map(|row| {
        let stanza: String = row.try_get("stanza")?;
        let source = durable_source_from_columns(
            row.try_get("delivery_recipient_id")?,
            row.try_get("delivery_message_id")?,
            row.try_get("delivery_claim_id")?,
            row.try_get("mix_delivery_id")?,
            row.try_get("mix_delivery_lease_token")?,
        )?;
        Ok(crate::outbound::SmUnackedStanza::with_source(
            stanza, source,
        ))
    })
    .collect()
}

fn validate_snapshot(
    snapshot: &SmSessionSnapshot,
    max_stanzas: usize,
    max_bytes: usize,
) -> Result<()> {
    if snapshot.joined_rooms.len() > 256 {
        anyhow::bail!("SM MUC membership snapshot is too large");
    }
    if snapshot.joined_rooms.iter().any(|membership| {
        crate::jid::CanonicalJid::parse_bare(&membership.room_jid).is_err()
            || crate::xmpp::xml_util::prepare_muc_nick(&membership.nick).is_err()
    }) {
        anyhow::bail!("SM MUC membership snapshot is invalid");
    }
    if snapshot.directed_presence.len() > 1_024
        || snapshot
            .directed_presence
            .iter()
            .any(|jid| jid.len() > 3_071 || crate::jid::CanonicalJid::parse(jid).is_err())
    {
        anyhow::bail!("SM directed-presence snapshot is invalid or too large");
    }
    if snapshot.last_presence.as_ref().is_some_and(|presence| {
        presence.is_empty()
            || presence.len() > 1_048_576
            || roxmltree::Document::parse(presence).is_err()
    }) {
        anyhow::bail!("SM last-presence snapshot is invalid or too large");
    }
    validate_queue(&snapshot.unacked, max_stanzas, max_bytes)
}

fn canonical_snapshot_identities(
    snapshot: &SmSessionSnapshot,
) -> Result<(serde_json::Value, serde_json::Value)> {
    let mut rooms = std::collections::BTreeSet::new();
    let mut joined_rooms = Vec::with_capacity(snapshot.joined_rooms.len());
    for membership in &snapshot.joined_rooms {
        let room_jid = crate::jid::canonicalize_bare(&membership.room_jid)?;
        anyhow::ensure!(
            crate::jid::CanonicalJid::parse_bare(&room_jid)?
                .localpart()
                .is_some(),
            "SM MUC room must contain a localpart"
        );
        anyhow::ensure!(
            rooms.insert(room_jid.clone()),
            "duplicate canonical SM MUC room"
        );
        joined_rooms.push(SmMucMembership {
            room_jid,
            nick: membership.nick.clone(),
        });
    }
    let mut directed_keys = std::collections::BTreeSet::new();
    let mut directed_presence = Vec::with_capacity(snapshot.directed_presence.len());
    for target in &snapshot.directed_presence {
        let target = crate::jid::canonicalize(target)?;
        anyhow::ensure!(
            directed_keys.insert(target.clone()),
            "duplicate canonical SM directed-presence target"
        );
        directed_presence.push(target);
    }
    Ok((
        serde_json::to_value(joined_rooms)?,
        serde_json::to_value(directed_presence)?,
    ))
}

fn validate_queue(
    queue: &[crate::outbound::SmUnackedStanza],
    max_stanzas: usize,
    max_bytes: usize,
) -> Result<()> {
    if queue.len() > max_stanzas {
        anyhow::bail!("SM unacknowledged stanza limit exceeded");
    }
    let bytes = queue
        .iter()
        .try_fold(0usize, |total, entry| total.checked_add(entry.stanza.len()))
        .context("SM unacknowledged byte count overflow")?;
    if bytes > max_bytes
        || queue
            .iter()
            .any(|entry| entry.stanza.is_empty() || entry.stanza.len() > 1024 * 1024)
    {
        anyhow::bail!("SM unacknowledged byte limit exceeded");
    }
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
