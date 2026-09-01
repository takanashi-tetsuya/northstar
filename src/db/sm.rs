use anyhow::{Context, Result};
use sqlx::{PgPool, Row};
use std::{collections::HashMap, net::IpAddr};
use uuid::Uuid;

const U32_MODULUS: i64 = 4_294_967_296;

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize, PartialEq, Eq)]
pub struct SmMucMembership {
    pub room_jid: String,
    pub nick: String,
}

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
    Pending,
    Rejected,
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SmIpPolicy {
    None,
    Exact,
    Subnet,
}

impl SmIpPolicy {
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "none" => Some(Self::None),
            "exact" => Some(Self::Exact),
            "subnet" => Some(Self::Subnet),
            _ => None,
        }
    }
}

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
    replace_queue(&mut transaction, id, &snapshot.unacked, &[]).await?;
    transaction.commit().await?;
    Ok(id)
}

#[allow(clippy::too_many_arguments)]
pub async fn checkpoint_sm_session(
    pool: &PgPool,
    id: Uuid,
    connection_id: Uuid,
    snapshot: &SmSessionSnapshot,
    ttl_seconds: u64,
    live_lease_seconds: u64,
    max_stanzas: usize,
    max_bytes: usize,
) -> Result<bool> {
    checkpoint_sm_session_and_acknowledge(
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
        return Ok(false);
    }
    replace_queue(&mut transaction, id, &snapshot.unacked, acknowledged).await?;
    transaction.commit().await?;
    Ok(true)
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
            SmClaimStatus::Pending | SmClaimStatus::Rejected => None,
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
            transaction.commit().await?;
            return Ok(SmClaimStatus::Pending);
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
    let claim = SmResumeClaim {
        session_id,
        claim_token,
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

async fn replace_queue(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    id: Uuid,
    queue: &[crate::outbound::SmUnackedStanza],
    acknowledged: &[crate::outbound::SmUnackedStanza],
) -> Result<()> {
    let existing_rows = sqlx::query(
        "SELECT delivery_recipient_id,delivery_message_id,delivery_claim_id
           FROM sm_resume_stanzas
          WHERE session_id=$1 AND delivery_message_id IS NOT NULL
          FOR UPDATE",
    )
    .bind(id)
    .fetch_all(&mut **transaction)
    .await?;
    let mut existing = HashMap::new();
    for row in existing_rows {
        let recipient_id: Uuid = row.try_get("delivery_recipient_id")?;
        let message_id: Uuid = row.try_get("delivery_message_id")?;
        let claim_id: Option<Uuid> = row.try_get("delivery_claim_id")?;
        anyhow::ensure!(
            existing
                .insert(
                    message_id,
                    crate::outbound::DurableDelivery {
                        recipient_id,
                        message_id,
                        claim_id,
                    },
                )
                .is_none(),
            "duplicate durable delivery in persisted SM queue"
        );
    }

    let mut next = HashMap::new();
    for entry in queue {
        let Some(delivery) = entry.durable_delivery else {
            continue;
        };
        anyhow::ensure!(
            next.insert(delivery.message_id, delivery).is_none(),
            "duplicate durable delivery in SM snapshot"
        );
    }
    let mut completed = HashMap::new();
    for entry in acknowledged {
        let Some(delivery) = entry.durable_delivery else {
            continue;
        };
        anyhow::ensure!(
            completed.insert(delivery.message_id, delivery).is_none(),
            "duplicate durable delivery in SM acknowledgement"
        );
    }
    anyhow::ensure!(
        completed
            .keys()
            .all(|message_id| existing.get(message_id).is_some_and(|owned| {
                let completed = completed[message_id];
                *owned == completed
            })),
        "SM acknowledgement does not own the durable delivery fence"
    );
    anyhow::ensure!(
        next.iter().all(|(message_id, delivery)| {
            existing
                .get(message_id)
                .is_none_or(|owned| owned == delivery)
        }),
        "SM snapshot changed an existing durable delivery fence"
    );
    anyhow::ensure!(
        existing.keys().all(|message_id| {
            next.contains_key(message_id) || completed.contains_key(message_id)
        }),
        "SM snapshot attempted to drop a durable delivery without client acknowledgement"
    );
    anyhow::ensure!(
        completed
            .keys()
            .all(|message_id| !next.contains_key(message_id)),
        "SM acknowledgement retained the same durable delivery"
    );

    // Acquire offline rows in UUID order so concurrent resources cannot form
    // a lock cycle while trying to bind different pages of one account.
    let mut new_deliveries = next
        .values()
        .filter(|delivery| !existing.contains_key(&delivery.message_id))
        .copied()
        .collect::<Vec<_>>();
    new_deliveries.sort_unstable_by_key(|delivery| delivery.message_id);
    for delivery in new_deliveries {
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
        sqlx::query(
            "UPDATE offline_messages
                SET delivery_claim_id=NULL,delivery_claim_expires_at=NULL
              WHERE recipient_id=$1 AND id=$2",
        )
        .bind(delivery.recipient_id)
        .bind(delivery.message_id)
        .execute(&mut **transaction)
        .await?;
    }

    sqlx::query("DELETE FROM sm_resume_stanzas WHERE session_id=$1")
        .bind(id)
        .execute(&mut **transaction)
        .await?;
    for (position, entry) in queue.iter().enumerate() {
        let delivery = entry.durable_delivery;
        sqlx::query(
            "INSERT INTO sm_resume_stanzas(
                session_id,position,stanza,delivery_recipient_id,
                delivery_message_id,delivery_claim_id
             ) VALUES($1,$2,$3,$4,$5,$6)",
        )
        .bind(id)
        .bind(i32::try_from(position).context("SM queue position overflow")?)
        .bind(&entry.stanza)
        .bind(delivery.map(|delivery| delivery.recipient_id))
        .bind(delivery.map(|delivery| delivery.message_id))
        .bind(delivery.and_then(|delivery| delivery.claim_id))
        .execute(&mut **transaction)
        .await?;
    }
    for delivery in completed.values() {
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
    Ok(())
}

async fn fetch_queue(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    id: Uuid,
) -> Result<Vec<crate::outbound::SmUnackedStanza>> {
    sqlx::query(
        "SELECT stanza,delivery_recipient_id,delivery_message_id,delivery_claim_id
           FROM sm_resume_stanzas WHERE session_id=$1 ORDER BY position",
    )
    .bind(id)
    .fetch_all(&mut **transaction)
    .await?
    .into_iter()
    .map(|row| {
        let stanza: String = row.try_get("stanza")?;
        let recipient_id: Option<Uuid> = row.try_get("delivery_recipient_id")?;
        let message_id: Option<Uuid> = row.try_get("delivery_message_id")?;
        let claim_id: Option<Uuid> = row.try_get("delivery_claim_id")?;
        let durable_delivery = match (recipient_id, message_id) {
            (Some(recipient_id), Some(message_id)) => Some(crate::outbound::DurableDelivery {
                recipient_id,
                message_id,
                claim_id,
            }),
            (None, None) if claim_id.is_none() => None,
            _ => anyhow::bail!("invalid durable delivery shape in SM queue"),
        };
        Ok(crate::outbound::SmUnackedStanza::with_delivery(
            stanza,
            durable_delivery,
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
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};
    use std::net::{Ipv4Addr, Ipv6Addr};

    async fn session_capability_catalog_healthy(pool: &PgPool) -> bool {
        sqlx::query_scalar(
            "SELECT northstar_session_capability_catalog_healthy(
                pg_catalog.current_schema())",
        )
        .fetch_one(pool)
        .await
        .unwrap()
    }

    #[tokio::test]
    #[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
    async fn owner_only_session_catalog_is_strict_and_development_safe() {
        let url = std::env::var("TEST_DATABASE_URL")
            .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(2)
            .connect(&url)
            .await
            .unwrap();
        crate::db::migrate(&pool).await.unwrap();

        assert!(session_capability_catalog_healthy(&pool).await);

        sqlx::query(
            "GRANT EXECUTE ON FUNCTION northstar_sm_count(text,uuid,bigint,text) TO PUBLIC",
        )
        .execute(&pool)
        .await
        .unwrap();
        assert!(!session_capability_catalog_healthy(&pool).await);
        sqlx::query(
            "REVOKE EXECUTE ON FUNCTION northstar_sm_count(text,uuid,bigint,text) FROM PUBLIC",
        )
        .execute(&pool)
        .await
        .unwrap();
        assert!(session_capability_catalog_healthy(&pool).await);

        sqlx::query("GRANT SELECT ON TABLE sm_resume_sessions TO PUBLIC")
            .execute(&pool)
            .await
            .unwrap();
        assert!(!session_capability_catalog_healthy(&pool).await);
        sqlx::query("REVOKE SELECT ON TABLE sm_resume_sessions FROM PUBLIC")
            .execute(&pool)
            .await
            .unwrap();
        assert!(session_capability_catalog_healthy(&pool).await);

        sqlx::query(
            "ALTER TABLE sm_resume_sessions DISABLE TRIGGER \
             sm_resume_sessions_deployment_capacity_insert",
        )
        .execute(&pool)
        .await
        .unwrap();
        assert!(!session_capability_catalog_healthy(&pool).await);
        sqlx::query(
            "ALTER TABLE sm_resume_sessions ENABLE TRIGGER \
             sm_resume_sessions_deployment_capacity_insert",
        )
        .execute(&pool)
        .await
        .unwrap();
        assert!(session_capability_catalog_healthy(&pool).await);
    }

    async fn install_authorization_test_sm(
        pool: &PgPool,
        user_id: Uuid,
        username: &str,
        marker: u8,
    ) -> ([u8; 32], Uuid, SmSessionSnapshot) {
        let bearer = [marker; 32];
        let hash: [u8; 32] = Sha256::digest(bearer).into();
        let snapshot = SmSessionSnapshot {
            inbound_h: 3,
            outbound_h: 5,
            acked_h: 4,
            available: true,
            carbons: true,
            priority: 7,
            blocklist_requested: true,
            roster_requested: true,
            active_privacy_list: None,
            privacy_requested: false,
            peer_ip: "192.0.2.33".parse().unwrap(),
            user_agent_id: Some(Uuid::new_v4()),
            joined_rooms: vec![SmMucMembership {
                room_jid: "room@conference.example.test".to_owned(),
                nick: format!("Device-{marker}"),
            }],
            directed_presence: vec!["friend@example.net".to_owned()],
            last_presence: Some("<presence xmlns='jabber:client'/>".to_owned()),
            unacked: vec![crate::outbound::SmUnackedStanza::plain(format!(
                "<message id='queued-{marker}'/>"
            ))],
        };
        let id = create_sm_session(
            pool,
            &hash,
            user_id,
            0,
            &format!("{username}@example.test/Device-{marker}"),
            &format!("Device-{marker}"),
            "example.test",
            Uuid::new_v4(),
            &snapshot,
            300,
            30,
            8,
            100,
        )
        .await
        .unwrap();
        (hash, id, snapshot)
    }

    async fn assert_authorization_revocation_is_durably_teardownable(
        pool: &PgPool,
        user_id: Uuid,
        hash: &[u8; 32],
        id: Uuid,
        snapshot: &SmSessionSnapshot,
    ) {
        assert!(matches!(
            claim_sm_session_status(
                pool,
                hash,
                user_id,
                snapshot.peer_ip,
                snapshot.user_agent_id,
                SmIpPolicy::Exact,
                true,
                30,
            )
            .await
            .unwrap(),
            SmClaimStatus::Rejected
        ));
        let rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM sm_resume_sessions WHERE id=$1")
            .bind(id)
            .fetch_one(pool)
            .await
            .unwrap();
        assert_eq!(rows, 1, "authorization mutation destroyed teardown state");
        let teardown = take_user_sm_sessions_for_teardown(pool, user_id, 30)
            .await
            .unwrap()
            .snapshots
            .into_iter()
            .find(|candidate| candidate.session_id == id)
            .expect("expired authorization epoch must retain a teardown lease");
        assert!(teardown.available);
        assert_eq!(teardown.joined_rooms, snapshot.joined_rooms);
        assert_eq!(teardown.directed_presence, snapshot.directed_presence);
        assert!(finalize_sm_teardown(pool, id, teardown.teardown_token)
            .await
            .unwrap());
    }

    #[test]
    fn subnet_binding_uses_v4_24_and_v6_64() {
        assert!(peer_ip_matches(
            SmIpPolicy::Subnet,
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 250))
        ));
        assert!(!peer_ip_matches(
            SmIpPolicy::Subnet,
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            IpAddr::V4(Ipv4Addr::new(192, 0, 3, 1))
        ));
        assert!(peer_ip_matches(
            SmIpPolicy::Subnet,
            IpAddr::V6("2001:db8:1:2::1".parse::<Ipv6Addr>().unwrap()),
            IpAddr::V6("2001:db8:1:2::ffff".parse::<Ipv6Addr>().unwrap())
        ));
    }

    #[test]
    fn queue_limits_are_enforced() {
        assert!(
            validate_queue(&[crate::outbound::SmUnackedStanza::plain("x".into())], 1, 1).is_ok()
        );
        assert!(validate_queue(
            &[
                crate::outbound::SmUnackedStanza::plain("x".into()),
                crate::outbound::SmUnackedStanza::plain("y".into())
            ],
            1,
            2
        )
        .is_err());
        assert!(validate_queue(
            &[crate::outbound::SmUnackedStanza::plain("xy".into())],
            1,
            1
        )
        .is_err());
    }

    #[test]
    fn snapshot_identity_keys_are_canonical_and_resources_remain_case_sensitive() {
        let mut snapshot = SmSessionSnapshot {
            inbound_h: 0,
            outbound_h: 0,
            acked_h: 0,
            available: false,
            carbons: false,
            priority: 0,
            blocklist_requested: false,
            roster_requested: false,
            active_privacy_list: None,
            privacy_requested: false,
            peer_ip: "192.0.2.10".parse().unwrap(),
            user_agent_id: None,
            joined_rooms: vec![SmMucMembership {
                room_jid: "room@conference.bücher.example".to_owned(),
                nick: "Nick".to_owned(),
            }],
            directed_presence: vec![
                "friend@bücher.example/Phone".to_owned(),
                "friend@bücher.example/phone".to_owned(),
            ],
            last_presence: None,
            unacked: vec![],
        };
        let (rooms, directed) = canonical_snapshot_identities(&snapshot).unwrap();
        assert_eq!(
            rooms,
            serde_json::json!([{
                "room_jid":"room@conference.bücher.example",
                "nick":"Nick"
            }])
        );
        assert_eq!(
            directed,
            serde_json::json!(["friend@bücher.example/Phone", "friend@bücher.example/phone"])
        );

        snapshot.joined_rooms.push(SmMucMembership {
            room_jid: "room@conference.bücher.example".to_owned(),
            nick: "Other".to_owned(),
        });
        assert!(canonical_snapshot_identities(&snapshot).is_err());
    }

    #[tokio::test]
    #[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
    async fn authorization_mutations_retain_sm_presence_and_muc_teardown_state() {
        let url = std::env::var("TEST_DATABASE_URL")
            .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(4)
            .connect(&url)
            .await
            .unwrap();
        crate::db::migrate(&pool).await.unwrap();
        let actor_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO users(id,username,password_hash,is_admin)
             VALUES($1,$2,'test-only',TRUE)",
        )
        .bind(actor_id)
        .bind(format!("sm-actor-{}", &actor_id.simple().to_string()[..10]))
        .execute(&pool)
        .await
        .unwrap();

        let password_user = Uuid::new_v4();
        let password_name = format!("sm-password-{}", &password_user.simple().to_string()[..10]);
        sqlx::query("INSERT INTO users(id,username,password_hash) VALUES($1,$2,'test-only')")
            .bind(password_user)
            .bind(&password_name)
            .execute(&pool)
            .await
            .unwrap();
        let (hash, id, snapshot) =
            install_authorization_test_sm(&pool, password_user, &password_name, 21).await;
        crate::db::change_password(
            &pool,
            password_user,
            "Correct-Horse-Battery-21",
            4096,
            false,
        )
        .await
        .unwrap();
        assert_authorization_revocation_is_durably_teardownable(
            &pool,
            password_user,
            &hash,
            id,
            &snapshot,
        )
        .await;

        let disabled_user = Uuid::new_v4();
        let disabled_name = format!("sm-disabled-{}", &disabled_user.simple().to_string()[..10]);
        sqlx::query("INSERT INTO users(id,username,password_hash) VALUES($1,$2,'test-only')")
            .bind(disabled_user)
            .bind(&disabled_name)
            .execute(&pool)
            .await
            .unwrap();
        let (hash, id, snapshot) =
            install_authorization_test_sm(&pool, disabled_user, &disabled_name, 22).await;
        crate::db::set_user_status(&pool, actor_id, disabled_user, Some(true), None)
            .await
            .unwrap();
        assert_authorization_revocation_is_durably_teardownable(
            &pool,
            disabled_user,
            &hash,
            id,
            &snapshot,
        )
        .await;

        let ended_user = Uuid::new_v4();
        let ended_name = format!("sm-ended-{}", &ended_user.simple().to_string()[..10]);
        sqlx::query("INSERT INTO users(id,username,password_hash) VALUES($1,$2,'test-only')")
            .bind(ended_user)
            .bind(&ended_name)
            .execute(&pool)
            .await
            .unwrap();
        let (hash, id, snapshot) =
            install_authorization_test_sm(&pool, ended_user, &ended_name, 23).await;
        assert!(crate::db::end_user_sessions(&pool, actor_id, ended_user)
            .await
            .unwrap());
        assert_authorization_revocation_is_durably_teardownable(
            &pool, ended_user, &hash, id, &snapshot,
        )
        .await;

        sqlx::query("DELETE FROM users WHERE id=ANY($1)")
            .bind(vec![actor_id, password_user, disabled_user, ended_user])
            .execute(&pool)
            .await
            .unwrap();
    }

    #[tokio::test]
    #[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
    async fn durable_delivery_fence_survives_checkpoint_resume_and_revocation() {
        let url = std::env::var("TEST_DATABASE_URL")
            .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(4)
            .connect(&url)
            .await
            .unwrap();
        crate::db::migrate(&pool).await.unwrap();
        let user_id = Uuid::new_v4();
        let username = format!("smfence{}", &user_id.simple().to_string()[..10]);
        sqlx::query("INSERT INTO users(id,username,password_hash) VALUES($1,$2,'test-only')")
            .bind(user_id)
            .bind(&username)
            .execute(&pool)
            .await
            .unwrap();
        let peer_ip = "192.0.2.44".parse().unwrap();

        async fn insert_delivery(pool: &PgPool, user_id: Uuid) -> crate::outbound::DurableDelivery {
            let message_id = Uuid::new_v4();
            let claim_id = Uuid::new_v4();
            sqlx::query(
                "INSERT INTO offline_messages(
                    id,recipient_id,sender_jid,stanza,encrypted,mam_backed,
                    delivery_claim_id,delivery_claim_expires_at
                 ) VALUES($1,$2,'sender@example.test','<message id=''sm''/>',FALSE,FALSE,
                          $3,clock_timestamp()+INTERVAL '1 hour')",
            )
            .bind(message_id)
            .bind(user_id)
            .bind(claim_id)
            .execute(pool)
            .await
            .unwrap();
            crate::outbound::DurableDelivery {
                recipient_id: user_id,
                message_id,
                claim_id: Some(claim_id),
            }
        }

        fn snapshot(
            peer_ip: IpAddr,
            delivery: crate::outbound::DurableDelivery,
        ) -> SmSessionSnapshot {
            SmSessionSnapshot {
                inbound_h: 0,
                outbound_h: 1,
                acked_h: 0,
                available: true,
                carbons: false,
                priority: 0,
                blocklist_requested: false,
                roster_requested: false,
                active_privacy_list: None,
                privacy_requested: false,
                peer_ip,
                user_agent_id: None,
                joined_rooms: vec![],
                directed_presence: vec![],
                last_presence: Some("<presence xmlns='jabber:client'/>".to_owned()),
                unacked: vec![crate::outbound::SmUnackedStanza::with_delivery(
                    "<message id='sm'/>".to_owned(),
                    Some(delivery),
                )],
            }
        }

        // A live checkpoint transfers the replay claim into the exact SM
        // sequence row. Only the matching client h removes both projections.
        let first = insert_delivery(&pool, user_id).await;
        let first_snapshot = snapshot(peer_ip, first);
        let first_connection = Uuid::new_v4();
        let first_id = create_sm_session(
            &pool,
            &[31_u8; 32],
            user_id,
            0,
            &format!("{username}@example.test/first"),
            "first",
            "example.test",
            first_connection,
            &first_snapshot,
            300,
            30,
            128,
            10_000,
        )
        .await
        .unwrap();
        let stored: (Option<Uuid>, i64) = sqlx::query_as(
            "SELECT message.delivery_claim_id,COUNT(stanza.delivery_message_id)
               FROM offline_messages message
               JOIN sm_resume_stanzas stanza ON stanza.delivery_message_id=message.id
              WHERE message.id=$1 GROUP BY message.delivery_claim_id",
        )
        .bind(first.message_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(stored, (None, 1));
        assert!(crate::db::replay::bind_bosh_delivery_response(
            &pool,
            Uuid::new_v4(),
            1,
            &[first],
            60,
        )
        .await
        .is_err());
        let mut acknowledged_snapshot = first_snapshot.clone();
        acknowledged_snapshot.acked_h = 1;
        acknowledged_snapshot.unacked.clear();
        assert!(checkpoint_sm_session_and_acknowledge(
            &pool,
            first_id,
            first_connection,
            &acknowledged_snapshot,
            &first_snapshot.unacked,
            300,
            30,
            128,
            10_000,
        )
        .await
        .unwrap());
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM offline_messages WHERE id=$1")
                .bind(first.message_id)
                .fetch_one(&pool)
                .await
                .unwrap(),
            0
        );
        revoke_sm_session(&pool, first_id).await.unwrap();

        // If a non-resumable stream disappears before h advances, deleting
        // the SM owner frees (rather than deletes) the durable offline row.
        let second = insert_delivery(&pool, user_id).await;
        let second_snapshot = snapshot(peer_ip, second);
        let second_id = create_sm_session(
            &pool,
            &[32_u8; 32],
            user_id,
            0,
            &format!("{username}@example.test/second"),
            "second",
            "example.test",
            Uuid::new_v4(),
            &second_snapshot,
            300,
            30,
            128,
            10_000,
        )
        .await
        .unwrap();
        revoke_sm_session(&pool, second_id).await.unwrap();
        let second_row: Option<Uuid> =
            sqlx::query_scalar("SELECT delivery_claim_id FROM offline_messages WHERE id=$1")
                .bind(second.message_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(second_row, None);

        // Resume h is committed with fence completion in the activation
        // transaction, before the replacement route becomes authoritative.
        let third = insert_delivery(&pool, user_id).await;
        let third_snapshot = snapshot(peer_ip, third);
        let third_connection = Uuid::new_v4();
        let third_hash = [33_u8; 32];
        let third_id = create_sm_session(
            &pool,
            &third_hash,
            user_id,
            0,
            &format!("{username}@example.test/third"),
            "third",
            "example.test",
            third_connection,
            &third_snapshot,
            300,
            30,
            128,
            10_000,
        )
        .await
        .unwrap();
        assert!(suspend_sm_session(
            &pool,
            third_id,
            third_connection,
            &third_snapshot,
            300,
            128,
            10_000,
        )
        .await
        .unwrap());
        let claim = claim_sm_session(
            &pool,
            &third_hash,
            user_id,
            peer_ip,
            None,
            SmIpPolicy::Exact,
            false,
            30,
        )
        .await
        .unwrap()
        .unwrap();
        let mut transaction = pool.begin().await.unwrap();
        let activated = activate_claimed_sm_session_in_transaction(
            &mut transaction,
            claim.session_id,
            claim.claim_token,
            Uuid::new_v4(),
            1,
            1,
            peer_ip,
            None,
            300,
            30,
            128,
            10_000,
        )
        .await
        .unwrap()
        .unwrap();
        assert!(activated.unacked.is_empty());
        transaction.commit().await.unwrap();
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM offline_messages WHERE id=$1")
                .bind(third.message_id)
                .fetch_one(&pool)
                .await
                .unwrap(),
            0
        );
        revoke_sm_session(&pool, third_id).await.unwrap();

        sqlx::query("DELETE FROM users WHERE id=$1")
            .bind(user_id)
            .execute(&pool)
            .await
            .unwrap();
    }

    #[tokio::test]
    #[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
    async fn strict_same_device_claim_rejects_legacy_and_null_claimant() {
        let url = std::env::var("TEST_DATABASE_URL")
            .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(4)
            .connect(&url)
            .await
            .unwrap();
        crate::db::migrate(&pool).await.unwrap();
        let user_id = Uuid::new_v4();
        let username = format!("smdevice{}", user_id.simple());
        sqlx::query("INSERT INTO users(id,username,password_hash) VALUES($1,$2,'test-only')")
            .bind(user_id)
            .bind(&username)
            .execute(&pool)
            .await
            .unwrap();
        let peer_ip = "192.0.2.44".parse().unwrap();
        let recorded_device = Uuid::new_v4();
        let base_snapshot = SmSessionSnapshot {
            inbound_h: 0,
            outbound_h: 0,
            acked_h: 0,
            available: false,
            carbons: false,
            priority: 0,
            blocklist_requested: false,
            roster_requested: false,
            active_privacy_list: None,
            privacy_requested: false,
            peer_ip,
            user_agent_id: None,
            joined_rooms: Vec::new(),
            directed_presence: Vec::new(),
            last_presence: None,
            unacked: Vec::new(),
        };

        // A legacy snapshot cannot prove continuity. Strict mode rejects it
        // even when the reconnect supplies a well-formed device identifier.
        let legacy_hash = [31_u8; 32];
        let legacy_connection = Uuid::new_v4();
        let legacy_id = create_sm_session(
            &pool,
            &legacy_hash,
            user_id,
            0,
            &format!("{username}@example.test/legacy"),
            "legacy",
            "example.test",
            legacy_connection,
            &base_snapshot,
            300,
            30,
            8,
            100,
        )
        .await
        .unwrap();
        assert!(suspend_sm_session(
            &pool,
            legacy_id,
            legacy_connection,
            &base_snapshot,
            300,
            8,
            4_096,
        )
        .await
        .unwrap());
        assert!(matches!(
            claim_sm_session_status(
                &pool,
                &legacy_hash,
                user_id,
                peer_ip,
                Some(recorded_device),
                SmIpPolicy::Exact,
                true,
                30,
            )
            .await
            .unwrap(),
            SmClaimStatus::Rejected
        ));
        let compatibility_claim = match claim_sm_session_status(
            &pool,
            &legacy_hash,
            user_id,
            peer_ip,
            None,
            SmIpPolicy::Exact,
            false,
            30,
        )
        .await
        .unwrap()
        {
            SmClaimStatus::Claimed(claim) => *claim,
            status => panic!("legacy compatibility claim was not accepted: {status:?}"),
        };
        release_sm_claim(
            &pool,
            compatibility_claim.session_id,
            compatibility_claim.claim_token,
        )
        .await
        .unwrap();
        revoke_sm_session(&pool, legacy_id).await.unwrap();

        // Conversely, a recorded device cannot be resumed in strict mode by
        // an anonymous claimant. A matching identifier remains valid.
        let mut bound_snapshot = base_snapshot;
        bound_snapshot.user_agent_id = Some(recorded_device);
        let bound_hash = [32_u8; 32];
        let bound_connection = Uuid::new_v4();
        let bound_id = create_sm_session(
            &pool,
            &bound_hash,
            user_id,
            0,
            &format!("{username}@example.test/bound"),
            "bound",
            "example.test",
            bound_connection,
            &bound_snapshot,
            300,
            30,
            8,
            100,
        )
        .await
        .unwrap();
        assert!(suspend_sm_session(
            &pool,
            bound_id,
            bound_connection,
            &bound_snapshot,
            300,
            8,
            4_096,
        )
        .await
        .unwrap());
        for claimant in [None, Some(Uuid::new_v4())] {
            assert!(matches!(
                claim_sm_session_status(
                    &pool,
                    &bound_hash,
                    user_id,
                    peer_ip,
                    claimant,
                    SmIpPolicy::Exact,
                    true,
                    30,
                )
                .await
                .unwrap(),
                SmClaimStatus::Rejected
            ));
        }
        let matching_claim = match claim_sm_session_status(
            &pool,
            &bound_hash,
            user_id,
            peer_ip,
            Some(recorded_device),
            SmIpPolicy::Exact,
            true,
            30,
        )
        .await
        .unwrap()
        {
            SmClaimStatus::Claimed(claim) => *claim,
            status => panic!("matching strict device claim was not accepted: {status:?}"),
        };
        release_sm_claim(&pool, matching_claim.session_id, matching_claim.claim_token)
            .await
            .unwrap();
        revoke_sm_session(&pool, bound_id).await.unwrap();
        sqlx::query("DELETE FROM users WHERE id=$1")
            .bind(user_id)
            .execute(&pool)
            .await
            .unwrap();
    }

    #[tokio::test]
    #[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
    async fn durable_claim_is_single_consumer_and_revocable() {
        use sha2::{Digest, Sha256};
        let url = std::env::var("TEST_DATABASE_URL")
            .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(4)
            .connect(&url)
            .await
            .unwrap();
        crate::db::migrate(&pool).await.unwrap();
        let user_id = Uuid::new_v4();
        let username = format!("smtest{}", user_id.simple());
        sqlx::query("INSERT INTO users(id,username,password_hash) VALUES($1,$2,'test-only')")
            .bind(user_id)
            .bind(&username)
            .execute(&pool)
            .await
            .unwrap();
        let bearer = [9_u8; 32];
        let hash: [u8; 32] = Sha256::digest(bearer).into();
        let snapshot = SmSessionSnapshot {
            inbound_h: u32::MAX,
            outbound_h: 1,
            acked_h: u32::MAX,
            available: true,
            carbons: true,
            priority: 1,
            blocklist_requested: false,
            roster_requested: true,
            active_privacy_list: None,
            privacy_requested: true,
            peer_ip: "192.0.2.10".parse().unwrap(),
            user_agent_id: Some(Uuid::new_v4()),
            joined_rooms: vec![],
            directed_presence: vec![],
            last_presence: Some("<presence xmlns='jabber:client'/>".to_owned()),
            unacked: vec![
                crate::outbound::SmUnackedStanza::plain("<message id='one'/>".into()),
                crate::outbound::SmUnackedStanza::plain("<message id='two'/>".into()),
            ],
        };
        let connection_id = Uuid::new_v4();
        let id = create_sm_session(
            &pool,
            &hash,
            user_id,
            0,
            &format!("{username}@example.test/r"),
            "r",
            "example.test",
            connection_id,
            &snapshot,
            300,
            30,
            4,
            100,
        )
        .await
        .unwrap();
        let (stored_privacy, stored_peer_ip): (bool, String) = sqlx::query_as(
            "SELECT privacy_requested,pg_catalog.host(peer_ip)
               FROM sm_resume_sessions WHERE id=$1",
        )
        .bind(id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(stored_privacy);
        assert_eq!(stored_peer_ip, snapshot.peer_ip.to_string());
        let stored: Vec<u8> =
            sqlx::query_scalar("SELECT token_hash FROM sm_resume_sessions WHERE id=$1")
                .bind(id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(stored, hash);
        assert_ne!(stored, bearer);
        assert!(
            suspend_sm_session(&pool, id, connection_id, &snapshot, 300, 8, 4096)
                .await
                .unwrap()
        );

        let device = snapshot.user_agent_id;
        let first = claim_sm_session(
            &pool,
            &hash,
            user_id,
            snapshot.peer_ip,
            device,
            SmIpPolicy::Exact,
            true,
            30,
        );
        let second = claim_sm_session(
            &pool,
            &hash,
            user_id,
            snapshot.peer_ip,
            device,
            SmIpPolicy::Exact,
            true,
            30,
        );
        let (first, second) = tokio::join!(first, second);
        let claims = [first.unwrap(), second.unwrap()];
        assert_eq!(claims.iter().filter(|claim| claim.is_some()).count(), 1);
        let claim = claims.into_iter().flatten().next().unwrap();
        assert_eq!(claim.unacked, snapshot.unacked);
        assert!(claim.roster_requested);
        release_sm_claim(&pool, claim.session_id, claim.claim_token)
            .await
            .unwrap();

        // A reconnect can arrive after the transport closes but before Drop's
        // asynchronous durable suspension commits. The valid bearer/binding
        // is reported as Pending (never confused with an invalid token), then
        // becomes claimable within the protocol's bounded grace window.
        let race_hash: [u8; 32] = Sha256::digest([12_u8; 32]).into();
        let race_connection = Uuid::new_v4();
        let race_id = create_sm_session(
            &pool,
            &race_hash,
            user_id,
            0,
            &format!("{username}@example.test/race"),
            "race",
            "example.test",
            race_connection,
            &snapshot,
            300,
            30,
            4,
            100,
        )
        .await
        .unwrap();
        assert!(matches!(
            claim_sm_session_status(
                &pool,
                &race_hash,
                user_id,
                snapshot.peer_ip,
                device,
                SmIpPolicy::Exact,
                true,
                30,
            )
            .await
            .unwrap(),
            SmClaimStatus::Pending
        ));
        let suspend_pool = pool.clone();
        let suspend_snapshot = snapshot.clone();
        let delayed_suspend = tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            suspend_sm_session(
                &suspend_pool,
                race_id,
                race_connection,
                &suspend_snapshot,
                300,
                8,
                4096,
            )
            .await
            .unwrap()
        });
        let raced_claim = loop {
            match claim_sm_session_status(
                &pool,
                &race_hash,
                user_id,
                snapshot.peer_ip,
                device,
                SmIpPolicy::Exact,
                true,
                30,
            )
            .await
            .unwrap()
            {
                SmClaimStatus::Claimed(claim) => break *claim,
                SmClaimStatus::Pending => {
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await
                }
                SmClaimStatus::Rejected => panic!("valid racing SM token was rejected"),
            }
        };
        assert!(delayed_suspend.await.unwrap());
        let resumed_connection = Uuid::new_v4();
        let mut resume_tx = crate::db::lock_auth_generation(&pool, user_id, 0)
            .await
            .unwrap()
            .unwrap();
        assert!(activate_claimed_sm_session_in_transaction(
            &mut resume_tx,
            raced_claim.session_id,
            raced_claim.claim_token,
            resumed_connection,
            raced_claim.acked_h,
            0,
            snapshot.peer_ip,
            device,
            300,
            30,
            8,
            4096,
        )
        .await
        .unwrap()
        .is_some());
        resume_tx.commit().await.unwrap();
        assert!(
            !suspend_sm_session(&pool, race_id, race_connection, &snapshot, 300, 8, 4096)
                .await
                .unwrap()
        );
        let owner: (Uuid, bool) =
            sqlx::query_as("SELECT connection_id,resumable FROM sm_resume_sessions WHERE id=$1")
                .bind(race_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(owner, (resumed_connection, false));
        revoke_sm_session(&pool, race_id).await.unwrap();

        // A password/status generation change invalidates the old bearer even
        // if a disconnect races a new checkpoint.
        sqlx::query("UPDATE users SET auth_generation=auth_generation+1 WHERE id=$1")
            .bind(user_id)
            .execute(&pool)
            .await
            .unwrap();
        assert!(claim_sm_session(
            &pool,
            &hash,
            user_id,
            snapshot.peer_ip,
            device,
            SmIpPolicy::Exact,
            true,
            30,
        )
        .await
        .unwrap()
        .is_none());

        // Simulate a process crash: no clean `resumable` transition happened,
        // but the heartbeat lease elapsed. The durable row remains claimable.
        let crash_hash: [u8; 32] = Sha256::digest([10_u8; 32]).into();
        let crash_id = create_sm_session(
            &pool,
            &crash_hash,
            user_id,
            1,
            &format!("{username}@example.test/crash"),
            "crash",
            "example.test",
            Uuid::new_v4(),
            &snapshot,
            300,
            30,
            4,
            100,
        )
        .await
        .unwrap();
        sqlx::query(
            "UPDATE sm_resume_sessions SET live_lease_until=NOW()-INTERVAL '1 second' WHERE id=$1",
        )
        .bind(crash_id)
        .execute(&pool)
        .await
        .unwrap();
        let crash_claim = claim_sm_session(
            &pool,
            &crash_hash,
            user_id,
            snapshot.peer_ip,
            device,
            SmIpPolicy::Exact,
            true,
            30,
        )
        .await
        .unwrap()
        .expect("expired live lease must be recoverable after a crash");
        release_sm_claim(&pool, crash_id, crash_claim.claim_token)
            .await
            .unwrap();
        sqlx::query(
            "UPDATE sm_resume_sessions SET expires_at=NOW()-INTERVAL '1 second' WHERE id=$1",
        )
        .bind(crash_id)
        .execute(&pool)
        .await
        .unwrap();
        assert!(claim_sm_session(
            &pool,
            &crash_hash,
            user_id,
            snapshot.peer_ip,
            device,
            SmIpPolicy::Exact,
            true,
            30,
        )
        .await
        .unwrap()
        .is_none());
        let crash_teardown = cleanup_expired_sm_sessions(&pool, 30)
            .await
            .unwrap()
            .into_iter()
            .find(|snapshot| snapshot.session_id == crash_id)
            .unwrap();
        assert!(!finalize_sm_teardown(&pool, crash_id, Uuid::new_v4())
            .await
            .unwrap());
        assert!(
            finalize_sm_teardown(&pool, crash_id, crash_teardown.teardown_token)
                .await
                .unwrap()
        );

        // A resume claimant that acquired the row before expiry owns it for
        // the bounded claim lease. Maintenance must not delete or tear it
        // down underneath activation; once released, exactly one cleanup
        // pass receives the complete teardown snapshot.
        let protected_hash: [u8; 32] = Sha256::digest([11_u8; 32]).into();
        let mut protected_snapshot = snapshot.clone();
        protected_snapshot.joined_rooms = vec![SmMucMembership {
            room_jid: "room@conference.example.test".to_owned(),
            nick: "Phone User".to_owned(),
        }];
        protected_snapshot.directed_presence = vec![
            "friend@example.net".to_owned(),
            "friend@example.test/Tablet".to_owned(),
        ];
        let protected_connection = Uuid::new_v4();
        let protected_id = create_sm_session(
            &pool,
            &protected_hash,
            user_id,
            1,
            &format!("{username}@example.test/protected"),
            "protected",
            "example.test",
            protected_connection,
            &protected_snapshot,
            300,
            30,
            4,
            100,
        )
        .await
        .unwrap();
        assert!(suspend_sm_session(
            &pool,
            protected_id,
            protected_connection,
            &protected_snapshot,
            300,
            8,
            4096,
        )
        .await
        .unwrap());
        let protected_claim = claim_sm_session(
            &pool,
            &protected_hash,
            user_id,
            protected_snapshot.peer_ip,
            protected_snapshot.user_agent_id,
            SmIpPolicy::Exact,
            true,
            30,
        )
        .await
        .unwrap()
        .unwrap();
        sqlx::query(
            "UPDATE sm_resume_sessions SET expires_at=NOW()-INTERVAL '1 second' WHERE id=$1",
        )
        .bind(protected_id)
        .execute(&pool)
        .await
        .unwrap();
        assert!(!cleanup_expired_sm_sessions(&pool, 30)
            .await
            .unwrap()
            .iter()
            .any(|candidate| candidate.session_id == protected_id));
        release_sm_claim(
            &pool,
            protected_claim.session_id,
            protected_claim.claim_token,
        )
        .await
        .unwrap();
        let first_cleanup = cleanup_expired_sm_sessions(&pool, 30);
        let second_cleanup = cleanup_expired_sm_sessions(&pool, 30);
        let (first_cleanup, second_cleanup) = tokio::join!(first_cleanup, second_cleanup);
        let teardowns = first_cleanup
            .unwrap()
            .into_iter()
            .chain(second_cleanup.unwrap())
            .filter(|candidate| candidate.session_id == protected_id)
            .collect::<Vec<_>>();
        assert_eq!(teardowns.len(), 1);
        let teardown = teardowns.into_iter().next().unwrap();
        assert_eq!(teardown.username, username);
        assert!(teardown.available);
        assert_eq!(teardown.joined_rooms, protected_snapshot.joined_rooms);
        assert_eq!(
            teardown.directed_presence,
            protected_snapshot.directed_presence
        );
        assert!(!finalize_sm_teardown(&pool, protected_id, Uuid::new_v4())
            .await
            .unwrap());
        // Simulate the teardown worker crashing before finalization. Once its
        // lease expires, maintenance acquires a new token and can repeat the
        // idempotent unavailable/MUC side effects.
        sqlx::query(
            "UPDATE sm_resume_sessions SET claimed_until=NOW()-INTERVAL '1 second' WHERE id=$1",
        )
        .bind(protected_id)
        .execute(&pool)
        .await
        .unwrap();
        let retry = cleanup_expired_sm_sessions(&pool, 30)
            .await
            .unwrap()
            .into_iter()
            .find(|candidate| candidate.session_id == protected_id)
            .unwrap();
        assert_ne!(retry.teardown_token, teardown.teardown_token);
        assert!(
            !finalize_sm_teardown(&pool, protected_id, teardown.teardown_token)
                .await
                .unwrap()
        );
        assert!(
            finalize_sm_teardown(&pool, protected_id, retry.teardown_token)
                .await
                .unwrap()
        );

        sqlx::query("UPDATE users SET is_disabled=TRUE WHERE id=$1")
            .bind(user_id)
            .execute(&pool)
            .await
            .unwrap();
        assert!(claim_sm_session(
            &pool,
            &hash,
            user_id,
            snapshot.peer_ip,
            device,
            SmIpPolicy::Exact,
            true,
            30,
        )
        .await
        .unwrap()
        .is_none());
        let revoked = take_user_sm_sessions_for_teardown(&pool, user_id, 30)
            .await
            .unwrap()
            .snapshots;
        assert_eq!(revoked.len(), 1);
        assert!(
            finalize_sm_teardown(&pool, revoked[0].session_id, revoked[0].teardown_token)
                .await
                .unwrap()
        );
        sqlx::query("DELETE FROM users WHERE id=$1")
            .bind(user_id)
            .execute(&pool)
            .await
            .unwrap();
    }

    #[tokio::test]
    #[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
    async fn every_teardown_scope_preserves_the_active_privacy_list() {
        let url = std::env::var("TEST_DATABASE_URL")
            .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(4)
            .connect(&url)
            .await
            .unwrap();
        crate::db::migrate(&pool).await.unwrap();

        let user_id = Uuid::new_v4();
        let username = format!("sm-privacy-{}", &user_id.simple().to_string()[..10]);
        sqlx::query("INSERT INTO users(id,username,password_hash) VALUES($1,$2,'test-only')")
            .bind(user_id)
            .bind(&username)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO privacy_lists(owner_id,name) VALUES($1,'trusted')")
            .bind(user_id)
            .execute(&pool)
            .await
            .unwrap();

        async fn install(
            pool: &PgPool,
            user_id: Uuid,
            username: &str,
            marker: u8,
        ) -> (Uuid, String) {
            let (_, id, _snapshot) =
                install_authorization_test_sm(pool, user_id, username, marker).await;
            sqlx::query(
                "UPDATE sm_resume_sessions SET active_privacy_list='trusted', privacy_requested=TRUE WHERE id=$1",
            )
            .bind(id)
            .execute(pool)
            .await
            .unwrap();
            (id, format!("{username}@example.test/Device-{marker}"))
        }

        async fn finish(pool: &PgPool, snapshot: SmTeardownSnapshot, expected: Uuid) {
            assert_eq!(snapshot.session_id, expected);
            assert_eq!(snapshot.active_privacy_list.as_deref(), Some("trusted"));
            assert!(
                finalize_sm_teardown(pool, expected, snapshot.teardown_token)
                    .await
                    .unwrap()
            );
        }

        let (single_id, _) = install(&pool, user_id, &username, 91).await;
        finish(
            &pool,
            take_sm_session_for_teardown(&pool, single_id, 30)
                .await
                .unwrap()
                .unwrap(),
            single_id,
        )
        .await;

        let (user_id_row, _) = install(&pool, user_id, &username, 92).await;
        let user_batch = take_user_sm_sessions_for_teardown(&pool, user_id, 30)
            .await
            .unwrap();
        assert_eq!(user_batch.pending, 0);
        assert_eq!(user_batch.snapshots.len(), 1);
        finish(
            &pool,
            user_batch.snapshots.into_iter().next().unwrap(),
            user_id_row,
        )
        .await;

        let (full_id, full_jid) = install(&pool, user_id, &username, 93).await;
        let full_batch = take_sm_sessions_for_full_jid_teardown(&pool, &full_jid, 30)
            .await
            .unwrap();
        assert_eq!(full_batch.pending, 0);
        assert_eq!(full_batch.snapshots.len(), 1);
        finish(
            &pool,
            full_batch.snapshots.into_iter().next().unwrap(),
            full_id,
        )
        .await;

        let (all_id, _) = install(&pool, user_id, &username, 94).await;
        let all_batch = take_all_sm_sessions_for_teardown(&pool, 30).await.unwrap();
        assert_eq!(all_batch.pending, 0);
        assert_eq!(all_batch.snapshots.len(), 1);
        finish(
            &pool,
            all_batch.snapshots.into_iter().next().unwrap(),
            all_id,
        )
        .await;

        let (expired_id, _) = install(&pool, user_id, &username, 95).await;
        sqlx::query(
            "UPDATE sm_resume_sessions SET expires_at=NOW()-INTERVAL '1 second' WHERE id=$1",
        )
        .bind(expired_id)
        .execute(&pool)
        .await
        .unwrap();
        let expired = cleanup_expired_sm_sessions(&pool, 30)
            .await
            .unwrap()
            .into_iter()
            .find(|candidate| candidate.session_id == expired_id)
            .unwrap();
        finish(&pool, expired, expired_id).await;

        sqlx::query("DELETE FROM users WHERE id=$1")
            .bind(user_id)
            .execute(&pool)
            .await
            .unwrap();
    }

    #[tokio::test]
    #[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
    async fn account_deletion_quiesce_closes_all_sm_race_barriers() {
        let url = std::env::var("TEST_DATABASE_URL")
            .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(8)
            .connect(&url)
            .await
            .unwrap();
        crate::db::migrate(&pool).await.unwrap();
        let user_id = Uuid::new_v4();
        let username = format!("sm-delete-{}", &user_id.simple().to_string()[..10]);
        sqlx::query("INSERT INTO users(id,username,password_hash) VALUES($1,$2,'test-only')")
            .bind(user_id)
            .bind(&username)
            .execute(&pool)
            .await
            .unwrap();
        let (hash, session_id, snapshot) =
            install_authorization_test_sm(&pool, user_id, &username, 81).await;
        sqlx::query(
            "UPDATE sm_resume_sessions SET resumable=TRUE,live_lease_until=NOW() WHERE id=$1",
        )
        .bind(session_id)
        .execute(&pool)
        .await
        .unwrap();
        let claim = match claim_sm_session_status(
            &pool,
            &hash,
            user_id,
            snapshot.peer_ip,
            snapshot.user_agent_id,
            SmIpPolicy::Exact,
            true,
            30,
        )
        .await
        .unwrap()
        {
            SmClaimStatus::Claimed(claim) => claim,
            other => panic!("expected a held claim, got {other:?}"),
        };

        // Barrier 1: none of the bulk teardown scopes may steal a live claim.
        let user_batch = take_user_sm_sessions_for_teardown(&pool, user_id, 30)
            .await
            .unwrap();
        assert!(user_batch.snapshots.is_empty());
        assert_eq!(user_batch.pending, 1);
        let full_batch = take_sm_sessions_for_full_jid_teardown(&pool, &claim.full_jid, 30)
            .await
            .unwrap();
        assert!(full_batch.snapshots.is_empty());
        assert_eq!(full_batch.pending, 1);
        let all_batch = take_all_sm_sessions_for_teardown(&pool, 30).await.unwrap();
        assert!(all_batch.snapshots.is_empty());
        assert_eq!(all_batch.pending, 1);
        let persisted_token: Option<Uuid> =
            sqlx::query_scalar("SELECT claim_token FROM sm_resume_sessions WHERE id=$1")
                .bind(session_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(persisted_token, Some(claim.claim_token));

        assert!(crate::db::begin_account_deletion_quiesce(&pool, user_id)
            .await
            .unwrap());

        // Barrier 2: a claim obtained before quiesce cannot activate after it.
        let mut activation = pool.begin().await.unwrap();
        assert!(activate_claimed_sm_session_in_transaction(
            &mut activation,
            claim.session_id,
            claim.claim_token,
            Uuid::new_v4(),
            claim.acked_h,
            0,
            snapshot.peer_ip,
            snapshot.user_agent_id,
            300,
            30,
            8,
            4096,
        )
        .await
        .unwrap()
        .is_none());
        activation.rollback().await.unwrap();

        // Barrier 3: a stale live connection cannot enable new durable SM.
        assert!(create_sm_session(
            &pool,
            &[82_u8; 32],
            user_id,
            0,
            &format!("{username}@example.test/new"),
            "new",
            "example.test",
            Uuid::new_v4(),
            &snapshot,
            300,
            30,
            8,
            100,
        )
        .await
        .is_err());

        // Barrier 4: quiesce rejects a new resume and the pending old claim
        // becomes teardownable without changing ownership behind its back.
        assert!(matches!(
            claim_sm_session_status(
                &pool,
                &hash,
                user_id,
                snapshot.peer_ip,
                snapshot.user_agent_id,
                SmIpPolicy::Exact,
                true,
                30,
            )
            .await
            .unwrap(),
            SmClaimStatus::Rejected
        ));
        release_sm_claim(&pool, session_id, claim.claim_token)
            .await
            .unwrap();
        let batch = take_user_sm_sessions_for_teardown(&pool, user_id, 30)
            .await
            .unwrap();
        assert_eq!(batch.pending, 0);
        assert_eq!(batch.snapshots.len(), 1);
        assert!(
            finalize_sm_teardown(&pool, session_id, batch.snapshots[0].teardown_token)
                .await
                .unwrap()
        );
        assert_eq!(count_user_sm_rows(&pool, user_id).await.unwrap(), 0);
        sqlx::query("DELETE FROM users WHERE id=$1")
            .bind(user_id)
            .execute(&pool)
            .await
            .unwrap();
    }
}
