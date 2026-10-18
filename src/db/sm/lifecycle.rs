//! Claims and revokes resumable sessions and leases, counts, and finalizes durable teardown state.

use super::*;

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
pub(super) async fn take_sm_teardown_scope(
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
