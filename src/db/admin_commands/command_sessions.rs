//! Persists command execution sessions and manages session-cleanup leases.

use super::*;

pub async fn claim_admin_session_cleanup(
    pool: &PgPool,
    worker_id: Uuid,
    lease_seconds: i32,
) -> Result<Option<AdminSessionCleanupLease>> {
    let row = sqlx::query(
        "SELECT id,command_operation_id,kind,user_id,auth_generation,bare_jid,
                full_jid,connection_id,lease_token,attempts
           FROM northstar_claim_admin_session_cleanup($1,$2)",
    )
    .bind(worker_id)
    .bind(lease_seconds)
    .fetch_optional(pool)
    .await?;
    row.map(|row| {
        let kind = match row.get::<String, _>("kind").as_str() {
            "account_generation" => AdminSessionCleanupKind::AccountGeneration,
            "exact_connection" => AdminSessionCleanupKind::ExactConnection,
            other => anyhow::bail!("unknown administrator session cleanup kind {other:?}"),
        };
        Ok(AdminSessionCleanupLease {
            id: row.get("id"),
            command_operation_id: row.get("command_operation_id"),
            kind,
            user_id: row.get("user_id"),
            auth_generation: row.get("auth_generation"),
            bare_jid: row.get("bare_jid"),
            full_jid: row.get("full_jid"),
            connection_id: row.get("connection_id"),
            lease_token: row.get("lease_token"),
            attempts: row.get("attempts"),
        })
    })
    .transpose()
}

pub async fn renew_admin_session_cleanup(
    pool: &PgPool,
    lease: &AdminSessionCleanupLease,
    worker_id: Uuid,
    lease_seconds: i32,
) -> Result<bool> {
    Ok(
        sqlx::query_scalar("SELECT northstar_renew_admin_session_cleanup($1,$2,$3,$4)")
            .bind(lease.id)
            .bind(worker_id)
            .bind(lease.lease_token)
            .bind(lease_seconds)
            .fetch_one(pool)
            .await?,
    )
}

pub async fn retry_admin_session_cleanup(
    pool: &PgPool,
    lease: &AdminSessionCleanupLease,
    worker_id: Uuid,
    error_code: &str,
) -> Result<bool> {
    Ok(
        sqlx::query_scalar("SELECT northstar_retry_admin_session_cleanup($1,$2,$3,$4)")
            .bind(lease.id)
            .bind(worker_id)
            .bind(lease.lease_token)
            .bind(error_code)
            .fetch_one(pool)
            .await?,
    )
}

pub async fn complete_admin_session_cleanup(
    pool: &PgPool,
    lease: &AdminSessionCleanupLease,
    worker_id: Uuid,
) -> Result<bool> {
    Ok(
        sqlx::query_scalar("SELECT northstar_complete_admin_session_cleanup($1,$2,$3)")
            .bind(lease.id)
            .bind(worker_id)
            .bind(lease.lease_token)
            .fetch_one(pool)
            .await?,
    )
}

pub async fn admin_session_cleanup_target_current(
    pool: &PgPool,
    lease: &AdminSessionCleanupLease,
    worker_id: Uuid,
) -> Result<bool> {
    Ok(
        sqlx::query_scalar("SELECT northstar_admin_session_cleanup_target_current($1,$2,$3)")
            .bind(lease.id)
            .bind(worker_id)
            .bind(lease.lease_token)
            .fetch_one(pool)
            .await?,
    )
}

pub async fn admin_session_cleanup_snapshot(pool: &PgPool) -> Result<AdminSessionCleanupSnapshot> {
    let row = sqlx::query(
        "SELECT pending,running,oldest_age_seconds,maximum_attempts,queued,capacity
           FROM northstar_admin_session_cleanup_snapshot()",
    )
    .fetch_one(pool)
    .await?;
    Ok(AdminSessionCleanupSnapshot {
        pending: row.get("pending"),
        running: row.get("running"),
        oldest_age_seconds: row.get("oldest_age_seconds"),
        maximum_attempts: row.get("maximum_attempts"),
        queued: row.get("queued"),
        capacity: row.get("capacity"),
    })
}

pub async fn create_admin_command_session(
    pool: &PgPool,
    owner_id: Uuid,
    owner_full_jid: &str,
    server_domain: &str,
    owner_auth_generation: i64,
    node: &str,
    stage: &str,
) -> Result<Option<zeroize::Zeroizing<String>>> {
    let owner_full_jid = crate::jid::canonical_session_key(owner_full_jid)?;
    let server_domain = crate::jid::prepare_domainpart(server_domain)?;
    let owner_username = crate::jid::CanonicalJid::parse(&owner_full_jid)?
        .localpart()
        .context("admin command owner JID has no localpart")?
        .to_owned();
    let bearer = zeroize::Zeroizing::new(crate::auth::new_session_token());
    let created: bool = sqlx::query_scalar(
        "SELECT northstar_admin_command_create_session(
           $1,$2,$3,$4,$5,$6,$7,$8,$9)",
    )
    .bind(Uuid::new_v4())
    .bind(bearer.as_str())
    .bind(owner_id)
    .bind(&owner_username)
    .bind(&owner_full_jid)
    .bind(&server_domain)
    .bind(owner_auth_generation)
    .bind(node)
    .bind(stage)
    .fetch_one(pool)
    .await?;
    Ok(created.then_some(bearer))
}

pub async fn finish_admin_command_session(
    pool: &PgPool,
    bearer: &str,
    owner_id: Uuid,
    owner_full_jid: &str,
    owner_auth_generation: i64,
    node: &str,
    final_stage: &str,
) -> Result<AdminCommandSessionState> {
    let owner_full_jid = crate::jid::canonical_session_key(owner_full_jid)?;
    let owner_username = crate::jid::CanonicalJid::parse(&owner_full_jid)?
        .localpart()
        .context("admin command owner JID has no localpart")?
        .to_owned();
    let outcome: String =
        sqlx::query_scalar("SELECT northstar_admin_command_finish_session($1,$2,$3,$4,$5,$6,$7)")
            .bind(bearer)
            .bind(owner_id)
            .bind(&owner_username)
            .bind(&owner_full_jid)
            .bind(owner_auth_generation)
            .bind(node)
            .bind(final_stage)
            .fetch_one(pool)
            .await?;
    Ok(match outcome.as_str() {
        "finished" => AdminCommandSessionState::Finished,
        "expired" => AdminCommandSessionState::Expired,
        "invalid" => AdminCommandSessionState::Invalid,
        other => anyhow::bail!("admin command finish capability returned {other:?}"),
    })
}

/// Finish an immediate read-only command and append its audit record in the
/// same transaction. The administrator row is rechecked after locking the
/// command session, so demotion, disablement or credential rotation cannot
/// race a stale stream cache into an unaudited read.
pub async fn complete_admin_count_command_session(
    pool: &PgPool,
    bearer: &str,
    owner_id: Uuid,
    owner_full_jid: &str,
    owner_auth_generation: i64,
    node: &str,
    payload: &str,
) -> Result<AdminCommandSessionState> {
    let owner_full_jid = crate::jid::canonical_session_key(owner_full_jid)?;
    let owner_username = crate::jid::CanonicalJid::parse(&owner_full_jid)?
        .localpart()
        .context("admin command owner JID has no localpart")?
        .to_owned();
    let outcome: String = sqlx::query_scalar(
        "SELECT northstar_admin_command_complete_immediate_read(
           $1,$2,$3,$4,$5,$6,$7)",
    )
    .bind(bearer)
    .bind(owner_id)
    .bind(&owner_username)
    .bind(&owner_full_jid)
    .bind(owner_auth_generation)
    .bind(node)
    .bind(payload)
    .fetch_one(pool)
    .await?;
    Ok(match outcome.as_str() {
        "finished" => AdminCommandSessionState::Finished,
        "expired" => AdminCommandSessionState::Expired,
        "invalid" => AdminCommandSessionState::Invalid,
        other => anyhow::bail!("admin command read completion returned {other:?}"),
    })
}

/// Claim a form submission for execution.  The non-sensitive protocol digest
/// binds retries to this command implementation version, while the durable
/// result lets a client safely repeat an IQ after losing the response.  An
/// in-flight operation is never
/// automatically stolen: doing so could repeat a mutation after a process
/// died between its business commit and result persistence.
pub async fn begin_admin_command_execution(
    pool: &PgPool,
    bearer: &str,
    owner_id: Uuid,
    owner_full_jid: &str,
    owner_auth_generation: i64,
    node: &str,
    request_digest: &[u8],
) -> Result<AdminCommandExecutionState> {
    let owner_full_jid = crate::jid::canonical_session_key(owner_full_jid)?;
    let owner_username = crate::jid::CanonicalJid::parse(&owner_full_jid)?
        .localpart()
        .context("admin command owner JID has no localpart")?
        .to_owned();
    anyhow::ensure!(request_digest.len() == 32, "invalid command target digest");
    let claim_token = zeroize::Zeroizing::new(crate::auth::new_session_token());
    let requested_operation_id = Uuid::new_v4();
    let row = sqlx::query(
        "SELECT outcome,operation_id,result_payload
           FROM northstar_admin_command_begin_execution(
             $1,$2,$3,$4,$5,$6,$7,$8,$9)",
    )
    .bind(bearer)
    .bind(claim_token.as_str())
    .bind(requested_operation_id)
    .bind(owner_id)
    .bind(&owner_username)
    .bind(&owner_full_jid)
    .bind(owner_auth_generation)
    .bind(node)
    .bind(request_digest)
    .fetch_one(pool)
    .await?;
    Ok(match row.get::<String, _>("outcome").as_str() {
        "started" => AdminCommandExecutionState::Started(AdminCommandClaim {
            operation_id: row
                .get::<Option<Uuid>, _>("operation_id")
                .context("started admin command omitted operation id")?,
            token: claim_token,
        }),
        "busy" => AdminCommandExecutionState::Busy,
        "completed" => AdminCommandExecutionState::Completed(
            row.get::<Option<String>, _>("result_payload")
                .context("completed admin command omitted result payload")?,
        ),
        "expired" => AdminCommandExecutionState::Expired,
        "invalid" => AdminCommandExecutionState::Invalid,
        other => anyhow::bail!("admin command claim returned {other:?}"),
    })
}

/// Return a syntactically valid but semantically invalid form to the form
/// stage.  Matching the operation id prevents a delayed failure from
/// releasing a newer execution claim.
pub async fn release_admin_command_execution(
    pool: &PgPool,
    claim_token: &str,
    actor_id: Uuid,
    actor_username: &str,
    actor_generation: i64,
    node: &str,
    target_digest: &[u8],
) -> Result<bool> {
    Ok(
        sqlx::query_scalar("SELECT northstar_admin_command_release_claim($1,$2,$3,$4,$5,$6)")
            .bind(claim_token)
            .bind(actor_id)
            .bind(actor_username)
            .bind(actor_generation)
            .bind(node)
            .bind(target_digest)
            .fetch_one(pool)
            .await?,
    )
}

pub async fn renew_admin_command_execution(
    pool: &PgPool,
    claim_token: &str,
    actor_id: Uuid,
    actor_username: &str,
    actor_generation: i64,
    node: &str,
    target_digest: &[u8],
) -> Result<bool> {
    Ok(
        sqlx::query_scalar("SELECT northstar_admin_command_renew_claim($1,$2,$3,$4,$5,$6)")
            .bind(claim_token)
            .bind(actor_id)
            .bind(actor_username)
            .bind(actor_generation)
            .bind(node)
            .bind(target_digest)
            .fetch_one(pool)
            .await?,
    )
}

#[expect(
    clippy::too_many_arguments,
    reason = "the claim capability is compared field-for-field by one database function"
)]
pub async fn complete_admin_command_read_execution(
    pool: &PgPool,
    claim_token: &str,
    actor_id: Uuid,
    actor_username: &str,
    actor_generation: i64,
    node: &str,
    target_digest: &[u8],
    payload: &str,
) -> Result<bool> {
    Ok(sqlx::query_scalar(
        "SELECT northstar_admin_command_complete_read_claim($1,$2,$3,$4,$5,$6,$7)",
    )
    .bind(claim_token)
    .bind(actor_id)
    .bind(actor_username)
    .bind(actor_generation)
    .bind(node)
    .bind(target_digest)
    .bind(payload)
    .fetch_one(pool)
    .await?)
}

pub async fn cleanup_admin_command_sessions(pool: &PgPool) -> Result<u64> {
    let removed: i64 = sqlx::query_scalar("SELECT northstar_admin_command_cleanup()")
        .fetch_one(pool)
        .await
        .context("could not prune admin command sessions")?;
    u64::try_from(removed).context("admin command cleanup returned a negative row count")
}
