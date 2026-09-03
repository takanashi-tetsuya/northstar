use anyhow::{Context, Result};
use sqlx::{PgPool, Row};
use std::collections::HashMap;
#[cfg(test)]
use std::collections::HashSet;
use uuid::Uuid;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdminCommandSessionState {
    Finished,
    Expired,
    Invalid,
}

#[derive(Debug, Eq, PartialEq)]
pub enum AdminCommandExecutionState {
    Started(AdminCommandClaim),
    Busy,
    Completed(String),
    Expired,
    Invalid,
}

#[derive(Eq, PartialEq)]
pub struct AdminCommandClaim {
    pub operation_id: Uuid,
    pub token: zeroize::Zeroizing<String>,
}

impl std::fmt::Debug for AdminCommandClaim {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AdminCommandClaim")
            .field("operation_id", &self.operation_id)
            .field("token", &"[REDACTED]")
            .finish()
    }
}

pub struct AdminCommandFence<'a> {
    pub claim_token: &'a str,
    pub actor_id: Uuid,
    pub actor_username: &'a str,
    pub actor_generation: i64,
    pub node: &'a str,
    pub target_digest: &'a [u8],
    pub result_payload: &'a str,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClaimedAdminServiceMessage {
    pub kind: String,
    pub body: String,
    pub revision: Uuid,
    pub delivery_date: chrono::NaiveDate,
    pub claim_id: Uuid,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DurableServiceControl {
    pub generation: Uuid,
    pub action: String,
    pub execute_at: chrono::DateTime<chrono::Utc>,
    pub fired_at: Option<chrono::DateTime<chrono::Utc>>,
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdminAccountIdentity {
    pub id: Uuid,
    pub username: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdminAccountMutationTarget {
    pub id: Uuid,
    pub username: String,
    pub exact_full_jid: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdminAccountMutationAction {
    Delete,
    Disable,
    Reenable,
    EndSessions,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AdminCreateAccountOutcome {
    Created,
    UsernameTaken,
    CapacityExhausted,
    Unauthorized,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdminAccountWriteOutcome {
    Applied,
    Unauthorized,
    TargetChanged,
    SelfMutation,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AdminBatchAccountWriteOutcome {
    Applied(Vec<AdminAccountMutationTarget>),
    Unauthorized,
    TargetChanged,
    SelfMutation,
    LastAdministrator,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdminSessionCleanupKind {
    AccountGeneration,
    ExactConnection,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdminSessionCleanupLease {
    pub id: Uuid,
    pub command_operation_id: Uuid,
    pub kind: AdminSessionCleanupKind,
    pub user_id: Uuid,
    pub auth_generation: i64,
    pub bare_jid: Option<String>,
    pub full_jid: Option<String>,
    pub connection_id: Option<Uuid>,
    pub lease_token: Uuid,
    pub attempts: i64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct AdminSessionCleanupSnapshot {
    pub pending: i64,
    pub running: i64,
    pub oldest_age_seconds: f64,
    pub maximum_attempts: i64,
    pub queued: i64,
    pub capacity: i64,
}

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

async fn admin_authorized_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    actor_id: Uuid,
    actor_username: &str,
    actor_generation: i64,
) -> Result<bool> {
    Ok(sqlx::query_scalar::<_, bool>(
        "SELECT TRUE FROM users
         WHERE id=$1 AND username=$2 AND auth_generation=$3
           AND is_admin AND NOT is_disabled FOR SHARE",
    )
    .bind(actor_id)
    .bind(actor_username)
    .bind(actor_generation)
    .fetch_optional(&mut **tx)
    .await?
    .is_some())
}

/// Resolve the exact account incarnations named by an administrative form.
/// Every mutating entry point below compares both UUID and username again
/// after locking, so a delete/recreate race cannot redirect a command to the
/// replacement account.
pub async fn resolve_admin_account_identities(
    pool: &PgPool,
    usernames: &[String],
) -> Result<Option<Vec<AdminAccountIdentity>>> {
    if usernames.is_empty() {
        return Ok(Some(Vec::new()));
    }
    let mut unique = usernames.to_vec();
    unique.sort();
    unique.dedup();
    if unique.len() != usernames.len() {
        return Ok(None);
    }
    let rows = sqlx::query("SELECT id,username FROM users WHERE username=ANY($1)")
        .bind(&unique)
        .fetch_all(pool)
        .await?;
    if rows.len() != unique.len() {
        return Ok(None);
    }
    let by_name = rows
        .into_iter()
        .map(|row| (row.get::<String, _>("username"), row.get::<Uuid, _>("id")))
        .collect::<HashMap<_, _>>();
    Ok(usernames
        .iter()
        .map(|username| {
            by_name
                .get(username)
                .copied()
                .map(|id| AdminAccountIdentity {
                    id,
                    username: username.clone(),
                })
        })
        .collect())
}

#[allow(clippy::too_many_arguments)]
pub async fn create_admin_account_authorized(
    pool: &PgPool,
    fence: AdminCommandFence<'_>,
    username: &str,
    password: &str,
    scram_iterations: u32,
    scram_sha1_enabled: bool,
) -> Result<AdminCreateAccountOutcome> {
    let username = crate::auth::normalize_username(username)?;
    let password = zeroize::Zeroizing::new(password.to_owned());
    let credentials = crate::password_work::run(move || {
        crate::auth::hash_password(&password, true, scram_iterations, scram_sha1_enabled)
    })
    .await
    .map_err(anyhow::Error::from)
    .context("password hashing task failed")?;

    let mut tx = pool.begin().await?;
    sqlx::query("SET LOCAL lock_timeout='2s'")
        .execute(&mut *tx)
        .await?;
    sqlx::query("SET LOCAL statement_timeout='15s'")
        .execute(&mut *tx)
        .await?;
    let user_id = Uuid::new_v4();
    let scram_iterations = i32::try_from(credentials.scram_iterations)?;
    let sha1_iterations = credentials
        .scram_sha1_stored_key
        .as_ref()
        .map(|_| scram_iterations);
    let outcome: String = sqlx::query_scalar(
        "SELECT northstar_admin_command_create_user(
            $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)",
    )
    .bind(fence.claim_token)
    .bind(fence.actor_id)
    .bind(fence.actor_username)
    .bind(fence.actor_generation)
    .bind(fence.node)
    .bind(fence.target_digest)
    .bind(user_id)
    .bind(&username)
    .bind(&credentials.hash)
    .bind(&credentials.scram_salt)
    .bind(scram_iterations)
    .bind(&credentials.scram_stored_key)
    .bind(&credentials.scram_server_key)
    .bind(&credentials.scram_sha1_salt)
    .bind(sha1_iterations)
    .bind(&credentials.scram_sha1_stored_key)
    .bind(&credentials.scram_sha1_server_key)
    .bind(fence.result_payload)
    .fetch_one(&mut *tx)
    .await?;
    let outcome = match outcome.as_str() {
        "created" => AdminCreateAccountOutcome::Created,
        "username_taken" => AdminCreateAccountOutcome::UsernameTaken,
        "capacity_exhausted" => AdminCreateAccountOutcome::CapacityExhausted,
        "unauthorized" => AdminCreateAccountOutcome::Unauthorized,
        other => anyhow::bail!("admin create-user capability returned {other:?}"),
    };
    if outcome == AdminCreateAccountOutcome::Created {
        tx.commit().await?;
    } else {
        tx.rollback().await?;
    }
    Ok(outcome)
}

#[allow(clippy::too_many_arguments)]
pub async fn reset_admin_account_password_authorized(
    pool: &PgPool,
    fence: AdminCommandFence<'_>,
    target: &AdminAccountIdentity,
    password: &str,
    scram_iterations: u32,
    scram_sha1_enabled: bool,
    bare_jid: &str,
) -> Result<AdminAccountWriteOutcome> {
    let bare_jid = crate::jid::CanonicalJid::parse_bare(bare_jid)?;
    anyhow::ensure!(
        bare_jid.localpart() == Some(target.username.as_str()),
        "password-reset JID does not match the target account"
    );
    let password = zeroize::Zeroizing::new(password.to_owned());
    let credentials = crate::password_work::run(move || {
        crate::auth::hash_password(&password, true, scram_iterations, scram_sha1_enabled)
    })
    .await
    .map_err(anyhow::Error::from)
    .context("password hashing task failed")?;
    let mut tx = pool.begin().await?;
    sqlx::query("SET LOCAL lock_timeout='2s'")
        .execute(&mut *tx)
        .await?;
    sqlx::query("SET LOCAL statement_timeout='15s'")
        .execute(&mut *tx)
        .await?;
    let scram_iterations = i32::try_from(credentials.scram_iterations)?;
    let sha1_iterations = credentials
        .scram_sha1_stored_key
        .as_ref()
        .map(|_| scram_iterations);
    let outcome: String = sqlx::query_scalar(
        "SELECT northstar_admin_command_reset_user_password(
            $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19)",
    )
    .bind(fence.claim_token)
    .bind(fence.actor_id)
    .bind(fence.actor_username)
    .bind(fence.actor_generation)
    .bind(fence.node)
    .bind(fence.target_digest)
    .bind(target.id)
    .bind(&target.username)
    .bind(&credentials.hash)
    .bind(&credentials.scram_salt)
    .bind(scram_iterations)
    .bind(&credentials.scram_stored_key)
    .bind(&credentials.scram_server_key)
    .bind(&credentials.scram_sha1_salt)
    .bind(sha1_iterations)
    .bind(&credentials.scram_sha1_stored_key)
    .bind(&credentials.scram_sha1_server_key)
    .bind(bare_jid.to_string())
    .bind(fence.result_payload)
    .fetch_one(&mut *tx)
    .await?;
    let outcome = match outcome.as_str() {
        "applied" => AdminAccountWriteOutcome::Applied,
        "unauthorized" => AdminAccountWriteOutcome::Unauthorized,
        "target_changed" => AdminAccountWriteOutcome::TargetChanged,
        other => anyhow::bail!("admin password-reset capability returned {other:?}"),
    };
    if outcome == AdminAccountWriteOutcome::Applied {
        tx.commit().await?;
    } else {
        tx.rollback().await?;
    }
    Ok(outcome)
}

#[allow(clippy::too_many_arguments)]
pub async fn mutate_admin_accounts_authorized(
    pool: &PgPool,
    fence: AdminCommandFence<'_>,
    targets: &[AdminAccountMutationTarget],
    action: AdminAccountMutationAction,
    domain: &str,
) -> Result<AdminBatchAccountWriteOutcome> {
    mutate_admin_accounts_authorized_inner(pool, fence, targets, action, domain, None).await
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
pub async fn mutate_admin_accounts_authorized_with_failure_after(
    pool: &PgPool,
    fence: AdminCommandFence<'_>,
    targets: &[AdminAccountMutationTarget],
    action: AdminAccountMutationAction,
    domain: &str,
    fail_after: usize,
) -> Result<AdminBatchAccountWriteOutcome> {
    mutate_admin_accounts_authorized_inner(pool, fence, targets, action, domain, Some(fail_after))
        .await
}

#[allow(clippy::too_many_arguments)]
async fn mutate_admin_accounts_authorized_inner(
    pool: &PgPool,
    fence: AdminCommandFence<'_>,
    targets: &[AdminAccountMutationTarget],
    action: AdminAccountMutationAction,
    domain: &str,
    fail_after: Option<usize>,
) -> Result<AdminBatchAccountWriteOutcome> {
    anyhow::ensure!(!targets.is_empty(), "account mutation target list is empty");
    anyhow::ensure!(targets.len() <= 200, "too many account mutation targets");
    let domain = crate::jid::prepare_domainpart(domain)?;
    let mut target_ids = targets.iter().map(|target| target.id).collect::<Vec<_>>();
    target_ids.sort_unstable();
    target_ids.dedup();
    if target_ids.len() != targets.len() {
        return Ok(AdminBatchAccountWriteOutcome::TargetChanged);
    }
    let mut usernames = targets
        .iter()
        .map(|target| target.username.as_str())
        .collect::<Vec<_>>();
    usernames.sort_unstable();
    usernames.dedup();
    if usernames.len() != targets.len() {
        return Ok(AdminBatchAccountWriteOutcome::TargetChanged);
    }
    for target in targets {
        if let Some(full_jid) = target.exact_full_jid.as_deref() {
            let full_jid = crate::jid::CanonicalJid::parse(full_jid)?;
            anyhow::ensure!(
                full_jid.localpart() == Some(target.username.as_str())
                    && full_jid.domainpart() == domain
                    && full_jid.resourcepart().is_some(),
                "exact session JID does not match its account incarnation"
            );
        }
    }

    let mut tx = pool.begin().await?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE")
        .execute(&mut *tx)
        .await?;
    sqlx::query("SET LOCAL lock_timeout='2s'")
        .execute(&mut *tx)
        .await?;
    sqlx::query("SET LOCAL statement_timeout='15s'")
        .execute(&mut *tx)
        .await?;
    // Account deletion cascades update the shared upload ledger. Preserve the
    // system-wide lock order used by self-service deletion: ledger, then
    // command session/actor authority, then the account-authority gate and
    // UUID-ordered target rows.
    if action == AdminAccountMutationAction::Delete {
        sqlx::query("SELECT northstar_upload_capacity_lock()")
            .fetch_one(&mut *tx)
            .await
            .context("upload storage capacity busy; retry administrative account deletion")?;
    }
    let claim_session: Option<Uuid> =
        sqlx::query_scalar("SELECT northstar_admin_command_authorize_claim($1,$2,$3,$4,$5,$6)")
            .bind(fence.claim_token)
            .bind(fence.actor_id)
            .bind(fence.actor_username)
            .bind(fence.actor_generation)
            .bind(fence.node)
            .bind(fence.target_digest)
            .fetch_one(&mut *tx)
            .await?;
    if claim_session.is_none() {
        tx.rollback().await?;
        return Ok(AdminBatchAccountWriteOutcome::Unauthorized);
    }
    sqlx::query("SELECT pg_advisory_xact_lock(5645368709120101)")
        .execute(&mut *tx)
        .await?;

    let mut local_contacts: HashMap<Uuid, HashMap<String, (Uuid, String)>> = HashMap::new();
    let mut lock_ids = target_ids.clone();
    lock_ids.push(fence.actor_id);
    if action == AdminAccountMutationAction::Delete {
        for row in sqlx::query(
            "SELECT r.owner_id,r.contact_jid,u.id,u.username
               FROM roster_items r
               JOIN users u ON u.username=split_part(r.contact_jid,'@',1)
              WHERE r.owner_id=ANY($1)
                AND split_part(r.contact_jid,'@',2)=$2
                AND position('/' in r.contact_jid)=0",
        )
        .bind(&target_ids)
        .bind(&domain)
        .fetch_all(&mut *tx)
        .await?
        {
            let owner_id: Uuid = row.get("owner_id");
            let contact_id: Uuid = row.get("id");
            if contact_id != owner_id {
                lock_ids.push(contact_id);
                local_contacts
                    .entry(owner_id)
                    .or_default()
                    .insert(row.get("contact_jid"), (contact_id, row.get("username")));
            }
        }
    }
    lock_ids.sort_unstable();
    lock_ids.dedup();
    sqlx::query_scalar::<_, Uuid>("SELECT id FROM users WHERE id=ANY($1) ORDER BY id FOR UPDATE")
        .bind(&lock_ids)
        .fetch_all(&mut *tx)
        .await?;
    if !admin_authorized_in_tx(
        &mut tx,
        fence.actor_id,
        fence.actor_username,
        fence.actor_generation,
    )
    .await?
    {
        tx.rollback().await?;
        return Ok(AdminBatchAccountWriteOutcome::Unauthorized);
    }
    let rows = sqlx::query(
        "SELECT id,username,is_admin,is_disabled FROM users
         WHERE id=ANY($1) ORDER BY id",
    )
    .bind(&target_ids)
    .fetch_all(&mut *tx)
    .await?;
    if rows.len() != targets.len() {
        tx.rollback().await?;
        return Ok(AdminBatchAccountWriteOutcome::TargetChanged);
    }
    let target_rows = rows
        .into_iter()
        .map(|row| {
            (
                row.get::<Uuid, _>("id"),
                (
                    row.get::<String, _>("username"),
                    row.get::<bool, _>("is_admin"),
                    row.get::<bool, _>("is_disabled"),
                ),
            )
        })
        .collect::<HashMap<_, _>>();
    if targets.iter().any(|target| {
        target_rows
            .get(&target.id)
            .is_none_or(|(username, _, _)| username != &target.username)
    }) {
        tx.rollback().await?;
        return Ok(AdminBatchAccountWriteOutcome::TargetChanged);
    }
    if matches!(
        action,
        AdminAccountMutationAction::Delete | AdminAccountMutationAction::Disable
    ) && target_ids.contains(&fence.actor_id)
    {
        tx.rollback().await?;
        return Ok(AdminBatchAccountWriteOutcome::SelfMutation);
    }
    if matches!(
        action,
        AdminAccountMutationAction::Delete | AdminAccountMutationAction::Disable
    ) {
        let removes_enabled_admin = targets.iter().any(|target| {
            target_rows
                .get(&target.id)
                .is_some_and(|(_, is_admin, disabled)| *is_admin && !*disabled)
        });
        if removes_enabled_admin {
            let remaining: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM users
                 WHERE is_admin AND NOT is_disabled AND NOT (id=ANY($1))",
            )
            .bind(&target_ids)
            .fetch_one(&mut *tx)
            .await?;
            if remaining == 0 {
                tx.rollback().await?;
                return Ok(AdminBatchAccountWriteOutcome::LastAdministrator);
            }
        }
    }

    let mut ordered = targets.to_vec();
    ordered.sort_by_key(|target| target.id);
    for (index, target) in ordered.iter().enumerate() {
        let bare_jid =
            crate::jid::CanonicalJid::parse_bare(&format!("{}@{}", target.username, domain))?;
        anyhow::ensure!(
            bare_jid.localpart() == Some(target.username.as_str())
                && bare_jid.domainpart() == domain,
            "administrator target identity changed during JID preparation"
        );
        let bare_jid = bare_jid.to_string();
        match action {
            AdminAccountMutationAction::Delete => {
                let cleanup_issued: bool = sqlx::query_scalar(
                    "SELECT northstar_admin_command_issue_delete_cleanup(
                      $1,$2,$3,$4,$5,$6,$7,$8,$9)",
                )
                .bind(fence.claim_token)
                .bind(fence.actor_id)
                .bind(fence.actor_username)
                .bind(fence.actor_generation)
                .bind(fence.node)
                .bind(fence.target_digest)
                .bind(target.id)
                .bind(&target.username)
                .bind(&bare_jid)
                .fetch_one(&mut *tx)
                .await?;
                if !cleanup_issued {
                    tx.rollback().await?;
                    return Ok(AdminBatchAccountWriteOutcome::TargetChanged);
                }
                crate::db::users::delete_user_with_roster_locked_in_transaction(
                    &mut tx,
                    target.id,
                    &domain,
                    local_contacts.remove(&target.id).unwrap_or_default(),
                    Some((
                        fence.actor_id,
                        "admin.user.delete",
                        serde_json::json!({"source":"xep-0133","username":target.username}),
                    )),
                    Some(crate::db::users::AdminDeletionFence {
                        actor_id: fence.actor_id,
                        actor_username: fence.actor_username,
                        actor_generation: fence.actor_generation,
                        claim_token: fence.claim_token,
                        node: fence.node,
                        target_digest: fence.target_digest,
                        complete_command: index + 1 == ordered.len(),
                        result_payload: fence.result_payload,
                    }),
                )
                .await?;
            }
            AdminAccountMutationAction::Disable | AdminAccountMutationAction::Reenable => {
                let lifecycle = if action == AdminAccountMutationAction::Disable {
                    "disable"
                } else {
                    "reenable"
                };
                let outcome: String = sqlx::query_scalar(
                    "SELECT northstar_admin_command_user_lifecycle(
                      $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,NULL,$11,$12)",
                )
                .bind(fence.claim_token)
                .bind(fence.actor_id)
                .bind(fence.actor_username)
                .bind(fence.actor_generation)
                .bind(fence.node)
                .bind(fence.target_digest)
                .bind(target.id)
                .bind(&target.username)
                .bind(lifecycle)
                .bind(&bare_jid)
                .bind(index + 1 == ordered.len())
                .bind(fence.result_payload)
                .fetch_one(&mut *tx)
                .await?;
                match outcome.as_str() {
                    "applied" => {}
                    "unauthorized" => {
                        tx.rollback().await?;
                        return Ok(AdminBatchAccountWriteOutcome::Unauthorized);
                    }
                    "target_changed" => {
                        tx.rollback().await?;
                        return Ok(AdminBatchAccountWriteOutcome::TargetChanged);
                    }
                    "self_mutation" => {
                        tx.rollback().await?;
                        return Ok(AdminBatchAccountWriteOutcome::SelfMutation);
                    }
                    "last_administrator" => {
                        tx.rollback().await?;
                        return Ok(AdminBatchAccountWriteOutcome::LastAdministrator);
                    }
                    other => anyhow::bail!("admin lifecycle capability returned {other:?}"),
                }
            }
            AdminAccountMutationAction::EndSessions => {
                let outcome: String = sqlx::query_scalar(
                    "SELECT northstar_admin_command_user_lifecycle(
                      $1,$2,$3,$4,$5,$6,$7,$8,'end_sessions',$9,$10,$11,$12)",
                )
                .bind(fence.claim_token)
                .bind(fence.actor_id)
                .bind(fence.actor_username)
                .bind(fence.actor_generation)
                .bind(fence.node)
                .bind(fence.target_digest)
                .bind(target.id)
                .bind(&target.username)
                .bind(&bare_jid)
                .bind(target.exact_full_jid.as_deref())
                .bind(index + 1 == ordered.len())
                .bind(fence.result_payload)
                .fetch_one(&mut *tx)
                .await?;
                if outcome != "applied" {
                    tx.rollback().await?;
                    return Ok(match outcome.as_str() {
                        "unauthorized" => AdminBatchAccountWriteOutcome::Unauthorized,
                        "target_changed" => AdminBatchAccountWriteOutcome::TargetChanged,
                        "self_mutation" => AdminBatchAccountWriteOutcome::SelfMutation,
                        "last_administrator" => AdminBatchAccountWriteOutcome::LastAdministrator,
                        other => {
                            anyhow::bail!("admin session lifecycle capability returned {other:?}")
                        }
                    });
                }
            }
        }
        if fail_after == Some(index + 1) {
            anyhow::bail!("test-only administrative batch failure");
        }
    }
    tx.commit().await?;
    Ok(AdminBatchAccountWriteOutcome::Applied(targets.to_vec()))
}

pub async fn replace_admins_authorized(
    pool: &PgPool,
    fence: AdminCommandFence<'_>,
    expected: &[AdminAccountIdentity],
) -> Result<AdminAccountWriteOutcome> {
    anyhow::ensure!(!expected.is_empty(), "administrator list cannot be empty");
    anyhow::ensure!(expected.len() <= 200, "administrator list is too large");
    let mut ids = expected.iter().map(|target| target.id).collect::<Vec<_>>();
    ids.sort_unstable();
    ids.dedup();
    if ids.len() != expected.len() || !ids.contains(&fence.actor_id) {
        return Ok(AdminAccountWriteOutcome::SelfMutation);
    }
    let mut tx = pool.begin().await?;
    sqlx::query("SET LOCAL lock_timeout='2s'")
        .execute(&mut *tx)
        .await?;
    sqlx::query("SET LOCAL statement_timeout='15s'")
        .execute(&mut *tx)
        .await?;
    let claim_session: Option<Uuid> =
        sqlx::query_scalar("SELECT northstar_admin_command_authorize_claim($1,$2,$3,$4,$5,$6)")
            .bind(fence.claim_token)
            .bind(fence.actor_id)
            .bind(fence.actor_username)
            .bind(fence.actor_generation)
            .bind(fence.node)
            .bind(fence.target_digest)
            .fetch_one(&mut *tx)
            .await?;
    if claim_session.is_none() {
        tx.rollback().await?;
        return Ok(AdminAccountWriteOutcome::Unauthorized);
    }
    sqlx::query("SELECT pg_advisory_xact_lock(5645368709120101)")
        .execute(&mut *tx)
        .await?;
    // Lock both the current and requested administrator sets in one UUID-ordered
    // statement.  A promotion racing this command is therefore either included
    // in this replacement or waits until the replacement has committed; it
    // cannot introduce a row-lock inversion through a stale pre-lock snapshot.
    sqlx::query_scalar::<_, Uuid>(
        "SELECT id FROM users
         WHERE is_admin OR id=ANY($1) OR id=$2
         ORDER BY id FOR UPDATE",
    )
    .bind(&ids)
    .bind(fence.actor_id)
    .fetch_all(&mut *tx)
    .await?;
    if !admin_authorized_in_tx(
        &mut tx,
        fence.actor_id,
        fence.actor_username,
        fence.actor_generation,
    )
    .await?
    {
        tx.rollback().await?;
        return Ok(AdminAccountWriteOutcome::Unauthorized);
    }
    let rows = sqlx::query("SELECT id,username,is_disabled FROM users WHERE id=ANY($1)")
        .bind(&ids)
        .fetch_all(&mut *tx)
        .await?;
    if rows.len() != expected.len() {
        tx.rollback().await?;
        return Ok(AdminAccountWriteOutcome::TargetChanged);
    }
    let exact = rows
        .into_iter()
        .map(|row| {
            (
                row.get::<Uuid, _>("id"),
                (
                    row.get::<String, _>("username"),
                    row.get::<bool, _>("is_disabled"),
                ),
            )
        })
        .collect::<HashMap<_, _>>();
    if expected.iter().any(|target| {
        exact
            .get(&target.id)
            .is_none_or(|(username, disabled)| username != &target.username || *disabled)
    }) {
        tx.rollback().await?;
        return Ok(AdminAccountWriteOutcome::TargetChanged);
    }
    let changed: Option<Vec<Uuid>> =
        sqlx::query_scalar("SELECT northstar_admin_command_replace_users($1,$2,$3,$4,$5,$6,$7,$8)")
            .bind(fence.claim_token)
            .bind(fence.actor_id)
            .bind(fence.actor_username)
            .bind(fence.actor_generation)
            .bind(fence.node)
            .bind(fence.target_digest)
            .bind(&ids)
            .bind(fence.result_payload)
            .fetch_one(&mut *tx)
            .await?;
    if changed.is_none() {
        tx.rollback().await?;
        return Ok(AdminAccountWriteOutcome::Unauthorized);
    }
    tx.commit().await?;
    Ok(AdminAccountWriteOutcome::Applied)
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

#[cfg(test)]
pub async fn set_admin_service_message(
    pool: &PgPool,
    actor_id: Uuid,
    actor_generation: i64,
    kind: &str,
    body: Option<&str>,
) -> Result<bool> {
    anyhow::ensure!(
        matches!(kind, "motd" | "welcome"),
        "invalid service message kind"
    );
    if let Some(body) = body {
        anyhow::ensure!(
            !body.is_empty() && body.len() <= 65_536,
            "invalid service message"
        );
    }
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(format!("northstar:admin-service-message:{kind}"))
        .execute(&mut *tx)
        .await?;
    let authorized = sqlx::query_scalar::<_, bool>(
        "SELECT TRUE FROM users WHERE id=$1 AND auth_generation=$2 AND is_admin AND NOT is_disabled FOR SHARE",
    )
    .bind(actor_id)
    .bind(actor_generation)
    .fetch_optional(&mut *tx)
    .await?;
    if authorized.is_none() {
        tx.rollback().await?;
        return Ok(false);
    }
    match body {
        Some(body) => {
            sqlx::query(
                "INSERT INTO admin_service_messages(kind,body,revision,updated_by)
                 VALUES($1,$2,$3,$4)
                 ON CONFLICT(kind) DO UPDATE SET body=EXCLUDED.body,revision=EXCLUDED.revision,
                    updated_by=EXCLUDED.updated_by,updated_at=clock_timestamp()",
            )
            .bind(kind)
            .bind(body)
            .bind(Uuid::new_v4())
            .bind(actor_id)
            .execute(&mut *tx)
            .await?;
        }
        None => {
            sqlx::query("DELETE FROM admin_service_messages WHERE kind=$1")
                .bind(kind)
                .execute(&mut *tx)
                .await?;
        }
    }
    sqlx::query(
        "INSERT INTO audit_log(actor_id,action,target,details)
         VALUES($1,$2,$3,$4)",
    )
    .bind(actor_id)
    .bind(if body.is_some() {
        "admin.service_message.set"
    } else {
        "admin.service_message.delete"
    })
    .bind(kind)
    .bind(serde_json::json!({"bytes":body.map(str::len)}))
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(true)
}

pub async fn set_admin_service_message_command(
    pool: &PgPool,
    fence: AdminCommandFence<'_>,
    kind: &str,
    body: Option<&str>,
) -> Result<bool> {
    anyhow::ensure!(
        matches!(kind, "motd" | "welcome"),
        "invalid service message kind"
    );
    Ok(sqlx::query_scalar(
        "SELECT northstar_admin_command_set_service_message(
          $1,$2,$3,$4,$5,$6,$7,$8,$9)",
    )
    .bind(fence.claim_token)
    .bind(fence.actor_id)
    .bind(fence.actor_username)
    .bind(fence.actor_generation)
    .bind(fence.node)
    .bind(fence.target_digest)
    .bind(kind)
    .bind(body)
    .bind(fence.result_payload)
    .fetch_one(pool)
    .await?)
}

pub async fn record_admin_announcement_command(
    pool: &PgPool,
    fence: AdminCommandFence<'_>,
    recipients: usize,
    bytes: usize,
) -> Result<bool> {
    let recipients = i32::try_from(recipients).context("announcement recipient count overflow")?;
    let bytes = i32::try_from(bytes).context("announcement size overflow")?;
    Ok(sqlx::query_scalar(
        "SELECT northstar_admin_command_record_announcement(
          $1,$2,$3,$4,$5,$6,$7,$8,$9)",
    )
    .bind(fence.claim_token)
    .bind(fence.actor_id)
    .bind(fence.actor_username)
    .bind(fence.actor_generation)
    .bind(fence.node)
    .bind(fence.target_digest)
    .bind(recipients)
    .bind(bytes)
    .bind(fence.result_payload)
    .fetch_one(pool)
    .await?)
}

/// Lease service messages for one account.  A socket/process failure before
/// enqueue confirmation leaves an expiring lease rather than a false
/// delivered marker, so a later initial presence can retry.  Completion is a
/// separate connection-incarnation-bound update below; delivery is therefore
/// at-least-once across the unavoidable queue/DB crash boundary.
pub async fn claim_admin_service_messages(
    pool: &PgPool,
    user_id: Uuid,
) -> Result<Vec<ClaimedAdminServiceMessage>> {
    let mut tx = pool.begin().await?;
    let rows = sqlx::query("SELECT kind,body,revision FROM admin_service_messages ORDER BY kind")
        .fetch_all(&mut *tx)
        .await?;
    let mut claimed = Vec::new();
    let delivery_date: chrono::NaiveDate = sqlx::query_scalar("SELECT CURRENT_DATE")
        .fetch_one(&mut *tx)
        .await?;
    for row in rows {
        let kind: String = row.get("kind");
        let body: String = row.get("body");
        let revision: Uuid = row.get("revision");
        let message_date = if kind == "motd" {
            delivery_date
        } else {
            chrono::NaiveDate::from_ymd_opt(1970, 1, 1)
                .expect("fixed welcome delivery date is valid")
        };
        let claim_id = Uuid::new_v4();
        let leased = if kind == "welcome" {
            // The partial welcome index intentionally means once per account,
            // not once per edited revision.  Only an expired, never-completed
            // first delivery may be reclaimed.
            let existing = sqlx::query(
                "SELECT delivered_at IS NULL
                        AND claim_expires_at <= clock_timestamp() AS claimable
                 FROM admin_service_message_deliveries
                 WHERE kind='welcome' AND user_id=$1 FOR UPDATE",
            )
            .bind(user_id)
            .fetch_optional(&mut *tx)
            .await?;
            match existing {
                None => {
                    sqlx::query(
                        "INSERT INTO admin_service_message_deliveries
                         (kind,revision,user_id,delivery_date,delivered_at,claim_id,claim_expires_at)
                         VALUES('welcome',$1,$2,$3,NULL,$4,clock_timestamp()+INTERVAL '30 seconds')",
                    )
                    .bind(revision)
                    .bind(user_id)
                    .bind(message_date)
                    .bind(claim_id)
                    .execute(&mut *tx)
                    .await?;
                    true
                }
                Some(existing) if existing.get::<bool, _>("claimable") => {
                    sqlx::query(
                        "UPDATE admin_service_message_deliveries
                         SET revision=$2,claim_id=$3,
                             claim_expires_at=clock_timestamp()+INTERVAL '30 seconds'
                         WHERE kind='welcome' AND user_id=$1",
                    )
                    .bind(user_id)
                    .bind(revision)
                    .bind(claim_id)
                    .execute(&mut *tx)
                    .await?;
                    true
                }
                _ => false,
            }
        } else {
            sqlx::query(
                "INSERT INTO admin_service_message_deliveries
                 (kind,revision,user_id,delivery_date,delivered_at,claim_id,claim_expires_at)
                 VALUES($1,$2,$3,$4,NULL,$5,clock_timestamp()+INTERVAL '30 seconds')
                 ON CONFLICT(kind,revision,user_id,delivery_date) DO UPDATE
                 SET claim_id=EXCLUDED.claim_id,
                     claim_expires_at=clock_timestamp()+INTERVAL '30 seconds'
                 WHERE admin_service_message_deliveries.delivered_at IS NULL
                   AND admin_service_message_deliveries.claim_expires_at <= clock_timestamp()
                 RETURNING TRUE",
            )
            .bind(&kind)
            .bind(revision)
            .bind(user_id)
            .bind(message_date)
            .bind(claim_id)
            .fetch_optional(&mut *tx)
            .await?
            .is_some()
        };
        if leased {
            claimed.push(ClaimedAdminServiceMessage {
                kind,
                body,
                revision,
                delivery_date: message_date,
                claim_id,
            });
        }
    }
    // Keep the delivery ledger bounded without a table-wide blocking delete.
    sqlx::query(
        "DELETE FROM admin_service_message_deliveries WHERE (kind,revision,user_id,delivery_date) IN (
             SELECT kind,revision,user_id,delivery_date FROM admin_service_message_deliveries
             WHERE kind='motd'
               AND COALESCE(delivered_at,claim_expires_at) < clock_timestamp()-INTERVAL '90 days'
             ORDER BY COALESCE(delivered_at,claim_expires_at) LIMIT 1000
         )",
    )
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(claimed)
}

pub async fn complete_admin_service_message_claim(
    pool: &PgPool,
    user_id: Uuid,
    claim: &ClaimedAdminServiceMessage,
) -> Result<bool> {
    Ok(sqlx::query(
        "UPDATE admin_service_message_deliveries
         SET delivered_at=clock_timestamp(),claim_id=NULL,claim_expires_at=NULL
         WHERE kind=$1 AND revision=$2 AND user_id=$3 AND delivery_date=$4
           AND claim_id=$5 AND delivered_at IS NULL",
    )
    .bind(&claim.kind)
    .bind(claim.revision)
    .bind(user_id)
    .bind(claim.delivery_date)
    .bind(claim.claim_id)
    .execute(pool)
    .await?
    .rows_affected()
        == 1)
}

pub async fn federation_runtime_rules(pool: &PgPool) -> Result<(Vec<String>, Vec<String>)> {
    let rows = sqlx::query("SELECT kind,domain FROM federation_runtime_rules ORDER BY kind,domain")
        .fetch_all(pool)
        .await?;
    let mut blacklist = Vec::new();
    let mut whitelist = Vec::new();
    for row in rows {
        let kind: String = row.get("kind");
        let domain: String = row.get("domain");
        if kind == "blacklist" {
            blacklist.push(domain);
        } else {
            whitelist.push(domain);
        }
    }
    Ok((blacklist, whitelist))
}

#[cfg(test)]
pub async fn replace_federation_runtime_rules(
    pool: &PgPool,
    actor_id: Uuid,
    actor_generation: i64,
    kind: &str,
    domains: &[String],
) -> Result<bool> {
    Ok(replace_federation_runtime_rules_and_snapshot(
        pool,
        actor_id,
        actor_generation,
        kind,
        domains,
    )
    .await?
    .is_some())
}

/// Replace one rule family and return the complete committed cache image from
/// the same authorized transaction. This prevents the control plane from
/// applying a write and then reading a different, potentially unauthorized
/// snapshot through the pool.
#[cfg(test)]
pub async fn replace_federation_runtime_rules_and_snapshot(
    pool: &PgPool,
    actor_id: Uuid,
    actor_generation: i64,
    kind: &str,
    domains: &[String],
) -> Result<Option<(Vec<String>, Vec<String>)>> {
    anyhow::ensure!(
        matches!(kind, "blacklist" | "whitelist"),
        "invalid rule kind"
    );
    anyhow::ensure!(domains.len() <= 1000, "too many federation rules");
    let mut seen = HashSet::with_capacity(domains.len());
    let mut canonical_domains = Vec::with_capacity(domains.len());
    for domain in domains {
        let domain = crate::jid::canonicalize(domain)?;
        anyhow::ensure!(
            seen.insert(domain.clone()),
            "duplicate canonical federation rule: {domain}"
        );
        canonical_domains.push(domain);
    }
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(format!("northstar:federation-runtime-rules:{kind}"))
        .execute(&mut *tx)
        .await?;
    let authorized = sqlx::query_scalar::<_, bool>(
        "SELECT TRUE FROM users WHERE id=$1 AND auth_generation=$2 AND is_admin AND NOT is_disabled FOR SHARE",
    )
    .bind(actor_id)
    .bind(actor_generation)
    .fetch_optional(&mut *tx)
    .await?;
    if authorized.is_none() {
        tx.rollback().await?;
        return Ok(None);
    }
    sqlx::query("DELETE FROM federation_runtime_rules WHERE kind=$1")
        .bind(kind)
        .execute(&mut *tx)
        .await?;
    for domain in &canonical_domains {
        sqlx::query(
            "INSERT INTO federation_runtime_rules(kind,domain,updated_by) VALUES($1,$2,$3)",
        )
        .bind(kind)
        .bind(domain)
        .bind(actor_id)
        .execute(&mut *tx)
        .await?;
    }
    sqlx::query(
        "INSERT INTO audit_log(actor_id,action,target,details)
         VALUES($1,'admin.federation_rules.replace',$2,$3)",
    )
    .bind(actor_id)
    .bind(kind)
    .bind(serde_json::json!({"count":canonical_domains.len()}))
    .execute(&mut *tx)
    .await?;
    let rows = sqlx::query(
        "SELECT kind,domain FROM federation_runtime_rules ORDER BY kind,domain LIMIT 2001",
    )
    .fetch_all(&mut *tx)
    .await?;
    anyhow::ensure!(
        rows.len() <= 2000,
        "federation rule snapshot exceeds the configured bound"
    );
    let mut blacklist = Vec::new();
    let mut whitelist = Vec::new();
    for row in rows {
        let kind: String = row.get("kind");
        let domain: String = row.get("domain");
        if kind == "blacklist" {
            blacklist.push(domain);
        } else {
            whitelist.push(domain);
        }
    }
    tx.commit().await?;
    Ok(Some((blacklist, whitelist)))
}

pub async fn replace_federation_runtime_rules_command(
    pool: &PgPool,
    fence: AdminCommandFence<'_>,
    kind: &str,
    domains: &[String],
) -> Result<Option<(Vec<String>, Vec<String>)>> {
    anyhow::ensure!(
        matches!(kind, "blacklist" | "whitelist"),
        "invalid rule kind"
    );
    anyhow::ensure!(domains.len() <= 1000, "too many federation rules");
    let row = sqlx::query(
        "SELECT blacklist,whitelist
           FROM northstar_admin_command_replace_federation_rules(
             $1,$2,$3,$4,$5,$6,$7,$8,$9)",
    )
    .bind(fence.claim_token)
    .bind(fence.actor_id)
    .bind(fence.actor_username)
    .bind(fence.actor_generation)
    .bind(fence.node)
    .bind(fence.target_digest)
    .bind(kind)
    .bind(domains)
    .bind(fence.result_payload)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|row| (row.get("blacklist"), row.get("whitelist"))))
}

pub async fn initialize_admin_runtime_settings(
    pool: &PgPool,
    island_mode: bool,
    registration_closed: bool,
    registration_must_remain_closed: bool,
) -> Result<()> {
    let mut tx = pool.begin().await?;
    sqlx::query(
        "INSERT INTO admin_runtime_settings(key,enabled)
         VALUES('island_mode',$1),('registration_closed',$2)
         ON CONFLICT(key) DO UPDATE
            SET enabled=TRUE,
                revision=admin_runtime_settings.revision+1,
                updated_at=clock_timestamp()
          WHERE $3
            AND EXCLUDED.key='registration_closed'
            AND NOT admin_runtime_settings.enabled",
    )
    .bind(island_mode)
    .bind(registration_closed)
    .bind(registration_must_remain_closed)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(())
}

pub async fn admin_runtime_settings(pool: &PgPool) -> Result<(bool, bool)> {
    let rows = sqlx::query("SELECT key,enabled FROM admin_runtime_settings ORDER BY key")
        .fetch_all(pool)
        .await?;
    let mut island_mode = None;
    let mut registration_closed = None;
    for row in rows {
        match row.get::<String, _>("key").as_str() {
            "island_mode" => island_mode = Some(row.get("enabled")),
            "registration_closed" => registration_closed = Some(row.get("enabled")),
            _ => {}
        }
    }
    Ok((
        island_mode.context("island_mode runtime setting is missing")?,
        registration_closed.context("registration_closed runtime setting is missing")?,
    ))
}

#[cfg(test)]
pub async fn set_admin_runtime_setting(
    pool: &PgPool,
    actor_id: Uuid,
    actor_generation: i64,
    key: &str,
    enabled: bool,
) -> Result<bool> {
    anyhow::ensure!(
        matches!(key, "island_mode" | "registration_closed"),
        "invalid runtime setting"
    );
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
        .bind(format!("northstar:admin-runtime-setting:{key}"))
        .execute(&mut *tx)
        .await?;
    let authorized = sqlx::query_scalar::<_, bool>(
        "SELECT TRUE FROM users
         WHERE id=$1 AND auth_generation=$2 AND is_admin AND NOT is_disabled FOR SHARE",
    )
    .bind(actor_id)
    .bind(actor_generation)
    .fetch_optional(&mut *tx)
    .await?;
    if authorized.is_none() {
        tx.rollback().await?;
        return Ok(false);
    }
    sqlx::query(
        "INSERT INTO admin_runtime_settings(key,enabled,updated_by)
         VALUES($1,$2,$3)
         ON CONFLICT(key) DO UPDATE SET enabled=EXCLUDED.enabled,
             revision=admin_runtime_settings.revision+1,
             updated_by=EXCLUDED.updated_by,updated_at=clock_timestamp()",
    )
    .bind(key)
    .bind(enabled)
    .bind(actor_id)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO audit_log(actor_id,action,target,details)
         VALUES($1,'admin.runtime_setting.set',$2,$3)",
    )
    .bind(actor_id)
    .bind(key)
    .bind(serde_json::json!({"enabled":enabled}))
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(true)
}

pub async fn set_admin_runtime_setting_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    actor_id: Uuid,
    key: &str,
    enabled: bool,
    request_id: Option<Uuid>,
) -> Result<()> {
    anyhow::ensure!(
        matches!(key, "island_mode" | "registration_closed"),
        "invalid runtime setting"
    );
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
        .bind(format!("northstar:admin-runtime-setting:{key}"))
        .execute(&mut **tx)
        .await?;
    sqlx::query(
        "INSERT INTO admin_runtime_settings(key,enabled,updated_by)
         VALUES($1,$2,$3)
         ON CONFLICT(key) DO UPDATE SET enabled=EXCLUDED.enabled,
             revision=admin_runtime_settings.revision+1,
             updated_by=EXCLUDED.updated_by,updated_at=clock_timestamp()",
    )
    .bind(key)
    .bind(enabled)
    .bind(actor_id)
    .execute(&mut **tx)
    .await?;
    sqlx::query(
        "INSERT INTO audit_log(actor_id,action,target,details,request_id)
         VALUES($1,'admin.runtime_setting.set',$2,$3,$4)",
    )
    .bind(actor_id)
    .bind(key)
    .bind(serde_json::json!({"enabled":enabled,"source":"rest"}))
    .bind(request_id)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

/// A generic offline-queue clear cannot revoke a delivery that is already
/// owned by a live or recoverable transport. Callers may map this typed
/// outcome to a conflict without exposing unrelated database diagnostics.
#[derive(Debug, thiserror::Error)]
#[error("offline queue contains transport-owned deliveries; end those sessions before clearing")]
pub struct OfflineMessagesTransportOwned;

pub async fn clear_offline_messages_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    actor_id: Uuid,
    request_id: Option<Uuid>,
) -> Result<u64> {
    // Exclusive against the shared gate held by every production enqueue.
    // Rows committed before this lock are deleted; enqueue transactions that
    // start after it survive. This is one atomic queue snapshot.
    sqlx::query("SELECT pg_advisory_xact_lock(5645368709120102)")
        .execute(&mut **tx)
        .await?;
    // This destructive operator action is deliberately rejected while any
    // transport owns a row. The table lock closes the check/delete race with
    // SM/BOSH binders, both of which update the offline row before publishing
    // their fence. Account deletion has its own session-quiesce workflow; a
    // generic queue clear must not silently revoke live delivery semantics.
    sqlx::query("LOCK TABLE offline_messages IN SHARE ROW EXCLUSIVE MODE")
        .execute(&mut **tx)
        .await?;
    let occupied: bool = sqlx::query_scalar(
        "SELECT EXISTS(
             SELECT 1 FROM offline_messages message
              WHERE message.delivery_claim_id IS NOT NULL
                 OR EXISTS (
                     SELECT 1 FROM sm_resume_stanzas sm
                      WHERE sm.delivery_message_id=message.id
                 )
                 OR EXISTS (
                     SELECT 1 FROM bosh_delivery_fences bosh
                      WHERE bosh.message_id=message.id
                 )
         )",
    )
    .fetch_one(&mut **tx)
    .await?;
    if occupied {
        return Err(OfflineMessagesTransportOwned.into());
    }
    let removed = sqlx::query("DELETE FROM offline_messages")
        .execute(&mut **tx)
        .await?
        .rows_affected();
    sqlx::query(
        "INSERT INTO audit_log(actor_id,action,target,details,request_id)
         VALUES($1,'admin.offline_messages.clear',NULL,$2,$3)",
    )
    .bind(actor_id)
    .bind(serde_json::json!({"removed":removed}))
    .bind(request_id)
    .execute(&mut **tx)
    .await?;
    Ok(removed)
}

#[cfg(test)]
pub async fn schedule_admin_service_control(
    pool: &PgPool,
    actor_id: Uuid,
    actor_generation: i64,
    action: &str,
    delay_seconds: i64,
    announcement: Option<&str>,
) -> Result<Option<DurableServiceControl>> {
    anyhow::ensure!(
        matches!(action, "restart" | "shutdown"),
        "invalid service action"
    );
    anyhow::ensure!((5..=3600).contains(&delay_seconds), "invalid service delay");
    anyhow::ensure!(
        announcement.is_none_or(|body| body.len() <= 65_536),
        "service announcement is too large"
    );
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(5645368709120134)")
        .execute(&mut *tx)
        .await?;
    let authorized = sqlx::query_scalar::<_, bool>(
        "SELECT TRUE FROM users
         WHERE id=$1 AND auth_generation=$2 AND is_admin AND NOT is_disabled FOR SHARE",
    )
    .bind(actor_id)
    .bind(actor_generation)
    .fetch_optional(&mut *tx)
    .await?;
    if authorized.is_none() {
        tx.rollback().await?;
        return Ok(None);
    }
    let active = sqlx::query_scalar::<_, bool>(
        "SELECT TRUE FROM admin_service_control
         WHERE singleton AND status IN ('scheduled','fired')
           AND expires_at > clock_timestamp()
         FOR UPDATE",
    )
    .fetch_optional(&mut *tx)
    .await?;
    if active.is_some() {
        tx.rollback().await?;
        return Ok(None);
    }
    let generation = Uuid::new_v4();
    let row = sqlx::query(
        "INSERT INTO admin_service_control
         (singleton,generation,action,status,execute_at,expires_at,requested_by,
          requested_generation)
         VALUES(TRUE,$1,$2,'scheduled',clock_timestamp()+($3*INTERVAL '1 second'),
                clock_timestamp()+(($3+300)*INTERVAL '1 second'),$4,$5)
         ON CONFLICT(singleton) DO UPDATE SET generation=EXCLUDED.generation,
             action=EXCLUDED.action,status='scheduled',execute_at=EXCLUDED.execute_at,
             fired_at=NULL,expires_at=EXCLUDED.expires_at,requested_by=EXCLUDED.requested_by,
             requested_generation=EXCLUDED.requested_generation,
             created_at=clock_timestamp(),updated_at=clock_timestamp()
         RETURNING generation,action,execute_at,fired_at,expires_at",
    )
    .bind(generation)
    .bind(action)
    .bind(delay_seconds)
    .bind(actor_id)
    .bind(actor_generation)
    .fetch_one(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO audit_log(actor_id,action,target,details)
         VALUES($1,'admin.service_control.request',$2,$3)",
    )
    .bind(actor_id)
    .bind(action)
    .bind(serde_json::json!({"generation":generation,"delay_seconds":delay_seconds,"announcement_bytes":announcement.map(str::len)}))
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(Some(service_control_from_row(&row)))
}

#[cfg(test)]
pub async fn cancel_admin_service_control(
    pool: &PgPool,
    actor_id: Uuid,
    actor_generation: i64,
) -> Result<Option<Uuid>> {
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(5645368709120134)")
        .execute(&mut *tx)
        .await?;
    let authorized = sqlx::query_scalar::<_, bool>(
        "SELECT TRUE FROM users
         WHERE id=$1 AND auth_generation=$2 AND is_admin AND NOT is_disabled FOR SHARE",
    )
    .bind(actor_id)
    .bind(actor_generation)
    .fetch_optional(&mut *tx)
    .await?;
    if authorized.is_none() {
        tx.rollback().await?;
        return Ok(None);
    }
    let generation = sqlx::query_scalar::<_, Uuid>(
        "UPDATE admin_service_control SET status='canceled',updated_at=clock_timestamp()
         WHERE singleton AND status='scheduled' AND execute_at > clock_timestamp()
         RETURNING generation",
    )
    .fetch_optional(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO audit_log(actor_id,action,target,details)
         VALUES($1,'admin.service_control.cancel',NULL,$2)",
    )
    .bind(actor_id)
    .bind(serde_json::json!({"generation":generation}))
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(generation)
}

#[allow(clippy::too_many_arguments)]
pub async fn apply_admin_service_control_command(
    pool: &PgPool,
    fence: AdminCommandFence<'_>,
    action: &str,
    delay_seconds: i64,
    announcement: Option<&str>,
    cancel: bool,
) -> Result<Option<Uuid>> {
    let delay_seconds = i32::try_from(delay_seconds).context("service delay overflow")?;
    sqlx::query_scalar::<_, Option<Uuid>>(
        "SELECT northstar_admin_command_service_control(
          $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)",
    )
    .bind(fence.claim_token)
    .bind(fence.actor_id)
    .bind(fence.actor_username)
    .bind(fence.actor_generation)
    .bind(fence.node)
    .bind(fence.target_digest)
    .bind(action)
    .bind(delay_seconds)
    .bind(announcement)
    .bind(cancel)
    .bind(fence.result_payload)
    .fetch_one(pool)
    .await
    .map_err(Into::into)
}

/// Return an active control generation, atomically advancing it to `fired`
/// when its PostgreSQL-clock deadline has arrived.  Every node polls this row;
/// only processes whose start time predates `fired_at` act on it.
pub async fn poll_admin_service_control(pool: &PgPool) -> Result<Option<DurableServiceControl>> {
    let row = sqlx::query(
        "SELECT generation,action,execute_at,fired_at,expires_at
           FROM northstar_admin_service_control_poll()",
    )
    .fetch_optional(pool)
    .await?;
    Ok(row.as_ref().map(service_control_from_row))
}

fn service_control_from_row(row: &sqlx::postgres::PgRow) -> DurableServiceControl {
    DurableServiceControl {
        generation: row.get("generation"),
        action: row.get("action"),
        execute_at: row.get("execute_at"),
        fired_at: row.get("fired_at"),
        expires_at: row.get("expires_at"),
    }
}

#[cfg(test)]
mod boundary_tests {
    use super::*;
    use sha2::Digest;

    async fn database() -> PgPool {
        let url = std::env::var("TEST_DATABASE_URL")
            .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(8)
            .connect(&url)
            .await
            .unwrap();
        crate::db::migrate(&pool).await.unwrap();
        pool
    }

    async fn insert_account(pool: &PgPool, id: Uuid, username: &str, admin: bool) {
        sqlx::query(
            "INSERT INTO users(id,username,password_hash,is_admin)
             VALUES($1,$2,'test-only',$3)",
        )
        .bind(id)
        .bind(username)
        .bind(admin)
        .execute(pool)
        .await
        .unwrap();
    }

    async fn begin_test_execution(
        pool: &PgPool,
        actor_id: Uuid,
        actor_name: &str,
        node: &str,
        label: &str,
    ) -> (zeroize::Zeroizing<String>, AdminCommandClaim, Vec<u8>) {
        let owner = format!("{actor_name}@example.test/console");
        let bearer =
            create_admin_command_session(pool, actor_id, &owner, "example.test", 0, node, "form")
                .await
                .unwrap()
                .expect("test command session must be created");
        let digest = sha2::Sha256::digest(label.as_bytes()).to_vec();
        let claim = match begin_admin_command_execution(
            pool,
            bearer.as_str(),
            actor_id,
            &owner,
            0,
            node,
            &digest,
        )
        .await
        .unwrap()
        {
            AdminCommandExecutionState::Started(claim) => claim,
            other => panic!("unexpected execution outcome: {other:?}"),
        };
        (bearer, claim, digest)
    }

    #[tokio::test]
    #[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
    async fn admin_cleanup_effects_are_atomic_lease_fenced_and_compacted() {
        let pool = database().await;
        let suffix = Uuid::new_v4().simple().to_string();
        let actor_id = Uuid::new_v4();
        let target_id = Uuid::new_v4();
        let actor_name = format!("cleanup-admin-{}", &suffix[..10]);
        let target_name = format!("cleanup-user-{}", &suffix[..10]);
        insert_account(&pool, actor_id, &actor_name, true).await;
        insert_account(&pool, target_id, &target_name, false).await;
        let node = "http://jabber.org/protocol/admin#disable-user";
        let (_bearer, claim, digest) =
            begin_test_execution(&pool, actor_id, &actor_name, node, "cleanup-atomic").await;
        let targets = [AdminAccountMutationTarget {
            id: target_id,
            username: target_name.clone(),
            exact_full_jid: None,
        }];

        let failed = mutate_admin_accounts_authorized_with_failure_after(
            &pool,
            AdminCommandFence {
                claim_token: claim.token.as_str(),
                actor_id,
                actor_username: &actor_name,
                actor_generation: 0,
                node,
                target_digest: &digest,
                result_payload: "<done/>",
            },
            &targets,
            AdminAccountMutationAction::Disable,
            "example.test",
            1,
        )
        .await;
        assert!(
            failed.is_err(),
            "test fault must abort the command transaction"
        );
        assert!(
            !sqlx::query_scalar::<_, bool>("SELECT is_disabled FROM users WHERE id=$1")
                .bind(target_id)
                .fetch_one(&pool)
                .await
                .unwrap()
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM admin_session_cleanup_effects WHERE user_id=$1",
            )
            .bind(target_id)
            .fetch_one(&pool)
            .await
            .unwrap(),
            0,
            "a cleanup effect cannot escape a rolled-back mutation"
        );

        let foreign_domain = mutate_admin_accounts_authorized(
            &pool,
            AdminCommandFence {
                claim_token: claim.token.as_str(),
                actor_id,
                actor_username: &actor_name,
                actor_generation: 0,
                node,
                target_digest: &digest,
                result_payload: "<done/>",
            },
            &targets,
            AdminAccountMutationAction::Disable,
            "foreign.example",
        )
        .await;
        assert!(
            foreign_domain.is_err(),
            "the database issuer must reject a cleanup outside the command owner's XMPP domain"
        );
        assert!(
            !sqlx::query_scalar::<_, bool>("SELECT is_disabled FROM users WHERE id=$1")
                .bind(target_id)
                .fetch_one(&pool)
                .await
                .unwrap(),
            "a rejected foreign-domain cleanup must roll back the account mutation"
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM admin_session_cleanup_effects WHERE user_id=$1",
            )
            .bind(target_id)
            .fetch_one(&pool)
            .await
            .unwrap(),
            0,
            "a rejected foreign-domain cleanup must not consume queue capacity"
        );

        assert!(matches!(
            mutate_admin_accounts_authorized(
                &pool,
                AdminCommandFence {
                    claim_token: claim.token.as_str(),
                    actor_id,
                    actor_username: &actor_name,
                    actor_generation: 0,
                    node,
                    target_digest: &digest,
                    result_payload: "<done/>",
                },
                &targets,
                AdminAccountMutationAction::Disable,
                "example.test",
            )
            .await
            .unwrap(),
            AdminBatchAccountWriteOutcome::Applied(_)
        ));
        let first_worker = Uuid::new_v4();
        let first = claim_admin_session_cleanup(&pool, first_worker, 60)
            .await
            .unwrap()
            .expect("committed mutation must publish one effect");
        assert_eq!(first.kind, AdminSessionCleanupKind::AccountGeneration);
        assert_eq!(first.user_id, target_id);
        assert_eq!(first.auth_generation, 1);
        assert!(
            retry_admin_session_cleanup(&pool, &first, first_worker, "test_retry")
                .await
                .unwrap()
        );
        sqlx::query(
            "UPDATE admin_session_cleanup_effects SET next_attempt_at=clock_timestamp()
              WHERE id=$1",
        )
        .bind(first.id)
        .execute(&pool)
        .await
        .unwrap();
        let second_worker_a = Uuid::new_v4();
        let second_worker_b = Uuid::new_v4();
        let (second_a, second_b) = tokio::join!(
            claim_admin_session_cleanup(&pool, second_worker_a, 60),
            claim_admin_session_cleanup(&pool, second_worker_b, 60),
        );
        let second_a = second_a.unwrap();
        let second_b = second_b.unwrap();
        assert_eq!(
            usize::from(second_a.is_some()) + usize::from(second_b.is_some()),
            1,
            "SKIP LOCKED must give a due effect to exactly one concurrent claimant"
        );
        let (second_worker, second) = match (second_a, second_b) {
            (Some(lease), None) => (second_worker_a, lease),
            (None, Some(lease)) => (second_worker_b, lease),
            _ => unreachable!("exactly one concurrent claimant was asserted"),
        };
        assert_eq!(second.id, first.id);
        assert!(
            !complete_admin_session_cleanup(&pool, &first, first_worker)
                .await
                .unwrap(),
            "a superseded lease cannot acknowledge the effect"
        );
        sqlx::query(
            "UPDATE admin_session_cleanup_effects
                SET lease_expires_at=clock_timestamp()-INTERVAL '1 second'
              WHERE id=$1",
        )
        .bind(second.id)
        .execute(&pool)
        .await
        .unwrap();
        let recovery_worker = Uuid::new_v4();
        let recovered = claim_admin_session_cleanup(&pool, recovery_worker, 60)
            .await
            .unwrap()
            .expect("an effect abandoned at the crash window must be reclaimed");
        assert_eq!(recovered.id, second.id);
        assert!(
            !complete_admin_session_cleanup(&pool, &second, second_worker)
                .await
                .unwrap(),
            "an expired worker lease cannot acknowledge a reclaimed effect"
        );
        assert!(
            complete_admin_session_cleanup(&pool, &recovered, recovery_worker)
                .await
                .unwrap()
        );
        let snapshot = admin_session_cleanup_snapshot(&pool).await.unwrap();
        assert_eq!(snapshot.queued, 0);
        assert_eq!(snapshot.pending + snapshot.running, 0);
        pool.close().await;
    }

    #[tokio::test]
    #[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
    async fn admin_cleanup_effects_survive_delete_and_do_not_retarget_rebinds() {
        let pool = database().await;
        let suffix = Uuid::new_v4().simple().to_string();
        let actor_id = Uuid::new_v4();
        let deleted_id = Uuid::new_v4();
        let actor_name = format!("delete-admin-{}", &suffix[..10]);
        let username = format!("delete-user-{}", &suffix[..10]);
        insert_account(&pool, actor_id, &actor_name, true).await;
        insert_account(&pool, deleted_id, &username, false).await;
        let delete_node = "http://jabber.org/protocol/admin#delete-user";
        let (_bearer, delete_claim, delete_digest) =
            begin_test_execution(&pool, actor_id, &actor_name, delete_node, "cleanup-delete").await;
        let mut deletion = pool.begin().await.unwrap();
        let issued: bool = sqlx::query_scalar(
            "SELECT northstar_admin_command_issue_delete_cleanup(
              $1,$2,$3,$4,$5,$6,$7,$8,$9)",
        )
        .bind(delete_claim.token.as_str())
        .bind(actor_id)
        .bind(&actor_name)
        .bind(0_i64)
        .bind(delete_node)
        .bind(&delete_digest)
        .bind(deleted_id)
        .bind(&username)
        .bind(format!("{username}@example.test"))
        .fetch_one(&mut *deletion)
        .await
        .unwrap();
        assert!(issued);
        let replayed: bool = sqlx::query_scalar(
            "SELECT northstar_admin_command_issue_delete_cleanup(
              $1,$2,$3,$4,$5,$6,$7,$8,$9)",
        )
        .bind(delete_claim.token.as_str())
        .bind(actor_id)
        .bind(&actor_name)
        .bind(0_i64)
        .bind(delete_node)
        .bind(&delete_digest)
        .bind(deleted_id)
        .bind(&username)
        .bind(format!("{username}@example.test"))
        .fetch_one(&mut *deletion)
        .await
        .unwrap();
        assert!(replayed);
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM admin_session_cleanup_effects
                  WHERE command_operation_id=$1",
            )
            .bind(delete_claim.operation_id)
            .fetch_one(&mut *deletion)
            .await
            .unwrap(),
            1,
            "replaying an issuer must not duplicate its stable effect"
        );
        sqlx::query("DELETE FROM users WHERE id=$1")
            .bind(deleted_id)
            .execute(&mut *deletion)
            .await
            .unwrap();
        deletion.commit().await.unwrap();
        let replacement_id = Uuid::new_v4();
        insert_account(&pool, replacement_id, &username, false).await;
        let delete_effect = sqlx::query(
            "SELECT user_id,auth_generation FROM admin_session_cleanup_effects
              WHERE command_operation_id=$1",
        )
        .bind(delete_claim.operation_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(delete_effect.get::<Uuid, _>("user_id"), deleted_id);
        assert_ne!(delete_effect.get::<Uuid, _>("user_id"), replacement_id);
        assert_eq!(delete_effect.get::<i64, _>("auth_generation"), 1);
        let worker = Uuid::new_v4();
        let lease = claim_admin_session_cleanup(&pool, worker, 60)
            .await
            .unwrap()
            .unwrap();
        assert!(complete_admin_session_cleanup(&pool, &lease, worker)
            .await
            .unwrap());

        let exact_target_id = Uuid::new_v4();
        let exact_name = format!("exact-user-{}", &suffix[..10]);
        insert_account(&pool, exact_target_id, &exact_name, false).await;
        let full_jid = format!("{exact_name}@example.test/phone");
        let sibling_jid = format!("{exact_name}@example.test/laptop");
        let old_connection = Uuid::new_v4();
        let sibling_connection = Uuid::new_v4();
        for (full, connection) in [
            (full_jid.as_str(), old_connection),
            (sibling_jid.as_str(), sibling_connection),
        ] {
            sqlx::query(
                "INSERT INTO deployment_session_leases(
                   lease_id,connection_id,user_id,full_jid,lease_until
                 ) VALUES($1,$1,$2,$3,clock_timestamp()+INTERVAL '5 minutes')",
            )
            .bind(connection)
            .bind(exact_target_id)
            .bind(full)
            .execute(&pool)
            .await
            .unwrap();
        }
        let exact_node = "http://jabber.org/protocol/admin#end-user-session";
        let (_bearer, exact_claim, exact_digest) =
            begin_test_execution(&pool, actor_id, &actor_name, exact_node, "cleanup-exact").await;
        let exact_outcome = mutate_admin_accounts_authorized(
            &pool,
            AdminCommandFence {
                claim_token: exact_claim.token.as_str(),
                actor_id,
                actor_username: &actor_name,
                actor_generation: 0,
                node: exact_node,
                target_digest: &exact_digest,
                result_payload: "<done/>",
            },
            &[AdminAccountMutationTarget {
                id: exact_target_id,
                username: exact_name,
                exact_full_jid: Some(full_jid.clone()),
            }],
            AdminAccountMutationAction::EndSessions,
            "example.test",
        )
        .await
        .unwrap();
        assert!(matches!(
            exact_outcome,
            AdminBatchAccountWriteOutcome::Applied(_)
        ));
        let worker = Uuid::new_v4();
        let exact_effect = claim_admin_session_cleanup(&pool, worker, 60)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(exact_effect.kind, AdminSessionCleanupKind::ExactConnection);
        assert!(
            admin_session_cleanup_target_current(&pool, &exact_effect, worker)
                .await
                .unwrap()
        );
        sqlx::query("UPDATE users SET auth_generation=auth_generation+1 WHERE id=$1")
            .bind(exact_target_id)
            .execute(&pool)
            .await
            .unwrap();
        assert!(
            !admin_session_cleanup_target_current(&pool, &exact_effect, worker)
                .await
                .unwrap(),
            "an exact effect cannot target a later account generation"
        );
        sqlx::query("UPDATE users SET auth_generation=auth_generation-1 WHERE id=$1")
            .bind(exact_target_id)
            .execute(&pool)
            .await
            .unwrap();
        assert!(
            admin_session_cleanup_target_current(&pool, &exact_effect, worker)
                .await
                .unwrap()
        );
        sqlx::query("DELETE FROM deployment_session_leases WHERE connection_id=$1")
            .bind(old_connection)
            .execute(&pool)
            .await
            .unwrap();
        let replacement_connection = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO deployment_session_leases(
               lease_id,connection_id,user_id,full_jid,lease_until
             ) VALUES($1,$1,$2,$3,clock_timestamp()+INTERVAL '5 minutes')",
        )
        .bind(replacement_connection)
        .bind(exact_target_id)
        .bind(&full_jid)
        .execute(&pool)
        .await
        .unwrap();
        assert!(
            !admin_session_cleanup_target_current(&pool, &exact_effect, worker)
                .await
                .unwrap(),
            "an old exact effect cannot retarget a replacement connection"
        );
        assert_eq!(
            sqlx::query_scalar::<_, Uuid>(
                "SELECT connection_id FROM deployment_session_leases WHERE full_jid=$1",
            )
            .bind(&sibling_jid)
            .fetch_one(&pool)
            .await
            .unwrap(),
            sibling_connection,
            "an exact effect cannot select a sibling full JID"
        );
        assert!(complete_admin_session_cleanup(&pool, &exact_effect, worker)
            .await
            .unwrap());
        pool.close().await;
    }

    // These pre-capability transaction tests are retained only as historical
    // race documentation.  The executable positive/negative/concurrency
    // coverage now lives in database-role-boundary-db-ci.sh, where the
    // migrator, runtime, and command identities are actually distinct.
    #[cfg(any())]
    #[tokio::test]
    #[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
    async fn admin_batch_rejects_concurrent_demotion_and_password_rotation() {
        let pool = database().await;
        let suffix = Uuid::new_v4().simple().to_string();
        let low = u64::from_be_bytes(Uuid::new_v4().as_bytes()[..8].try_into().unwrap());
        let target_id = Uuid::from_u128(low as u128);
        let actor_id = Uuid::from_u128((u128::from(u64::MAX) << 64) | low as u128);
        let actor_name = format!("admin-{}", &suffix[..12]);
        let target_name = format!("member-{}", &suffix[..12]);
        insert_account(&pool, actor_id, &actor_name, true).await;
        insert_account(&pool, target_id, &target_name, false).await;
        let targets = vec![AdminAccountMutationTarget {
            id: target_id,
            username: target_name.clone(),
            exact_full_jid: None,
        }];

        let mut blocker = pool.begin().await.unwrap();
        sqlx::query("SELECT id FROM users WHERE id=$1 FOR UPDATE")
            .bind(target_id)
            .fetch_one(&mut *blocker)
            .await
            .unwrap();
        let task_pool = pool.clone();
        let task_targets = targets.clone();
        let task_actor = actor_name.clone();
        let task = tokio::spawn(async move {
            mutate_admin_accounts_authorized(
                &task_pool,
                actor_id,
                &task_actor,
                0,
                &task_targets,
                AdminAccountMutationAction::Disable,
                "example.test",
            )
            .await
            .unwrap()
        });
        tokio::task::yield_now().await;
        sqlx::query("UPDATE users SET is_admin=FALSE WHERE id=$1")
            .bind(actor_id)
            .execute(&pool)
            .await
            .unwrap();
        blocker.rollback().await.unwrap();
        assert_eq!(
            task.await.unwrap(),
            AdminBatchAccountWriteOutcome::Unauthorized
        );
        assert!(
            !sqlx::query_scalar::<_, bool>("SELECT is_disabled FROM users WHERE id=$1")
                .bind(target_id)
                .fetch_one(&pool)
                .await
                .unwrap()
        );

        sqlx::query("UPDATE users SET is_admin=TRUE WHERE id=$1")
            .bind(actor_id)
            .execute(&pool)
            .await
            .unwrap();
        let mut blocker = pool.begin().await.unwrap();
        sqlx::query("SELECT id FROM users WHERE id=$1 FOR UPDATE")
            .bind(target_id)
            .fetch_one(&mut *blocker)
            .await
            .unwrap();
        let task_pool = pool.clone();
        let task_targets = targets.clone();
        let task = tokio::spawn(async move {
            mutate_admin_accounts_authorized(
                &task_pool,
                actor_id,
                &actor_name,
                0,
                &task_targets,
                AdminAccountMutationAction::Disable,
                "example.test",
            )
            .await
            .unwrap()
        });
        tokio::task::yield_now().await;
        sqlx::query("UPDATE users SET auth_generation=auth_generation+1 WHERE id=$1")
            .bind(actor_id)
            .execute(&pool)
            .await
            .unwrap();
        blocker.rollback().await.unwrap();
        assert_eq!(
            task.await.unwrap(),
            AdminBatchAccountWriteOutcome::Unauthorized
        );
        assert!(
            !sqlx::query_scalar::<_, bool>("SELECT is_disabled FROM users WHERE id=$1")
                .bind(target_id)
                .fetch_one(&pool)
                .await
                .unwrap()
        );
    }

    #[cfg(any())]
    #[tokio::test]
    #[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
    async fn admin_batch_fences_target_delete_recreate_incarnation() {
        let pool = database().await;
        let suffix = Uuid::new_v4().simple().to_string();
        // Make the actor the first row in the batch's UUID lock order. Holding
        // it lets the competing transaction replace the still-unlocked target
        // after command resolution but before the authoritative recheck.
        let low = u64::from_be_bytes(Uuid::new_v4().as_bytes()[..8].try_into().unwrap());
        let actor_id = Uuid::from_u128(low as u128);
        let old_id = Uuid::from_u128((u128::from(u64::MAX) << 64) | low as u128);
        let replacement_id = Uuid::new_v4();
        let actor_name = format!("admin-{}", &suffix[..12]);
        let username = format!("replace-{}", &suffix[..12]);
        insert_account(&pool, actor_id, &actor_name, true).await;
        insert_account(&pool, old_id, &username, false).await;

        let mut blocker = pool.begin().await.unwrap();
        sqlx::query("SELECT id FROM users WHERE id=$1 FOR UPDATE")
            .bind(actor_id)
            .fetch_one(&mut *blocker)
            .await
            .unwrap();
        let task_pool = pool.clone();
        let task_actor = actor_name.clone();
        let task_username = username.clone();
        let task = tokio::spawn(async move {
            mutate_admin_accounts_authorized(
                &task_pool,
                actor_id,
                &task_actor,
                0,
                &[AdminAccountMutationTarget {
                    id: old_id,
                    username: task_username,
                    exact_full_jid: None,
                }],
                AdminAccountMutationAction::Disable,
                "example.test",
            )
            .await
            .unwrap()
        });
        tokio::task::yield_now().await;
        sqlx::query("DELETE FROM users WHERE id=$1")
            .bind(old_id)
            .execute(&pool)
            .await
            .unwrap();
        insert_account(&pool, replacement_id, &username, false).await;
        blocker.rollback().await.unwrap();
        let outcome = task.await.unwrap();
        assert_eq!(outcome, AdminBatchAccountWriteOutcome::TargetChanged);
        assert!(
            !sqlx::query_scalar::<_, bool>("SELECT is_disabled FROM users WHERE id=$1")
                .bind(replacement_id)
                .fetch_one(&pool)
                .await
                .unwrap()
        );
    }

    #[cfg(any())]
    #[tokio::test]
    #[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
    async fn admin_batch_mid_request_failure_rolls_back_every_target_and_audit() {
        let pool = database().await;
        let suffix = Uuid::new_v4().simple().to_string();
        let actor_id = Uuid::new_v4();
        let actor_name = format!("admin-{}", &suffix[..12]);
        insert_account(&pool, actor_id, &actor_name, true).await;
        let mut targets = Vec::new();
        for index in 0..2 {
            let id = Uuid::new_v4();
            let username = format!("rollback-{index}-{}", &suffix[..10]);
            insert_account(&pool, id, &username, false).await;
            targets.push(AdminAccountMutationTarget {
                id,
                username,
                exact_full_jid: None,
            });
        }
        assert!(mutate_admin_accounts_authorized_with_failure_after(
            &pool,
            actor_id,
            &actor_name,
            0,
            &targets,
            AdminAccountMutationAction::Disable,
            "example.test",
            1,
        )
        .await
        .is_err());
        let disabled: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE id=ANY($1) AND is_disabled")
                .bind(targets.iter().map(|target| target.id).collect::<Vec<_>>())
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(disabled, 0);
        let audits: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM audit_log
             WHERE actor_id=$1 AND action='admin.user.update'",
        )
        .bind(actor_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(audits, 0);
    }

    #[tokio::test]
    #[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
    async fn admin_command_same_request_retry_replays_one_terminal_result() {
        let pool = database().await;
        let suffix = Uuid::new_v4().simple().to_string();
        let actor_id = Uuid::new_v4();
        let actor_name = format!("admin-{}", &suffix[..12]);
        insert_account(&pool, actor_id, &actor_name, true).await;
        let owner = format!("{actor_name}@example.test/console");
        let node = "http://jabber.org/protocol/admin#get-registered-users-list";
        let bearer =
            create_admin_command_session(&pool, actor_id, &owner, "example.test", 0, node, "form")
                .await
                .unwrap()
                .unwrap();
        let digest = sha2::Sha256::digest(b"same-request").to_vec();
        let claim = match begin_admin_command_execution(
            &pool,
            bearer.as_str(),
            actor_id,
            &owner,
            0,
            node,
            &digest,
        )
        .await
        .unwrap()
        {
            AdminCommandExecutionState::Started(claim) => claim,
            other => panic!("unexpected execution outcome: {other:?}"),
        };
        let payload = "<x xmlns='jabber:x:data' type='result'/>";
        assert!(complete_admin_command_read_execution(
            &pool,
            claim.token.as_str(),
            actor_id,
            &actor_name,
            0,
            node,
            &digest,
            payload,
        )
        .await
        .unwrap());
        assert_eq!(
            begin_admin_command_execution(
                &pool,
                bearer.as_str(),
                actor_id,
                &owner,
                0,
                node,
                &digest,
            )
            .await
            .unwrap(),
            AdminCommandExecutionState::Completed(payload.to_owned())
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM audit_log
                 WHERE actor_id=$1 AND action='admin.command.read' AND target=$2",
            )
            .bind(actor_id)
            .bind(node)
            .fetch_one(&pool)
            .await
            .unwrap(),
            1
        );
    }
}
