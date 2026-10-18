use anyhow::{Context, Result};
use sqlx::{Acquire, PgConnection, PgPool, Row};
use std::collections::HashMap;
#[cfg(test)]
use std::collections::HashSet;
use std::time::Duration;
use uuid::Uuid;

mod accounts;
mod command_sessions;
mod runtime_control;

pub use self::accounts::*;
pub use self::command_sessions::*;
pub use self::runtime_control::*;

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

pub use crate::services::presence::ServiceMessageDeliveryClaim as ClaimedAdminServiceMessage;

pub use crate::services::runtime_control::DurableServiceControl;
pub(crate) use crate::services::runtime_control::RuntimeControlReadPhase;

// The service-control watcher has a three-second WorkerRegistry silence
// budget. Keep all database phases materially below that budget so a stalled
// control row reports a bounded business failure rather than looking like a
// hung worker. The watcher owns an isolated one-connection runtime pool; these
// limits are its second line of defense against a blocked database backend.
const SERVICE_CONTROL_POLL_TIMEOUT: Duration = Duration::from_millis(750);
const SERVICE_CONTROL_LOCK_TIMEOUT: &str = "250ms";
const SERVICE_CONTROL_STATEMENT_TIMEOUT: &str = "500ms";

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

#[cfg(test)]
mod boundary_tests;
