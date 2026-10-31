use anyhow::{Context, Result};
use northstar_operations_application::admin_session_cleanup_worker::{
    AdminSessionCleanupKind, AdminSessionCleanupLease, AdminSessionCleanupSnapshot,
};
use sqlx::{Acquire, PgConnection, PgPool, Row};
#[cfg(any(test, feature = "test-support"))]
use std::collections::HashSet;
use std::time::Duration;
use uuid::Uuid;

mod command_sessions;
mod runtime_control;

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

pub use northstar_roster_core::ServiceMessageDeliveryClaim as ClaimedAdminServiceMessage;

pub use northstar_operations_application::runtime_control::DurableServiceControl;
pub use northstar_operations_application::runtime_control::RuntimeControlReadPhase;

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

#[cfg(any(test, feature = "test-support"))]
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

#[cfg(any(test, feature = "test-support"))]
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
#[cfg(any(test, feature = "test-support"))]
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
        let domain = northstar_xmpp_types::jid::canonicalize(domain)?;
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

#[cfg(any(test, feature = "test-support"))]
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

#[cfg(any(test, feature = "test-support"))]
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

#[cfg(any(test, feature = "test-support"))]
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
