use crate::services::operations::{
    contains_secret_key, validate_error_code, validate_json,
    validate_manual_reconciliation_content, MAX_RESULT_BYTES,
};
pub use crate::services::operations::{
    AuthorizationPolicy, OperationPage, OperationPageBoundary, OperationRecord, OperationStatus,
    OperationTargetPage, OperationTargetRecord,
};
use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde_json::{json, Value};
#[cfg(test)]
use sqlx::PgPool;
use sqlx::{Postgres, Row, Transaction};
use uuid::Uuid;

mod operation_leases;
mod operation_queue;
mod reconciliation;
mod target_leases;

pub use self::operation_leases::*;
pub use self::operation_queue::*;
pub use self::reconciliation::*;
pub use self::target_leases::*;

const MAX_OPERATION_PAYLOAD_BYTES: usize = 256 * 1024;
const MAX_TARGET_PAYLOAD_BYTES: usize = 64 * 1024;
const MAX_TARGET_BYTES: usize = 4096;

/// Test projection for the aggregate operation-backlog query.
#[cfg(test)]
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct ApiOperationSnapshot {
    pub pending: i64,
    pub running: i64,
    pub indeterminate: i64,
    pub oldest_active_age_seconds: f64,
}

#[cfg(test)]
pub async fn api_operation_snapshot(pool: &PgPool) -> Result<ApiOperationSnapshot> {
    let row = sqlx::query(
        "SELECT
            COUNT(*) FILTER (WHERE status='pending')::BIGINT AS pending,
            COUNT(*) FILTER (WHERE status='running')::BIGINT AS running,
            COUNT(*) FILTER (WHERE status='indeterminate')::BIGINT AS indeterminate,
            COALESCE(EXTRACT(EPOCH FROM (
                clock_timestamp() - MIN(created_at) FILTER (
                    WHERE status IN ('pending','running')
                )
            )),0)::FLOAT8 AS oldest_active_age_seconds
         FROM api_operation_journal",
    )
    .fetch_one(pool)
    .await?;
    Ok(ApiOperationSnapshot {
        pending: row.get("pending"),
        running: row.get("running"),
        indeterminate: row.get("indeterminate"),
        oldest_active_age_seconds: row.get::<f64, _>("oldest_active_age_seconds").max(0.0),
    })
}

#[derive(Clone, Debug)]
pub struct OperationLease {
    pub operation: OperationRecord,
    pub worker_id: Uuid,
    lease_token: Uuid,
}

pub struct EnqueueOperation<'a> {
    pub request_id: Uuid,
    pub idempotency_id: Uuid,
    pub idempotency_lease_token: Uuid,
    pub actor_id: Uuid,
    pub actor_auth_generation: i64,
    pub authorization_policy: AuthorizationPolicy,
    pub kind: &'a str,
    pub target: Option<&'a str>,
    pub payload_version: i16,
    pub payload: &'a Value,
    pub max_attempts: i32,
    pub deadline_seconds: i64,
}

#[derive(Clone, Debug)]
pub struct OperationTargetLease {
    pub target: OperationTargetRecord,
    pub worker_id: Uuid,
    lease_token: Uuid,
}

pub struct EnqueueOperationTarget<'a> {
    pub operation_id: Uuid,
    pub target_key: &'a str,
    pub ordinal: i64,
    pub payload: &'a Value,
    pub max_attempts: i32,
    pub deadline_seconds: i64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CancelOutcome {
    Requested,
    Canceled,
    AlreadyTerminal,
    NotCancelable,
    PastPointOfNoReturn,
    NotFound,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetryOutcome {
    Pending { retry_after_seconds: i64 },
    Failed,
    Canceled,
    LostLease,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EffectAuthorizationOutcome {
    Authorized,
    AuthorizationRevoked,
    LostLease,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManualReconcileOutcome {
    Succeeded,
    Failed,
    NotIndeterminate,
    IndeterminateTargetsRemain,
    TargetsPreventSuccess,
    NotFound,
}

pub struct ManualReconciliation<'a> {
    pub reconciled_by: Uuid,
    pub reconciler_auth_generation: i64,
    /// The request that performed this reconciliation. This is deliberately
    /// distinct from the request that originally created the operation.
    pub request_id: Uuid,
    pub succeeded: bool,
    pub result: Option<&'a Value>,
    pub error_code: Option<&'a str>,
    pub evidence_note: &'a str,
}

fn validate_allowed_object_keys(value: &Value, allowed: &[&str]) -> Result<()> {
    let object = value
        .as_object()
        .context("operation payload must be a JSON object")?;
    anyhow::ensure!(
        object.keys().all(|key| allowed.contains(&key.as_str())),
        "operation payload contains an unsupported field"
    );
    Ok(())
}

fn validate_operation_payload(kind: &str, version: i16, value: &Value) -> Result<()> {
    anyhow::ensure!(version == 1, "unsupported operation payload version");
    anyhow::ensure!(
        !contains_secret_key(value),
        "operation payload must not contain credentials or private keys"
    );
    let allowed = match kind {
        "admin.user_session_cleanup" => &["user_id", "auth_generation"][..],
        "admin.tls_reload" => &[],
        "admin.panic_disconnect" => &["reason"],
        "admin.session_kick" => &["user_id", "auth_generation", "connection_id"],
        "admin.broadcast" => &["message"],
        "admin.muc_destroy" => &["room_jid", "reason", "alternate_jid"],
        "admin.island_converge" => &["mode", "epoch"],
        _ => anyhow::bail!("unsupported operation kind"),
    };
    validate_allowed_object_keys(value, allowed)?;
    let required = match kind {
        "admin.user_session_cleanup" => &["user_id", "auth_generation"][..],
        "admin.session_kick" => &["user_id", "auth_generation", "connection_id"],
        "admin.broadcast" => &["message"],
        "admin.muc_destroy" => &["room_jid"],
        "admin.island_converge" => &["mode", "epoch"],
        _ => &[],
    };
    anyhow::ensure!(
        required.iter().all(|field| value.get(*field).is_some()),
        "operation payload is missing a required field"
    );
    if let Some(user_id) = value.get("user_id") {
        Uuid::parse_str(user_id.as_str().context("user_id must be a string")?)
            .context("user_id must be a UUID")?;
    }
    for field in ["auth_generation", "epoch"] {
        if let Some(number) = value.get(field) {
            anyhow::ensure!(
                number.as_i64().is_some_and(|value| value >= 0),
                "invalid {field}"
            );
        }
    }
    for field in [
        "reason",
        "connection_id",
        "message",
        "room_jid",
        "alternate_jid",
        "mode",
    ] {
        if let Some(text) = value.get(field) {
            let text = text
                .as_str()
                .context("operation string field has the wrong type")?;
            let maximum = if field == "message" { 32_768 } else { 4_096 };
            let may_be_empty = matches!(field, "reason" | "alternate_jid");
            anyhow::ensure!(
                (may_be_empty || !text.is_empty()) && text.len() <= maximum,
                "invalid {field}"
            );
        }
    }
    if kind == "admin.muc_destroy" {
        let room_jid = value
            .get("room_jid")
            .and_then(Value::as_str)
            .context("room_jid must be a string")?;
        validate_canonical_muc_room_jid(room_jid, "room_jid")?;
        if let Some(alternate_jid) = value.get("alternate_jid").and_then(Value::as_str) {
            if !alternate_jid.is_empty() {
                validate_canonical_muc_room_jid(alternate_jid, "alternate_jid")?;
            }
        }
    }
    Ok(())
}

fn validate_canonical_muc_room_jid(value: &str, field: &str) -> Result<()> {
    let jid = northstar_xmpp_types::jid::CanonicalJid::parse_bare(value)
        .with_context(|| format!("{field} must be a valid bare JID"))?;
    anyhow::ensure!(
        jid.localpart().is_some(),
        "{field} must identify a room, not a domain"
    );
    anyhow::ensure!(
        jid.to_string() == value,
        "{field} must use its RFC 7622 canonical representation"
    );
    Ok(())
}

fn validate_operation_identity_keys(
    kind: &str,
    target: Option<&str>,
    payload: &Value,
) -> Result<()> {
    if kind != "admin.muc_destroy" {
        return Ok(());
    }
    let room_jid = payload
        .get("room_jid")
        .and_then(Value::as_str)
        .context("room_jid must be a string")?;
    anyhow::ensure!(
        target == Some(room_jid),
        "MUC destroy target must equal its canonical room_jid payload"
    );
    Ok(())
}

fn required_authorization_policy(kind: &str) -> Result<AuthorizationPolicy> {
    match kind {
        "admin.user_session_cleanup" | "admin.muc_destroy" | "admin.island_converge" => {
            Ok(AuthorizationPolicy::CommittedConsequence)
        }
        "admin.tls_reload"
        | "admin.panic_disconnect"
        | "admin.session_kick"
        | "admin.broadcast" => Ok(AuthorizationPolicy::ReauthorizeUntilEffect),
        _ => anyhow::bail!("unsupported operation kind"),
    }
}

fn operation_from_row(row: &sqlx::postgres::PgRow) -> Result<OperationRecord> {
    Ok(OperationRecord {
        id: row.get("id"),
        request_id: row.get("request_id"),
        #[cfg(test)]
        idempotency_id: row.get("idempotency_id"),
        actor_id: row.get("actor_id"),
        actor_subject_id: row.get("actor_subject_id"),
        actor_auth_generation: row.get("actor_auth_generation"),
        authorization_policy: AuthorizationPolicy::parse(
            row.get::<String, _>("authorization_policy").as_str(),
        )?,
        kind: row.get("kind"),
        target: row.get("target"),
        status: OperationStatus::parse(row.get::<String, _>("status").as_str())?,
        payload_version: row.get("payload_version"),
        payload: row.get("payload"),
        result: row.get("result"),
        error_code: row.get("error_code"),
        attempts: row.get("attempts"),
        max_attempts: row.get("max_attempts"),
        next_attempt_at: row.get("next_attempt_at"),
        deadline_at: row.get("deadline_at"),
        cancel_requested_at: row.get("cancel_requested_at"),
        point_of_no_return_at: row.get("point_of_no_return_at"),
        created_at: row.get("created_at"),
        completed_at: row.get("completed_at"),
    })
}

fn target_from_row(row: &sqlx::postgres::PgRow) -> Result<OperationTargetRecord> {
    Ok(OperationTargetRecord {
        id: row.get("id"),
        operation_id: row.get("operation_id"),
        target_key: row.get("target_key"),
        ordinal: row.get("ordinal"),
        status: OperationStatus::parse(row.get::<String, _>("status").as_str())?,
        payload: row.get("payload"),
        result: row.get("result"),
        error_code: row.get("error_code"),
        attempts: row.get("attempts"),
        max_attempts: row.get("max_attempts"),
        next_attempt_at: row.get("next_attempt_at"),
        deadline_at: row.get("deadline_at"),
        cancel_requested_at: row.get("cancel_requested_at"),
        point_of_no_return_at: row.get("point_of_no_return_at"),
        created_at: row.get("created_at"),
        completed_at: row.get("completed_at"),
    })
}

async fn audit_operation_transition(
    tx: &mut Transaction<'_, Postgres>,
    operation: &OperationRecord,
    phase: &str,
    details: Value,
) -> Result<()> {
    audit_operation_transition_for_request(
        tx,
        operation,
        phase,
        details,
        operation.request_id,
        operation.actor_id,
    )
    .await
}

async fn audit_operation_transition_for_request(
    tx: &mut Transaction<'_, Postgres>,
    operation: &OperationRecord,
    phase: &str,
    details: Value,
    request_id: Uuid,
    actor_id: Option<Uuid>,
) -> Result<()> {
    anyhow::ensure!(!request_id.is_nil(), "audit request id must not be nil");
    sqlx::query(
        "INSERT INTO audit_log(actor_id,action,target,details,request_id,operation_id)
         VALUES($1,'api.operation.transition',$2,$3,$4,$5)",
    )
    .bind(actor_id)
    .bind(&operation.target)
    .bind(json!({
        "phase": phase,
        "kind": &operation.kind,
        "status": format!("{:?}", operation.status).to_ascii_lowercase(),
        "details": details,
    }))
    .bind(request_id)
    .bind(operation.id)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests;
