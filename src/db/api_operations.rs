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
    let jid = crate::jid::CanonicalJid::parse_bare(value)
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

pub async fn enqueue_operation_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    input: &EnqueueOperation<'_>,
) -> Result<OperationRecord> {
    anyhow::ensure!(!input.request_id.is_nil(), "request id must not be nil");
    anyhow::ensure!(
        !input.idempotency_id.is_nil(),
        "idempotency id must not be nil"
    );
    anyhow::ensure!(
        !input.idempotency_lease_token.is_nil(),
        "idempotency lease token must not be nil"
    );
    anyhow::ensure!(!input.actor_id.is_nil(), "operation actor must not be nil");
    anyhow::ensure!(input.actor_auth_generation >= 0, "invalid actor generation");
    anyhow::ensure!(
        (1..=32767).contains(&input.payload_version),
        "invalid payload version"
    );
    anyhow::ensure!(
        (1..=1000).contains(&input.max_attempts),
        "invalid attempt budget"
    );
    anyhow::ensure!(
        (1..=604_800).contains(&input.deadline_seconds),
        "invalid operation deadline"
    );
    anyhow::ensure!(
        input
            .target
            .is_none_or(|target| !target.is_empty() && target.len() <= MAX_TARGET_BYTES),
        "operation target is invalid"
    );
    validate_json(
        input.payload,
        MAX_OPERATION_PAYLOAD_BYTES,
        "operation payload",
    )?;
    validate_operation_payload(input.kind, input.payload_version, input.payload)?;
    validate_operation_identity_keys(input.kind, input.target, input.payload)?;
    anyhow::ensure!(
        input.authorization_policy == required_authorization_policy(input.kind)?,
        "operation kind requires a different authorization policy"
    );

    let id = Uuid::new_v4();
    let row = sqlx::query(
        "INSERT INTO api_operation_journal
         (id,request_id,idempotency_id,actor_id,actor_subject_id,actor_auth_generation,
          authorization_policy,kind,target,payload_version,payload,max_attempts,deadline_at)
         SELECT $1,reservation.request_id,reservation.id,$4,$4,$5,kind.authorization_policy,
                kind.kind,$8,$9,$10,$11,
                clock_timestamp()+($12*INTERVAL '1 second')
         FROM api_idempotency_records AS reservation
         JOIN api_operation_kinds AS kind
           ON kind.kind=$7 AND kind.authorization_policy=$6
         WHERE reservation.id=$2 AND reservation.request_id=$3
           AND reservation.request_actor_id=$4
           AND reservation.state='started'
           AND reservation.lease_token=$13
           AND reservation.lease_expires_at > clock_timestamp()
           AND reservation.expires_at > clock_timestamp()
         RETURNING api_operation_journal.*",
    )
    .bind(id)
    .bind(input.idempotency_id)
    .bind(input.request_id)
    .bind(input.actor_id)
    .bind(input.actor_auth_generation)
    .bind(input.authorization_policy.as_str())
    .bind(input.kind)
    .bind(input.target)
    .bind(input.payload_version)
    .bind(input.payload)
    .bind(input.max_attempts)
    .bind(input.deadline_seconds)
    .bind(input.idempotency_lease_token)
    .fetch_optional(&mut **tx)
    .await?
    .context("idempotency reservation is absent, stale, or belongs to another actor")?;
    let operation = operation_from_row(&row)?;
    audit_operation_transition(tx, &operation, "requested", json!({})).await?;
    Ok(operation)
}

pub async fn operation_by_id(
    tx: &mut Transaction<'_, Postgres>,
    id: Uuid,
) -> Result<Option<OperationRecord>> {
    let row = sqlx::query("SELECT * FROM api_operation_journal WHERE id=$1")
        .bind(id)
        .fetch_optional(&mut **tx)
        .await?;
    row.as_ref().map(operation_from_row).transpose()
}

pub async fn operation_target_by_id(
    tx: &mut Transaction<'_, Postgres>,
    id: Uuid,
) -> Result<Option<OperationTargetRecord>> {
    let row = sqlx::query("SELECT * FROM api_operation_targets WHERE id=$1")
        .bind(id)
        .fetch_optional(&mut **tx)
        .await?;
    row.as_ref().map(target_from_row).transpose()
}

/// Lists operations using a stable descending `(created_at,id)` keyset. The
/// returned records intentionally exclude worker and lease credentials.
pub async fn list_operations(
    tx: &mut Transaction<'_, Postgres>,
    status: Option<&str>,
    kind: Option<&str>,
    boundary: Option<OperationPageBoundary>,
    limit: i64,
) -> Result<OperationPage> {
    anyhow::ensure!((1..=100).contains(&limit), "invalid operation page size");
    if let Some(status) = status {
        OperationStatus::parse(status)?;
    }
    if let Some(kind) = kind {
        required_authorization_policy(kind)?;
    }
    let database_now: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(&mut **tx)
        .await?;
    let (after_created_at, after_id) = boundary
        .map(|value| (Some(value.created_at), Some(value.id)))
        .unwrap_or((None, None));
    let rows = sqlx::query(
        "SELECT * FROM api_operation_journal
         WHERE ($1::text IS NULL OR status=$1)
           AND ($2::text IS NULL OR kind=$2)
           AND ($3::timestamptz IS NULL OR (created_at,id) < ($3,$4))
         ORDER BY created_at DESC,id DESC LIMIT $5",
    )
    .bind(status)
    .bind(kind)
    .bind(after_created_at)
    .bind(after_id)
    .bind(limit + 1)
    .fetch_all(&mut **tx)
    .await?;
    let mut items = rows
        .iter()
        .map(operation_from_row)
        .collect::<Result<Vec<_>>>()?;
    let next = if items.len() > limit as usize {
        items.truncate(limit as usize);
        items.last().map(|item| OperationPageBoundary {
            created_at: item.created_at,
            id: item.id,
        })
    } else {
        None
    };
    Ok(OperationPage {
        items,
        next,
        database_now,
    })
}

/// Lists a single operation's fan-out targets without exposing lease fencing
/// tokens or worker identity.
pub async fn list_operation_targets(
    tx: &mut Transaction<'_, Postgres>,
    operation_id: Uuid,
    status: Option<&str>,
    boundary: Option<OperationPageBoundary>,
    limit: i64,
) -> Result<OperationTargetPage> {
    anyhow::ensure!(!operation_id.is_nil(), "operation id must not be nil");
    anyhow::ensure!((1..=100).contains(&limit), "invalid target page size");
    if let Some(status) = status {
        OperationStatus::parse(status)?;
    }
    let database_now: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(&mut **tx)
        .await?;
    let (after_created_at, after_id) = boundary
        .map(|value| (Some(value.created_at), Some(value.id)))
        .unwrap_or((None, None));
    let rows = sqlx::query(
        "SELECT * FROM api_operation_targets
         WHERE operation_id=$1
           AND ($2::text IS NULL OR status=$2)
           AND ($3::timestamptz IS NULL OR (created_at,id) < ($3,$4))
         ORDER BY created_at DESC,id DESC LIMIT $5",
    )
    .bind(operation_id)
    .bind(status)
    .bind(after_created_at)
    .bind(after_id)
    .bind(limit + 1)
    .fetch_all(&mut **tx)
    .await?;
    let mut items = rows
        .iter()
        .map(target_from_row)
        .collect::<Result<Vec<_>>>()?;
    let next = if items.len() > limit as usize {
        items.truncate(limit as usize);
        items.last().map(|item| OperationPageBoundary {
            created_at: item.created_at,
            id: item.id,
        })
    } else {
        None
    };
    Ok(OperationTargetPage {
        items,
        next,
        database_now,
    })
}

async fn terminalize_authorization_revoked(
    tx: &mut Transaction<'_, Postgres>,
    operation: &OperationRecord,
) -> Result<bool> {
    if !no_live_targets(tx, operation.id).await? {
        return Ok(false);
    }
    sqlx::query(
        "UPDATE api_operation_targets
         SET status='failed',error_code='authorization_revoked',
             last_error_at=clock_timestamp(),completed_at=clock_timestamp(),
             updated_at=clock_timestamp()
         WHERE operation_id=$1 AND status='pending'",
    )
    .bind(operation.id)
    .execute(&mut **tx)
    .await?;
    let row = sqlx::query(
        "UPDATE api_operation_journal
         SET status='failed',error_code='authorization_revoked',
             last_error_at=clock_timestamp(),worker_id=NULL,lease_token=NULL,
             lease_expires_at=NULL,completed_at=clock_timestamp(),updated_at=clock_timestamp()
         WHERE id=$1 AND status IN ('pending','running')
           AND point_of_no_return_at IS NULL
         RETURNING *",
    )
    .bind(operation.id)
    .fetch_optional(&mut **tx)
    .await?;
    let Some(row) = row else {
        return Ok(false);
    };
    let failed = operation_from_row(&row)?;
    audit_operation_transition(
        tx,
        &failed,
        "authorization_revoked",
        json!({"actor_subject_id": failed.actor_subject_id}),
    )
    .await?;
    Ok(true)
}

pub async fn reject_revoked_operations_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    limit: i64,
) -> Result<u64> {
    anyhow::ensure!((1..=1000).contains(&limit), "invalid rejection batch size");
    let rows = sqlx::query(
        "SELECT operation.* FROM api_operation_journal AS operation
         WHERE operation.authorization_policy='reauthorize_until_effect'
           AND operation.status IN ('pending','running')
           AND operation.point_of_no_return_at IS NULL
           AND (operation.status='pending' OR operation.lease_expires_at <= clock_timestamp())
           AND NOT EXISTS (
               SELECT 1 FROM users AS actor
               WHERE actor.id=operation.actor_subject_id
                 AND actor.auth_generation=operation.actor_auth_generation
                 AND actor.is_admin AND NOT actor.is_disabled
           )
           AND NOT EXISTS (
               SELECT 1 FROM api_operation_targets AS target
               WHERE target.operation_id=operation.id AND target.status='running'
                 AND target.lease_expires_at > clock_timestamp()
           )
         ORDER BY operation.created_at,operation.id
         FOR UPDATE OF operation SKIP LOCKED LIMIT $1",
    )
    .bind(limit)
    .fetch_all(&mut **tx)
    .await?;
    let mut rejected = 0;
    for row in rows {
        let operation = operation_from_row(&row)?;
        if terminalize_authorization_revoked(tx, &operation).await? {
            rejected += 1;
        }
    }
    Ok(rejected)
}

pub async fn authorize_operation_effect_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    lease: &OperationLease,
) -> Result<EffectAuthorizationOutcome> {
    let Some(operation) = lock_current_operation_lease(tx, lease).await? else {
        return Ok(EffectAuthorizationOutcome::LostLease);
    };
    if operation.deadline_at
        <= sqlx::query_scalar::<_, DateTime<Utc>>("SELECT clock_timestamp()")
            .fetch_one(&mut **tx)
            .await?
    {
        return Ok(EffectAuthorizationOutcome::LostLease);
    }
    if operation.authorization_policy == AuthorizationPolicy::CommittedConsequence
        || operation.point_of_no_return_at.is_some()
    {
        return Ok(EffectAuthorizationOutcome::Authorized);
    }
    let authorized = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM users
         WHERE id=$1 AND auth_generation=$2 AND is_admin AND NOT is_disabled FOR SHARE)",
    )
    .bind(operation.actor_subject_id)
    .bind(operation.actor_auth_generation)
    .fetch_one(&mut **tx)
    .await?;
    if authorized {
        return Ok(EffectAuthorizationOutcome::Authorized);
    }
    if terminalize_authorization_revoked(tx, &operation).await? {
        Ok(EffectAuthorizationOutcome::AuthorizationRevoked)
    } else {
        Ok(EffectAuthorizationOutcome::LostLease)
    }
}

fn validate_operation_claim(worker_id: Uuid, lease_seconds: i64) -> Result<()> {
    anyhow::ensure!(!worker_id.is_nil(), "worker id must not be nil");
    anyhow::ensure!(
        (5..=300).contains(&lease_seconds),
        "invalid operation lease"
    );
    Ok(())
}

/// Avoid an empty claim transaction without caching the absence of work.
/// Every pending/running row must reach the original claim path: even a future
/// retry or a live lease can need authorization, cancellation or expiry work.
/// The same statement checks the empty claim's schema/ACL dependencies and
/// writable transaction state; losing authority must never look like idleness.
pub async fn operation_work_pending<'e, E>(
    executor: E,
    worker_id: Uuid,
    lease_seconds: i64,
) -> Result<bool>
where
    E: sqlx::Executor<'e, Database = Postgres>,
{
    validate_operation_claim(worker_id, lease_seconds)?;
    let row = sqlx::query(
        "WITH required(name,read_columns,write_columns,select_all) AS (VALUES
             ('api_operation_journal',
              ARRAY['id','authorization_policy','status','point_of_no_return_at',
                    'lease_expires_at','actor_subject_id','actor_auth_generation',
                    'created_at','cancel_requested_at','attempts','max_attempts',
                    'deadline_at','next_attempt_at'],
              ARRAY['status','worker_id','lease_token','lease_expires_at',
                    'attempts','updated_at'], TRUE),
             ('users', ARRAY['id','auth_generation','is_admin','is_disabled'],
              ARRAY[]::TEXT[], FALSE),
             ('api_operation_targets',
              ARRAY['operation_id','status','lease_expires_at',
                    'point_of_no_return_at','deadline_at'],
              ARRAY[]::TEXT[], FALSE)
         ), relations AS (
             SELECT required.*,pg_catalog.to_regclass(name) AS relation_id
             FROM required
         )
         SELECT EXISTS(SELECT 1 FROM api_operation_journal
                       WHERE status IN ('pending','running')) AS has_work,
                pg_catalog.current_setting('transaction_read_only')='off' AS writable,
                (SELECT bool_and(COALESCE(
                    relation.relation_id IS NOT NULL
                    AND pg_catalog.has_schema_privilege(
                        current_user,table_info.relnamespace,'USAGE')
                    AND NOT EXISTS (
                        SELECT 1 FROM pg_catalog.unnest(
                            relation.read_columns || relation.write_columns
                        ) AS expected(name)
                        WHERE NOT EXISTS (
                            SELECT 1 FROM pg_catalog.pg_attribute AS column_info
                            WHERE column_info.attrelid=relation.relation_id
                              AND column_info.attnum>0 AND NOT column_info.attisdropped
                              AND column_info.attname=expected.name
                        )
                    )
                    AND CASE WHEN pg_catalog.has_table_privilege(
                        current_user,relation.relation_id,'SELECT') THEN TRUE
                    ELSE COALESCE((
                        SELECT bool_and(pg_catalog.has_column_privilege(
                            current_user,relation.relation_id,column_info.attnum,'SELECT'))
                        FROM pg_catalog.pg_attribute AS column_info
                        WHERE column_info.attrelid=relation.relation_id
                          AND column_info.attnum>0 AND NOT column_info.attisdropped
                          AND (relation.select_all
                               OR column_info.attname=ANY(relation.read_columns))
                    ),FALSE) END
                    AND CASE WHEN pg_catalog.cardinality(relation.write_columns)=0 THEN TRUE
                    WHEN pg_catalog.has_table_privilege(
                        current_user,relation.relation_id,'UPDATE') THEN TRUE
                    ELSE COALESCE((
                        SELECT bool_and(pg_catalog.has_column_privilege(
                            current_user,relation.relation_id,column_info.attnum,'UPDATE'))
                        FROM pg_catalog.pg_attribute AS column_info
                        WHERE column_info.attrelid=relation.relation_id
                          AND column_info.attnum>0 AND NOT column_info.attisdropped
                          AND column_info.attname=ANY(relation.write_columns)
                    ),FALSE) END,
                    FALSE))
                 FROM relations AS relation
                 LEFT JOIN pg_catalog.pg_class AS table_info
                   ON table_info.oid=relation.relation_id) AS authority_valid",
    )
    .fetch_one(executor)
    .await
    .context("could not inspect durable operation work")?;
    anyhow::ensure!(
        row.try_get::<bool, _>("writable")?,
        "durable operation database is read-only"
    );
    anyhow::ensure!(
        row.try_get::<bool, _>("authority_valid")?,
        "durable operation claim permissions or schema are unavailable"
    );
    Ok(row.try_get("has_work")?)
}

pub async fn claim_operation_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    worker_id: Uuid,
    lease_seconds: i64,
) -> Result<Option<OperationLease>> {
    validate_operation_claim(worker_id, lease_seconds)?;
    expire_exhausted_operations_in_tx(tx, 64).await?;
    reject_revoked_operations_in_tx(tx, 64).await?;
    let lease_token = Uuid::new_v4();
    let row = sqlx::query(
        "WITH candidate AS (
             SELECT id FROM api_operation_journal
             WHERE cancel_requested_at IS NULL
               AND point_of_no_return_at IS NULL
               AND attempts < max_attempts
               AND deadline_at > clock_timestamp()
               AND (authorization_policy='committed_consequence' OR EXISTS (
                   SELECT 1 FROM users AS actor
                   WHERE actor.id=api_operation_journal.actor_subject_id
                     AND actor.auth_generation=api_operation_journal.actor_auth_generation
                     AND actor.is_admin AND NOT actor.is_disabled
               ))
               AND (
                    (status='pending' AND next_attempt_at <= clock_timestamp())
                 OR (status='running' AND lease_expires_at <= clock_timestamp())
               )
             ORDER BY next_attempt_at,created_at,id
             FOR UPDATE SKIP LOCKED LIMIT 1
         )
         UPDATE api_operation_journal AS operation
         SET status='running',worker_id=$1,lease_token=$2,
             lease_expires_at=LEAST(operation.deadline_at,
                 clock_timestamp()+($3*INTERVAL '1 second')),
             attempts=attempts+1,updated_at=clock_timestamp()
         FROM candidate WHERE operation.id=candidate.id
         RETURNING operation.*",
    )
    .bind(worker_id)
    .bind(lease_token)
    .bind(lease_seconds)
    .fetch_optional(&mut **tx)
    .await?;
    let Some(row) = row else {
        return Ok(None);
    };
    let operation = operation_from_row(&row)?;
    audit_operation_transition(
        tx,
        &operation,
        "claimed",
        json!({"worker_id":worker_id,"attempt":operation.attempts}),
    )
    .await?;
    Ok(Some(OperationLease {
        operation,
        worker_id,
        lease_token,
    }))
}

pub async fn renew_operation_lease_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    lease: &OperationLease,
    lease_seconds: i64,
) -> Result<bool> {
    anyhow::ensure!(
        (5..=300).contains(&lease_seconds),
        "invalid operation lease"
    );
    Ok(sqlx::query(
        "UPDATE api_operation_journal
         SET lease_expires_at=LEAST(deadline_at,
                 clock_timestamp()+($4*INTERVAL '1 second')),
             updated_at=clock_timestamp()
         WHERE id=$1 AND status='running' AND worker_id=$2 AND lease_token=$3
           AND lease_expires_at > clock_timestamp()
           AND deadline_at > clock_timestamp()",
    )
    .bind(lease.operation.id)
    .bind(lease.worker_id)
    .bind(lease.lease_token)
    .bind(lease_seconds)
    .execute(&mut **tx)
    .await?
    .rows_affected()
        == 1)
}

#[cfg(test)]
pub async fn mark_operation_point_of_no_return_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    lease: &OperationLease,
) -> Result<bool> {
    Ok(sqlx::query(
        "UPDATE api_operation_journal
         SET point_of_no_return_at=COALESCE(point_of_no_return_at,clock_timestamp()),
             updated_at=clock_timestamp()
         WHERE id=$1 AND status='running' AND worker_id=$2 AND lease_token=$3
           AND lease_expires_at > clock_timestamp()
           AND deadline_at > clock_timestamp()
           AND cancel_requested_at IS NULL
           AND point_of_no_return_at IS NULL
           AND (authorization_policy='committed_consequence' OR EXISTS (
               SELECT 1 FROM users AS actor
               WHERE actor.id=api_operation_journal.actor_subject_id
                 AND actor.auth_generation=api_operation_journal.actor_auth_generation
                 AND actor.is_admin AND NOT actor.is_disabled
           ))",
    )
    .bind(lease.operation.id)
    .bind(lease.worker_id)
    .bind(lease.lease_token)
    .execute(&mut **tx)
    .await?
    .rows_affected()
        == 1)
}

pub async fn succeed_operation_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    lease: &OperationLease,
    result: &Value,
) -> Result<bool> {
    validate_json(result, MAX_RESULT_BYTES, "operation result")?;
    let row = sqlx::query(
        "UPDATE api_operation_journal AS operation
         SET status='succeeded',result=$4,error_code=NULL,worker_id=NULL,
             lease_token=NULL,lease_expires_at=NULL,completed_at=clock_timestamp(),
             updated_at=clock_timestamp()
         WHERE id=$1 AND status='running' AND worker_id=$2 AND lease_token=$3
           AND lease_expires_at > clock_timestamp()
           AND deadline_at > clock_timestamp()
           AND (point_of_no_return_at IS NOT NULL OR EXISTS (
               SELECT 1 FROM api_operation_targets AS any_target
               WHERE any_target.operation_id=operation.id
           ))
           AND (cancel_requested_at IS NULL OR point_of_no_return_at IS NOT NULL)
           AND NOT EXISTS (
               SELECT 1 FROM api_operation_targets AS target
               WHERE target.operation_id=operation.id AND target.status <> 'succeeded'
           )
         RETURNING operation.*",
    )
    .bind(lease.operation.id)
    .bind(lease.worker_id)
    .bind(lease.lease_token)
    .bind(result)
    .fetch_optional(&mut **tx)
    .await?;
    let Some(row) = row else {
        return Ok(false);
    };
    let operation = operation_from_row(&row)?;
    audit_operation_transition(tx, &operation, "succeeded", json!({})).await?;
    Ok(true)
}

async fn no_live_targets(tx: &mut Transaction<'_, Postgres>, operation_id: Uuid) -> Result<bool> {
    Ok(!sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(
             SELECT 1 FROM api_operation_targets
             WHERE operation_id=$1 AND status='running'
         )",
    )
    .bind(operation_id)
    .fetch_one(&mut **tx)
    .await?)
}

async fn lock_current_operation_lease(
    tx: &mut Transaction<'_, Postgres>,
    lease: &OperationLease,
) -> Result<Option<OperationRecord>> {
    let row = sqlx::query(
        "SELECT * FROM api_operation_journal
         WHERE id=$1 AND status='running' AND worker_id=$2 AND lease_token=$3
           AND lease_expires_at > clock_timestamp()
         FOR UPDATE",
    )
    .bind(lease.operation.id)
    .bind(lease.worker_id)
    .bind(lease.lease_token)
    .fetch_optional(&mut **tx)
    .await?;
    row.as_ref().map(operation_from_row).transpose()
}

/// Lock order for every fan-out mutation is parent operation first, target
/// second. This is the same order used by parent cancellation/terminalization
/// and prevents a target completion racing a parent terminal transition.
async fn lock_parent_and_current_target_lease(
    tx: &mut Transaction<'_, Postgres>,
    lease: &OperationTargetLease,
) -> Result<Option<(OperationRecord, OperationTargetRecord)>> {
    let parent = sqlx::query(
        "SELECT operation.*
         FROM api_operation_journal AS operation
         JOIN api_operation_targets AS target ON target.operation_id=operation.id
         WHERE target.id=$1 AND operation.status='running'
           AND operation.lease_expires_at > clock_timestamp()
           AND operation.deadline_at > clock_timestamp()
         FOR UPDATE OF operation",
    )
    .bind(lease.target.id)
    .fetch_optional(&mut **tx)
    .await?;
    let Some(parent) = parent else {
        return Ok(None);
    };
    let parent = operation_from_row(&parent)?;
    let target = sqlx::query(
        "SELECT * FROM api_operation_targets
         WHERE id=$1 AND operation_id=$2 AND status='running'
           AND worker_id=$3 AND lease_token=$4
           AND lease_expires_at > clock_timestamp()
           AND deadline_at > clock_timestamp()
         FOR UPDATE",
    )
    .bind(lease.target.id)
    .bind(parent.id)
    .bind(lease.worker_id)
    .bind(lease.lease_token)
    .fetch_optional(&mut **tx)
    .await?;
    let Some(target) = target else {
        return Ok(None);
    };
    Ok(Some((parent, target_from_row(&target)?)))
}

async fn parent_effect_is_authorized(
    tx: &mut Transaction<'_, Postgres>,
    parent: &OperationRecord,
) -> Result<bool> {
    if parent.authorization_policy == AuthorizationPolicy::CommittedConsequence
        || parent.point_of_no_return_at.is_some()
    {
        return Ok(true);
    }
    Ok(sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM users
         WHERE id=$1 AND auth_generation=$2 AND is_admin AND NOT is_disabled FOR SHARE)",
    )
    .bind(parent.actor_subject_id)
    .bind(parent.actor_auth_generation)
    .fetch_one(&mut **tx)
    .await?)
}

async fn finalize_parent_cancel_if_targets_acked(
    tx: &mut Transaction<'_, Postgres>,
    parent: &OperationRecord,
) -> Result<()> {
    let row = sqlx::query(
        "UPDATE api_operation_journal AS operation
         SET status='canceled',worker_id=NULL,lease_token=NULL,lease_expires_at=NULL,
             completed_at=clock_timestamp(),updated_at=clock_timestamp()
         WHERE operation.id=$1 AND operation.status='running'
           AND operation.cancel_requested_at IS NOT NULL
           AND operation.point_of_no_return_at IS NULL
           AND NOT EXISTS (
               SELECT 1 FROM api_operation_targets AS target
               WHERE target.operation_id=operation.id
                 AND target.status IN ('pending','running')
           )
         RETURNING operation.*",
    )
    .bind(parent.id)
    .fetch_optional(&mut **tx)
    .await?;
    if let Some(row) = row {
        let operation = operation_from_row(&row)?;
        audit_operation_transition(
            tx,
            &operation,
            "canceled",
            json!({"targets_acknowledged":true}),
        )
        .await?;
    }
    Ok(())
}

pub async fn fail_operation_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    lease: &OperationLease,
    error_code: &str,
    result: Option<&Value>,
) -> Result<bool> {
    validate_error_code(error_code)?;
    if let Some(result) = result {
        validate_json(result, MAX_RESULT_BYTES, "operation result")?;
    }
    if lock_current_operation_lease(tx, lease).await?.is_none() {
        return Ok(false);
    }
    if !no_live_targets(tx, lease.operation.id).await? {
        return Ok(false);
    }
    sqlx::query(
        "UPDATE api_operation_targets SET status='failed',error_code=$2,
             last_error_at=clock_timestamp(),worker_id=NULL,lease_token=NULL,
             lease_expires_at=NULL,completed_at=clock_timestamp(),updated_at=clock_timestamp()
         WHERE operation_id=$1 AND status='pending'",
    )
    .bind(lease.operation.id)
    .bind(error_code)
    .execute(&mut **tx)
    .await?;
    let row = sqlx::query(
        "UPDATE api_operation_journal
         SET status='failed',result=$4,error_code=$5,last_error_at=clock_timestamp(),
             worker_id=NULL,lease_token=NULL,lease_expires_at=NULL,
             completed_at=clock_timestamp(),updated_at=clock_timestamp()
         WHERE id=$1 AND status='running' AND worker_id=$2 AND lease_token=$3
           AND lease_expires_at > clock_timestamp()
         RETURNING *",
    )
    .bind(lease.operation.id)
    .bind(lease.worker_id)
    .bind(lease.lease_token)
    .bind(result)
    .bind(error_code)
    .fetch_optional(&mut **tx)
    .await?;
    let Some(row) = row else {
        return Ok(false);
    };
    let operation = operation_from_row(&row)?;
    audit_operation_transition(tx, &operation, "failed", json!({"error_code":error_code})).await?;
    Ok(true)
}

#[cfg(test)]
fn retry_backoff_seconds(id: Uuid, attempts: i32) -> i64 {
    let exponent = u32::try_from(attempts.saturating_sub(1))
        .unwrap_or_default()
        .min(8);
    let base = 1_i64.checked_shl(exponent).unwrap_or(256).min(240);
    let jitter_window = (base / 4).max(1);
    let jitter = i64::from(id.as_bytes()[15]) % (jitter_window + 1);
    (base + jitter).min(300)
}

#[cfg(test)]
pub async fn retry_operation_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    lease: &OperationLease,
    error_code: &str,
) -> Result<RetryOutcome> {
    validate_error_code(error_code)?;
    let Some(operation) = lock_current_operation_lease(tx, lease).await? else {
        return Ok(RetryOutcome::LostLease);
    };
    let has_nonterminal_targets = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM api_operation_targets
         WHERE operation_id=$1 AND status IN ('pending','running'))",
    )
    .bind(operation.id)
    .fetch_one(&mut **tx)
    .await?;
    if has_nonterminal_targets {
        return Ok(RetryOutcome::LostLease);
    }
    if operation.cancel_requested_at.is_some() && operation.point_of_no_return_at.is_none() {
        return if acknowledge_operation_cancel_in_tx(tx, lease).await? {
            Ok(RetryOutcome::Canceled)
        } else {
            Ok(RetryOutcome::LostLease)
        };
    }
    let now: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(&mut **tx)
        .await?;
    let retry_after_seconds = retry_backoff_seconds(operation.id, operation.attempts);
    let retry_at = now + chrono::Duration::seconds(retry_after_seconds);
    if operation.attempts >= operation.max_attempts || retry_at >= operation.deadline_at {
        return if fail_operation_in_tx(tx, lease, error_code, None).await? {
            Ok(RetryOutcome::Failed)
        } else {
            Ok(RetryOutcome::LostLease)
        };
    }
    let changed = sqlx::query(
        "UPDATE api_operation_journal
         SET status='pending',error_code=$4,last_error_at=clock_timestamp(),
             next_attempt_at=$5,worker_id=NULL,lease_token=NULL,lease_expires_at=NULL,
             updated_at=clock_timestamp()
         WHERE id=$1 AND status='running' AND worker_id=$2 AND lease_token=$3
           AND lease_expires_at > clock_timestamp()",
    )
    .bind(operation.id)
    .bind(lease.worker_id)
    .bind(lease.lease_token)
    .bind(error_code)
    .bind(retry_at)
    .execute(&mut **tx)
    .await?
    .rows_affected();
    if changed != 1 {
        return Ok(RetryOutcome::LostLease);
    }
    let mut pending = operation;
    pending.status = OperationStatus::Pending;
    audit_operation_transition(
        tx,
        &pending,
        "retry_scheduled",
        json!({"error_code":error_code,"retry_after_seconds":retry_after_seconds}),
    )
    .await?;
    Ok(RetryOutcome::Pending {
        retry_after_seconds,
    })
}

pub async fn request_operation_cancel_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    operation_id: Uuid,
    canceled_by: Uuid,
    request_id: Uuid,
) -> Result<CancelOutcome> {
    anyhow::ensure!(!canceled_by.is_nil(), "cancel actor must not be nil");
    anyhow::ensure!(!request_id.is_nil(), "cancel request id must not be nil");
    let row = sqlx::query(
        "SELECT operation.*,kind.supports_cancel,
                EXISTS(SELECT 1 FROM api_operation_targets AS target
                       WHERE target.operation_id=operation.id
                         AND target.point_of_no_return_at IS NOT NULL)
                    AS target_point_of_no_return
         FROM api_operation_journal AS operation
         JOIN api_operation_kinds AS kind ON kind.kind=operation.kind
         WHERE operation.id=$1 FOR UPDATE OF operation",
    )
    .bind(operation_id)
    .fetch_optional(&mut **tx)
    .await?;
    let Some(row) = row else {
        return Ok(CancelOutcome::NotFound);
    };
    let operation = operation_from_row(&row)?;
    if operation.status.is_terminal() {
        return Ok(CancelOutcome::AlreadyTerminal);
    }
    if !row.get::<bool, _>("supports_cancel") {
        return Ok(CancelOutcome::NotCancelable);
    }
    if operation.point_of_no_return_at.is_some() || row.get::<bool, _>("target_point_of_no_return")
    {
        return Ok(CancelOutcome::PastPointOfNoReturn);
    }
    if operation.status == OperationStatus::Pending {
        sqlx::query(
            "UPDATE api_operation_targets
             SET status='canceled',cancel_requested_at=COALESCE(cancel_requested_at,clock_timestamp()),
                 worker_id=NULL,lease_token=NULL,lease_expires_at=NULL,
                 completed_at=clock_timestamp(),updated_at=clock_timestamp()
             WHERE operation_id=$1 AND status='pending'",
        )
        .bind(operation_id)
        .execute(&mut **tx)
        .await?;
        let row = sqlx::query(
            "UPDATE api_operation_journal
             SET status='canceled',cancel_requested_at=COALESCE(cancel_requested_at,clock_timestamp()),
                 cancel_requested_by=$2,completed_at=clock_timestamp(),updated_at=clock_timestamp()
             WHERE id=$1 AND status='pending' RETURNING *",
        )
        .bind(operation_id)
        .bind(canceled_by)
        .fetch_one(&mut **tx)
        .await?;
        let canceled = operation_from_row(&row)?;
        audit_operation_transition_for_request(
            tx,
            &canceled,
            "canceled",
            json!({
                "by":canceled_by,
                "original_operation_request_id":operation.request_id,
            }),
            request_id,
            Some(canceled_by),
        )
        .await?;
        return Ok(CancelOutcome::Canceled);
    }
    sqlx::query(
        "UPDATE api_operation_journal
         SET cancel_requested_at=COALESCE(cancel_requested_at,clock_timestamp()),
             cancel_requested_by=COALESCE(cancel_requested_by,$2),updated_at=clock_timestamp()
         WHERE id=$1 AND status='running' AND point_of_no_return_at IS NULL",
    )
    .bind(operation_id)
    .bind(canceled_by)
    .execute(&mut **tx)
    .await?;
    sqlx::query(
        "UPDATE api_operation_targets
         SET status=CASE WHEN status='pending' THEN 'canceled' ELSE status END,
             cancel_requested_at=COALESCE(cancel_requested_at,clock_timestamp()),
             completed_at=CASE WHEN status='pending' THEN clock_timestamp() ELSE completed_at END,
             updated_at=clock_timestamp()
         WHERE operation_id=$1 AND status IN ('pending','running')
           AND point_of_no_return_at IS NULL",
    )
    .bind(operation_id)
    .execute(&mut **tx)
    .await?;
    audit_operation_transition_for_request(
        tx,
        &operation,
        "cancel_requested",
        json!({
            "by":canceled_by,
            "original_operation_request_id":operation.request_id,
        }),
        request_id,
        Some(canceled_by),
    )
    .await?;
    Ok(CancelOutcome::Requested)
}

pub async fn acknowledge_operation_cancel_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    lease: &OperationLease,
) -> Result<bool> {
    let Some(operation) = lock_current_operation_lease(tx, lease).await? else {
        return Ok(false);
    };
    if operation.cancel_requested_at.is_none() || operation.point_of_no_return_at.is_some() {
        return Ok(false);
    }
    if !no_live_targets(tx, lease.operation.id).await? {
        return Ok(false);
    }
    sqlx::query(
        "UPDATE api_operation_targets
         SET status='canceled',cancel_requested_at=COALESCE(cancel_requested_at,clock_timestamp()),
             completed_at=clock_timestamp(),updated_at=clock_timestamp()
         WHERE operation_id=$1 AND status='pending'",
    )
    .bind(lease.operation.id)
    .execute(&mut **tx)
    .await?;
    let row = sqlx::query(
        "UPDATE api_operation_journal
         SET status='canceled',worker_id=NULL,lease_token=NULL,lease_expires_at=NULL,
             completed_at=clock_timestamp(),updated_at=clock_timestamp()
         WHERE id=$1 AND status='running' AND worker_id=$2 AND lease_token=$3
           AND lease_expires_at > clock_timestamp()
           AND cancel_requested_at IS NOT NULL AND point_of_no_return_at IS NULL
         RETURNING *",
    )
    .bind(lease.operation.id)
    .bind(lease.worker_id)
    .bind(lease.lease_token)
    .fetch_optional(&mut **tx)
    .await?;
    let Some(row) = row else {
        return Ok(false);
    };
    let operation = operation_from_row(&row)?;
    audit_operation_transition(tx, &operation, "canceled", json!({})).await?;
    Ok(true)
}

pub async fn enqueue_operation_target_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    input: &EnqueueOperationTarget<'_>,
) -> Result<OperationTargetRecord> {
    anyhow::ensure!(
        !input.target_key.is_empty() && input.target_key.len() <= MAX_TARGET_BYTES,
        "operation target key is invalid"
    );
    anyhow::ensure!(input.ordinal >= 0, "operation target ordinal is invalid");
    anyhow::ensure!(
        (1..=1000).contains(&input.max_attempts),
        "invalid target attempt budget"
    );
    anyhow::ensure!(
        (1..=604_800).contains(&input.deadline_seconds),
        "invalid target deadline"
    );
    validate_json(
        input.payload,
        MAX_TARGET_PAYLOAD_BYTES,
        "operation target payload",
    )?;
    anyhow::ensure!(
        !contains_secret_key(input.payload),
        "operation target payload must not contain credentials or private keys"
    );
    let parent = sqlx::query(
        "SELECT operation.*,kind.supports_targets,
                operation.deadline_at > clock_timestamp() AS within_deadline
         FROM api_operation_journal AS operation
         JOIN api_operation_kinds AS kind ON kind.kind=operation.kind
         WHERE operation.id=$1 FOR UPDATE OF operation",
    )
    .bind(input.operation_id)
    .fetch_optional(&mut **tx)
    .await?
    .context("operation does not exist")?;
    let operation = operation_from_row(&parent)?;
    anyhow::ensure!(
        matches!(
            operation.status,
            OperationStatus::Pending | OperationStatus::Running
        ) && operation.cancel_requested_at.is_none()
            && operation.point_of_no_return_at.is_none()
            && parent.get::<bool, _>("within_deadline")
            && parent.get::<bool, _>("supports_targets"),
        "operation cannot accept targets"
    );
    let row = sqlx::query(
        "INSERT INTO api_operation_targets
         (id,operation_id,target_key,ordinal,payload,max_attempts,deadline_at)
         VALUES($1,$2,$3,$4,$5,$6,
                LEAST($7,clock_timestamp()+($8*INTERVAL '1 second')))
         ON CONFLICT(operation_id,target_key) DO UPDATE
           SET target_key=EXCLUDED.target_key
           WHERE api_operation_targets.ordinal=EXCLUDED.ordinal
             AND api_operation_targets.payload=EXCLUDED.payload
             AND api_operation_targets.max_attempts=EXCLUDED.max_attempts
         RETURNING api_operation_targets.*",
    )
    .bind(Uuid::new_v4())
    .bind(input.operation_id)
    .bind(input.target_key)
    .bind(input.ordinal)
    .bind(input.payload)
    .bind(input.max_attempts)
    .bind(operation.deadline_at)
    .bind(input.deadline_seconds)
    .fetch_optional(&mut **tx)
    .await?
    .context("operation cannot accept targets")?;
    target_from_row(&row)
}

pub async fn claim_operation_target_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    operation_id: Uuid,
    worker_id: Uuid,
    lease_seconds: i64,
) -> Result<Option<OperationTargetLease>> {
    anyhow::ensure!(!worker_id.is_nil(), "worker id must not be nil");
    anyhow::ensure!((5..=300).contains(&lease_seconds), "invalid target lease");
    expire_exhausted_operations_in_tx(tx, 64).await?;
    let parent = sqlx::query(
        "SELECT operation.*,
                (operation.authorization_policy='committed_consequence'
                 OR operation.point_of_no_return_at IS NOT NULL OR EXISTS (
                    SELECT 1 FROM users AS actor
                    WHERE actor.id=operation.actor_subject_id
                      AND actor.auth_generation=operation.actor_auth_generation
                      AND actor.is_admin AND NOT actor.is_disabled
                )) AS effect_authorized
         FROM api_operation_journal AS operation
         WHERE operation.id=$1 AND operation.status='running'
           AND operation.cancel_requested_at IS NULL
           AND operation.lease_expires_at > clock_timestamp()
           AND operation.deadline_at > clock_timestamp()
         FOR UPDATE OF operation",
    )
    .bind(operation_id)
    .fetch_optional(&mut **tx)
    .await?;
    let Some(parent) = parent else {
        return Ok(None);
    };
    if !parent.get::<bool, _>("effect_authorized") {
        return Ok(None);
    }
    let lease_token = Uuid::new_v4();
    let row = sqlx::query(
        "WITH candidate AS (
             SELECT target.id
             FROM api_operation_targets AS target
             WHERE target.operation_id=$1
               AND target.cancel_requested_at IS NULL
               AND target.point_of_no_return_at IS NULL
               AND target.attempts < target.max_attempts
               AND target.deadline_at > clock_timestamp()
               AND (
                    (target.status='pending' AND target.next_attempt_at <= clock_timestamp())
                 OR (target.status='running' AND target.lease_expires_at <= clock_timestamp())
               )
             ORDER BY target.next_attempt_at,target.ordinal,target.id
             FOR UPDATE OF target SKIP LOCKED LIMIT 1
         )
         UPDATE api_operation_targets AS target
         SET status='running',worker_id=$2,lease_token=$3,
             lease_expires_at=LEAST(target.deadline_at,
                 clock_timestamp()+($4*INTERVAL '1 second')),
             attempts=attempts+1,updated_at=clock_timestamp()
         FROM candidate WHERE target.id=candidate.id
         RETURNING target.*",
    )
    .bind(operation_id)
    .bind(worker_id)
    .bind(lease_token)
    .bind(lease_seconds)
    .fetch_optional(&mut **tx)
    .await?;
    let Some(row) = row else {
        return Ok(None);
    };
    Ok(Some(OperationTargetLease {
        target: target_from_row(&row)?,
        worker_id,
        lease_token,
    }))
}

pub async fn renew_operation_target_lease_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    lease: &OperationTargetLease,
    lease_seconds: i64,
) -> Result<bool> {
    anyhow::ensure!((5..=300).contains(&lease_seconds), "invalid target lease");
    if lock_parent_and_current_target_lease(tx, lease)
        .await?
        .is_none()
    {
        return Ok(false);
    }
    Ok(sqlx::query(
        "UPDATE api_operation_targets
         SET lease_expires_at=LEAST(deadline_at,
                 clock_timestamp()+($4*INTERVAL '1 second')),
             updated_at=clock_timestamp()
         WHERE id=$1 AND status='running' AND worker_id=$2 AND lease_token=$3
           AND lease_expires_at > clock_timestamp()
           AND deadline_at > clock_timestamp()",
    )
    .bind(lease.target.id)
    .bind(lease.worker_id)
    .bind(lease.lease_token)
    .bind(lease_seconds)
    .execute(&mut **tx)
    .await?
    .rows_affected()
        == 1)
}

pub async fn mark_operation_target_point_of_no_return_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    lease: &OperationTargetLease,
) -> Result<bool> {
    let Some((parent, target)) = lock_parent_and_current_target_lease(tx, lease).await? else {
        return Ok(false);
    };
    if parent.cancel_requested_at.is_some()
        || target.cancel_requested_at.is_some()
        || target.point_of_no_return_at.is_some()
        || !parent_effect_is_authorized(tx, &parent).await?
    {
        return Ok(false);
    }
    Ok(sqlx::query(
        "UPDATE api_operation_targets
         SET point_of_no_return_at=COALESCE(point_of_no_return_at,clock_timestamp()),
             updated_at=clock_timestamp()
         WHERE id=$1 AND status='running' AND worker_id=$2 AND lease_token=$3
           AND lease_expires_at > clock_timestamp()
           AND deadline_at > clock_timestamp()
           AND cancel_requested_at IS NULL
           AND point_of_no_return_at IS NULL",
    )
    .bind(lease.target.id)
    .bind(lease.worker_id)
    .bind(lease.lease_token)
    .execute(&mut **tx)
    .await?
    .rows_affected()
        == 1)
}

pub async fn succeed_operation_target_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    lease: &OperationTargetLease,
    result: &Value,
) -> Result<bool> {
    validate_json(result, MAX_RESULT_BYTES, "operation target result")?;
    let Some((parent, target)) = lock_parent_and_current_target_lease(tx, lease).await? else {
        return Ok(false);
    };
    if target.point_of_no_return_at.is_none() || !parent_effect_is_authorized(tx, &parent).await? {
        return Ok(false);
    }
    Ok(sqlx::query(
        "UPDATE api_operation_targets
         SET status='succeeded',result=$4,error_code=NULL,worker_id=NULL,
             lease_token=NULL,lease_expires_at=NULL,completed_at=clock_timestamp(),
             updated_at=clock_timestamp()
         WHERE id=$1 AND status='running' AND worker_id=$2 AND lease_token=$3
           AND lease_expires_at > clock_timestamp()
           AND deadline_at > clock_timestamp()
           AND point_of_no_return_at IS NOT NULL
           AND (cancel_requested_at IS NULL OR point_of_no_return_at IS NOT NULL)",
    )
    .bind(lease.target.id)
    .bind(lease.worker_id)
    .bind(lease.lease_token)
    .bind(result)
    .execute(&mut **tx)
    .await?
    .rows_affected()
        == 1)
}

/// Record an effect whose outcome cannot be proved after the target crossed
/// its point of no return.  This is deliberately different from an ordinary
/// failure: the effect may have happened partially (or completely) before the
/// executor returned an error, so retrying or claiming that it failed would
/// both be unsafe.  The parent and the affected target remain terminally
/// `indeterminate` until an administrator records evidence through the
/// reconciliation API.
pub async fn mark_operation_target_indeterminate_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    parent_lease: &OperationLease,
    target_lease: &OperationTargetLease,
    error_code: &str,
    result: Option<&Value>,
) -> Result<bool> {
    validate_error_code(error_code)?;
    if let Some(result) = result {
        validate_json(result, MAX_RESULT_BYTES, "operation target result")?;
    }
    let Some(current_parent) = lock_current_operation_lease(tx, parent_lease).await? else {
        return Ok(false);
    };
    let Some((parent, target)) = lock_parent_and_current_target_lease(tx, target_lease).await?
    else {
        return Ok(false);
    };
    // A target lease has its own fencing token. Never reuse it as the
    // parent's token when terminalizing the journal row: the two leases are
    // intentionally claimed independently. Requiring both current leases
    // also prevents a stale target worker from making the parent terminal.
    if parent.id != current_parent.id {
        return Ok(false);
    }
    let Some(target_point_of_no_return) = target.point_of_no_return_at else {
        return Ok(false);
    };

    // The production worker executes one target at a time for a parent. Keep
    // that invariant explicit here so a future concurrent caller cannot
    // terminalize the parent while another fenced effect is still running.
    let another_target_is_running = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(
             SELECT 1 FROM api_operation_targets
             WHERE operation_id=$1 AND id<>$2 AND status='running'
         )",
    )
    .bind(parent.id)
    .bind(target.id)
    .fetch_one(&mut **tx)
    .await?;
    if another_target_is_running {
        return Ok(false);
    }

    let target_changed = sqlx::query(
        "UPDATE api_operation_targets
         SET status='indeterminate',result=$4,error_code=$5,
             last_error_at=clock_timestamp(),worker_id=NULL,lease_token=NULL,
             lease_expires_at=NULL,completed_at=clock_timestamp(),
             updated_at=clock_timestamp()
         WHERE id=$1 AND status='running' AND worker_id=$2 AND lease_token=$3
           AND lease_expires_at > clock_timestamp()
           AND deadline_at > clock_timestamp()
           AND point_of_no_return_at IS NOT NULL",
    )
    .bind(target.id)
    .bind(target_lease.worker_id)
    .bind(target_lease.lease_token)
    .bind(result)
    .bind(error_code)
    .execute(&mut **tx)
    .await?
    .rows_affected()
        == 1;
    if !target_changed {
        return Ok(false);
    }

    sqlx::query(
        "UPDATE api_operation_targets
         SET status='failed',error_code='parent_outcome_indeterminate',
             last_error_at=clock_timestamp(),worker_id=NULL,lease_token=NULL,
             lease_expires_at=NULL,completed_at=clock_timestamp(),
             updated_at=clock_timestamp()
         WHERE operation_id=$1 AND status='pending'",
    )
    .bind(parent.id)
    .execute(&mut **tx)
    .await?;

    let row = sqlx::query(
        "UPDATE api_operation_journal
         SET status='indeterminate',result=$4,error_code=$5,
             last_error_at=clock_timestamp(),worker_id=NULL,lease_token=NULL,
             lease_expires_at=NULL,
             point_of_no_return_at=COALESCE(point_of_no_return_at,$6),
             completed_at=clock_timestamp(),updated_at=clock_timestamp()
         WHERE id=$1 AND status='running' AND worker_id=$2 AND lease_token=$3
           AND lease_expires_at > clock_timestamp()
         RETURNING *",
    )
    .bind(parent.id)
    .bind(parent_lease.worker_id)
    .bind(parent_lease.lease_token)
    .bind(result)
    .bind(error_code)
    .bind(target_point_of_no_return)
    .fetch_optional(&mut **tx)
    .await?;
    let Some(row) = row else {
        anyhow::bail!("parent operation lease changed while recording indeterminate effect");
    };
    let operation = operation_from_row(&row)?;
    audit_operation_transition(
        tx,
        &operation,
        "indeterminate",
        json!({"error_code":error_code,"effect_returned_error":true}),
    )
    .await?;
    Ok(true)
}

pub async fn acknowledge_operation_target_cancel_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    lease: &OperationTargetLease,
) -> Result<bool> {
    let Some((parent, _)) = lock_parent_and_current_target_lease(tx, lease).await? else {
        return Ok(false);
    };
    let changed = sqlx::query(
        "UPDATE api_operation_targets
         SET status='canceled',worker_id=NULL,lease_token=NULL,lease_expires_at=NULL,
             completed_at=clock_timestamp(),updated_at=clock_timestamp()
         WHERE id=$1 AND status='running' AND worker_id=$2 AND lease_token=$3
           AND lease_expires_at > clock_timestamp()
           AND cancel_requested_at IS NOT NULL AND point_of_no_return_at IS NULL",
    )
    .bind(lease.target.id)
    .bind(lease.worker_id)
    .bind(lease.lease_token)
    .execute(&mut **tx)
    .await?
    .rows_affected()
        == 1;
    if changed {
        finalize_parent_cancel_if_targets_acked(tx, &parent).await?;
    }
    Ok(changed)
}

/// Bound one maintenance pass. Once a worker has crossed the point of no
/// return, an expired lease is never reclaimed and never guessed to have
/// failed: the durable state becomes `indeterminate` until an administrator
/// reconciles the real external outcome.
pub async fn expire_exhausted_operations_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    limit: i64,
) -> Result<u64> {
    anyhow::ensure!((1..=1000).contains(&limit), "invalid expiry batch size");
    let ids: Vec<Uuid> = sqlx::query_scalar(
        "SELECT operation.id FROM api_operation_journal AS operation
         WHERE operation.status IN ('pending','running')
           AND (
                operation.deadline_at <= clock_timestamp()
             OR (operation.attempts >= operation.max_attempts AND
                 (operation.status='pending' OR operation.lease_expires_at <= clock_timestamp()))
             OR (operation.status='running' AND operation.point_of_no_return_at IS NOT NULL
                 AND operation.lease_expires_at <= clock_timestamp())
             OR (operation.status='running' AND operation.cancel_requested_at IS NOT NULL
                 AND operation.lease_expires_at <= clock_timestamp())
             OR EXISTS (
                 SELECT 1 FROM api_operation_targets AS expired_target
                 WHERE expired_target.operation_id=operation.id
                   AND expired_target.status='running'
                   AND expired_target.point_of_no_return_at IS NOT NULL
                   AND (expired_target.lease_expires_at <= clock_timestamp()
                        OR expired_target.deadline_at <= clock_timestamp())
             )
           )
           AND NOT EXISTS (
               SELECT 1 FROM api_operation_targets AS target
               WHERE target.operation_id=operation.id AND target.status='running'
                 AND target.lease_expires_at > clock_timestamp()
           )
         ORDER BY operation.deadline_at,operation.id
         FOR UPDATE SKIP LOCKED LIMIT $1",
    )
    .bind(limit)
    .fetch_all(&mut **tx)
    .await?;
    let mut expired = 0_u64;
    for id in ids {
        let operation_row =
            sqlx::query("SELECT * FROM api_operation_journal WHERE id=$1 FOR UPDATE")
                .bind(id)
                .fetch_one(&mut **tx)
                .await?;
        let operation = operation_from_row(&operation_row)?;
        let target_pnr: Option<DateTime<Utc>> = sqlx::query_scalar(
            "SELECT MIN(point_of_no_return_at) FROM api_operation_targets
             WHERE operation_id=$1 AND status IN ('running','indeterminate')
               AND point_of_no_return_at IS NOT NULL",
        )
        .bind(id)
        .fetch_one(&mut **tx)
        .await?;
        let is_indeterminate = operation.point_of_no_return_at.is_some() || target_pnr.is_some();
        let is_canceled = operation.cancel_requested_at.is_some() && !is_indeterminate;

        if is_indeterminate {
            sqlx::query(
                "UPDATE api_operation_targets
                 SET status=CASE WHEN point_of_no_return_at IS NOT NULL
                                 THEN 'indeterminate' ELSE 'failed' END,
                     error_code=CASE WHEN point_of_no_return_at IS NOT NULL
                                     THEN 'worker_lost_after_point_of_no_return'
                                     ELSE 'parent_outcome_indeterminate' END,
                     last_error_at=clock_timestamp(),worker_id=NULL,lease_token=NULL,
                     lease_expires_at=NULL,completed_at=clock_timestamp(),updated_at=clock_timestamp()
                 WHERE operation_id=$1 AND status IN ('pending','running')",
            )
            .bind(id)
            .execute(&mut **tx)
            .await?;
        } else if is_canceled {
            sqlx::query(
                "UPDATE api_operation_targets
                 SET status='canceled',cancel_requested_at=COALESCE(cancel_requested_at,clock_timestamp()),
                     worker_id=NULL,lease_token=NULL,lease_expires_at=NULL,
                     completed_at=clock_timestamp(),updated_at=clock_timestamp()
                 WHERE operation_id=$1 AND status IN ('pending','running')",
            )
            .bind(id)
            .execute(&mut **tx)
            .await?;
        } else {
            sqlx::query(
                "UPDATE api_operation_targets
                 SET status='failed',error_code='operation_deadline_or_attempts_exhausted',
                     last_error_at=clock_timestamp(),worker_id=NULL,lease_token=NULL,
                     lease_expires_at=NULL,completed_at=clock_timestamp(),updated_at=clock_timestamp()
                 WHERE operation_id=$1 AND status IN ('pending','running')",
            )
            .bind(id)
            .execute(&mut **tx)
            .await?;
        }
        let status = if is_indeterminate {
            "indeterminate"
        } else if is_canceled {
            "canceled"
        } else {
            "failed"
        };
        let error_code = if is_indeterminate {
            Some("worker_lost_after_point_of_no_return")
        } else if is_canceled {
            None
        } else {
            Some("operation_deadline_or_attempts_exhausted")
        };
        let row = sqlx::query(
            "UPDATE api_operation_journal
             SET status=$2,error_code=$3,
                 last_error_at=clock_timestamp(),worker_id=NULL,lease_token=NULL,
                 lease_expires_at=NULL,
                 point_of_no_return_at=CASE WHEN $2='indeterminate'
                     THEN COALESCE(point_of_no_return_at,$4,clock_timestamp())
                     ELSE point_of_no_return_at END,
                 completed_at=clock_timestamp(),updated_at=clock_timestamp()
             WHERE id=$1 AND status IN ('pending','running') RETURNING *",
        )
        .bind(id)
        .bind(status)
        .bind(error_code)
        .bind(target_pnr)
        .fetch_optional(&mut **tx)
        .await?;
        if let Some(row) = row {
            let operation = operation_from_row(&row)?;
            audit_operation_transition(
                tx,
                &operation,
                status,
                json!({"error_code":error_code,"maintenance":true}),
            )
            .await?;
            expired += 1;
        }
    }
    Ok(expired)
}

async fn authorize_manual_reconciler(
    tx: &mut Transaction<'_, Postgres>,
    actor_id: Uuid,
    auth_generation: i64,
) -> Result<bool> {
    anyhow::ensure!(
        !actor_id.is_nil() && auth_generation >= 0,
        "invalid reconciler"
    );
    Ok(sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM users
         WHERE id=$1 AND auth_generation=$2 AND is_admin AND NOT is_disabled FOR SHARE)",
    )
    .bind(actor_id)
    .bind(auth_generation)
    .fetch_one(&mut **tx)
    .await?)
}

/// Resolve one indeterminate target after an operator has checked the actual
/// external system. The evidence note is mandatory and is written only to the
/// audit log; it must never contain a credential.
pub async fn reconcile_indeterminate_target_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    target_id: Uuid,
    input: &ManualReconciliation<'_>,
) -> Result<ManualReconcileOutcome> {
    anyhow::ensure!(
        !input.request_id.is_nil(),
        "reconciliation request id is invalid"
    );
    validate_manual_reconciliation_content(
        input.succeeded,
        input.result,
        input.error_code,
        input.evidence_note,
    )?;
    if !authorize_manual_reconciler(tx, input.reconciled_by, input.reconciler_auth_generation)
        .await?
    {
        return Ok(ManualReconcileOutcome::NotFound);
    }
    let parent = sqlx::query(
        "SELECT operation.* FROM api_operation_journal AS operation
         JOIN api_operation_targets AS target ON target.operation_id=operation.id
         WHERE target.id=$1 FOR UPDATE OF operation",
    )
    .bind(target_id)
    .fetch_optional(&mut **tx)
    .await?;
    let Some(parent) = parent else {
        return Ok(ManualReconcileOutcome::NotFound);
    };
    let parent = operation_from_row(&parent)?;
    let status = if input.succeeded {
        "succeeded"
    } else {
        "failed"
    };
    let row = sqlx::query(
        "UPDATE api_operation_targets
         SET status=$2,result=$3,error_code=$4,last_error_at=CASE WHEN $2='failed'
                 THEN clock_timestamp() ELSE last_error_at END,
             updated_at=clock_timestamp()
         WHERE id=$1 AND status='indeterminate' RETURNING id",
    )
    .bind(target_id)
    .bind(status)
    .bind(input.result)
    .bind(if input.succeeded {
        None
    } else {
        input.error_code
    })
    .fetch_optional(&mut **tx)
    .await?;
    if row.is_none() {
        return Ok(ManualReconcileOutcome::NotIndeterminate);
    }
    sqlx::query(
        "INSERT INTO audit_log(actor_id,action,target,details,request_id,operation_id)
         VALUES($1,'api.operation.target_reconciled',$2,$3,$4,$5)",
    )
    .bind(input.reconciled_by)
    .bind(target_id.to_string())
    .bind(json!({
        "status":status,
        "evidence_note":input.evidence_note,
        "original_operation_request_id":parent.request_id,
    }))
    .bind(input.request_id)
    .bind(parent.id)
    .execute(&mut **tx)
    .await?;
    Ok(if input.succeeded {
        ManualReconcileOutcome::Succeeded
    } else {
        ManualReconcileOutcome::Failed
    })
}

/// Resolve the parent only after every indeterminate target was separately
/// reconciled. A success is accepted only when every fan-out target succeeded.
pub async fn reconcile_indeterminate_operation_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    operation_id: Uuid,
    input: &ManualReconciliation<'_>,
) -> Result<ManualReconcileOutcome> {
    anyhow::ensure!(
        !input.request_id.is_nil(),
        "reconciliation request id is invalid"
    );
    validate_manual_reconciliation_content(
        input.succeeded,
        input.result,
        input.error_code,
        input.evidence_note,
    )?;
    if !authorize_manual_reconciler(tx, input.reconciled_by, input.reconciler_auth_generation)
        .await?
    {
        return Ok(ManualReconcileOutcome::NotFound);
    }
    let operation = sqlx::query("SELECT * FROM api_operation_journal WHERE id=$1 FOR UPDATE")
        .bind(operation_id)
        .fetch_optional(&mut **tx)
        .await?;
    let Some(operation) = operation else {
        return Ok(ManualReconcileOutcome::NotFound);
    };
    let operation = operation_from_row(&operation)?;
    if operation.status != OperationStatus::Indeterminate {
        return Ok(ManualReconcileOutcome::NotIndeterminate);
    }
    let counts = sqlx::query(
        "SELECT COUNT(*) FILTER (WHERE status='indeterminate') AS indeterminate,
                COUNT(*) FILTER (WHERE status<>'succeeded') AS not_succeeded
         FROM api_operation_targets WHERE operation_id=$1",
    )
    .bind(operation_id)
    .fetch_one(&mut **tx)
    .await?;
    if counts.get::<i64, _>("indeterminate") != 0 {
        return Ok(ManualReconcileOutcome::IndeterminateTargetsRemain);
    }
    if input.succeeded && counts.get::<i64, _>("not_succeeded") != 0 {
        return Ok(ManualReconcileOutcome::TargetsPreventSuccess);
    }
    let status = if input.succeeded {
        "succeeded"
    } else {
        "failed"
    };
    let row = sqlx::query(
        "UPDATE api_operation_journal
         SET status=$2,result=$3,error_code=$4,
             last_error_at=CASE WHEN $2='failed' THEN clock_timestamp() ELSE last_error_at END,
             updated_at=clock_timestamp()
         WHERE id=$1 AND status='indeterminate' RETURNING *",
    )
    .bind(operation_id)
    .bind(status)
    .bind(input.result)
    .bind(if input.succeeded {
        None
    } else {
        input.error_code
    })
    .fetch_one(&mut **tx)
    .await?;
    let reconciled = operation_from_row(&row)?;
    audit_operation_transition_for_request(
        tx,
        &reconciled,
        "manually_reconciled",
        json!({
            "by":input.reconciled_by,
            "status":status,
            "evidence_note":input.evidence_note,
            "original_operation_request_id":operation.request_id,
        }),
        input.request_id,
        Some(input.reconciled_by),
    )
    .await?;
    Ok(if input.succeeded {
        ManualReconcileOutcome::Succeeded
    } else {
        ManualReconcileOutcome::Failed
    })
}

#[cfg(test)]
mod tests;
