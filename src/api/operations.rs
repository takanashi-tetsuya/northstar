use std::sync::Arc;

use axum::{extract::State, http::StatusCode, response::Response, Json};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use uuid::Uuid;

use crate::{db, error::AppError, state::AppState};

use super::{
    admin::{acquire_admin_mutation_in_tx, complete_admin_response, AdminMutationAcquire},
    idempotency_replay_response, pagination, ApiAdmin, ApiEmpty, ApiJson, ApiPath, ApiQuery,
};

const OPERATIONS_ENDPOINT: &str = "admin.operations";
const TARGETS_ENDPOINT: &str = "admin.operation_targets";
// Operation and target summaries contain a caller-controlled (but database
// constrained) 4 KiB target string. Keeping pages at 25 items bounds a
// successful encoded summary page to comfortably below the API body limit.
const MAX_SUMMARY_PAGE_ITEMS: i64 = 25;
const OPERATION_STATUSES: &[&str] = &[
    "pending",
    "running",
    "succeeded",
    "failed",
    "canceled",
    "indeterminate",
];
const PUBLIC_OPERATION_KINDS: &[&str] = &[
    "admin.user_session_cleanup",
    "admin.tls_reload",
    "admin.panic_disconnect",
    "admin.session_kick",
    "admin.broadcast",
    "admin.muc_destroy",
    "admin.island_converge",
];

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationListQuery {
    status: Option<String>,
    kind: Option<String>,
    cursor: Option<String>,
    limit: Option<i64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetListQuery {
    status: Option<String>,
    cursor: Option<String>,
    limit: Option<i64>,
}

#[derive(Serialize)]
pub struct OperationView {
    id: Uuid,
    request_id: Uuid,
    actor_subject_id: Uuid,
    authorization_policy: &'static str,
    kind: String,
    target: Option<String>,
    status: &'static str,
    payload_version: i16,
    payload: Value,
    result: Option<Value>,
    error_code: Option<String>,
    attempts: i32,
    max_attempts: i32,
    next_attempt_at: DateTime<Utc>,
    deadline_at: DateTime<Utc>,
    cancel_requested_at: Option<DateTime<Utc>>,
    point_of_no_return_at: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
    completed_at: Option<DateTime<Utc>>,
}

#[derive(Serialize)]
pub struct OperationSummary {
    id: Uuid,
    request_id: Uuid,
    actor_subject_id: Uuid,
    authorization_policy: &'static str,
    kind: String,
    target: Option<String>,
    status: &'static str,
    payload_version: i16,
    error_code: Option<String>,
    attempts: i32,
    max_attempts: i32,
    next_attempt_at: DateTime<Utc>,
    deadline_at: DateTime<Utc>,
    cancel_requested_at: Option<DateTime<Utc>>,
    point_of_no_return_at: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
    completed_at: Option<DateTime<Utc>>,
}

impl From<db::OperationRecord> for OperationSummary {
    fn from(value: db::OperationRecord) -> Self {
        Self {
            id: value.id,
            request_id: value.request_id,
            actor_subject_id: value.actor_subject_id,
            authorization_policy: value.authorization_policy.label(),
            kind: value.kind,
            target: value.target,
            status: value.status.label(),
            payload_version: value.payload_version,
            error_code: value.error_code,
            attempts: value.attempts,
            max_attempts: value.max_attempts,
            next_attempt_at: value.next_attempt_at,
            deadline_at: value.deadline_at,
            cancel_requested_at: value.cancel_requested_at,
            point_of_no_return_at: value.point_of_no_return_at,
            created_at: value.created_at,
            completed_at: value.completed_at,
        }
    }
}

impl From<db::OperationRecord> for OperationView {
    fn from(value: db::OperationRecord) -> Self {
        Self {
            id: value.id,
            request_id: value.request_id,
            actor_subject_id: value.actor_subject_id,
            authorization_policy: value.authorization_policy.label(),
            kind: value.kind,
            target: value.target,
            status: value.status.label(),
            payload_version: value.payload_version,
            payload: value.payload,
            result: value.result,
            error_code: value.error_code,
            attempts: value.attempts,
            max_attempts: value.max_attempts,
            next_attempt_at: value.next_attempt_at,
            deadline_at: value.deadline_at,
            cancel_requested_at: value.cancel_requested_at,
            point_of_no_return_at: value.point_of_no_return_at,
            created_at: value.created_at,
            completed_at: value.completed_at,
        }
    }
}

#[derive(Serialize)]
pub struct TargetView {
    id: Uuid,
    operation_id: Uuid,
    target_key: String,
    ordinal: i64,
    status: &'static str,
    payload: Value,
    result: Option<Value>,
    error_code: Option<String>,
    attempts: i32,
    max_attempts: i32,
    next_attempt_at: DateTime<Utc>,
    deadline_at: DateTime<Utc>,
    cancel_requested_at: Option<DateTime<Utc>>,
    point_of_no_return_at: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
    completed_at: Option<DateTime<Utc>>,
}

impl From<db::OperationTargetRecord> for TargetView {
    fn from(value: db::OperationTargetRecord) -> Self {
        Self {
            id: value.id,
            operation_id: value.operation_id,
            target_key: value.target_key,
            ordinal: value.ordinal,
            status: value.status.label(),
            payload: value.payload,
            result: value.result,
            error_code: value.error_code,
            attempts: value.attempts,
            max_attempts: value.max_attempts,
            next_attempt_at: value.next_attempt_at,
            deadline_at: value.deadline_at,
            cancel_requested_at: value.cancel_requested_at,
            point_of_no_return_at: value.point_of_no_return_at,
            created_at: value.created_at,
            completed_at: value.completed_at,
        }
    }
}

#[derive(Serialize)]
pub struct TargetSummary {
    id: Uuid,
    operation_id: Uuid,
    target_key: String,
    ordinal: i64,
    status: &'static str,
    error_code: Option<String>,
    attempts: i32,
    max_attempts: i32,
    next_attempt_at: DateTime<Utc>,
    deadline_at: DateTime<Utc>,
    cancel_requested_at: Option<DateTime<Utc>>,
    point_of_no_return_at: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
    completed_at: Option<DateTime<Utc>>,
}

impl From<db::OperationTargetRecord> for TargetSummary {
    fn from(value: db::OperationTargetRecord) -> Self {
        Self {
            id: value.id,
            operation_id: value.operation_id,
            target_key: value.target_key,
            ordinal: value.ordinal,
            status: value.status.label(),
            error_code: value.error_code,
            attempts: value.attempts,
            max_attempts: value.max_attempts,
            next_attempt_at: value.next_attempt_at,
            deadline_at: value.deadline_at,
            cancel_requested_at: value.cancel_requested_at,
            point_of_no_return_at: value.point_of_no_return_at,
            created_at: value.created_at,
            completed_at: value.completed_at,
        }
    }
}

#[derive(Serialize)]
pub struct Page<T> {
    items: Vec<T>,
    next_cursor: Option<String>,
}

async fn reauthorize(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    actor: &ApiAdmin,
) -> Result<(), AppError> {
    if !db::authorize_user_in_tx(tx, actor.id, actor.auth_generation, actor.session_token()).await?
    {
        return Err(AppError::Unauthorized);
    }
    if !db::authorize_admin_in_tx(tx, actor.id, actor.auth_generation, actor.session_token())
        .await?
    {
        return Err(AppError::Forbidden);
    }
    Ok(())
}

fn validate_filter<'a>(
    value: Option<&'a str>,
    allowed: &[&str],
    label: &str,
) -> Result<Option<&'a str>, AppError> {
    match value {
        None => Ok(None),
        Some(value) if allowed.contains(&value) => Ok(Some(value)),
        Some(_) => Err(AppError::BadRequest(format!(
            "unsupported operation {label}"
        ))),
    }
}

fn operation_filter_scope(
    status: Option<&str>,
    kind: Option<&str>,
) -> Result<super::cursor::CanonicalScope, super::cursor::CursorIssueError> {
    // CanonicalScope deliberately rejects caller-dependent field ordering.
    // Keep labels in bytewise order so every combination of optional filters
    // produces a valid, unambiguous cursor binding.
    super::cursor::CanonicalScope::new()
        .field("kind", kind.map(str::as_bytes))?
        .field("status", status.map(str::as_bytes))
}

#[cfg(test)]
mod read_tests {
    use super::*;
    use serde_json::json;

    fn operation_record() -> db::OperationRecord {
        let now = Utc::now();
        db::OperationRecord {
            id: Uuid::new_v4(),
            request_id: Uuid::new_v4(),
            idempotency_id: Some(Uuid::new_v4()),
            actor_id: Some(Uuid::new_v4()),
            actor_subject_id: Uuid::new_v4(),
            actor_auth_generation: 0,
            authorization_policy: db::AuthorizationPolicy::ReauthorizeUntilEffect,
            kind: "admin.broadcast".into(),
            target: Some("x".repeat(4096)),
            status: db::OperationStatus::Pending,
            payload_version: 1,
            payload: json!({"message": "sensitive operation input"}),
            result: Some(json!({"large": "sensitive operation result"})),
            error_code: None,
            attempts: 0,
            max_attempts: 20,
            next_attempt_at: now,
            deadline_at: now + chrono::Duration::hours(1),
            cancel_requested_at: None,
            point_of_no_return_at: None,
            created_at: now,
            completed_at: None,
        }
    }

    fn target_record() -> db::OperationTargetRecord {
        let now = Utc::now();
        db::OperationTargetRecord {
            id: Uuid::new_v4(),
            operation_id: Uuid::new_v4(),
            target_key: "x".repeat(4096),
            ordinal: 0,
            status: db::OperationStatus::Pending,
            payload: json!({"input": "must not appear in a collection"}),
            result: Some(json!({"output": "must not appear in a collection"})),
            error_code: None,
            attempts: 0,
            max_attempts: 20,
            next_attempt_at: now,
            deadline_at: now + chrono::Duration::hours(1),
            cancel_requested_at: None,
            point_of_no_return_at: None,
            created_at: now,
            completed_at: None,
        }
    }

    #[test]
    fn operation_filters_accept_only_exact_registered_labels() {
        for status in OPERATION_STATUSES {
            assert_eq!(
                validate_filter(Some(status), OPERATION_STATUSES, "status").unwrap(),
                Some(*status)
            );
        }
        for kind in PUBLIC_OPERATION_KINDS {
            assert_eq!(
                validate_filter(Some(kind), PUBLIC_OPERATION_KINDS, "kind").unwrap(),
                Some(*kind)
            );
        }
        for invalid in ["", "Running", " running", "running ", "unknown"] {
            assert!(matches!(
                validate_filter(Some(invalid), OPERATION_STATUSES, "status"),
                Err(AppError::BadRequest(_))
            ));
        }
        assert!(matches!(
            validate_filter(
                Some("admin.private_future_kind"),
                PUBLIC_OPERATION_KINDS,
                "kind"
            ),
            Err(AppError::BadRequest(_))
        ));

        for status in [None, Some("running")] {
            for kind in [None, Some("admin.session_kick")] {
                assert!(operation_filter_scope(status, kind).is_ok());
            }
        }
    }

    #[test]
    fn collection_summaries_omit_payload_and_result_and_have_a_safe_page_bound() {
        let operation = serde_json::to_value(OperationSummary::from(operation_record())).unwrap();
        assert!(operation.get("payload").is_none());
        assert!(operation.get("result").is_none());

        let target = serde_json::to_value(TargetSummary::from(target_record())).unwrap();
        assert!(target.get("payload").is_none());
        assert!(target.get("result").is_none());

        let page = Page {
            items: (0..MAX_SUMMARY_PAGE_ITEMS)
                .map(|_| TargetSummary::from(target_record()))
                .collect::<Vec<_>>(),
            next_cursor: Some("x".repeat(512)),
        };
        let encoded = serde_json::to_vec(&page).unwrap();
        assert!(encoded.len() < super::super::API_BODY_LIMIT_BYTES);
    }

    #[test]
    fn operation_detail_retains_payload_and_result() {
        let detail = serde_json::to_value(OperationView::from(operation_record())).unwrap();
        assert_eq!(detail["payload"]["message"], "sensitive operation input");
        assert_eq!(detail["result"]["large"], "sensitive operation result");

        let target = serde_json::to_value(TargetView::from(target_record())).unwrap();
        assert_eq!(
            target["payload"]["input"],
            "must not appear in a collection"
        );
        assert_eq!(
            target["result"]["output"],
            "must not appear in a collection"
        );
    }
}

pub async fn list_operations(
    State(state): State<Arc<AppState>>,
    actor: ApiAdmin,
    ApiQuery(query): ApiQuery<OperationListQuery>,
) -> Result<Json<Page<OperationSummary>>, AppError> {
    // Validate semantic filters before verifying a cursor or touching the
    // database. Unsupported values are client errors, never internal errors.
    let status = validate_filter(query.status.as_deref(), OPERATION_STATUSES, "status")?;
    let kind = validate_filter(query.kind.as_deref(), PUBLIC_OPERATION_KINDS, "kind")?;
    let limit = pagination::checked_limit(query.limit, 25, MAX_SUMMARY_PAGE_ITEMS)?;
    let filter =
        operation_filter_scope(status, kind).map_err(|error| AppError::Internal(error.into()))?;
    let principal = actor.id.as_bytes();
    let binding = pagination::pg_binding(OPERATIONS_ENDPOINT, principal, &filter);
    let boundary = pagination::pg_boundary(&state, query.cursor.as_deref(), &binding)
        .await?
        .map(|b| db::OperationPageBoundary {
            created_at: b.created_at,
            id: b.id,
        });
    let mut tx = state.pool.begin().await?;
    reauthorize(&mut tx, &actor).await?;
    let page = db::list_operations(&mut tx, status, kind, boundary, limit).await?;
    tx.commit().await?;
    let next = page.next.map(|b| db::PageBoundary {
        created_at: b.created_at,
        id: b.id,
    });
    let next_cursor = pagination::issue_pg_cursor(&state, &binding, next, page.database_now)?;
    Ok(Json(Page {
        items: page.items.into_iter().map(Into::into).collect(),
        next_cursor,
    }))
}

pub async fn get_operation(
    State(state): State<Arc<AppState>>,
    actor: ApiAdmin,
    ApiPath(id): ApiPath<Uuid>,
) -> Result<Json<OperationView>, AppError> {
    if id.is_nil() {
        return Err(AppError::BadRequest("operation id must not be nil".into()));
    }
    let mut tx = state.pool.begin().await?;
    reauthorize(&mut tx, &actor).await?;
    let item = db::operation_by_id(&mut tx, id)
        .await?
        .ok_or_else(|| AppError::NotFound("operation does not exist".into()))?;
    tx.commit().await?;
    Ok(Json(item.into()))
}

pub async fn list_targets(
    State(state): State<Arc<AppState>>,
    actor: ApiAdmin,
    ApiPath(id): ApiPath<Uuid>,
    ApiQuery(query): ApiQuery<TargetListQuery>,
) -> Result<Json<Page<TargetSummary>>, AppError> {
    if id.is_nil() {
        return Err(AppError::BadRequest("operation id must not be nil".into()));
    }
    let status = validate_filter(query.status.as_deref(), OPERATION_STATUSES, "target status")?;
    let limit = pagination::checked_limit(query.limit, 25, MAX_SUMMARY_PAGE_ITEMS)?;
    let filter = super::cursor::CanonicalScope::new()
        .field("operation_id", Some(id.as_bytes()))
        .and_then(|scope| scope.field("status", status.map(str::as_bytes)))
        .map_err(|e| AppError::Internal(e.into()))?;
    let binding = pagination::pg_binding(TARGETS_ENDPOINT, actor.id.as_bytes(), &filter);
    let boundary = pagination::pg_boundary(&state, query.cursor.as_deref(), &binding)
        .await?
        .map(|b| db::OperationPageBoundary {
            created_at: b.created_at,
            id: b.id,
        });
    let mut tx = state.pool.begin().await?;
    reauthorize(&mut tx, &actor).await?;
    if db::operation_by_id(&mut tx, id).await?.is_none() {
        return Err(AppError::NotFound("operation does not exist".into()));
    }
    let page = db::list_operation_targets(&mut tx, id, status, boundary, limit).await?;
    tx.commit().await?;
    let next = page.next.map(|b| db::PageBoundary {
        created_at: b.created_at,
        id: b.id,
    });
    let next_cursor = pagination::issue_pg_cursor(&state, &binding, next, page.database_now)?;
    Ok(Json(Page {
        items: page.items.into_iter().map(Into::into).collect(),
        next_cursor,
    }))
}

pub async fn get_target(
    State(state): State<Arc<AppState>>,
    actor: ApiAdmin,
    ApiPath((operation_id, target_id)): ApiPath<(Uuid, Uuid)>,
) -> Result<Json<TargetView>, AppError> {
    if operation_id.is_nil() || target_id.is_nil() {
        return Err(AppError::BadRequest(
            "operation target id must not be nil".into(),
        ));
    }
    let mut tx = state.pool.begin().await?;
    reauthorize(&mut tx, &actor).await?;
    let item = db::operation_target_by_id(&mut tx, target_id)
        .await?
        .filter(|target| target.operation_id == operation_id)
        .ok_or_else(|| AppError::NotFound("operation target does not exist".into()))?;
    tx.commit().await?;
    Ok(Json(item.into()))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReconcileRequest {
    succeeded: bool,
    result: Option<Value>,
    error_code: Option<String>,
    evidence_note: String,
}

pub async fn cancel_operation(
    State(state): State<Arc<AppState>>,
    actor: ApiAdmin,
    ApiPath(id): ApiPath<Uuid>,
    request: ApiEmpty,
) -> Result<Response, AppError> {
    if id.is_nil() {
        return Err(AppError::BadRequest("operation id must not be nil".into()));
    }
    let mut idempotency = request.idempotency(
        Some(actor.id),
        actor.id.as_bytes(),
        db::ApiPrincipalKind::Admin,
        "POST",
        "/api/v1/admin/operations/{id}/cancel",
    );
    idempotency.target_scope = id.as_bytes();
    let mut tx = state.pool.begin().await?;
    let lease = match acquire_admin_mutation_in_tx(&state, &mut tx, &actor, &idempotency).await? {
        AdminMutationAcquire::Acquired(lease) => lease,
        AdminMutationAcquire::Replay(replay) => {
            tx.commit().await?;
            return idempotency_replay_response(replay);
        }
        AdminMutationAcquire::Busy {
            retry_after_seconds,
        } => {
            tx.rollback().await?;
            return Err(AppError::IdempotencyBusy {
                retry_after: retry_after_seconds,
            });
        }
    };
    let outcome =
        db::request_operation_cancel_in_tx(&mut tx, id, actor.id, lease.request_id).await?;
    if outcome == db::CancelOutcome::NotFound {
        let response = complete_admin_response(
            &state,
            &mut tx,
            &lease,
            StatusCode::NOT_FOUND,
            json!({"error":{"code":"not_found","message":"operation does not exist"}}),
            None,
        )
        .await?;
        tx.commit().await?;
        return Ok(response);
    }
    if matches!(
        outcome,
        db::CancelOutcome::NotCancelable | db::CancelOutcome::PastPointOfNoReturn
    ) {
        let message = match outcome {
            db::CancelOutcome::NotCancelable => "operation does not support cancellation",
            db::CancelOutcome::PastPointOfNoReturn => "operation has passed its point of no return",
            _ => unreachable!("matched above"),
        };
        let response = complete_admin_response(
            &state,
            &mut tx,
            &lease,
            StatusCode::CONFLICT,
            json!({"error":{"code":"conflict","message":message}}),
            None,
        )
        .await?;
        tx.commit().await?;
        return Ok(response);
    }
    let outcome = match outcome {
        db::CancelOutcome::Requested => "requested",
        db::CancelOutcome::Canceled => "canceled",
        db::CancelOutcome::AlreadyTerminal => "already_terminal",
        db::CancelOutcome::NotCancelable | db::CancelOutcome::PastPointOfNoReturn => {
            unreachable!("handled above")
        }
        db::CancelOutcome::NotFound => unreachable!("handled above"),
    };
    let response = complete_admin_response(
        &state,
        &mut tx,
        &lease,
        StatusCode::OK,
        json!({"outcome":outcome}),
        None,
    )
    .await?;
    tx.commit().await?;
    Ok(response)
}

pub async fn reconcile_operation(
    State(state): State<Arc<AppState>>,
    actor: ApiAdmin,
    ApiPath(id): ApiPath<Uuid>,
    request: ApiJson<ReconcileRequest>,
) -> Result<Response, AppError> {
    if id.is_nil() {
        return Err(AppError::BadRequest("operation id must not be nil".into()));
    }
    let evidence_note = request.evidence_note.trim();
    db::validate_manual_reconciliation_content(
        request.succeeded,
        request.result.as_ref(),
        request.error_code.as_deref(),
        evidence_note,
    )
    .map_err(|_| AppError::BadRequest("invalid reconciliation data".into()))?;
    let mut idempotency = request.idempotency(
        Some(actor.id),
        actor.id.as_bytes(),
        db::ApiPrincipalKind::Admin,
        "POST",
        "/api/v1/admin/operations/{id}/reconcile",
    );
    idempotency.target_scope = id.as_bytes();
    let mut tx = state.pool.begin().await?;
    let lease = match acquire_admin_mutation_in_tx(&state, &mut tx, &actor, &idempotency).await? {
        AdminMutationAcquire::Acquired(lease) => lease,
        AdminMutationAcquire::Replay(replay) => {
            tx.commit().await?;
            return idempotency_replay_response(replay);
        }
        AdminMutationAcquire::Busy {
            retry_after_seconds,
        } => {
            tx.rollback().await?;
            return Err(AppError::IdempotencyBusy {
                retry_after: retry_after_seconds,
            });
        }
    };
    let input = db::ManualReconciliation {
        reconciled_by: actor.id,
        reconciler_auth_generation: actor.auth_generation,
        request_id: lease.request_id,
        succeeded: request.succeeded,
        result: request.result.as_ref(),
        error_code: request.error_code.as_deref(),
        evidence_note,
    };
    let outcome = db::reconcile_indeterminate_operation_in_tx(&mut tx, id, &input).await?;
    if outcome == db::ManualReconcileOutcome::NotFound {
        let response = complete_admin_response(
            &state,
            &mut tx,
            &lease,
            StatusCode::NOT_FOUND,
            json!({"error":{"code":"not_found","message":"operation does not exist"}}),
            None,
        )
        .await?;
        tx.commit().await?;
        return Ok(response);
    }
    let reconciliation_conflict = match outcome {
        db::ManualReconcileOutcome::NotIndeterminate => Some("operation is not indeterminate"),
        db::ManualReconcileOutcome::IndeterminateTargetsRemain => {
            Some("indeterminate operation targets must be reconciled first")
        }
        db::ManualReconcileOutcome::TargetsPreventSuccess => {
            Some("operation cannot be marked succeeded because a target did not succeed")
        }
        _ => None,
    };
    if let Some(message) = reconciliation_conflict {
        let response = complete_admin_response(
            &state,
            &mut tx,
            &lease,
            StatusCode::CONFLICT,
            json!({"error":{"code":"conflict","message":message}}),
            None,
        )
        .await?;
        tx.commit().await?;
        return Ok(response);
    }
    let outcome = match outcome {
        db::ManualReconcileOutcome::Succeeded => "succeeded",
        db::ManualReconcileOutcome::Failed => "failed",
        db::ManualReconcileOutcome::NotIndeterminate
        | db::ManualReconcileOutcome::IndeterminateTargetsRemain
        | db::ManualReconcileOutcome::TargetsPreventSuccess => unreachable!("handled above"),
        db::ManualReconcileOutcome::NotFound => unreachable!("handled above"),
    };
    let response = complete_admin_response(
        &state,
        &mut tx,
        &lease,
        StatusCode::OK,
        json!({"outcome":outcome}),
        None,
    )
    .await?;
    tx.commit().await?;
    Ok(response)
}

pub async fn reconcile_target(
    State(state): State<Arc<AppState>>,
    actor: ApiAdmin,
    ApiPath((operation_id, target_id)): ApiPath<(Uuid, Uuid)>,
    request: ApiJson<ReconcileRequest>,
) -> Result<Response, AppError> {
    if operation_id.is_nil() || target_id.is_nil() {
        return Err(AppError::BadRequest(
            "operation target id must not be nil".into(),
        ));
    }
    let evidence_note = request.evidence_note.trim();
    db::validate_manual_reconciliation_content(
        request.succeeded,
        request.result.as_ref(),
        request.error_code.as_deref(),
        evidence_note,
    )
    .map_err(|_| AppError::BadRequest("invalid reconciliation data".into()))?;
    let mut target_scope = [0_u8; 32];
    target_scope[..16].copy_from_slice(operation_id.as_bytes());
    target_scope[16..].copy_from_slice(target_id.as_bytes());
    let mut idempotency = request.idempotency(
        Some(actor.id),
        actor.id.as_bytes(),
        db::ApiPrincipalKind::Admin,
        "POST",
        "/api/v1/admin/operations/{operation_id}/targets/{target_id}/reconcile",
    );
    idempotency.target_scope = &target_scope;
    let mut tx = state.pool.begin().await?;
    let lease = match acquire_admin_mutation_in_tx(&state, &mut tx, &actor, &idempotency).await? {
        AdminMutationAcquire::Acquired(lease) => lease,
        AdminMutationAcquire::Replay(replay) => {
            tx.commit().await?;
            return idempotency_replay_response(replay);
        }
        AdminMutationAcquire::Busy {
            retry_after_seconds,
        } => {
            tx.rollback().await?;
            return Err(AppError::IdempotencyBusy {
                retry_after: retry_after_seconds,
            });
        }
    };
    if db::operation_target_by_id(&mut tx, target_id)
        .await?
        .is_none_or(|target| target.operation_id != operation_id)
    {
        let response = complete_admin_response(
            &state,
            &mut tx,
            &lease,
            StatusCode::NOT_FOUND,
            json!({"error":{"code":"not_found","message":"operation target does not exist"}}),
            None,
        )
        .await?;
        tx.commit().await?;
        return Ok(response);
    }
    let input = db::ManualReconciliation {
        reconciled_by: actor.id,
        reconciler_auth_generation: actor.auth_generation,
        request_id: lease.request_id,
        succeeded: request.succeeded,
        result: request.result.as_ref(),
        error_code: request.error_code.as_deref(),
        evidence_note,
    };
    let outcome = db::reconcile_indeterminate_target_in_tx(&mut tx, target_id, &input).await?;
    if outcome == db::ManualReconcileOutcome::NotFound {
        let response = complete_admin_response(
            &state,
            &mut tx,
            &lease,
            StatusCode::NOT_FOUND,
            json!({"error":{"code":"not_found","message":"operation target does not exist"}}),
            None,
        )
        .await?;
        tx.commit().await?;
        return Ok(response);
    }
    if outcome == db::ManualReconcileOutcome::NotIndeterminate {
        let response = complete_admin_response(
            &state,
            &mut tx,
            &lease,
            StatusCode::CONFLICT,
            json!({"error":{"code":"conflict","message":"operation target is not indeterminate"}}),
            None,
        )
        .await?;
        tx.commit().await?;
        return Ok(response);
    }
    let outcome = match outcome {
        db::ManualReconcileOutcome::Succeeded => "succeeded",
        db::ManualReconcileOutcome::Failed => "failed",
        db::ManualReconcileOutcome::NotIndeterminate
        | db::ManualReconcileOutcome::IndeterminateTargetsRemain
        | db::ManualReconcileOutcome::TargetsPreventSuccess => {
            unreachable!("target reconciliation cannot return a parent-target conflict")
        }
        db::ManualReconcileOutcome::NotFound => unreachable!("handled above"),
    };
    let response = complete_admin_response(
        &state,
        &mut tx,
        &lease,
        StatusCode::OK,
        json!({"outcome":outcome}),
        None,
    )
    .await?;
    tx.commit().await?;
    Ok(response)
}
