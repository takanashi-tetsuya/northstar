use crate::api::cursor::{
    CanonicalScope, CursorBinding, CursorDirection, CursorPosition, CursorValue,
};
use crate::api::*;
use crate::db;
use crate::error::AppError;
use crate::state::AppState;
use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use axum::Json;
use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fmt::Write as _;
use std::sync::{atomic::Ordering, Arc};
use uuid::Uuid;

const GOVERNANCE_EXPORT_REPLAY_MAX_BYTES: usize = 1024 * 1024;
const LEGAL_HOLD_EXPORT_ENDPOINT: &str = "admin/legal-holds/export-v2";
const LEGAL_HOLD_EXPORT_SORT: &str = "resource.created_at.id.asc";
const AUDIT_EXPORT_ENDPOINT: &str = "admin/audit/export-v2";
const AUDIT_EXPORT_SORT: &str = "id.asc.snapshot";

fn require_explicit_idempotency_key(headers: &HeaderMap) -> Result<&str, AppError> {
    let mut values = headers.get_all("idempotency-key").iter();
    let Some(value) = values.next() else {
        return Err(AppError::BadRequest(
            "Idempotency-Key is required for data-governance writes and exports".into(),
        ));
    };
    if values.next().is_some() {
        return Err(AppError::BadRequest(
            "exactly one Idempotency-Key header is allowed".into(),
        ));
    }
    let value = value
        .to_str()
        .map_err(|_| AppError::BadRequest("Idempotency-Key is invalid".into()))?;
    if !(8..=200).contains(&value.len()) || !value.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
    {
        return Err(AppError::BadRequest(
            "Idempotency-Key must contain 8 to 200 visible ASCII bytes".into(),
        ));
    }
    Ok(value)
}

fn access_key_sha256(key: &str) -> String {
    let mut output = String::with_capacity(64);
    for byte in Sha256::digest(key.as_bytes()) {
        let _ = write!(output, "{byte:02x}");
    }
    output
}

fn retention_error(error: db::RetentionPolicyError) -> AppError {
    match error {
        db::RetentionPolicyError::Forbidden => AppError::Forbidden,
        db::RetentionPolicyError::NotFound => AppError::NotFound(error.to_string()),
        db::RetentionPolicyError::Internal(error) => AppError::Internal(error),
    }
}

fn hold_error(error: db::LegalHoldError) -> AppError {
    match error {
        db::LegalHoldError::Forbidden => AppError::Forbidden,
        db::LegalHoldError::NotFound => AppError::NotFound(error.to_string()),
        db::LegalHoldError::Conflict => AppError::Conflict(error.to_string()),
        db::LegalHoldError::InvalidCursor => AppError::InvalidCursor,
        db::LegalHoldError::Invalid => AppError::BadRequest(error.to_string()),
        db::LegalHoldError::Internal(error) => AppError::from_internal(error),
    }
}

fn legal_hold_export_filter(hold_id: Uuid) -> Result<CanonicalScope, AppError> {
    CanonicalScope::new()
        .field("hold_id", Some(hold_id.as_bytes()))
        .map_err(|error| AppError::Internal(error.into()))
}

fn audit_export_filter(
    start: Option<chrono::DateTime<chrono::Utc>>,
    end: Option<chrono::DateTime<chrono::Utc>>,
) -> Result<CanonicalScope, AppError> {
    let start = start.map(|value| value.timestamp_micros().to_string());
    let end = end.map(|value| value.timestamp_micros().to_string());
    CanonicalScope::new()
        .field("end", end.as_deref().map(str::as_bytes))
        .and_then(|scope| scope.field("start", start.as_deref().map(str::as_bytes)))
        .map_err(|error| AppError::Internal(error.into()))
}

fn governance_binding<'a>(
    endpoint: &'a str,
    sort: &'a str,
    actor_id: &'a Uuid,
    filter: &'a CanonicalScope,
) -> CursorBinding<'a> {
    CursorBinding {
        endpoint,
        principal_scope: actor_id.as_bytes(),
        filter_scope: filter.as_bytes(),
        sort,
        direction: CursorDirection::Forward,
        // Governance snapshots live in PostgreSQL and are portable across
        // nodes/restarts as long as the cursor HMAC key remains deployed.
        node_incarnation: Uuid::nil(),
    }
}

async fn verify_governance_cursor(
    state: &AppState,
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    token: &str,
    binding: &CursorBinding<'_>,
) -> Result<CursorPosition, AppError> {
    // The caller already owns a pool connection through this transaction.
    // Reuse it so N concurrent exports cannot each hold one connection while
    // all wait for a second connection from an exhausted pool.
    let database_now = db::database_cursor_clock_in_tx(tx).await?;
    state
        .api_cursor()
        .verify(token, binding, database_now.timestamp())
        .map_err(|_| {
            state
                .metrics
                .governance_export_cursor_rejections_total
                .fetch_add(1, Ordering::Relaxed);
            AppError::InvalidCursor
        })
}

fn decode_legal_hold_cursor(
    position: CursorPosition,
) -> Result<db::LegalHoldExportCursor, AppError> {
    match position.last.as_slice() {
        [CursorValue::Uuid(export_id), CursorValue::U64(resource_order), CursorValue::TimestampMicros(created_at), CursorValue::Uuid(record_id), CursorValue::TimestampMicros(snapshot_at), CursorValue::Digest32(chain_root)]
            if !export_id.is_nil() && !record_id.is_nil() && (1..=4).contains(resource_order) =>
        {
            Ok(db::LegalHoldExportCursor {
                export_id: *export_id,
                after_resource_order: i64::try_from(*resource_order)
                    .map_err(|_| AppError::InvalidCursor)?,
                after_created_at: chrono::DateTime::from_timestamp_micros(*created_at)
                    .ok_or(AppError::InvalidCursor)?,
                after_record_id: *record_id,
                snapshot_at: chrono::DateTime::from_timestamp_micros(*snapshot_at)
                    .ok_or(AppError::InvalidCursor)?,
                chain_root: *chain_root,
            })
        }
        _ => Err(AppError::InvalidCursor),
    }
}

fn decode_audit_cursor(position: CursorPosition) -> Result<db::AuditExportCursor, AppError> {
    match position.last.as_slice() {
        [CursorValue::Uuid(export_id), CursorValue::I64(after_id), CursorValue::I64(snapshot_max_id), CursorValue::TimestampMicros(snapshot_at), CursorValue::Digest32(chain_root)]
            if !export_id.is_nil() && *after_id >= 0 && *snapshot_max_id >= *after_id =>
        {
            Ok(db::AuditExportCursor {
                export_id: *export_id,
                after_id: *after_id,
                snapshot_max_id: *snapshot_max_id,
                snapshot_at: chrono::DateTime::from_timestamp_micros(*snapshot_at)
                    .ok_or(AppError::InvalidCursor)?,
                chain_root: *chain_root,
            })
        }
        _ => Err(AppError::InvalidCursor),
    }
}

fn export_cursor_ttl_seconds(
    exported_at: chrono::DateTime<chrono::Utc>,
    expires_at: chrono::DateTime<chrono::Utc>,
) -> Result<i64, AppError> {
    let remaining = expires_at
        .timestamp()
        .saturating_sub(exported_at.timestamp());
    if !(30..=db::GOVERNANCE_EXPORT_LEASE_SECONDS).contains(&remaining) {
        return Err(AppError::InvalidCursor);
    }
    Ok(remaining)
}

fn issue_legal_hold_cursor(
    state: &AppState,
    binding: &CursorBinding<'_>,
    export: &db::LegalHoldExport,
) -> Result<Option<String>, AppError> {
    let Some(next) = export.next.as_ref() else {
        return Ok(None);
    };
    let expires_at = export.lease_expires_at.ok_or_else(|| {
        AppError::Internal(anyhow::anyhow!(
            "legal-hold continuation has no export lease"
        ))
    })?;
    let ttl = export_cursor_ttl_seconds(export.exported_at, expires_at)?;
    state
        .api_cursor()
        .issue(
            binding,
            &CursorPosition {
                last: vec![
                    CursorValue::Uuid(next.export_id),
                    CursorValue::U64(
                        u64::try_from(next.after_resource_order)
                            .map_err(|_| AppError::InvalidCursor)?,
                    ),
                    CursorValue::TimestampMicros(next.after_created_at.timestamp_micros()),
                    CursorValue::Uuid(next.after_record_id),
                    CursorValue::TimestampMicros(next.snapshot_at.timestamp_micros()),
                    CursorValue::Digest32(next.chain_root),
                ],
            },
            export.exported_at.timestamp(),
            ttl,
        )
        .map(Some)
        .map_err(|error| AppError::Internal(error.into()))
}

fn issue_audit_cursor(
    state: &AppState,
    binding: &CursorBinding<'_>,
    export: &db::AuditExport,
) -> Result<Option<String>, AppError> {
    let Some(next) = export.next.as_ref() else {
        return Ok(None);
    };
    let ttl = export_cursor_ttl_seconds(export.exported_at, export.lease_expires_at)?;
    state
        .api_cursor()
        .issue(
            binding,
            &CursorPosition {
                last: vec![
                    CursorValue::Uuid(next.export_id),
                    CursorValue::I64(next.after_id),
                    CursorValue::I64(next.snapshot_max_id),
                    CursorValue::TimestampMicros(next.snapshot_at.timestamp_micros()),
                    CursorValue::Digest32(next.chain_root),
                ],
            },
            export.exported_at.timestamp(),
            ttl,
        )
        .map(Some)
        .map_err(|error| AppError::Internal(error.into()))
}

fn with_next_cursor<T: Serialize>(
    export: &T,
    next_cursor: Option<String>,
) -> Result<Value, AppError> {
    let mut value =
        serde_json::to_value(export).map_err(|error| AppError::Internal(error.into()))?;
    value
        .as_object_mut()
        .ok_or_else(|| AppError::Internal(anyhow::anyhow!("export response is not an object")))?
        .insert("next_cursor".into(), json!(next_cursor));
    Ok(value)
}

fn user_limits(state: &AppState) -> db::RetentionPolicyLimits {
    db::RetentionPolicyLimits {
        personal_mam_days: state.config.mam_retention_days,
        offline_message_days: state.config.offline_message_ttl_days,
        moderation_evidence_days: state.config.moderation_retention_days,
    }
}

async fn acquire_user_mutation(
    state: &AppState,
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    request: &db::IdempotencyRequest<'_>,
) -> Result<db::IdempotencyAcquire, AppError> {
    Ok(db::acquire_idempotency_in_tx(state.api_control(), tx, request).await?)
}

async fn complete_user_response(
    state: &AppState,
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    lease: &db::IdempotencyLease,
    status: StatusCode,
    body: Value,
) -> Result<Response, AppError> {
    let headers = json_replay_headers();
    let bytes = serde_json::to_vec(&body).map_err(|error| AppError::Internal(error.into()))?;
    if !db::complete_idempotency_in_tx(
        state.api_control(),
        tx,
        lease,
        status.as_u16(),
        &headers,
        &bytes,
    )
    .await?
    {
        return Err(AppError::Internal(anyhow::anyhow!(
            "data-policy idempotency lease changed"
        )));
    }
    let mut response = Response::builder().status(status);
    for (name, value) in headers {
        response = response.header(name, value);
    }
    response
        .body(Body::from(bytes))
        .map_err(|error| AppError::Internal(error.into()))
}

fn ensure_governance_export_size(bytes: &[u8]) -> Result<(), AppError> {
    if bytes.len() > GOVERNANCE_EXPORT_REPLAY_MAX_BYTES {
        return Err(AppError::BadRequest(
            "governance export exceeds the 1 MiB idempotent replay bound; reduce max_rows".into(),
        ));
    }
    Ok(())
}

fn governance_export_rows(
    requested: Option<i64>,
    default: i64,
    maximum: i64,
) -> Result<i64, AppError> {
    let rows = requested.unwrap_or(default);
    if !(1..=maximum).contains(&rows) {
        return Err(AppError::BadRequest(format!(
            "max_rows must be between 1 and {maximum}"
        )));
    }
    Ok(rows)
}

async fn complete_governance_export<T: Serialize>(
    state: &AppState,
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    lease: &db::IdempotencyLease,
    export: &T,
) -> Result<Response, AppError> {
    let bytes = serde_json::to_vec(export).map_err(|error| AppError::Internal(error.into()))?;
    ensure_governance_export_size(&bytes)?;
    let headers = json_replay_headers();
    if !db::complete_idempotency_in_tx(
        state.api_control(),
        tx,
        lease,
        StatusCode::OK.as_u16(),
        &headers,
        &bytes,
    )
    .await?
    {
        return Err(AppError::Internal(anyhow::anyhow!(
            "governance-export idempotency lease changed"
        )));
    }
    let mut response = Response::builder().status(StatusCode::OK);
    for (name, value) in headers {
        response = response.header(name, value);
    }
    response
        .body(Body::from(bytes))
        .map_err(|error| AppError::Internal(error.into()))
}

pub async fn get_my_retention(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<Value>, AppError> {
    let user = current_user(&state, &headers).await?;
    let policy = db::user_retention_policy(&state.pool, user.id).await?;
    Ok(Json(json!({
        "policy":policy,
        "operator_limits":{
            "personal_mam_days":state.config.mam_retention_days,
            "offline_message_days":state.config.offline_message_ttl_days,
            "moderation_evidence_days":state.config.moderation_retention_days
        },
        "zero_operator_limit_means":"inherited_cleanup_disabled; an explicit shorter user policy remains effective"
    })))
}

pub async fn update_my_retention(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    request: ApiJson<UserRetentionPolicyRequest>,
) -> Result<Response, AppError> {
    require_explicit_idempotency_key(&headers)?;
    let token = zeroize::Zeroizing::new(bearer_token(&headers)?.to_owned());
    let idempotency = request.idempotency(
        None,
        token.as_bytes(),
        db::ApiPrincipalKind::User,
        "PUT",
        "/api/v1/me/retention",
    );
    let mut tx = state.pool.begin().await?;
    let user = db::user_for_token_in_tx(&mut tx, &token)
        .await?
        .ok_or(AppError::Unauthorized)?;
    let lease = match acquire_user_mutation(&state, &mut tx, &idempotency).await? {
        db::IdempotencyAcquire::Acquired(lease) => lease,
        db::IdempotencyAcquire::Replay(replay) => {
            tx.commit().await?;
            return idempotency_replay_response(replay);
        }
        db::IdempotencyAcquire::FingerprintConflict | db::IdempotencyAcquire::RotationConflict => {
            return Err(AppError::IdempotencyConflict);
        }
        db::IdempotencyAcquire::ReplayInvalidated => {
            return Err(AppError::IdempotencyReplayInvalidated);
        }
        db::IdempotencyAcquire::Busy {
            retry_after_seconds,
        } => {
            tx.rollback().await?;
            return Err(AppError::IdempotencyBusy {
                retry_after: retry_after_seconds,
            });
        }
        db::IdempotencyAcquire::CapacityLimited {
            retry_after_seconds,
        } => {
            return Err(AppError::TooManyRequests {
                message: "too many retained requests; try again later".into(),
                retry_after: retry_after_seconds,
            });
        }
        db::IdempotencyAcquire::InProgress {
            retry_after_seconds,
        } => {
            return Err(AppError::IdempotencyInProgress {
                retry_after: retry_after_seconds,
            });
        }
    };
    let policy = db::UserRetentionPolicy {
        personal_mam_days: request.personal_mam_days,
        offline_message_days: request.offline_message_days,
        moderation_evidence_days: request.moderation_evidence_days,
    };
    db::set_user_retention_policy_in_tx(
        &mut tx,
        user.id,
        user.id,
        policy,
        user_limits(&state),
        lease.request_id,
    )
    .await
    .map_err(retention_error)?;
    let response = complete_user_response(
        &state,
        &mut tx,
        &lease,
        StatusCode::OK,
        json!({"policy":policy}),
    )
    .await?;
    tx.commit().await?;
    Ok(response)
}

pub async fn get_muc_retention(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    ApiPath(room_id): ApiPath<Uuid>,
) -> Result<Json<Value>, AppError> {
    let user = current_user(&state, &headers).await?;
    let policy = db::muc_retention_policy_authorized(&state.pool, user.id, room_id)
        .await
        .map_err(retention_error)?;
    Ok(Json(json!({
        "room_id":room_id,
        "retention_days":policy,
        "operator_limit_days":state.config.muc_mam_retention_days
    })))
}

pub async fn update_muc_retention(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    ApiPath(room_id): ApiPath<Uuid>,
    request: ApiJson<MucRetentionPolicyRequest>,
) -> Result<Response, AppError> {
    require_explicit_idempotency_key(&headers)?;
    let token = zeroize::Zeroizing::new(bearer_token(&headers)?.to_owned());
    let mut idempotency = request.idempotency(
        None,
        token.as_bytes(),
        db::ApiPrincipalKind::User,
        "PUT",
        "/api/v1/muc_rooms/{id}/retention",
    );
    idempotency.target_scope = room_id.as_bytes();
    let mut tx = state.pool.begin().await?;
    let user = db::user_for_token_in_tx(&mut tx, &token)
        .await?
        .ok_or(AppError::Unauthorized)?;
    let lease = match acquire_user_mutation(&state, &mut tx, &idempotency).await? {
        db::IdempotencyAcquire::Acquired(lease) => lease,
        db::IdempotencyAcquire::Replay(replay) => {
            tx.commit().await?;
            return idempotency_replay_response(replay);
        }
        db::IdempotencyAcquire::FingerprintConflict | db::IdempotencyAcquire::RotationConflict => {
            return Err(AppError::IdempotencyConflict);
        }
        db::IdempotencyAcquire::ReplayInvalidated => {
            return Err(AppError::IdempotencyReplayInvalidated);
        }
        db::IdempotencyAcquire::Busy {
            retry_after_seconds,
        } => {
            tx.rollback().await?;
            return Err(AppError::IdempotencyBusy {
                retry_after: retry_after_seconds,
            });
        }
        db::IdempotencyAcquire::CapacityLimited {
            retry_after_seconds,
        } => {
            return Err(AppError::TooManyRequests {
                message: "too many retained requests; try again later".into(),
                retry_after: retry_after_seconds,
            });
        }
        db::IdempotencyAcquire::InProgress {
            retry_after_seconds,
        } => {
            return Err(AppError::IdempotencyInProgress {
                retry_after: retry_after_seconds,
            });
        }
    };
    db::set_muc_retention_policy_in_tx(
        &mut tx,
        user.id,
        room_id,
        request.retention_days,
        state.config.muc_mam_retention_days,
        lease.request_id,
    )
    .await
    .map_err(retention_error)?;
    let response = complete_user_response(
        &state,
        &mut tx,
        &lease,
        StatusCode::OK,
        json!({"room_id":room_id,"retention_days":request.retention_days}),
    )
    .await?;
    tx.commit().await?;
    Ok(response)
}

fn parse_hold_targets(
    targets: &[LegalHoldTargetRequest],
) -> Result<Vec<db::LegalHoldTarget>, AppError> {
    targets
        .iter()
        .map(|target| {
            Ok(match target.kind.as_str() {
                "personal_archive" => db::LegalHoldTarget::PersonalArchive(target.id),
                "muc_archive" => db::LegalHoldTarget::MucArchive(target.id),
                "offline_message" => db::LegalHoldTarget::OfflineMessage(target.id),
                "report_evidence" => db::LegalHoldTarget::ReportEvidence(target.id),
                "personal_archive_owner" => db::LegalHoldTarget::PersonalArchiveOwner(target.id),
                "muc_archive_room" => db::LegalHoldTarget::MucArchiveRoom(target.id),
                "offline_message_recipient" => {
                    db::LegalHoldTarget::OfflineMessageRecipient(target.id)
                }
                "report_evidence_report" => db::LegalHoldTarget::ReportEvidenceReport(target.id),
                _ => {
                    return Err(AppError::BadRequest(
                        "unknown legal-hold target kind".into(),
                    ));
                }
            })
        })
        .collect()
}

pub async fn list_legal_holds(
    State(state): State<Arc<AppState>>,
    actor: ApiAdmin,
    headers: HeaderMap,
    ApiQuery(query): ApiQuery<LegalHoldPageQuery>,
) -> Result<Json<Value>, AppError> {
    let access_key = require_explicit_idempotency_key(&headers)?;
    let limit = pagination::checked_limit(query.limit, 100, 100)?;
    let holds = db::list_legal_holds_audited(
        &state.pool,
        actor.id,
        actor.auth_generation,
        actor.session_token(),
        query.active_only.unwrap_or(false),
        limit,
        &access_key_sha256(access_key),
    )
    .await
    .map_err(hold_error)?;
    state
        .metrics
        .legal_hold_operations_total
        .fetch_add(1, Ordering::Relaxed);
    Ok(Json(json!({"legal_holds":holds})))
}

pub async fn create_legal_hold(
    State(state): State<Arc<AppState>>,
    actor: ApiAdmin,
    headers: HeaderMap,
    request: ApiJson<LegalHoldCreateRequest>,
) -> Result<Response, AppError> {
    require_explicit_idempotency_key(&headers)?;
    let targets = parse_hold_targets(&request.targets)?;
    let mut idempotency = request.idempotency(
        Some(actor.id),
        actor.id.as_bytes(),
        db::ApiPrincipalKind::Admin,
        "POST",
        "/api/v1/admin/legal-holds",
    );
    idempotency.target_scope = b"legal-hold:create";
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
    let id = Uuid::new_v4();
    let input = db::CreateLegalHold {
        id,
        title: &request.title,
        authority_reference: &request.authority_reference,
        reason: &request.reason,
        targets: &targets,
        request_id: lease.request_id,
    };
    if let Err(error) = db::create_legal_hold_in_tx(&mut tx, actor.id, &input).await {
        state
            .metrics
            .legal_hold_operation_failures_total
            .fetch_add(1, Ordering::Relaxed);
        return Err(hold_error(error));
    }
    let response = complete_admin_response(
        &state,
        &mut tx,
        &lease,
        StatusCode::CREATED,
        json!({"id":id,"active":true,"target_count":targets.len()}),
        None,
    )
    .await?;
    tx.commit().await?;
    state
        .metrics
        .legal_hold_operations_total
        .fetch_add(1, Ordering::Relaxed);
    Ok(response)
}

pub async fn release_legal_hold(
    State(state): State<Arc<AppState>>,
    actor: ApiAdmin,
    headers: HeaderMap,
    ApiPath(id): ApiPath<Uuid>,
    request: ApiJson<LegalHoldReleaseRequest>,
) -> Result<Response, AppError> {
    require_explicit_idempotency_key(&headers)?;
    let mut idempotency = request.idempotency(
        Some(actor.id),
        actor.id.as_bytes(),
        db::ApiPrincipalKind::Admin,
        "POST",
        "/api/v1/admin/legal-holds/{id}/release",
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
    if let Err(error) =
        db::release_legal_hold_in_tx(&mut tx, actor.id, id, &request.reason, lease.request_id).await
    {
        state
            .metrics
            .legal_hold_operation_failures_total
            .fetch_add(1, Ordering::Relaxed);
        return Err(hold_error(error));
    }
    let response = complete_admin_response(
        &state,
        &mut tx,
        &lease,
        StatusCode::OK,
        json!({"id":id,"active":false}),
        None,
    )
    .await?;
    tx.commit().await?;
    state
        .metrics
        .legal_hold_operations_total
        .fetch_add(1, Ordering::Relaxed);
    Ok(response)
}

pub async fn export_legal_hold(
    State(state): State<Arc<AppState>>,
    actor: ApiAdmin,
    headers: HeaderMap,
    ApiPath(id): ApiPath<Uuid>,
    request: ApiJson<GovernanceExportRequest>,
) -> Result<Response, AppError> {
    require_explicit_idempotency_key(&headers)?;
    if request.start.is_some() || request.end.is_some() {
        return Err(AppError::BadRequest(
            "legal-hold export does not accept start/end filters".into(),
        ));
    }
    let max_rows = governance_export_rows(request.max_rows, 100, 100)?;
    let filter = legal_hold_export_filter(id)?;
    let binding = governance_binding(
        LEGAL_HOLD_EXPORT_ENDPOINT,
        LEGAL_HOLD_EXPORT_SORT,
        &actor.id,
        &filter,
    );
    let mut idempotency = request.idempotency(
        Some(actor.id),
        actor.id.as_bytes(),
        db::ApiPrincipalKind::Admin,
        "POST",
        "/api/v1/admin/legal-holds/{id}/export",
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
    // Exact idempotency replay wins even after a cursor expires. A new
    // request/key must still pass current cursor and database-lease checks.
    let continuation = match request.cursor.as_deref() {
        Some(token) => Some(decode_legal_hold_cursor(
            verify_governance_cursor(&state, &mut tx, token, &binding).await?,
        )?),
        None => None,
    };
    let export = match db::export_legal_hold_page_in_tx(
        &mut tx,
        actor.id,
        id,
        max_rows,
        Uuid::new_v4(),
        continuation,
        lease.request_id,
    )
    .await
    {
        Ok(export) => export,
        Err(error) => {
            if matches!(&error, db::LegalHoldError::InvalidCursor) {
                state
                    .metrics
                    .governance_export_cursor_rejections_total
                    .fetch_add(1, Ordering::Relaxed);
            }
            state
                .metrics
                .legal_hold_operation_failures_total
                .fetch_add(1, Ordering::Relaxed);
            return Err(hold_error(error));
        }
    };
    let next_cursor = issue_legal_hold_cursor(&state, &binding, &export)?;
    let export_response = with_next_cursor(&export, next_cursor)?;
    let response = match complete_governance_export(&state, &mut tx, &lease, &export_response).await
    {
        Ok(response) => response,
        Err(error) => {
            state
                .metrics
                .legal_hold_operation_failures_total
                .fetch_add(1, Ordering::Relaxed);
            return Err(error);
        }
    };
    tx.commit().await?;
    state
        .metrics
        .legal_hold_operations_total
        .fetch_add(1, Ordering::Relaxed);
    Ok(response)
}

pub async fn export_audit(
    State(state): State<Arc<AppState>>,
    actor: ApiAdmin,
    headers: HeaderMap,
    request: ApiJson<GovernanceExportRequest>,
) -> Result<Response, AppError> {
    require_explicit_idempotency_key(&headers)?;
    if request
        .start
        .as_ref()
        .zip(request.end.as_ref())
        .is_some_and(|(start, end)| start >= end)
    {
        return Err(AppError::BadRequest(
            "audit export start must precede end".into(),
        ));
    }
    let max_rows = governance_export_rows(request.max_rows, 500, 500)?;
    let filter = audit_export_filter(request.start, request.end)?;
    let binding = governance_binding(AUDIT_EXPORT_ENDPOINT, AUDIT_EXPORT_SORT, &actor.id, &filter);
    let mut idempotency = request.idempotency(
        Some(actor.id),
        actor.id.as_bytes(),
        db::ApiPrincipalKind::Admin,
        "POST",
        "/api/v1/admin/audit/export",
    );
    idempotency.target_scope = b"audit:export";
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
    let continuation = match request.cursor.as_deref() {
        Some(token) => Some(decode_audit_cursor(
            verify_governance_cursor(&state, &mut tx, token, &binding).await?,
        )?),
        None => None,
    };
    let export = match db::export_audit_log_page_in_tx(
        &mut tx,
        db::AuditExportPageRequest {
            actor_id: actor.id,
            start: request.start,
            end: request.end,
            max_rows,
            initial_export_id: Uuid::new_v4(),
            continuation,
            access_request_id: lease.request_id,
        },
    )
    .await
    {
        Ok(export) => export,
        Err(error) => {
            if matches!(&error, db::LegalHoldError::InvalidCursor) {
                state
                    .metrics
                    .governance_export_cursor_rejections_total
                    .fetch_add(1, Ordering::Relaxed);
            }
            state
                .metrics
                .audit_export_operation_failures_total
                .fetch_add(1, Ordering::Relaxed);
            return Err(hold_error(error));
        }
    };
    let next_cursor = issue_audit_cursor(&state, &binding, &export)?;
    let export_response = with_next_cursor(&export, next_cursor)?;
    let response = match complete_governance_export(&state, &mut tx, &lease, &export_response).await
    {
        Ok(response) => response,
        Err(error) => {
            state
                .metrics
                .audit_export_operation_failures_total
                .fetch_add(1, Ordering::Relaxed);
            return Err(error);
        }
    };
    tx.commit().await?;
    state
        .metrics
        .audit_export_operations_total
        .fetch_add(1, Ordering::Relaxed);
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_kinds_are_closed_and_typed() {
        let id = Uuid::nil();
        let parsed = parse_hold_targets(&[LegalHoldTargetRequest {
            kind: "muc_archive_room".into(),
            id,
        }])
        .unwrap();
        assert_eq!(parsed, vec![db::LegalHoldTarget::MucArchiveRoom(id)]);
        assert!(parse_hold_targets(&[LegalHoldTargetRequest {
            kind: "arbitrary_table".into(),
            id,
        }])
        .is_err());
    }

    #[test]
    fn governance_export_never_silently_exceeds_replay_storage() {
        assert!(
            ensure_governance_export_size(&vec![0; GOVERNANCE_EXPORT_REPLAY_MAX_BYTES]).is_ok()
        );
        let error = ensure_governance_export_size(&vec![0; GOVERNANCE_EXPORT_REPLAY_MAX_BYTES + 1])
            .unwrap_err();
        assert!(matches!(error, AppError::BadRequest(_)));
        assert!(error.to_string().contains("reduce max_rows"));
    }

    #[test]
    fn governance_row_limits_reject_instead_of_silently_clamping() {
        assert_eq!(governance_export_rows(None, 100, 100).unwrap(), 100);
        assert_eq!(governance_export_rows(Some(1), 100, 100).unwrap(), 1);
        assert!(governance_export_rows(Some(0), 100, 100).is_err());
        assert!(governance_export_rows(Some(101), 100, 100).is_err());
    }

    #[test]
    fn governance_mutations_require_one_explicit_idempotency_key() {
        let mut headers = HeaderMap::new();
        assert!(require_explicit_idempotency_key(&headers).is_err());
        headers.insert(
            "idempotency-key",
            "governance-test-key-0001".parse().unwrap(),
        );
        assert_eq!(
            require_explicit_idempotency_key(&headers).unwrap(),
            "governance-test-key-0001"
        );
        headers.append("idempotency-key", "duplicate-key-0002".parse().unwrap());
        assert!(require_explicit_idempotency_key(&headers).is_err());
        assert_eq!(access_key_sha256("stable-key").len(), 64);
    }

    #[test]
    fn governance_cursor_positions_are_endpoint_specific_and_bounded() {
        let snapshot = 1_700_000_000_123_456_i64;
        let legal = CursorPosition {
            last: vec![
                CursorValue::Uuid(Uuid::from_u128(1)),
                CursorValue::U64(2),
                CursorValue::TimestampMicros(snapshot - 1),
                CursorValue::Uuid(Uuid::from_u128(2)),
                CursorValue::TimestampMicros(snapshot),
                CursorValue::Digest32([7; 32]),
            ],
        };
        let decoded = decode_legal_hold_cursor(legal.clone()).unwrap();
        assert_eq!(decoded.after_resource_order, 2);
        assert_eq!(decoded.chain_root, [7; 32]);
        assert!(decode_audit_cursor(legal).is_err());

        let audit = CursorPosition {
            last: vec![
                CursorValue::Uuid(Uuid::from_u128(3)),
                CursorValue::I64(10),
                CursorValue::I64(20),
                CursorValue::TimestampMicros(snapshot),
                CursorValue::Digest32([9; 32]),
            ],
        };
        assert_eq!(decode_audit_cursor(audit.clone()).unwrap().after_id, 10);
        assert!(decode_legal_hold_cursor(audit).is_err());
        assert!(decode_audit_cursor(CursorPosition {
            last: vec![
                CursorValue::Uuid(Uuid::from_u128(3)),
                CursorValue::I64(21),
                CursorValue::I64(20),
                CursorValue::TimestampMicros(snapshot),
                CursorValue::Digest32([9; 32]),
            ],
        })
        .is_err());
    }

    #[test]
    fn governance_cursor_scope_and_lease_lifetime_fail_closed() {
        let hold_a = legal_hold_export_filter(Uuid::from_u128(1)).unwrap();
        let hold_b = legal_hold_export_filter(Uuid::from_u128(2)).unwrap();
        assert_ne!(hold_a.as_bytes(), hold_b.as_bytes());
        let start = chrono::DateTime::from_timestamp_micros(1_700_000_000_000_000);
        let end = chrono::DateTime::from_timestamp_micros(1_700_000_100_000_000);
        assert_ne!(
            audit_export_filter(start, end).unwrap().as_bytes(),
            audit_export_filter(start, None).unwrap().as_bytes()
        );
        let now = chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap();
        assert_eq!(
            export_cursor_ttl_seconds(now, now + chrono::Duration::seconds(900)).unwrap(),
            900
        );
        assert!(export_cursor_ttl_seconds(now, now + chrono::Duration::seconds(29)).is_err());
        assert!(export_cursor_ttl_seconds(now, now + chrono::Duration::seconds(901)).is_err());
    }
}
