use crate::api::*;
use axum::http::HeaderMap;
use axum::{extract::State, http::StatusCode, response::Response, Json};
use serde_json::json;
use serde_json::Value;
use std::sync::Arc;
use uuid::Uuid;

use crate::api::idempotency::StoredHttpResponse;
use crate::api::models::{
    BooleanToggle, BroadcastRequest, MucRoomView, OfflineMessagesStats, SessionView,
};
use crate::db;
use crate::error::{AppError, Result};
use crate::state::AppState;

pub(crate) enum AdminMutationAcquire {
    Acquired(db::IdempotencyLease),
    Replay(db::IdempotentResponse),
    Busy { retry_after_seconds: u64 },
}

pub(crate) async fn acquire_admin_mutation_in_tx(
    state: &AppState,
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    actor: &ApiAdmin,
    request: &db::IdempotencyRequest<'_>,
) -> Result<AdminMutationAcquire, AppError> {
    state
        .cluster
        .admit(crate::cluster::ClusterOperation::AdminMutation)
        .map_err(|error| AppError::Unavailable(error.to_string()))?;
    if !db::authorize_admin_in_tx(tx, actor.id, actor.auth_generation, actor.session_token())
        .await?
    {
        return Err(AppError::Forbidden);
    }
    match db::acquire_idempotency_in_tx(state.api_control(), tx, request).await? {
        db::IdempotencyAcquire::Acquired(lease) => Ok(AdminMutationAcquire::Acquired(lease)),
        db::IdempotencyAcquire::Replay(replay) => Ok(AdminMutationAcquire::Replay(replay)),
        db::IdempotencyAcquire::FingerprintConflict | db::IdempotencyAcquire::RotationConflict => {
            Err(AppError::IdempotencyConflict)
        }
        db::IdempotencyAcquire::ReplayInvalidated => Err(AppError::IdempotencyReplayInvalidated),
        db::IdempotencyAcquire::Busy {
            retry_after_seconds,
        } => Ok(AdminMutationAcquire::Busy {
            retry_after_seconds,
        }),
        db::IdempotencyAcquire::CapacityLimited {
            retry_after_seconds,
        } => Err(AppError::TooManyRequests {
            message: "too many retained requests; try again later".into(),
            retry_after: retry_after_seconds,
        }),
        db::IdempotencyAcquire::InProgress {
            retry_after_seconds,
        } => Err(AppError::IdempotencyInProgress {
            retry_after: retry_after_seconds,
        }),
    }
}

pub(crate) async fn complete_admin_response(
    state: &AppState,
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    lease: &db::IdempotencyLease,
    status: StatusCode,
    body: Value,
    replay_resource_id: Option<Uuid>,
) -> Result<Response, AppError> {
    let stored_response = StoredHttpResponse::json(status, body)?
        .with_optional_replay_resource_id(replay_resource_id);
    if !stored_response
        .persist_in_tx(state.api_control(), tx, lease)
        .await?
    {
        return Err(AppError::Internal(anyhow::anyhow!(
            "administrator idempotency lease changed"
        )));
    }
    stored_response.build_response()
}

struct AdminOperationRequest<'a> {
    kind: &'a str,
    target: Option<&'a str>,
    policy: db::AuthorizationPolicy,
    payload: &'a Value,
}

async fn enqueue_admin_operation(
    state: &AppState,
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    actor: &ApiAdmin,
    lease: &db::IdempotencyLease,
    request: AdminOperationRequest<'_>,
) -> Result<(Response, Uuid), AppError> {
    let operation = db::enqueue_operation_in_tx(
        tx,
        &db::EnqueueOperation {
            request_id: lease.request_id,
            idempotency_id: lease.record_id,
            idempotency_lease_token: lease.lease_token(),
            actor_id: actor.id,
            actor_auth_generation: actor.auth_generation,
            authorization_policy: request.policy,
            kind: request.kind,
            target: request.target,
            payload_version: 1,
            payload: request.payload,
            max_attempts: 8,
            deadline_seconds: 24 * 60 * 60,
        },
    )
    .await?;
    let location = format!("/api/v1/admin/operations/{}", operation.id);
    let stored_response = StoredHttpResponse::json(
        StatusCode::ACCEPTED,
        json!({"operation_id":operation.id,"status":"pending"}),
    )?
    .with_header("location", location);
    // The operation identifier is already protected inside the encrypted
    // response body and Location header, while the journal is linked to this
    // idempotency record. `replay_resource_id` is intentionally reserved for
    // secret-bearing invitation responses whose current resource state must
    // be revalidated before disclosure; treating an ordinary operation as
    // that polymorphic resource violates the database route constraint.
    if !stored_response
        .persist_in_tx(state.api_control(), tx, lease)
        .await?
    {
        return Err(AppError::Internal(anyhow::anyhow!(
            "administrator idempotency lease changed"
        )));
    }
    let response = stored_response.build_response()?;
    Ok((response, operation.id))
}

async fn refresh_registration_cache(state: &AppState) -> Result<(), AppError> {
    let (_, registration_closed) = db::admin_runtime_settings(&state.pool).await?;
    state.apply_registration_closed(registration_closed);
    Ok(())
}

async fn refresh_registration_cache_best_effort(state: &AppState, committed_action: &'static str) {
    if let Err(error) = refresh_registration_cache(state).await {
        // The PostgreSQL transaction and its idempotent response are already
        // committed.  The periodic runtime-settings refresher will reconcile
        // this process-local cache, so a cache read failure must not turn the
        // durable success into a contradictory HTTP error.
        tracing::error!(
            ?error,
            committed_action,
            "failed to refresh registration cache after committed administrator mutation"
        );
    }
}

fn valid_admin_text(value: &str, max_chars: usize, max_bytes: usize, multiline: bool) -> bool {
    !value.is_empty()
        && value.len() <= max_bytes
        && value.chars().count() <= max_chars
        && value.chars().all(|character| {
            let code = character as u32;
            let allowed_space = multiline && matches!(character, '\t' | '\n' | '\r');
            (allowed_space || !(code <= 0x1f || (0x7f..=0x9f).contains(&code)))
                && !(0x202a..=0x202e).contains(&code)
        })
}

pub async fn admin_stats(
    State(state): State<Arc<AppState>>,
    actor: ApiAdmin,
) -> Result<Json<Value>, AppError> {
    let mut read_tx = actor.begin_authorized_read(&state).await?;
    let island_mode = state.island_mode_enabled();
    let registration_open = !state.registration_is_closed();
    let (users, archived, offline) = db::counts_in_tx(&mut read_tx).await?;
    let (rooms, uploads, push_subscriptions) = db::operational_counts_in_tx(&mut read_tx).await?;
    let (pending_reports, pending_appeals, active_invitations) =
        db::moderation_counts_in_tx(&mut read_tx).await?;
    let online_sessions = state.sessions.len();
    let room_occupants = state.muc_occupants.len();
    read_tx.commit().await?;
    Ok(Json(json!({
        "users":users, "online_sessions":online_sessions, "archived_stanzas":archived,
        "offline_stanzas":offline, "uptime_seconds":state.uptime().as_secs(),
        "archive_policy":if state.config.require_encrypted_archive {"encrypted_only"} else {"all"},
        "rooms":rooms, "room_occupants":room_occupants, "uploaded_files":uploads,
        "push_subscriptions":push_subscriptions,
        "island_mode":island_mode,
        "registration_open":registration_open,
        "federation_configured":state.config.federation_enabled,
        "federation_enabled":state.config.federation_enabled && !island_mode,
        "federation_inbound_connections":state.metrics.federation_inbound_connections_total.load(std::sync::atomic::Ordering::Relaxed),
        "federation_outbound_deliveries":state.metrics.federation_outbound_deliveries_total.load(std::sync::atomic::Ordering::Relaxed),
        "federation_failures":state.metrics.federation_failures_total.load(std::sync::atomic::Ordering::Relaxed),
        "pending_reports":pending_reports, "pending_appeals":pending_appeals,
        "active_invitations":active_invitations,
        "anti_abuse_challenges":state.metrics.anti_abuse_challenges_total.load(std::sync::atomic::Ordering::Relaxed),
        "rate_limited_operations":state.metrics.rate_limited_total.load(std::sync::atomic::Ordering::Relaxed),
        "reports_created":state.metrics.reports_total.load(std::sync::atomic::Ordering::Relaxed),
        "appeals_created":state.metrics.appeals_total.load(std::sync::atomic::Ordering::Relaxed)
    })))
}

pub async fn admin_users(
    State(state): State<Arc<AppState>>,
    actor: ApiAdmin,
    ApiQuery(query): ApiQuery<CursorPage>,
) -> Result<Json<Value>, AppError> {
    let limit = pagination::checked_limit(query.limit, 100, 100)?;
    let filter = pagination::no_filter_scope();
    let binding = pagination::pg_binding("admin/users", actor.id.as_bytes(), &filter);
    let after = pagination::pg_boundary(&state, query.cursor.as_deref(), &binding).await?;
    let mut read_tx = actor.begin_authorized_read(&state).await?;
    let page = db::users_page_in_tx(&mut read_tx, after, limit).await?;
    read_tx.commit().await?;
    let next_cursor = pagination::issue_pg_cursor(&state, &binding, page.next, page.database_now)?;
    Ok(Json(json!({"users":page.rows,"next_cursor":next_cursor})))
}

pub async fn admin_update_user(
    State(state): State<Arc<AppState>>,
    actor: ApiAdmin,
    ApiPath(id): ApiPath<Uuid>,
    request: ApiJson<UserPatch>,
) -> Result<Response, AppError> {
    if request.disabled.is_none() && request.admin.is_none() {
        return Err(AppError::BadRequest("user patch is empty".into()));
    }
    let mut idempotency = request.idempotency(
        Some(actor.id),
        actor.id.as_bytes(),
        db::ApiPrincipalKind::Admin,
        "PATCH",
        "/api/v1/admin/users/{id}",
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
    let previous_auth_generation = db::set_user_status_admin_in_tx(
        &mut tx,
        actor.id,
        actor.auth_generation,
        actor.session_token(),
        id,
        request.disabled,
        request.admin,
    )
    .await
    .map_err(|error| match error {
        db::UserStatusError::NotFound => AppError::BadRequest("user does not exist".into()),
        db::UserStatusError::LastAdministrator => AppError::Conflict(error.to_string()),
        db::UserStatusError::SelfMutation => AppError::BadRequest(error.to_string()),
        db::UserStatusError::Unauthorized => AppError::Forbidden,
        db::UserStatusError::Internal(error) => AppError::Internal(error),
    })?;
    if request.disabled == Some(true) {
        let target_key = format!("user:{id}:generation:{previous_auth_generation}");
        let (response, _operation_id) = enqueue_admin_operation(
            &state,
            &mut tx,
            &actor,
            &lease,
            AdminOperationRequest {
                kind: "admin.user_session_cleanup",
                target: Some(&target_key),
                policy: db::AuthorizationPolicy::CommittedConsequence,
                payload: &json!({"user_id":id,"auth_generation":previous_auth_generation}),
            },
        )
        .await?;
        tx.commit().await?;
        Ok(response)
    } else {
        let response = complete_admin_response(
            &state,
            &mut tx,
            &lease,
            StatusCode::OK,
            json!({"updated":true}),
            None,
        )
        .await?;
        tx.commit().await?;
        Ok(response)
    }
}

pub async fn admin_reports(
    State(state): State<Arc<AppState>>,
    actor: ApiAdmin,
    ApiQuery(query): ApiQuery<ReportPageQuery>,
) -> Result<Json<Value>, AppError> {
    let limit = pagination::checked_limit(query.limit, 25, 25)?;
    let status = pagination::checked_report_status(query.status.as_deref())?;
    let filter = pagination::one_filter_scope("status", status)?;
    let binding = pagination::pg_binding("admin/reports", actor.id.as_bytes(), &filter);
    let after = pagination::pg_boundary(&state, query.cursor.as_deref(), &binding).await?;
    let mut read_tx = actor.begin_authorized_read(&state).await?;
    let page = db::admin_reports_page_in_tx(&mut read_tx, status, after, limit).await?;
    read_tx.commit().await?;
    let next_cursor = pagination::issue_pg_cursor(&state, &binding, page.next, page.database_now)?;
    Ok(Json(json!({
        "reports":page.rows,
        "limit":limit,
        "next_cursor":next_cursor
    })))
}

pub async fn admin_update_report(
    State(state): State<Arc<AppState>>,
    actor: ApiAdmin,
    ApiPath(id): ApiPath<Uuid>,
    request: ApiJson<ModerationPatch>,
) -> Result<Response, AppError> {
    if !matches!(
        request.status.as_str(),
        "submitted" | "reviewing" | "actioned" | "rejected" | "closed"
    ) {
        return Err(AppError::BadRequest("invalid report status".into()));
    }
    let resolution = request.resolution.as_deref().unwrap_or_default().trim();
    if (!resolution.is_empty() && !valid_admin_text(resolution, 8000, 32_000, true))
        || (matches!(request.status.as_str(), "actioned" | "rejected" | "closed")
            && resolution.trim().is_empty())
    {
        return Err(AppError::BadRequest(
            "a resolution is required when resolving a report".into(),
        ));
    }
    let mut idempotency = request.idempotency(
        Some(actor.id),
        actor.id.as_bytes(),
        db::ApiPrincipalKind::Admin,
        "PATCH",
        "/api/v1/admin/reports/{id}",
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
    let (status, response_body) = match db::admin_update_report_in_tx(
        &mut tx,
        id,
        actor.id,
        &request.status,
        resolution,
        lease.request_id,
    )
    .await
    {
        Ok(()) => (StatusCode::OK, json!({"updated":true})),
        Err(db::ModerationUpdateError::NotFound) => (
            StatusCode::NOT_FOUND,
            json!({"error":{"code":"not_found","message":"moderation record does not exist"}}),
        ),
        Err(db::ModerationUpdateError::InvalidTransition) => (
            StatusCode::CONFLICT,
            json!({"error":{"code":"conflict","message":"invalid moderation state transition"}}),
        ),
        Err(db::ModerationUpdateError::Unauthorized) => return Err(AppError::Forbidden),
        Err(db::ModerationUpdateError::Internal(error)) => return Err(AppError::Internal(error)),
    };
    let response =
        complete_admin_response(&state, &mut tx, &lease, status, response_body, None).await?;
    tx.commit().await?;
    Ok(response)
}

pub async fn admin_update_appeal(
    State(state): State<Arc<AppState>>,
    actor: ApiAdmin,
    ApiPath(id): ApiPath<Uuid>,
    request: ApiJson<ModerationPatch>,
) -> Result<Response, AppError> {
    if !matches!(
        request.status.as_str(),
        "submitted" | "reviewing" | "upheld" | "denied"
    ) {
        return Err(AppError::BadRequest("invalid appeal status".into()));
    }
    let resolution = request.resolution.as_deref().unwrap_or_default().trim();
    if (!resolution.is_empty() && !valid_admin_text(resolution, 8000, 32_000, true))
        || (matches!(request.status.as_str(), "upheld" | "denied") && resolution.trim().is_empty())
    {
        return Err(AppError::BadRequest(
            "a resolution is required when resolving an appeal".into(),
        ));
    }
    let mut idempotency = request.idempotency(
        Some(actor.id),
        actor.id.as_bytes(),
        db::ApiPrincipalKind::Admin,
        "PATCH",
        "/api/v1/admin/appeals/{id}",
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
    let (status, response_body) = match db::admin_update_appeal_in_tx(
        &mut tx,
        id,
        actor.id,
        &request.status,
        resolution,
        lease.request_id,
    )
    .await
    {
        Ok(()) => (StatusCode::OK, json!({"updated":true})),
        Err(db::ModerationUpdateError::NotFound) => (
            StatusCode::NOT_FOUND,
            json!({"error":{"code":"not_found","message":"moderation record does not exist"}}),
        ),
        Err(db::ModerationUpdateError::InvalidTransition) => (
            StatusCode::CONFLICT,
            json!({"error":{"code":"conflict","message":"invalid moderation state transition"}}),
        ),
        Err(db::ModerationUpdateError::Unauthorized) => return Err(AppError::Forbidden),
        Err(db::ModerationUpdateError::Internal(error)) => return Err(AppError::Internal(error)),
    };
    let response =
        complete_admin_response(&state, &mut tx, &lease, status, response_body, None).await?;
    tx.commit().await?;
    Ok(response)
}

pub async fn admin_tls_reload(
    State(state): State<Arc<AppState>>,
    actor: ApiAdmin,
    request: ApiEmpty,
) -> Result<Response, AppError> {
    let idempotency = request.idempotency(
        Some(actor.id),
        actor.id.as_bytes(),
        db::ApiPrincipalKind::Admin,
        "POST",
        "/api/v1/admin/tls/reload",
    );
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
    let (response, _operation_id) = enqueue_admin_operation(
        &state,
        &mut tx,
        &actor,
        &lease,
        AdminOperationRequest {
            kind: "admin.tls_reload",
            target: None,
            policy: db::AuthorizationPolicy::ReauthorizeUntilEffect,
            payload: &json!({}),
        },
    )
    .await?;
    tx.commit().await?;
    Ok(response)
}

pub async fn admin_invitations(
    State(state): State<Arc<AppState>>,
    actor: ApiAdmin,
    ApiQuery(query): ApiQuery<CursorPage>,
) -> Result<Json<Value>, AppError> {
    let limit = pagination::checked_limit(query.limit, 25, 100)?;
    let filter = pagination::no_filter_scope();
    let binding = pagination::pg_binding("admin/invitations", actor.id.as_bytes(), &filter);
    let after = pagination::pg_boundary(&state, query.cursor.as_deref(), &binding).await?;
    let mut read_tx = actor.begin_authorized_read(&state).await?;
    let page = db::invitations_page_in_tx(&mut read_tx, after, limit).await?;
    read_tx.commit().await?;
    let next_cursor = pagination::issue_pg_cursor(&state, &binding, page.next, page.database_now)?;
    Ok(Json(json!({
        "invitations":page.rows,
        "required":state.config.invitation_required,
        "limit":limit,
        "next_cursor":next_cursor
    })))
}

pub async fn admin_create_invitation(
    State(state): State<Arc<AppState>>,
    actor: ApiAdmin,
    request: ApiJson<InvitationRequest>,
) -> Result<Response, AppError> {
    let label = request.label.trim();
    if !valid_admin_text(label, 128, 512, false) {
        return Err(AppError::BadRequest("invitation label is invalid".into()));
    }
    let max_uses = request.max_uses.unwrap_or(1);
    if !(1..=100_000).contains(&max_uses) {
        return Err(AppError::BadRequest(
            "invitation max uses is invalid".into(),
        ));
    }
    if request
        .expires_in_hours
        .is_some_and(|hours| !(1..=8760).contains(&hours))
    {
        return Err(AppError::BadRequest("invitation expiry is invalid".into()));
    }
    let mut idempotency = request.idempotency(
        Some(actor.id),
        actor.id.as_bytes(),
        db::ApiPrincipalKind::Admin,
        "POST",
        "/api/v1/admin/invitations",
    );
    idempotency.target_scope = b"invitation:create";
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
    let token = crate::auth::new_session_token();
    db::create_invitation_in_tx(
        &mut tx,
        actor.id,
        id,
        &token,
        label,
        max_uses,
        request.expires_in_hours,
        Some(lease.request_id),
    )
    .await?;
    let response = complete_admin_response(
        &state,
        &mut tx,
        &lease,
        StatusCode::CREATED,
        json!({"id":id,"token":token,"shown_once":true}),
        Some(id),
    )
    .await?;
    tx.commit().await?;
    Ok(response)
}

pub async fn admin_revoke_invitation(
    State(state): State<Arc<AppState>>,
    actor: ApiAdmin,
    ApiPath(id): ApiPath<Uuid>,
    request: ApiEmpty,
) -> Result<Response, AppError> {
    let mut idempotency = request.idempotency(
        Some(actor.id),
        actor.id.as_bytes(),
        db::ApiPrincipalKind::Admin,
        "DELETE",
        "/api/v1/admin/invitations/{id}",
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
    let revoked =
        db::revoke_invitation_in_tx(&mut tx, actor.id, id, Some(lease.request_id)).await?;
    if revoked == db::InvitationRevokeOutcome::NotFound {
        let response = complete_admin_response(
            &state,
            &mut tx,
            &lease,
            StatusCode::NOT_FOUND,
            json!({"error":{"code":"not_found","message":"invitation does not exist"}}),
            None,
        )
        .await?;
        tx.commit().await?;
        return Ok(response);
    }
    let response = complete_admin_response(
        &state,
        &mut tx,
        &lease,
        StatusCode::OK,
        json!({"revoked":true,"already_revoked":revoked == db::InvitationRevokeOutcome::AlreadyRevoked}),
        None,
    )
    .await?;
    tx.commit().await?;
    Ok(response)
}

pub async fn admin_nuke(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(_body): Json<Value>,
) -> Result<Json<Value>, AppError> {
    let _actor = admin(&state, &headers).await?;
    Err(AppError::OperationDisabled(
        "REST factory reset is disabled; use the staged operator recovery procedure".into(),
    ))
}

pub async fn admin_panic_disconnect(
    State(state): State<Arc<AppState>>,
    actor: ApiAdmin,
    request: ApiEmpty,
) -> Result<Response, AppError> {
    let idempotency = request.idempotency(
        Some(actor.id),
        actor.id.as_bytes(),
        db::ApiPrincipalKind::Admin,
        "POST",
        "/api/v1/admin/panic_disconnect",
    );
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
    let (response, _operation_id) = enqueue_admin_operation(
        &state,
        &mut tx,
        &actor,
        &lease,
        AdminOperationRequest {
            kind: "admin.panic_disconnect",
            target: None,
            policy: db::AuthorizationPolicy::ReauthorizeUntilEffect,
            payload: &json!({"reason":"administrator request"}),
        },
    )
    .await?;
    tx.commit().await?;
    Ok(response)
}

pub async fn admin_toggle_island_mode(
    State(state): State<Arc<AppState>>,
    actor: ApiAdmin,
    request: ApiJson<BooleanToggle>,
) -> Result<Response, AppError> {
    let mut idempotency = request.idempotency(
        Some(actor.id),
        actor.id.as_bytes(),
        db::ApiPrincipalKind::Admin,
        "POST",
        "/api/v1/admin/island_mode",
    );
    idempotency.target_scope = b"island_mode";
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
    db::set_admin_runtime_setting_in_tx(
        &mut tx,
        actor.id,
        "island_mode",
        request.enabled,
        Some(lease.request_id),
    )
    .await?;
    let payload = json!({"mode":if request.enabled {"enabled"} else {"disabled"},"epoch":lease.request_id.as_u128().min(i64::MAX as u128) as i64});
    let (response, _operation_id) = enqueue_admin_operation(
        &state,
        &mut tx,
        &actor,
        &lease,
        AdminOperationRequest {
            kind: "admin.island_converge",
            target: Some("island_mode"),
            policy: db::AuthorizationPolicy::CommittedConsequence,
            payload: &payload,
        },
    )
    .await?;
    tx.commit().await?;
    Ok(response)
}

pub async fn admin_toggle_registration(
    State(state): State<Arc<AppState>>,
    actor: ApiAdmin,
    request: ApiJson<BooleanToggle>,
) -> Result<Response, AppError> {
    let mut idempotency = request.idempotency(
        Some(actor.id),
        actor.id.as_bytes(),
        db::ApiPrincipalKind::Admin,
        "POST",
        "/api/v1/admin/registration",
    );
    idempotency.target_scope = b"registration_closed";
    let mut tx = state.pool.begin().await?;
    let lease = match acquire_admin_mutation_in_tx(&state, &mut tx, &actor, &idempotency).await? {
        AdminMutationAcquire::Acquired(lease) => lease,
        AdminMutationAcquire::Replay(replay) => {
            tx.commit().await?;
            // A replay may be older than a later toggle made with another
            // key. Refresh from durable state rather than re-applying the
            // historical request body to this process-local discovery cache.
            refresh_registration_cache_best_effort(&state, "idempotency_replay").await;
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
    db::set_admin_runtime_setting_in_tx(
        &mut tx,
        actor.id,
        "registration_closed",
        !request.enabled,
        Some(lease.request_id),
    )
    .await?;
    let response = complete_admin_response(
        &state,
        &mut tx,
        &lease,
        StatusCode::OK,
        json!({"open_registration": request.enabled}),
        None,
    )
    .await?;
    tx.commit().await?;
    refresh_registration_cache_best_effort(&state, "registration_toggle").await;

    Ok(response)
}

pub async fn admin_sessions(
    State(state): State<Arc<AppState>>,
    actor: ApiAdmin,
    ApiQuery(query): ApiQuery<CursorPage>,
) -> Result<Json<Value>, AppError> {
    let limit = pagination::checked_limit(query.limit, 100, 100)?;
    let node_incarnation = Uuid::parse_str(&state.cluster.node_id)
        .map_err(|error| AppError::Internal(error.into()))?;
    let filter = pagination::no_filter_scope();
    let binding = pagination::session_binding(
        "admin/sessions",
        actor.id.as_bytes(),
        &filter,
        node_incarnation,
    );
    let after = pagination::session_after(&state, query.cursor.as_deref(), &binding).await?;
    let mut read_tx = actor.begin_authorized_read(&state).await?;
    let mut views = Vec::new();
    let now = std::time::Instant::now();
    for entry in state.sessions.iter() {
        let jid = entry.key().clone();
        let session = entry.value();
        if !session.routable.load(std::sync::atomic::Ordering::Acquire) {
            continue;
        }
        views.push(SessionView {
            connection_id: session.connection_id,
            node: state.cluster.node_id.clone(),
            jid,
            ip: session.ip.map(|ip| ip.to_string()),
            resource: session.resource.clone(),
            carbons_enabled: session.carbons.load(std::sync::atomic::Ordering::Acquire),
            connected_duration_seconds: now
                .saturating_duration_since(session.connected_at)
                .as_secs(),
        });
    }
    let (views, next) = finish_session_page(views, after, limit);
    let database_now = db::database_cursor_clock_in_tx(&mut read_tx).await?;
    read_tx.commit().await?;
    let next_cursor = pagination::issue_session_cursor(&state, &binding, next, database_now)?;
    Ok(Json(json!({"sessions":views,"next_cursor":next_cursor})))
}

fn finish_session_page(
    mut views: Vec<SessionView>,
    after: Option<Uuid>,
    limit: i64,
) -> (Vec<SessionView>, Option<Uuid>) {
    views.sort_unstable_by_key(|view| std::cmp::Reverse(view.connection_id));
    if let Some(after) = after {
        views.retain(|session| session.connection_id < after);
    }
    let has_more = views.len() > limit as usize;
    views.truncate(limit as usize);
    let next = has_more.then(|| {
        views
            .last()
            .expect("a live-session page with an extra item is nonempty")
            .connection_id
    });
    (views, next)
}

pub async fn admin_kick_session(
    State(state): State<Arc<AppState>>,
    actor: ApiAdmin,
    ApiPath(connection_id): ApiPath<Uuid>,
    request: ApiEmpty,
) -> Result<Response, AppError> {
    if connection_id.is_nil() {
        return Err(AppError::BadRequest("connection id must not be nil".into()));
    }
    let target = format!("connection:{connection_id}");
    let mut idempotency = request.idempotency(
        Some(actor.id),
        actor.id.as_bytes(),
        db::ApiPrincipalKind::Admin,
        "DELETE",
        "/api/v1/admin/sessions/{connection_id}",
    );
    idempotency.target_scope = target.as_bytes();
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
    let session = state
        .sessions
        .iter()
        .find(|entry| entry.connection_id == connection_id);
    let Some(session) = session else {
        let response = complete_admin_response(
            &state,
            &mut tx,
            &lease,
            StatusCode::BAD_REQUEST,
            json!({"error":{"code":"bad_request","message":"session does not exist"}}),
            None,
        )
        .await?;
        tx.commit().await?;
        return Ok(response);
    };
    let payload = json!({"user_id":session.user_id,"auth_generation":session.auth_generation,
        "connection_id":connection_id.to_string()});
    drop(session);
    let (response, _operation_id) = enqueue_admin_operation(
        &state,
        &mut tx,
        &actor,
        &lease,
        AdminOperationRequest {
            kind: "admin.session_kick",
            target: Some(&target),
            policy: db::AuthorizationPolicy::ReauthorizeUntilEffect,
            payload: &payload,
        },
    )
    .await?;
    tx.commit().await?;
    Ok(response)
}

pub async fn admin_offline_messages_stats(
    State(state): State<Arc<AppState>>,
    actor: ApiAdmin,
) -> Result<Json<OfflineMessagesStats>, AppError> {
    let mut read_tx = actor.begin_authorized_read(&state).await?;
    let row: (i64, i64) =
        sqlx::query_as("SELECT COUNT(*), COALESCE(SUM(LENGTH(stanza)), 0) FROM offline_messages")
            .fetch_one(&mut *read_tx)
            .await?;
    read_tx.commit().await?;

    Ok(Json(OfflineMessagesStats {
        total_messages: row.0,
        estimated_bytes: row.1,
    }))
}

pub async fn admin_clear_offline_messages(
    State(state): State<Arc<AppState>>,
    actor: ApiAdmin,
    request: ApiEmpty,
) -> Result<Response, AppError> {
    let mut idempotency = request.idempotency(
        Some(actor.id),
        actor.id.as_bytes(),
        db::ApiPrincipalKind::Admin,
        "DELETE",
        "/api/v1/admin/offline_messages",
    );
    idempotency.target_scope = b"offline_messages";
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
    let removed =
        match db::clear_offline_messages_in_tx(&mut tx, actor.id, Some(lease.request_id)).await {
            Ok(removed) => removed,
            Err(error)
                if error
                    .downcast_ref::<db::OfflineMessagesTransportOwned>()
                    .is_some() =>
            {
                return Err(AppError::Conflict(error.to_string()));
            }
            Err(error) => return Err(error.into()),
        };
    let response = complete_admin_response(
        &state,
        &mut tx,
        &lease,
        StatusCode::OK,
        json!({"cleared":true,"removed":removed}),
        None,
    )
    .await?;
    tx.commit().await?;
    Ok(response)
}

pub async fn admin_muc_rooms(
    State(state): State<Arc<AppState>>,
    actor: ApiAdmin,
    ApiQuery(query): ApiQuery<CursorPage>,
) -> Result<Json<Value>, AppError> {
    let limit = pagination::checked_limit(query.limit, 100, 100)?;
    let filter = pagination::no_filter_scope();
    let binding = pagination::pg_binding("admin/muc-rooms", actor.id.as_bytes(), &filter);
    let after = pagination::pg_boundary(&state, query.cursor.as_deref(), &binding).await?;
    let mut read_tx = actor.begin_authorized_read(&state).await?;
    let page = db::admin_muc_rooms_page_in_tx(&mut read_tx, after, limit).await?;
    let mut views = Vec::with_capacity(page.rows.len());
    for row in page.rows {
        let localpart = row.localpart;
        let occupants = state
            .muc_occupants
            .iter()
            .filter(|occ| {
                occ.room_jid == format!("{}@conference.{}", localpart, state.config.domain)
            })
            .count();

        views.push(MucRoomView {
            id: row.id,
            localpart,
            title: row.title,
            created_at: row.created_at,
            public: row.public,
            persistent: row.persistent,
            members_only: row.members_only,
            moderated: row.moderated,
            non_anonymous: row.non_anonymous,
            current_occupants: occupants,
        });
    }
    read_tx.commit().await?;
    let next_cursor = pagination::issue_pg_cursor(&state, &binding, page.next, page.database_now)?;
    Ok(Json(json!({"rooms":views,"next_cursor":next_cursor})))
}

pub async fn admin_destroy_muc_room(
    State(state): State<Arc<AppState>>,
    actor: ApiAdmin,
    ApiPath(localpart): ApiPath<String>,
    request: ApiEmpty,
) -> Result<Response, AppError> {
    let room_jid = format!("{}@conference.{}", localpart, state.config.domain);
    let canonical = crate::jid::CanonicalJid::parse(&room_jid)
        .map_err(|_| AppError::BadRequest("room localpart is invalid".into()))?;
    if canonical.resourcepart().is_some()
        || canonical.localpart().is_none()
        || canonical.to_string() != room_jid
    {
        return Err(AppError::BadRequest("room JID is not canonical".into()));
    }
    let mut idempotency = request.idempotency(
        Some(actor.id),
        actor.id.as_bytes(),
        db::ApiPrincipalKind::Admin,
        "DELETE",
        "/api/v1/admin/muc_rooms/{localpart}",
    );
    idempotency.target_scope = room_jid.as_bytes();
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
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
        .bind(format!("northstar:muc-room:{localpart}"))
        .execute(&mut *tx)
        .await?;
    let room_exists = sqlx::query_scalar::<_, String>(
        "SELECT localpart FROM muc_rooms
          WHERE localpart=$1 AND destroyed_at IS NULL FOR UPDATE",
    )
    .bind(&localpart)
    .fetch_optional(&mut *tx)
    .await?
    .is_some();
    if !room_exists {
        return Err(AppError::BadRequest("room does not exist".into()));
    }
    let (response, operation_id) = enqueue_admin_operation(
        &state,
        &mut tx,
        &actor,
        &lease,
        AdminOperationRequest {
            kind: "admin.muc_destroy",
            target: Some(&room_jid),
            policy: db::AuthorizationPolicy::CommittedConsequence,
            payload: &json!({"room_jid":room_jid}),
        },
    )
    .await?;
    sqlx::query(
        "INSERT INTO api_muc_destroy_intents(room_jid,localpart,operation_id) VALUES($1,$2,$3)",
    )
    .bind(&room_jid)
    .bind(&localpart)
    .bind(operation_id)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(response)
}

pub async fn admin_broadcast(
    State(state): State<Arc<AppState>>,
    actor: ApiAdmin,
    request: ApiJson<BroadcastRequest>,
) -> Result<Response, AppError> {
    let body_text = request.message.trim();
    if body_text.is_empty() || body_text.len() > 32_768 {
        return Err(AppError::BadRequest(
            "broadcast message must contain 1 to 32768 bytes".into(),
        ));
    }
    let idempotency = request.idempotency(
        Some(actor.id),
        actor.id.as_bytes(),
        db::ApiPrincipalKind::Admin,
        "POST",
        "/api/v1/admin/broadcast",
    );
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
    let (response, _operation_id) = enqueue_admin_operation(
        &state,
        &mut tx,
        &actor,
        &lease,
        AdminOperationRequest {
            kind: "admin.broadcast",
            target: None,
            policy: db::AuthorizationPolicy::ReauthorizeUntilEffect,
            payload: &json!({"message":body_text}),
        },
    )
    .await?;
    tx.commit().await?;
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::{finish_session_page, valid_admin_text};
    use axum::body::Body;
    use axum::extract::FromRequest;
    use axum::http::{HeaderValue, Request};

    use crate::api::{ApiEmpty, SessionView};

    fn session(connection_id: u128) -> SessionView {
        SessionView {
            connection_id: uuid::Uuid::from_u128(connection_id),
            node: "test-node".into(),
            jid: format!("user{connection_id}@example.test/phone"),
            ip: None,
            resource: "phone".into(),
            carbons_enabled: false,
            connected_duration_seconds: 0,
        }
    }

    #[test]
    fn administrator_text_rejects_database_and_display_controls() {
        assert!(valid_admin_text("ordinary label", 128, 512, false));
        assert!(valid_admin_text(
            "مراجعة \u{2067}example.test\u{2069}",
            128,
            512,
            false
        ));
        assert!(valid_admin_text("line one\nline two", 128, 512, true));
        assert!(!valid_admin_text("line one\nline two", 128, 512, false));
        assert!(!valid_admin_text("hidden\0suffix", 128, 512, false));
        assert!(!valid_admin_text("hidden\u{0085}suffix", 128, 512, false));
        assert!(!valid_admin_text("spoof\u{202e}txt", 128, 512, false));
        assert!(!valid_admin_text("", 128, 512, false));
        assert!(!valid_admin_text("é", 8, 1, false));
    }

    #[tokio::test]
    async fn empty_admin_mutations_reject_bodies_and_duplicate_idempotency_keys() {
        let valid = Request::builder()
            .header("idempotency-key", "admin-delete-key-0001")
            .body(Body::empty())
            .unwrap();
        assert!(ApiEmpty::from_request(valid, &()).await.is_ok());

        let nonempty = Request::builder()
            .header("idempotency-key", "admin-delete-key-0002")
            .body(Body::from("{}"))
            .unwrap();
        assert!(ApiEmpty::from_request(nonempty, &()).await.is_err());

        let mut duplicate = Request::builder().body(Body::empty()).unwrap();
        duplicate.headers_mut().append(
            "idempotency-key",
            HeaderValue::from_static("admin-delete-key-0003"),
        );
        duplicate.headers_mut().append(
            "idempotency-key",
            HeaderValue::from_static("admin-delete-key-0004"),
        );
        assert!(ApiEmpty::from_request(duplicate, &()).await.is_err());
    }

    #[test]
    fn live_session_pages_use_strict_immutable_connection_boundaries() {
        let (first, next) = finish_session_page(
            vec![session(1), session(5), session(3), session(4), session(2)],
            None,
            2,
        );
        assert_eq!(
            first
                .iter()
                .map(|row| row.connection_id.as_u128())
                .collect::<Vec<_>>(),
            vec![5, 4]
        );
        assert_eq!(next.map(|id| id.as_u128()), Some(4));

        // A new connection above the signed boundary cannot be duplicated on
        // the continuation page; a vanished connection creates no offset gap.
        let (second, next) = finish_session_page(
            vec![session(6), session(5), session(3), session(2), session(1)],
            next,
            2,
        );
        assert_eq!(
            second
                .iter()
                .map(|row| row.connection_id.as_u128())
                .collect::<Vec<_>>(),
            vec![3, 2]
        );
        assert_eq!(next.map(|id| id.as_u128()), Some(2));
    }
}
