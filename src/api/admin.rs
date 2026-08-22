use crate::api::*;
use axum::http::HeaderMap;
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Json,
};
use serde_json::json;
use serde_json::Value;
use std::sync::Arc;
use uuid::Uuid;

use crate::db;
use crate::error::{AppError, Result};
use crate::state::AppState;

pub async fn admin_stats(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<Value>, AppError> {
    let _ = admin(&state, &headers).await?;
    let (users, archived, offline) = db::counts(&state.pool).await?;
    let (rooms, uploads, push_subscriptions) = db::operational_counts(&state.pool).await?;
    let (pending_reports, pending_appeals, active_invitations) =
        db::moderation_counts(&state.pool).await?;
    Ok(Json(json!({
        "users":users, "online_sessions":state.sessions.len(), "archived_stanzas":archived,
        "offline_stanzas":offline, "uptime_seconds":state.started_at.elapsed().as_secs(),
        "archive_policy":if state.config.require_encrypted_archive {"encrypted_only"} else {"all"},
        "rooms":rooms, "room_occupants":state.muc_occupants.len(), "uploaded_files":uploads,
        "push_subscriptions":push_subscriptions, "federation_enabled":state.config.federation_enabled,
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
    headers: HeaderMap,
    Query(page): Query<Page>,
) -> Result<Json<Value>, AppError> {
    let _ = admin(&state, &headers).await?;
    let users = db::list_users(
        &state.pool,
        page.limit.unwrap_or(100).clamp(1, 200),
        page.offset.unwrap_or(0).max(0),
    )
    .await?;
    Ok(Json(json!({"users":users})))
}

pub async fn admin_update_user(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(body): Json<UserPatch>,
) -> Result<Json<Value>, AppError> {
    let actor = admin(&state, &headers).await?;
    if actor.id == id && body.disabled == Some(true) {
        return Err(AppError::BadRequest(
            "an administrator cannot disable their current account".into(),
        ));
    }
    if actor.id == id && body.admin == Some(false) {
        return Err(AppError::BadRequest(
            "an administrator cannot remove their own privileges".into(),
        ));
    }
    let updated = db::set_user_status(&state.pool, id, body.disabled, body.admin).await?;
    if !updated {
        return Err(AppError::BadRequest("user does not exist".into()));
    }
    db::audit(
        &state.pool,
        Some(actor.id),
        "admin.user.update",
        Some(&id.to_string()),
        json!({"disabled":body.disabled,"admin":body.admin}),
    )
    .await?;
    Ok(Json(json!({"updated":true})))
}

pub async fn admin_reports(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<Value>, AppError> {
    let _ = admin(&state, &headers).await?;
    Ok(Json(
        json!({"reports":db::list_reports(&state.pool, None, 200).await?}),
    ))
}

pub async fn admin_update_report(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(body): Json<ModerationPatch>,
) -> Result<Json<Value>, AppError> {
    let actor = admin(&state, &headers).await?;
    if !matches!(
        body.status.as_str(),
        "submitted" | "reviewing" | "actioned" | "rejected" | "closed"
    ) {
        return Err(AppError::BadRequest("invalid report status".into()));
    }
    let resolution = body.resolution.unwrap_or_default();
    if resolution.len() > 8000
        || (matches!(body.status.as_str(), "actioned" | "rejected" | "closed")
            && resolution.trim().is_empty())
    {
        return Err(AppError::BadRequest(
            "a resolution is required when resolving a report".into(),
        ));
    }
    if !db::admin_update_report(&state.pool, id, actor.id, &body.status, resolution.trim()).await? {
        return Err(AppError::BadRequest("report does not exist".into()));
    }
    db::audit(
        &state.pool,
        Some(actor.id),
        "admin.report.update",
        Some(&id.to_string()),
        json!({"status":body.status}),
    )
    .await?;
    Ok(Json(json!({"updated":true})))
}

pub async fn admin_update_appeal(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(body): Json<ModerationPatch>,
) -> Result<Json<Value>, AppError> {
    let actor = admin(&state, &headers).await?;
    if !matches!(
        body.status.as_str(),
        "submitted" | "reviewing" | "upheld" | "denied"
    ) {
        return Err(AppError::BadRequest("invalid appeal status".into()));
    }
    let resolution = body.resolution.unwrap_or_default();
    if resolution.len() > 8000
        || (matches!(body.status.as_str(), "upheld" | "denied") && resolution.trim().is_empty())
    {
        return Err(AppError::BadRequest(
            "a resolution is required when resolving an appeal".into(),
        ));
    }
    if !db::admin_update_appeal(&state.pool, id, actor.id, &body.status, resolution.trim()).await? {
        return Err(AppError::BadRequest("appeal does not exist".into()));
    }
    db::audit(
        &state.pool,
        Some(actor.id),
        "admin.appeal.update",
        Some(&id.to_string()),
        json!({"status":body.status}),
    )
    .await?;
    Ok(Json(json!({"updated":true})))
}

pub async fn admin_tls_reload(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<Value>, AppError> {
    let actor = admin(&state, &headers).await?;
    state.tls.reload().map_err(AppError::Internal)?;
    db::audit(
        &state.pool,
        Some(actor.id),
        "admin.tls.reload",
        None,
        json!({}),
    )
    .await?;
    Ok(Json(json!({"reloaded":true})))
}

pub async fn admin_invitations(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<Value>, AppError> {
    let _ = admin(&state, &headers).await?;
    Ok(Json(
        json!({"invitations":db::list_invitations(&state.pool).await?,"required":state.config.invitation_required}),
    ))
}

pub async fn admin_create_invitation(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<InvitationRequest>,
) -> Result<(StatusCode, Json<Value>), AppError> {
    let actor = admin(&state, &headers).await?;
    let label = body.label.trim();
    if label.is_empty() || label.len() > 128 {
        return Err(AppError::BadRequest("invitation label is invalid".into()));
    }
    let max_uses = body.max_uses.unwrap_or(1);
    if !(1..=100_000).contains(&max_uses) {
        return Err(AppError::BadRequest(
            "invitation max uses is invalid".into(),
        ));
    }
    let expires_at = body
        .expires_in_hours
        .map(|hours| chrono::Utc::now() + chrono::Duration::hours(hours.clamp(1, 8760).into()));
    let (id, token) =
        db::create_invitation(&state.pool, actor.id, label, max_uses, expires_at).await?;
    db::audit(
        &state.pool,
        Some(actor.id),
        "admin.invitation.create",
        Some(&id.to_string()),
        json!({"label":label,"max_uses":max_uses}),
    )
    .await?;
    Ok((
        StatusCode::CREATED,
        Json(json!({"id":id,"token":token,"shown_once":true})),
    ))
}

pub async fn admin_revoke_invitation(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<Value>, AppError> {
    let actor = admin(&state, &headers).await?;
    if !db::revoke_invitation(&state.pool, id).await? {
        return Err(AppError::BadRequest("invitation does not exist".into()));
    }
    db::audit(
        &state.pool,
        Some(actor.id),
        "admin.invitation.revoke",
        Some(&id.to_string()),
        json!({}),
    )
    .await?;
    Ok(Json(json!({"revoked":true})))
}
