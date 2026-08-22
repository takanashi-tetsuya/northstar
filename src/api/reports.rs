use crate::api::*;
use axum::http::HeaderMap;
use axum::{
    extract::{ConnectInfo, Path, State},
    http::StatusCode,
    Json,
};
use serde_json::json;
use serde_json::Value;
use std::net::SocketAddr;
use std::sync::Arc;
use uuid::Uuid;

use crate::abuse::AbuseAction;
use crate::db;
use crate::error::{AppError, Result};
use crate::state::AppState;

pub async fn create_report(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<ReportRequest>,
) -> Result<(StatusCode, Json<Value>), AppError> {
    let user = current_user(&state, &headers).await?;
    let reported_jid = body.reported_jid.trim().to_ascii_lowercase();
    if reported_jid.is_empty() || reported_jid.len() > 3071 || !reported_jid.contains('@') {
        return Err(AppError::BadRequest("reported JID is invalid".into()));
    }
    if !matches!(
        body.category.as_str(),
        "spam" | "harassment" | "threat" | "impersonation" | "illegal" | "other"
    ) {
        return Err(AppError::BadRequest("report category is invalid".into()));
    }
    if body.evidence.is_empty() || body.evidence.len() > 20 {
        return Err(AppError::BadRequest(
            "select between 1 and 20 messages as evidence".into(),
        ));
    }
    let description = body.description.unwrap_or_default().trim().to_owned();
    if description.len() > 4000 {
        return Err(AppError::BadRequest(
            "report description is too long".into(),
        ));
    }
    let mut evidence = Vec::with_capacity(body.evidence.len());
    for item in body.evidence {
        let text = item.body_text.trim().to_owned();
        if text.is_empty() || text.len() > 8000 || item.sender_jid.len() > 3071 {
            return Err(AppError::BadRequest("report evidence is invalid".into()));
        }
        evidence.push(db::ReportEvidenceInput {
            client_message_id: item.client_message_id.filter(|id| id.len() <= 128),
            sender_jid: item.sender_jid,
            sent_at: item.sent_at,
            body_text: text,
            encrypted: item.encrypted.unwrap_or(true),
        });
    }
    let peer_ip = client_ip(peer.ip(), &headers, &state);
    let (subject, actors) = abuse_identity(AbuseAction::Report, peer_ip, Some(&user));
    state
        .abuse
        .verify_or_allow(AbuseAction::Report, &subject, &actors, body.pow.as_ref())
        .map_err(|error| {
            state
                .metrics
                .rate_limited_total
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            rate_limited(error)
        })?;
    let id = db::create_report(
        &state.pool,
        user.id,
        &reported_jid,
        &body.category,
        &description,
        &evidence,
    )
    .await?;
    state
        .metrics
        .reports_total
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    db::audit(
        &state.pool,
        Some(user.id),
        "abuse.report.create",
        Some(&id.to_string()),
        json!({"reported_jid":reported_jid,"evidence_count":evidence.len()}),
    )
    .await?;
    Ok((
        StatusCode::CREATED,
        Json(json!({"id":id,"status":"submitted"})),
    ))
}

pub async fn my_reports(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<Value>, AppError> {
    let user = current_user(&state, &headers).await?;
    Ok(Json(
        json!({"reports":db::list_reports(&state.pool, Some(user.id), 100).await?}),
    ))
}

pub async fn create_appeal(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(report_id): Path<Uuid>,
    Json(body): Json<AppealRequest>,
) -> Result<(StatusCode, Json<Value>), AppError> {
    let user = current_user(&state, &headers).await?;
    let reason = body.reason.trim();
    if !(20..=4000).contains(&reason.len()) {
        return Err(AppError::BadRequest(
            "appeal reason must be between 20 and 4000 characters".into(),
        ));
    }
    let peer_ip = client_ip(peer.ip(), &headers, &state);
    let (subject, actors) = abuse_identity(AbuseAction::Appeal, peer_ip, Some(&user));
    state
        .abuse
        .verify_or_allow(AbuseAction::Appeal, &subject, &actors, body.pow.as_ref())
        .map_err(|error| {
            state
                .metrics
                .rate_limited_total
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            rate_limited(error)
        })?;
    let id = db::create_appeal(&state.pool, report_id, user.id, reason)
        .await
        .map_err(|error| AppError::Conflict(error.to_string()))?;
    state
        .metrics
        .appeals_total
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    db::audit(
        &state.pool,
        Some(user.id),
        "abuse.appeal.create",
        Some(&id.to_string()),
        json!({"report_id":report_id}),
    )
    .await?;
    Ok((
        StatusCode::CREATED,
        Json(json!({"id":id,"status":"submitted"})),
    ))
}
