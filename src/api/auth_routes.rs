use crate::api::*;
use axum::http::HeaderMap;
use axum::{
    extract::{ConnectInfo, State},
    http::StatusCode,
    Json,
};
use serde_json::json;
use serde_json::Value;
use std::net::SocketAddr;
use std::sync::Arc;

use crate::abuse::AbuseAction;
use crate::auth;
use crate::db;
use crate::error::{AppError, Result};
use crate::state::AppState;

pub async fn register(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<RegistrationRequest>,
) -> Result<(StatusCode, Json<Value>), AppError> {
    if !state.config.open_registration {
        return Err(AppError::Forbidden);
    }
    if db::registrations_last_hour(&state.pool).await?
        >= i64::from(state.config.registration_rate_per_hour)
    {
        return Err(AppError::Conflict(
            "registration limit reached; try again later".into(),
        ));
    }
    let peer_ip = client_ip(peer.ip(), &headers, &state);
    let actors = vec![ip_actor(peer_ip)];
    state
        .abuse
        .verify_or_allow(
            AbuseAction::Registration,
            &format!("registration:{peer_ip}"),
            &actors,
            body.pow.as_ref(),
        )
        .map_err(|error| {
            state
                .metrics
                .rate_limited_total
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            rate_limited(error)
        })?;
    let username = auth::normalize_username(&body.username)
        .map_err(|error| AppError::BadRequest(error.to_string()))?;
    auth::validate_password(&body.password)
        .map_err(|error| AppError::BadRequest(error.to_string()))?;
    if db::find_user(&state.pool, &username).await?.is_some() {
        return Err(AppError::Conflict("username is already registered".into()));
    }
    let user = db::create_user_with_invitation(
        &state.pool,
        &username,
        &body.password,
        body.invitation_token.as_deref(),
        state.config.invitation_required,
    )
    .await
    .map_err(|error| AppError::Conflict(error.to_string()))?;
    state
        .metrics
        .registrations_total
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    db::audit(
        &state.pool,
        Some(user.id),
        "user.register",
        Some(&user.username),
        json!({"source":"rest"}),
    )
    .await?;
    Ok((
        StatusCode::CREATED,
        Json(json!({"jid":format!("{}@{}", user.username, state.config.domain)})),
    ))
}

pub async fn login(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<Credentials>,
) -> Result<Json<SessionResponse>, AppError> {
    let peer_ip = client_ip(peer.ip(), &headers, &state);
    let actors = vec![ip_actor(peer_ip)];

    let req = state.abuse.current_requirement(AbuseAction::Login, &actors);
    if req.work_factor > 1 || req.retry_after_seconds > 0 {
        if body.pow.is_none() {
            state
                .metrics
                .rate_limited_total
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return Err(rate_limited(GuardError::Required(req)));
        }
        state
            .abuse
            .verify_or_allow(
                AbuseAction::Login,
                &format!("login:{peer_ip}"),
                &actors,
                body.pow.as_ref(),
            )
            .map_err(|error| {
                state
                    .metrics
                    .rate_limited_total
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                rate_limited(error)
            })?;
    }

    let user = match db::authenticate(&state.pool, &body.username, &body.password).await? {
        Some(user) => user,
        None => {
            state.abuse.record_failure(AbuseAction::Login, &actors);
            return Err(AppError::Unauthorized);
        }
    };
    let token =
        db::create_api_session(&state.pool, user.id, state.config.session_ttl_hours).await?;
    Ok(Json(SessionResponse {
        token,
        jid: format!("{}@{}", user.username, state.config.domain),
        is_admin: user.is_admin,
    }))
}

pub async fn anti_abuse_challenge(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<ChallengeRequest>,
) -> Result<Json<Value>, AppError> {
    let action = AbuseAction::parse(&body.action)
        .ok_or_else(|| AppError::BadRequest("unknown anti-abuse action".into()))?;
    let user = if action == AbuseAction::Registration {
        None
    } else {
        Some(current_user(&state, &headers).await?)
    };
    let peer_ip = client_ip(peer.ip(), &headers, &state);
    let (subject, actors) = abuse_identity(action, peer_ip, user.as_ref());
    state
        .metrics
        .anti_abuse_challenges_total
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    Ok(Json(json!(state.abuse.issue(action, &subject, &actors))))
}
