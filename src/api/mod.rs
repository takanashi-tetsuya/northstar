use axum::{
    http::header,
    routing::{get, post, put},
    Router,
};
use serde_json::json;
use std::net::SocketAddr;
use std::sync::Arc;

use crate::abuse::AbuseAction;
use crate::db;
use crate::error::{AppError, Result};
use crate::state::AppState;

use crate::abuse::GuardError;
use axum::extract::DefaultBodyLimit;
use axum::http::header::{HeaderMap, HeaderName, HeaderValue};
use axum::routing::{delete, patch};
use std::net::IpAddr;
use tower_http::services::ServeDir;
use tower_http::set_header::SetResponseHeaderLayer;
use tower_http::trace::TraceLayer;

pub mod models;
pub use models::*;
pub mod auth_routes;
pub use auth_routes::*;
pub mod admin;
pub mod reports;
pub mod system;
pub mod upload;
pub mod users;

pub use admin::*;
pub use reports::*;
pub use system::*;
pub use upload::*;
pub use users::*;

pub fn router(state: Arc<AppState>) -> Router {
    let upload_limit = usize::try_from(state.config.upload_max_bytes).unwrap_or(usize::MAX);
    Router::new()
        .route("/healthz", get(health))
        .route("/readyz", get(ready))
        .route("/metrics", get(metrics))
        .route("/xmpp-websocket", get(websocket))
        .route("/api/v1/config", get(public_config))
        .route("/api/v1/register", post(register))
        .route("/api/v1/anti-abuse/challenge", post(anti_abuse_challenge))
        .route("/api/v1/login", post(login))
        .route("/api/v1/me", get(me))
        .route("/api/v1/me/password", patch(change_password))
        .route("/api/v1/history", get(history))
        .route("/api/v1/reports", get(my_reports).post(create_report))
        .route("/api/v1/reports/{id}/appeals", post(create_appeal))
        .route(
            "/api/v1/upload/{id}",
            put(upload_put).layer(DefaultBodyLimit::max(upload_limit)),
        )
        .route("/uploads/{id}", get(upload_get))
        .route("/api/v1/admin/stats", get(admin_stats))
        .route("/api/v1/admin/users", get(admin_users))
        .route("/api/v1/admin/users/{id}", patch(admin_update_user))
        .route("/api/v1/admin/reports", get(admin_reports))
        .route("/api/v1/admin/reports/{id}", patch(admin_update_report))
        .route("/api/v1/admin/appeals/{id}", patch(admin_update_appeal))
        .route("/api/v1/admin/tls/reload", post(admin_tls_reload))
        .route("/api/v1/admin/invitations", get(admin_invitations).post(admin_create_invitation))
        .route("/api/v1/admin/invitations/{id}", delete(admin_revoke_invitation))
        .fallback_service(ServeDir::new("web").append_index_html_on_directories(true))
        .layer(SetResponseHeaderLayer::if_not_present(
            HeaderName::from_static("content-security-policy"),
            HeaderValue::from_static(
                "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; font-src 'self'; connect-src 'self' ws: wss:; media-src 'self' blob:; worker-src 'self' blob:; object-src 'none'; base-uri 'self'; frame-ancestors 'none'",
            ),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            header::X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            header::REFERRER_POLICY,
            HeaderValue::from_static("no-referrer"),
        ))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

pub fn ip_actor(ip: IpAddr) -> String {
    format!("ip:{ip}")
}

pub fn client_ip(peer_ip: IpAddr, headers: &HeaderMap, state: &AppState) -> IpAddr {
    if !state.config.trusted_proxy_ips.contains(&peer_ip) {
        return peer_ip;
    }
    headers
        .get("x-forwarded-for")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(',').next())
        .and_then(|value| value.trim().parse().ok())
        .filter(|ip: &IpAddr| !ip.is_unspecified())
        .unwrap_or(peer_ip)
}

pub fn abuse_identity(
    action: AbuseAction,
    ip: IpAddr,
    user: Option<&db::User>,
) -> (String, Vec<String>) {
    if action == AbuseAction::Registration {
        return (format!("registration:{ip}"), vec![ip_actor(ip)]);
    }
    let user = user.expect("authenticated anti-abuse action");
    (
        format!("{}:{}", action.as_str(), user.id),
        vec![
            ip_actor(ip),
            format!("user:{}", user.id),
            format!("behavior:{}", user.id),
        ],
    )
}

pub fn rate_limited(error: GuardError) -> AppError {
    AppError::RateLimited(json!({"message":error.message(),"requirement":error.requirement()}))
}

pub async fn current_user(state: &AppState, headers: &HeaderMap) -> Result<db::User, AppError> {
    let value = headers
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .ok_or(AppError::Unauthorized)?;
    let token = value
        .strip_prefix("Bearer ")
        .ok_or(AppError::Unauthorized)?;
    db::user_for_token(&state.pool, token)
        .await?
        .ok_or(AppError::Unauthorized)
}

pub async fn admin(state: &AppState, headers: &HeaderMap) -> Result<db::User, AppError> {
    let user = current_user(state, headers).await?;
    if !user.is_admin {
        return Err(AppError::Forbidden);
    }
    Ok(user)
}

pub async fn serve(
    state: Arc<AppState>,
    cancel: tokio_util::sync::CancellationToken,
) -> anyhow::Result<()> {
    let listener = tokio::net::TcpListener::bind(state.config.http_bind).await?;
    tracing::info!(address = %state.config.http_bind, "HTTP, WebSocket and administration listener ready");
    axum::serve(
        listener,
        router(state).into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(cancel.cancelled_owned())
    .await?;
    Ok(())
}

pub async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let terminate = async {
        let mut signal = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("signal handler");
        signal.recv().await;
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! { _ = ctrl_c => {}, _ = terminate => {} }
}
