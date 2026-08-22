use crate::api::*;
use axum::http::HeaderMap;
use axum::{
    extract::{ConnectInfo, State, WebSocketUpgrade},
    http::header,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use serde_json::Value;
use std::net::SocketAddr;
use std::sync::Arc;

use crate::error::{AppError, Result};
use crate::state::AppState;
use crate::xmpp;

pub async fn health() -> &'static str {
    "ok"
}

pub async fn ready(State(state): State<Arc<AppState>>) -> Result<&'static str, AppError> {
    sqlx::query_scalar::<_, i32>("SELECT 1")
        .fetch_one(&state.pool)
        .await?;
    Ok("ready")
}

pub async fn metrics(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/plain; version=0.0.4")],
        state.metrics.render(),
    )
}

pub async fn websocket(
    ws: WebSocketUpgrade,
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Response {
    let peer_ip = client_ip(peer.ip(), &headers, &state);
    ws.protocols(["xmpp"])
        .max_message_size(1024 * 1024)
        .on_upgrade(move |socket| xmpp::websocket_connection(socket, state, peer_ip))
}

pub async fn public_config(State(state): State<Arc<AppState>>) -> Json<Value> {
    Json(json!({
        "domain":state.config.domain,
        "open_registration":state.config.open_registration,
        "invitation_required":state.config.invitation_required,
        "archive_policy":if state.config.require_encrypted_archive {"encrypted_only"} else {"all"},
        "websocket_path":"/xmpp-websocket"
        ,"upload_max_bytes":state.config.upload_max_bytes
        ,"upload_service":format!("upload.{}",state.config.domain)
        ,"muc_service":format!("conference.{}",state.config.domain)
        ,"federation_enabled":state.config.federation_enabled
        ,"pow_max_work_factor":state.config.pow_max_work_factor
        ,"pow_approximate_max_device_seconds":8
    }))
}
