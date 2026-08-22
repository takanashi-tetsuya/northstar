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
    match tokio::time::timeout(
        std::time::Duration::from_secs(2),
        sqlx::query_scalar::<_, i32>("SELECT 1").fetch_one(&state.pool),
    )
    .await
    {
        Ok(Ok(_)) => Ok("ready"),
        Ok(Err(error)) => {
            tracing::warn!(?error, "readiness database probe failed");
            Err(AppError::Unavailable("database is not ready".into()))
        }
        Err(_) => Err(AppError::Unavailable(
            "database readiness probe timed out".into(),
        )),
    }
}

pub async fn metrics(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let started = std::time::Instant::now();
    let database_up = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        sqlx::query_scalar::<_, i32>("SELECT 1").fetch_one(&state.pool),
    )
    .await
    .is_ok_and(|result| result.is_ok());
    let mut body = state.metrics.render();
    body.push_str(&format!(
        concat!(
            "# TYPE xmpp_database_up gauge\n",
            "xmpp_database_up {}\n",
            "# TYPE xmpp_database_ping_duration_seconds gauge\n",
            "xmpp_database_ping_duration_seconds {:.6}\n",
            "# TYPE xmpp_database_pool_connections gauge\n",
            "xmpp_database_pool_connections {}\n",
            "# TYPE xmpp_database_pool_idle_connections gauge\n",
            "xmpp_database_pool_idle_connections {}\n",
            "# TYPE xmpp_database_pool_max_connections gauge\n",
            "xmpp_database_pool_max_connections {}\n",
            "# TYPE xmpp_resumable_sessions gauge\n",
            "xmpp_resumable_sessions {}\n",
            "# TYPE xmpp_muc_occupants gauge\n",
            "xmpp_muc_occupants {}\n",
            "# TYPE xmpp_federation_outbound_workers gauge\n",
            "xmpp_federation_outbound_workers {}\n",
            "# TYPE xmpp_uptime_seconds gauge\n",
            "xmpp_uptime_seconds {}\n"
        ),
        u8::from(database_up),
        started.elapsed().as_secs_f64(),
        state.pool.size(),
        state.pool.num_idle(),
        state.config.database_max_connections,
        state.resumable_sessions.len(),
        state.muc_occupants.len(),
        state.s2s_outbound_connections.len(),
        state.started_at.elapsed().as_secs(),
    ));
    ([(header::CONTENT_TYPE, "text/plain; version=0.0.4")], body)
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
