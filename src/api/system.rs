use crate::api::*;
use axum::body::Body;
use axum::http::{HeaderMap, StatusCode};
use axum::{
    extract::{ConnectInfo, State, WebSocketUpgrade},
    http::header,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use serde_json::Value;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};
#[cfg(test)]
use subtle::ConstantTimeEq;
use tokio::sync::{Mutex, Semaphore};

use crate::api::contexts::{MetricsContext, ReadinessContext};
use crate::platform::error::{AppError, Result};
use crate::xmpp;

use crate::services::metrics_snapshot::DatabaseMetricsSnapshot;
#[cfg(test)]
use crate::services::readiness::{
    admin_session_cleanup_ready, ADMIN_CLEANUP_MAX_READY_AGE_SECONDS,
    ADMIN_CLEANUP_MAX_READY_ATTEMPTS,
};

/// Cache and single-flight gate for the private observability listener.
pub struct MetricsEndpointState {
    context: MetricsContext,
    gate: Semaphore,
    cache: Mutex<Option<(Instant, String)>>,
}

const READINESS_CACHE_TTL: Duration = Duration::from_secs(2);
const READINESS_GATE_WAIT: Duration = Duration::from_millis(200);
const READINESS_PROBE_TIMEOUT: Duration = Duration::from_millis(1500);

#[derive(Clone)]
enum ReadinessSnapshot {
    Ready,
    Unavailable(&'static str),
}

/// A bounded readiness capability. Its context exposes only live read-only
/// health probes and a typed persistence service; one single-flight probe may
/// use the authoritative pool while duplicates use the cache or fail fast.
pub struct ReadyEndpointState {
    context: ReadinessContext,
    gate: Semaphore,
    cache: Mutex<Option<(Instant, ReadinessSnapshot)>>,
}

impl ReadyEndpointState {
    pub(crate) fn new(context: ReadinessContext) -> Arc<Self> {
        Arc::new(Self {
            context,
            gate: Semaphore::new(1),
            cache: Mutex::new(None),
        })
    }

    async fn cached(&self) -> Option<ReadinessSnapshot> {
        self.cache
            .lock()
            .await
            .as_ref()
            .filter(|(created, _)| created.elapsed() < READINESS_CACHE_TTL)
            .map(|(_, snapshot)| snapshot.clone())
    }
}

impl MetricsEndpointState {
    pub fn new(context: MetricsContext) -> Arc<Self> {
        Arc::new(Self {
            context,
            gate: Semaphore::new(1),
            cache: Mutex::new(None),
        })
    }

    async fn cached(&self) -> Option<String> {
        self.cache
            .lock()
            .await
            .as_ref()
            .filter(|(created, _)| created.elapsed() < Duration::from_secs(5))
            .map(|(_, body)| body.clone())
    }
}

pub async fn health() -> &'static str {
    "ok"
}

const API_DOCS_CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";
const API_DOCS_HTML: &str = r#"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="referrer" content="no-referrer">
  <title>Northstar REST API</title>
  <link rel="icon" type="image/png" sizes="32x32" href="/api/docs/assets/5.32.14/favicon-32x32.png">
  <link rel="stylesheet" href="/api/docs/assets/5.32.14/swagger-ui.css">
</head>
<body>
  <div id="swagger-ui"></div>
  <script src="/api/docs/assets/5.32.14/swagger-ui-bundle.js"></script>
  <script src="/api/docs/assets/5.32.14/northstar-swagger-initializer.js"></script>
</body>
</html>
"#;

/// Serve the exact checked-in OpenAPI contract from the same origin as the
/// API. It is intentionally not generated at runtime, so CI can compare the
/// reviewed contract with the router before a release is built.
pub async fn openapi_document() -> Response {
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/yaml; charset=utf-8")
        .header(header::CACHE_CONTROL, "no-store, max-age=0")
        .header(
            "content-security-policy",
            "default-src 'none'; frame-ancestors 'none'",
        )
        .body(Body::from(include_str!("../../docs/openapi.yaml")))
        .expect("static OpenAPI response is valid")
}

/// Read-only, self-hosted Swagger UI. Submission and authorization controls
/// are disabled in the pinned initializer even for administrators; this keeps
/// bearer tokens out of documentation state and turns the UI into a contract
/// browser rather than an alternate control plane.
pub async fn api_docs() -> Response {
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
        .header(header::CACHE_CONTROL, "no-store, max-age=0")
        .header("content-security-policy", API_DOCS_CSP)
        .body(Body::from(API_DOCS_HTML))
        .expect("static API documentation response is valid")
}

pub async fn ready(
    State(endpoint): State<Arc<ReadyEndpointState>>,
) -> Result<&'static str, AppError> {
    if let Some(error) = current_runtime_readiness_error(&endpoint.context) {
        return Err(AppError::Unavailable(error.into()));
    }
    if let Some(snapshot) = endpoint.cached().await {
        return runtime_readiness_response(&endpoint.context, snapshot);
    }
    let permit = tokio::time::timeout(READINESS_GATE_WAIT, endpoint.gate.acquire())
        .await
        .map_err(|_| AppError::Unavailable("readiness probe is busy".into()))?
        .map_err(|_| AppError::Unavailable("readiness probe is unavailable".into()))?;
    // The cache is deliberately only for database work. Re-check cheap,
    // process-local safety authorities after waiting for the single-flight
    // gate so an old Ready snapshot cannot mask a worker or cluster failure.
    if let Some(error) = current_runtime_readiness_error(&endpoint.context) {
        drop(permit);
        return Err(AppError::Unavailable(error.into()));
    }
    if let Some(snapshot) = endpoint.cached().await {
        drop(permit);
        return runtime_readiness_response(&endpoint.context, snapshot);
    }
    let snapshot = probe_readiness(&endpoint.context).await;
    *endpoint.cache.lock().await = Some((Instant::now(), snapshot.clone()));
    drop(permit);
    runtime_readiness_response(&endpoint.context, snapshot)
}

fn current_runtime_readiness_error(context: &ReadinessContext) -> Option<&'static str> {
    if !context.connection_accepting() {
        return Some("connection admission is closed");
    }
    if !context.sm_ready() {
        return Some("XEP-0198 memory or recovery capacity is not ready");
    }
    if !upload_storage_ready(context.upload_state()) {
        return Some("upload storage authority is not ready");
    }
    if context.cluster_error().is_some() {
        return Some("cluster policy is not ready");
    }
    if context.worker_error().is_some() {
        return Some("background workers are not ready");
    }
    None
}

fn runtime_readiness_response(
    context: &ReadinessContext,
    snapshot: ReadinessSnapshot,
) -> Result<&'static str, AppError> {
    // Admission can close while awaiting either the cache mutex or the
    // database. Every response rechecks live authority after its last await.
    if let Some(error) = current_runtime_readiness_error(context) {
        return Err(AppError::Unavailable(error.into()));
    }
    readiness_response(snapshot)
}

fn readiness_response(snapshot: ReadinessSnapshot) -> Result<&'static str, AppError> {
    match snapshot {
        ReadinessSnapshot::Ready => Ok("ready"),
        ReadinessSnapshot::Unavailable(message) => Err(AppError::Unavailable(message.into())),
    }
}

fn upload_storage_ready(state: crate::services::upload_safety::UploadSafetyState) -> bool {
    matches!(
        state,
        crate::services::upload_safety::UploadSafetyState::Disabled
            | crate::services::upload_safety::UploadSafetyState::Healthy
            | crate::services::upload_safety::UploadSafetyState::RecoveryDraining
    )
}

async fn probe_readiness(context: &ReadinessContext) -> ReadinessSnapshot {
    let cluster_authority = context.cluster_authority_snapshot();
    let persistence_probe = context.validate_persistence(cluster_authority.as_ref());
    match tokio::time::timeout(READINESS_PROBE_TIMEOUT, persistence_probe).await {
        Ok(Ok(())) => {
            // An instance lease may be replaced while the persistence query is
            // in flight. Never report ready for a superseded local epoch.
            if cluster_authority != context.cluster_authority_snapshot() {
                tracing::warn!("readiness cluster authority changed during persistence probe");
                return ReadinessSnapshot::Unavailable(
                    "database or persisted security authority is not ready",
                );
            }
            if !context.sm_ready() {
                return ReadinessSnapshot::Unavailable(
                    "XEP-0198 memory or recovery capacity is not ready",
                );
            }
            let upload_state = context.upload_state();
            if !upload_storage_ready(upload_state) {
                tracing::warn!(?upload_state, "readiness upload authority probe failed");
                return ReadinessSnapshot::Unavailable("upload storage authority is not ready");
            }
            if let Some(error) = context.cluster_error() {
                tracing::warn!(%error, "readiness cluster policy probe failed");
                return ReadinessSnapshot::Unavailable("cluster policy is not ready");
            }
            if let Some(error) = context.worker_error() {
                tracing::warn!(%error, "readiness worker probe failed");
                ReadinessSnapshot::Unavailable("background workers are not ready")
            } else {
                ReadinessSnapshot::Ready
            }
        }
        Ok(Err(error)) => {
            tracing::error!(?error, "readiness persistence authority probe failed");
            ReadinessSnapshot::Unavailable("database or persisted security authority is not ready")
        }
        Err(_) => ReadinessSnapshot::Unavailable("readiness persistence authority probe timed out"),
    }
}

pub async fn metrics(
    State(endpoint): State<Arc<MetricsEndpointState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Response {
    if !metrics_request_authorized(&endpoint.context, peer.ip(), &headers) {
        let mut response = (StatusCode::UNAUTHORIZED, "unauthorized\n").into_response();
        response.headers_mut().insert(
            header::WWW_AUTHENTICATE,
            "Bearer realm=\"northstar-metrics\"".parse().unwrap(),
        );
        return response;
    }
    if let Some(body) = endpoint.cached().await {
        return metrics_response(body);
    }
    let permit =
        match tokio::time::timeout(Duration::from_millis(250), endpoint.gate.acquire()).await {
            Ok(Ok(permit)) => permit,
            _ => return (StatusCode::SERVICE_UNAVAILABLE, "collector busy\n").into_response(),
        };
    if let Some(body) = endpoint.cached().await {
        drop(permit);
        return metrics_response(body);
    }
    let body = collect_metrics(&endpoint.context).await;
    *endpoint.cache.lock().await = Some((Instant::now(), body.clone()));
    drop(permit);
    metrics_response(body)
}

fn metrics_request_authorized(context: &MetricsContext, peer: IpAddr, headers: &HeaderMap) -> bool {
    context.authorized(peer, metrics_bearer_candidate(headers))
}

fn metrics_bearer_candidate(headers: &HeaderMap) -> Option<&str> {
    // Reject duplicate field-lines instead of selecting whichever value
    // HeaderMap happens to return first.  Proxies and origin servers are not
    // guaranteed to make the same choice for a non-list Authorization field;
    // accepting one of several values would therefore create a credential
    // smuggling boundary on the only remotely reachable metrics profile.
    let mut authorizations = headers.get_all(header::AUTHORIZATION).iter();
    let authorization = authorizations.next()?;
    if authorizations.next().is_some() {
        return None;
    }
    let authorization = authorization.to_str().ok()?;
    let mut fields = authorization.split_ascii_whitespace();
    let scheme = fields.next()?;
    let candidate = fields.next()?;
    if !scheme.eq_ignore_ascii_case("Bearer") || fields.next().is_some() {
        return None;
    }
    Some(candidate)
}

#[cfg(test)]
fn metrics_credentials_authorized(
    expected: Option<&str>,
    peer: IpAddr,
    headers: &HeaderMap,
) -> bool {
    let Some(expected) = expected else {
        return peer.is_loopback();
    };
    metrics_bearer_candidate(headers).is_some_and(|candidate| {
        candidate.len() == expected.len()
            && bool::from(candidate.as_bytes().ct_eq(expected.as_bytes()))
    })
}

fn metrics_response(body: String) -> Response {
    (
        [
            (header::CONTENT_TYPE, "text/plain; version=0.0.4"),
            (header::CACHE_CONTROL, "no-store"),
        ],
        body,
    )
        .into_response()
}

async fn collect_metrics(context: &MetricsContext) -> String {
    let ping_started = std::time::Instant::now();
    let database_up = tokio::time::timeout(std::time::Duration::from_secs(2), context.ping())
        .await
        .is_ok_and(|result| result.is_ok());
    let database_ping_duration = ping_started.elapsed();
    context.record_database_ping(database_ping_duration);
    let database_ping_seconds = database_ping_duration.as_secs_f64();
    let pool_status = context.pool_status();
    let collector =
        tokio::time::timeout(std::time::Duration::from_secs(2), context.collect()).await;
    let collector = match collector {
        Ok(Ok(snapshot)) => Some(snapshot),
        Ok(Err(error)) => {
            tracing::debug!(?error, "database metrics snapshot failed");
            None
        }
        Err(_) => {
            tracing::debug!("database metrics snapshot exceeded its total deadline");
            None
        }
    };
    let process = context.process_snapshot();
    let mut body = crate::services::metrics_snapshot::render_process_gauges(
        database_up,
        database_ping_seconds,
        pool_status,
        &process,
    );
    body.push_str(&render_password_work_metrics(
        northstar_security::password_work::rejections_total(),
    ));
    body.push_str(&northstar_telemetry::logging::render_metrics());
    body.push_str(&render_database_collector(collector.as_ref()));
    let sm = context.sm_snapshot();
    body.push_str(&crate::services::metrics_snapshot::render_sm_recovery_gauges(&sm));
    body
}

fn render_password_work_metrics(rejections_total: u64) -> String {
    format!(
        concat!(
            "# HELP xmpp_password_work_rejections_total Password hashing or verification requests rejected by the bounded CPU admission gate.\n",
            "# TYPE xmpp_password_work_rejections_total counter\n",
            "xmpp_password_work_rejections_total {}\n"
        ),
        rejections_total
    )
}

fn render_database_collector(snapshot: Option<&DatabaseMetricsSnapshot>) -> String {
    let mut body = format!(
        "# TYPE xmpp_database_collector_up gauge\nxmpp_database_collector_up {}\n",
        u8::from(snapshot.is_some())
    );
    let Some((
        resumable_sessions,
        outbox,
        operations,
        admin_cleanup,
        moderation,
        governance,
        capacity,
    )) = snapshot
    else {
        return body;
    };
    body.push_str(&format!(
        concat!(
            "# TYPE xmpp_resumable_sessions gauge\n",
            "xmpp_resumable_sessions {}\n",
            "# TYPE xmpp_s2s_outbox_pending_rows gauge\n",
            "xmpp_s2s_outbox_pending_rows {}\n",
            "# TYPE xmpp_s2s_outbox_pending_bytes gauge\n",
            "xmpp_s2s_outbox_pending_bytes {}\n",
            "# TYPE xmpp_s2s_outbox_oldest_age_seconds gauge\n",
            "xmpp_s2s_outbox_oldest_age_seconds {:.6}\n",
            "# TYPE xmpp_s2s_outbox_due_rows gauge\n",
            "xmpp_s2s_outbox_due_rows {}\n",
            "# TYPE xmpp_s2s_outbox_locked_rows gauge\n",
            "xmpp_s2s_outbox_locked_rows {}\n",
            "# TYPE xmpp_component_outbox_pending_rows gauge\n",
            "xmpp_component_outbox_pending_rows {}\n",
            "# TYPE xmpp_api_operations_pending gauge\n",
            "xmpp_api_operations_pending {}\n",
            "# TYPE xmpp_api_operations_running gauge\n",
            "xmpp_api_operations_running {}\n",
            "# TYPE xmpp_api_operations_indeterminate gauge\n",
            "xmpp_api_operations_indeterminate {}\n",
            "# TYPE xmpp_api_operations_oldest_active_age_seconds gauge\n",
            "xmpp_api_operations_oldest_active_age_seconds {:.6}\n",
            "# TYPE xmpp_admin_session_cleanup_pending gauge\n",
            "xmpp_admin_session_cleanup_pending {}\n",
            "# TYPE xmpp_admin_session_cleanup_running gauge\n",
            "xmpp_admin_session_cleanup_running {}\n",
            "# TYPE xmpp_admin_session_cleanup_oldest_age_seconds gauge\n",
            "xmpp_admin_session_cleanup_oldest_age_seconds {:.6}\n",
            "# TYPE xmpp_admin_session_cleanup_maximum_attempts gauge\n",
            "xmpp_admin_session_cleanup_maximum_attempts {}\n",
            "# TYPE xmpp_admin_session_cleanup_capacity_used gauge\n",
            "xmpp_admin_session_cleanup_capacity_used {}\n",
            "# TYPE xmpp_admin_session_cleanup_capacity_limit gauge\n",
            "xmpp_admin_session_cleanup_capacity_limit {}\n",
            "# TYPE xmpp_moderation_pending_reports gauge\n",
            "xmpp_moderation_pending_reports {}\n",
            "# TYPE xmpp_moderation_pending_appeals gauge\n",
            "xmpp_moderation_pending_appeals {}\n",
            "# TYPE xmpp_active_invitation_tokens gauge\n",
            "xmpp_active_invitation_tokens {}\n",
            "# TYPE xmpp_legal_holds_active gauge\n",
            "xmpp_legal_holds_active {}\n",
            "# TYPE xmpp_legal_hold_preserved_offline_records gauge\n",
            "xmpp_legal_hold_preserved_offline_records {}\n",
            "# TYPE xmpp_governance_export_leases_active gauge\n",
            "xmpp_governance_export_leases_active {}\n",
            "# TYPE xmpp_governance_export_leases_expired_incomplete gauge\n",
            "xmpp_governance_export_leases_expired_incomplete {}\n",
            "# TYPE xmpp_capacity_accounts_used gauge\n",
            "xmpp_capacity_accounts_used {}\n",
            "# TYPE xmpp_capacity_accounts_limit gauge\n",
            "xmpp_capacity_accounts_limit {}\n",
            "# TYPE xmpp_capacity_muc_rooms_used gauge\n",
            "xmpp_capacity_muc_rooms_used {}\n",
            "# TYPE xmpp_capacity_muc_rooms_limit gauge\n",
            "xmpp_capacity_muc_rooms_limit {}\n",
            "# TYPE xmpp_capacity_live_sessions_used gauge\n",
            "xmpp_capacity_live_sessions_used {}\n",
            "# TYPE xmpp_capacity_live_sessions_limit gauge\n",
            "xmpp_capacity_live_sessions_limit {}\n",
            "# TYPE xmpp_capacity_resumable_sessions_used gauge\n",
            "xmpp_capacity_resumable_sessions_used {}\n",
            "# TYPE xmpp_capacity_resumable_sessions_limit gauge\n",
            "xmpp_capacity_resumable_sessions_limit {}\n",
            "# TYPE xmpp_capacity_configuration_epoch gauge\n",
            "xmpp_capacity_configuration_epoch {}\n",
            "# TYPE xmpp_capacity_muc_rooms_per_owner_limit gauge\n",
            "xmpp_capacity_muc_rooms_per_owner_limit {}\n",
            "# TYPE xmpp_capacity_sessions_per_account_limit gauge\n",
            "xmpp_capacity_sessions_per_account_limit {}\n"
        ),
        resumable_sessions,
        outbox.pending_rows,
        outbox.pending_bytes,
        outbox.oldest_age_seconds,
        outbox.due_rows,
        outbox.locked_rows,
        outbox.component_pending_rows,
        operations.pending,
        operations.running,
        operations.indeterminate,
        operations.oldest_active_age_seconds,
        admin_cleanup.pending,
        admin_cleanup.running,
        admin_cleanup.oldest_age_seconds,
        admin_cleanup.maximum_attempts,
        admin_cleanup.queued,
        admin_cleanup.capacity,
        moderation.0,
        moderation.1,
        moderation.2,
        governance.active_holds,
        governance.preserved_offline_records,
        governance.active_export_leases,
        governance.expired_incomplete_export_leases,
        capacity.accounts_used,
        capacity.accounts_limit,
        capacity.muc_rooms_used,
        capacity.muc_rooms_limit,
        capacity.live_sessions_used,
        capacity.live_sessions_limit,
        capacity.resumable_sessions_used,
        capacity.resumable_sessions_limit,
        capacity.configuration_epoch,
        capacity.muc_rooms_per_owner_limit,
        capacity.sessions_per_account_limit,
    ));
    body
}

pub async fn websocket(
    ws: WebSocketUpgrade,
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Response {
    let policy = state.public_discovery_context().policy();
    if !secure_websocket_request(
        peer.ip(),
        &headers,
        &policy.trusted_proxy_ips,
        &policy.public_url,
    ) {
        return (
            axum::http::StatusCode::BAD_REQUEST,
            "the XMPP WebSocket endpoint requires a secure WSS transport",
        )
            .into_response();
    }
    if !allowed_websocket_origin(
        &headers,
        &policy.public_url,
        &policy.websocket_allowed_origins,
    ) {
        return (
            axum::http::StatusCode::FORBIDDEN,
            "the WebSocket Origin is not permitted",
        )
            .into_response();
    }
    if !offers_xmpp_subprotocol(&headers) {
        return (
            axum::http::StatusCode::BAD_REQUEST,
            "the xmpp WebSocket subprotocol is required",
        )
            .into_response();
    }
    let peer_ip = client_ip(peer.ip(), &headers, &state);
    let Some(connection_guard) = state.acquire_client_connection(peer_ip) else {
        return axum::http::StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    ws.protocols(["xmpp"])
        // Grow for large stanzas instead of reserving 128 KiB per idle client.
        .read_buffer_size(8 * 1024)
        .max_message_size(1024 * 1024)
        .max_frame_size(1024 * 1024)
        .on_upgrade(move |socket| async move {
            let actors = state.connection_actors().clone();
            let actor_shutdown = actors.shutdown_token().child_token();
            let result = actors.try_spawn(
                northstar_runtime::connection_actors::ConnectionActorKind::C2sWebSocket,
                Some(peer_ip.to_string()),
                async move {
                    let _connection_guard = connection_guard;
                    xmpp::websocket_connection(socket, state, peer_ip, actor_shutdown).await;
                },
            );
            if let Err(error) = result {
                tracing::debug!(%peer_ip, ?error, "rejected WebSocket connection actor admission");
            }
        })
}

fn secure_websocket_request(
    peer_ip: IpAddr,
    headers: &HeaderMap,
    trusted: &[IpAddr],
    public_url: &str,
) -> bool {
    let mut forwarded = headers.get_all("x-forwarded-proto").iter();
    match (forwarded.next(), forwarded.next()) {
        (None, None) => {
            // Plain `ws://` is a development-only exception. Tying it to an
            // explicitly loopback PUBLIC_URL prevents a production reverse
            // proxy that forgot X-Forwarded-Proto from silently downgrading
            // every external XMPP login to a transport the protocol treats
            // as encrypted.
            peer_ip.is_loopback() && development_loopback_url(public_url)
        }
        (Some(value), None) => {
            trusted.contains(&peer_ip)
                && value.to_str().ok().is_some_and(|value| {
                    !value.contains(',') && value.trim().eq_ignore_ascii_case("https")
                })
        }
        _ => false,
    }
}

fn development_loopback_url(public_url: &str) -> bool {
    let Ok(uri) = public_url.parse::<axum::http::Uri>() else {
        return false;
    };
    uri.scheme_str()
        .is_some_and(|scheme| scheme.eq_ignore_ascii_case("http"))
        && uri
            .authority()
            .is_some_and(|authority| origin_host_is_loopback(authority.host()))
}

fn allowed_websocket_origin(
    headers: &HeaderMap,
    public_url: &str,
    configured_origins: &[String],
) -> bool {
    let mut origins = headers.get_all(header::ORIGIN).iter();
    let origin = match (origins.next(), origins.next()) {
        (None, None) => return true,
        (Some(origin), None) => match origin.to_str() {
            Ok(origin) if !origin.contains(',') && origin.len() <= 2_048 => origin,
            _ => return false,
        },
        _ => return false,
    };
    let Some(origin) = crate::platform::config::canonical_web_origin(origin) else {
        return false;
    };
    crate::platform::config::canonical_public_web_origin(public_url).as_ref() == Some(&origin)
        || configured_origins
            .iter()
            .any(|configured| configured == &origin)
}

fn origin_host_is_loopback(host: &str) -> bool {
    let host = host
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
        .unwrap_or(host);
    host.eq_ignore_ascii_case("localhost")
        || host
            .strip_suffix(".localhost")
            .is_some_and(|prefix| !prefix.is_empty())
        || host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
}

fn offers_xmpp_subprotocol(headers: &HeaderMap) -> bool {
    headers
        .get_all(header::SEC_WEBSOCKET_PROTOCOL)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .any(|protocol| protocol.trim() == "xmpp")
}

pub async fn public_config(
    State(state): State<crate::api::contexts::PublicDiscoveryContext>,
) -> Json<Value> {
    let policy = state.policy();
    let registration_mode = state.registration_mode();
    let open_registration = registration_mode != crate::platform::config::RegistrationMode::Closed;
    let registration_mode = match registration_mode {
        crate::platform::config::RegistrationMode::Closed => "closed",
        crate::platform::config::RegistrationMode::Open => "open",
        crate::platform::config::RegistrationMode::InvitationOnly => "invitation",
    };
    let federation_enabled = state.federation_enabled();
    Json(json!({
        "domain":policy.domain,
        "public_url":policy.public_url,
        "open_registration":open_registration,
        "invitation_required":state.registration_requires_invitation(),
        "registration_mode":registration_mode,
        "registration_dependency_locked":state.registration_opening_is_dependency_locked(),
        "archive_policy":if policy.require_encrypted_archive {"encrypted_only"} else {"all"},
        "websocket_path":policy.websocket_enabled.then_some("/xmpp-websocket")
        ,"bosh_path":(policy.bosh_enabled && policy.public_url.starts_with("https://")).then_some("/http-bind")
        ,"upload_max_bytes":policy.upload_mode.admits_new_uploads().then_some(policy.upload_max_bytes)
        ,"upload_download_max_bytes":policy.upload_mode.keeps_storage_runtime().then_some(policy.upload_download_max_bytes)
        ,"upload_service":policy.upload_mode.admits_new_uploads().then(||format!("upload.{}",policy.domain))
        ,"muc_service":format!("conference.{}",policy.domain)
        ,"federation_enabled":federation_enabled
        ,"pow_max_work_factor":policy.pow_max_work_factor
        ,"pow_approximate_max_device_seconds":policy.pow_max_device_seconds
        ,"capabilities":{
            "rest_api":policy.rest_api_enabled,
            "websocket":policy.websocket_enabled,
            "bosh":policy.bosh_enabled,
            "web_client":policy.web_client_enabled,
            "passkeys":policy.passkeys_enabled,
            "web_administration":policy.web_admin_enabled,
            "invitation_registration":policy.web_client_enabled,
            "upload_admission":policy.upload_mode.admits_new_uploads(),
            "upload_download":policy.upload_mode.keeps_storage_runtime(),
            "upload_mode":match policy.upload_mode {
                crate::platform::config::UploadMode::Enabled => "enabled",
                crate::platform::config::UploadMode::DrainReadOnly => "drain_read_only",
                crate::platform::config::UploadMode::Disabled => "disabled",
            }
        }
    }))
}

pub async fn host_meta_xml(
    State(state): State<crate::api::contexts::PublicDiscoveryContext>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let policy = state.policy();
    let origin = request_base_url(
        peer.ip(),
        &headers,
        &policy.trusted_proxy_ips,
        &policy.domain,
        &policy.public_url,
    );
    let ws_href = policy
        .websocket_enabled
        .then(|| secure_websocket_url(&origin));
    let bosh_href = advertised_bosh_url(policy.bosh_enabled, &policy.public_url);

    let bosh_link = bosh_href.as_deref().map_or_else(String::new, |href| {
        format!(
            "\x20\x20<Link rel=\"urn:xmpp:alt-connections:xbosh\" href=\"{}\" />\n",
            crate::platform::jid_text::attr_escape(href)
        )
    });
    let websocket_link = ws_href.as_deref().map_or_else(String::new, |href| {
        format!(
            "\x20\x20<Link rel=\"urn:xmpp:alt-connections:websocket\" href=\"{}\" />\n",
            crate::platform::jid_text::attr_escape(href)
        )
    });
    let xml = format!(
        "<?xml version='1.0' encoding='utf-8'?>\n\
         <XRD xmlns='http://docs.oasis-open.org/ns/xri/xrd-1.0'>\n\
         {}{}\
         </XRD>",
        websocket_link, bosh_link,
    );

    (
        [
            (header::CONTENT_TYPE, "application/xrd+xml"),
            (header::ACCESS_CONTROL_ALLOW_ORIGIN, "*"),
            (header::CACHE_CONTROL, "public, max-age=300"),
        ],
        xml,
    )
}

pub async fn host_meta_json(
    State(state): State<crate::api::contexts::PublicDiscoveryContext>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let policy = state.policy();
    let origin = request_base_url(
        peer.ip(),
        &headers,
        &policy.trusted_proxy_ips,
        &policy.domain,
        &policy.public_url,
    );
    let ws_href = policy
        .websocket_enabled
        .then(|| secure_websocket_url(&origin));
    let bosh_href = advertised_bosh_url(policy.bosh_enabled, &policy.public_url);
    let federation_enabled = state.federation_enabled();
    let json_body = host_meta_json_document(
        ws_href.as_deref(),
        bosh_href.as_deref(),
        &policy.domain,
        &policy.xep_0487_ips,
        policy.xep_0487_ttl_seconds,
        policy.xep_0487_priority,
        policy.xep_0487_weight,
        policy.xmpps_port,
        federation_enabled.then_some(policy.s2s_tls_port),
    );
    let cache_control = header::HeaderValue::from_str(&format!(
        "public, max-age={}",
        if policy.xep_0487_ips.is_empty() {
            300
        } else {
            policy.xep_0487_ttl_seconds
        }
    ))
    .expect("validated XEP-0487 TTL always forms a valid header");

    (
        [
            (
                header::CONTENT_TYPE,
                header::HeaderValue::from_static("application/jrd+json"),
            ),
            (
                header::ACCESS_CONTROL_ALLOW_ORIGIN,
                header::HeaderValue::from_static("*"),
            ),
            (header::CACHE_CONTROL, cache_control),
        ],
        Json(json_body),
    )
}

#[allow(clippy::too_many_arguments)]
fn host_meta_json_document(
    ws_href: Option<&str>,
    bosh_href: Option<&str>,
    domain: &str,
    ips: &[IpAddr],
    ttl_seconds: u64,
    priority: u16,
    weight: u16,
    c2s_tls_port: u16,
    s2s_tls_port: Option<u16>,
) -> Value {
    if ips.is_empty() {
        let mut links = Vec::new();
        if let Some(ws_href) = ws_href {
            links.push(json!({
                "rel": "urn:xmpp:alt-connections:websocket",
                "href": ws_href
            }));
        }
        if let Some(bosh_href) = bosh_href {
            links.push(json!({
                "rel": "urn:xmpp:alt-connections:xbosh",
                "href": bosh_href
            }));
        }
        return json!({ "links": links });
    }

    let ips = ips.iter().map(ToString::to_string).collect::<Vec<_>>();
    let mut links = Vec::new();
    if let Some(ws_href) = ws_href {
        links.push(json!({
            "rel": "urn:xmpp:alt-connections:websocket",
            "href": ws_href,
            "ips": &ips,
            "priority": priority,
            "weight": weight,
            "sni": domain
        }));
    }
    if let Some(bosh_href) = bosh_href {
        links.push(json!({
            "rel": "urn:xmpp:alt-connections:xbosh",
            "href": bosh_href,
            "ips": &ips,
            "priority": priority,
            "weight": weight,
            "sni": domain
        }));
    }
    if c2s_tls_port != 0 {
        links.push(json!({
            "rel": "urn:xmpp:alt-connections:tls",
            "port": c2s_tls_port,
            "ips": &ips,
            "priority": priority,
            "weight": weight,
            "sni": domain
        }));
    }
    if let Some(port) = s2s_tls_port.filter(|port| *port != 0) {
        links.push(json!({
            "rel": "urn:xmpp:alt-connections:s2s-tls",
            "port": port,
            "ips": &ips,
            "priority": priority,
            "weight": weight,
            "sni": domain
        }));
    }
    json!({
        "xmpp": { "ttl": ttl_seconds },
        "links": links
    })
}

fn secure_websocket_url(origin: &str) -> String {
    let authority = origin
        .strip_prefix("https://")
        .or_else(|| origin.strip_prefix("http://"))
        .unwrap_or(origin)
        .trim_end_matches('/');
    format!("wss://{authority}/xmpp-websocket")
}

fn advertised_bosh_url(enabled: bool, public_url: &str) -> Option<String> {
    (enabled && public_url.starts_with("https://"))
        .then(|| format!("{}/http-bind", public_url.trim_end_matches('/')))
}

fn request_base_url(
    peer_ip: IpAddr,
    headers: &HeaderMap,
    trusted_proxy_ips: &[IpAddr],
    domain: &str,
    public_url: &str,
) -> String {
    let is_trusted = trusted_proxy_ips.contains(&peer_ip);

    let host = if is_trusted {
        headers
            .get("x-forwarded-host")
            .and_then(|h| h.to_str().ok())
            .or_else(|| headers.get(header::HOST).and_then(|h| h.to_str().ok()))
    } else {
        headers.get(header::HOST).and_then(|h| h.to_str().ok())
    };

    let forwarded_scheme = if is_trusted {
        headers
            .get("x-forwarded-proto")
            .and_then(|h| h.to_str().ok())
            .or_else(|| {
                headers
                    .get("x-forwarded-scheme")
                    .and_then(|h| h.to_str().ok())
            })
            .unwrap_or("https")
    } else {
        "https"
    };
    let scheme = match forwarded_scheme {
        "http" | "https" => forwarded_scheme,
        _ => "https",
    };

    if let Some(host) = host {
        if let Ok(authority) = axum::http::uri::Authority::from_str(host) {
            let host_name = authority.host();
            if is_trusted
                || host_name.eq_ignore_ascii_case(domain)
                || host_name.eq_ignore_ascii_case("localhost")
            {
                return format!("{scheme}://{authority}");
            }
        }
    }

    public_url.to_owned()
}

#[cfg(test)]
mod tests;
