use axum::{
    body::{to_bytes, Body},
    extract::{ConnectInfo, FromRequest, FromRequestParts, Request, State},
    http::{header, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post, put},
    Json, Router,
};
use serde::de::DeserializeOwned;
use serde_json::json;
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::{atomic::Ordering, Arc};

use crate::abuse::AbuseAction;
use crate::auth;
use crate::db;
use crate::error::{AppError, Result};
use crate::state::AppState;

use crate::abuse::GuardError;
use axum::extract::DefaultBodyLimit;
use axum::http::header::{HeaderMap, HeaderName, HeaderValue};
use axum::routing::{delete, options, patch};
use std::net::IpAddr;
use std::ops::Deref;
use tower_http::services::{ServeDir, ServeFile};
use tower_http::set_header::SetResponseHeaderLayer;
use tower_http::trace::TraceLayer;

use axum::http::request::Parts;

pub mod extract;
pub use extract::{ApiPath, ApiQuery};

const API_BODY_LIMIT_BYTES: usize = 256 * 1024;
const API_TOKEN_LENGTH: usize = 64;
const API_IDEMPOTENCY_TTL_SECONDS: i64 = 24 * 60 * 60;
const API_IDEMPOTENCY_LEASE_SECONDS: i64 = 180;
const SPA_CONTENT_SECURITY_POLICY: &str = "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; img-src 'self' data: blob:; font-src 'self'; connect-src 'self'; media-src 'self' blob:; worker-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'";
const WEB_CLIENT_STATIC_FILES: &[(&str, &str)] = &[
    ("/client.css", "web/client.css"),
    ("/client.js", "web/client.js"),
    ("/avatar-editor.js", "web/avatar-editor.js"),
    ("/i18n.css", "web/i18n.css"),
    ("/i18n.js", "web/i18n.js"),
    ("/locales.generated.js", "web/locales.generated.js"),
    ("/xmpp.js", "web/xmpp.js"),
    ("/storage.js", "web/storage.js"),
    ("/pow.js", "web/pow.js"),
    ("/pow-worker.js", "web/pow-worker.js"),
    ("/outbox-delivery.js", "web/outbox-delivery.js"),
    ("/omemo.js", "web/omemo.js"),
    ("/omemo-recovery.mjs", "web/omemo-recovery.mjs"),
    (
        "/omemo-recovery-worker-client.mjs",
        "web/omemo-recovery-worker-client.mjs",
    ),
    (
        "/omemo-recovery-worker.mjs",
        "web/omemo-recovery-worker.mjs",
    ),
    (
        "/omemo-state-validation.mjs",
        "web/omemo-state-validation.mjs",
    ),
];
const WEB_ADMIN_STATIC_FILES: &[(&str, &str)] = &[
    ("/app.js", "web/app.js"),
    ("/admin.css", "web/admin.css"),
    ("/styles.css", "web/styles.css"),
    ("/i18n.css", "web/i18n.css"),
    ("/i18n.js", "web/i18n.js"),
    ("/locales.generated.js", "web/locales.generated.js"),
];

#[derive(Clone, Copy, Debug)]
pub struct ApiRequestId(pub uuid::Uuid);

pub struct ApiJson<T> {
    pub value: T,
    request_id: ApiRequestId,
    request_fingerprint: [u8; 32],
    idempotency_key: String,
}

pub struct ApiEmpty {
    request_id: ApiRequestId,
    request_fingerprint: [u8; 32],
    idempotency_key: String,
}

fn idempotency_key(headers: &HeaderMap) -> Result<String, AppError> {
    let mut keys = headers.get_all("idempotency-key").iter();
    let key = match (keys.next(), keys.next()) {
        (None, None) => None,
        (Some(value), None) => Some(
            value
                .to_str()
                .map_err(|_| AppError::BadRequest("Idempotency-Key is invalid".into()))?
                .to_owned(),
        ),
        _ => {
            return Err(AppError::BadRequest(
                "exactly one Idempotency-Key header is allowed".into(),
            ));
        }
    };
    if key.as_ref().is_some_and(|key| {
        !(8..=200).contains(&key.len()) || !key.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
    }) {
        return Err(AppError::BadRequest(
            "Idempotency-Key must contain 8 to 200 visible ASCII bytes".into(),
        ));
    }
    Ok(key.unwrap_or_else(|| uuid::Uuid::new_v4().to_string()))
}

impl<T> Deref for ApiJson<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.value
    }
}

impl<S, T> FromRequest<S> for ApiJson<T>
where
    S: Send + Sync,
    T: DeserializeOwned,
{
    type Rejection = AppError;

    async fn from_request(request: Request, _state: &S) -> Result<Self, Self::Rejection> {
        let media_type = request
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split(';').next())
            .map(str::trim)
            .map(str::to_ascii_lowercase)
            .filter(|value| value == "application/json" || value.ends_with("+json"))
            .ok_or_else(|| AppError::BadRequest("Content-Type must be application/json".into()))?;
        let idempotency_key = idempotency_key(request.headers())?;
        let request_id = request
            .extensions()
            .get::<ApiRequestId>()
            .copied()
            .unwrap_or_else(|| ApiRequestId(uuid::Uuid::new_v4()));
        let bytes = to_bytes(request.into_body(), API_BODY_LIMIT_BYTES)
            .await
            .map_err(|_| AppError::PayloadTooLarge)?;
        let value = serde_json::from_slice(&bytes)
            .map_err(|_| AppError::BadRequest("request body is not valid JSON".into()))?;
        Ok(Self {
            value,
            request_id,
            request_fingerprint: db::api_request_fingerprint(&media_type, &bytes),
            idempotency_key,
        })
    }
}

impl<S> FromRequest<S> for ApiEmpty
where
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request(request: Request, _state: &S) -> Result<Self, Self::Rejection> {
        let request_id = request
            .extensions()
            .get::<ApiRequestId>()
            .copied()
            .unwrap_or_else(|| ApiRequestId(uuid::Uuid::new_v4()));
        let idempotency_key = idempotency_key(request.headers())?;
        let bytes = to_bytes(request.into_body(), 1)
            .await
            .map_err(|_| AppError::BadRequest("request body must be empty".into()))?;
        if !bytes.is_empty() {
            return Err(AppError::BadRequest("request body must be empty".into()));
        }
        Ok(Self {
            request_id,
            request_fingerprint: db::api_request_fingerprint("", &bytes),
            idempotency_key,
        })
    }
}

impl<T> ApiJson<T> {
    pub fn idempotency<'a>(
        &'a self,
        actor_id: Option<uuid::Uuid>,
        principal_scope: &'a [u8],
        principal_kind: db::ApiPrincipalKind,
        method: &'a str,
        route: &'a str,
    ) -> db::IdempotencyRequest<'a> {
        db::IdempotencyRequest {
            request_id: self.request_id.0,
            actor_id,
            principal_scope,
            capacity_scope: principal_scope,
            target_scope: b"",
            principal_kind,
            method,
            route,
            idempotency_key: &self.idempotency_key,
            request_fingerprint: self.request_fingerprint,
            ttl_seconds: API_IDEMPOTENCY_TTL_SECONDS,
            lease_seconds: API_IDEMPOTENCY_LEASE_SECONDS,
        }
    }
}

impl ApiEmpty {
    pub fn idempotency<'a>(
        &'a self,
        actor_id: Option<uuid::Uuid>,
        principal_scope: &'a [u8],
        principal_kind: db::ApiPrincipalKind,
        method: &'a str,
        route: &'a str,
    ) -> db::IdempotencyRequest<'a> {
        db::IdempotencyRequest {
            request_id: self.request_id.0,
            actor_id,
            principal_scope,
            capacity_scope: principal_scope,
            target_scope: b"",
            principal_kind,
            method,
            route,
            idempotency_key: &self.idempotency_key,
            request_fingerprint: self.request_fingerprint,
            ttl_seconds: API_IDEMPOTENCY_TTL_SECONDS,
            lease_seconds: API_IDEMPOTENCY_LEASE_SECONDS,
        }
    }
}

pub fn json_replay_headers() -> BTreeMap<String, String> {
    BTreeMap::from([
        ("cache-control".to_owned(), "no-store, max-age=0".to_owned()),
        ("content-type".to_owned(), "application/json".to_owned()),
    ])
}

pub fn idempotency_replay_response(replay: db::IdempotentResponse) -> Result<Response, AppError> {
    let status =
        StatusCode::from_u16(replay.status).map_err(|error| AppError::Internal(error.into()))?;
    let mut response = Response::builder().status(status);
    for (name, value) in replay.headers {
        response = response.header(name, value);
    }
    response = response.header("idempotency-replayed", "true").header(
        "idempotency-original-request-id",
        replay.request_id.to_string(),
    );
    response
        .body(Body::from(replay.body))
        .map_err(|error| AppError::Internal(error.into()))
}

pub fn json_bytes_response(status: StatusCode, body: Vec<u8>) -> Result<Response, AppError> {
    Response::builder()
        .status(status)
        .header(header::CACHE_CONTROL, "no-store, max-age=0")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body))
        .map_err(|error| AppError::Internal(error.into()))
}

pub mod models;
pub use models::*;
pub mod auth_routes;
pub mod cursor;
pub mod data_lifecycle;
pub(crate) mod idempotency;
pub mod pagination;
pub use auth_routes::*;
pub use data_lifecycle::*;
pub mod admin;
pub mod omemo_recovery;
pub mod operations;
pub mod reports;
pub mod system;
pub mod upload;
pub mod upload_admin;
pub mod users;

pub use admin::*;
pub use omemo_recovery::*;
pub use operations::*;
pub use reports::*;
pub use system::*;
pub use upload::*;
pub use upload_admin::*;
pub use users::*;

fn public_rest_routes() -> Router<Arc<AppState>> {
    Router::new()
        // Keep the API namespace out of every static fallback. Without an
        // explicit root route, a file service can turn a missing API endpoint
        // into an HTML 200 response.
        .route("/api", get(api_root_not_found))
        .route("/api/openapi.yaml", get(openapi_document))
        .route("/api/docs", get(api_docs))
        .nest_service(
            "/api/docs/assets/5.32.14",
            ServeDir::new("third_party/swagger-ui/dist"),
        )
        .route("/api/v1/config", get(public_config))
        .route("/api/v1/register", post(register))
        .route("/api/v1/anti-abuse/challenge", post(anti_abuse_challenge))
        .route("/api/v1/login", post(login))
        .route("/api/v1/session", delete(logout))
        .route("/api/v1/me", get(me))
        .route(
            "/api/v1/me/retention",
            get(get_my_retention).put(update_my_retention),
        )
        .route("/api/v1/me/password", patch(change_password))
        .route(
            "/api/v1/me/omemo-recovery-transfers",
            post(prepare_omemo_recovery),
        )
        .route(
            "/api/v1/me/omemo-recovery-authority",
            get(get_omemo_recovery_authority),
        )
        .route(
            "/api/v1/me/omemo-recovery-transfers/{id}",
            get(get_omemo_recovery)
                .put(seal_omemo_recovery)
                .delete(revoke_omemo_recovery),
        )
        .route(
            "/api/v1/me/omemo-recovery-transfers/{id}/consume",
            post(consume_omemo_recovery),
        )
        .route(
            "/api/v1/omemo-recovery-transfers/{id}/poll",
            post(poll_omemo_recovery),
        )
        .route("/api/v1/history", get(history))
        .route("/api/v1/reports", get(my_reports).post(create_report))
        .route("/api/v1/reports/{id}/appeals", post(create_appeal))
        .route(
            "/api/v1/muc_rooms/{id}/retention",
            get(get_muc_retention).put(update_muc_retention),
        )
}

fn upload_http_routes(upload_limit: usize, admission_enabled: bool) -> Router<Arc<AppState>> {
    let router = Router::new().route("/uploads/{id}", get(upload_get));
    if admission_enabled {
        router.route(
            "/api/v1/upload/{id}",
            put(upload_put)
                .delete(upload_delete)
                // The storage reader deliberately consumes one byte beyond
                // the reserved size to distinguish an oversized stream from
                // an exact upload without buffering it.
                .layer(DefaultBodyLimit::max(upload_limit.saturating_add(1))),
        )
    } else {
        router.route("/api/v1/upload/{id}", delete(upload_delete))
    }
}

fn administrator_api_routes(
    upload_runtime_enabled: bool,
    invitation_enabled: bool,
) -> Router<Arc<AppState>> {
    // Authentication and public config are duplicated intentionally on the
    // private administration origin: the admin SPA never needs cross-origin
    // access to the public REST listener.
    let router = Router::new()
        .route("/api", get(api_root_not_found))
        .route("/api/v1/config", get(public_config))
        .route("/api/v1/login", post(login))
        .route("/api/v1/session", delete(logout))
        .route("/api/v1/admin/stats", get(admin_stats))
        .route("/api/v1/admin/nuke", post(admin_nuke))
        .route(
            "/api/v1/admin/panic_disconnect",
            post(admin_panic_disconnect),
        )
        .route("/api/v1/admin/island_mode", post(admin_toggle_island_mode))
        .route(
            "/api/v1/admin/registration",
            post(admin_toggle_registration),
        )
        .route("/api/v1/admin/sessions", get(admin_sessions))
        .route(
            "/api/v1/admin/sessions/{connection_id}",
            delete(admin_kick_session),
        )
        .route(
            "/api/v1/admin/offline_messages",
            get(admin_offline_messages_stats).delete(admin_clear_offline_messages),
        )
        .route("/api/v1/admin/muc_rooms", get(admin_muc_rooms))
        .route(
            "/api/v1/admin/muc_rooms/{localpart}",
            delete(admin_destroy_muc_room),
        )
        .route("/api/v1/admin/broadcast", post(admin_broadcast))
        .route("/api/v1/admin/users", get(admin_users))
        .route("/api/v1/admin/users/{id}", patch(admin_update_user))
        .route("/api/v1/admin/reports", get(admin_reports))
        .route("/api/v1/admin/reports/{id}", patch(admin_update_report))
        .route("/api/v1/admin/appeals/{id}", patch(admin_update_appeal))
        .route("/api/v1/admin/tls/reload", post(admin_tls_reload))
        .route("/api/v1/admin/operations", get(list_operations))
        .route("/api/v1/admin/operations/{id}", get(get_operation))
        .route("/api/v1/admin/operations/{id}/targets", get(list_targets))
        .route(
            "/api/v1/admin/operations/{operation_id}/targets/{target_id}",
            get(get_target),
        )
        .route(
            "/api/v1/admin/operations/{id}/cancel",
            post(cancel_operation),
        )
        .route(
            "/api/v1/admin/operations/{id}/reconcile",
            post(reconcile_operation),
        )
        .route(
            "/api/v1/admin/operations/{operation_id}/targets/{target_id}/reconcile",
            post(reconcile_target),
        )
        .route(
            "/api/v1/admin/legal-holds",
            get(list_legal_holds).post(create_legal_hold),
        )
        .route(
            "/api/v1/admin/legal-holds/{id}/release",
            post(release_legal_hold),
        )
        .route(
            "/api/v1/admin/legal-holds/{id}/export",
            post(export_legal_hold),
        )
        .route("/api/v1/admin/audit/export", post(export_audit));
    let router = if upload_runtime_enabled {
        router
            .route(
                "/api/v1/admin/upload-dead-letters",
                get(admin_upload_dead_letters),
            )
            .route(
                "/api/v1/admin/upload-dead-letters/{kind}/{id}/retry",
                post(admin_retry_upload_dead_letter),
            )
    } else {
        router
    };
    if invitation_enabled {
        router
            .route(
                "/api/v1/admin/invitations",
                get(admin_invitations).post(admin_create_invitation),
            )
            .route(
                "/api/v1/admin/invitations/{id}",
                delete(admin_revoke_invitation),
            )
    } else {
        router
    }
}

fn web_client_static_routes() -> Router<Arc<AppState>> {
    let mut router = Router::new()
        .route_service("/", ServeFile::new("web/client.html"))
        .route_service("/client.html", ServeFile::new("web/client.html"))
        .nest_service("/crypto", ServeDir::new("web/crypto"));
    for &(route, file) in WEB_CLIENT_STATIC_FILES {
        router = router.route_service(route, ServeFile::new(file));
    }
    router
}

fn administrator_static_routes() -> Router<Arc<AppState>> {
    let mut router = Router::new()
        .route_service("/", ServeFile::new("web/index.html"))
        .route_service("/index.html", ServeFile::new("web/index.html"));
    for &(route, file) in WEB_ADMIN_STATIC_FILES {
        router = router.route_service(route, ServeFile::new(file));
    }
    router
}

fn common_http_layers(
    router: Router<Arc<AppState>>,
    state: Arc<AppState>,
    allow_plaintext_observability: bool,
) -> Router<Arc<AppState>> {
    let router = if allow_plaintext_observability {
        router.layer(middleware::from_fn_with_state(state, secure_http_transport))
    } else {
        router.layer(middleware::from_fn_with_state(
            state,
            secure_administrator_transport,
        ))
    };
    router
        .layer(SetResponseHeaderLayer::if_not_present(
            HeaderName::from_static("content-security-policy"),
            HeaderValue::from_static(SPA_CONTENT_SECURITY_POLICY),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            header::X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            header::REFERRER_POLICY,
            HeaderValue::from_static("no-referrer"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            header::X_FRAME_OPTIONS,
            HeaderValue::from_static("DENY"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            HeaderName::from_static("permissions-policy"),
            HeaderValue::from_static("camera=(), microphone=(), geolocation=(), payment=()"),
        ))
        .layer(middleware::from_fn(api_cache_policy))
        .layer(middleware::from_fn(api_error_envelope))
        .layer(
            TraceLayer::new_for_http().make_span_with(|request: &Request| {
                let request_id = request
                    .extensions()
                    .get::<ApiRequestId>()
                    .map(|value| value.0.to_string())
                    .unwrap_or_else(|| "missing".to_owned());
                tracing::info_span!(
                    "http_request",
                    request_id = %request_id,
                    http.method = %request.method(),
                    http.target = %request.uri().path()
                )
            }),
        )
        .layer(DefaultBodyLimit::max(API_BODY_LIMIT_BYTES))
        .layer(middleware::from_fn(api_request_id))
}

fn host_meta_route_contributions(websocket: bool, bosh: bool, xep_0487: bool) -> (bool, bool) {
    // XML carries the XEP-0156 WebSocket/BOSH links. JSON also carries the
    // XEP-0487 direct-TLS records and therefore has an independent lifetime.
    (websocket || bosh, websocket || bosh || xep_0487)
}

pub fn public_router(state: Arc<AppState>) -> Router {
    let readiness = ReadyEndpointState::new(Arc::clone(&state));
    let mut router = Router::new()
        .route("/healthz", get(health))
        .route("/readyz", get(ready).with_state(readiness));
    if state.config.rest_api_enabled {
        router = router.merge(public_rest_routes());
    }
    if state.config.upload_mode.keeps_storage_runtime() {
        let upload_limit = usize::try_from(state.config.upload_max_bytes).unwrap_or(usize::MAX);
        router = router.merge(upload_http_routes(
            upload_limit,
            state.config.upload_mode.admits_new_uploads(),
        ));
    }
    if state.config.websocket_enabled {
        router = router.route("/xmpp-websocket", get(websocket));
    }
    let (serve_host_meta_xml, serve_host_meta_json) = host_meta_route_contributions(
        state.config.websocket_enabled,
        state.config.bosh_enabled,
        !state.config.xep_0487_ips.is_empty(),
    );
    if serve_host_meta_xml {
        router = router.route("/.well-known/host-meta", get(host_meta_xml));
    }
    if serve_host_meta_json {
        router = router.route("/.well-known/host-meta.json", get(host_meta_json));
    }
    if state.config.bosh_enabled {
        router = router
            .route("/http-bind", post(crate::bosh::http_bind))
            .route("/http-bind", options(crate::bosh::http_bind_options))
            .route("/bosh", post(crate::bosh::http_bind))
            .route("/bosh", options(crate::bosh::http_bind_options));
    }
    if state.config.web_client_enabled {
        router = router.merge(web_client_static_routes());
    }
    common_http_layers(router, Arc::clone(&state), true).with_state(state)
}

pub fn administrator_router(state: Arc<AppState>) -> Router {
    let readiness = ReadyEndpointState::new(Arc::clone(&state));
    let router = Router::new()
        .route("/healthz", get(health))
        .route("/readyz", get(ready).with_state(readiness))
        .merge(administrator_api_routes(
            state.config.upload_mode.keeps_storage_runtime(),
            state.config.web_client_enabled,
        ))
        .merge(administrator_static_routes());
    common_http_layers(
        router.layer(middleware::from_fn_with_state(
            Arc::clone(&state),
            administrator_gateway_authentication,
        )),
        Arc::clone(&state),
        false,
    )
    .with_state(state)
}

async fn api_request_id(mut request: Request, next: Next) -> Response {
    let request_id = ApiRequestId(uuid::Uuid::new_v4());
    request.extensions_mut().insert(request_id);
    let mut response = next.run(request).await;
    if let Ok(value) = HeaderValue::from_str(&request_id.0.to_string()) {
        response
            .headers_mut()
            .insert(HeaderName::from_static("x-request-id"), value);
    }
    response
}

async fn secure_http_transport(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    request: Request,
    next: Next,
) -> Response {
    secure_http_transport_policy(state, peer, request, next, true).await
}

async fn secure_administrator_transport(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    request: Request,
    next: Next,
) -> Response {
    secure_http_transport_policy(state, peer, request, next, false).await
}

async fn secure_http_transport_policy(
    state: Arc<AppState>,
    peer: SocketAddr,
    request: Request,
    next: Next,
    allow_plaintext_observability: bool,
) -> Response {
    if secure_transport_allowed(
        allow_plaintext_observability,
        request.uri().path(),
        peer.ip(),
        request.headers(),
        &state.config.trusted_proxy_ips,
    ) {
        return next.run(request).await;
    }

    let rejected = state
        .metrics
        .http_insecure_requests_rejected_total
        .fetch_add(1, Ordering::Relaxed)
        .saturating_add(1);
    if rejected.is_power_of_two() {
        tracing::warn!(
            peer_ip = %peer.ip(),
            rejected_total = rejected,
            "rejected HTTP request without a trusted HTTPS transport assertion"
        );
    }
    let mut response = (
        StatusCode::FORBIDDEN,
        Json(json!({
            "error": {
                "code": "https_required",
                "message": "HTTPS is required for this resource"
            }
        })),
    )
        .into_response();
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("no-store, max-age=0"),
    );
    response
}

fn secure_transport_allowed(
    allow_plaintext_observability: bool,
    path: &str,
    peer_ip: IpAddr,
    headers: &HeaderMap,
    trusted: &[IpAddr],
) -> bool {
    (allow_plaintext_observability && plaintext_observability_path(path))
        || secure_http_request(peer_ip, headers, trusted)
}

async fn administrator_gateway_authentication(
    State(state): State<Arc<AppState>>,
    mut request: Request,
    next: Next,
) -> Response {
    let mut supplied = request
        .headers()
        .get_all("x-northstar-admin-gateway-token")
        .iter();
    let candidate = match (supplied.next(), supplied.next()) {
        (Some(value), None) => value.to_str().ok(),
        (None, None) => None,
        _ => return administrator_gateway_rejection(),
    };
    if state.admin_gateway_request_authorized(candidate) {
        // The proxy credential authorizes entry to this listener; it must not
        // become ambient request data visible to downstream REST handlers,
        // tracing, or future reverse-proxy integrations.
        request
            .headers_mut()
            .remove("x-northstar-admin-gateway-token");
        return next.run(request).await;
    }
    administrator_gateway_rejection()
}

fn administrator_gateway_rejection() -> Response {
    let mut response = (
        StatusCode::UNAUTHORIZED,
        Json(json!({
            "error": {
                "code": "admin_gateway_unauthorized",
                "message": "administrator gateway authentication is required"
            }
        })),
    )
        .into_response();
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("no-store, max-age=0"),
    );
    response
}

fn plaintext_observability_path(path: &str) -> bool {
    matches!(path, "/healthz" | "/readyz")
}

fn secure_http_request(peer_ip: IpAddr, headers: &HeaderMap, trusted: &[IpAddr]) -> bool {
    let mut forwarded = headers.get_all("x-forwarded-proto").iter();
    match (forwarded.next(), forwarded.next()) {
        (None, None) => peer_ip.is_loopback(),
        (Some(value), None) => {
            trusted.contains(&peer_ip)
                && value.to_str().ok().is_some_and(|value| {
                    !value.contains(',') && value.trim().eq_ignore_ascii_case("https")
                })
        }
        _ => false,
    }
}

async fn api_cache_policy(request: Request, next: Next) -> Response {
    let sensitive = is_api_path(request.uri().path());
    let mut response = next.run(request).await;
    if sensitive {
        response.headers_mut().insert(
            header::CACHE_CONTROL,
            HeaderValue::from_static("no-store, max-age=0"),
        );
        response
            .headers_mut()
            .insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    }
    response
}

async fn api_error_envelope(request: Request, next: Next) -> Response {
    let is_api = is_api_path(request.uri().path());
    let response = next.run(request).await;
    if !is_api {
        return response;
    }

    // A routed handler may intentionally return a typed resource-level 404.
    // Preserve that JSON contract; only translate Axum/static-service routing
    // rejections, whose bodies are not API JSON.
    if response.status() == StatusCode::NOT_FOUND
        && response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split(';').next())
            .is_some_and(|value| {
                let value = value.trim();
                value.eq_ignore_ascii_case("application/json")
                    || value.to_ascii_lowercase().ends_with("+json")
            })
    {
        return response;
    }

    let (code, message) = match response.status() {
        StatusCode::NOT_FOUND => ("not_found", "API endpoint was not found"),
        StatusCode::METHOD_NOT_ALLOWED => (
            "method_not_allowed",
            "HTTP method is not allowed for this API endpoint",
        ),
        _ => return response,
    };
    let status = response.status();
    let allow = response.headers().get(header::ALLOW).cloned();
    let mut replacement = (
        status,
        Json(json!({"error":{"code":code,"message":message}})),
    )
        .into_response();
    if let Some(allow) = allow {
        replacement.headers_mut().insert(header::ALLOW, allow);
    }
    replacement
}

fn is_api_path(path: &str) -> bool {
    path == "/api" || path.starts_with("/api/")
}

async fn api_root_not_found() -> Result<(), AppError> {
    Err(AppError::NotFound("API endpoint was not found".into()))
}

pub fn ip_actor(ip: IpAddr) -> String {
    format!("ip:{ip}")
}

pub fn client_ip(peer_ip: IpAddr, headers: &HeaderMap, state: &AppState) -> IpAddr {
    if !state.config.trusted_proxy_ips.contains(&peer_ip) {
        return peer_ip;
    }
    forwarded_client_ip_from_headers(peer_ip, headers, &state.config.trusted_proxy_ips)
}

fn forwarded_client_ip_from_headers(
    peer_ip: IpAddr,
    headers: &HeaderMap,
    trusted: &[IpAddr],
) -> IpAddr {
    // Multiple field-lines are ambiguous because intermediaries disagree on
    // whether the first or last value wins. Fail closed to the proxy address
    // so an attacker cannot split the HTTP authorization identity from the
    // anti-abuse/rate-limit identity.
    let mut forwarded_values = headers.get_all("x-forwarded-for").iter();
    let Some(forwarded) = forwarded_values.next() else {
        return peer_ip;
    };
    if forwarded_values.next().is_some() {
        return peer_ip;
    }
    let Ok(forwarded) = forwarded.to_str() else {
        return peer_ip;
    };
    forwarded_client_ip(peer_ip, forwarded, trusted)
}

fn forwarded_client_ip(peer_ip: IpAddr, forwarded: &str, trusted: &[IpAddr]) -> IpAddr {
    let chain = forwarded
        .split(',')
        .map(str::trim)
        .map(str::parse::<IpAddr>)
        .collect::<std::result::Result<Vec<_>, _>>();
    let Ok(chain) = chain else {
        return peer_ip;
    };
    if chain.iter().any(IpAddr::is_unspecified) {
        return peer_ip;
    }
    chain
        .into_iter()
        .rev()
        .find(|ip| !trusted.contains(ip))
        .unwrap_or(peer_ip)
}

pub fn abuse_identity(
    action: AbuseAction,
    ip: IpAddr,
    user: Option<&db::ApiPrincipal>,
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

pub fn login_abuse_identity(ip: IpAddr, username: &str) -> Option<(String, Vec<String>)> {
    if username.is_empty() || username.len() > 1024 {
        return None;
    }
    let identity = auth::normalize_username(username).unwrap_or_else(|_| username.to_owned());
    let digest = auth::token_hash(&identity);
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    let account_actor = format!("login-account:{}", URL_SAFE_NO_PAD.encode(digest));
    Some((
        format!("login:{ip}:{account_actor}"),
        vec![ip_actor(ip), account_actor],
    ))
}

pub fn bearer_token(headers: &HeaderMap) -> Result<&str, AppError> {
    let mut values = headers.get_all(header::AUTHORIZATION).iter();
    let value = match (values.next(), values.next()) {
        (Some(value), None) => value.to_str().map_err(|_| AppError::Unauthorized)?,
        _ => return Err(AppError::Unauthorized),
    };
    let mut parts = value.split_ascii_whitespace();
    let scheme = parts.next().ok_or(AppError::Unauthorized)?;
    let token = parts.next().ok_or(AppError::Unauthorized)?;
    if !scheme.eq_ignore_ascii_case("Bearer")
        || parts.next().is_some()
        || token.len() != API_TOKEN_LENGTH
        || !token.bytes().all(|byte| byte.is_ascii_alphanumeric())
    {
        return Err(AppError::Unauthorized);
    }
    Ok(token)
}

pub fn rate_limited(error: GuardError) -> AppError {
    AppError::RateLimited(json!({"message":error.message(),"requirement":error.requirement()}))
}

pub struct ApiUser {
    user: db::ApiPrincipal,
    session_token: zeroize::Zeroizing<String>,
}

impl ApiUser {
    pub fn session_token(&self) -> &str {
        self.session_token.as_str()
    }

    /// Start a repeatable authorization snapshot for a sensitive read.
    ///
    /// The shared locks taken by `authorize_user_in_tx` keep password
    /// rotation, account disablement and explicit bearer revocation from
    /// committing between this check and the caller's final database read.
    pub(crate) async fn begin_authorized_read<'a>(
        &self,
        state: &'a AppState,
    ) -> Result<sqlx::Transaction<'a, sqlx::Postgres>, AppError> {
        let mut tx = state.pool.begin().await?;
        sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
            .execute(&mut *tx)
            .await?;
        if !db::authorize_user_in_tx(&mut tx, self.id, self.auth_generation, self.session_token())
            .await?
        {
            tx.rollback().await?;
            return Err(AppError::Unauthorized);
        }
        Ok(tx)
    }
}

impl Deref for ApiUser {
    type Target = db::ApiPrincipal;

    fn deref(&self) -> &Self::Target {
        &self.user
    }
}

pub async fn current_user(state: &AppState, headers: &HeaderMap) -> Result<ApiUser, AppError> {
    let _authentication_timer = state.metrics.authentication_duration_seconds.start_timer();
    let token = bearer_token(headers)?;
    let database_timer = state
        .metrics
        .database_operation_duration_seconds
        .start_timer();
    let user = db::user_for_token(&state.pool, token)
        .await?
        .ok_or(AppError::Unauthorized)?;
    drop(database_timer);
    Ok(ApiUser {
        user,
        session_token: zeroize::Zeroizing::new(token.to_owned()),
    })
}

pub struct ApiAdmin {
    user: ApiUser,
}

impl ApiAdmin {
    pub fn session_token(&self) -> &str {
        self.user.session_token()
    }

    /// Hold the exact administrator bearer, credential generation and role
    /// stable until a sensitive read has produced its complete projection.
    pub(crate) async fn begin_authorized_read<'a>(
        &self,
        state: &'a AppState,
    ) -> Result<sqlx::Transaction<'a, sqlx::Postgres>, AppError> {
        let mut tx = state.pool.begin().await?;
        sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
            .execute(&mut *tx)
            .await?;
        if !db::authorize_admin_in_tx(&mut tx, self.id, self.auth_generation, self.session_token())
            .await?
        {
            tx.rollback().await?;
            return Err(AppError::Forbidden);
        }
        Ok(tx)
    }
}

impl Deref for ApiAdmin {
    type Target = db::ApiPrincipal;

    fn deref(&self) -> &Self::Target {
        &self.user.user
    }
}

impl FromRequestParts<Arc<AppState>> for ApiAdmin {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        let token = bearer_token(&parts.headers)?;
        let user = db::user_for_token(&state.pool, token)
            .await?
            .ok_or(AppError::Unauthorized)?;
        if !user.is_admin {
            return Err(AppError::Forbidden);
        }
        Ok(Self {
            user: ApiUser {
                user,
                session_token: zeroize::Zeroizing::new(token.to_owned()),
            },
        })
    }
}

pub async fn admin(state: &AppState, headers: &HeaderMap) -> Result<ApiAdmin, AppError> {
    let token = bearer_token(headers)?;
    let user = db::user_for_token(&state.pool, token)
        .await?
        .ok_or(AppError::Unauthorized)?;
    if !user.is_admin {
        return Err(AppError::Forbidden);
    }
    Ok(ApiAdmin {
        user: ApiUser {
            user,
            session_token: zeroize::Zeroizing::new(token.to_owned()),
        },
    })
}

pub async fn serve(
    state: Arc<AppState>,
    cancel: tokio_util::sync::CancellationToken,
    listener: tokio::net::TcpListener,
) -> anyhow::Result<()> {
    let address = listener.local_addr().unwrap_or(state.config.http_bind);
    tracing::info!(address = %address, "public HTTP capability listener ready");
    axum::serve(
        listener,
        public_router(state).into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(cancel.cancelled_owned())
    .await?;
    Ok(())
}

pub async fn serve_administration(
    state: Arc<AppState>,
    cancel: tokio_util::sync::CancellationToken,
    listener: tokio::net::TcpListener,
) -> anyhow::Result<()> {
    let address = listener.local_addr().unwrap_or(state.config.web_admin_bind);
    tracing::info!(
        address = %address,
        gateway_authentication = state.admin_gateway_authentication_enabled(),
        "private Web administration listener ready"
    );
    axum::serve(
        listener,
        administrator_router(state).into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(cancel.cancelled_owned())
    .await?;
    Ok(())
}

pub async fn serve_metrics(
    state: Arc<AppState>,
    cancel: tokio_util::sync::CancellationToken,
    listener: tokio::net::TcpListener,
) -> anyhow::Result<()> {
    let endpoint = MetricsEndpointState::new(Arc::clone(&state));
    let address = listener.local_addr().unwrap_or(state.config.metrics_bind);
    tracing::info!(address = %address, "private metrics listener ready");
    let router = Router::new()
        .route("/metrics", get(metrics))
        .with_state(endpoint);
    axum::serve(
        listener,
        router.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(cancel.cancelled_owned())
    .await?;
    Ok(())
}

pub async fn shutdown_signal() {
    let ctrl_c = tokio::signal::ctrl_c();
    #[cfg(unix)]
    let terminate = async {
        let mut signal = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("signal handler");
        signal.recv().await;
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    wait_for_shutdown_signal(ctrl_c, terminate).await;
}

async fn wait_for_shutdown_signal<C, T>(ctrl_c: C, terminate: T)
where
    C: std::future::Future<Output = std::io::Result<()>>,
    T: std::future::Future<Output = ()>,
{
    let ctrl_c = async {
        match ctrl_c.await {
            Ok(()) => {}
            Err(error) => {
                tracing::error!(
                    ?error,
                    "could not register Ctrl+C shutdown handler; continuing to serve"
                );
                std::future::pending::<()>().await;
            }
        }
    };
    tokio::pin!(ctrl_c);
    tokio::pin!(terminate);
    tokio::select! { _ = &mut ctrl_c => {}, _ = &mut terminate => {} }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_and_administrator_static_manifests_are_explicitly_isolated() {
        let client = WEB_CLIENT_STATIC_FILES
            .iter()
            .map(|(route, _)| *route)
            .collect::<std::collections::BTreeSet<_>>();
        let admin = WEB_ADMIN_STATIC_FILES
            .iter()
            .map(|(route, _)| *route)
            .collect::<std::collections::BTreeSet<_>>();
        for shared in ["/i18n.css", "/i18n.js", "/locales.generated.js"] {
            assert!(client.contains(shared));
            assert!(admin.contains(shared));
        }
        for admin_only in ["/app.js", "/admin.css", "/styles.css"] {
            assert!(admin.contains(admin_only));
            assert!(!client.contains(admin_only));
        }
        for client_only in ["/client.js", "/xmpp.js", "/omemo.js"] {
            assert!(client.contains(client_only));
            assert!(!admin.contains(client_only));
        }
    }

    #[test]
    fn public_router_never_merges_administrator_routes() {
        let source = include_str!("mod.rs");
        let public = source
            .split_once("pub fn public_router")
            .unwrap()
            .1
            .split_once("pub fn administrator_router")
            .unwrap()
            .0;
        assert!(public.contains("public_rest_routes"));
        assert!(public.contains("web_client_static_routes"));
        assert!(!public.contains("administrator_api_routes"));
        assert!(!public.contains("administrator_static_routes"));
    }

    #[test]
    fn administrator_observability_never_bypasses_transport_security() {
        let remote: IpAddr = "192.0.2.10".parse().unwrap();
        let headers = HeaderMap::new();
        assert!(secure_transport_allowed(
            true,
            "/healthz",
            remote,
            &headers,
            &[]
        ));
        assert!(!secure_transport_allowed(
            false,
            "/healthz",
            remote,
            &headers,
            &[]
        ));
        assert!(!secure_transport_allowed(
            false,
            "/readyz",
            remote,
            &headers,
            &[]
        ));
    }

    #[test]
    fn xep_0487_keeps_json_host_meta_without_web_transports() {
        assert_eq!(
            host_meta_route_contributions(false, false, true),
            (false, true)
        );
        assert_eq!(
            host_meta_route_contributions(false, false, false),
            (false, false)
        );
        assert_eq!(
            host_meta_route_contributions(true, false, false),
            (true, true)
        );
        assert_eq!(
            host_meta_route_contributions(false, true, false),
            (true, true)
        );
    }

    #[tokio::test]
    async fn shutdown_signal_registration_error_does_not_request_shutdown() {
        let ctrl_c = std::future::ready(Err(std::io::Error::other(
            "injected signal registration failure",
        )));
        let wait = wait_for_shutdown_signal(ctrl_c, std::future::pending());
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(50), wait)
                .await
                .is_err(),
            "a Ctrl+C handler registration error must not stop the server"
        );
    }

    #[tokio::test]
    async fn shutdown_signal_success_requests_shutdown() {
        let ctrl_c = std::future::ready(Ok(()));
        tokio::time::timeout(
            std::time::Duration::from_secs(1),
            wait_for_shutdown_signal(ctrl_c, std::future::pending()),
        )
        .await
        .expect("a successful Ctrl+C signal should stop the server");
    }

    #[test]
    fn api_path_boundary_includes_the_api_root_without_matching_prefixes() {
        assert!(is_api_path("/api"));
        assert!(is_api_path("/api/"));
        assert!(is_api_path("/api/v1/status"));
        assert!(!is_api_path("/apiary"));
        assert!(!is_api_path("/client.html"));
    }

    #[tokio::test]
    async fn api_json_preserves_exact_body_identity_and_enforces_its_limit() {
        let request_id = ApiRequestId(uuid::Uuid::new_v4());
        let body = br#"{"username":"alice","password":"test-password"}"#;
        let mut request = Request::builder()
            .method("POST")
            .uri("/api/v1/login")
            .header(header::CONTENT_TYPE, "application/json; charset=utf-8")
            .header("idempotency-key", "login-request-key-0001")
            .body(Body::from(body.as_slice()))
            .unwrap();
        request.extensions_mut().insert(request_id);
        let parsed = ApiJson::<Credentials>::from_request(request, &())
            .await
            .unwrap();
        assert_eq!(parsed.username, "alice");
        let idempotency = parsed.idempotency(
            None,
            b"login:127.0.0.1:alice",
            db::ApiPrincipalKind::Anonymous,
            "POST",
            "/api/v1/login",
        );
        assert_eq!(idempotency.request_id, request_id.0);
        assert_eq!(idempotency.idempotency_key, "login-request-key-0001");
        assert_eq!(
            idempotency.request_fingerprint,
            db::api_request_fingerprint("application/json", body)
        );

        let oversized = Request::builder()
            .method("POST")
            .uri("/api/v1/login")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(vec![b' '; API_BODY_LIMIT_BYTES + 1]))
            .unwrap();
        assert!(matches!(
            ApiJson::<Credentials>::from_request(oversized, &()).await,
            Err(AppError::PayloadTooLarge)
        ));
    }

    #[tokio::test]
    async fn idempotency_replay_marks_the_original_attempt() {
        let original_request_id = uuid::Uuid::new_v4();
        let replay = db::IdempotentResponse {
            request_id: original_request_id,
            status: StatusCode::OK.as_u16(),
            headers: json_replay_headers(),
            body: br#"{"token":"stored"}"#.to_vec(),
        };
        let response = idempotency_replay_response(replay).unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get("idempotency-replayed")
                .and_then(|value| value.to_str().ok()),
            Some("true")
        );
        assert_eq!(
            response
                .headers()
                .get("idempotency-original-request-id")
                .and_then(|value| value.to_str().ok())
                .unwrap(),
            original_request_id.to_string()
        );
        assert_eq!(
            to_bytes(response.into_body(), 1024).await.unwrap(),
            br#"{"token":"stored"}"#.as_slice()
        );
    }

    #[test]
    fn bearer_parser_has_an_exact_non_ambiguous_boundary() {
        let valid = "A".repeat(API_TOKEN_LENGTH);
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            format!("bearer {valid}").parse().unwrap(),
        );
        assert_eq!(bearer_token(&headers).unwrap(), valid);

        for invalid in [
            format!("Bearer {} extra", "A".repeat(API_TOKEN_LENGTH)),
            format!("Basic {}", "A".repeat(API_TOKEN_LENGTH)),
            format!("Bearer {}", "_".repeat(API_TOKEN_LENGTH)),
            format!("Bearer {}", "A".repeat(API_TOKEN_LENGTH - 1)),
        ] {
            headers.insert(header::AUTHORIZATION, invalid.parse().unwrap());
            assert!(matches!(
                bearer_token(&headers),
                Err(AppError::Unauthorized)
            ));
        }

        headers.clear();
        headers.append(
            header::AUTHORIZATION,
            format!("Bearer {valid}").parse().unwrap(),
        );
        headers.append(
            header::AUTHORIZATION,
            format!("Bearer {valid}").parse().unwrap(),
        );
        assert!(matches!(
            bearer_token(&headers),
            Err(AppError::Unauthorized)
        ));
    }

    #[test]
    fn forwarded_chain_uses_the_nearest_untrusted_hop() {
        let peer: IpAddr = "10.0.0.1".parse().unwrap();
        let trusted = vec![peer, "10.0.0.2".parse().unwrap()];
        assert_eq!(
            forwarded_client_ip(peer, "198.51.100.99, 203.0.113.7, 10.0.0.2", &trusted),
            "203.0.113.7".parse::<IpAddr>().unwrap()
        );
        assert_eq!(
            forwarded_client_ip(peer, "spoofed, 203.0.113.7", &trusted),
            peer
        );
        assert_eq!(forwarded_client_ip(peer, "0.0.0.0", &trusted), peer);

        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_static("198.51.100.99, 10.0.0.2"),
        );
        assert_eq!(
            forwarded_client_ip_from_headers(peer, &headers, &trusted),
            "198.51.100.99".parse::<IpAddr>().unwrap()
        );
        headers.append("x-forwarded-for", HeaderValue::from_static("203.0.113.7"));
        assert_eq!(
            forwarded_client_ip_from_headers(peer, &headers, &trusted),
            peer
        );
    }

    #[test]
    fn http_transport_requires_loopback_or_one_trusted_https_assertion() {
        let loopback: IpAddr = "127.0.0.1".parse().unwrap();
        let proxy: IpAddr = "10.0.0.2".parse().unwrap();
        let external: IpAddr = "203.0.113.9".parse().unwrap();
        let trusted = vec![proxy];
        let mut headers = HeaderMap::new();

        assert!(secure_http_request(loopback, &headers, &trusted));
        assert!(!secure_http_request(external, &headers, &trusted));

        headers.insert("x-forwarded-proto", HeaderValue::from_static("https"));
        assert!(secure_http_request(proxy, &headers, &trusted));
        assert!(!secure_http_request(external, &headers, &trusted));

        headers.insert("x-forwarded-proto", HeaderValue::from_static("http"));
        assert!(!secure_http_request(proxy, &headers, &trusted));
        headers.insert("x-forwarded-proto", HeaderValue::from_static("https, http"));
        assert!(!secure_http_request(proxy, &headers, &trusted));
        headers.remove("x-forwarded-proto");
        headers.append("x-forwarded-proto", HeaderValue::from_static("https"));
        headers.append("x-forwarded-proto", HeaderValue::from_static("https"));
        assert!(!secure_http_request(proxy, &headers, &trusted));
        assert!(plaintext_observability_path("/healthz"));
        assert!(plaintext_observability_path("/readyz"));
        assert!(!plaintext_observability_path("/metrics"));
        assert!(!plaintext_observability_path("/client.html"));
        assert!(!plaintext_observability_path("/uploads/example"));
    }

    #[test]
    fn browser_csp_does_not_allow_inline_code_or_styles() {
        assert!(!SPA_CONTENT_SECURITY_POLICY.contains("'unsafe-inline'"));
        assert!(!SPA_CONTENT_SECURITY_POLICY.contains("'unsafe-eval'"));
        assert!(SPA_CONTENT_SECURITY_POLICY.contains("object-src 'none'"));
        assert!(SPA_CONTENT_SECURITY_POLICY.contains("connect-src 'self'"));
        assert!(!SPA_CONTENT_SECURITY_POLICY.contains(" ws:"));
        assert!(!SPA_CONTENT_SECURITY_POLICY.contains(" wss:"));
        assert!(SPA_CONTENT_SECURITY_POLICY.contains("worker-src 'self'"));
        assert!(!SPA_CONTENT_SECURITY_POLICY.contains("worker-src 'self' blob:"));
        assert!(SPA_CONTENT_SECURITY_POLICY.contains("base-uri 'none'"));
        assert!(SPA_CONTENT_SECURITY_POLICY.contains("form-action 'self'"));
        assert!(SPA_CONTENT_SECURITY_POLICY.contains("frame-ancestors 'none'"));
    }

    #[test]
    fn login_pow_identity_is_bound_to_ip_and_normalized_account() {
        let ip: IpAddr = "203.0.113.9".parse().unwrap();
        let alice = login_abuse_identity(ip, "Alice").unwrap();
        let alice_case_variant = login_abuse_identity(ip, "alice").unwrap();
        let bob = login_abuse_identity(ip, "bob").unwrap();
        assert_eq!(alice, alice_case_variant);
        assert_ne!(alice.0, bob.0);
        assert_ne!(alice.1, bob.1);
        assert!(login_abuse_identity(ip, "").is_none());
    }
}
