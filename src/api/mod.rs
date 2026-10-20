use axum::{
    body::{to_bytes, Body},
    extract::{ConnectInfo, FromRef, FromRequest, FromRequestParts, Request, State},
    http::{header, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post, put},
    Json, Router,
};
use serde::de::DeserializeOwned;
use serde_json::json;
use std::net::SocketAddr;
use std::sync::Arc;

use crate::api::contexts::{
    api_session_http::ApiSessionHttpContext,
    http_registration_endpoint::HttpRegistrationEndpointContext,
    omemo_recovery_http::OmemoRecoveryHttpContext, passkey_http::PasskeyStartHttpContext,
    AdminGatewayVerifier, ApiQueryContext, HttpLoginEndpointContext, HttpTransportPolicy,
    OmemoRecoveryPollContext, PasskeyLoginFinishContext, PublicDiscoveryContext,
    RetentionPolicyContext, UploadHttpReadContext,
};
use crate::auth;
use crate::platform::error::{AppError, Result};
use crate::services::abuse::AbuseAction;
use crate::services::api_mutations::{
    api_request_fingerprint, ApiPrincipalKind, IdempotencyRequest, IdempotentResponse,
};
use crate::state::{AppState, MetricsContext};

use crate::services::abuse::GuardError;
use axum::extract::DefaultBodyLimit;
use axum::http::header::{HeaderMap, HeaderName, HeaderValue};
use axum::routing::{delete, options, patch};
use std::net::IpAddr;
use std::ops::Deref;
use tower_http::services::{ServeDir, ServeFile};
use tower_http::set_header::SetResponseHeaderLayer;
use tower_http::trace::TraceLayer;

use axum::http::request::Parts;

mod route_composition;

use self::route_composition::{
    administrator_command_routes, administrator_query_routes, administrator_static_routes,
    authentication_routes, discovery_routes, omemo_recovery_routes, personal_credential_routes,
    personal_policy_routes, public_authorized_routes, public_capability_routes,
    public_query_routes, public_rest_routes, public_upload_read_routes, upload_http_routes,
    web_client_static_routes, xmpp_transport_routes,
};

mod body_limits;
pub(crate) mod contexts;
pub mod extract;
pub(crate) mod governance_cursor;
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
    ("/passkeys.js", "web/passkeys.js"),
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
            request_fingerprint: api_request_fingerprint(&media_type, &bytes),
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
            request_fingerprint: api_request_fingerprint("", &bytes),
            idempotency_key,
        })
    }
}

impl<T> ApiJson<T> {
    pub fn idempotency<'a>(
        &'a self,
        actor_id: Option<uuid::Uuid>,
        principal_scope: &'a [u8],
        principal_kind: ApiPrincipalKind,
        method: &'a str,
        route: &'a str,
    ) -> IdempotencyRequest<'a> {
        IdempotencyRequest {
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
        principal_kind: ApiPrincipalKind,
        method: &'a str,
        route: &'a str,
    ) -> IdempotencyRequest<'a> {
        IdempotencyRequest {
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

pub fn idempotency_replay_response(replay: IdempotentResponse) -> Result<Response, AppError> {
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
mod passkeys;
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

fn common_http_layers(
    router: Router,
    state: HttpTransportPolicy,
    allow_plaintext_observability: bool,
) -> Router {
    let router = router.layer(middleware::from_fn_with_state(
        state.clone(),
        body_limits::read_rest_body,
    ));
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
    let readiness = ReadyEndpointState::new(state.readiness_context());
    let discovery = state.public_discovery_context().clone();
    let policy = discovery.policy();
    let mut router = Router::new()
        .route("/healthz", get(health))
        .route("/readyz", get(ready).with_state(readiness));
    if policy.rest_api_enabled {
        router = router
            .merge(public_rest_routes())
            .merge(authentication_routes(&state, true))
            .merge(public_query_routes(state.api_query_context()))
            .merge(public_authorized_routes(&state))
            .merge(personal_credential_routes(&state))
            .merge(public_capability_routes(&state))
            .merge(personal_policy_routes(&state))
            .merge(omemo_recovery_routes(&state));
    }
    if policy.upload_mode.keeps_storage_runtime() {
        let upload_limit = usize::try_from(policy.upload_max_bytes).unwrap_or(usize::MAX);
        router = router
            .merge(upload_http_routes(
                &state,
                upload_limit,
                policy.upload_mode.admits_new_uploads(),
            ))
            .merge(public_upload_read_routes(&state));
    }
    let (serve_host_meta_xml, serve_host_meta_json) = host_meta_route_contributions(
        policy.websocket_enabled,
        policy.bosh_enabled,
        !policy.xep_0487_ips.is_empty(),
    );
    router = router
        .merge(discovery_routes(
            discovery.clone(),
            policy.rest_api_enabled,
            serve_host_meta_xml,
            serve_host_meta_json,
        ))
        .merge(xmpp_transport_routes(
            Arc::clone(&state),
            policy.websocket_enabled,
            policy.bosh_enabled,
        ));
    if policy.web_client_enabled {
        router = router.merge(web_client_static_routes());
    }
    common_http_layers(router, state.http_transport_policy(), true)
}

pub fn administrator_router(state: Arc<AppState>) -> Router {
    let readiness = ReadyEndpointState::new(state.readiness_context());
    let discovery = state.public_discovery_context().clone();
    let policy = discovery.policy();
    let router = Router::new()
        .route("/healthz", get(health))
        .route("/readyz", get(ready).with_state(readiness))
        .merge(administrator_command_routes(
            &state,
            policy.upload_mode.keeps_storage_runtime(),
            policy.web_client_enabled,
        ))
        .merge(administrator_query_routes(
            state.api_query_context(),
            policy.upload_mode.keeps_storage_runtime(),
        ))
        .merge(authentication_routes(&state, false))
        .merge(discovery_routes(discovery.clone(), true, false, false))
        .merge(administrator_static_routes());
    common_http_layers(
        router.layer(middleware::from_fn_with_state(
            state.admin_gateway_verifier(),
            administrator_gateway_authentication,
        )),
        state.http_transport_policy(),
        false,
    )
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
    State(state): State<HttpTransportPolicy>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    request: Request,
    next: Next,
) -> Response {
    secure_http_transport_policy(state, peer, request, next, true).await
}

async fn secure_administrator_transport(
    State(state): State<HttpTransportPolicy>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    request: Request,
    next: Next,
) -> Response {
    secure_http_transport_policy(state, peer, request, next, false).await
}

async fn secure_http_transport_policy(
    state: HttpTransportPolicy,
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
        state.trusted_proxies(),
    ) {
        return next.run(request).await;
    }

    let rejected = state.record_insecure_rejection();
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
    State(verifier): State<AdminGatewayVerifier>,
    mut request: Request,
    next: Next,
) -> Response {
    if authorize_administrator_gateway_headers(&verifier, request.headers_mut()) {
        return next.run(request).await;
    }
    administrator_gateway_rejection()
}

fn authorize_administrator_gateway_headers(
    verifier: &AdminGatewayVerifier,
    headers: &mut HeaderMap,
) -> bool {
    let mut supplied = headers.get_all("x-northstar-admin-gateway-token").iter();
    let candidate = match (supplied.next(), supplied.next()) {
        (Some(value), None) => value.to_str().ok(),
        (None, None) => None,
        _ => return false,
    };
    if !verifier.authorized(candidate) {
        return false;
    }
    // The proxy credential authorizes entry to this listener; it must not
    // remain visible to downstream handlers, tracing or proxy integrations.
    headers.remove("x-northstar-admin-gateway-token");
    true
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
    let transport = state.http_transport_policy();
    client_ip_with_trusted_proxies(peer_ip, headers, transport.trusted_proxies())
}

fn client_ip_with_trusted_proxies(
    peer_ip: IpAddr,
    headers: &HeaderMap,
    trusted: &[IpAddr],
) -> IpAddr {
    if !trusted.contains(&peer_ip) {
        return peer_ip;
    }
    forwarded_client_ip_from_headers(peer_ip, headers, trusted)
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
    user: Option<&crate::services::api_queries::ApiPrincipal>,
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
    user: crate::services::api_queries::ApiPrincipal,
    session_token: zeroize::Zeroizing<String>,
}

impl ApiUser {
    pub fn session_token(&self) -> &str {
        self.session_token.as_str()
    }
    pub(crate) fn read_authority(&self) -> crate::services::api_queries::ApiReadAuthority<'_> {
        crate::services::api_queries::ApiReadAuthority {
            user_id: self.id,
            auth_generation: self.auth_generation,
            session_token: self.session_token(),
        }
    }
}

impl Deref for ApiUser {
    type Target = crate::services::api_queries::ApiPrincipal;

    fn deref(&self) -> &Self::Target {
        &self.user
    }
}

pub(crate) async fn current_user_with_queries(
    state: &crate::api::contexts::ApiQueryContext,
    headers: &HeaderMap,
) -> Result<ApiUser, AppError> {
    let _authentication_timer = state.authentication_timer();
    let token = bearer_token(headers)?;
    let database_timer = state.database_timer();
    let user = state
        .api_query_service()
        .principal(token)
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
    pub(crate) fn read_authority(&self) -> crate::services::api_queries::ApiReadAuthority<'_> {
        self.user.read_authority()
    }
}

impl Deref for ApiAdmin {
    type Target = crate::services::api_queries::ApiPrincipal;

    fn deref(&self) -> &Self::Target {
        &self.user.user
    }
}

impl<S> FromRequestParts<S> for ApiAdmin
where
    S: Send + Sync,
    crate::api::contexts::ApiQueryContext: axum::extract::FromRef<S>,
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let state =
            <crate::api::contexts::ApiQueryContext as axum::extract::FromRef<S>>::from_ref(state);
        let token = bearer_token(&parts.headers)?;
        let user = state
            .api_query_service()
            .principal(token)
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

pub async fn serve(
    state: Arc<AppState>,
    cancel: tokio_util::sync::CancellationToken,
    listener: tokio::net::TcpListener,
) -> anyhow::Result<()> {
    let address = listener
        .local_addr()
        .unwrap_or(state.public_http_bind_address());
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
    let address = listener
        .local_addr()
        .unwrap_or(state.admin_http_bind_address());
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
    context: MetricsContext,
    cancel: tokio_util::sync::CancellationToken,
    listener: tokio::net::TcpListener,
) -> anyhow::Result<()> {
    let address = listener.local_addr().unwrap_or(context.bind_fallback());
    let endpoint = MetricsEndpointState::new(context);
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

/// Production source of this file's role split: the file itself followed
/// by the role child modules split out of it, so source-contract tests keep
/// reading the same code after it moves between them. The children are
/// listed in the order their code had in the former single file. The
/// directory also holds independently owned modules, which are not part of
/// this source. `module_source_lists_every_role_split_child` keeps this list
/// in step with the entry for this file in catalog/source-role-splits.json.
#[cfg(test)]
const MODULE_SOURCE: &[(&str, &str)] = &[
    ("mod", include_str!("mod.rs")),
    ("route_composition", include_str!("route_composition.rs")),
];

#[cfg(test)]
fn module_source() -> String {
    MODULE_SOURCE
        .iter()
        .map(|(_, text)| *text)
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod module_source_tests;
