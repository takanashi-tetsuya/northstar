//! Handle BOSH HTTP requests, responses, and CORS.

use crate::host::BoshHost;
use crate::request_policy::{parse_body, secure_proxy_request, supported_request_headers};
use crate::response_output::terminal_response;
use crate::BoshHttpResponse;
use axum::body::Body;
use axum::extract::{ConnectInfo, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;

pub(super) type BoshResponseBody = (
    BoshHttpResponse,
    Vec<northstar_stream::outbound::TransportOwnershipSource>,
    Vec<mpsc::UnboundedSender<()>>,
    VecDeque<northstar_stream::outbound::OutboundItem>,
);

pub(super) type BoshResponsePayload = (
    String,
    Vec<northstar_stream::outbound::TransportOwnershipSource>,
    Vec<mpsc::UnboundedSender<()>>,
    Vec<Arc<Vec<northstar_session_application::sm_capacity::SmCapacityLease>>>,
    VecDeque<northstar_stream::outbound::OutboundItem>,
);

pub async fn http_bind<H: BoshHost>(
    State(host): State<Arc<H>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    request: axum::extract::Request,
) -> Response {
    let headers = request.headers().clone();
    if !secure_proxy_request(peer.ip(), &headers, host.trusted_proxy_ips()) {
        return cors_response(StatusCode::OK, terminal_response("policy-violation"));
    }
    if !supported_request_headers(&headers) {
        return cors_response(StatusCode::OK, terminal_response("bad-request"));
    }
    let Some(body_read_slot) = host.bosh_manager().try_body_read() else {
        return cors_response(StatusCode::OK, terminal_response("policy-violation"));
    };
    let policy = host.bosh_policy();
    let body = match tokio::time::timeout(
        Duration::from_secs(policy.body_read_timeout_seconds),
        axum::body::to_bytes(request.into_body(), policy.max_request_bytes),
    )
    .await
    {
        Ok(Ok(body)) => body,
        Ok(Err(_)) => {
            return cors_response(
                StatusCode::PAYLOAD_TOO_LARGE,
                terminal_response("policy-violation"),
            );
        }
        Err(_) => {
            return cors_response(StatusCode::OK, terminal_response("policy-violation"));
        }
    };
    let parsed = std::str::from_utf8(&body)
        .map_err(|_| "bad-request")
        .and_then(|raw| parse_body(raw, policy.max_stanzas_per_request));
    drop(body);
    drop(body_read_slot);
    let response = match parsed {
        Ok(request) if request.sid.is_some() => host.bosh_manager().request(request).await,
        Ok(request) => {
            let peer_ip = host.client_ip(peer.ip(), &headers);
            match host.acquire_client_connection(peer_ip) {
                Some(guard) => match host
                    .bosh_manager()
                    .create(Arc::clone(&host), request, peer_ip, guard)
                    .await
                {
                    Ok(response) => response,
                    Err(condition) => terminal_response(condition),
                },
                None => terminal_response("policy-violation"),
            }
        }
        Err(condition) => terminal_response(condition),
    };
    cors_response(StatusCode::OK, response)
}

pub async fn http_bind_options() -> Response {
    let mut response = StatusCode::NO_CONTENT.into_response();
    apply_cors(response.headers_mut());
    response
}

pub(super) fn cors_response(status: StatusCode, response: BoshHttpResponse) -> Response {
    let BoshHttpResponse { body, content_type } = response;
    let content_type = HeaderValue::from_str(&content_type)
        .unwrap_or_else(|_| HeaderValue::from_static("text/xml; charset=utf-8"));
    // `Bytes` transfers the same ref-counted allocation into Hyper. Cached
    // response replay and duplicate RID waiters therefore create no hidden
    // body clones and all owners retain the same capacity lease.
    let mut response = Response::new(Body::from(body));
    *response.status_mut() = status;
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, content_type);
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("no-store, max-age=0"),
    );
    apply_cors(response.headers_mut());
    response
}

fn apply_cors(headers: &mut HeaderMap) {
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_ORIGIN,
        HeaderValue::from_static("*"),
    );
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_METHODS,
        HeaderValue::from_static("POST, OPTIONS"),
    );
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_HEADERS,
        HeaderValue::from_static("Content-Type"),
    );
    headers.insert(
        header::ACCESS_CONTROL_MAX_AGE,
        HeaderValue::from_static("86400"),
    );
}
