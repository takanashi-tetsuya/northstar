//! Read only the small REST body under a deadline, before any extractor can
//! authenticate or mutate state. Never put a timeout around handler execution.
use axum::{
    body::{to_bytes, Body},
    extract::{ConnectInfo, MatchedPath, Request, State},
    http::{header, HeaderValue, Method, Version},
    middleware::Next,
    response::{IntoResponse, Response},
};
use std::net::SocketAddr;

use crate::{error::AppError, state::HttpTransportPolicy};

pub(super) async fn read_rest_body(
    State(policy): State<HttpTransportPolicy>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    request: Request,
    next: Next,
) -> Response {
    let upload = request.method() == Method::PUT
        && request
            .extensions()
            .get::<MatchedPath>()
            .is_some_and(|path| path.as_str() == "/api/v1/upload/{id}");
    if !super::is_api_path(request.uri().path()) || upload {
        // Upload PUT and BOSH own streaming limits, admission and deadlines.
        return next.run(request).await;
    }
    let version = request.version();
    let ip = super::client_ip_with_trusted_proxies(
        peer.ip(),
        request.headers(),
        policy.trusted_proxies(),
    );
    let Some(permit) = policy.body_admission().try_acquire(ip) else {
        return reject(
            version,
            AppError::TooManyRequests {
                message: "too many concurrent REST request bodies".into(),
                retry_after: 1,
            },
        );
    };
    let (parts, body) = request.into_parts();
    let bytes = tokio::time::timeout(
        policy.body_admission().timeout,
        to_bytes(body, super::API_BODY_LIMIT_BYTES),
    )
    .await;
    // Release on success, read failure, timeout or cancellation, before the
    // handler executes. Dropping the timed-out future also drops its body.
    drop(permit);
    match bytes {
        Ok(Ok(bytes)) => {
            next.run(Request::from_parts(parts, Body::from(bytes)))
                .await
        }
        Ok(Err(_)) => reject(version, AppError::PayloadTooLarge),
        Err(_) => reject(version, AppError::RequestTimeout),
    }
}

fn reject(version: Version, error: AppError) -> Response {
    let mut response = error.into_response();
    if matches!(version, Version::HTTP_10 | Version::HTTP_11) {
        // Do not retain or drain an incomplete HTTP/1 body for keep-alive.
        // Connection-specific headers are forbidden on HTTP/2 and HTTP/3.
        response
            .headers_mut()
            .insert(header::CONNECTION, HeaderValue::from_static("close"));
    }
    response
}

#[cfg(test)]
mod tests;
