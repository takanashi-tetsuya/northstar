//! The HTTP upgrade into an XMPP WebSocket stream (RFC 7395): the secure-transport, origin and
//! subprotocol checks, connection admission, and the hand-off to [`crate::websocket_connection`].

use crate::host::C2sHost;
use axum::{
    extract::{ConnectInfo, State, WebSocketUpgrade},
    http::{header, HeaderMap},
    response::{IntoResponse, Response},
};
use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
};

/// What the upgrade checks before it admits a WebSocket client.
pub trait WebSocketHost: C2sHost {
    /// The public URL. A loopback `http` URL admits plain `ws://` from loopback peers.
    fn public_url(&self) -> &str;

    /// Proxies whose `X-Forwarded-Proto` may vouch for the client's TLS.
    fn trusted_proxy_ips(&self) -> &[IpAddr];

    /// Web origins admitted besides the public URL's own.
    fn websocket_allowed_origins(&self) -> &[String];

    /// The client address behind trusted proxies, for admission and logs.
    fn client_ip(&self, peer_ip: IpAddr, headers: &HeaderMap) -> IpAddr;
}

/// Upgrades an admitted request to an XMPP WebSocket stream and spawns its connection actor.
pub async fn websocket_upgrade<H: WebSocketHost>(
    ws: WebSocketUpgrade,
    State(host): State<Arc<H>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Response {
    if !secure_websocket_request(
        peer.ip(),
        &headers,
        host.trusted_proxy_ips(),
        host.public_url(),
    ) {
        return (
            axum::http::StatusCode::BAD_REQUEST,
            "the XMPP WebSocket endpoint requires a secure WSS transport",
        )
            .into_response();
    }
    if !allowed_websocket_origin(
        &headers,
        host.public_url(),
        host.websocket_allowed_origins(),
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
    let peer_ip = host.client_ip(peer.ip(), &headers);
    let Some(connection_guard) = host.acquire_client_connection(peer_ip) else {
        return axum::http::StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    ws.protocols(["xmpp"])
        // Grow for large stanzas instead of reserving 128 KiB per idle client.
        .read_buffer_size(8 * 1024)
        .max_message_size(1024 * 1024)
        .max_frame_size(1024 * 1024)
        .on_upgrade(move |socket| async move {
            let actors = host.connection_actors().clone();
            let actor_shutdown = actors.shutdown_token().child_token();
            let result = actors.try_spawn(
                northstar_runtime::connection_actors::ConnectionActorKind::C2sWebSocket,
                Some(peer_ip.to_string()),
                async move {
                    let _connection_guard = connection_guard;
                    crate::websocket_connection(socket, host, peer_ip, actor_shutdown).await;
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
    let Some(origin) = northstar_config::canonical_web_origin(origin) else {
        return false;
    };
    northstar_config::canonical_public_web_origin(public_url).as_ref() == Some(&origin)
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

#[cfg(test)]
mod tests;
