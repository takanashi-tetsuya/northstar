//! Canonical web origins and loopback origin hosts.

use super::*;

/// Return the canonical serialized origin accepted from a browser `Origin`
/// header or an explicit WebSocket allowlist entry. Only secure origins are
/// accepted outside loopback development hosts.
pub fn canonical_web_origin(value: &str) -> Option<String> {
    if value.is_empty() || value.len() > 2_048 || value.trim() != value || value.contains(',') {
        return None;
    }
    let uri = value.parse::<axum::http::Uri>().ok()?;
    if uri
        .path_and_query()
        .is_some_and(|path| path.as_str() != "/")
    {
        return None;
    }
    canonical_origin_uri(&uri)
}

/// Derive an origin from PUBLIC_URL. A deployment may publish HTTP paths, but
/// browser Origin never contains one, so only scheme/authority participate.
pub fn canonical_public_web_origin(value: &str) -> Option<String> {
    let uri = value.parse::<axum::http::Uri>().ok()?;
    canonical_origin_uri(&uri)
}

pub(super) fn canonical_origin_uri(uri: &axum::http::Uri) -> Option<String> {
    let scheme = uri.scheme_str()?.to_ascii_lowercase();
    let authority = uri.authority()?;
    if authority.as_str().contains('@') {
        return None;
    }
    let host = authority
        .host()
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
        .unwrap_or(authority.host());
    if host.is_empty() {
        return None;
    }
    if scheme != "https" && !(scheme == "http" && web_origin_host_is_loopback(host)) {
        return None;
    }

    let host = host.to_ascii_lowercase();
    let host = if host.contains(':') {
        format!("[{host}]")
    } else {
        host
    };
    let port = authority
        .port()
        .map(|port| port.as_str().parse::<u16>())
        .transpose()
        .ok()?;
    let default_port = if scheme == "https" { 443 } else { 80 };
    match port {
        Some(port) if port != default_port => Some(format!("{scheme}://{host}:{port}")),
        _ => Some(format!("{scheme}://{host}")),
    }
}

pub(super) fn web_origin_host_is_loopback(host: &str) -> bool {
    let host = host.to_ascii_lowercase();
    host == "localhost"
        || host
            .strip_suffix(".localhost")
            .is_some_and(|prefix| !prefix.is_empty())
        || host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
}
