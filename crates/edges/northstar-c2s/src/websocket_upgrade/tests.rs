use super::*;

#[test]
fn websocket_requires_the_exact_xmpp_subprotocol_token() {
    let mut headers = HeaderMap::new();
    headers.append(
        header::SEC_WEBSOCKET_PROTOCOL,
        "chat, xmpp".parse().unwrap(),
    );
    assert!(offers_xmpp_subprotocol(&headers));

    for value in ["", "chat", "XMPP", "xmpp2", "not-xmpp"] {
        let mut headers = HeaderMap::new();
        if !value.is_empty() {
            headers.insert(header::SEC_WEBSOCKET_PROTOCOL, value.parse().unwrap());
        }
        assert!(!offers_xmpp_subprotocol(&headers), "accepted {value:?}");
    }
}

#[test]
fn websocket_requires_wss_except_for_direct_loopback_development() {
    let loopback: IpAddr = "127.0.0.1".parse().unwrap();
    let proxy: IpAddr = "10.0.0.2".parse().unwrap();
    let public: IpAddr = "192.0.2.1".parse().unwrap();
    assert!(secure_websocket_request(
        loopback,
        &HeaderMap::new(),
        &[],
        "http://localhost:8080"
    ));
    assert!(!secure_websocket_request(
        loopback,
        &HeaderMap::new(),
        &[],
        "https://chat.example"
    ));
    assert!(!secure_websocket_request(
        public,
        &HeaderMap::new(),
        &[],
        "http://localhost:8080"
    ));

    let mut headers = HeaderMap::new();
    headers.insert("x-forwarded-proto", "https".parse().unwrap());
    assert!(secure_websocket_request(
        proxy,
        &headers,
        &[proxy],
        "https://chat.example"
    ));
    assert!(!secure_websocket_request(
        public,
        &headers,
        &[proxy],
        "https://chat.example"
    ));
    headers.insert("x-forwarded-proto", "http".parse().unwrap());
    assert!(!secure_websocket_request(
        proxy,
        &headers,
        &[proxy],
        "https://chat.example"
    ));
    headers.insert("x-forwarded-proto", "https,http".parse().unwrap());
    assert!(!secure_websocket_request(
        proxy,
        &headers,
        &[proxy],
        "https://chat.example"
    ));
}

#[test]
fn websocket_origin_policy_accepts_native_and_secure_web_clients() {
    assert!(allowed_websocket_origin(
        &HeaderMap::new(),
        "https://chat.example",
        &[]
    ));
    for (origin, public_url, configured) in [
        (
            "https://chat.example",
            "https://chat.example/client",
            &[][..],
        ),
        ("https://chat.example:443", "https://chat.example", &[][..]),
        (
            "https://web.example:8443",
            "https://chat.example",
            &["https://web.example:8443".to_owned()][..],
        ),
        ("http://localhost:18080", "http://localhost:18080", &[][..]),
        ("http://127.0.0.1:18080", "http://127.0.0.1:18080", &[][..]),
        ("http://[::1]:18080", "http://[::1]:18080", &[][..]),
    ] {
        let mut headers = HeaderMap::new();
        headers.insert(header::ORIGIN, origin.parse().unwrap());
        assert!(
            allowed_websocket_origin(&headers, public_url, configured),
            "rejected {origin}"
        );
    }
}

#[test]
fn websocket_origin_policy_rejects_opaque_insecure_or_ambiguous_origins() {
    for origin in [
        "null",
        "http://example.org",
        "ftp://example.org",
        "https://user@example.org",
        "https://example.org/path",
        "https://example.org?query",
        "https://example.org:99999",
        "https://example.org, https://evil.example",
        "https://evil.example",
        "https://chat.example:8443",
    ] {
        let mut headers = HeaderMap::new();
        headers.insert(header::ORIGIN, origin.parse().unwrap());
        assert!(
            !allowed_websocket_origin(&headers, "https://chat.example", &[]),
            "accepted {origin}"
        );
    }
    let mut headers = HeaderMap::new();
    headers.append(header::ORIGIN, "https://one.example".parse().unwrap());
    headers.append(header::ORIGIN, "https://two.example".parse().unwrap());
    assert!(!allowed_websocket_origin(
        &headers,
        "https://one.example",
        &[]
    ));
}
