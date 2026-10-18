use super::*;
use crate::services::api_mutations::json_replay_headers;

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
    let source = super::module_source();
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
fn gateway_headers_require_one_verified_value_and_are_removed_before_dispatch() {
    let secret = Arc::new(zeroize::Zeroizing::new(
        uuid::Uuid::new_v4().simple().to_string(),
    ));
    let verifier = AdminGatewayVerifier::new(Some(Arc::clone(&secret)));
    let mut headers = HeaderMap::new();
    assert!(!authorize_administrator_gateway_headers(
        &verifier,
        &mut headers
    ));
    headers.insert(
        "x-northstar-admin-gateway-token",
        HeaderValue::from_bytes(&[0xff]).unwrap(),
    );
    assert!(!authorize_administrator_gateway_headers(
        &verifier,
        &mut headers
    ));
    headers.insert(
        "x-northstar-admin-gateway-token",
        HeaderValue::from_str(&secret).unwrap(),
    );
    headers.append(
        "x-northstar-admin-gateway-token",
        HeaderValue::from_str(&secret).unwrap(),
    );
    assert!(!authorize_administrator_gateway_headers(
        &verifier,
        &mut headers
    ));
    assert!(!authorize_administrator_gateway_headers(
        &AdminGatewayVerifier::new(None),
        &mut headers
    ));
    headers.remove("x-northstar-admin-gateway-token");
    headers.insert(
        "x-northstar-admin-gateway-token",
        HeaderValue::from_str(&secret).unwrap(),
    );
    assert!(authorize_administrator_gateway_headers(
        &verifier,
        &mut headers
    ));
    assert!(!headers.contains_key("x-northstar-admin-gateway-token"));
    assert!(authorize_administrator_gateway_headers(
        &AdminGatewayVerifier::new(None),
        &mut headers
    ));
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
        ApiPrincipalKind::Anonymous,
        "POST",
        "/api/v1/login",
    );
    assert_eq!(idempotency.request_id, request_id.0);
    assert_eq!(idempotency.idempotency_key, "login-request-key-0001");
    assert_eq!(
        idempotency.request_fingerprint,
        api_request_fingerprint("application/json", body)
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
    let replay = IdempotentResponse {
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
