use super::*;

#[test]
fn readiness_snapshots_are_typed_and_the_probe_budget_is_short() {
    assert!(readiness_response(ReadinessSnapshot::Ready).is_ok());
    assert!(readiness_response(ReadinessSnapshot::Unavailable("not ready")).is_err());
    assert!(READINESS_CACHE_TTL <= Duration::from_secs(2));
    assert!(READINESS_GATE_WAIT < READINESS_PROBE_TIMEOUT);
    assert!(READINESS_PROBE_TIMEOUT < Duration::from_secs(2));
}

#[test]
fn readiness_checks_runtime_authorities_before_reusing_the_database_cache() {
    let source = include_str!("../system.rs");
    let ready = source
        .split("pub async fn ready(")
        .nth(1)
        .expect("ready handler exists")
        .split("fn current_runtime_readiness_error")
        .next()
        .expect("runtime readiness helper follows ready handler");
    let first_runtime_check = ready
        .find("current_runtime_readiness_error(&endpoint.context)")
        .expect("ready handler checks current runtime health");
    let first_cache_read = ready
        .find("endpoint.cached().await")
        .expect("ready handler uses its database cache");
    assert!(first_runtime_check < first_cache_read);
    assert_eq!(
        ready
            .matches("current_runtime_readiness_error(&endpoint.context)")
            .count(),
        2,
        "runtime health must be checked before and after waiting for the gate"
    );
    assert_eq!(
        ready
            .matches("runtime_readiness_response(&endpoint.context, snapshot)")
            .count(),
        3,
        "both cached responses and the completed probe must recheck live authority"
    );
    assert!(
        ready
            .rfind("runtime_readiness_response(&endpoint.context, snapshot)")
            .unwrap()
            > ready
                .find("probe_readiness(&endpoint.context).await")
                .unwrap(),
        "a database probe started before shutdown cannot restore readiness"
    );
}

#[test]
fn readiness_persistence_uses_service_without_transport_database_authority() {
    let source = include_str!("../system.rs");
    let probe = source
        .split("async fn probe_readiness(")
        .nth(1)
        .expect("readiness probe exists")
        .split("pub async fn metrics(")
        .next()
        .expect("metrics handler follows readiness probe");
    assert!(probe.contains("context.validate_persistence("));
    assert!(probe.contains("context.cluster_authority_snapshot()"));
    assert!(!probe.contains("state.pool"));
    assert!(!probe.contains("crate::db::"));
    assert!(probe.contains("READINESS_PROBE_TIMEOUT"));
}

#[test]
fn database_metrics_use_one_read_only_transaction_without_pool_fanout() {
    let source = include_str!("../../db/metrics_snapshot_repository.rs");
    let collector = source
        .split("async fn collect(")
        .nth(1)
        .expect("database metrics collector exists");
    assert_eq!(collector.matches("self.pool.begin().await?").count(), 1);
    assert!(collector.contains("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY"));
    assert!(!collector.contains("tokio::try_join!"));
    assert!(collector.contains("transaction.commit().await?"));
    assert!(collector.matches("&mut *transaction").count() >= 8);
}

#[test]
fn metrics_authorization_precedes_cache_and_collection() {
    let source = include_str!("../system.rs");
    let handler = source
        .split("pub async fn metrics(")
        .nth(1)
        .unwrap()
        .split("fn metrics_request_authorized")
        .next()
        .unwrap();
    let authorize = handler.find("metrics_request_authorized(").unwrap();
    let cached = handler.find("endpoint.cached().await").unwrap();
    let collect = handler
        .find("collect_metrics(&endpoint.context).await")
        .unwrap();
    assert!(authorize < cached && cached < collect);
    assert_eq!(handler.matches("endpoint.cached().await").count(), 2);
}

#[test]
fn upload_readiness_is_fail_closed_but_allows_bounded_recovery_drain() {
    use crate::services::upload_safety::UploadSafetyState;

    assert!(upload_storage_ready(UploadSafetyState::Disabled));
    assert!(upload_storage_ready(UploadSafetyState::Healthy));
    assert!(upload_storage_ready(UploadSafetyState::RecoveryDraining));
    for unsafe_state in [
        UploadSafetyState::Unproven,
        UploadSafetyState::NamespaceUnsafe,
        UploadSafetyState::CapacityAuthorityUnsafe,
        UploadSafetyState::LedgerMismatch,
    ] {
        assert!(!upload_storage_ready(unsafe_state));
    }
}

#[test]
fn admin_cleanup_readiness_requires_capacity_and_convergence() {
    let healthy = crate::db::AdminSessionCleanupSnapshot {
        pending: 1,
        running: 0,
        oldest_age_seconds: ADMIN_CLEANUP_MAX_READY_AGE_SECONDS,
        maximum_attempts: ADMIN_CLEANUP_MAX_READY_ATTEMPTS - 1,
        queued: 1,
        capacity: 100_000,
    };
    assert!(admin_session_cleanup_ready(&healthy));

    assert!(!admin_session_cleanup_ready(
        &crate::db::AdminSessionCleanupSnapshot {
            oldest_age_seconds: ADMIN_CLEANUP_MAX_READY_AGE_SECONDS + 0.001,
            ..healthy
        }
    ));
    assert!(!admin_session_cleanup_ready(
        &crate::db::AdminSessionCleanupSnapshot {
            maximum_attempts: ADMIN_CLEANUP_MAX_READY_ATTEMPTS,
            ..healthy
        }
    ));
    assert!(!admin_session_cleanup_ready(
        &crate::db::AdminSessionCleanupSnapshot {
            pending: 100_000,
            queued: 100_000,
            ..healthy
        }
    ));
    assert!(!admin_session_cleanup_ready(
        &crate::db::AdminSessionCleanupSnapshot {
            running: 1,
            ..healthy
        }
    ));
    assert!(admin_session_cleanup_ready(
        &crate::db::AdminSessionCleanupSnapshot {
            pending: 0,
            oldest_age_seconds: 0.0,
            maximum_attempts: 0,
            queued: 0,
            ..healthy
        }
    ));
}

#[test]
fn default_reverse_proxy_does_not_publish_database_readiness() {
    let caddy = include_str!("../../../deploy/Caddyfile");
    assert!(caddy.contains("@private_observability path /metrics /readyz"));
    assert!(caddy.contains("respond @private_observability 404"));
}

#[tokio::test]
async fn api_documentation_is_same_origin_read_only_and_strictly_isolated() {
    let response = api_docs().await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL).unwrap(),
        "no-store, max-age=0"
    );
    let csp = response
        .headers()
        .get("content-security-policy")
        .unwrap()
        .to_str()
        .unwrap();
    for required in [
        "default-src 'none'",
        "script-src 'self'",
        "connect-src 'self'",
        "object-src 'none'",
        "form-action 'none'",
        "frame-ancestors 'none'",
    ] {
        assert!(csp.contains(required), "documentation CSP lost {required}");
    }
    assert!(!csp.contains("unsafe-inline"));
    assert!(!csp.contains("unsafe-eval"));
    let body = axum::body::to_bytes(response.into_body(), 32 * 1024)
        .await
        .unwrap();
    let body = std::str::from_utf8(&body).unwrap();
    assert!(body.contains("/api/docs/assets/5.32.14/swagger-ui-bundle.js"));
    assert!(body.contains("/api/docs/assets/5.32.14/swagger-ui.css"));
    assert!(body.contains("northstar-swagger-initializer.js"));
    assert!(!body.contains("http://"));
    assert!(!body.contains("https://"));
    assert!(!body.contains("localStorage"));

    let response = openapi_document().await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get(header::CONTENT_TYPE).unwrap(),
        "application/yaml; charset=utf-8"
    );
    let body = axum::body::to_bytes(response.into_body(), 2 * 1024 * 1024)
        .await
        .unwrap();
    assert_eq!(body.as_ref(), include_bytes!("../../../docs/openapi.yaml"));
}

#[test]
fn metrics_require_loopback_or_the_exact_constant_time_bearer_boundary() {
    let loopback: IpAddr = "127.0.0.1".parse().unwrap();
    let public: IpAddr = "192.0.2.10".parse().unwrap();
    let empty = HeaderMap::new();
    assert!(metrics_credentials_authorized(None, loopback, &empty));
    assert!(!metrics_credentials_authorized(None, public, &empty));

    let token = "0123456789abcdef0123456789abcdef";
    assert!(!metrics_credentials_authorized(
        Some(token),
        loopback,
        &empty
    ));
    for value in [
        token,
        "0123456789abcdef0123456789abcdee",
        "0123456789abcdef0123456789abcdef0",
    ] {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            format!("Bearer {value}").parse().unwrap(),
        );
        assert_eq!(
            metrics_credentials_authorized(Some(token), public, &headers),
            value == token
        );
    }

    let mut mixed_case = HeaderMap::new();
    mixed_case.insert(
        header::AUTHORIZATION,
        format!("bEaReR {token}").parse().unwrap(),
    );
    assert!(metrics_credentials_authorized(
        Some(token),
        public,
        &mixed_case
    ));

    let mut duplicate = HeaderMap::new();
    duplicate.append(
        header::AUTHORIZATION,
        format!("Bearer {token}").parse().unwrap(),
    );
    duplicate.append(
        header::AUTHORIZATION,
        format!("Bearer {token}").parse().unwrap(),
    );
    assert!(!metrics_credentials_authorized(
        Some(token),
        public,
        &duplicate
    ));

    let mut extra_field = HeaderMap::new();
    extra_field.insert(
        header::AUTHORIZATION,
        format!("Bearer {token} ignored").parse().unwrap(),
    );
    assert!(!metrics_credentials_authorized(
        Some(token),
        public,
        &extra_field
    ));
}

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
use std::str::FromStr;

#[test]
fn test_request_base_url_untrusted_ip() {
    let mut headers = HeaderMap::new();
    headers.insert(header::HOST, "evil.com".parse().unwrap());
    headers.insert("x-forwarded-host", "example.com".parse().unwrap());

    let url = request_base_url(
        IpAddr::from_str("192.168.1.1").unwrap(),
        &headers,
        &[IpAddr::from_str("10.0.0.1").unwrap()],
        "example.com",
        "https://example.com:8443",
    );
    // Untrusted IP with evil.com Host should fallback to public_url
    assert_eq!(url, "https://example.com:8443");
}

#[test]
fn test_request_base_url_untrusted_ip_matching_domain() {
    let mut headers = HeaderMap::new();
    headers.insert(header::HOST, "example.com:443".parse().unwrap());

    let url = request_base_url(
        IpAddr::from_str("192.168.1.1").unwrap(),
        &headers,
        &[IpAddr::from_str("10.0.0.1").unwrap()],
        "example.com",
        "https://example.com",
    );
    // Untrusted IP but Host matches domain, so allowed.
    assert_eq!(url, "https://example.com:443");
}

#[test]
fn test_request_base_url_trusted_ip() {
    let mut headers = HeaderMap::new();
    headers.insert("x-forwarded-host", "api.example.com".parse().unwrap());
    headers.insert("x-forwarded-proto", "http".parse().unwrap());

    let url = request_base_url(
        IpAddr::from_str("10.0.0.1").unwrap(),
        &headers,
        &[IpAddr::from_str("10.0.0.1").unwrap()],
        "example.com",
        "https://example.com",
    );
    // Trusted IP gets to use x-forwarded-*
    assert_eq!(url, "http://api.example.com");
}

#[test]
fn rejects_untrusted_ipv6_confusion_and_forwarded_scheme_injection() {
    let mut headers = HeaderMap::new();
    headers.insert(header::HOST, "example.com.evil:443".parse().unwrap());
    headers.insert("x-forwarded-proto", "javascript".parse().unwrap());
    let url = request_base_url(
        IpAddr::from_str("192.0.2.1").unwrap(),
        &headers,
        &[],
        "example.com",
        "https://example.com",
    );
    assert_eq!(url, "https://example.com");
}

#[test]
fn xep_0156_always_advertises_a_secure_websocket_url() {
    assert_eq!(
        secure_websocket_url("http://localhost:18080"),
        "wss://localhost:18080/xmpp-websocket"
    );
}

#[test]
fn xep_0156_bosh_is_advertised_only_when_enabled_over_https() {
    assert_eq!(advertised_bosh_url(false, "https://example.org"), None);
    assert_eq!(advertised_bosh_url(true, "http://example.org"), None);
    assert_eq!(
        advertised_bosh_url(true, "https://example.org/"),
        Some("https://example.org/http-bind".to_owned())
    );
}

#[test]
fn xep_0487_is_only_asserted_with_explicit_public_ips() {
    let legacy = host_meta_json_document(
        Some("wss://example.org/xmpp-websocket"),
        None,
        "example.org",
        &[],
        300,
        10,
        50,
        5223,
        Some(5270),
    );
    assert!(legacy.get("xmpp").is_none());
    assert_eq!(legacy["links"].as_array().unwrap().len(), 1);

    let with_bosh = host_meta_json_document(
        Some("wss://example.org/xmpp-websocket"),
        Some("https://example.org/http-bind"),
        "example.org",
        &[],
        300,
        10,
        50,
        5223,
        Some(5270),
    );
    assert_eq!(with_bosh["links"].as_array().unwrap().len(), 2);
    assert_eq!(
        with_bosh["links"][1]["rel"],
        "urn:xmpp:alt-connections:xbosh"
    );

    let direct_tls_only = host_meta_json_document(
        None,
        None,
        "example.org",
        &["192.0.2.10".parse().unwrap()],
        300,
        10,
        50,
        5223,
        Some(5270),
    );
    assert_eq!(direct_tls_only["links"].as_array().unwrap().len(), 2);
    assert_eq!(
        direct_tls_only["links"][0]["rel"],
        "urn:xmpp:alt-connections:tls"
    );

    let modern = host_meta_json_document(
        Some("wss://example.org/xmpp-websocket"),
        None,
        "example.org",
        &[
            "192.0.2.10".parse().unwrap(),
            "2001:db8::10".parse().unwrap(),
        ],
        600,
        10,
        50,
        5223,
        Some(5270),
    );
    assert_eq!(modern["xmpp"]["ttl"], 600);
    let links = modern["links"].as_array().unwrap();
    assert_eq!(links.len(), 3);
    for link in links {
        assert_eq!(link["sni"], "example.org");
        assert_eq!(link["priority"], 10);
        assert_eq!(link["weight"], 50);
        assert_eq!(link["ips"].as_array().unwrap().len(), 2);
    }
    assert_eq!(links[1]["port"], 5223);
    assert_eq!(links[2]["port"], 5270);
}

#[test]
fn failed_database_collector_does_not_publish_plausible_zeroes() {
    let failed = render_database_collector(None);
    assert!(failed.contains("xmpp_database_collector_up 0\n"));
    for absent in [
        "xmpp_resumable_sessions ",
        "xmpp_s2s_outbox_pending_rows ",
        "xmpp_s2s_outbox_pending_bytes ",
        "xmpp_s2s_outbox_oldest_age_seconds ",
        "xmpp_s2s_outbox_due_rows ",
        "xmpp_s2s_outbox_locked_rows ",
        "xmpp_component_outbox_pending_rows ",
        "xmpp_api_operations_pending ",
        "xmpp_api_operations_running ",
        "xmpp_api_operations_indeterminate ",
        "xmpp_api_operations_oldest_active_age_seconds ",
        "xmpp_admin_session_cleanup_pending ",
        "xmpp_admin_session_cleanup_running ",
        "xmpp_admin_session_cleanup_oldest_age_seconds ",
        "xmpp_admin_session_cleanup_maximum_attempts ",
        "xmpp_admin_session_cleanup_capacity_used ",
        "xmpp_admin_session_cleanup_capacity_limit ",
        "xmpp_moderation_pending_reports ",
        "xmpp_moderation_pending_appeals ",
        "xmpp_active_invitation_tokens ",
        "xmpp_legal_holds_active ",
        "xmpp_legal_hold_preserved_offline_records ",
        "xmpp_governance_export_leases_active ",
        "xmpp_governance_export_leases_expired_incomplete ",
        "xmpp_capacity_accounts_used ",
        "xmpp_capacity_accounts_limit ",
        "xmpp_capacity_muc_rooms_used ",
        "xmpp_capacity_muc_rooms_limit ",
        "xmpp_capacity_live_sessions_used ",
        "xmpp_capacity_live_sessions_limit ",
        "xmpp_capacity_resumable_sessions_used ",
        "xmpp_capacity_resumable_sessions_limit ",
        "xmpp_capacity_configuration_epoch ",
        "xmpp_capacity_muc_rooms_per_owner_limit ",
        "xmpp_capacity_sessions_per_account_limit ",
    ] {
        assert!(
            !failed.contains(absent),
            "published a fake zero for {absent}"
        );
    }

    let snapshot = crate::services::metrics_snapshot::S2sOutboxSnapshot {
        pending_rows: 11,
        pending_bytes: 12_345,
        oldest_age_seconds: 67.5,
        due_rows: 2,
        locked_rows: 3,
        component_pending_rows: 4,
    };
    let operations = crate::services::metrics_snapshot::ApiOperationSnapshot {
        pending: 6,
        running: 7,
        indeterminate: 8,
        oldest_active_age_seconds: 91.25,
    };
    let healthy = render_database_collector(Some(&(
        5,
        snapshot,
        operations,
        crate::services::metrics_snapshot::AdminSessionCleanupSnapshot {
            pending: 27,
            running: 28,
            oldest_age_seconds: 29.5,
            maximum_attempts: 30,
            queued: 55,
            capacity: 100_000,
        },
        (9, 10, 11),
        crate::services::metrics_snapshot::DataGovernanceSnapshot {
            active_holds: 12,
            preserved_offline_records: 13,
            active_export_leases: 14,
            expired_incomplete_export_leases: 15,
        },
        crate::services::metrics_snapshot::DeploymentCapacitySnapshot {
            configuration_epoch: 16,
            accounts_used: 17,
            accounts_limit: 18,
            muc_rooms_used: 19,
            muc_rooms_limit: 20,
            live_sessions_used: 21,
            live_sessions_limit: 22,
            resumable_sessions_used: 23,
            resumable_sessions_limit: 24,
            muc_rooms_per_owner_limit: 25,
            sessions_per_account_limit: 26,
        },
    )));
    for expected in [
        "xmpp_database_collector_up 1\n",
        "xmpp_resumable_sessions 5\n",
        "xmpp_s2s_outbox_pending_rows 11\n",
        "xmpp_s2s_outbox_pending_bytes 12345\n",
        "xmpp_s2s_outbox_oldest_age_seconds 67.500000\n",
        "xmpp_s2s_outbox_due_rows 2\n",
        "xmpp_s2s_outbox_locked_rows 3\n",
        "xmpp_component_outbox_pending_rows 4\n",
        "xmpp_api_operations_pending 6\n",
        "xmpp_api_operations_running 7\n",
        "xmpp_api_operations_indeterminate 8\n",
        "xmpp_api_operations_oldest_active_age_seconds 91.250000\n",
        "xmpp_admin_session_cleanup_pending 27\n",
        "xmpp_admin_session_cleanup_running 28\n",
        "xmpp_admin_session_cleanup_oldest_age_seconds 29.500000\n",
        "xmpp_admin_session_cleanup_maximum_attempts 30\n",
        "xmpp_admin_session_cleanup_capacity_used 55\n",
        "xmpp_admin_session_cleanup_capacity_limit 100000\n",
        "xmpp_moderation_pending_reports 9\n",
        "xmpp_moderation_pending_appeals 10\n",
        "xmpp_active_invitation_tokens 11\n",
        "xmpp_legal_holds_active 12\n",
        "xmpp_legal_hold_preserved_offline_records 13\n",
        "xmpp_governance_export_leases_active 14\n",
        "xmpp_governance_export_leases_expired_incomplete 15\n",
        "xmpp_capacity_accounts_used 17\n",
        "xmpp_capacity_accounts_limit 18\n",
        "xmpp_capacity_muc_rooms_used 19\n",
        "xmpp_capacity_muc_rooms_limit 20\n",
        "xmpp_capacity_live_sessions_used 21\n",
        "xmpp_capacity_live_sessions_limit 22\n",
        "xmpp_capacity_resumable_sessions_used 23\n",
        "xmpp_capacity_resumable_sessions_limit 24\n",
        "xmpp_capacity_configuration_epoch 16\n",
        "xmpp_capacity_muc_rooms_per_owner_limit 25\n",
        "xmpp_capacity_sessions_per_account_limit 26\n",
    ] {
        assert!(healthy.contains(expected), "missing {expected}");
    }
}

#[test]
fn password_work_rejections_are_exported_as_a_counter() {
    let rendered = render_password_work_metrics(17);
    assert!(rendered.contains(
        "# HELP xmpp_password_work_rejections_total Password hashing or verification requests rejected by the bounded CPU admission gate.\n"
    ));
    assert!(rendered.contains("# TYPE xmpp_password_work_rejections_total counter\n"));
    assert!(rendered.contains("xmpp_password_work_rejections_total 17\n"));
}

#[test]
fn openapi_contract_lists_exact_router_methods() {
    use std::collections::BTreeSet;

    let document = include_str!("../../../docs/openapi.yaml");
    assert!(document.starts_with("openapi: 3.1.0\n"));
    assert!(document.contains("\npaths:\n"));
    assert!(document.contains("\ncomponents:\n"));
    assert!(!document.contains('\t'));

    let mut current_path = None;
    let mut documented = BTreeSet::new();
    for line in document.lines() {
        if let Some(path) = line
            .strip_prefix("  ")
            .and_then(|line| line.strip_suffix(':'))
            .filter(|line| line.starts_with('/'))
        {
            current_path = Some(path);
            continue;
        }
        if line == "components:" {
            current_path = None;
            continue;
        }
        let Some(path) = current_path else { continue };
        let method = match line {
            "    get:" => Some("GET"),
            "    post:" => Some("POST"),
            "    put:" => Some("PUT"),
            "    patch:" => Some("PATCH"),
            "    delete:" => Some("DELETE"),
            "    options:" => Some("OPTIONS"),
            _ => None,
        };
        if let Some(method) = method {
            documented.insert(format!("{method} {path}"));
        }
    }

    let router_source = crate::api::module_source();
    let mut router_contract = BTreeSet::new();
    let mut search_from = 0;
    while let Some(relative) = router_source[search_from..].find(".route(") {
        let route_offset = search_from + relative;
        let opening = route_offset + ".route".len();
        let mut depth = 0_u32;
        let mut quoted = false;
        let mut escaped = false;
        let mut closing = None;
        for (offset, character) in router_source[opening..].char_indices() {
            if quoted {
                if escaped {
                    escaped = false;
                } else if character == '\\' {
                    escaped = true;
                } else if character == '"' {
                    quoted = false;
                }
                continue;
            }
            match character {
                '"' => quoted = true,
                '(' => depth = depth.saturating_add(1),
                ')' => {
                    depth = depth.saturating_sub(1);
                    if depth == 0 {
                        closing = Some(opening + offset);
                        break;
                    }
                }
                _ => {}
            }
        }
        let closing = closing.expect("balanced route call");
        let call = &router_source[opening + 1..closing];
        let quote = call.find('"').expect("route path opening quote");
        let path_tail = &call[quote + 1..];
        let path_end = path_tail.find('"').expect("route path closing quote");
        let path = &path_tail[..path_end];
        let handler = &path_tail[path_end + 1..];
        for (method, needles) in [
            ("GET", [" get(", ".get("]),
            ("POST", [" post(", ".post("]),
            ("PUT", [" put(", ".put("]),
            ("PATCH", [" patch(", ".patch("]),
            ("DELETE", [" delete(", ".delete("]),
            ("OPTIONS", [" options(", ".options("]),
        ] {
            if needles.iter().any(|needle| handler.contains(needle)) {
                router_contract.insert(format!("{method} {path}"));
            }
        }
        search_from = closing + 1;
    }
    assert!(!router_contract.is_empty(), "router parser found no routes");
    assert_eq!(documented, router_contract);

    for required_contract in [
        "schema: { $ref: \"#/components/schemas/ReportModerationPatch\" }",
        "schema: { $ref: \"#/components/schemas/AppealModerationPatch\" }",
        "additionalProperties: false",
        "name: cursor",
        "OperationTarget:",
    ] {
        assert!(document.contains(required_contract));
    }
    assert!(
        !document.contains("name: offset"),
        "offset pagination must not reappear in the public contract"
    );
}
