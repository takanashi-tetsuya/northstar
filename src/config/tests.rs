//! Unit tests of configuration loading, validation, origins, secrets and listener plans.

use super::{
    authentication_master_secrets_are_independent, domain_list, domain_pattern_matches,
    ephemeral_development_secret_allowed, listener_addresses_overlap, load_component_credentials,
    parse_external_service, parse_pow_v1_compatibility_until, parse_xep_0487_ips, read_secret_file,
    redis_endpoint_is_local, resolve_admin_command_pool_mode, resolve_storage_pool_mode,
    resolve_web_capability_plan, runtime_connection_budget_manifest,
    storage_connection_budget_manifest, valid_http_bearer_secret, validate_cluster_dialback_secret,
    validate_cluster_fast_secret, validate_component_capacity, validate_component_transport,
    validate_redis_transport, validate_runtime_pool_budget, validate_shared_runtime_secret,
    validate_web_admin_exposure, AdminCommandPoolMode, ComponentConnectionMode,
    ComponentCredential, StoragePoolMode, DATABASE_MAX_CONNECTIONS_LIMIT,
    DATABASE_PRIMARY_POOL_MIN_CONNECTIONS, RUNTIME_ROLE_CONNECTION_LIMIT,
    RUNTIME_ROLE_RESERVED_CONNECTIONS, STORAGE_MAX_ENABLED_NODES, STORAGE_POOL_MAX_CONNECTIONS,
    STORAGE_ROLE_CONNECTION_LIMIT,
};

fn web_dependency_fixture() -> super::RawConfig {
    envy::from_iter::<_, super::RawConfig>(std::iter::empty::<(String, String)>())
        .expect("RawConfig defaults must deserialize")
}

#[test]
fn external_route_policy_keeps_component_and_federation_domains_distinct() {
    let policy = super::ExternalRouteDomainPolicy {
        local_domain: "example.test".to_owned(),
        federation_enabled: true,
        federation_allowlist: vec!["*.federated.test".to_owned()],
        federation_denylist: vec!["blocked.federated.test".to_owned()],
        component_domains: vec!["bridge.example.test".to_owned()],
    };
    for (domain, federation, external) in [
        ("chat.federated.test", true, true),
        ("blocked.federated.test", false, false),
        ("federated.test", false, false),
        ("bridge.example.test", false, true),
        ("mix.example.test", false, false),
        ("example.test", false, false),
    ] {
        assert_eq!(
            policy.federation_domain_allowed(domain),
            federation,
            "{domain}"
        );
        assert_eq!(
            policy.external_route_domain_allowed(domain),
            external,
            "{domain}"
        );
    }
    let mut federation_disabled = policy.clone();
    federation_disabled.federation_enabled = false;
    assert!(!federation_disabled.federation_domain_allowed("chat.federated.test"));
    assert!(federation_disabled.external_route_domain_allowed("bridge.example.test"));
}

#[test]
fn test_listener_activation_is_explicit_and_loopback_only() {
    let mut raw = web_dependency_fixture();
    raw.test_listener_activation = true;
    raw.test_readiness_file = Some(std::env::temp_dir().join("northstar-ready.json"));
    raw.test_readiness_nonce = Some("0123456789abcdef".to_owned());
    super::validate_test_listener_activation(&raw, true, true).unwrap();

    assert!(super::validate_test_listener_activation(&raw, false, true).is_err());
    raw.test_readiness_nonce = Some("not-a-canonical-nonce".to_owned());
    assert!(super::validate_test_listener_activation(&raw, true, true).is_err());

    raw.test_listener_activation = false;
    assert!(super::validate_test_listener_activation(&raw, true, true).is_err());
}

#[test]
fn test_listener_activation_uses_ephemeral_listener_binds_only_when_inherited() {
    let mut raw = web_dependency_fixture();
    let configured_xmpp = raw.xmpp_bind;
    let configured_admin = raw.web_admin_bind;

    super::apply_test_listener_defaults(
        &mut raw,
        super::TestListenerBindExplicitness {
            xmpp: true,
            web_admin: true,
            ..super::TestListenerBindExplicitness::default()
        },
    );
    assert_eq!(raw.xmpp_bind, configured_xmpp);
    assert_eq!(raw.web_admin_bind, configured_admin);

    raw.test_listener_activation = true;
    super::apply_test_listener_defaults(&mut raw, super::TestListenerBindExplicitness::default());
    let ephemeral = "127.0.0.1:0".parse().unwrap();
    assert_eq!(raw.xmpp_bind, ephemeral);
    assert_eq!(raw.xmpps_bind, ephemeral);
    assert_eq!(raw.http_bind, ephemeral);
    assert_eq!(raw.web_admin_bind, ephemeral);
    assert_eq!(raw.metrics_bind, ephemeral);
    assert_eq!(raw.s2s_bind, ephemeral);
    assert_eq!(raw.s2s_tls_bind, ephemeral);
    assert_eq!(raw.component_bind, ephemeral);

    raw.web_admin_bind = "127.0.0.1:8443".parse().unwrap();
    super::apply_test_listener_defaults(
        &mut raw,
        super::TestListenerBindExplicitness {
            web_admin: true,
            ..super::TestListenerBindExplicitness::default()
        },
    );
    assert_eq!(raw.web_admin_bind, "127.0.0.1:8443".parse().unwrap());
}

#[test]
fn test_listener_activation_never_derives_a_public_url_from_port_zero() {
    let mut raw = web_dependency_fixture();
    raw.test_listener_activation = true;
    raw.http_bind = "127.0.0.1:0".parse().unwrap();
    assert!(super::resolve_public_url(&raw, "localhost", true).is_err());

    raw.public_url = Some("https://fixture.example.test/".to_owned());
    assert_eq!(
        super::resolve_public_url(&raw, "localhost", true).unwrap(),
        "https://fixture.example.test"
    );

    raw.public_url = None;
    raw.http_bind = "127.0.0.1:18080".parse().unwrap();
    assert_eq!(
        super::resolve_public_url(&raw, "localhost", false).unwrap(),
        "http://localhost:18080"
    );
}

#[test]
fn web_client_requires_its_rest_and_websocket_dependencies() {
    let mut without_rest = web_dependency_fixture();
    without_rest.rest_api_enabled = false;
    assert!(resolve_web_capability_plan(&without_rest).is_err());

    let mut without_websocket = web_dependency_fixture();
    without_websocket.websocket_enabled = false;
    assert!(resolve_web_capability_plan(&without_websocket).is_err());
}

#[test]
fn disabling_web_client_fails_invitation_registration_closed() {
    let mut raw = web_dependency_fixture();
    raw.web_client_enabled = false;
    raw.invitation_required = true;
    raw.open_registration = true;
    let plan = resolve_web_capability_plan(&raw).unwrap();
    assert!(plan.registration.lock.is_locked());
    assert_eq!(plan.registration.mode, super::RegistrationMode::Closed);
}

#[test]
fn disabling_xep_0363_removes_new_upload_admission_but_keeps_safe_drain() {
    let mut raw = web_dependency_fixture();
    raw.xep_0363_enabled = false;
    let plan = resolve_web_capability_plan(&raw).unwrap();
    assert_eq!(plan.upload_mode, super::UploadMode::DrainReadOnly);
    assert!(!plan.upload.slot_admission);
    assert!(!plan.upload.put);
    assert!(!plan.upload.xmpp_advertisement);
    assert!(plan.upload.get);
    assert!(plan.upload.cleanup_worker);
}

#[test]
fn runtime_role_pool_budget_reserves_all_nonprimary_connections() {
    let manifest = runtime_connection_budget_manifest();
    assert_eq!(manifest.schema_version, 1);
    assert_eq!(manifest.runtime_role_connection_limit, 64);
    assert_eq!(manifest.primary_pool_min_connections, 2);
    assert_eq!(manifest.primary_pool_max_connections, 60);
    assert_eq!(manifest.omemo_recovery_pool_max_connections, 2);
    assert_eq!(manifest.sm_authority_listener_max_connections, 1);
    assert_eq!(manifest.service_control_pool_max_connections, 1);
    assert_eq!(manifest.auxiliary_connections, 4);
    assert_eq!(RUNTIME_ROLE_CONNECTION_LIMIT, 64);
    assert_eq!(RUNTIME_ROLE_RESERVED_CONNECTIONS, 4);
    assert_eq!(DATABASE_PRIMARY_POOL_MIN_CONNECTIONS, 2);
    assert_eq!(DATABASE_MAX_CONNECTIONS_LIMIT, 60);

    // The listener/MIX stress profile intentionally uses a tiny *primary*
    // pool. It remains valid; the fixed auxiliary pools are accounted for
    // separately rather than making the test's DB_MAX=2 impossible.
    assert!(validate_runtime_pool_budget(2, 0).is_ok());
    assert!(validate_runtime_pool_budget(DATABASE_MAX_CONNECTIONS_LIMIT, 0).is_ok());
    assert!(validate_runtime_pool_budget(
        DATABASE_MAX_CONNECTIONS_LIMIT,
        DATABASE_MAX_CONNECTIONS_LIMIT
    )
    .is_ok());
    assert!(validate_runtime_pool_budget(DATABASE_MAX_CONNECTIONS_LIMIT + 1, 0).is_err());
    assert!(validate_runtime_pool_budget(2, 3).is_err());
    assert!(validate_runtime_pool_budget(1, 0).is_err());
    assert!(validate_runtime_pool_budget(0, 0).is_err());
}

#[test]
fn command_pool_mode_only_shares_the_primary_pool_in_explicit_unsafe_development() {
    assert_eq!(
        resolve_admin_command_pool_mode(true, "").unwrap(),
        AdminCommandPoolMode::SharedUnsafeDevelopment
    );
    assert!(resolve_admin_command_pool_mode(
        true,
        "postgres://northstar_commands:secret@127.0.0.1/northstar"
    )
    .is_err());
    assert!(resolve_admin_command_pool_mode(false, "").is_err());
    assert_eq!(
        resolve_admin_command_pool_mode(
            false,
            "postgres://northstar_commands:secret@127.0.0.1/northstar"
        )
        .unwrap(),
        AdminCommandPoolMode::DedicatedProductionRole
    );
}

#[test]
fn storage_pool_is_required_only_for_enabled_or_draining_production_uploads() {
    assert_eq!(STORAGE_POOL_MAX_CONNECTIONS, 2);
    let budget = storage_connection_budget_manifest();
    assert_eq!(budget.schema_version, 1);
    assert_eq!(
        budget.storage_role_connection_limit,
        STORAGE_ROLE_CONNECTION_LIMIT
    );
    assert_eq!(budget.enabled_pool_max_connections_per_node, 2);
    assert_eq!(budget.disabled_pool_max_connections_per_node, 0);
    assert_eq!(
        budget.max_enabled_nodes_at_pool_limit,
        STORAGE_MAX_ENABLED_NODES
    );
    assert_eq!(STORAGE_MAX_ENABLED_NODES, 8);
    assert_eq!(
        STORAGE_MAX_ENABLED_NODES * STORAGE_POOL_MAX_CONNECTIONS,
        STORAGE_ROLE_CONNECTION_LIMIT
    );
    assert!(
        (budget.max_enabled_nodes_at_pool_limit + 1) * budget.enabled_pool_max_connections_per_node
            > budget.storage_role_connection_limit
    );
    assert_eq!(
        serde_json::to_value(budget).unwrap(),
        serde_json::json!({
            "schema_version": 1,
            "storage_role_connection_limit": 16,
            "enabled_pool_max_connections_per_node": 2,
            "disabled_pool_max_connections_per_node": 0,
            "max_enabled_nodes_at_pool_limit": 8
        })
    );
    assert_eq!(
        resolve_storage_pool_mode(false, false, "").unwrap(),
        StoragePoolMode::Disabled
    );
    assert_eq!(
        resolve_storage_pool_mode(false, false, "postgres://storage").unwrap(),
        StoragePoolMode::Disabled
    );
    assert!(resolve_storage_pool_mode(false, true, "").is_err());
    assert_eq!(
        resolve_storage_pool_mode(false, true, "postgres://storage").unwrap(),
        StoragePoolMode::DedicatedProductionRole
    );
    assert_eq!(
        resolve_storage_pool_mode(true, true, "").unwrap(),
        StoragePoolMode::SharedUnsafeDevelopment
    );
    assert!(resolve_storage_pool_mode(true, true, "postgres://storage").is_err());
}

#[test]
fn administration_is_strictly_loopback_only() {
    let public = "0.0.0.0:8081".parse().unwrap();
    let loopback = "127.0.0.1:8081".parse().unwrap();
    assert!(validate_web_admin_exposure(true, loopback).is_ok());
    assert!(validate_web_admin_exposure(false, public).is_ok());
    assert!(validate_web_admin_exposure(true, public).is_err());
}

#[test]
fn ephemeral_authentication_keys_require_every_development_fence() {
    assert!(ephemeral_development_secret_allowed(
        true, false, true, true
    ));
    for denied in [
        (false, false, true, true),
        (true, true, true, true),
        (true, false, false, true),
        (true, false, true, false),
    ] {
        assert!(!ephemeral_development_secret_allowed(
            denied.0, denied.1, denied.2, denied.3
        ));
    }
}

#[test]
fn fast_and_dummy_scram_master_keys_cannot_reuse_exact_bytes() {
    let fast = "f".repeat(32);
    let dummy = "d".repeat(32);
    assert!(authentication_master_secrets_are_independent(
        Some(&fast),
        Some(&dummy)
    ));
    assert!(!authentication_master_secrets_are_independent(
        Some(&fast),
        Some(&fast)
    ));
    assert!(authentication_master_secrets_are_independent(
        None,
        Some(&dummy)
    ));
}

#[test]
fn clustered_dialback_requires_a_shared_secret_file() {
    assert!(validate_cluster_dialback_secret(true, true, None).is_err());
    assert!(validate_cluster_dialback_secret(
        true,
        true,
        Some(std::path::Path::new("/run/secrets/dialback")),
    )
    .is_ok());
    assert!(validate_cluster_dialback_secret(false, true, None).is_ok());
    assert!(validate_cluster_dialback_secret(true, false, None).is_ok());
}

#[test]
fn clustered_fast_requires_a_shared_secret_file() {
    assert!(validate_cluster_fast_secret(true, None).is_err());
    assert!(
        validate_cluster_fast_secret(true, Some(std::path::Path::new("/run/secrets/fast")),)
            .is_ok()
    );
    assert!(validate_cluster_fast_secret(false, None).is_ok());
}

#[test]
fn shared_runtime_secrets_reject_empty_short_long_and_nul_values() {
    assert!(validate_shared_runtime_secret("TEST_SECRET", None).is_ok());
    assert!(validate_shared_runtime_secret("TEST_SECRET", Some("")).is_err());
    assert!(validate_shared_runtime_secret("TEST_SECRET", Some(&"x".repeat(31))).is_err());
    assert!(validate_shared_runtime_secret("TEST_SECRET", Some(&"x".repeat(32))).is_ok());
    assert!(validate_shared_runtime_secret("TEST_SECRET", Some(&"x".repeat(4096))).is_ok());
    assert!(validate_shared_runtime_secret("TEST_SECRET", Some(&"x".repeat(4097))).is_err());
    assert!(
        validate_shared_runtime_secret("TEST_SECRET", Some(&format!("{}\0", "x".repeat(32))))
            .is_err()
    );
}

#[test]
fn shared_key_file_length_is_validated_after_protected_read() {
    let path = std::env::temp_dir().join(format!(
        "northstar-short-shared-key-{}",
        uuid::Uuid::new_v4().simple()
    ));
    std::fs::write(&path, "x".repeat(31)).unwrap();
    restrict(&path);
    let value = read_secret_file(&path, "FAST_TOKEN_SECRET_FILE").unwrap();
    assert!(validate_shared_runtime_secret("FAST_TOKEN_SECRET", Some(&value)).is_err());
    std::fs::remove_file(path).unwrap();
}

#[cfg(unix)]
fn restrict(path: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
}

#[cfg(not(unix))]
fn restrict(_path: &std::path::Path) {}

#[test]
fn external_services_accept_dns_ipv4_and_bracketed_ipv6() {
    assert_eq!(
        parse_external_service("turn.example.test:3478").unwrap(),
        ("turn.example.test".to_owned(), 3478)
    );
    assert_eq!(
        parse_external_service("BÜCHER.example.:3478").unwrap(),
        ("bücher.example".to_owned(), 3478)
    );
    assert_eq!(
        parse_external_service("[2001:db8::1]:5349").unwrap(),
        ("2001:db8::1".to_owned(), 5349)
    );
    assert!(parse_external_service("2001:db8::1:5349").is_err());
    assert!(parse_external_service("host:0").is_err());
    assert!(parse_external_service("bad_domain.example:3478").is_err());
}

#[test]
fn pow_v1_cutover_requires_canonical_utc_and_defaults_closed() {
    assert!(parse_pow_v1_compatibility_until(None).unwrap().is_none());
    assert_eq!(
        parse_pow_v1_compatibility_until(Some("2026-10-01T00:00:00Z"))
            .unwrap()
            .unwrap()
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        "2026-10-01T00:00:00Z"
    );
    assert!(parse_pow_v1_compatibility_until(Some("2026-10-01T09:00:00+09:00")).is_err());
    assert!(parse_pow_v1_compatibility_until(Some("not-a-time")).is_err());
}

#[test]
fn metrics_bearer_secret_has_one_http_representable_shape() {
    assert!(valid_http_bearer_secret(&"a".repeat(32)));
    assert!(valid_http_bearer_secret(
        "0123456789abcdefghijklmnopqrstuvwxyz-._~+/="
    ));
    for invalid in [
        "short",
        "0123456789abcdef0123456789abcde ",
        "0123456789abcdef0123456789abcde\t",
        "0123456789abcdef0123456789abcde\u{00e9}",
    ] {
        assert!(!valid_http_bearer_secret(invalid), "accepted {invalid:?}");
    }
    assert!(!valid_http_bearer_secret(&"a".repeat(4097)));
}

#[test]
fn host_meta_v2_advertises_only_bounded_public_literal_addresses() {
    assert_eq!(
        parse_xep_0487_ips("8.8.8.8,2606:4700:4700::1111")
            .unwrap()
            .len(),
        2
    );
    for invalid in [
        "127.0.0.1",
        "10.0.0.1",
        "192.0.2.1",
        "::1",
        "fc00::1",
        "fe80::1",
        "not-an-ip",
    ] {
        assert!(parse_xep_0487_ips(invalid).is_err(), "accepted {invalid}");
    }
    let too_many = std::iter::repeat_n("8.8.8.8", 33)
        .collect::<Vec<_>>()
        .join(",");
    assert!(parse_xep_0487_ips(&too_many).is_err());
}

#[test]
fn federation_domain_patterns_are_idna_canonical_and_strict() {
    let patterns = domain_list("BÜCHER.example,*.FÖÖ.example").unwrap();
    assert_eq!(patterns, vec!["bücher.example", "*.föö.example"]);
    assert!(domain_pattern_matches("*.föö.example", "chat.föö.example"));
    assert!(!domain_pattern_matches("*.föö.example", "föö.example"));
    assert!(domain_list("*.example..test").is_err());
    assert!(domain_list("*.").is_err());
}

#[test]
fn plaintext_legacy_component_listener_is_loopback_only() {
    let legacy = ComponentCredential {
        primary_domain: "gateway.example".to_owned(),
        allowed_domains: vec!["gateway.example".to_owned()],
        secret_value: Some(std::sync::Arc::new(zeroize::Zeroizing::new(
            "this-is-a-32-byte-component-test-secret".to_owned(),
        ))),
        secret_file: None,
        secret_sha256: [0; 32],
        legacy_0114: true,
        modern_0225: true,
        connection: super::ComponentConnectionMode::Accept,
        connect_endpoint: None,
        allow_public_connect: false,
    };
    assert!(validate_component_transport(
        "127.0.0.1:5347".parse().unwrap(),
        std::slice::from_ref(&legacy)
    )
    .is_ok());
    assert!(validate_component_transport(
        "0.0.0.0:5347".parse().unwrap(),
        std::slice::from_ref(&legacy)
    )
    .is_err());
    let modern = ComponentCredential {
        legacy_0114: false,
        ..legacy
    };
    assert!(validate_component_transport("0.0.0.0:5347".parse().unwrap(), &[modern]).is_ok());
}

#[test]
fn connect_supervisors_and_accept_listener_fit_the_global_capacity() {
    let secret_value = Some(std::sync::Arc::new(zeroize::Zeroizing::new(
        "this-is-a-32-byte-component-test-secret".to_owned(),
    )));
    let outbound = ComponentCredential {
        primary_domain: "gateway.example".to_owned(),
        allowed_domains: vec!["gateway.example".to_owned(), "alias.example".to_owned()],
        secret_value: secret_value.clone(),
        secret_file: None,
        secret_sha256: [0; 32],
        legacy_0114: true,
        modern_0225: false,
        connection: ComponentConnectionMode::Connect,
        connect_endpoint: None,
        allow_public_connect: false,
    };
    let accept = ComponentCredential {
        primary_domain: "accept.example".to_owned(),
        allowed_domains: vec!["accept.example".to_owned()],
        secret_value,
        secret_file: None,
        secret_sha256: [0; 32],
        legacy_0114: true,
        modern_0225: false,
        connection: ComponentConnectionMode::Accept,
        connect_endpoint: None,
        allow_public_connect: false,
    };
    assert!(validate_component_capacity(0, &[]).is_ok());
    assert!(validate_component_capacity(0, std::slice::from_ref(&outbound)).is_err());
    assert!(validate_component_capacity(0, std::slice::from_ref(&accept)).is_err());
    assert!(validate_component_capacity(2, std::slice::from_ref(&outbound)).is_ok());
    assert!(validate_component_capacity(2, &[outbound.clone(), accept.clone()]).is_err());
    assert!(validate_component_capacity(3, &[outbound, accept]).is_ok());
}

#[test]
fn connect_component_profile_is_explicit_and_domain_claims_are_unique() {
    let directory = std::env::temp_dir().join(format!(
        "northstar-component-config-{}",
        uuid::Uuid::new_v4().simple()
    ));
    std::fs::create_dir(&directory).unwrap();
    let secret = directory.join("component.secret");
    std::fs::write(&secret, "this-is-a-long-random-looking-component-secret\n").unwrap();
    restrict(&secret);
    let config = directory.join("components.json");
    let entry = serde_json::json!({
        "jid": "outbound.example",
        "aliases": ["alias.outbound.example"],
        "secret_file": secret,
        "connection": "connect",
        "connect_endpoint": "127.0.0.1:5347",
        "legacy_0114": true,
        "modern_0225": false
    });
    std::fs::write(
        &config,
        serde_json::json!({"components": [entry.clone()]}).to_string(),
    )
    .unwrap();
    restrict(&config);
    let loaded = load_component_credentials(&config, "example").unwrap();
    assert_eq!(loaded.len(), 1);
    assert_eq!(loaded[0].connection, ComponentConnectionMode::Connect);
    assert_eq!(
        loaded[0].secret_value.as_ref().map(|value| value.as_str()),
        Some("this-is-a-long-random-looking-component-secret")
    );
    assert_eq!(loaded[0].secret_file.as_deref(), Some(secret.as_path()));
    assert_eq!(
        loaded[0].connect_endpoint.as_ref().unwrap().host,
        "127.0.0.1"
    );

    let mut inline = entry.clone();
    inline.as_object_mut().unwrap().remove("secret_file");
    inline.as_object_mut().unwrap().insert(
        "secret".to_owned(),
        serde_json::json!("this-is-an-inline-component-secret-value"),
    );
    std::fs::write(
        &config,
        serde_json::json!({"components": [inline.clone()]}).to_string(),
    )
    .unwrap();
    let inline_loaded = load_component_credentials(&config, "example").unwrap();
    assert!(inline_loaded[0].secret_file.is_none());
    assert_eq!(
        inline_loaded[0]
            .secret_value
            .as_ref()
            .map(|value| value.as_str()),
        Some("this-is-an-inline-component-secret-value")
    );

    let mut both_sources = inline.clone();
    both_sources
        .as_object_mut()
        .unwrap()
        .insert("secret_file".to_owned(), serde_json::json!(secret));
    std::fs::write(
        &config,
        serde_json::json!({"components": [both_sources]}).to_string(),
    )
    .unwrap();
    let both_error = match load_component_credentials(&config, "example") {
        Ok(_) => panic!("component accepted both inline and file secret sources"),
        Err(error) => error.to_string(),
    };
    assert!(both_error.contains("exactly one"));

    let mut missing_endpoint = entry.clone();
    missing_endpoint
        .as_object_mut()
        .unwrap()
        .remove("connect_endpoint");
    std::fs::write(
        &config,
        serde_json::json!({"components": [missing_endpoint]}).to_string(),
    )
    .unwrap();
    assert!(load_component_credentials(&config, "example").is_err());

    std::fs::write(
        &config,
        serde_json::json!({"components": [entry.clone(), entry]}).to_string(),
    )
    .unwrap();
    let duplicate = match load_component_credentials(&config, "example") {
        Ok(_) => panic!("duplicate component domain was accepted"),
        Err(error) => error.to_string(),
    };
    assert!(duplicate.contains("globally unique"));
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn secret_files_drop_only_the_line_ending() {
    let path = std::env::temp_dir().join(format!(
        "northstar-config-secret-{}.txt",
        uuid::Uuid::new_v4()
    ));
    std::fs::write(&path, "  keep surrounding spaces  \r\n").unwrap();
    restrict(&path);
    let value = read_secret_file(&path, "TEST_SECRET_FILE").unwrap();
    std::fs::remove_file(path).unwrap();
    assert_eq!(value, "  keep surrounding spaces  ");
}

#[test]
fn redis_transport_requires_tls_off_loopback_and_forbids_insecure_modes() {
    assert!(validate_redis_transport(None, None, None, None).is_ok());
    assert!(validate_redis_transport(Some("redis://127.0.0.1:6379/"), None, None, None).is_ok());
    assert!(validate_redis_transport(Some("redis://localhost:6379/"), None, None, None).is_ok());
    assert!(
        validate_redis_transport(Some("redis://cache.localhost:6379/"), None, None, None).is_ok()
    );
    assert!(
        validate_redis_transport(Some("rediss://cache.internal:6379/"), None, None, None).is_ok()
    );
    assert!(validate_redis_transport(Some("redis://10.0.0.8:6379/"), None, None, None).is_err());
    assert!(
        validate_redis_transport(Some("redis://cache.internal:6379/"), None, None, None).is_err()
    );
    assert!(validate_redis_transport(
        Some("rediss://cache.internal:6379/#insecure"),
        None,
        None,
        None
    )
    .is_err());
    assert!(
        validate_redis_transport(Some("http://cache.internal:6379/"), None, None, None).is_err()
    );
}

#[test]
fn development_database_role_override_accepts_only_local_redis_endpoints() {
    assert!(redis_endpoint_is_local(None).unwrap());
    assert!(redis_endpoint_is_local(Some("redis://127.0.0.1:6379/")).unwrap());
    assert!(redis_endpoint_is_local(Some("rediss://localhost:6379/")).unwrap());
    assert!(redis_endpoint_is_local(Some("rediss://cache.localhost:6379/")).unwrap());
    assert!(redis_endpoint_is_local(Some("redis+unix:///tmp/northstar-redis.sock")).unwrap());
    assert!(!redis_endpoint_is_local(Some("rediss://cache.internal:6379/")).unwrap());
    assert!(!redis_endpoint_is_local(Some("rediss://10.0.0.8:6379/")).unwrap());
    assert!(redis_endpoint_is_local(Some("https://cache.internal:6379/")).is_err());
}

#[test]
fn redis_tls_files_require_secure_url_and_complete_client_identity() {
    let ca = std::path::Path::new("redis-ca.pem");
    let cert = std::path::Path::new("redis-client.pem");
    let key = std::path::Path::new("redis-client.key");
    assert!(validate_redis_transport(None, Some(ca), None, None).is_err());
    assert!(
        validate_redis_transport(Some("redis://127.0.0.1:6379/"), Some(ca), None, None).is_err()
    );
    assert!(
        validate_redis_transport(Some("rediss://localhost:6379/"), Some(ca), Some(cert), None)
            .is_err()
    );
    assert!(
        validate_redis_transport(Some("rediss://localhost:6379/"), Some(ca), None, Some(key))
            .is_err()
    );
    assert!(
        validate_redis_transport(Some("rediss://localhost:6379/"), Some(ca), None, None).is_ok()
    );
    assert!(validate_redis_transport(
        Some("rediss://localhost:6379/"),
        Some(ca),
        Some(cert),
        Some(key)
    )
    .is_ok());
}

#[test]
fn empty_secret_files_are_rejected() {
    let path = std::env::temp_dir().join(format!(
        "northstar-empty-secret-{}.txt",
        uuid::Uuid::new_v4()
    ));
    std::fs::write(&path, "\r\n").unwrap();
    restrict(&path);
    let error = read_secret_file(&path, "TEST_SECRET_FILE").unwrap_err();
    std::fs::remove_file(path).unwrap();
    assert!(error.to_string().contains("empty or invalid"));
}

#[cfg(unix)]
#[test]
fn permissive_secret_files_are_rejected_without_reading_their_value() {
    use std::os::unix::fs::PermissionsExt;
    let path = std::env::temp_dir().join(format!(
        "northstar-permissive-secret-{}.txt",
        uuid::Uuid::new_v4()
    ));
    std::fs::write(&path, "do-not-log-this-value\n").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    let error = read_secret_file(&path, "TEST_SECRET_FILE").unwrap_err();
    std::fs::remove_file(path).unwrap();
    let error = error.to_string();
    assert!(error.contains("permissions 0400 or 0600"));
    assert!(!error.contains("do-not-log-this-value"));
}

#[cfg(unix)]
#[test]
fn symbolic_link_secret_files_are_rejected() {
    use std::os::unix::fs::symlink;
    let nonce = uuid::Uuid::new_v4();
    let target = std::env::temp_dir().join(format!("northstar-secret-target-{nonce}"));
    let link = std::env::temp_dir().join(format!("northstar-secret-link-{nonce}"));
    std::fs::write(&target, "never-include-this-secret-in-an-error\n").unwrap();
    restrict(&target);
    symlink(&target, &link).unwrap();
    let error = read_secret_file(&link, "TEST_SECRET_FILE")
        .unwrap_err()
        .to_string();
    std::fs::remove_file(link).unwrap();
    std::fs::remove_file(target).unwrap();
    assert!(error.contains("non-symlink regular file"));
    assert!(!error.contains("never-include-this-secret"));
}

#[test]
fn test_listener_addresses_overlap_port_zero() {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    let a = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
    let b = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
    assert!(!listener_addresses_overlap(a, b));

    let c = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5222);
    assert!(!listener_addresses_overlap(a, c));

    let d = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5222);
    assert!(listener_addresses_overlap(c, d));
}
