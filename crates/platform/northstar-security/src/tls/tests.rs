use super::*;

#[test]
fn certificate_log_metadata_is_control_escaped_and_bounded() {
    assert_eq!(bounded_log_metadata("issuer\nname", 64), "issuer\\nname");
    assert_eq!(bounded_log_metadata("abcdef", 3), "abc");
}

fn test_certificate_session_entry(
    connection_id: uuid::Uuid,
    registration_id: uuid::Uuid,
    kind: CertificateSessionKind,
    disconnect: tokio_util::sync::CancellationToken,
) -> CertificateSessionEntry {
    CertificateSessionEntry {
        registration_id,
        connection_id,
        kind,
        peer_chain: Vec::new(),
        certificate_issuer: "CN=test issuer".into(),
        certificate_serial: "01".into(),
        certificate_sha256: "00".repeat(32),
        handshake_tls_generation: 7,
        authenticated_at: UnixTime::since_unix_epoch(std::time::Duration::from_secs(1)),
        disconnect,
    }
}

#[test]
fn certificate_session_registry_cancels_only_the_exact_match() {
    let registry = Arc::new(CertificateSessionRegistry::default());
    let first_connection = uuid::Uuid::new_v4();
    let second_connection = uuid::Uuid::new_v4();
    let first_registration = uuid::Uuid::new_v4();
    let second_registration = uuid::Uuid::new_v4();
    let first_disconnect = tokio_util::sync::CancellationToken::new();
    let second_disconnect = tokio_util::sync::CancellationToken::new();
    {
        let mut sessions = registry.sessions.lock().unwrap();
        sessions.insert(
            first_connection,
            test_certificate_session_entry(
                first_connection,
                first_registration,
                CertificateSessionKind::C2s,
                first_disconnect.clone(),
            ),
        );
        sessions.insert(
            second_connection,
            test_certificate_session_entry(
                second_connection,
                second_registration,
                CertificateSessionKind::InboundS2s,
                second_disconnect.clone(),
            ),
        );
    }
    let (evaluated, drained) = registry.cancel_matching(|entry| {
        entry.connection_id == first_connection && entry.registration_id == first_registration
    });
    assert_eq!(evaluated, 2);
    assert_eq!(drained.len(), 1);
    assert_eq!(drained[0].connection_id, first_connection);
    assert!(first_disconnect.is_cancelled());
    assert!(!second_disconnect.is_cancelled());
    assert_eq!(
        registry.metrics(),
        CertificateSessionMetrics {
            active: 2,
            c2s_external: 1,
            inbound_s2s_external: 1,
            outbound_s2s_external: 0,
        }
    );
    let (_, repeated) = registry.cancel_matching(|entry| entry.connection_id == first_connection);
    assert!(repeated.is_empty());
}

#[test]
fn stale_certificate_session_guard_cannot_remove_reused_connection_id() {
    let registry = Arc::new(CertificateSessionRegistry::default());
    let connection_id = uuid::Uuid::new_v4();
    let old_registration = uuid::Uuid::new_v4();
    let replacement_registration = uuid::Uuid::new_v4();
    registry.sessions.lock().unwrap().insert(
        connection_id,
        test_certificate_session_entry(
            connection_id,
            replacement_registration,
            CertificateSessionKind::OutboundS2s,
            tokio_util::sync::CancellationToken::new(),
        ),
    );
    let stale_guard = CertificateSessionGuard {
        registry: Arc::clone(&registry),
        connection_id,
        registration_id: old_registration,
    };
    drop(stale_guard);
    assert_eq!(registry.metrics().active, 1);
    registry.unregister(connection_id, replacement_registration);
    assert_eq!(registry.metrics().active, 0);
}

#[test]
fn stale_revocation_snapshot_cannot_cancel_reused_connection_id() {
    let registry = Arc::new(CertificateSessionRegistry::default());
    let connection_id = uuid::Uuid::new_v4();
    let stale = test_certificate_session_entry(
        connection_id,
        uuid::Uuid::new_v4(),
        CertificateSessionKind::InboundS2s,
        tokio_util::sync::CancellationToken::new(),
    );
    let replacement_disconnect = tokio_util::sync::CancellationToken::new();
    registry.sessions.lock().unwrap().insert(
        connection_id,
        test_certificate_session_entry(
            connection_id,
            uuid::Uuid::new_v4(),
            CertificateSessionKind::InboundS2s,
            replacement_disconnect.clone(),
        ),
    );

    assert!(!registry.signal_snapshot_if_current(&stale));
    assert!(!replacement_disconnect.is_cancelled());
}

#[test]
fn direct_tls_sni_is_required_and_matches_the_prepared_xmpp_domain() {
    assert!(direct_tls_sni_matches(
        Some("B\u{fc}CHER.example."),
        "xn--bcher-kva.example"
    ));
    assert!(!direct_tls_sni_matches(None, "example.test"));
    assert!(!direct_tls_sni_matches(
        Some("other.example"),
        "example.test"
    ));
    assert!(!direct_tls_sni_matches(Some("bad domain"), "example.test"));
}

#[test]
fn c2s_xmppaddr_decoder_requires_explicit_utf8_der() {
    let value = b"alice@example.test";
    let mut encoded = vec![0xa0, (value.len() + 2) as u8, 0x0c, value.len() as u8];
    encoded.extend_from_slice(value);
    assert_eq!(
        decode_explicit_utf8_string(&encoded),
        Some("alice@example.test")
    );
    encoded[2] = 0x16;
    assert!(decode_explicit_utf8_string(&encoded).is_none());
    assert!(decode_explicit_utf8_string(&encoded[1..]).is_none());
}

fn install_crypto_provider() {
    // The binary installs this before constructing AppState. Unit tests
    // enter TLS construction directly and can race each other, so an
    // already-installed identical process provider is also success.
    let _ = tokio_rustls::rustls::crypto::aws_lc_rs::default_provider().install_default();
}

#[test]
fn development_certificate_exemption_is_reserved_name_only() {
    for domain in [
        "localhost",
        "conference.localhost",
        "alpha.test",
        "invalid",
        "service.example",
        "example.com",
    ] {
        assert!(development_certificate_domain(domain));
    }
    for domain in [
        "localhost.example.com",
        "test.example.net",
        "example.com.evil",
    ] {
        assert!(!development_certificate_domain(domain));
    }
}

#[test]
fn unsupported_and_obsolete_signature_algorithms_are_not_silently_mapped() {
    assert_eq!(
        signature_digest_oid("1.2.840.113549.1.1.11"),
        Some("2.16.840.1.101.3.4.2.1")
    );
    assert_eq!(
        signature_digest_oid("1.2.840.113549.1.1.5"),
        Some("1.3.14.3.2.26")
    );
    assert_eq!(signature_digest_oid("1.3.101.112"), None);
    assert!(hashless_certificate_signature("1.3.101.112"));
    assert!(hashless_certificate_signature("1.3.101.113"));
    assert!(!hashless_certificate_signature("1.2.840.113549.1.1.11"));
}

#[test]
fn pem_label_parser_never_treats_private_material_as_a_certificate() {
    let mixed = "-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----\n\
                 -----BEGIN PRIVATE KEY-----\nAA==\n-----END PRIVATE KEY-----\n";
    assert_eq!(
        pem_begin_labels(mixed).collect::<Vec<_>>(),
        vec!["CERTIFICATE", "PRIVATE KEY"]
    );
}

#[test]
#[ignore = "requires TEST_TLS_CERT_PATH and TEST_TLS_KEY_PATH generated outside the repository"]
fn generated_identity_builds_every_profile_and_failed_reload_is_atomic() {
    install_crypto_provider();
    let source_certificate =
        PathBuf::from(std::env::var("TEST_TLS_CERT_PATH").expect("TEST_TLS_CERT_PATH"));
    let source_key = PathBuf::from(std::env::var("TEST_TLS_KEY_PATH").expect("TEST_TLS_KEY_PATH"));
    let directory = std::env::temp_dir().join(format!("northstar-tls-{}", uuid::Uuid::new_v4()));
    fs::create_dir(&directory).unwrap();
    let certificate = directory.join("server.crt");
    let key = directory.join("server.key");
    fs::copy(source_certificate, &certificate).unwrap();
    fs::copy(source_key, &key).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
    }

    let reloadable =
        ReloadableTlsConfig::new(&certificate, &key, "localhost", TlsPolicyFiles::default())
            .unwrap();
    let initial = reloadable.current();
    let context = TlsContext::new(Arc::clone(&reloadable));
    let c2s_snapshot = context.c2s_snapshot(false);
    let federation_snapshot = context.federation_snapshot();
    assert_eq!(c2s_snapshot.generation, initial.generation);
    assert_eq!(federation_snapshot.generation, initial.generation);
    assert!(Arc::ptr_eq(
        &c2s_snapshot.server_config,
        &initial.c2s_starttls
    ));
    assert!(Arc::ptr_eq(
        &federation_snapshot.roots,
        &initial.federation_roots
    ));
    assert_eq!(
        context.metrics_probe().leaf_status(),
        (initial.leaf_not_after_unix, initial.generation)
    );
    for config in [
        &initial.c2s_starttls,
        &initial.c2s_direct,
        &initial.s2s_starttls,
        &initial.s2s_direct,
    ] {
        assert!(config.require_ems);
    }
    assert!(initial.s2s_client_starttls.require_ems);
    assert!(initial.s2s_client_direct.require_ems);
    assert!(initial
        .tls_server_end_point
        .as_ref()
        .is_some_and(|binding| !binding.is_empty()));
    assert!(initial.leaf_not_after_unix > 0);
    assert!(initial.c2s_starttls.alpn_protocols.is_empty());
    assert_eq!(
        initial.c2s_direct.alpn_protocols,
        vec![b"xmpp-client".to_vec()]
    );
    assert!(initial.s2s_starttls.alpn_protocols.is_empty());
    assert_eq!(
        initial.s2s_direct.alpn_protocols,
        vec![b"xmpp-server".to_vec()]
    );
    assert!(initial.s2s_client_starttls.alpn_protocols.is_empty());
    assert_eq!(
        initial.s2s_client_direct.alpn_protocols,
        vec![b"xmpp-server".to_vec()]
    );

    let original_key = fs::read(&key).unwrap();
    fs::write(&key, b"not a private key\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
    }
    let error = reloadable.reload().unwrap_err().to_string();
    assert!(!error.contains("PRIVATE KEY"));
    assert!(Arc::ptr_eq(&initial, &reloadable.current()));

    fs::write(&key, original_key).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
    }
    let reloaded = context.reload().unwrap();
    assert!(!Arc::ptr_eq(&initial, &reloadable.current()));
    assert_eq!(context.c2s_snapshot(true).generation, reloaded.generation);
    assert_eq!(
        context.federation_snapshot().generation,
        reloaded.generation
    );

    fs::remove_dir_all(directory).unwrap();
}

#[tokio::test]
#[ignore = "requires generated TLS fixture and loopback sockets"]
async fn generated_tls12_requires_ems_and_tls13_still_connects() {
    use openssl::ssl::{SslConnector, SslMethod, SslOptions, SslVerifyMode, SslVersion};
    install_crypto_provider();
    let reloadable = ReloadableTlsConfig::new(
        &PathBuf::from(std::env::var("TEST_TLS_CERT_PATH").unwrap()),
        &PathBuf::from(std::env::var("TEST_TLS_KEY_PATH").unwrap()),
        "localhost",
        TlsPolicyFiles::default(),
    )
    .unwrap();
    for (version, without_ems, accepted) in [
        (SslVersion::TLS1_2, false, true),
        (SslVersion::TLS1_2, true, false),
        (SslVersion::TLS1_3, false, true),
    ] {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = listener.local_addr().unwrap();
        let acceptor =
            tokio_rustls::TlsAcceptor::from(Arc::clone(&reloadable.current().c2s_starttls));
        let client = tokio::task::spawn_blocking(move || {
            let mut connector = SslConnector::builder(SslMethod::tls()).unwrap();
            connector.set_min_proto_version(Some(version)).unwrap();
            connector.set_max_proto_version(Some(version)).unwrap();
            connector.set_verify(SslVerifyMode::NONE);
            if without_ems {
                // OpenSSL's SSL_OP_NO_EXTENDED_MASTER_SECRET is bit 0.
                // The Rust bindings omit its name; use the pinned vendored
                // library so this does not depend on the host CLI version.
                connector.set_options(SslOptions::from_bits_retain(1));
            }
            let budget = std::time::Duration::from_secs(5);
            let socket = std::net::TcpStream::connect_timeout(&endpoint, budget).unwrap();
            socket.set_read_timeout(Some(budget)).unwrap();
            socket.set_write_timeout(Some(budget)).unwrap();
            connector.build().connect("localhost", socket).is_ok()
        });
        let result = tokio::time::timeout(std::time::Duration::from_secs(10), async {
            tokio::join!(client, async {
                let (socket, _) = listener.accept().await.unwrap();
                acceptor.accept(socket).await
            })
        })
        .await
        .expect("TLS handshake timed out");
        assert_eq!(
            result.1.is_ok(),
            accepted,
            "{version:?}, no EMS={without_ems}: {:?}",
            result.1.err()
        );
        assert_eq!(result.0.unwrap(), accepted);
    }
}

#[tokio::test]
#[ignore = "requires OCSP responses generated by scripts/test-ocsp-stapling.sh and loopback sockets"]
async fn ocsp_staple_survives_tls12_tls13_and_rejects_bad_reload() {
    use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode, SslVersion, StatusType};
    install_crypto_provider();
    let fixture = PathBuf::from(std::env::var("TEST_OCSP_FIXTURE_DIR").unwrap());
    let response_path = fixture.join("active.der");
    let expected = fs::read(fixture.join("good.der")).unwrap();
    fs::write(&response_path, &expected).unwrap();
    let reloadable = ReloadableTlsConfig::new(
        &fixture.join("chain.crt"),
        &fixture.join("leaf.key"),
        "localhost",
        TlsPolicyFiles {
            ocsp_response: Some(&response_path),
            ..TlsPolicyFiles::default()
        },
    )
    .unwrap();
    let initial = reloadable.current();
    fs::write(
        &response_path,
        fs::read(fixture.join("revoked.der")).unwrap(),
    )
    .unwrap();
    assert!(reloadable.reload().is_err());
    assert!(Arc::ptr_eq(&initial, &reloadable.current()));

    for version in [SslVersion::TLS1_2, SslVersion::TLS1_3] {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = listener.local_addr().unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::clone(&initial.c2s_starttls));
        let client = tokio::task::spawn_blocking(move || {
            let mut connector = SslConnector::builder(SslMethod::tls()).unwrap();
            connector.set_min_proto_version(Some(version)).unwrap();
            connector.set_max_proto_version(Some(version)).unwrap();
            connector.set_verify(SslVerifyMode::NONE);
            let mut configured = connector.build().configure().unwrap();
            configured.set_status_type(StatusType::OCSP).unwrap();
            let budget = std::time::Duration::from_secs(5);
            let socket = std::net::TcpStream::connect_timeout(&endpoint, budget).unwrap();
            socket.set_read_timeout(Some(budget)).unwrap();
            socket.set_write_timeout(Some(budget)).unwrap();
            configured
                .connect("localhost", socket)
                .unwrap()
                .ssl()
                .ocsp_status()
                .map(ToOwned::to_owned)
        });
        let (received, server) = tokio::time::timeout(std::time::Duration::from_secs(10), async {
            tokio::join!(client, async {
                let (socket, _) = listener.accept().await.unwrap();
                acceptor.accept(socket).await
            })
        })
        .await
        .expect("stapled TLS handshake timed out");
        server.unwrap();
        assert_eq!(received.unwrap().as_deref(), Some(expected.as_slice()));
    }

    fs::write(&response_path, &expected).unwrap();
    reloadable.reload().unwrap();
    assert!(!Arc::ptr_eq(&initial, &reloadable.current()));
}

#[test]
#[ignore = "requires generated C2S client-certificate fixtures outside the repository"]
fn generated_c2s_external_accepts_only_local_xmppaddr_sans_and_never_cn() {
    install_crypto_provider();
    let client_ca =
        PathBuf::from(std::env::var("TEST_C2S_CLIENT_CA_PATH").expect("C2S client CA path"));
    let valid = certificate_chain(Path::new(
        &std::env::var("TEST_C2S_CLIENT_CERT_PATH").expect("C2S client certificate"),
    ))
    .unwrap();
    let wrong_domain = certificate_chain(Path::new(
        &std::env::var("TEST_C2S_WRONG_DOMAIN_CERT_PATH")
            .expect("wrong-domain C2S client certificate"),
    ))
    .unwrap();
    let cn_only = certificate_chain(Path::new(
        &std::env::var("TEST_C2S_CN_ONLY_CERT_PATH").expect("CN-only C2S client certificate"),
    ))
    .unwrap();

    assert_eq!(
        c2s_client_xmpp_identities(&valid, "localhost").unwrap(),
        vec!["alice@localhost"]
    );
    assert!(c2s_client_xmpp_identities(&wrong_domain, "localhost")
        .unwrap()
        .is_empty());
    assert!(c2s_client_xmpp_identities(&cn_only, "localhost")
        .unwrap()
        .is_empty());

    let server_certificate =
        PathBuf::from(std::env::var("TEST_TLS_CERT_PATH").expect("development server certificate"));
    let server_key =
        PathBuf::from(std::env::var("TEST_TLS_KEY_PATH").expect("development server key"));
    let material = ReloadableTlsConfig::new(
        &server_certificate,
        &server_key,
        "localhost",
        TlsPolicyFiles {
            c2s_client_trust_root: Some(&client_ca),
            ..TlsPolicyFiles::default()
        },
    )
    .unwrap()
    .current();
    assert!(material.c2s_starttls.alpn_protocols.is_empty());
    assert_eq!(
        material.c2s_direct.alpn_protocols,
        vec![b"xmpp-client".to_vec()]
    );
}

#[cfg(unix)]
#[test]
#[ignore = "requires a generated private-CA fixture outside the repository"]
fn generated_public_identity_enforces_trust_domain_permissions_and_atomic_reload() {
    use std::os::unix::fs::PermissionsExt;

    install_crypto_provider();

    let source_certificate =
        PathBuf::from(std::env::var("TEST_PUBLIC_TLS_CERT_PATH").expect("public certificate"));
    let source_key = PathBuf::from(std::env::var("TEST_PUBLIC_TLS_KEY_PATH").expect("public key"));
    let trust_root = PathBuf::from(std::env::var("TEST_PUBLIC_TLS_CA_PATH").expect("private CA"));
    let domain = std::env::var("TEST_PUBLIC_TLS_DOMAIN").expect("public test domain");
    assert!(!development_certificate_domain(&domain));

    let directory =
        std::env::temp_dir().join(format!("northstar-public-tls-{}", uuid::Uuid::new_v4()));
    fs::create_dir(&directory).unwrap();
    let certificate = directory.join("server.crt");
    let key = directory.join("server.key");
    fs::copy(source_certificate, &certificate).unwrap();
    fs::copy(source_key, &key).unwrap();

    fs::set_permissions(&certificate, fs::Permissions::from_mode(0o666)).unwrap();
    assert!(ReloadableTlsConfig::new(
        &certificate,
        &key,
        &domain,
        TlsPolicyFiles {
            extra_root: Some(&trust_root),
            ..TlsPolicyFiles::default()
        }
    )
    .is_err());
    fs::set_permissions(&certificate, fs::Permissions::from_mode(0o644)).unwrap();
    fs::set_permissions(&key, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(ReloadableTlsConfig::new(
        &certificate,
        &key,
        &domain,
        TlsPolicyFiles {
            extra_root: Some(&trust_root),
            ..TlsPolicyFiles::default()
        }
    )
    .is_err());
    fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(
        ReloadableTlsConfig::new(&certificate, &key, &domain, TlsPolicyFiles::default()).is_err()
    );
    assert!(ReloadableTlsConfig::new(
        &certificate,
        &key,
        "wrong.runtime.northstar.internal",
        TlsPolicyFiles {
            extra_root: Some(&trust_root),
            ..TlsPolicyFiles::default()
        }
    )
    .is_err());

    let reloadable = ReloadableTlsConfig::new(
        &certificate,
        &key,
        &domain,
        TlsPolicyFiles {
            extra_root: Some(&trust_root),
            ..TlsPolicyFiles::default()
        },
    )
    .unwrap();
    let initial = reloadable.current();
    let original_key = fs::read(&key).unwrap();
    fs::write(&key, b"invalid key fixture\n").unwrap();
    fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
    let error = reloadable.reload().unwrap_err().to_string();
    assert!(!error.contains("invalid key fixture"));
    assert!(Arc::ptr_eq(&initial, &reloadable.current()));

    fs::write(&key, original_key).unwrap();
    fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
    reloadable.reload().unwrap();
    assert!(!Arc::ptr_eq(&initial, &reloadable.current()));
    fs::remove_dir_all(directory).unwrap();
}

#[test]
#[ignore = "requires generated CRL reload fixtures outside the repository"]
fn generated_crl_reload_is_atomic_and_rolls_back_on_invalid_input() {
    install_crypto_provider();
    let certificate =
        PathBuf::from(std::env::var("TEST_TLS_RELOAD_CERT_PATH").expect("reload certificate path"));
    let key =
        PathBuf::from(std::env::var("TEST_TLS_RELOAD_KEY_PATH").expect("reload private-key path"));
    let root = PathBuf::from(std::env::var("TEST_TLS_RELOAD_ROOT_PATH").expect("reload root path"));
    let initial_crl =
        fs::read(std::env::var("TEST_TLS_RELOAD_CRL_PATH").expect("initial CRL path")).unwrap();
    let renewed_crl =
        fs::read(std::env::var("TEST_TLS_RELOAD_RENEWED_CRL_PATH").expect("renewed CRL path"))
            .unwrap();
    let reload_crl = certificate.with_file_name("reload-under-test.crl.pem");
    fs::write(&reload_crl, &initial_crl).unwrap();

    let reloadable = ReloadableTlsConfig::new(
        &certificate,
        &key,
        "server.example.test",
        TlsPolicyFiles {
            extra_root: Some(&root),
            federation_crl: Some(&reload_crl),
            ..TlsPolicyFiles::default()
        },
    )
    .unwrap();
    let initial = reloadable.current();
    assert!(initial.federation_crls.is_some());

    fs::write(&reload_crl, b"not a CRL\n").unwrap();
    assert!(reloadable.reload().is_err());
    assert!(Arc::ptr_eq(&initial, &reloadable.current()));

    fs::write(&reload_crl, renewed_crl).unwrap();
    reloadable.reload().unwrap();
    assert!(!Arc::ptr_eq(&initial, &reloadable.current()));
    assert!(reloadable.current().federation_crls.is_some());
    fs::remove_file(reload_crl).unwrap();
}
