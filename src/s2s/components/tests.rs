use super::*;
use std::{
    pin::Pin,
    sync::atomic::{AtomicBool, AtomicUsize},
    task::{Context as TaskContext, Poll},
};

struct RenewalGatedWriter {
    writable: Arc<AtomicBool>,
    bytes: Vec<u8>,
}

impl AsyncWrite for RenewalGatedWriter {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _context: &mut TaskContext<'_>,
        buffer: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if !self.writable.load(Ordering::Acquire) {
            return Poll::Pending;
        }
        self.bytes.extend_from_slice(buffer);
        Poll::Ready(Ok(buffer.len()))
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        _context: &mut TaskContext<'_>,
    ) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        _context: &mut TaskContext<'_>,
    ) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[tokio::test]
async fn unconfigured_component_task_stays_alive_until_cancelled() {
    let cancel = tokio_util::sync::CancellationToken::new();
    let task_cancel = cancel.clone();
    let mut task = tokio::spawn(async move {
        wait_for_component_shutdown(&task_cancel).await;
    });

    assert!(
        tokio::time::timeout(Duration::from_millis(50), &mut task)
            .await
            .is_err(),
        "an unconfigured component task must not terminate main"
    );
    cancel.cancel();
    tokio::time::timeout(Duration::from_secs(1), task)
        .await
        .expect("component shutdown wait timed out")
        .expect("component shutdown task panicked");
}

#[tokio::test]
async fn connect_supervisor_failures_and_panics_are_never_silent() {
    let mut failed = JoinSet::new();
    failed
        .spawn(async { Err::<(), anyhow::Error>(anyhow::anyhow!("injected supervisor failure")) });
    let error = component_supervisor_completion(failed.join_next().await, false)
        .expect_err("supervisor error must terminate the component service");
    assert!(format!("{error:#}").contains("injected supervisor failure"));

    let joined: std::result::Result<Result<()>, tokio::task::JoinError> =
        tokio::spawn(async { panic!("injected supervisor panic") })
            .await
            .map(|()| Ok(()));
    let error = component_supervisor_completion(Some(joined), false)
        .expect_err("supervisor panic must terminate the component service");
    assert!(format!("{error:#}").contains("panicked or was cancelled"));

    assert!(component_supervisor_completion(Some(Ok(Ok(()))), true).is_ok());
    assert!(component_supervisor_completion(Some(Ok(Ok(()))), false).is_err());
}

#[tokio::test]
async fn component_socket_write_is_fenced_by_lease_renewal() {
    let writable = Arc::new(AtomicBool::new(false));
    let renewals = Arc::new(AtomicUsize::new(0));
    let mut writer = RenewalGatedWriter {
        writable: Arc::clone(&writable),
        bytes: Vec::new(),
    };
    let writable_after_renewal = Arc::clone(&writable);
    let renewal_count = Arc::clone(&renewals);
    let cancel = tokio_util::sync::CancellationToken::new();
    tokio::time::timeout(
        Duration::from_secs(1),
        write_component_outbox_with_renewal(
            &mut writer,
            "<message/>".to_owned(),
            Duration::from_millis(1),
            Duration::from_millis(100),
            cancel.clone(),
            move || {
                writable_after_renewal.store(true, Ordering::Release);
                renewal_count.fetch_add(1, Ordering::Relaxed);
                std::future::ready(Ok(true))
            },
        ),
    )
    .await
    .expect("lease-fenced component write timed out")
    .expect("renewed component write failed");
    assert_eq!(renewals.load(Ordering::Relaxed), 1);
    assert_eq!(writer.bytes, b"<message/>");

    let mut blocked = RenewalGatedWriter {
        writable: Arc::new(AtomicBool::new(false)),
        bytes: Vec::new(),
    };
    let result = tokio::time::timeout(
        Duration::from_secs(1),
        write_component_outbox_with_renewal(
            &mut blocked,
            "<message/>".to_owned(),
            Duration::from_millis(1),
            Duration::from_millis(100),
            cancel,
            || std::future::ready(Ok(false)),
        ),
    )
    .await
    .expect("lease-loss component write timed out");
    assert!(matches!(result, Err(ComponentOutboxWriteError::Lease(_))));
    assert!(blocked.bytes.is_empty());
}

#[test]
fn component_outbox_claims_are_just_in_time_and_bounded() {
    assert_eq!(COMPONENT_OUTBOX_CLAIM_BATCH, 1);
    const { assert!(COMPONENT_OUTBOX_DRAIN_LIMIT <= 32) };
    assert_eq!(component_lease_renewal_period(30), Duration::from_secs(10));
    assert_eq!(component_lease_renewal_period(1), Duration::from_secs(1));
}

fn credential(secret: &str, secret_file: std::path::PathBuf) -> ComponentCredential {
    ComponentCredential {
        primary_domain: "gateway.example".to_owned(),
        allowed_domains: vec!["gateway.example".to_owned()],
        secret_value: Some(Arc::new(Zeroizing::new(secret.to_owned()))),
        secret_file: Some(secret_file),
        secret_sha256: Sha256::digest(secret.as_bytes()).into(),
        legacy_0114: true,
        modern_0225: true,
        connection: ComponentConnectionMode::Accept,
        connect_endpoint: None,
        allow_public_connect: false,
    }
}

#[test]
fn active_component_connection_counter_is_drop_safe() {
    let counter = AtomicU64::new(0);
    {
        let _connection = ActiveComponentConnection::new(&counter);
        assert_eq!(counter.load(Ordering::Relaxed), 1);
    }
    assert_eq!(counter.load(Ordering::Relaxed), 0);
}

#[test]
fn component_target_uses_prepared_jid_domain() {
    assert_eq!(
        target_domain("romeo@Chat.Example/resource").as_deref(),
        Some("chat.example")
    );
    assert_eq!(
        target_domain("romeo@BÜCHER.example/Resource").as_deref(),
        Some("bücher.example")
    );
    assert!(target_domain("bad jid").is_none());
    assert!(target_domain("romeo@example..test/resource").is_none());
    assert!(target_domain("romeo@example.test/bad\u{0007}resource").is_none());
}

#[test]
fn component_wake_is_bounded_and_requires_configuration() {
    let registry = registry();
    let connection_id = Uuid::new_v4();
    let (sender, mut receiver) = mpsc::channel(1);
    registry
        .register_domain("gateway.example", connection_id, sender)
        .expect("register component");
    let configured = HashSet::from(["gateway.example".to_owned()]);
    assert_eq!(
        registry.wake_route(&configured, "alice@gateway.example"),
        ComponentRoute::Delivered
    );
    assert_eq!(
        registry.wake_route(&configured, "alice@gateway.example"),
        ComponentRoute::Unavailable
    );
    assert_eq!(receiver.try_recv(), Ok(()));
    assert_eq!(
        registry.wake_route(&HashSet::new(), "alice@gateway.example"),
        ComponentRoute::NotConfigured
    );
    drop(receiver);
    assert_eq!(
        registry.wake_route(&configured, "alice@gateway.example"),
        ComponentRoute::Unavailable
    );
}

#[test]
fn legacy_hex_decoder_is_strict() {
    assert_eq!(decode_hex_20(&"a5".repeat(20)), Some([0xa5; 20]));
    assert!(decode_hex_20(&"a5".repeat(19)).is_none());
    assert!(decode_hex_20(&format!("{}zz", "a5".repeat(19))).is_none());
    assert!(decode_hex_20(&"A5".repeat(20)).is_none());
}

#[test]
fn component_stream_attributes_accept_only_the_protocol_namespace_and_version() {
    let legacy = format!(
        "<stream:stream xmlns='{COMPONENT_ACCEPT_NS}' xmlns:stream='{STREAMS_NS}' to='gateway.example'>"
    );
    let formatted = format!(
        "<stream:stream\n  xmlns='{COMPONENT_ACCEPT_NS}'\n  xmlns:stream='{STREAMS_NS}'\n  to='gateway.example'>"
    );
    assert_eq!(stream_namespace(&formatted).unwrap(), COMPONENT_ACCEPT_NS);
    assert_eq!(
        component_stream_attribute(&legacy, "to", COMPONENT_ACCEPT_NS, false).as_deref(),
        Some("gateway.example")
    );

    let modern = format!(
        "<stream:stream xmlns='jabber:client' xmlns:stream='{STREAMS_NS}' from='gateway.example' to='example' version='1.0'>"
    );
    assert_eq!(
        component_stream_attribute(&modern, "from", "jabber:client", true).as_deref(),
        Some("gateway.example")
    );
    assert!(component_stream_attribute(&legacy, "to", "jabber:client", true).is_none());
    assert!(component_stream_attribute(
        &modern.replace(" version='1.0'", ""),
        "from",
        "jabber:client",
        true,
    )
    .is_none());
}

#[test]
fn starttls_and_sasl_abort_controls_are_empty_and_namespaced() {
    assert!(is_empty_element(
        "<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>",
        "starttls",
        "urn:ietf:params:xml:ns:xmpp-tls"
    ));
    assert!(!is_empty_element(
        "<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'><extra/></starttls>",
        "starttls",
        "urn:ietf:params:xml:ns:xmpp-tls"
    ));
    assert!(is_empty_element(
        "<abort xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/>",
        "abort",
        SASL_NS
    ));
}

#[test]
fn namespace_conversion_does_not_leave_client_namespace_on_legacy_stream() {
    let stanza = "<message xmlns='jabber:client' from='a.test' to='b.test'/>";
    assert!(
        client_to_component(stanza, ComponentProtocol::Legacy0114Accept)
            .contains("xmlns='jabber:component:accept'")
    );
    assert!(
        client_to_component(stanza, ComponentProtocol::Legacy0114Connect)
            .contains("xmlns='jabber:component:connect'")
    );
}

#[test]
fn connect_endpoint_ssrf_policy_requires_explicit_public_opt_in() {
    for private in [
        "127.0.0.1",
        "10.0.0.1",
        "172.16.0.1",
        "192.168.0.1",
        "::1",
        "fd00::1",
    ] {
        assert!(component_connect_address_allowed(
            private.parse().unwrap(),
            false
        ));
    }
    for forbidden in ["0.0.0.0", "224.0.0.1", "::", "ff02::1", "169.254.169.254"] {
        assert!(!component_connect_address_allowed(
            forbidden.parse().unwrap(),
            false
        ));
    }
    assert!(component_connect_address_allowed(
        "203.0.113.1".parse().unwrap(),
        true
    ));
    for forbidden_even_when_public in ["0.0.0.0", "255.255.255.255", "169.254.169.254", "fe80::1"] {
        assert!(!component_connect_address_allowed(
            forbidden_even_when_public.parse().unwrap(),
            true
        ));
    }
}

#[test]
fn connect_handshake_ack_may_inherit_only_the_connect_namespace() {
    assert!(is_inherited_empty_element(
        "<handshake/>",
        "handshake",
        COMPONENT_CONNECT_NS
    ));
    assert!(is_inherited_empty_element(
        "<handshake xmlns='jabber:component:connect'/>",
        "handshake",
        COMPONENT_CONNECT_NS
    ));
    assert!(!is_inherited_empty_element(
        "<handshake xmlns='jabber:component:accept'/>",
        "handshake",
        COMPONENT_CONNECT_NS
    ));
    assert!(!is_inherited_empty_element(
        "<handshake><extra/></handshake>",
        "handshake",
        COMPONENT_CONNECT_NS
    ));
}

#[test]
fn connect_responder_stream_is_strictly_addressed_to_the_component() {
    let valid = format!(
        "<stream:stream xmlns='{COMPONENT_CONNECT_NS}' xmlns:stream='{STREAMS_NS}' to='gateway.example' id='stream-id'>"
    );
    assert_eq!(
        validate_legacy_connect_opening(&valid, "gateway.example").unwrap(),
        "stream-id"
    );
    let equivalent = valid.replace(
        "to='gateway.example'",
        "to='GATEWAY.EXAMPLE' from='gateway.example'",
    );
    assert_eq!(
        validate_legacy_connect_opening(&equivalent, "gateway.example").unwrap(),
        "stream-id"
    );
    for invalid in [
        valid.replace("to='gateway.example' ", ""),
        valid.replace("to='gateway.example'", "to='forged.example'"),
        valid.replace(
            "to='gateway.example'",
            "to='gateway.example' from='forged.example'",
        ),
        valid.replace(COMPONENT_CONNECT_NS, COMPONENT_ACCEPT_NS),
        valid.replace(" id='stream-id'", ""),
    ] {
        assert!(
            validate_legacy_connect_opening(&invalid, "gateway.example").is_err(),
            "accepted invalid connect responder opening: {invalid}"
        );
    }
}

#[test]
fn legacy_handshake_uses_stream_id_plus_mounted_secret() {
    let secret = "this-is-a-32-byte-or-longer-component-secret";
    let path = std::env::temp_dir().join(format!(
        "northstar-component-secret-{}",
        Uuid::new_v4().simple()
    ));
    std::fs::write(&path, format!("{secret}\n")).expect("write test secret");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let mut permissions = std::fs::metadata(&path)
            .expect("read test secret metadata")
            .permissions();
        permissions.set_mode(0o600);
        std::fs::set_permissions(&path, permissions).expect("restrict test secret permissions");
    }
    let credential = credential(secret, path.clone());
    let stream_id = "0123456789abcdef";
    let mut digest = Sha1::new();
    digest.update(stream_id.as_bytes());
    digest.update(secret.as_bytes());
    let response = digest
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    assert!(verify_legacy_handshake(
        &credential,
        stream_id,
        &format!("<handshake xmlns='{COMPONENT_ACCEPT_NS}'>{response}</handshake>")
    )
    .expect("verify handshake"));
    assert!(!verify_legacy_handshake(
        &credential,
        stream_id,
        &format!(
            "<handshake xmlns='{COMPONENT_ACCEPT_NS}'>{}</handshake>",
            "00".repeat(20)
        )
    )
    .expect("reject handshake"));
    assert!(!verify_legacy_handshake(
        &credential,
        stream_id,
        &format!("<handshake xmlns='urn:example:forged'>{response}</handshake>")
    )
    .expect("reject forged namespace"));
    let _ = std::fs::remove_file(path);
}

#[test]
fn modern_plain_binds_authentication_to_primary_domain() {
    let secret = "this-is-a-32-byte-or-longer-component-secret";
    let credential = credential(secret, std::path::PathBuf::new());
    let valid = STANDARD.encode(format!("\0gateway.example\0{secret}"));
    assert!(verify_modern_plain(
        &credential,
        &format!("<auth xmlns='{SASL_NS}' mechanism='PLAIN'>{valid}</auth>")
    )
    .expect("verify SASL PLAIN"));
    let forged = STANDARD.encode(format!("\0other.example\0{secret}"));
    assert!(!verify_modern_plain(
        &credential,
        &format!("<auth xmlns='{SASL_NS}' mechanism='PLAIN'>{forged}</auth>")
    )
    .expect("reject forged identity"));
    assert!(!verify_modern_plain(
        &credential,
        &format!("<auth xmlns='{SASL_NS}' mechanism='PLAIN' forged='true'>{valid}</auth>")
    )
    .expect("reject extra SASL attribute"));
    assert!(!verify_modern_plain(
        &credential,
        &format!("<auth xmlns='{SASL_NS}' mechanism='PLAIN'>{valid}<extra/></auth>")
    )
    .expect("reject SASL child element"));
}

#[test]
fn component_stanza_shape_is_strict_before_remote_routing() {
    for valid in [
        "<message xmlns='jabber:client' from='a.example' to='b.example'/>",
        "<presence xmlns='jabber:client' from='a.example' to='b.example' type='probe'/>",
        "<iq xmlns='jabber:client' from='a.example' to='b.example' type='get' id='i'><ping xmlns='urn:xmpp:ping'/></iq>",
    ] {
        let document = Document::parse(valid).unwrap();
        assert_eq!(invalid_component_stanza(document.root_element()), None);
    }
    for invalid in [
        "<message xmlns='jabber:client' from='a.example' to='b.example' type='invalid'/>",
        "<presence xmlns='jabber:client' from='a.example' to='b.example' type='available'/>",
        "<iq xmlns='jabber:client' from='a.example' to='b.example' type='get' id='i'/>",
        "<iq xmlns='jabber:client' from='a.example' to='b.example' type='set' id='i'><a/><b/></iq>",
        "<iq xmlns='jabber:client' from='a.example' to='b.example' type='result'/>",
    ] {
        let document = Document::parse(invalid).unwrap();
        assert_eq!(
            invalid_component_stanza(document.root_element()),
            Some("bad-request"),
            "accepted {invalid}"
        );
    }
}

#[test]
fn fatal_component_frames_are_classified_as_stream_errors() {
    assert_eq!(
        component_frame_stream_error("<message xmlns='jabber:client'/>"),
        None
    );
    assert_eq!(
        component_frame_stream_error("<handshake xmlns='jabber:component:accept'/>"),
        Some("unsupported-stanza-type")
    );
    assert_eq!(
        component_frame_stream_error("<message><broken></message>"),
        Some("not-well-formed")
    );
    assert!(is_component_stream_error(
        "<stream:error xmlns:stream='http://etherx.jabber.org/streams'><policy-violation xmlns='urn:ietf:params:xml:ns:xmpp-streams'/></stream:error>"
    ));
}

#[test]
fn component_error_stanzas_never_create_error_loops() {
    let document = Document::parse(
        "<message xmlns='jabber:client' from='a.example' to='b.example' type='error'><error type='cancel'/></message>",
    )
    .unwrap();
    assert_eq!(
        component_stanza_error(document.root_element(), "not-authorized"),
        None
    );
}

#[test]
fn rejected_remote_component_route_uses_the_standard_condition() {
    let document = Document::parse(
        "<message xmlns='jabber:client' id='relay' from='gateway.example' to='user@denied.example'><body>blocked</body></message>",
    )
    .unwrap();
    let error = component_stanza_error(document.root_element(), "remote-server-not-found")
        .expect("ordinary stanza must be reflected as an error");
    assert!(
        error.contains("<remote-server-not-found xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/>")
    );
    assert!(!error.contains("undefined-condition"));
}

#[test]
fn connect_mode_cannot_relay_beyond_locally_hosted_domains() {
    let connect = ComponentProtocol::Legacy0114Connect.relay_grant();
    let stanza = Document::parse(
        "<message xmlns='jabber:client' from='gateway.example' to='user@remote.example'><body>hello</body></message>",
    )
    .unwrap();
    let target = target_domain(stanza.root_element().attribute("to").unwrap()).unwrap();
    assert_eq!(
        component_route_target("example.test", &target, false, connect),
        ComponentRouteTarget::Denied
    );
    for local in [
        "EXAMPLE.TEST.",
        "pubsub.example.test",
        "conference.example.test",
        "mix.example.test",
        "upload.example.test",
    ] {
        assert_eq!(
            component_route_target("example.test", local, false, connect),
            ComponentRouteTarget::LocalService
        );
    }
    assert_eq!(
        component_route_target("example.test", "other-component.test", true, connect),
        ComponentRouteTarget::ConfiguredComponent
    );
    assert_eq!(
        component_route_target("example.test", "mix.example.test", true, connect),
        ComponentRouteTarget::LocalService
    );

    for protocol in [
        ComponentProtocol::Legacy0114Accept,
        ComponentProtocol::Modern0225,
    ] {
        let grant = protocol.relay_grant();
        assert_eq!(
            component_route_target("example.test", &target, false, grant),
            ComponentRouteTarget::Federation
        );
        assert_eq!(
            component_route_target("example.test", "other-component.test", true, grant),
            ComponentRouteTarget::ConfiguredComponent
        );
    }
}

#[test]
fn unregistering_one_connection_never_removes_another_incarnation() {
    let registry = registry();
    let first = Uuid::new_v4();
    let second = Uuid::new_v4();
    let (sender, _receiver) = mpsc::channel(1);
    registry
        .register_domain("gateway.example", second, sender)
        .unwrap();
    registry.remove_connection(first);
    assert!(registry.connection_owns_domain("gateway.example", second));
}
