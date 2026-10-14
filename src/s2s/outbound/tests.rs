use super::*;

fn test_dispatch(pool: &sqlx::PgPool) -> DispatchService {
    use crate::services::s2s_outbox_dispatch::S2sOutboxDispatchPolicy;
    S2sOutboxDispatchService::new(
        crate::db::s2s_outbox_dispatch_repository::PostgresS2sOutboxDispatchRepository::new(
            pool.clone(),
        ),
        S2sOutboxDispatchPolicy {
            claim_batch: 10,
            lease_seconds: 120,
            retry_base_seconds: 60,
            retry_max_seconds: 60,
            max_attempts: 200,
        },
    )
}

async fn enqueue_authenticated_recovery_test_row(
    pool: &sqlx::PgPool,
    target: &str,
    stanza: &str,
) -> uuid::Uuid {
    db::enqueue_s2s_outbox(pool, target, stanza, None, 300, 100, 1_000_000, 100)
        .await
        .unwrap()
}

fn publish_authenticated_recovery_test_route(
    registry: &S2sConnectionRegistry,
    target: &str,
    disconnect: tokio_util::sync::CancellationToken,
) -> mpsc::Receiver<FederationEnvelope> {
    let (sender, receiver) = mpsc::channel(4);
    assert!(registry
        .register_bidirectional_if_vacant(
            bidi_connection_key("local.test", target).unwrap(),
            BidiS2sSession::new(
                uuid::Uuid::new_v4(),
                "local.test".to_owned(),
                sender,
                disconnect
            ),
        )
        .is_ok());
    receiver
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "requires TEST_DATABASE_URL; uses and removes a random isolated schema"]
async fn authenticated_route_recovery_integrates_with_fifo_and_leased_failure_commit() {
    let url = std::env::var("TEST_DATABASE_URL")
        .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
    let admin = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .unwrap();
    let schema = format!("s2s_recovery_integration_{}", uuid::Uuid::new_v4().simple());
    sqlx::query(&format!("CREATE SCHEMA {schema}"))
        .execute(&admin)
        .await
        .unwrap();
    eprintln!("isolated_schema_created={schema}");
    let connection_schema = schema.clone();
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(6)
        .after_connect(move |connection, _| {
            let statement = format!("SET search_path TO {connection_schema}");
            Box::pin(async move {
                sqlx::query(&statement).execute(connection).await?;
                Ok(())
            })
        })
        .connect(&url)
        .await
        .unwrap();
    db::migrate(&pool).await.unwrap();
    let dispatch = test_dispatch(&pool);

    let registry = S2sConnectionRegistry::default();
    let target = "recovered.remote.test";
    let domains = vec![target.to_owned()];
    let head_id = enqueue_authenticated_recovery_test_row(
        &pool,
        target,
        "<message from='sender@local.test' to='peer@recovered.remote.test' id='first'/>",
    )
    .await;
    let successor_id = enqueue_authenticated_recovery_test_row(
        &pool,
        target,
        "<message from='sender@local.test' to='peer@recovered.remote.test' id='second'/>",
    )
    .await;
    let mut claimed = db::claim_due_s2s_outbox_for_domains(&pool, 10, 120, &domains)
        .await
        .unwrap();
    assert_eq!(claimed.len(), 1);
    let first = claimed.remove(0);
    assert_eq!(first.id, head_id);
    assert_eq!(
        db::fail_s2s_outbox(&pool, &first, "initial route outage", 60, 60, 200, false)
            .await
            .unwrap(),
        db::S2sFailureDisposition::RetryScheduled
    );
    assert_eq!(
        recover_authenticated_route_heads(&dispatch, &registry, &[], |_| true, 4)
            .await
            .unwrap(),
        0
    );
    assert!(
        !db::s2s_route_recovery_head(&pool, target)
            .await
            .unwrap()
            .unwrap()
            .retry_due
    );
    let _first_receiver = publish_authenticated_recovery_test_route(
        &registry,
        target,
        tokio_util::sync::CancellationToken::new(),
    );
    assert_eq!(
        recover_authenticated_route_heads(&dispatch, &registry, &[], |_| true, 4)
            .await
            .unwrap(),
        1
    );
    let mut claimed = db::claim_due_s2s_outbox_for_domains(&pool, 10, 120, &domains)
        .await
        .unwrap();
    assert_eq!(
        claimed.len(),
        1,
        "recovery must not let a successor overtake its head"
    );
    let recovered = claimed.remove(0);
    assert_eq!(recovered.id, head_id);
    assert_ne!(recovered.id, successor_id);
    assert_ne!(recovered.lock_token, first.lock_token);
    assert!(!db::complete_s2s_outbox(&pool, first.id, first.lock_token)
        .await
        .unwrap());
    assert_eq!(
        db::fail_s2s_outbox(
            &pool,
            &recovered,
            "same stream failed again",
            60,
            60,
            200,
            false
        )
        .await
        .unwrap(),
        db::S2sFailureDisposition::RetryScheduled
    );
    assert_eq!(
        recover_authenticated_route_heads(&dispatch, &registry, &[], |_| true, 4)
            .await
            .unwrap(),
        0,
        "the same authenticated stream must not repeatedly defeat backoff"
    );
    assert!(
        !db::s2s_route_recovery_head(&pool, target)
            .await
            .unwrap()
            .unwrap()
            .retry_due
    );
    assert!(
        db::claim_due_s2s_outbox_for_domains(&pool, 10, 120, &domains)
            .await
            .unwrap()
            .is_empty()
    );

    let leased_target = "leased.remote.test";
    let leased_domains = vec![leased_target.to_owned()];
    let leased_id = enqueue_authenticated_recovery_test_row(
        &pool,
        leased_target,
        "<message from='sender@local.test' to='peer@leased.remote.test' id='leased'/>",
    )
    .await;
    let mut claimed = db::claim_due_s2s_outbox_for_domains(&pool, 10, 120, &leased_domains)
        .await
        .unwrap();
    assert_eq!(claimed.len(), 1);
    let leased = claimed.remove(0);
    let _leased_receiver = publish_authenticated_recovery_test_route(
        &registry,
        leased_target,
        tokio_util::sync::CancellationToken::new(),
    );
    let mut blocker = pool.begin().await.unwrap();
    let _: uuid::Uuid = sqlx::query_scalar("SELECT id FROM s2s_outbox WHERE id=$1 FOR UPDATE")
        .bind(leased_id)
        .fetch_one(&mut *blocker)
        .await
        .unwrap();
    let fail_pool = pool.clone();
    let failing_item = leased.clone();
    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    let failing = tokio::spawn(async move {
        started_tx.send(()).unwrap();
        db::fail_s2s_outbox(
            &fail_pool,
            &failing_item,
            "old lease failure awaiting commit",
            60,
            60,
            200,
            false,
        )
        .await
    });
    started_rx.await.unwrap();
    // The actual failure cannot commit while the row lock is held. The
    // production recovery helper must retain the exact head's hint.
    assert_eq!(
        recover_authenticated_route_heads(&dispatch, &registry, &[], |_| true, 4)
            .await
            .unwrap(),
        0
    );
    assert_eq!(registry.pending_bidi_recoveries(4).len(), 1);
    assert!(
        db::s2s_route_recovery_head(&pool, leased_target)
            .await
            .unwrap()
            .unwrap()
            .claim_in_flight
    );
    assert!(!failing.is_finished());
    blocker.commit().await.unwrap();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(5), failing)
            .await
            .expect("released row lock must allow the real failure to commit")
            .unwrap()
            .unwrap(),
        db::S2sFailureDisposition::RetryScheduled
    );
    assert_eq!(
        recover_authenticated_route_heads(&dispatch, &registry, &[], |_| true, 4)
            .await
            .unwrap(),
        1
    );
    let mut claimed = db::claim_due_s2s_outbox_for_domains(&pool, 10, 120, &leased_domains)
        .await
        .unwrap();
    assert_eq!(claimed.len(), 1);
    let after_commit = claimed.remove(0);
    assert_eq!(after_commit.id, leased_id);
    assert_eq!(after_commit.attempt_count, leased.attempt_count + 1);
    assert_ne!(after_commit.lock_token, leased.lock_token);
    assert!(
        !db::complete_s2s_outbox(&pool, leased.id, leased.lock_token)
            .await
            .unwrap()
    );
    assert!(
        db::complete_s2s_outbox(&pool, after_commit.id, after_commit.lock_token)
            .await
            .unwrap()
    );
    assert!(registry.pending_bidi_recoveries(4).is_empty());

    for reason in ["direction", "component", "denied", "revoked"] {
        let target = format!("{reason}.remote.test");
        let source = if reason == "direction" {
            "other.test"
        } else {
            "local.test"
        };
        let stanza = format!("<message from='sender@{source}' to='peer@{target}' id='{reason}'/>");
        let id = enqueue_authenticated_recovery_test_row(&pool, &target, &stanza).await;
        sqlx::query(
            "UPDATE s2s_outbox SET next_attempt_at=NOW()+INTERVAL '10 minutes' WHERE id=$1",
        )
        .bind(id)
        .execute(&pool)
        .await
        .unwrap();
        let rejected_registry = S2sConnectionRegistry::default();
        let disconnect = tokio_util::sync::CancellationToken::new();
        let _receiver = publish_authenticated_recovery_test_route(
            &rejected_registry,
            &target,
            disconnect.clone(),
        );
        if reason == "revoked" {
            disconnect.cancel();
        }
        let excluded = if reason == "component" {
            vec![target.clone()]
        } else {
            vec![]
        };
        assert_eq!(
            recover_authenticated_route_heads(
                &dispatch,
                &rejected_registry,
                &excluded,
                |_| reason != "denied",
                4
            )
            .await
            .unwrap(),
            0,
            "an ineligible route must not accelerate its head: {reason}"
        );
        assert!(
            !db::s2s_route_recovery_head(&pool, &target)
                .await
                .unwrap()
                .unwrap()
                .retry_due
        );
        assert_eq!(
            recover_authenticated_route_heads(&dispatch, &rejected_registry, &[], |_| true, 4)
                .await
                .unwrap(),
            0,
            "a consumed or revoked route hint must not reappear: {reason}"
        );
    }
    pool.close().await;
    sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
        .execute(&admin)
        .await
        .unwrap();
    admin.close().await;
}

#[test]
fn authenticated_recovery_requires_the_exact_stanza_direction() {
    assert!(bidi_stanza_authorized(
        "<message from='alice@LOCAL.test/a' to='room@REMOTE.test'/>",
        "local.test",
        "remote.test",
    ));
    for stanza in [
        "<message from='alice@other.test' to='room@remote.test'/>",
        "<message from='alice@local.test' to='room@other.test'/>",
        "<message from='alice@remote.test' to='room@local.test'/>",
        "<message to='room@remote.test'/>",
        "<message from='alice@local.test'/>",
        "<message from='invalid user@local.test' to='room@remote.test'/>",
        "<message from='alice@local.test' to='@remote.test'/>",
        "<message><body>from='alice@local.test' to='room@remote.test'</body></message>",
        "<message",
    ] {
        assert!(!bidi_stanza_authorized(stanza, "local.test", "remote.test"));
    }
}

#[tokio::test]
async fn disallowed_recovery_routes_never_poll_the_database() {
    let pool = sqlx::postgres::PgPoolOptions::new()
        .connect_lazy("postgres://unused:unused@127.0.0.1/unused")
        .unwrap();
    pool.close().await;
    let dispatch = test_dispatch(&pool);
    for component in [false, true] {
        let registry = S2sConnectionRegistry::default();
        let (sender, _receiver) = mpsc::channel(1);
        assert!(registry
            .register_bidirectional_if_vacant(
                bidi_connection_key("local.test", "remote.test").unwrap(),
                BidiS2sSession::new(
                    uuid::Uuid::new_v4(),
                    "local.test".to_owned(),
                    sender,
                    tokio_util::sync::CancellationToken::new(),
                ),
            )
            .is_ok());
        let excluded = if component {
            vec!["remote.test".to_owned()]
        } else {
            vec![]
        };
        assert_eq!(
            recover_authenticated_route_heads(&dispatch, &registry, &excluded, |_| component, 1,)
                .await
                .unwrap(),
            0
        );
        assert!(registry.pending_bidi_recoveries(1).is_empty());
    }
}

#[test]
fn outbound_cancellation_distinguishes_shutdown_from_certificate_revocation() {
    assert_eq!(
        outbound_cancellation_message(true, " before delivery"),
        "outbound S2S connection closed during server shutdown before delivery"
    );
    assert_eq!(
        outbound_cancellation_message(false, " before delivery"),
        "outbound S2S certificate was explicitly revoked before delivery"
    );
}

#[test]
fn happy_eyeballs_staggers_candidates_deterministically() {
    assert_eq!(happy_eyeballs_delay(0), Duration::ZERO);
    assert_eq!(happy_eyeballs_delay(1), Duration::from_millis(250));
    assert_eq!(happy_eyeballs_delay(4), Duration::from_secs(1));
    assert_eq!(HAPPY_EYEBALLS_MAX_IN_FLIGHT, 4);
}

#[test]
fn happy_eyeballs_alternates_families_and_preserves_family_order() {
    let endpoint = |address: &str| FederationEndpoint {
        address: address.parse().unwrap(),
        direct_tls: true,
        tls_server_name: "remote.test".to_owned(),
        delegated_identity: false,
        public_key_pins: Vec::new(),
        selection_group: 0,
        dane_srv_binding: None,
    };
    let ordered = happy_eyeballs_endpoint_order(&[
        endpoint("[2001:4860:4860::8888]:5269"),
        endpoint("[2001:4860:4860::8844]:5269"),
        endpoint("8.8.8.8:5269"),
        endpoint("8.8.4.4:5269"),
    ]);
    assert_eq!(
        ordered
            .iter()
            .map(|endpoint| endpoint.address)
            .collect::<Vec<_>>(),
        vec![
            "[2001:4860:4860::8888]:5269".parse().unwrap(),
            "8.8.8.8:5269".parse().unwrap(),
            "[2001:4860:4860::8844]:5269".parse().unwrap(),
            "8.8.4.4:5269".parse().unwrap(),
        ]
    );
}

#[tokio::test]
async fn happy_eyeballs_live_fallback_reaches_ipv4_after_ipv6_failure() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let endpoint = |address| FederationEndpoint {
        address,
        direct_tls: true,
        tls_server_name: "remote.test".to_owned(),
        delegated_identity: false,
        public_key_pins: Vec::new(),
        selection_group: 0,
        dane_srv_binding: None,
    };
    let endpoints = [
        endpoint(format!("[::1]:{port}").parse().unwrap()),
        endpoint(format!("127.0.0.1:{port}").parse().unwrap()),
    ];
    let connect = race_happy_eyeballs(&endpoints, |endpoint| async move {
        tokio::time::timeout(Duration::from_secs(2), TcpStream::connect(endpoint.address))
            .await
            .context("live Happy Eyeballs attempt timed out")?
            .context("live Happy Eyeballs attempt failed")
    });
    let (connected, accepted) = tokio::join!(connect, listener.accept());
    let connected = connected.unwrap();
    let (_, accepted_peer) = accepted.unwrap();
    assert!(connected.peer_addr().unwrap().is_ipv4());
    assert!(accepted_peer.is_ipv4());
}

#[test]
fn stream_identity_uses_idna_and_rejects_non_domain_identities() {
    assert!(validate_stream_identity(
        "example.test",
        "B\u{fc}CHER.Example.",
        "<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:server' version='1.0' from='xn--bcher-kva.example' to='EXAMPLE.TEST'>"
    )
    .is_ok());
    assert!(validate_stream_identity(
        "example.test",
        "remote.test",
        "<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:server' version='1.0' from='alice@remote.test' to='example.test'>"
    )
    .is_err());
    assert!(validate_stream_identity(
        "example.test",
        "remote..test",
        "<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:server' version='1.0' from='remote..test' to='example.test'>"
    )
    .is_err());
}

#[test]
fn peer_stream_limit_is_applied_after_server_namespace_serialization() {
    let stanza = "<message xmlns='jabber:client'><body>hello</body></message>";
    let serialized = serialize_for_peer(stanza, None).unwrap();
    assert!(serialized.contains("xmlns='jabber:server'"));
    assert!(serialize_for_peer(stanza, Some(serialized.len())).is_ok());
    let error = serialize_for_peer(stanza, Some(serialized.len() - 1)).unwrap_err();
    assert!(is_peer_stanza_limit_error(&error));
}

#[test]
fn dialback_authorization_failures_use_xep_0220_bounce_conditions() {
    let invalid = anyhow::Error::new(DialbackAuthorizationFailure::Invalid);
    let timeout = anyhow::Error::new(DialbackAuthorizationFailure::Error(
        "remote-server-not-found".to_owned(),
    ));
    assert!(is_dialback_authorization_error(&invalid));
    assert!(is_dialback_authorization_error(&timeout));
    assert_eq!(
        invalid
            .downcast_ref::<DialbackAuthorizationFailure>()
            .unwrap()
            .bounce_condition(),
        "internal-server-error"
    );
    assert_eq!(
        timeout
            .downcast_ref::<DialbackAuthorizationFailure>()
            .unwrap()
            .bounce_condition(),
        "remote-server-timeout"
    );
}

#[test]
fn federation_failure_bounces_reflect_the_original_stanza_without_error_loops() {
    let original = "<message xmlns='jabber:server' from='alice@local.test/Phone' to='bob@remote.test' type='chat' id='m1'><body>still here</body><x xmlns='urn:example:extension'/></message>";
    for (condition, error_type) in [
        ("internal-server-error", "wait"),
        ("remote-server-timeout", "wait"),
        ("remote-server-not-found", "cancel"),
        ("policy-violation", "modify"),
    ] {
        let bounced = delivery_failure_stanza(original, condition).unwrap();
        let document = Document::parse(&bounced).unwrap();
        let root = document.root_element();
        assert_eq!(root.tag_name().namespace(), Some("jabber:client"));
        assert_eq!(root.attribute("type"), Some("error"));
        assert_eq!(root.attribute("id"), Some("m1"));
        assert_eq!(root.attribute("from"), Some("bob@remote.test"));
        assert_eq!(root.attribute("to"), Some("alice@local.test/Phone"));
        assert!(root.children().any(|child| {
            child.is_element()
                && child.tag_name().name() == "body"
                && child.text() == Some("still here")
        }));
        assert!(root.children().any(|child| {
            child.is_element()
                && child.tag_name().name() == "x"
                && child.tag_name().namespace() == Some("urn:example:extension")
        }));
        let error = root
            .children()
            .find(|child| {
                child.is_element()
                    && child.tag_name().name() == "error"
                    && child.tag_name().namespace() == Some("jabber:client")
            })
            .unwrap();
        assert_eq!(error.attribute("type"), Some(error_type));
        assert!(error.children().any(|child| {
            child.is_element()
                && child.tag_name().name() == condition
                && child.tag_name().namespace() == Some("urn:ietf:params:xml:ns:xmpp-stanzas")
        }));
    }

    let error = "<message xmlns='jabber:client' from='alice@local.test' to='bob@remote.test' type='error' id='e1'><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></message>";
    assert!(delivery_failure_stanza(error, "remote-server-not-found").is_none());
    assert!(delivery_failure_stanza(original, "invented-condition").is_none());
}

#[test]
fn negotiation_features_require_exact_elements_and_namespaces() {
    let features = "<stream:features><starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'><required/></starttls><mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><mechanism>EXTERNAL</mechanism></mechanisms></stream:features>";
    assert!(stream_feature_advertised(
        features,
        "starttls",
        "urn:ietf:params:xml:ns:xmpp-tls"
    ));
    assert!(sasl_external_advertised(features));
    assert!(!sasl_external_advertised(
        "<stream:features><feature var='EXTERNAL'/></stream:features>"
    ));
    assert!(!stream_feature_advertised(
        "<stream:features><feature var='urn:ietf:params:xml:ns:xmpp-tls'/></stream:features>",
        "starttls",
        "urn:ietf:params:xml:ns:xmpp-tls"
    ));

    assert!(valid_empty_negotiation_element(
        "<proceed xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>",
        "proceed",
        "urn:ietf:params:xml:ns:xmpp-tls"
    ));
    assert!(!valid_empty_negotiation_element(
        "<proceed-bogus xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>",
        "proceed",
        "urn:ietf:params:xml:ns:xmpp-tls"
    ));
}
