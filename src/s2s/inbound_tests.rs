use super::*;
use crate::services::retractions::RetractionService;

#[test]
fn bidi_route_waits_for_resume_preface_but_admits_non_sm_peers() {
    // A new authenticated transport has not established its SM mode yet.
    // In particular it must not receive an outbox stanza before <resume/>.
    assert!(!initial_bidi_route_admissible(false, false, false, false));
    // A peer that does not use SM still obtains a BIDI route after the
    // bounded negotiation wait, unless an older resumable owner exists.
    assert!(initial_bidi_route_admissible(false, false, true, false));
    assert!(!initial_bidi_route_admissible(false, false, true, true));
    // Once the peer enables SM or sends an application stanza, the route
    // can carry reverse traffic without waiting for the timer.
    assert!(initial_bidi_route_admissible(true, false, false, true));
    assert!(initial_bidi_route_admissible(false, true, false, true));
}

#[test]
fn local_service_domains_cannot_be_asserted_by_an_inbound_federation_stream() {
    for domain in [
        "example.test",
        "PUBSUB.Example.Test.",
        "conference.example.test",
        "mix.example.test",
        "upload.example.test",
    ] {
        assert!(locally_hosted_identity_domain("example.test", domain));
    }
    assert!(!locally_hosted_identity_domain(
        "example.test",
        "remote.example.test"
    ));
}

#[tokio::test]
async fn disabled_federation_task_waits_for_cancel() {
    let cancel = tokio_util::sync::CancellationToken::new();
    let task_cancel = cancel.clone();
    let mut task = tokio::spawn(async move {
        wait_for_federation_shutdown(&task_cancel).await;
    });

    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(50), &mut task)
            .await
            .is_err(),
        "disabled federation must not terminate the whole server"
    );
    cancel.cancel();
    tokio::time::timeout(std::time::Duration::from_secs(1), task)
        .await
        .expect("disabled federation shutdown wait timed out")
        .expect("disabled federation shutdown task panicked");
}

#[test]
fn push_notification_publish_routes_to_service_instead_of_pep() {
    let push = Document::parse(
        "<pubsub xmlns='http://jabber.org/protocol/pubsub'><publish node='device'><item><notification xmlns='urn:xmpp:push:0'/></item></publish><publish-options/></pubsub>",
    )
    .unwrap();
    assert!(is_xep0357_notification_publish(push.root_element()));

    let pep = Document::parse(
        "<pubsub xmlns='http://jabber.org/protocol/pubsub'><publish node='urn:test'><item><value xmlns='urn:test'>payload</value></item></publish></pubsub>",
    )
    .unwrap();
    assert!(!is_xep0357_notification_publish(pep.root_element()));

    // RFC 6121 §§8.5.2.1.3 and 8.5.2.2.3 say that an IQ addressed to a
    // bare account is answered by the server and MUST NOT be delivered to
    // account resources.  Northstar's explicit, narrow service extension
    // is limited to the XEP-0357 notification shape; generic PubSub or an
    // arbitrary IQ cannot use this compatibility route.
    let service_account = CanonicalJid::parse_bare("push@example.test").unwrap();
    assert!(bare_account_iq_may_route_to_service_resource(
        &service_account,
        push.root_element()
    ));
    assert!(!bare_account_iq_may_route_to_service_resource(
        &service_account,
        pep.root_element()
    ));
    let domain_service = CanonicalJid::parse("push.example.test").unwrap();
    assert!(!bare_account_iq_may_route_to_service_resource(
        &domain_service,
        push.root_element()
    ));
    let full_resource = CanonicalJid::parse("push@example.test/worker").unwrap();
    assert!(!bare_account_iq_may_route_to_service_resource(
        &full_resource,
        push.root_element()
    ));
}

#[test]
fn authoritative_dialback_callbacks_are_not_misclassified_as_downgrades() {
    assert!(is_certificate_downgrade("result", true));
    assert!(!is_certificate_downgrade("verify", true));
    assert!(!is_certificate_downgrade("result", false));
}

#[test]
fn remote_history_identity_is_bound_to_the_authenticated_domain() {
    let document = Document::parse(
        "<message><stanza-id xmlns='urn:xmpp:sid:0' by='Alice@REMOTE.test' id='trusted'/><stanza-id xmlns='urn:xmpp:sid:0' by='mallory.test' id='ignored'/></message>",
    )
    .unwrap();
    assert_eq!(
        authoritative_remote_stanza_identity(document.root_element(), "remote.TEST"),
        Some((
            "Alice@REMOTE.test".to_owned(),
            "alice@remote.test".to_owned(),
            "trusted".to_owned()
        ))
    );
    assert!(
        authoritative_remote_stanza_identity(document.root_element(), "unrelated.test").is_none()
    );

    let ambiguous = Document::parse(
        "<message><stanza-id xmlns='urn:xmpp:sid:0' by='alice@remote.test' id='a'/><stanza-id xmlns='urn:xmpp:sid:0' by='remote.test' id='b'/></message>",
    )
    .unwrap();
    assert!(
        authoritative_remote_stanza_identity(ambiguous.root_element(), "remote.test").is_none()
    );
}

#[test]
fn s2s_sender_authentication_uses_idna_and_rejects_malformed_jids() {
    assert!(authenticated_s2s_sender(
        "Alice@B\u{fc}cher.Example/Phone",
        "bücher.example"
    ));
    assert!(authenticated_s2s_sender(
        "mix.bücher.example",
        "MIX.B\u{fc}CHER.example."
    ));
    assert!(!authenticated_s2s_sender(
        "alice@example.test/\u{0007}",
        "example.test"
    ));
    assert!(!authenticated_s2s_sender(
        "alice@evil.test/Phone",
        "example.test"
    ));
}

#[test]
fn rfc6120_s2s_address_violations_are_fatal_stream_errors() {
    let valid = "<message from='alice@remote.test/phone' to='bob@local.test'/>";
    assert_eq!(
        s2s_stream_address_error(valid, "remote.test", "local.test"),
        None
    );
    for (stanza, expected) in [
        (
            "<message to='bob@local.test'/>",
            Some("improper-addressing"),
        ),
        (
            "<message from='alice@remote.test'/>",
            Some("improper-addressing"),
        ),
        (
            "<message from='not a jid' to='bob@local.test'/>",
            Some("improper-addressing"),
        ),
        (
            "<message from='alice@remote.test' to='not a jid'/>",
            Some("improper-addressing"),
        ),
        (
            "<message from='mallory@evil.test' to='bob@local.test'/>",
            Some("invalid-from"),
        ),
        (
            "<message from='alice@remote.test' to='bob@elsewhere.test'/>",
            Some("host-unknown"),
        ),
    ] {
        assert_eq!(
            s2s_stream_address_error(stanza, "REMOTE.test", "LOCAL.test"),
            expected,
            "wrong stream result for {stanza}"
        );
    }
}

#[test]
fn inbound_federation_uses_the_same_strict_core_stanza_grammar() {
    assert!(valid_inbound_wire_namespace(
        "<message from='a@remote.test' to='b@local.test'/>"
    ));
    assert!(valid_inbound_wire_namespace(
        "<message xmlns='jabber:server' from='a@remote.test' to='b@local.test'/>"
    ));
    assert!(!valid_inbound_wire_namespace(
        "<message xmlns='jabber:client' from='a@remote.test' to='b@local.test'/>"
    ));
    assert!(!valid_inbound_wire_namespace(
        "<message xmlns='urn:wrong' from='a@remote.test' to='b@local.test'/>"
    ));
    for valid in [
        "<message xmlns='jabber:client' from='a@remote.test' to='b@local.test' type='chat'><body>ok</body></message>",
        "<presence xmlns='jabber:client' from='a@remote.test' to='b@local.test' type='subscribe'/>",
        "<iq xmlns='jabber:client' from='a@remote.test' to='b@local.test' type='get' id='q1'><ping xmlns='urn:xmpp:ping'/></iq>",
    ] {
        let document = Document::parse(valid).unwrap();
        assert_eq!(
            validate_inbound_core_stanza(document.root_element()),
            InboundCoreValidation::Valid,
            "rejected {valid}"
        );
    }

    for (invalid, expected) in [
        (
            "<message xmlns='jabber:client' from='a@remote.test' to='b@local.test' type='invented'/>",
            InboundCoreValidation::Error("bad-request"),
        ),
        (
            "<presence xmlns='jabber:client' from='a@remote.test' to='b@local.test'><priority>128</priority></presence>",
            InboundCoreValidation::Error("bad-request"),
        ),
    ] {
        let document = Document::parse(invalid).unwrap();
        assert_eq!(
            validate_inbound_core_stanza(document.root_element()),
            expected,
            "accepted {invalid}"
        );
    }

    for dropped in [
        "<message xmlns='urn:wrong' type='chat'/>",
        "<feature xmlns='jabber:client'/>",
        "<iq xmlns='jabber:client' type='error' id='e'><error/></iq>",
        "<iq xmlns='jabber:client' from='a@remote.test' to='b@local.test' type='get'><ping xmlns='urn:xmpp:ping'/></iq>",
        "<message xmlns='jabber:client' from='bad domain' to='b@local.test' type='chat'/>",
    ] {
        let document = Document::parse(dropped).unwrap();
        assert_eq!(
            validate_inbound_core_stanza(document.root_element()),
            InboundCoreValidation::Drop,
            "reflected {dropped}"
        );
    }
}

#[test]
fn probe_status_responses_preserve_correlation_and_escape_addresses() {
    let response = presence_probe_status_response(
        "alice@local.test",
        "bob&carol@remote.test",
        "unavailable",
        Some("probe'1"),
    );
    assert_eq!(
        response,
        "<presence xmlns='jabber:server' from='alice@local.test' to='bob&amp;carol@remote.test' type='unavailable' id='probe&apos;1'/>"
    );
}

#[test]
fn bidi_replies_honor_the_peer_limit_and_use_policy_violation_when_possible() {
    let request = "<iq xmlns='jabber:server' type='get' id='q1' from='remote.test' to='local.test'><ping xmlns='urn:xmpp:ping'/></iq>";
    let oversized = format!(
        "<iq xmlns='jabber:server' type='result' id='q1' from='local.test' to='remote.test'><value>{}</value></iq>",
        "x".repeat(2_048)
    );
    let error = s2s_stanza_error(
        Document::parse(request).unwrap().root_element(),
        "modify",
        "policy-violation",
    );
    let error_bytes = super::super::outbound::serialize_for_peer(&error, None)
        .unwrap()
        .len();

    let bounded = reply_within_peer_limit(&oversized, request, Some(error_bytes))
        .unwrap()
        .expect("the compact policy error fits exactly");
    assert!(bounded.contains("<policy-violation"));
    assert!(bounded.contains("id='q1'"));
    assert!(
        reply_within_peer_limit(&oversized, request, Some(error_bytes - 1))
            .unwrap()
            .is_none()
    );
    assert!(reply_within_peer_limit(&oversized, request, Some(0))
        .unwrap()
        .is_none());
}

#[test]
fn bidi_request_requires_the_negotiation_namespace() {
    assert_eq!(
        parse_bidi_request("<bidi xmlns='urn:xmpp:bidi'/>"),
        Some(BidiRequest {
            peer_limits: AdvertisedStreamLimits::default()
        })
    );
    assert_eq!(
        parse_bidi_request("<bidi xmlns='urn:xmpp:bidi'><limits xmlns='urn:xmpp:stream-limits:0'><max-bytes>8192</max-bytes><idle-seconds>12</idle-seconds></limits></bidi>"),
        Some(BidiRequest {
            peer_limits: AdvertisedStreamLimits {
                max_bytes: Some(8192),
                idle_seconds: Some(12),
            }
        })
    );
    for invalid in [
        "<bidi xmlns='urn:xmpp:features:bidi'/>",
        "<bidi/>",
        "<message xmlns='jabber:server'/>",
        "<bidi xmlns='urn:xmpp:bidi' extra='true'/>",
        "<bidi xmlns='urn:xmpp:bidi'>text</bidi>",
        "<bidi xmlns='urn:xmpp:bidi'><unknown/></bidi>",
        "<bidi xmlns='urn:xmpp:bidi'><limits xmlns='urn:xmpp:stream-limits:0'/><limits xmlns='urn:xmpp:stream-limits:0'/></bidi>",
        "<bidi xmlns='urn:xmpp:bidi'><limits xmlns='urn:xmpp:stream-limits:0'><idle-seconds>12</idle-seconds><max-bytes>8192</max-bytes></limits></bidi>",
    ] {
        assert!(parse_bidi_request(invalid).is_none(), "accepted {invalid}");
    }
}

#[test]
fn starttls_requires_the_exact_empty_negotiation_element() {
    assert!(valid_starttls_request(
        "<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>"
    ));
    for invalid in [
        "<starttls/>",
        "<starttls-bogus xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>",
        "<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls' extra='1'/>",
        "<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'><required/></starttls>",
    ] {
        assert!(!valid_starttls_request(invalid), "accepted {invalid}");
    }
}

#[test]
fn dialback_frames_inherit_only_the_stream_declared_prefix() {
    let inherited = restore_inherited_dialback_namespace(
        "<db:result from='remote.test' to='local.test'>00</db:result>",
    );
    let document = Document::parse(&inherited).unwrap();
    assert_eq!(
        document.root_element().tag_name().namespace(),
        Some(DIALBACK_NS)
    );

    let conflicting =
        "<db:result xmlns:db='urn:wrong' from='remote.test' to='local.test'>00</db:result>";
    assert!(matches!(
        restore_inherited_dialback_namespace(conflicting),
        Cow::Borrowed(_)
    ));
    let document = Document::parse(conflicting).unwrap();
    assert_ne!(
        document.root_element().tag_name().namespace(),
        Some(DIALBACK_NS)
    );
}

#[test]
fn external_authentication_rejects_ambiguous_xml_and_base64() {
    let valid = Document::parse(
        "<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='EXTERNAL'>=</auth>",
    )
    .unwrap();
    assert!(valid_external_auth_shape(valid.root_element()));
    assert_eq!(decode_external("=").unwrap(), "");
    assert_eq!(decode_external("").unwrap(), "");

    for invalid in [
        "<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='EXTERNAL' extra='1'>=</auth>",
        "<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='EXTERNAL'><response/></auth>",
        "<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='EXTERNAL'><!--split-->ZXhhbXBsZS50ZXN0</auth>",
    ] {
        let document = Document::parse(invalid).unwrap();
        assert!(!valid_external_auth_shape(document.root_element()), "accepted {invalid}");
    }
    assert!(decode_external(" ZXhhbXBsZS50ZXN0").is_err());
    assert!(decode_external("ZXhhbXBsZS50ZXN0\n").is_err());
    assert!(decode_external("=AAA").is_err());
}

#[test]
fn message_delivery_errors_use_rfc6120_type_condition_pairs() {
    let request = Document::parse(
        "<message xmlns='jabber:server' from='alice@remote.test/a' to='bob@local.test'><body>hello</body></message>",
    )
    .unwrap();
    for (serialized, condition) in [
        (
            offline_quota_error(request.root_element()),
            "resource-constraint",
        ),
        (
            recipient_unavailable_error(request.root_element()),
            "recipient-unavailable",
        ),
    ] {
        let response = Document::parse(&serialized).unwrap();
        let error = response
            .root_element()
            .children()
            .find(|child| {
                child.is_element()
                    && child.tag_name().name() == "error"
                    && child.tag_name().namespace() == Some("jabber:server")
            })
            .unwrap();
        assert_eq!(error.attribute("type"), Some("wait"));
        assert!(error.children().any(|child| {
            child.is_element()
                && child.tag_name().name() == condition
                && child.tag_name().namespace() == Some("urn:ietf:params:xml:ns:xmpp-stanzas")
        }));
    }
}

#[test]
fn message_errors_never_generate_error_loops() {
    let ordinary = Document::parse(
        "<message xmlns='jabber:server' from='alice@remote.test/a' to='bob@local.test'><body>hello</body></message>",
    )
    .unwrap();
    assert!(
        inbound_message_error(ordinary.root_element(), "cancel", "service-unavailable").is_some()
    );

    let error = Document::parse(
        "<message xmlns='jabber:server' type='error' from='alice@remote.test/a' to='missing@local.test'><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></message>",
    )
    .unwrap();
    assert!(inbound_message_error(error.root_element(), "cancel", "service-unavailable").is_none());
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "requires TEST_DATABASE_URL; uses and removes a random isolated schema"]
async fn message_acceptance_boundary_prevents_mam_retraction_and_offline_ghosts() {
    let url = std::env::var("TEST_DATABASE_URL")
        .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
    let admin = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .unwrap();
    let schema = format!("message_acceptance_test_{}", uuid::Uuid::new_v4().simple());
    eprintln!("isolated_schema={schema}");
    sqlx::query(&format!("CREATE SCHEMA {schema}"))
        .execute(&admin)
        .await
        .unwrap();
    let connection_schema = schema.clone();
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(4)
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
    crate::db::migrate(&pool).await.unwrap();

    let recipient_id = uuid::Uuid::new_v4();
    let sender_id = uuid::Uuid::new_v4();
    sqlx::query("INSERT INTO users(id, username, password_hash) VALUES($1, 'bob', 'test-only'), ($2, 'alice', 'test-only')")
        .bind(recipient_id)
        .bind(sender_id)
        .execute(&pool)
        .await
        .unwrap();
    let persisted_subscribe = "<presence xmlns='jabber:client' from='alice@remote.test' to='bob@local.test' type='subscribe'><status>hello</status></presence>";
    db::add_federated_presence_pending_with_stanza(
        &pool,
        recipient_id,
        "alice@remote.test",
        Some(persisted_subscribe),
    )
    .await
    .unwrap();
    let oversized_subscription = "x".repeat(65_537);
    assert!(db::add_federated_presence_pending_with_stanza(
        &pool,
        recipient_id,
        "mallory@remote.test",
        Some(&oversized_subscription),
    )
    .await
    .is_err());
    let pending_rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM federated_presence_pending")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(pending_rows, 1);
    let retained_subscription: String = sqlx::query_scalar(
        "SELECT stanza FROM federated_presence_pending WHERE recipient_id=$1 AND from_jid='alice@remote.test'",
    )
    .bind(recipient_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(retained_subscription, persisted_subscribe);
    db::archive_message(
        &pool,
        uuid::Uuid::new_v4(),
        recipient_id,
        "alice@remote.test/Phone",
        "<message from='alice@remote.test/Phone' to='bob@local.test' id='remote-original'><body>recipient original</body></message>",
        false,
        Some("remote-original"),
    )
    .await
    .unwrap();
    db::archive_message(
        &pool,
        uuid::Uuid::new_v4(),
        sender_id,
        "carol@remote.test/Laptop",
        "<message from='alice@local.test/Phone' to='carol@remote.test/Laptop' id='outbound-original'><body>sender original</body></message>",
        false,
        Some("outbound-original"),
    )
    .await
    .unwrap();

    use crate::xmpp::protocol::messaging::{undelivered_disposition, UndeliveredDisposition};
    assert_eq!(
        undelivered_disposition("headline", true, true),
        UndeliveredDisposition::Drop
    );
    assert_eq!(
        undelivered_disposition("chat", false, true),
        UndeliveredDisposition::Drop
    );
    assert_eq!(
        undelivered_disposition("normal", true, false),
        UndeliveredDisposition::RejectWait
    );
    assert_eq!(
        undelivered_disposition("groupchat", true, true),
        UndeliveredDisposition::RejectCancel
    );

    sqlx::query("INSERT INTO offline_messages(id, recipient_id, sender_jid, stanza, encrypted) VALUES($1, $2, 'seed@remote.test', '<message/>', FALSE)")
        .bind(uuid::Uuid::new_v4())
        .bind(recipient_id)
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(
        db::store_offline(
            &pool,
            recipient_id,
            "alice@remote.test/Phone",
            "<message><retract xmlns='urn:xmpp:message-retract:1' id='remote-original'/></message>",
            false,
            db::OfflineStorePolicy {
                max_messages: 1,
                max_bytes: 1_000_000,
                ttl_days: 30,
                mam_backed: false,
            },
        )
        .await
        .unwrap(),
        db::OfflineStoreOutcome::QuotaExceeded
    );
    assert!(db::enqueue_s2s_outbox(
        &pool,
        "remote.test",
        "<message from='alice@local.test' to='carol@remote.test'/>",
        Some("alice@local.test/Phone"),
        300,
        0,
        1_000_000,
        100,
    )
    .await
    .is_err());
    let rejected_archive_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM message_archive")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(rejected_archive_count, 2);
    let recipient_original: String = sqlx::query_scalar(
        "SELECT stanza FROM message_archive WHERE owner_id=$1 AND stanza_id='remote-original'",
    )
    .bind(recipient_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(recipient_original.contains("recipient original"));
    let sender_original: String = sqlx::query_scalar(
        "SELECT stanza FROM message_archive WHERE owner_id=$1 AND stanza_id='outbound-original'",
    )
    .bind(sender_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(sender_original.contains("sender original"));
    let rejected_offline_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM offline_messages")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(rejected_offline_count, 1);

    let online_retraction = Document::parse(
        "<message id='online-retraction'><retract xmlns='urn:xmpp:message-retract:1' id='remote-original'/></message>",
    )
    .unwrap();
    let online_stable_id = uuid::Uuid::new_v4();
    let retraction_service = RetractionService::new(
        crate::db::retractions::PostgresRetractionRepository::new(pool.clone()),
        crate::abuse::test_personal_retraction_content_keyring(),
        "local.test",
    );
    let online_action = "<message from='alice@remote.test/Phone' to='bob@local.test' id='online-retraction'><retract xmlns='urn:xmpp:message-retract:1' id='remote-original'/></message>";
    let online_command = crate::xmpp::protocol::retractions::personal_retraction_command(
        online_retraction.root_element(),
    )
    .unwrap()
    .unwrap();
    let online_writes = [ArchiveWrite {
        id: online_stable_id,
        owner_id: recipient_id,
        peer_jid: "alice@remote.test/Phone",
        stanza: online_action,
        encrypted: false,
        stanza_id: Some("online-retraction"),
    }];
    let online_delivery = DeliveryProjection {
        id: online_stable_id,
        recipient_id,
        local_actor_id: None,
        sender_jid: "alice@remote.test/Phone",
        stanza: online_action,
        encrypted: false,
        max_messages: 100,
        max_bytes: 1_000_000,
        ttl_days: 30,
        mam_backed: true,
    };
    assert_eq!(
        retraction_service
            .apply_with_delivery(
                &[OwnerProjection {
                    owner_id: recipient_id,
                    peer_jid: "alice@remote.test/Phone",
                }],
                "alice@remote.test/Phone",
                &RetractionCommand {
                    target_id: &online_command.target_id,
                    action_id: &online_command.action_id,
                    semantic_payload: &online_command.semantic_payload,
                },
                &online_writes,
                Some(&online_delivery),
                None,
            )
            .await
            .unwrap(),
        RetractionOutcome::Applied { tombstones: 1 }
    );
    let tombstone: String = sqlx::query_scalar(
        "SELECT stanza FROM message_archive WHERE owner_id=$1 AND stanza_id='remote-original'",
    )
    .bind(recipient_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(tombstone.contains("urn:xmpp:message-retract:1"));
    assert!(!tombstone.contains("recipient original"));

    db::archive_message(
        &pool,
        uuid::Uuid::new_v4(),
        recipient_id,
        "alice@remote.test/Phone",
        "<message from='alice@remote.test/Phone' to='bob@local.test' id='offline-original'><body>offline original</body></message>",
        false,
        Some("offline-original"),
    )
    .await
    .unwrap();
    sqlx::query("DELETE FROM offline_messages")
        .execute(&pool)
        .await
        .unwrap();
    let offline_retraction_xml = "<message from='alice@remote.test/Phone' to='bob@local.test' id='offline-retraction'><retract xmlns='urn:xmpp:message-retract:1' id='offline-original'/></message>";
    let offline_retraction = Document::parse(offline_retraction_xml).unwrap();
    let offline_command = crate::xmpp::protocol::retractions::personal_retraction_command(
        offline_retraction.root_element(),
    )
    .unwrap()
    .unwrap();
    let offline_delivery_id = uuid::Uuid::new_v4();
    let offline_writes = [ArchiveWrite {
        id: uuid::Uuid::new_v4(),
        owner_id: recipient_id,
        peer_jid: "alice@remote.test/Phone",
        stanza: offline_retraction_xml,
        encrypted: false,
        stanza_id: Some("offline-retraction"),
    }];
    let offline_delivery = DeliveryProjection {
        id: offline_delivery_id,
        recipient_id,
        local_actor_id: None,
        sender_jid: "alice@remote.test/Phone",
        stanza: offline_retraction_xml,
        encrypted: false,
        max_messages: 100,
        max_bytes: 1_000_000,
        ttl_days: 30,
        mam_backed: true,
    };
    assert_eq!(
        retraction_service
            .apply_with_delivery(
                &[OwnerProjection {
                    owner_id: recipient_id,
                    peer_jid: "alice@remote.test/Phone",
                }],
                "alice@remote.test/Phone",
                &RetractionCommand {
                    target_id: &offline_command.target_id,
                    action_id: &offline_command.action_id,
                    semantic_payload: &offline_command.semantic_payload,
                },
                &offline_writes,
                Some(&offline_delivery),
                None,
            )
            .await
            .unwrap(),
        RetractionOutcome::Applied { tombstones: 1 }
    );
    let offline_tombstone: String = sqlx::query_scalar(
        "SELECT stanza FROM message_archive WHERE owner_id=$1 AND stanza_id='offline-original'",
    )
    .bind(recipient_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(offline_tombstone.contains("urn:xmpp:message-retract:1"));
    let accepted_offline_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM offline_messages")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(accepted_offline_count, 1);

    db::enqueue_s2s_outbox(
        &pool,
        "remote.test",
        "<message from='alice@local.test' to='carol@remote.test'><retract xmlns='urn:xmpp:message-retract:1' id='outbound-original'/></message>",
        Some("alice@local.test/Phone"),
        300,
        100,
        1_000_000,
        100,
    )
    .await
    .unwrap();
    let outbound_retraction = Document::parse(
        "<message id='outbound-retraction'><retract xmlns='urn:xmpp:message-retract:1' id='outbound-original'/></message>",
    )
    .unwrap();
    let outbound_action = "<message from='alice@local.test/Phone' to='carol@remote.test/Laptop' id='outbound-retraction'><retract xmlns='urn:xmpp:message-retract:1' id='outbound-original'/></message>";
    let outbound_action_write = [ArchiveWrite {
        id: uuid::Uuid::new_v4(),
        owner_id: sender_id,
        peer_jid: "carol@remote.test/Laptop",
        stanza: outbound_action,
        encrypted: false,
        stanza_id: Some("outbound-retraction"),
    }];
    let outbound_command = crate::xmpp::protocol::retractions::personal_retraction_command(
        outbound_retraction.root_element(),
    )
    .unwrap()
    .unwrap();
    assert_eq!(
        retraction_service
            .apply(
                &[OwnerProjection {
                    owner_id: sender_id,
                    peer_jid: "carol@remote.test/Laptop",
                }],
                "alice@local.test/Phone",
                &RetractionCommand {
                    target_id: &outbound_command.target_id,
                    action_id: &outbound_command.action_id,
                    semantic_payload: &outbound_command.semantic_payload,
                },
                &outbound_action_write,
                None,
            )
            .await
            .unwrap(),
        RetractionOutcome::Applied { tombstones: 1 }
    );
    let rollback_original_id = uuid::Uuid::new_v4();
    db::archive_message(
        &pool,
        rollback_original_id,
        sender_id,
        "carol@remote.test/Laptop",
        "<message from='alice@local.test/Phone' to='carol@remote.test/Laptop' id='rollback-original'><body>must survive rollback</body></message>",
        false,
        Some("rollback-original"),
    )
    .await
    .unwrap();
    let rollback_retraction = Document::parse(
        "<message id='rollback-action'><retract xmlns='urn:xmpp:message-retract:1' id='rollback-original'/></message>",
    )
    .unwrap();
    let conflicting_action = [ArchiveWrite {
        id: rollback_original_id,
        owner_id: sender_id,
        peer_jid: "carol@remote.test/Laptop",
        stanza: "<message from='alice@local.test/Phone' to='carol@remote.test/Laptop' id='rollback-action'><retract xmlns='urn:xmpp:message-retract:1' id='rollback-original'/></message>",
        encrypted: false,
        stanza_id: Some("rollback-action"),
    }];
    let rollback_command = crate::xmpp::protocol::retractions::personal_retraction_command(
        rollback_retraction.root_element(),
    )
    .unwrap()
    .unwrap();
    assert!(retraction_service
        .apply(
            &[OwnerProjection {
                owner_id: sender_id,
                peer_jid: "carol@remote.test/Laptop",
            }],
            "alice@local.test/Phone",
            &RetractionCommand {
                target_id: &rollback_command.target_id,
                action_id: &rollback_command.action_id,
                semantic_payload: &rollback_command.semantic_payload,
            },
            &conflicting_action,
            None,
        )
        .await
        .is_err());
    let rollback_original: String =
        sqlx::query_scalar("SELECT stanza FROM message_archive WHERE id=$1 AND owner_id=$2")
            .bind(rollback_original_id)
            .bind(sender_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(rollback_original.contains("must survive rollback"));
    let outbound_tombstone: String = sqlx::query_scalar(
        "SELECT stanza FROM message_archive WHERE owner_id=$1 AND stanza_id='outbound-original'",
    )
    .bind(sender_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(outbound_tombstone.contains("urn:xmpp:message-retract:1"));
    let outbox_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM s2s_outbox")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(outbox_count, 1);

    pool.close().await;
    sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
        .execute(&admin)
        .await
        .unwrap();
    admin.close().await;
}

#[test]
fn persisted_federated_subscription_keeps_extensions_and_uses_bare_jids() {
    let raw = "<presence xmlns='jabber:server' type='subscribe' from='Alice@Remote.Test/Phone' to='Bob@Local.Test/Desktop'><status xml:lang='en'>Please add me</status><nick xmlns='http://jabber.org/protocol/nick'>Alice</nick></presence>";
    let persisted = canonical_subscription_stanza(raw, "alice@remote.test", "bob@local.test");
    let document = Document::parse(&persisted).unwrap();
    let root = document.root_element();
    assert_eq!(root.attribute("from"), Some("alice@remote.test"));
    assert_eq!(root.attribute("to"), Some("bob@local.test"));
    assert_eq!(root.tag_name().namespace(), Some("jabber:client"));
    assert!(!persisted.contains("jabber:server"));
    assert!(root.children().any(|child| {
        child.is_element()
            && child.tag_name().name() == "status"
            && child.text() == Some("Please add me")
    }));
    assert!(root.children().any(|child| {
        child.is_element()
            && child.tag_name().name() == "nick"
            && child.tag_name().namespace() == Some("http://jabber.org/protocol/nick")
            && child.text() == Some("Alice")
    }));
}

#[test]
fn authenticated_sender_cannot_escape_the_peer_domain() {
    assert!(authenticated_s2s_sender(
        "alice@remote.example/phone",
        "remote.example"
    ));
    assert!(!authenticated_s2s_sender(
        "pubsub.remote.example",
        "remote.example"
    ));
    assert!(authenticated_s2s_sender(
        "pubsub.remote.example",
        "pubsub.remote.example"
    ));
    assert!(!authenticated_s2s_sender(
        "room@conference.remote.example/Alice",
        "remote.example"
    ));
    assert!(authenticated_s2s_sender(
        "room@conference.remote.example/Alice",
        "conference.remote.example"
    ));
    assert!(!authenticated_s2s_sender(
        "alice@evil.example/phone",
        "remote.example"
    ));
    assert!(!authenticated_s2s_sender(
        "alice@conference.remote.example.evil/phone",
        "remote.example"
    ));
}

#[test]
fn federated_pep_subscription_branch_has_no_split_authority_reads() {
    let source = include_str!("inbound.rs");
    let branch = source
        .split_once("if !is_xep0357_notification_publish(child) =>")
        .expect("federated PEP set branch must remain identifiable")
        .1
        .split_once("(\"query\", \"http://jabber.org/protocol/disco#info\", \"get\")")
        .expect("federated PEP set branch must end before disco handling")
        .0;
    for forbidden in [
        "db::pep_node(",
        "pep_access_allowed(",
        "subscribe_pep_node_with_outbox(",
        "db::unsubscribe_pep_node(",
    ] {
        assert!(
            !branch.contains(forbidden),
            "federated PEP policy escaped the service transaction: {forbidden}"
        );
    }
    assert!(branch.contains(".subscribe_pep_node("));
    assert!(branch.contains(".unsubscribe_pep_node("));
    assert!(branch.contains("PepSubscriptionActor"));
}

#[test]
fn remote_muc_private_messages_are_not_carbon_copied() {
    let private = Document::parse(
        "<message xmlns='jabber:client' type='chat' from='room@conference.remote.example/nick' to='alice@example.test/phone'><body>private</body></message>",
    )
    .unwrap();
    assert!(is_remote_muc_private_message(
        private.root_element(),
        "room@conference.remote.example/nick",
        "conference.remote.example"
    ));
    let direct = Document::parse(
        "<message xmlns='jabber:client' type='chat' from='bob@remote.example/phone' to='alice@example.test/phone'><body>direct</body></message>",
    )
    .unwrap();
    assert!(!is_remote_muc_private_message(
        direct.root_element(),
        "bob@remote.example/phone",
        "remote.example"
    ));
}
