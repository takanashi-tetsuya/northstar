use super::dispatch::{unbound_mix_dispatch, MixDispatch};
use super::*;

#[test]
fn unbound_mix_retraction_does_not_fall_through_to_personal_delivery() {
    let action = "<retract xmlns='urn:xmpp:mix:misc:0' id='00000000-0000-4000-8000-000000000001'/>";
    for (from, to, payload, mix_command, suppressed) in [
        (
            "alice@remote.test/phone",
            "bob@local.test",
            action,
            false,
            true,
        ),
        (
            "room@mix.other.test/actor",
            "bob@local.test",
            action,
            false,
            true,
        ),
        (
            "alice@remote.test/phone",
            "bob@local.test",
            "<body>ordinary</body>",
            false,
            false,
        ),
        (
            "alice@remote.test/phone",
            "room@mix.local.test",
            action,
            true,
            false,
        ),
    ] {
        let stanza = format!("<message xmlns='jabber:client' type='groupchat' id='action' from='{from}' to='{to}'>{payload}</message>");
        let document = Document::parse(&stanza).unwrap();
        let dispatch = unbound_mix_dispatch(document.root_element(), "remote.test", "local.test");
        assert_eq!(dispatch.is_none(), mix_command);
        assert_eq!(
            matches!(dispatch, Some(MixDispatch::Handled(None))),
            suppressed
        );
        if !mix_command && !suppressed {
            assert!(matches!(dispatch, Some(MixDispatch::NotMix)));
        }
    }
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

#[test]
fn s2s_stream_targets_exclude_upload_but_not_other_local_services() {
    for domain in [
        "EXAMPLE.TEST.",
        "pubsub.example.test",
        "conference.example.test",
        "mix.example.test",
    ] {
        assert!(hosted_s2s_domain("example.test", domain));
    }
    for domain in ["upload.example.test", "remote.example.test", "bad domain"] {
        assert!(!hosted_s2s_domain("example.test", domain));
    }
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
fn authoritative_dialback_callbacks_are_not_misclassified_as_downgrades() {
    assert!(is_certificate_downgrade("result", true));
    assert!(!is_certificate_downgrade("verify", true));
    assert!(!is_certificate_downgrade("result", false));
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
    let error_bytes = crate::outbound::serialize_for_peer(&error, None)
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
