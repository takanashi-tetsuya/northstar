use super::*;

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
