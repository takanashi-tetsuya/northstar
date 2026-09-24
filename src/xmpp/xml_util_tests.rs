use super::{
    add_delay_from, add_muc_user_status, add_stanza_id, blocked_stanza_error, carbon_message,
    child_text, failure, has_no_store_hint, iq_error, iq_error_to, iq_result, iq_result_to,
    is_abuse_rated_message, mam_muc_stanza, mam_storage_eligible, message_storage_policy,
    muc_occupant_id, muc_occupant_key, muc_presence_stanza_with_status, offline_storage_permitted,
    prepare_muc_nick, reflect_iq_error_response, set_from, set_muc_occupant_id, set_to,
    should_carbon, stanza_error, stanza_error_type, stream_error, stream_id,
    strip_stanza_ids_by_domain, strip_untrusted_direct_delays, valid_bare_jid, valid_language_tag,
    valid_muc_nick, validate_delivery_receipts, validate_modern_message_payloads,
    validate_no_client_carbon, validate_routed_message, BASE64, MAX_OMEMO2_PAYLOAD_BYTES,
};
use base64::Engine;
use roxmltree::Document;

fn transient(xml: &str) -> bool {
    let document = Document::parse(xml).expect("test message must be valid XML");
    has_no_store_hint(document.root_element())
}

#[test]
fn addressed_iq_builder_preserves_routing_and_rejects_malformed_payloads() {
    let valid = iq_result_to(
        "req-1",
        "room@example.test",
        "alice@example.test",
        "<query/>",
    );
    let document = Document::parse(&valid).unwrap();
    let root = document.root_element();
    assert_eq!(root.attribute("type"), Some("result"));
    assert_eq!(root.attribute("from"), Some("room@example.test"));
    assert_eq!(root.attribute("to"), Some("alice@example.test"));
    assert_eq!(root.attribute("id"), Some("req-1"));
    assert_eq!(root.children().filter(|node| node.is_element()).count(), 1);

    let rejected = iq_result_to("req-2", "room@example.test", "alice@example.test", "<x>");
    let document = Document::parse(&rejected).unwrap();
    let root = document.root_element();
    assert_eq!(root.attribute("type"), Some("error"));
    assert!(document.descendants().any(|node| {
        node.is_element()
            && node.tag_name().name() == "internal-server-error"
            && node.tag_name().namespace() == Some("urn:ietf:params:xml:ns:xmpp-stanzas")
    }));

    let error = iq_error_to(
        "req-3",
        "room@example.test",
        "alice@example.test",
        "auth",
        "forbidden",
    );
    let document = Document::parse(&error).unwrap();
    assert_eq!(document.root_element().attribute("type"), Some("error"));
}

#[test]
fn disabled_message_extensions_fail_closed_at_the_shared_ingress_boundary() {
    let disabled = crate::xmpp::extensions::ExtensionRuntime::resolve(
        crate::xmpp::extensions::ExtensionSwitches {
            xep_0016: true,
            xep_0045: true,
            xep_0059: true,
            xep_0060: true,
            xep_0085: false,
            xep_0092: true,
            xep_0115: true,
            xep_0184: false,
            xep_0191: true,
            xep_0198: true,
            xep_0199: true,
            xep_0202: true,
            xep_0215: true,
            xep_0280: true,
            xep_0313: true,
            xep_0352: true,
            xep_0357: true,
            xep_0359: false,
            xep_0363: true,
            xep_0308: false,
            xep_0333: false,
            xep_0380: false,
            xep_0444: false,
            xep_0461: false,
        },
    );
    for xml in [
        "<message><active xmlns='http://jabber.org/protocol/chatstates'/></message>",
        "<message id='m1'><request xmlns='urn:xmpp:receipts'/></message>",
        "<message><body>updated</body><replace xmlns='urn:xmpp:message-correct:0' id='m1'/></message>",
        "<message id='m2'><markable xmlns='urn:xmpp:chat-markers:0'/></message>",
        "<message><encryption xmlns='urn:xmpp:eme:0' namespace='urn:xmpp:omemo:2'/></message>",
        "<message><reactions xmlns='urn:xmpp:reactions:0' id='m1'><reaction>yes</reaction></reactions></message>",
        "<message><origin-id xmlns='urn:xmpp:sid:0' id='m1'/></message>",
        "<message><reply xmlns='urn:xmpp:reply:0' to='alice@example.test' id='m1'/></message>",
    ] {
        let document = Document::parse(xml).unwrap();
        assert_eq!(
            validate_routed_message(document.root_element(), &disabled),
            Err("feature-not-implemented"),
            "{xml}"
        );
    }
}

#[test]
fn enabled_message_extensions_delegate_wire_validation_to_their_crates() {
    let enabled = crate::xmpp::extensions::ExtensionRuntime::resolve(
        crate::xmpp::extensions::ExtensionSwitches::default(),
    );
    let malformed = Document::parse(
        "<message><reply xmlns='urn:xmpp:reply:0' to='not a jid' id='m1'/></message>",
    )
    .unwrap();
    assert_eq!(
        validate_routed_message(malformed.root_element(), &enabled),
        Err("bad-request")
    );
}

#[test]
fn stream_identifiers_are_csprng_unique() {
    let first = stream_id();
    let second = stream_id();
    assert_ne!(first, second);
    assert_ne!(first, 0);
    assert_ne!(second, 0);
}

#[test]
fn common_error_builders_escape_values_and_whitelist_condition_elements() {
    let iq = iq_error("id' /><injected/>", "bad-request/><injected");
    let document = Document::parse(&iq).unwrap();
    let root = document.root_element();
    assert_eq!(root.attribute("id"), Some("id' /><injected/>"));
    assert_eq!(
        root.descendants()
            .filter(|node| node.is_element() && node.tag_name().name() == "injected")
            .count(),
        0
    );
    assert!(root.descendants().any(|node| {
        node.is_element()
            && node.tag_name().name() == "undefined-condition"
            && node.tag_name().namespace() == Some("urn:ietf:params:xml:ns:xmpp-stanzas")
    }));

    let stream = stream_error("policy-violation/><injected");
    let document = Document::parse(&stream).unwrap();
    assert!(document
        .descendants()
        .any(|node| node.is_element() && node.tag_name().name() == "undefined-condition"));

    let sasl = failure(
        "urn:ietf:params:xml:ns:xmpp-sasl' injected='true",
        "not-authorized/><injected",
    );
    let document = Document::parse(&sasl).unwrap();
    let root = document.root_element();
    assert_eq!(
        root.attribute("xmlns"),
        // Namespace declarations are not ordinary attributes in
        // roxmltree; lookup proves the escaped runtime URI stayed one
        // namespace value rather than becoming markup.
        None
    );
    assert_eq!(
        root.lookup_namespace_uri(None),
        Some("urn:ietf:params:xml:ns:xmpp-sasl' injected='true")
    );
    assert!(root
        .descendants()
        .any(|node| { node.is_element() && node.tag_name().name() == "temporary-auth-failure" }));
}

#[test]
fn iq_result_raw_payload_crosses_the_validated_fragment_boundary() {
    let valid = iq_result(
        "result-1",
        "<query xmlns='urn:example:query'><value>safe</value></query>",
    );
    let document = Document::parse(&valid).unwrap();
    assert_eq!(document.root_element().attribute("type"), Some("result"));
    assert!(valid.contains("urn:example:query"));

    let rejected = iq_result("result-2", "</iq><injected/>");
    let document = Document::parse(&rejected).unwrap();
    let root = document.root_element();
    assert_eq!(root.attribute("type"), Some("error"));
    assert!(root
        .descendants()
        .any(|node| { node.is_element() && node.tag_name().name() == "internal-server-error" }));
    assert!(!rejected.contains("<injected"));
}

#[test]
fn child_text_respects_protocol_namespaces() {
    let document = Document::parse(
        "<presence><priority xmlns='urn:evil'>127</priority><priority xmlns='jabber:client'>5</priority></presence>",
    )
    .unwrap();
    assert_eq!(child_text(document.root_element(), "priority"), Some("5"));

    let document = Document::parse(
        "<field xmlns='jabber:x:data'><value xmlns='urn:evil'>bad</value><value>good</value></field>",
    )
    .unwrap();
    assert_eq!(child_text(document.root_element(), "value"), Some("good"));
}

#[test]
fn standalone_chat_signals_are_transient() {
    assert!(transient(
        "<message><composing xmlns='http://jabber.org/protocol/chatstates'/></message>"
    ));
    assert!(transient(
        "<message><displayed xmlns='urn:xmpp:chat-markers:0' id='m1'/></message>"
    ));
    assert!(transient(
        "<message><thread>chat-1</thread><composing xmlns='http://jabber.org/protocol/chatstates'/><origin-id xmlns='urn:xmpp:sid:0' id='state-1'/></message>"
    ));
}

#[test]
fn offline_delay_is_server_asserted_and_utc() {
    let stamp = chrono::DateTime::parse_from_rfc3339("2026-08-25T12:34:56Z")
        .unwrap()
        .with_timezone(&chrono::Utc);
    let delayed = add_delay_from(
        "<message><body>queued</body></message>",
        stamp,
        Some("example.test"),
    );
    assert!(delayed.contains(
        "<delay xmlns='urn:xmpp:delay' from='example.test' stamp='2026-08-25T12:34:56Z'/>"
    ));

    let forged = "<message><delay xmlns='urn:xmpp:delay' from='mallory.test' stamp='1999-01-01T00:00:00Z'/><body>queued</body></message>";
    let delayed = add_delay_from(forged, stamp, Some("example.test"));
    assert_eq!(delayed.matches("urn:xmpp:delay").count(), 1);
    assert!(!delayed.contains("mallory.test"));
}

#[test]
fn direct_delay_requires_the_current_transport_authority() {
    let stanza = "<message><body>x</body><delay xmlns='urn:xmpp:delay' from='remote.test' stamp='2024-01-01T00:00:00Z'/><forwarded xmlns='urn:xmpp:forward:0'><delay xmlns='urn:xmpp:delay' from='archive.remote.test' stamp='2023-01-01T00:00:00Z'/></forwarded></message>";
    let c2s = strip_untrusted_direct_delays(stanza, None);
    assert!(!c2s.contains("from='remote.test'"));
    assert!(c2s.contains("from='archive.remote.test'"));

    let s2s = strip_untrusted_direct_delays(stanza, Some("REMOTE.TEST"));
    assert!(s2s.contains("from='remote.test'"));
    assert!(s2s.contains("from='archive.remote.test'"));

    let forged = "<message><delay xmlns='urn:xmpp:delay' from='local.test' stamp='2024-01-01T00:00:00Z'/><delay xmlns='urn:xmpp:delay' from='remote.test' stamp='not-a-date'/></message>";
    let sanitized = strip_untrusted_direct_delays(forged, Some("remote.test"));
    assert!(!sanitized.contains("<delay"));

    let reason = "<message><delay xmlns='urn:xmpp:delay' stamp='2024-01-01T00:00:00.123Z'>Offline Storage</delay></message>";
    assert_eq!(
        strip_untrusted_direct_delays(reason, Some("remote.test")),
        reason
    );

    let offset = "<message><delay xmlns='urn:xmpp:delay' from='remote.test' stamp='2024-01-01T01:00:00+01:00'/></message>";
    assert!(!strip_untrusted_direct_delays(offset, Some("remote.test")).contains("<delay"));

    let duplicate = "<message><delay xmlns='urn:xmpp:delay' from='remote.test' stamp='2024-01-01T00:00:00Z'/><delay xmlns='urn:xmpp:delay' from='remote.test' stamp='2024-01-02T00:00:00Z'/></message>";
    assert!(!strip_untrusted_direct_delays(duplicate, Some("remote.test")).contains("<delay"));
}

#[test]
fn root_address_rewriting_ignores_markup_like_attribute_values() {
    let raw = "<message xmlns = \"jabber:client\" note=\"from='mallory' and >\" from = \"mallory@example.test/phone\"><body>to='victim'</body></message>";
    let rewritten = set_to(
        &set_from(raw, "alice@example.test/Phone"),
        "bob@example.test",
    );
    let document = Document::parse(&rewritten).unwrap();
    let root = document.root_element();
    assert_eq!(root.attribute("from"), Some("alice@example.test/Phone"));
    assert_eq!(root.attribute("to"), Some("bob@example.test"));
    assert_eq!(root.attribute("note"), Some("from='mallory' and >"));
    assert_eq!(
        root.children()
            .find(|child| child.is_element())
            .and_then(|body| body.text()),
        Some("to='victim'")
    );
    assert_eq!(rewritten.matches(" from=").count(), 1);
    assert_eq!(rewritten.matches(" to=").count(), 1);
}

#[test]
fn source_rewriting_adds_the_inherited_client_namespace_once() {
    let rewritten = set_from("<message to='bob@example.test'/>", "alice@example.test/a");
    let document = Document::parse(&rewritten).unwrap();
    let root = document.root_element();
    assert_eq!(root.tag_name().namespace(), Some("jabber:client"));
    assert_eq!(rewritten.matches("xmlns='jabber:client'").count(), 1);
    assert!(rewritten.ends_with("/>"));
}

#[test]
fn authoritative_extensions_support_prefixed_and_self_closing_roots() {
    let id = uuid::Uuid::nil();
    let annotated = add_stanza_id(
        "<c:message xmlns:c='jabber:client' note='a>b'/>",
        "example.test",
        id,
    );
    let document = Document::parse(&annotated).unwrap();
    let root = document.root_element();
    assert_eq!(root.tag_name().name(), "message");
    assert_eq!(root.attribute("note"), Some("a>b"));
    assert!(root.children().any(|child| {
        child.is_element()
            && child.tag_name().name() == "stanza-id"
            && child.tag_name().namespace() == Some("urn:xmpp:sid:0")
    }));

    let delayed = add_delay_from(
        "<c:message xmlns:c='jabber:client'><c:body>queued</c:body></c:message>",
        chrono::DateTime::parse_from_rfc3339("2026-08-25T12:34:56Z")
            .unwrap()
            .with_timezone(&chrono::Utc),
        Some("example.test"),
    );
    let document = Document::parse(&delayed).unwrap();
    assert!(document.root_element().children().any(|child| {
        child.is_element()
            && child.tag_name().name() == "delay"
            && child.tag_name().namespace() == Some("urn:xmpp:delay")
    }));
}

#[test]
fn stanza_errors_reflect_payload_namespaces_and_swap_addresses() {
    let input = "<c:message xmlns:c='jabber:client' xmlns:e='urn:example' type='chat' id='m1' from='alice@example.test/A' to='bob@example.test'><c:body>hello</c:body><e:payload value='1'/></c:message>";
    let document = Document::parse(input).unwrap();
    let error = stanza_error(document.root_element(), "cancel", "service-unavailable");
    let document = Document::parse(&error).unwrap();
    let root = document.root_element();
    assert_eq!(root.attribute("type"), Some("error"));
    assert_eq!(root.attribute("from"), Some("bob@example.test"));
    assert_eq!(root.attribute("to"), Some("alice@example.test/A"));
    assert!(root.children().any(|child| {
        child.is_element()
            && child.tag_name().name() == "payload"
            && child.tag_name().namespace() == Some("urn:example")
    }));
    let error_node = root
        .children()
        .find(|child| child.is_element() && child.tag_name().name() == "error")
        .unwrap();
    assert_eq!(error_node.tag_name().namespace(), Some("jabber:client"));
    assert_eq!(error_node.attribute("type"), Some("cancel"));

    let blocked = blocked_stanza_error(document.root_element());
    let document = Document::parse(&blocked).unwrap();
    assert_eq!(
        document
            .descendants()
            .filter(|node| node.is_element() && node.tag_name().name() == "error")
            .count(),
        1
    );
}

#[test]
fn iq_errors_reflect_the_request_and_use_rfc_error_types() {
    let request = Document::parse(
        "<iq xmlns='jabber:client' type='get' id='q1' from='alice@example.test/A' to='pubsub.example.test'><query xmlns='urn:example'/></iq>",
    )
    .unwrap();
    let reflected = reflect_iq_error_response(
        request.root_element(),
        "<iq xmlns='jabber:client' type='error' id='q1'><error type='wait'><resource-constraint xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/><retry xmlns='urn:example' seconds='3'/></error></iq>",
    )
    .unwrap();
    let document = Document::parse(&reflected).unwrap();
    let root = document.root_element();
    assert_eq!(root.attribute("type"), Some("error"));
    assert_eq!(root.attribute("from"), Some("pubsub.example.test"));
    assert_eq!(root.attribute("to"), Some("alice@example.test/A"));
    assert!(root.children().any(|child| {
        child.is_element()
            && child.tag_name().name() == "query"
            && child.tag_name().namespace() == Some("urn:example")
    }));
    assert!(root.descendants().any(|child| {
        child.is_element()
            && child.tag_name().name() == "retry"
            && child.tag_name().namespace() == Some("urn:example")
    }));
    assert_eq!(stanza_error_type("not-authorized"), "auth");
    assert_eq!(stanza_error_type("bad-request"), "modify");
    assert_eq!(stanza_error_type("remote-server-timeout"), "wait");
    assert_eq!(stanza_error_type("item-not-found"), "cancel");

    let implicit = Document::parse(
        "<iq xmlns='jabber:client' type='set' id='c1' from='alice@example.test/A'><enable xmlns='urn:xmpp:carbons:2' unexpected='true'/></iq>",
    )
    .unwrap();
    let addressed = reflect_iq_error_response(
        implicit.root_element(),
        "<iq xmlns='jabber:client' type='error' id='c1' from='alice@example.test' to='alice@example.test/A'><error type='modify'><bad-request xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></iq>",
    )
    .unwrap();
    let addressed = Document::parse(&addressed).unwrap();
    assert_eq!(
        addressed.root_element().attribute("from"),
        Some("alice@example.test")
    );
    assert_eq!(
        addressed.root_element().attribute("to"),
        Some("alice@example.test/A")
    );
}

#[test]
fn reflected_errors_never_echo_registration_or_form_secrets() {
    let request = Document::parse(
        "<iq xmlns='jabber:client' type='set' id='pw1' from='alice@example.test/A'><query xmlns='jabber:iq:register'><username>alice</username><password>new-secret</password><x xmlns='jabber:x:data' type='submit'><field var='urn:northstar:invite:token'><value>invite-secret</value></field></x></query></iq>",
    )
    .unwrap();
    let reflected = reflect_iq_error_response(
        request.root_element(),
        "<iq xmlns='jabber:client' type='error' id='pw1'><error type='modify'><not-acceptable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></iq>",
    )
    .unwrap();
    assert!(!reflected.contains("new-secret"));
    assert!(!reflected.contains("invite-secret"));
    let document = Document::parse(&reflected).unwrap();
    let password = document
        .descendants()
        .find(|node| {
            node.is_element()
                && node.tag_name().name() == "password"
                && node.tag_name().namespace() == Some("jabber:iq:register")
        })
        .unwrap();
    assert!(password.text().is_none());
}

#[test]
fn stanza_ids_are_well_formed_and_unique_per_canonical_issuer() {
    for valid in [
        "<message><origin-id xmlns='urn:xmpp:sid:0' id='client-1'/><stanza-id xmlns='urn:xmpp:sid:0' id='server-1' by='Alice@Example.test'/><stanza-id xmlns='urn:xmpp:sid:0' id='remote-1' by='remote.test'/><referenced-stanza xmlns='urn:xmpp:sid:0' id='older' by='room@conference.example.test'/></message>",
        "<message><stanza-id xmlns='urn:xmpp:sid:0' id='upper' by='alice@example.test/Phone'/><stanza-id xmlns='urn:xmpp:sid:0' id='lower' by='alice@example.test/phone'/></message>",
    ] {
        let document = Document::parse(valid).unwrap();
        assert_eq!(validate_modern_message_payloads(document.root_element()), Ok(()));
    }
    for invalid in [
        "<message><origin-id xmlns='urn:xmpp:sid:0'/></message>",
        "<message><stanza-id xmlns='urn:xmpp:sid:0' id='one'/></message>",
        "<message><stanza-id xmlns='urn:xmpp:sid:0' id='one' by='bad jid'/></message>",
        "<message><stanza-id xmlns='urn:xmpp:sid:0' id='one' by='Alice@Example.test'/><stanza-id xmlns='urn:xmpp:sid:0' id='two' by='alice@example.test'/></message>",
        "<message><origin-id xmlns='urn:xmpp:sid:0' id='one'>text</origin-id></message>",
        "<message><origin-id xmlns='urn:xmpp:sid:0' id='one'/><origin-id xmlns='urn:xmpp:sid:0' id='two'/></message>",
        "<message><referenced-stanza xmlns='urn:xmpp:sid:0' id='one'><child/></referenced-stanza></message>",
    ] {
        let document = Document::parse(invalid).unwrap();
        assert!(validate_modern_message_payloads(document.root_element()).is_err());
    }
}

#[test]
fn stickers_require_one_bounded_stateless_file_share() {
    for valid in [
        "<message><sticker xmlns='urn:xmpp:stickers:0'/><file-sharing xmlns='urn:xmpp:sfs:0'><file xmlns='urn:xmpp:file:metadata:0'><media-type>image/png</media-type><size>1</size></file><sources><url-data xmlns='http://jabber.org/protocol/url-data' target='https://files.example/sticker.png'/></sources></file-sharing></message>",
        "<message><sticker xmlns='urn:xmpp:stickers:0' pack='EpRv28DHHzFrE4zd+xaNpVb4' jid='pubsub.example.test' node='urn:xmpp:stickers:0'/><file-sharing xmlns='urn:xmpp:sfs:0'><file xmlns='urn:xmpp:file:metadata:0'><media-type>image/webp</media-type></file></file-sharing></message>",
    ] {
        let document = Document::parse(valid).unwrap();
        let root = document.root_element();
        assert_eq!(validate_modern_message_payloads(root), Ok(()), "{valid}");
        assert!(is_abuse_rated_message(root));
    }
    for (invalid, condition) in [
        ("<message><sticker xmlns='urn:xmpp:stickers:0'/></message>", "bad-request"),
        ("<message><sticker xmlns='urn:xmpp:stickers:0'>not empty</sticker><file-sharing xmlns='urn:xmpp:sfs:0'><file xmlns='urn:xmpp:file:metadata:0'/></file-sharing></message>", "bad-request"),
        ("<message><sticker xmlns='urn:xmpp:stickers:0' pack='p' node='n'/><file-sharing xmlns='urn:xmpp:sfs:0'><file xmlns='urn:xmpp:file:metadata:0'/></file-sharing></message>", "bad-request"),
        ("<message><sticker xmlns='urn:xmpp:stickers:0' pack='p' jid='bad jid' node='n'/><file-sharing xmlns='urn:xmpp:sfs:0'><file xmlns='urn:xmpp:file:metadata:0'/></file-sharing></message>", "jid-malformed"),
        ("<message><sticker xmlns='urn:xmpp:stickers:0'/><sticker xmlns='urn:xmpp:stickers:0'/><file-sharing xmlns='urn:xmpp:sfs:0'><file xmlns='urn:xmpp:file:metadata:0'/></file-sharing></message>", "bad-request"),
        ("<message><sticker xmlns='urn:xmpp:stickers:0'/><file-sharing xmlns='urn:xmpp:sfs:0'><file xmlns='urn:xmpp:file:metadata:0'/></file-sharing><file-sharing xmlns='urn:xmpp:sfs:0'><file xmlns='urn:xmpp:file:metadata:0'/></file-sharing></message>", "bad-request"),
    ] {
        let document = Document::parse(invalid).unwrap();
        assert_eq!(
            validate_modern_message_payloads(document.root_element()),
            Err(condition),
            "{invalid}"
        );
    }
}

#[test]
fn plaintext_trust_messages_are_bounded_and_unambiguous() {
    let valid = "<message type='chat'><store xmlns='urn:xmpp:hints'/><trust-message xmlns='urn:xmpp:tm:1' usage='urn:xmpp:atm:1' encryption='urn:xmpp:omemo:2'><key-owner jid='Alice@Example.test'><trust>aFABnX7Q/rbTgjBySYzrT2FsYCVYb49mbca5yB734KQ=</trust></key-owner><key-owner jid='bob@example.test'><distrust>tCP1CI3pqSTVGzFYFyPYUMfMZ9Ck/msmfD0wH/VtJBM=</distrust></key-owner></trust-message></message>";
    let document = Document::parse(valid).unwrap();
    assert_eq!(
        validate_modern_message_payloads(document.root_element()),
        Ok(())
    );
    assert!(is_abuse_rated_message(document.root_element()));

    for (invalid, condition) in [
        ("<message><trust-message xmlns='urn:xmpp:tm:1' encryption='urn:xmpp:omemo:2'><key-owner jid='alice@example.test'><trust>AQIDBA==</trust></key-owner></trust-message></message>", "bad-request"),
        ("<message><trust-message xmlns='urn:xmpp:tm:1' usage='urn:xmpp:atm:1' encryption='urn:xmpp:omemo:2'><key-owner jid='alice@example.test/phone'><trust>AQIDBA==</trust></key-owner></trust-message></message>", "jid-malformed"),
        ("<message><trust-message xmlns='urn:xmpp:tm:1' usage='urn:xmpp:atm:1' encryption='urn:xmpp:omemo:2'><key-owner jid='alice@example.test'/></trust-message></message>", "bad-request"),
        ("<message><trust-message xmlns='urn:xmpp:tm:1' usage='urn:xmpp:atm:1' encryption='urn:xmpp:omemo:2'><key-owner jid='alice@example.test'><trust>not base64!</trust></key-owner></trust-message></message>", "bad-request"),
        ("<message><trust-message xmlns='urn:xmpp:tm:1' usage='urn:xmpp:atm:1' encryption='urn:xmpp:omemo:2'><key-owner jid='Alice@Example.test'><trust>AQIDBA==</trust></key-owner><key-owner jid='alice@example.test'><distrust>BQYHCA==</distrust></key-owner></trust-message></message>", "bad-request"),
        ("<message><trust-message xmlns='urn:xmpp:tm:1' usage='urn:xmpp:atm:1' encryption='urn:xmpp:omemo:2'><key-owner jid='alice@example.test'><trust>AQIDBA==</trust><distrust>AQIDBA==</distrust></key-owner></trust-message></message>", "bad-request"),
        ("<message><trust-message xmlns='urn:xmpp:tm:1' usage='urn:xmpp:atm:1' encryption='urn:xmpp:omemo:2'><unknown/></trust-message></message>", "bad-request"),
        ("<message><trust-message xmlns='urn:xmpp:tm:1' usage='urn:xmpp:atm:1' encryption='urn:xmpp:omemo:2'><key-owner jid='alice@example.test'><trust>AQIDBA==</trust></key-owner></trust-message><trust-message xmlns='urn:xmpp:tm:1' usage='urn:xmpp:atm:1' encryption='urn:xmpp:omemo:2'><key-owner jid='bob@example.test'><trust>BQYHCA==</trust></key-owner></trust-message></message>", "bad-request"),
    ] {
        let document = Document::parse(invalid).unwrap();
        assert_eq!(
            validate_modern_message_payloads(document.root_element()),
            Err(condition),
            "{invalid}"
        );
    }
}

#[test]
fn language_tags_follow_bcp47_structure() {
    for valid in [
        "en",
        "en-US",
        "zh-Hant-TW",
        "de-CH-1901",
        "sl-rozaj-biske-1994",
        "en-a-myext-x-private",
        "x-klingon",
        "i-default",
    ] {
        assert!(valid_language_tag(valid), "rejected {valid}");
    }
    for invalid in [
        "",
        "e",
        "en--US",
        "en-abcdefghi",
        "en-a",
        "en-a-test-a-again",
        "de-1901-1901",
        "x",
        "en-工具",
    ] {
        assert!(!valid_language_tag(invalid), "accepted {invalid}");
    }
}

#[test]
fn error_messages_never_enter_mam_even_with_store_hint() {
    let document = Document::parse(
        "<message type='error'><store xmlns='urn:xmpp:hints'/><error type='cancel'/></message>",
    )
    .unwrap();
    assert!(!mam_storage_eligible(document.root_element()));
}

#[test]
fn processing_hints_on_error_messages_are_ignored() {
    let document = Document::parse(
        "<message type='error'><no-copy xmlns='urn:xmpp:hints'>malformed-but-ignored</no-copy><body>original IM payload</body><error type='cancel'/></message>",
    )
    .unwrap();
    let root = document.root_element();
    assert_eq!(
        message_storage_policy(root).unwrap(),
        super::MessageStoragePolicy {
            temporary: false,
            permanent: false,
        }
    );
    assert!(should_carbon(root));
    assert!(super::validate_processing_hints(root).is_ok());
}

#[test]
fn service_rewrites_preserve_processing_hints_verbatim() {
    let raw = "<message><x/><no-store xmlns='urn:xmpp:hints'/><future xmlns='urn:xmpp:hints' opaque='yes'/></message>";
    let document = Document::parse(raw).unwrap();
    assert_eq!(
        super::processing_hints_fragment(document.root_element(), raw),
        "<no-store xmlns='urn:xmpp:hints'/><future xmlns='urn:xmpp:hints' opaque='yes'/>"
    );
}

#[test]
fn jingle_message_signalling_is_abuse_rated() {
    let document = Document::parse(
        "<message type='chat'><ringing xmlns='urn:xmpp:jingle-message:0' id='call-1'/><store xmlns='urn:xmpp:hints'/></message>",
    )
    .unwrap();
    assert!(is_abuse_rated_message(document.root_element()));
}

#[test]
fn chat_signal_with_other_payload_remains_persistent() {
    assert!(!transient(
        "<message><active xmlns='http://jabber.org/protocol/chatstates'/><request xmlns='urn:xmpp:receipts'/></message>"
    ));
    assert!(!transient(
        "<message><body>hello</body><markable xmlns='urn:xmpp:chat-markers:0'/></message>"
    ));
}

#[test]
fn carbon_rules_select_only_im_traffic_and_honor_suppression() {
    for xml in [
        "<message type='chat'/>",
        // XEP-0334 limits <no-copy/> to messages addressed to a full
        // JID.  On an unaddressed stanza the server ignores the hint
        // instead of suppressing RFC 6121 / XEP-0280 delivery.
        "<message type='chat'><no-copy xmlns='urn:xmpp:hints'/></message>",
        "<message><body>hello</body></message>",
        "<message><received xmlns='urn:xmpp:receipts' id='m1'/></message>",
        "<message><displayed xmlns='urn:xmpp:chat-markers:0' id='m1'/></message>",
        "<message><x xmlns='jabber:x:conference' jid='room@conference.example.test'/></message>",
        "<message><x xmlns='http://jabber.org/protocol/muc#user'><invite to='bob@example.test'/></x></message>",
    ] {
        let document = Document::parse(xml).unwrap();
        assert!(should_carbon(document.root_element()), "{xml}");
    }
    for xml in [
        "<message/>",
        "<message type='groupchat'><body>room</body></message>",
        "<message type='headline'><body>news</body></message>",
        "<message type='chat'><private xmlns='urn:xmpp:carbons:2'/></message>",
        "<message><reactions xmlns='urn:xmpp:reactions:0' id='m1'><reaction>👍</reaction></reactions></message>",
        "<message><retract xmlns='urn:xmpp:message-retract:1' id='m1'/></message>",
        "<message><replace xmlns='urn:xmpp:message-correct:0' id='m1'/></message>",
        "<message><reply xmlns='urn:xmpp:reply:0' id='m1'/></message>",
    ] {
        let document = Document::parse(xml).unwrap();
        assert!(!should_carbon(document.root_element()), "{xml}");
    }
}

#[test]
fn carbon_rules_include_eligible_error_replies() {
    let eligible = Document::parse(
        "<message type='error'><body>original IM payload</body><error type='cancel'/></message>",
    )
    .unwrap();
    assert!(should_carbon(eligible.root_element()));
    let ineligible =
        Document::parse("<message type='error'><error type='cancel'/></message>").unwrap();
    assert!(!should_carbon(ineligible.root_element()));
}

#[test]
fn clients_cannot_assert_or_nest_server_carbon_wrappers() {
    for xml in [
        "<message><sent xmlns='urn:xmpp:carbons:2'><forwarded xmlns='urn:xmpp:forward:0'><message/></forwarded></sent></message>",
        "<message><x><received xmlns='urn:xmpp:carbons:2'/></x></message>",
    ] {
        let document = Document::parse(xml).unwrap();
        assert_eq!(
            validate_no_client_carbon(document.root_element()),
            Err("not-allowed")
        );
    }
}

#[test]
fn carbon_wrapper_preserves_type_and_server_addressing() {
    let wrapped = carbon_message(
        "received",
        "alice@example.test",
        "alice@example.test/tablet",
        "<message xmlns='jabber:client' from='bob@example.net/phone' to='alice@example.test' type='chat'><body>hi</body></message>",
    )
    .unwrap();
    let document = Document::parse(&wrapped).unwrap();
    let root = document.root_element();
    assert_eq!(root.attribute("type"), Some("chat"));
    assert_eq!(root.attribute("from"), Some("alice@example.test"));
    assert_eq!(root.attribute("to"), Some("alice@example.test/tablet"));
    assert_eq!(
        root.descendants()
            .filter(|node| node.is_element()
                && node.tag_name().name() == "forwarded"
                && node.tag_name().namespace() == Some("urn:xmpp:forward:0"))
            .count(),
        1
    );

    let forwarded_message = root
        .descendants()
        .find(|node| {
            node.is_element()
                && node.tag_name().name() == "forwarded"
                && node.tag_name().namespace() == Some("urn:xmpp:forward:0")
        })
        .unwrap()
        .children()
        .find(|node| node.is_element())
        .unwrap();
    assert_eq!(forwarded_message.tag_name().name(), "message");
    assert_eq!(
        forwarded_message.tag_name().namespace(),
        Some("jabber:client")
    );
    assert_eq!(
        forwarded_message
            .children()
            .find(|node| node.is_element() && node.tag_name().name() == "body")
            .unwrap()
            .tag_name()
            .namespace(),
        Some("jabber:client")
    );
}

#[test]
fn carbon_wrapper_rejects_dynamic_element_name_injection() {
    assert!(carbon_message(
        "received></received><injected",
        "alice@example.test",
        "alice@example.test/tablet",
        "<message xmlns='jabber:client' type='chat'><body>hi</body></message>",
    )
    .is_none());
}

#[test]
fn carbon_wrapper_suppresses_invalid_or_restricted_forwarded_fragments() {
    for forwarded in [
        "<message><body></message>",
        "<message><!-- restricted --><body>hi</body></message>",
        "<message><unbound:payload/></message>",
    ] {
        assert!(carbon_message(
            "received",
            "alice@example.test",
            "alice@example.test/tablet",
            forwarded,
        )
        .is_none());
    }
}

#[test]
fn carbon_wrapper_restores_the_inherited_client_namespace() {
    for forwarded in [
        "<message from='bob@example.net/phone' to='alice@example.test' type='chat'><body>stream inherited</body></message>",
        "<message xmlns='jabber:server' from='bob@example.net/phone' to='alice@example.test' type='chat'><body>federated</body></message>",
    ] {
        let wrapped = carbon_message(
            "received",
            "alice@example.test",
            "alice@example.test/tablet",
            forwarded,
        )
        .unwrap();
        let document = Document::parse(&wrapped).unwrap();
        let forwarded = document
            .descendants()
            .find(|node| {
                node.is_element()
                    && node.tag_name().name() == "forwarded"
                    && node.tag_name().namespace() == Some("urn:xmpp:forward:0")
            })
            .unwrap();
        let message = forwarded
            .children()
            .find(|node| node.is_element())
            .unwrap();
        assert_eq!(message.tag_name().namespace(), Some("jabber:client"));
        let body = message
            .children()
            .find(|node| node.is_element() && node.tag_name().name() == "body")
            .unwrap();
        assert_eq!(body.tag_name().namespace(), Some("jabber:client"));
    }
}

#[test]
fn muc_mam_payload_never_trusts_archived_identity_extensions() {
    let archived = "<message xmlns='jabber:client' from='room@conference.example.test/nick' to='alice@example.test/phone'><body>hi</body><x xmlns='http://jabber.org/protocol/muc#user'><item jid='forged@example.test'/></x><x xmlns='urn:northstar:muc:sender:0' jid='forged@example.test'/></message>";
    let hidden = mam_muc_stanza(archived, "real@example.test/phone", false);
    assert!(!hidden.contains(" to="));
    assert!(!hidden.contains("forged@example.test"));
    assert!(!hidden.contains("real@example.test"));

    let revealed = mam_muc_stanza(archived, "real@example.test/phone", true);
    assert!(!revealed.contains("forged@example.test"));
    assert!(revealed.contains("<item jid='real@example.test/phone'/>"));
    assert_eq!(
        revealed
            .matches("http://jabber.org/protocol/muc#user")
            .count(),
        1
    );
}

#[test]
fn explicit_no_store_always_wins() {
    assert!(transient(
        "<message><body>secret</body><no-store xmlns='urn:xmpp:hints'/></message>"
    ));
}

#[test]
fn explicit_store_keeps_a_standalone_chat_signal() {
    assert!(!transient(
        "<message><active xmlns='http://jabber.org/protocol/chatstates'/><store xmlns='urn:xmpp:hints'/></message>"
    ));
    assert!(!transient(
        "<message><displayed xmlns='urn:xmpp:chat-markers:0' id='m1'/><store xmlns='urn:xmpp:hints'/></message>"
    ));
}

#[test]
fn no_permanent_store_keeps_temporary_offline_recovery_only() {
    let document = Document::parse(
        "<message to='bob@example.test'><body>temporary</body><no-permanent-store xmlns='urn:xmpp:hints'/></message>",
    )
    .unwrap();
    let root = document.root_element();
    assert!(offline_storage_permitted(root));
    assert!(!mam_storage_eligible(root));
    assert_eq!(
        message_storage_policy(root).unwrap(),
        super::MessageStoragePolicy {
            temporary: true,
            permanent: false,
        }
    );
}

#[test]
fn processing_hints_are_empty_and_unique() {
    for invalid in [
        "<message to='bob@example.test'><store xmlns='urn:xmpp:hints'/><store xmlns='urn:xmpp:hints'/></message>",
        "<message to='bob@example.test'><no-store xmlns='urn:xmpp:hints'>yes</no-store></message>",
        "<message to='bob@example.test/phone'><private xmlns='urn:xmpp:carbons:2'/><private xmlns='urn:xmpp:carbons:2'/></message>",
    ] {
        assert!(!modern_payload_valid(invalid), "{invalid}");
    }
    assert!(modern_payload_valid(
        "<message to='bob@example.test/phone'><no-copy xmlns='urn:xmpp:hints'/></message>"
    ));
    assert!(modern_payload_valid(
        "<message to='bob@example.test'><no-copy xmlns='urn:xmpp:hints'/></message>"
    ));
    let bare = Document::parse(
        "<message to='bob@example.test'><body>fan out</body><no-copy xmlns='urn:xmpp:hints'/></message>",
    )
    .unwrap();
    assert!(should_carbon(bare.root_element()));
    let full = Document::parse(
        "<message to='bob@example.test/phone'><body>single target</body><no-copy xmlns='urn:xmpp:hints'/></message>",
    )
    .unwrap();
    assert!(!should_carbon(full.root_element()));
}

#[test]
fn overlapping_storage_hints_use_privacy_preserving_precedence() {
    for (xml, expected) in [
        (
            "<message><store xmlns='urn:xmpp:hints'/><no-permanent-store xmlns='urn:xmpp:hints'/></message>",
            super::MessageStoragePolicy {
                temporary: true,
                permanent: false,
            },
        ),
        (
            "<message><store xmlns='urn:xmpp:hints'/><no-permanent-store xmlns='urn:xmpp:hints'/><no-store xmlns='urn:xmpp:hints'/></message>",
            super::MessageStoragePolicy {
                temporary: false,
                permanent: false,
            },
        ),
    ] {
        let document = Document::parse(xml).unwrap();
        assert_eq!(
            message_storage_policy(document.root_element()).unwrap(),
            expected,
            "{xml}"
        );
    }
}

#[test]
fn delivery_receipts_require_unambiguous_ids() {
    let valid =
        Document::parse("<message id='m1'><request xmlns='urn:xmpp:receipts'/></message>").unwrap();
    assert!(validate_delivery_receipts(valid.root_element()).is_ok());
    assert!(transient(
        "<message><received xmlns='urn:xmpp:receipts' id='m1'/></message>"
    ));

    for invalid in [
        "<message><request xmlns='urn:xmpp:receipts'/></message>",
        "<message><received xmlns='urn:xmpp:receipts'/></message>",
        "<message id='m1'><request xmlns='urn:xmpp:receipts'/><received xmlns='urn:xmpp:receipts' id='m0'/></message>",
        "<message id='m1'><received xmlns='urn:xmpp:receipts' evil:id='m0' xmlns:evil='urn:evil'/></message>",
    ] {
        let document = Document::parse(invalid).unwrap();
        assert!(validate_delivery_receipts(document.root_element()).is_err());
    }
}

fn modern_payload_valid(xml: &str) -> bool {
    let document = Document::parse(xml).expect("test message must be XML");
    validate_modern_message_payloads(document.root_element()).is_ok()
}

#[test]
fn modern_message_extensions_accept_current_wire_shapes() {
    for xml in [
        "<message type='chat'><composing xmlns='http://jabber.org/protocol/chatstates'/></message>",
        "<message id='m2'><body>fixed</body><replace xmlns='urn:xmpp:message-correct:0' id='m1'/></message>",
        "<message id='m1'><markable xmlns='urn:xmpp:chat-markers:0'/></message>",
        "<message><received xmlns='urn:xmpp:chat-markers:0' id='m1'/></message>",
        "<message><displayed xmlns='urn:xmpp:chat-markers:0' id='m1'/></message>",
        "<message><acknowledged xmlns='urn:xmpp:chat-markers:0' id='m1'/></message>",
        "<message><openpgp xmlns='urn:xmpp:openpgp:0'/><encryption xmlns='urn:xmpp:eme:0' namespace='urn:xmpp:openpgp:0'/></message>",
        "<message><body>🧛🏾 &amp; ok</body><fallback xmlns='urn:xmpp:fallback:0' for='urn:xmpp:reply:0'><body start='0' end='7'/></fallback></message>",
        "<message><reactions xmlns='urn:xmpp:reactions:0' id='m1'><reaction>👍</reaction></reactions></message>",
        "<message><reactions xmlns='urn:xmpp:reactions:0' id='m1'><reaction>👍</reaction><reaction>👍</reaction></reactions></message>",
        "<message><reactions xmlns='urn:xmpp:reactions:0' id='m1'/></message>",
        "<message><reply xmlns='urn:xmpp:reply:0' id='m1' to='alice@example.test/phone'/></message>",
        "<message><file-sharing xmlns='urn:xmpp:sfs:0' disposition='attachment'><file xmlns='urn:xmpp:file:metadata:0'><name>a.txt</name></file></file-sharing></message>",
    ] {
        assert!(modern_payload_valid(xml), "{xml}");
    }
}

#[test]
fn encrypted_archive_preserves_ciphertext_and_eme_but_not_fallback_text() {
    for (namespace, payload) in [
        (
            "urn:xmpp:omemo:1",
            "<encrypted xmlns='urn:xmpp:omemo:1'><payload>cipher</payload></encrypted>",
        ),
        (
            "urn:xmpp:openpgp:0",
            "<openpgp xmlns='urn:xmpp:openpgp:0'>cipher</openpgp>",
        ),
        (
            "jabber:x:encrypted",
            "<x xmlns='jabber:x:encrypted'>cipher</x>",
        ),
    ] {
        let stanza = format!(
            "<message><body>plaintext fallback</body>{payload}<encryption xmlns='urn:xmpp:eme:0' namespace='{namespace}'/><origin-id xmlns='urn:xmpp:sid:0' id='m1'/><replace xmlns='urn:xmpp:message-correct:0' id='old'/><reply xmlns='urn:xmpp:reply:0' id='parent'/><markable xmlns='urn:xmpp:chat-markers:0'/><request xmlns='urn:xmpp:receipts'/><fallback xmlns='urn:xmpp:fallback:0' for='urn:xmpp:reply:0'/></message>"
        );
        let document = Document::parse(&stanza).unwrap();
        assert!(super::is_encrypted(document.root_element()), "{namespace}");
        let archived = super::encrypted_archive_stanza(&stanza);
        assert!(archived.contains("cipher"), "{namespace}");
        assert!(archived.contains("urn:xmpp:eme:0"), "{namespace}");
        assert!(archived.contains("urn:xmpp:sid:0"), "{namespace}");
        assert!(
            archived.contains("urn:xmpp:message-correct:0"),
            "{namespace}"
        );
        assert!(archived.contains("urn:xmpp:reply:0"), "{namespace}");
        assert!(archived.contains("urn:xmpp:chat-markers:0"), "{namespace}");
        assert!(archived.contains("urn:xmpp:receipts"), "{namespace}");
        assert!(!archived.contains("urn:xmpp:fallback:0"), "{namespace}");
        assert!(!archived.contains("plaintext fallback"), "{namespace}");
        assert!(archived.contains("This message is end-to-end encrypted."));
    }

    let nested = Document::parse(
        "<message><wrapper xmlns='urn:example'><encrypted xmlns='urn:xmpp:omemo:2'/></wrapper></message>",
    )
    .unwrap();
    assert!(!super::is_encrypted(nested.root_element()));

    // XEP-0380 is only an informational assertion.  It is abuse-rated,
    // but cannot by itself satisfy an encrypted-archive policy.
    let marker_only = Document::parse(
        "<message><encryption xmlns='urn:xmpp:eme:0' namespace='urn:xmpp:omemo:2'/></message>",
    )
    .unwrap();
    assert!(!super::is_encrypted(marker_only.root_element()));
    assert!(super::is_abuse_rated_message(marker_only.root_element()));

    let omemo2 = "<message><encrypted xmlns='urn:xmpp:omemo:2'><header sid='7'><keys jid='alice@example.test'><key rid='9'>AQ==</key></keys></header><payload>Ag==</payload></encrypted><encryption xmlns='urn:xmpp:eme:0' namespace='urn:xmpp:omemo:2'/><store xmlns='urn:xmpp:hints'/></message>";
    let archived = super::encrypted_archive_stanza(omemo2);
    assert!(archived.contains("urn:xmpp:omemo:2"));
    assert!(archived.contains("<payload>Ag==</payload>"));
    assert!(archived.contains("<store xmlns='urn:xmpp:hints'/>"));
    assert!(!archived.contains("<body"));
    assert!(!archived.contains("This message is end-to-end encrypted."));
    assert!(modern_payload_valid(&archived));
}

#[test]
fn omemo2_transport_shape_is_bounded_and_rejects_plaintext_downgrades() {
    let valid = "<message type='chat'><encrypted xmlns='urn:xmpp:omemo:2'><header sid='7'><keys jid='alice@example.test'><key rid='9' kex='true'>AQ==</key></keys><keys jid='bob@bücher.example'><key rid='10'>Ag==</key></keys></header><payload>Aw==</payload></encrypted><encryption xmlns='urn:xmpp:eme:0' namespace='urn:xmpp:omemo:2' name='OMEMO'/><store xmlns='urn:xmpp:hints'/></message>";
    assert!(modern_payload_valid(valid));
    let empty = "<message><encrypted xmlns='urn:xmpp:omemo:2'><header sid='7'><keys jid='alice@example.test'><key rid='9'>AQ==</key></keys></header></encrypted><encryption xmlns='urn:xmpp:eme:0' namespace='urn:xmpp:omemo:2'/><no-store xmlns='urn:xmpp:hints'/></message>";
    assert!(modern_payload_valid(empty));

    for invalid in [
        "<message><envelope xmlns='urn:xmpp:sce:1'><content/></envelope></message>",
        "<message><encrypted xmlns='urn:xmpp:omemo:2'><header sid='7'><keys jid='alice@example.test'><key rid='9'>AQ==</key></keys></header><payload>Ag==</payload></encrypted><body>plaintext downgrade</body></message>",
        "<message><encrypted xmlns='urn:xmpp:omemo:2'><header sid='7'><keys jid='alice@example.test'><key rid='9'>AQ==</key></keys></header><payload>Ag==</payload></encrypted><file-sharing xmlns='urn:xmpp:sfs:0'/></message>",
        "<message><encrypted xmlns='urn:xmpp:omemo:2'><header sid='0'><keys jid='alice@example.test'><key rid='9'>AQ==</key></keys></header></encrypted></message>",
        "<message><encrypted xmlns='urn:xmpp:omemo:2'><header sid='7'><keys jid='alice@example.test/device'><key rid='9'>AQ==</key></keys></header></encrypted></message>",
        "<message><encrypted xmlns='urn:xmpp:omemo:2'><header sid='7'><keys jid='alice@example.test'><key rid='9'>AQ==</key></keys><keys jid='ALICE@example.test'><key rid='10'>Ag==</key></keys></header></encrypted></message>",
        "<message><encrypted xmlns='urn:xmpp:omemo:2'><header sid='7'><keys jid='alice@example.test'><key rid='9'>AQ==</key><key rid='9'>Ag==</key></keys></header></encrypted></message>",
        "<message><encrypted xmlns='urn:xmpp:omemo:2'><header sid='7'><keys jid='alice@example.test'><key rid='9' kex='yes'>AQ==</key></keys></header></encrypted></message>",
        "<message><encrypted xmlns='urn:xmpp:omemo:2'><header sid='7'><keys jid='alice@example.test'><key rid='9'>not-base64!</key></keys></header></encrypted></message>",
        "<message><encrypted xmlns='urn:xmpp:omemo:2'><header sid='7'><keys jid='alice@example.test'><key rid='9'>AQ==</key></keys></header><payload/></encrypted></message>",
        "<message><encrypted xmlns='urn:xmpp:omemo:2'><payload>Ag==</payload><header sid='7'><keys jid='alice@example.test'><key rid='9'>AQ==</key></keys></header></encrypted><store xmlns='urn:xmpp:hints'/></message>",
        "<message><encrypted xmlns='urn:xmpp:omemo:2'><header sid='7'><keys jid='alice@example.test'><key rid='9'>AQ==</key></keys></header></encrypted><encrypted xmlns='urn:xmpp:omemo:2'><header sid='8'><keys jid='alice@example.test'><key rid='9'>AQ==</key></keys></header></encrypted></message>",
    ] {
        assert!(!modern_payload_valid(invalid), "{invalid}");
    }

    let oversized_payload = BASE64.encode(vec![0_u8; MAX_OMEMO2_PAYLOAD_BYTES + 1]);
    let oversized = format!(
        "<message><encrypted xmlns='urn:xmpp:omemo:2'><header sid='7'><keys jid='alice@example.test'><key rid='9'>AQ==</key></keys></header><payload>{oversized_payload}</payload></encrypted><store xmlns='urn:xmpp:hints'/></message>"
    );
    assert!(!modern_payload_valid(&oversized));
}

#[test]
fn omemo2_payload_store_requirement_does_not_override_no_store_policy() {
    let no_store = "<message type='chat'><encrypted xmlns='urn:xmpp:omemo:2'><header sid='7'><keys jid='alice@example.test'><key rid='9'>AQ==</key></keys></header><payload>Ag==</payload></encrypted><encryption xmlns='urn:xmpp:eme:0' namespace='urn:xmpp:omemo:2'/><store xmlns='urn:xmpp:hints'/><no-store xmlns='urn:xmpp:hints'/></message>";
    let document = Document::parse(no_store).unwrap();
    let root = document.root_element();

    assert_eq!(validate_modern_message_payloads(root), Ok(()));
    assert_eq!(
        message_storage_policy(root),
        Ok(super::MessageStoragePolicy {
            temporary: false,
            permanent: false,
        })
    );
    assert!(!offline_storage_permitted(root));
    assert!(!mam_storage_eligible(root));

    let missing_store = "<message type='chat'><encrypted xmlns='urn:xmpp:omemo:2'><header sid='7'><keys jid='alice@example.test'><key rid='9'>AQ==</key></keys></header><payload>Ag==</payload></encrypted><encryption xmlns='urn:xmpp:eme:0' namespace='urn:xmpp:omemo:2'/><no-store xmlns='urn:xmpp:hints'/></message>";
    let document = Document::parse(missing_store).unwrap();
    assert_eq!(
        validate_modern_message_payloads(document.root_element()),
        Err("not-acceptable")
    );
}

#[test]
fn modern_message_extensions_reject_ambiguous_or_unbounded_controls() {
    for xml in [
        "<message><active xmlns='http://jabber.org/protocol/chatstates'/><composing xmlns='http://jabber.org/protocol/chatstates'/></message>",
        "<message><typing xmlns='http://jabber.org/protocol/chatstates'/></message>",
        "<message><encryption xmlns='urn:xmpp:eme:0'/></message>",
        "<message><encryption xmlns='urn:xmpp:eme:0' namespace='urn:xmpp:omemo:2' evil:name='spoof' xmlns:evil='urn:evil'/></message>",
        "<message><body>🧛🏾</body><fallback xmlns='urn:xmpp:fallback:0' for='urn:xmpp:reply:0'><body start='0' end='9'/></fallback></message>",
        "<message><body>reply</body><fallback xmlns='urn:xmpp:fallback:0' for='urn:xmpp:reply:0'><body start='4'/></fallback></message>",
        "<message><body>reply</body><fallback xmlns='urn:xmpp:fallback:0'><body/></fallback></message>",
        "<message><replace xmlns='urn:xmpp:message-correct:0' id='m1'/></message>",
        "<message><body>not a correction</body><received xmlns='urn:xmpp:receipts' id='delivery'/><replace xmlns='urn:xmpp:message-correct:0' id='m1'/></message>",
        "<message><body>not a correction</body><propose xmlns='urn:xmpp:jingle-message:0' id='call'><description xmlns='urn:xmpp:jingle:apps:rtp:1' media='audio'/></propose><replace xmlns='urn:xmpp:message-correct:0' id='m1'/></message>",
        "<message id='m1'><markable xmlns='urn:xmpp:chat-markers:0'/><displayed xmlns='urn:xmpp:chat-markers:0' id='m0'/></message>",
        "<message><retracted xmlns='urn:xmpp:message-retract:1' id='server-only'/></message>",
        "<message><reply xmlns='urn:xmpp:reply:0' id='m1' evil:to='alice@example.test' xmlns:evil='urn:evil'/></message>",
        "<message><reply xmlns='urn:xmpp:reply:0' id='m1' to='bad@@example.test'/></message>",
        "<message><file-sharing xmlns='urn:xmpp:sfs:0'/></message>",
        "<message><file-sharing xmlns='urn:xmpp:sfs:0' id='same'><file xmlns='urn:xmpp:file:metadata:0'/></file-sharing><file-sharing xmlns='urn:xmpp:sfs:0' id='same'><file xmlns='urn:xmpp:file:metadata:0'/></file-sharing></message>",
        "<message><file-sharing xmlns='urn:xmpp:sfs:0'><file xmlns='urn:xmpp:file:metadata:0'><size>-1</size></file></file-sharing></message>",
        "<message><file-sharing xmlns='urn:xmpp:sfs:0'><file xmlns='urn:xmpp:file:metadata:0'><name>a</name><name>b</name></file></file-sharing></message>",
        "<message><file-sharing xmlns='urn:xmpp:sfs:0'><file xmlns='urn:xmpp:file:metadata:0'><date>not-a-date</date></file></file-sharing></message>",
    ] {
        assert!(!modern_payload_valid(xml), "{xml}");
    }
}

#[test]
fn bare_jid_validation_rejects_resources_and_malformed_addresses() {
    assert!(valid_bare_jid("alice@example.test"));
    assert!(valid_bare_jid("用户@例子.测试"));
    assert!(valid_bare_jid("example.test"));
    assert!(!valid_bare_jid("@example.test"));
    assert!(!valid_bare_jid("alice@"));
    assert!(!valid_bare_jid("alice@example.test/resource"));
    assert!(!valid_bare_jid("alice@@example.test"));
    assert!(!valid_bare_jid("ali ce@example.test"));
}

#[test]
fn stable_id_replaces_spoofed_issuer_and_preserves_origin() {
    let id = uuid::Uuid::parse_str("de305d54-75b4-431b-adb2-eb6b9e546013").unwrap();
    let annotated = add_stanza_id(
        "<message><origin-id xmlns='urn:xmpp:sid:0' id='client'/><stanza-id xmlns='urn:xmpp:sid:0' id='spoofed' by='alice@example.test'/><stanza-id xmlns='urn:xmpp:sid:0' id='remote' by='remote.test'/></message>",
        "alice@example.test",
        id,
    );
    assert!(annotated.contains("id='client'"));
    assert!(annotated.contains("id='remote'"));
    assert!(!annotated.contains("spoofed"));
    assert!(annotated.contains(&id.to_string()));
    assert_eq!(annotated.matches("by='alice@example.test'").count(), 1);
}

#[test]
fn stable_id_can_be_removed_without_disclosing_the_senders_archive_id() {
    let cleaned = strip_stanza_ids_by_domain(
        "<message><origin-id xmlns='urn:xmpp:sid:0' id='client'/><stanza-id xmlns='urn:xmpp:sid:0' id='spoofed' by='Alice@Example.test'/><stanza-id xmlns='urn:xmpp:sid:0' id='remote' by='remote.test'/></message>",
        "example.test",
    );
    assert!(cleaned.contains("id='client'"));
    assert!(cleaned.contains("id='remote'"));
    assert!(!cleaned.contains("spoofed"));
    assert!(!cleaned.contains("by='Alice@Example.test'"));
}

#[test]
fn local_domain_identity_sanitization_removes_every_forged_account() {
    let cleaned = strip_stanza_ids_by_domain(
        "<message><stanza-id xmlns='urn:xmpp:sid:0' id='one' by='alice@example.test'/><stanza-id xmlns='urn:xmpp:sid:0' id='two' by='Mallory@EXAMPLE.TEST'/><stanza-id xmlns='urn:xmpp:sid:0' id='remote' by='remote.test'/></message>",
        "example.test",
    );
    assert!(!cleaned.contains("id='one'"));
    assert!(!cleaned.contains("id='two'"));
    assert!(cleaned.contains("id='remote'"));
}

#[test]
fn occupant_ids_are_stable_and_scoped_to_a_room_secret() {
    let first = muc_occupant_id(&[7_u8; 32], "Alice@Example.test/phone");
    assert_eq!(
        first,
        muc_occupant_id(&[7_u8; 32], "alice@example.test/laptop")
    );
    assert_ne!(first, muc_occupant_id(&[8_u8; 32], "alice@example.test"));
    assert_eq!(first.len(), 64);
}

#[test]
fn authoritative_occupant_id_replaces_client_spoofing() {
    let stanza = set_muc_occupant_id(
        "<message><body>hello</body><occupant-id xmlns='urn:xmpp:occupant-id:0' id='spoofed'/></message>",
        "authoritative",
    );
    assert!(!stanza.contains("spoofed"));
    assert!(stanza.contains("id='authoritative'"));
    assert_eq!(stanza.matches("urn:xmpp:occupant-id:0").count(), 1);
}

#[test]
fn muc_removal_presence_carries_self_kick_and_occupant_identity() {
    let occupant = crate::state::SerializableMucOccupant {
        full_jid: "alice@example.test/phone".to_owned(),
        room_jid: "room@conference.example.test".to_owned(),
        nick: "alice".to_owned(),
        affiliation: "member".to_owned(),
        role: "none".to_owned(),
        room_non_anonymous: false,
        occupant_id: "opaque-id".to_owned(),
        cluster_epoch: uuid::Uuid::new_v4(),
        connection_id: uuid::Uuid::new_v4(),
        federated_domain: None,
        sm_session_id: None,
        payload: String::new(),
    };
    let stanza = muc_presence_stanza_with_status(
        &occupant,
        &occupant.full_jid,
        true,
        true,
        false,
        Some("leave-1"),
        true,
        Some(307),
        Some("moderator"),
        Some("flooding"),
    );
    assert!(stanza.contains("<status code='110'/><status code='307'/>"));
    assert!(stanza.contains("<actor nick='moderator'/><reason>flooding</reason>"));
    assert!(stanza.contains("id='opaque-id'"));
}

#[test]
fn muc_status_insertion_handles_prefixed_self_closing_extensions() {
    let input = "<c:presence xmlns:c='jabber:client'><m:x xmlns:m='http://jabber.org/protocol/muc#user'/></c:presence>";
    let stanza = add_muc_user_status(input, 170);
    let document = Document::parse(&stanza).unwrap();
    let status = document
        .descendants()
        .find(|node| node.is_element() && node.tag_name().name() == "status")
        .unwrap();
    assert_eq!(
        status.tag_name().namespace(),
        Some("http://jabber.org/protocol/muc#user")
    );
    assert_eq!(status.attribute("code"), Some("170"));
    assert_eq!(
        document
            .descendants()
            .filter(|node| node.is_element() && node.tag_name().name() == "status")
            .count(),
        1
    );
}

#[test]
fn muc_occupant_keys_preserve_precis_opaque_nickname_case() {
    let upper = muc_occupant_key("ROOM@Conference.Example.test", "Nick");
    let lower = muc_occupant_key("room@conference.example.test", "nick");
    assert_eq!(upper, "room@conference.example.test/Nick");
    assert_eq!(lower, "room@conference.example.test/nick");
    assert_ne!(upper, lower);
}

#[test]
fn muc_nickname_preparation_normalizes_without_trimming_or_case_mapping() {
    assert_eq!(prepare_muc_nick("A\u{30a}").unwrap(), "\u{c5}");
    assert_eq!(prepare_muc_nick(" Nick ").unwrap(), " Nick ");
    assert_ne!(
        prepare_muc_nick("Nick").unwrap(),
        prepare_muc_nick("nick").unwrap()
    );
    assert!(!valid_muc_nick(""));
    assert!(!valid_muc_nick("bad\u{0007}nick"));
}
