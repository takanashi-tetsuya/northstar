use super::{
    authoritative_client_stanza, full_jid_iq_visible, is_caps_disco_get, is_stream_close,
    missing_full_jid_iq_needs_error, pre_auth_registration_iq, resource_binding_iq, tls_failure,
    valid_bind_payload, valid_client_stanza_namespace, valid_empty_iq_payload, xmpp_version_os,
};
use crate::services::stanza_validation::validate_client_stanza;
use roxmltree::Document;

fn with_root(xml: &str, check: impl FnOnce(roxmltree::Node<'_, '_>)) {
    let document = Document::parse(xml).expect("test stanza must be XML");
    check(document.root_element());
}

#[test]
fn version_response_reports_the_compilation_target_os() {
    let expected = match std::env::consts::OS {
        "linux" => "Linux",
        "windows" => "Windows",
        "macos" => "macOS",
        other => other,
    };
    assert_eq!(xmpp_version_os(), expected);
}

#[test]
fn websocket_stanzas_require_the_client_namespace() {
    with_root("<message/>", |root| {
        assert!(!valid_client_stanza_namespace(root, true, "<message/>"));
        assert!(valid_client_stanza_namespace(root, false, "<message/>"));
    });
    with_root("<message xmlns='jabber:client'/>", |root| {
        assert!(valid_client_stanza_namespace(
            root,
            true,
            "<message xmlns='jabber:client'/>"
        ));
    });
    with_root("<message xmlns='urn:evil'/>", |root| {
        assert!(!valid_client_stanza_namespace(
            root,
            false,
            "<message xmlns='urn:evil'/>"
        ));
    });
    with_root("<message xmlns=''/>", |root| {
        assert!(!valid_client_stanza_namespace(
            root,
            false,
            "<message xmlns=''/>"
        ));
    });
}

#[test]
fn tcp_stream_close_accepts_only_xml_whitespace_before_the_delimiter() {
    assert!(is_stream_close("</stream:stream>"));
    assert!(is_stream_close("</stream:stream \r\n>"));
    assert!(!is_stream_close("</stream:stream bogus>"));
    assert!(!is_stream_close("</stream:streams>"));
}

#[test]
fn starttls_failure_uses_the_terminal_rfc6120_shape() {
    let failure = tls_failure();
    assert_eq!(
        failure,
        "<failure xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>"
    );
    assert!(!failure.contains("unexpected-request"));
}

#[test]
fn c2s_sender_is_always_server_authoritative() {
    with_root(
        "<message from='mallory@example.test/Other'><body>Hello</body></message>",
        |root| {
            let stamped = authoritative_client_stanza(
                "<message from='mallory@example.test/Other'><body>Hello</body></message>",
                root,
                "alice@example.test/Phone",
            );
            with_root(&stamped, |stamped_root| {
                assert_eq!(
                    stamped_root.attribute("from"),
                    Some("alice@example.test/Phone")
                );
            });
        },
    );
    with_root(
        "<presence type='subscribe' to='bob@example.test'/>",
        |root| {
            let stamped = authoritative_client_stanza(
                "<presence type='subscribe' to='bob@example.test'/>",
                root,
                "alice@example.test/Phone",
            );
            with_root(&stamped, |stamped_root| {
                assert_eq!(stamped_root.attribute("from"), Some("alice@example.test"));
            });
        },
    );
}

#[test]
fn unentitled_full_jid_caps_disco_is_hidden() {
    with_root(
        "<iq type='get' id='caps' to='bob@example.test/Phone'><query xmlns='http://jabber.org/protocol/disco#info' node='client#hash'/></iq>",
        |root| assert!(is_caps_disco_get(root)),
    );
    assert!(!full_jid_iq_visible(false, false, false));
    assert!(full_jid_iq_visible(true, false, false));
    assert!(full_jid_iq_visible(false, true, false));
    assert!(full_jid_iq_visible(false, false, true));
}

#[test]
fn full_jid_jingle_is_subject_to_the_same_presence_leak_gate() {
    with_root(
        "<iq type='set' id='info' to='alice@example.test/Phone'><jingle xmlns='urn:xmpp:jingle:1' action='session-info' sid='s'><ringing xmlns='urn:xmpp:jingle:apps:rtp:info:1'/></jingle></iq>",
        |root| assert!(!is_caps_disco_get(root)),
    );
    assert!(!full_jid_iq_visible(false, false, false));
}

#[test]
fn missing_full_jid_iq_never_creates_a_result_or_error_loop() {
    assert!(missing_full_jid_iq_needs_error("get"));
    assert!(missing_full_jid_iq_needs_error("set"));
    assert!(!missing_full_jid_iq_needs_error("result"));
    assert!(!missing_full_jid_iq_needs_error("error"));
}

#[test]
fn iq_type_id_and_payload_cardinality_are_strict() {
    for valid in [
        "<iq type='get' id='g'><ping/></iq>",
        "<iq type='set' id='s'><query/></iq>",
        "<iq type='result' id='r'/>",
        "<iq type='result' id='r2'><query/></iq>",
        "<iq type='error' id='e'><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></iq>",
        "<iq type='error' id='e2'><query/><error type='modify'><bad-request xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></iq>",
    ] {
        with_root(valid, |root| {
            assert_eq!(validate_client_stanza(root), Ok(()))
        });
    }
    for invalid in [
        "<iq id='missing-type'><ping/></iq>",
        "<iq type='get'><ping/></iq>",
        "<iq type='get' id='empty'/>",
        "<iq type='set' id='many'><a/><b/></iq>",
        "<iq type='result' id='many'><a/><b/></iq>",
        "<iq type='error' id='missing-error'><query/></iq>",
        "<iq type='error' id='duplicate-error'><error/><error/></iq>",
        "<iq type='error' id='malformed-error'><error/></iq>",
        "<iq type='invented' id='bad'><query/></iq>",
    ] {
        with_root(invalid, |root| {
            assert_eq!(validate_client_stanza(root), Err("bad-request"))
        });
    }
}

#[test]
fn stanza_types_ids_and_jids_are_bounded_and_validated() {
    with_root(
        "<message type='chat' to='Alice@Example.test/Phone'/>",
        |root| {
            assert_eq!(validate_client_stanza(root), Ok(()));
        },
    );
    for valid in [
        "<presence xml:lang='en'><priority> 1 </priority><show>away</show><status>Busy</status><status xml:lang='ja'>多忙</status></presence>",
        "<message xmlns:x='urn:example:extension' x:trace='ok'><body>Hello</body><body xml:lang='fr'>Salut</body><thread parent='older'>newer</thread></message>",
        "<presence type='error' to='alice@example.test'><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/><text xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'>Offline</text></error></presence>",
        "<message type='error'><error type='cancel'><gone xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'>xmpp:new@example.test</gone></error></message>",
        "<message type='error'><error type='cancel'><future-condition xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></message>",
    ] {
        with_root(valid, |root| {
            assert_eq!(validate_client_stanza(root), Ok(()))
        });
    }
    for invalid in [
        "<message type='invented'/>",
        "<presence type='available'/>",
        "<presence type='invented'/>",
        "<presence><priority>128</priority></presence>",
        "<presence><priority>1</priority><priority>2</priority></presence>",
        "<presence><show>online</show></presence>",
        "<presence type='unavailable'><priority>1</priority></presence>",
        "<presence type='subscribe'><show>away</show></presence>",
        "<presence type='subscribe'/>",
        "<presence type='probe'/>",
        "<presence type='error'/>",
        "<presence type='error'><error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></presence>",
        "<message><body>one</body><body>two</body></message>",
        "<message><body><b>nested</b></body></message>",
        "<message invented='value'/>",
        "<message xml:lang='en--US'/>",
        "<message><body xml:lang='not_a_tag'>bad</body></message>",
        "<message type='error'><error type='cancel'><bad-request xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></message>",
        "<message type='error'><error type='modify'><bad-request xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'>must be empty</bad-request></error></message>",
        "<message to='alice@bad domain'/>",
        "<message id=''/>",
    ] {
        with_root(invalid, |root| {
            assert!(validate_client_stanza(root).is_err())
        });
    }
}

#[test]
fn explicit_stream_namespace_cannot_bypass_core_child_validation() {
    for invalid in [
        "<message><body xmlns='jabber:client'><nested/></body></message>",
        "<message><body xml:lang='en'/><body xmlns='jabber:client' xml:lang='EN'/></message>",
    ] {
        with_root(invalid, |root| {
            assert_eq!(validate_client_stanza(root), Err("bad-request"))
        });
    }
}

#[test]
fn negotiation_phase_helpers_allow_only_registration_and_binding() {
    for allowed in [
        "<iq type='get' id='r'><query xmlns='jabber:iq:register'/></iq>",
        "<iq type='set' id='r'><register xmlns='urn:xmpp:register:0'/></iq>",
    ] {
        with_root(allowed, |root| assert!(pre_auth_registration_iq(root)));
    }
    for denied in [
        "<message><body>pre-auth</body></message>",
        "<iq type='get' id='d'><query xmlns='http://jabber.org/protocol/disco#info'/></iq>",
        "<iq type='result' id='r'><query xmlns='jabber:iq:register'/></iq>",
    ] {
        with_root(denied, |root| assert!(!pre_auth_registration_iq(root)));
    }

    with_root(
        "<iq type='set' id='b'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><resource>Phone</resource></bind></iq>",
        |root| assert!(resource_binding_iq(root)),
    );
    for denied in [
        "<iq type='get' id='b'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'/></iq>",
        "<iq type='set' id='x'><session xmlns='urn:ietf:params:xml:ns:xmpp-session'/></iq>",
    ] {
        with_root(denied, |root| assert!(!resource_binding_iq(root)));
    }

    for valid in [
        "<bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'/>",
        "<bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><resource>Phone</resource></bind>",
    ] {
        with_root(valid, |root| assert!(valid_bind_payload(root)));
    }
    for invalid in [
        "<bind xmlns='urn:ietf:params:xml:ns:xmpp-bind' extra='x'/>",
        "<bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><resource/><resource>two</resource></bind>",
        "<bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><resource><nested/></resource></bind>",
        "<bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><jid>a@example.test/r</jid></bind>",
    ] {
        with_root(invalid, |root| assert!(!valid_bind_payload(root)));
    }
    with_root(
        "<session xmlns='urn:ietf:params:xml:ns:xmpp-session'/>",
        |root| assert!(valid_empty_iq_payload(root)),
    );
    with_root(
        "<session xmlns='urn:ietf:params:xml:ns:xmpp-session'><extra/></session>",
        |root| assert!(!valid_empty_iq_payload(root)),
    );
}
