use super::*;

fn parse(xml: &str) -> std::result::Result<Sasl2Request, &'static str> {
    let document = Document::parse(xml).unwrap();
    parse_authenticate(document.root_element())
}

const DEVICE: &str = "67e55044-10b1-426f-9247-bb680e5fe0c8";

#[test]
fn request_and_context_debug_redact_all_bearer_material() {
    use base64::Engine;

    let initial =
        base64::engine::general_purpose::STANDARD.encode(b"\0alice\0secret-password-material");
    let previd = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0x91_u8; 32]);
    let xml = format!(
        "<authenticate xmlns='{SASL2_NS}' mechanism='PLAIN'>\
           <initial-response>{initial}</initial-response>\
           <resume xmlns='urn:xmpp:sm:3' previd='{previd}' h='0'/>\
         </authenticate>"
    );
    let request = parse(&xml).unwrap();
    let request_debug = format!("{request:?}");
    assert!(request_debug.contains("[REDACTED]"));
    assert!(!request_debug.contains(&initial));
    assert!(!request_debug.contains(&previd));

    let token_id = Uuid::new_v4();
    let context = Sasl2Context {
        request,
        fast_should_rotate: false,
        awaiting_initial_response: false,
        fast_token_id: Some(token_id),
        fast_token_was_new: false,
        fast_invalidate: false,
        authenticated_generation: Some(7),
        inherited_fast_chain: None,
    };
    let context_debug = format!("{context:?}");
    assert!(!context_debug.contains(&initial));
    assert!(!context_debug.contains(&previd));
    assert!(!context_debug.contains(&token_id.to_string()));
}

#[test]
fn validates_tcp_and_websocket_stream_openings() {
    let tcp = "<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:client' to='EXAMPLE.test.' from='A\u{30a}LICE@example.test' version='1.0' xml:lang='en-US'>";
    assert_eq!(
        parse_stream_open(tcp, false, "example.test").unwrap(),
        ParsedStreamOpen {
            from: Some("\u{e5}lice".to_owned()),
            language: Some("en-US".to_owned()),
        }
    );
    let websocket =
        "<open xmlns='urn:ietf:params:xml:ns:xmpp-framing' to='example.test' version='1.0'/>";
    assert_eq!(
        parse_stream_open(websocket, true, "example.test").unwrap(),
        ParsedStreamOpen {
            from: None,
            language: None,
        }
    );
    assert!(parse_stream_open(tcp, true, "example.test").is_err());
    assert!(parse_stream_open(websocket, false, "example.test").is_err());
}

#[test]
fn stream_versions_are_numeric_and_minor_versions_are_forward_compatible() {
    for version in ["1.0", "1.1", "1.01", "0001.00042"] {
        let opening = format!(
            "<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:client' to='example.test' version='{version}'>"
        );
        assert!(
            parse_stream_open(&opening, false, "example.test").is_ok(),
            "rejected {version}"
        );
    }
    for version in ["2.0", "0.9", "1", "1.", ".1", "1.x", "1.0.1"] {
        let opening = format!(
            "<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:client' to='example.test' version='{version}'>"
        );
        assert_eq!(
            parse_stream_open(&opening, false, "example.test"),
            Err(StreamOpenError::UnsupportedVersion),
            "accepted {version}"
        );
    }
}

#[test]
fn stream_open_failures_keep_the_rfc_condition() {
    let bad_prefix = "<s:stream xmlns:s='http://etherx.jabber.org/streams' xmlns='jabber:client' to='example.test' version='1.0'>";
    assert_eq!(
        parse_stream_open(bad_prefix, false, "example.test"),
        Err(StreamOpenError::BadNamespacePrefix)
    );
    let missing_to = "<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:client' version='1.0'>";
    assert_eq!(
        parse_stream_open(missing_to, false, "example.test"),
        Err(StreamOpenError::ImproperAddressing)
    );
    let unknown_host = "<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:client' to='other.test' version='1.0'>";
    assert_eq!(
        parse_stream_open(unknown_host, false, "example.test"),
        Err(StreamOpenError::HostUnknown)
    );
    let invalid_from = "<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:client' to='example.test' from='alice@example.test/Phone' version='1.0'>";
    assert_eq!(
        parse_stream_open(invalid_from, false, "example.test"),
        Err(StreamOpenError::InvalidFrom)
    );
    let empty_from = "<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:client' to='example.test' from='' version='1.0'>";
    assert_eq!(
        parse_stream_open(empty_from, false, "example.test"),
        Err(StreamOpenError::InvalidFrom)
    );
    let invalid_namespace = "<stream:stream xmlns:stream='urn:wrong' xmlns='jabber:client' to='example.test' version='1.0'>";
    assert_eq!(
        parse_stream_open(invalid_namespace, false, "example.test"),
        Err(StreamOpenError::InvalidNamespace)
    );
}

#[test]
fn rejects_incomplete_or_smuggled_stream_openings() {
    for opening in [
        "<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:client' to='example.test'>",
        "<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:server' to='example.test' version='1.0'>",
        "<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:client' version='1.0'>",
        "<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:client' to='other.test' version='1.0'>",
        "<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:client' to='example.test' version='1.0' id='client-controlled'>",
        "<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:client' to='example.test' from='alice@example.test/device' version='1.0'>",
        "<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:client' to='example.test' version='1.0'><auth/>",
    ] {
        assert!(
            parse_stream_open(opening, false, "example.test").is_err(),
            "accepted {opening}"
        );
    }
    for opening in [
        "<open xmlns='urn:ietf:params:xml:ns:xmpp-framing' to='example.test'/>",
        "<open xmlns='urn:evil' to='example.test' version='1.0'/>",
        "<open xmlns='urn:ietf:params:xml:ns:xmpp-framing' to='example.test' version='1.0' restart='true'/>",
        "<open xmlns='urn:ietf:params:xml:ns:xmpp-framing' to='example.test' version='1.0'><auth/></open>",
    ] {
        assert!(
            parse_stream_open(opening, true, "example.test").is_err(),
            "accepted {opening}"
        );
    }
}

#[test]
fn parses_password_auth_with_inline_bind() {
    let xml = format!(
        "<authenticate xmlns='{SASL2_NS}' mechanism='SCRAM-SHA-256'><initial-response>biwsbj11LHI9eA==</initial-response><user-agent id='{DEVICE}'><software>Test</software></user-agent><bind xmlns='{BIND2_NS}'><tag>Phone</tag><enable xmlns='urn:xmpp:carbons:2'/><enable xmlns='urn:xmpp:sm:3' resume='true'/><inactive xmlns='urn:xmpp:csi:0'/></bind><request-token xmlns='{FAST_NS}' mechanism='HT-SHA-256-ENDP'/></authenticate>"
    );
    let request = parse(&xml).unwrap();
    assert_eq!(request.bind.unwrap().tag.as_deref(), Some("Phone"));
    assert_eq!(request.request_token.as_deref(), Some("HT-SHA-256-ENDP"));
}

#[test]
fn parses_strict_inline_sm_resume() {
    use base64::Engine;
    let previd = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([7_u8; 32]);
    let request = parse(&format!(
        "<authenticate xmlns='{SASL2_NS}' mechanism='SCRAM-SHA-256'><resume xmlns='urn:xmpp:sm:3' previd='{previd}' h='4294967295'/><bind xmlns='{BIND2_NS}'/></authenticate>"
    ))
    .unwrap();
    let resume = request.resume.unwrap();
    assert_eq!(resume.previd.as_str(), previd);
    assert_eq!(resume.h, u32::MAX);

    for invalid in [
        "<resume xmlns='urn:xmpp:sm:3' previd='short' h='0'/>".to_owned(),
        format!("<resume xmlns='urn:xmpp:sm:3' previd='{previd}' h='4294967296'/>"),
        format!("<resume xmlns='urn:xmpp:sm:3' previd='{previd}' h='0' extra='x'/>"),
    ] {
        let xml = format!(
            "<authenticate xmlns='{SASL2_NS}' mechanism='SCRAM-SHA-256'>{invalid}</authenticate>"
        );
        assert_eq!(parse(&xml).unwrap_err(), "malformed-request");
    }
}

#[test]
fn user_agent_and_initial_response_are_optional_for_sasl2() {
    let request = parse(&format!(
        "<authenticate xmlns='{SASL2_NS}' mechanism='SCRAM-SHA-256'/>"
    ))
    .unwrap();
    assert!(request.user_agent_id.is_none());
    assert!(request.initial_response.is_none());
}

#[test]
fn sasl2_rejects_legacy_explicit_empty_but_accepts_an_empty_element() {
    let malformed = format!(
        "<authenticate xmlns='{SASL2_NS}' mechanism='PLAIN'><initial-response>***</initial-response></authenticate>"
    );
    assert_eq!(parse(&malformed).unwrap_err(), "incorrect-encoding");
    let legacy_explicit_empty = format!(
        "<authenticate xmlns='{SASL2_NS}' mechanism='PLAIN'><initial-response>=</initial-response></authenticate>"
    );
    assert_eq!(
        parse(&legacy_explicit_empty).unwrap_err(),
        "incorrect-encoding"
    );
    let empty_element = format!(
        "<authenticate xmlns='{SASL2_NS}' mechanism='PLAIN'><initial-response/></authenticate>"
    );
    assert_eq!(
        parse(&empty_element)
            .unwrap()
            .initial_response
            .as_ref()
            .map(|value| value.as_str()),
        Some("")
    );
}

#[test]
fn rejects_out_of_order_sasl2_user_agent_and_bind2_children() {
    for xml in [
        format!(
            "<authenticate xmlns='{SASL2_NS}' mechanism='PLAIN'><user-agent id='{DEVICE}'/><initial-response>AA==</initial-response></authenticate>"
        ),
        format!(
            "<authenticate xmlns='{SASL2_NS}' mechanism='PLAIN'><bind xmlns='{BIND2_NS}'/><user-agent id='{DEVICE}'/></authenticate>"
        ),
        format!(
            "<authenticate xmlns='{SASL2_NS}' mechanism='PLAIN'><user-agent id='{DEVICE}'><device>Phone</device><software>Client</software></user-agent></authenticate>"
        ),
        format!(
            "<authenticate xmlns='{SASL2_NS}' mechanism='PLAIN'><bind xmlns='{BIND2_NS}'><enable xmlns='urn:xmpp:carbons:2'/><tag>late</tag></bind></authenticate>"
        ),
        format!(
            "<authenticate xmlns='{SASL2_NS}' mechanism='PLAIN'><bind xmlns='{BIND2_NS}'><tag/></bind></authenticate>"
        ),
    ] {
        assert_eq!(parse(&xml).unwrap_err(), "malformed-request", "{xml}");
    }
}

#[test]
fn rejects_duplicate_and_wrong_namespace_children() {
    let duplicate = format!(
        "<authenticate xmlns='{SASL2_NS}' mechanism='PLAIN'><user-agent id='{DEVICE}'/><user-agent id='{DEVICE}'/></authenticate>"
    );
    assert_eq!(parse(&duplicate).unwrap_err(), "malformed-request");
    let wrong_ns = format!(
        "<authenticate xmlns='{SASL2_NS}' mechanism='PLAIN'><initial-response xmlns='urn:evil'>AA==</initial-response><user-agent id='{DEVICE}'/></authenticate>"
    );
    assert_eq!(parse(&wrong_ns).unwrap_err(), "malformed-request");
}

#[test]
fn rejects_non_v4_device_ids_and_invalid_replay_counts() {
    let nil = format!(
        "<authenticate xmlns='{SASL2_NS}' mechanism='HT-SHA-256-NONE'><user-agent id='00000000-0000-0000-0000-000000000000'/><fast xmlns='{FAST_NS}' count='0'/></authenticate>"
    );
    assert_eq!(parse(&nil).unwrap_err(), "malformed-request");
    let non_rfc_variant = format!(
        "<authenticate xmlns='{SASL2_NS}' mechanism='HT-SHA-256-NONE'><user-agent id='550e8400-e29b-41d4-c716-446655440000'/></authenticate>"
    );
    assert_eq!(parse(&non_rfc_variant).unwrap_err(), "malformed-request");
    let negative = format!(
        "<authenticate xmlns='{SASL2_NS}' mechanism='HT-SHA-256-NONE'><user-agent id='{DEVICE}'/><fast xmlns='{FAST_NS}' count='-1'/></authenticate>"
    );
    assert_eq!(parse(&negative).unwrap_err(), "malformed-request");

    let ordinary_non_early_data = format!(
        "<authenticate xmlns='{SASL2_NS}' mechanism='HT-SHA-256-NONE'><initial-response>AA==</initial-response><user-agent id='{DEVICE}'/><fast xmlns='{FAST_NS}'/></authenticate>"
    );
    assert_eq!(
        parse(&ordinary_non_early_data).unwrap().fast.unwrap().count,
        None
    );
}

#[test]
fn rejects_channel_binding_downgrade_at_request_boundary() {
    let unsupported = format!(
        "<authenticate xmlns='{SASL2_NS}' mechanism='PLAIN'><user-agent id='{DEVICE}'/><bind xmlns='{BIND2_NS}'/><request-token xmlns='{FAST_NS}' mechanism='HT-SHA-512-NONE'/></authenticate>"
    );
    assert_eq!(parse(&unsupported).unwrap_err(), "invalid-mechanism");
}

#[test]
fn rejects_text_smuggling_in_empty_extension_elements() {
    let xml = format!(
        "<authenticate xmlns='{SASL2_NS}' mechanism='PLAIN'><initial-response>AA==</initial-response><user-agent id='{DEVICE}'/><bind xmlns='{BIND2_NS}'><enable xmlns='urn:xmpp:carbons:2'>junk</enable></bind></authenticate>"
    );
    assert_eq!(parse(&xml).unwrap_err(), "malformed-request");
    let fast = format!(
        "<authenticate xmlns='{SASL2_NS}' mechanism='HT-SHA-256-NONE'><initial-response>AA==</initial-response><user-agent id='{DEVICE}'/><fast xmlns='{FAST_NS}' count='1'>junk</fast></authenticate>"
    );
    assert_eq!(parse(&fast).unwrap_err(), "malformed-request");
}

#[test]
fn sasl2_failure_keeps_text_in_the_sasl2_namespace() {
    let hostile = "denied </text><success xmlns='urn:evil'/>&\r🙂";
    let xml = failure_xml("not-authorized", Some(hostile));
    let document = Document::parse(&xml).unwrap();
    let text = document
        .root_element()
        .children()
        .find(|child| child.tag_name().name() == "text")
        .unwrap();
    assert_eq!(text.tag_name().namespace(), Some(SASL2_NS));
    assert_eq!(text.text(), Some(hostile));
    assert_eq!(
        document
            .descendants()
            .filter(|node| node.is_element() && node.tag_name().name() == "success")
            .count(),
        0
    );
}

#[test]
fn sasl2_success_validates_fragments_and_escapes_authorization_identifier() {
    let hostile = "alice<&'@example.test/🙂";
    let success = sasl2_success_xml(
        Some(b"server-final"),
        hostile,
        &["<resumed xmlns='urn:xmpp:sm:3' h='7'/>"],
    )
    .unwrap();
    let document = Document::parse(&success).unwrap();
    assert_eq!(
        document
            .descendants()
            .find(|node| {
                node.is_element() && node.tag_name().name() == "authorization-identifier"
            })
            .and_then(|node| node.text()),
        Some(hostile)
    );
    assert!(document.descendants().any(|node| {
        node.is_element()
            && node.tag_name().name() == "resumed"
            && node.tag_name().namespace() == Some("urn:xmpp:sm:3")
    }));
    assert!(sasl2_success_xml(None, hostile, &["<broken></fragment>"]).is_err());
}

#[test]
fn fast_token_xml_formats_valid_rfc3339_response() {
    let now = chrono::Utc::now();
    let token = crate::services::authentication::IssuedFastToken {
        token: Zeroizing::new("fast-token-payload-abc".to_string()),
        expires_at: now,
    };
    let xml = fast_token_xml(&token);
    assert!(xml.starts_with("<token xmlns='urn:xmpp:fast:0'"));
    assert!(xml.contains("token='fast-token-payload-abc'"));
    let expected_expiry = now.to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    assert!(xml.contains(&format!("expiry='{expected_expiry}'")));
}
