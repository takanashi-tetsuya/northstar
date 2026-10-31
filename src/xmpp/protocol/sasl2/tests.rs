use super::*;

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
