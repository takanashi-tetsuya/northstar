use super::*;

#[test]
fn sm_lease_polling_keeps_the_existing_floor_and_ratio() {
    assert_eq!(sm_lease_poll_interval(1), Duration::from_secs(1));
    assert_eq!(sm_lease_poll_interval(2), Duration::from_secs(1));
    assert_eq!(sm_lease_poll_interval(3), Duration::from_secs(1));
    assert_eq!(sm_lease_poll_interval(8), Duration::from_secs(2));
    assert_eq!(sm_lease_poll_interval(9), Duration::from_secs(3));
}

#[tokio::test]
async fn websocket_terminal_write_runs_after_session_disconnect_is_latched() {
    let disconnect = tokio_util::sync::CancellationToken::new();
    disconnect.cancel();
    let mut write_polled = false;

    assert!(
        bounded_websocket_terminal_write(async {
            assert!(disconnect.is_cancelled());
            write_polled = true;
            Ok::<(), ()>(())
        })
        .await
    );
    assert!(write_polled);
}

#[test]
fn websocket_shutdown_finishes_exactly_one_terminal_sequence() {
    let mut terminal = WebSocketTerminalSequence::default();
    assert!(needs_shutdown_terminal_sequence(false, true, &terminal));
    assert!(terminal.begin());
    assert!(!needs_shutdown_terminal_sequence(true, true, &terminal));
    assert!(!terminal.begin());
}

#[test]
fn websocket_terminal_action_orders_replies_before_both_close_frames() {
    let messages = websocket_terminal_messages(
        vec!["<iq id='account-remove' type='result'/>".to_owned()],
        true,
    );
    assert_eq!(messages.len(), 3);
    assert!(matches!(
        &messages[0],
        Message::Text(reply) if reply.contains("account-remove")
    ));
    assert!(matches!(
        &messages[1],
        Message::Text(close) if close.as_str() == websocket_close()
    ));
    assert!(matches!(&messages[2], Message::Close(None)));
}

#[test]
fn peer_idle_deadline_changes_only_for_peer_traffic_or_authentication() {
    let started = tokio::time::Instant::now();
    let limits = native_stream_limits();
    let mut tracker = PeerIdleTracker::new(limits, false, started);
    assert_eq!(tracker.deadline, started + C2S_NEGOTIATION_IDLE_TIMEOUT);

    // Local queue/timer selection does not call either mutating method.
    // Merely re-entering the loop with the same auth state must preserve
    // the original absolute deadline.
    let local_event = started + Duration::from_secs(5);
    tracker.synchronize_authentication(false, local_event);
    assert_eq!(tracker.deadline, started + C2S_NEGOTIATION_IDLE_TIMEOUT);

    tracker.note_peer_traffic(false, local_event);
    assert_eq!(tracker.deadline, local_event + C2S_NEGOTIATION_IDLE_TIMEOUT);

    let authenticated_at = started + Duration::from_secs(7);
    tracker.synchronize_authentication(true, authenticated_at);
    assert_eq!(
        tracker.deadline,
        authenticated_at + C2S_AUTHENTICATED_IDLE_TIMEOUT
    );
}

#[test]
fn peer_idle_deadline_uses_transport_supplied_limits() {
    let limits = protocol::StreamLimits {
        max_bytes: 128,
        negotiation_idle: Duration::from_secs(2),
        authenticated_idle: Duration::from_secs(7),
    };
    let started = tokio::time::Instant::now();
    let mut tracker = PeerIdleTracker::new(limits, false, started);
    assert_eq!(tracker.deadline, started + Duration::from_secs(2));
    tracker.synchronize_authentication(true, started + Duration::from_secs(1));
    assert_eq!(tracker.deadline, started + Duration::from_secs(8));
    tracker.note_peer_traffic(true, started + Duration::from_secs(3));
    assert_eq!(tracker.deadline, started + Duration::from_secs(10));
}

#[test]
fn accepts_utf8_split_between_network_reads() {
    let encoded = "消息".as_bytes();
    let mut pending = encoded[..2].to_vec();
    let mut output = String::new();
    append_utf8(&mut pending, &mut output).unwrap();
    assert!(output.is_empty());
    pending.extend_from_slice(&encoded[2..]);
    append_utf8(&mut pending, &mut output).unwrap();
    assert_eq!(output, "消息");
}

#[test]
fn websocket_frames_must_start_with_markup() {
    assert!(crate::transport_parsing::websocket_frame_starts_with_markup("<response/>"));
    assert!(
        crate::transport_parsing::websocket_frame_starts_with_markup(
            "<?xml version='1.0'?><response/>"
        )
    );
    for invalid in ["", " <response/>", "\n<response/>", "x<response/>"] {
        assert!(
            !crate::transport_parsing::websocket_frame_starts_with_markup(invalid),
            "{invalid:?}"
        );
    }
}

#[test]
fn websocket_accepts_a_strict_utf8_xml_declaration() {
    let mut framer = XmlEntityFramer::default();
    assert_eq!(
        take_websocket_frame("<?xml version='1.0' encoding='UTF-8'?><open xmlns='urn:ietf:params:xml:ns:xmpp-framing'/>", &mut framer, MAX_XMPP_FRAME_BYTES).unwrap(),
        "<open xmlns='urn:ietf:params:xml:ns:xmpp-framing'/>"
    );
    assert!(take_websocket_frame(
        "<?xml version='1.0'?><message xmlns='jabber:client'/>",
        &mut framer,
        MAX_XMPP_FRAME_BYTES,
    )
    .is_err());
}

#[test]
fn websocket_message_contains_exactly_one_frame_and_no_stream_whitespace() {
    let mut framer = XmlEntityFramer::default();
    assert_eq!(
        take_websocket_frame(
            "<message xmlns='jabber:client'/>",
            &mut framer,
            MAX_XMPP_FRAME_BYTES
        )
        .unwrap(),
        "<message xmlns='jabber:client'/>"
    );
    for invalid in [
        "",
        " <message xmlns='jabber:client'/>",
        "<message xmlns='jabber:client'/> ",
        "<message xmlns='jabber:client'/><presence xmlns='jabber:client'/>",
        "<message xmlns='jabber:client'>",
    ] {
        assert!(
            take_websocket_frame(
                invalid,
                &mut XmlEntityFramer::default(),
                MAX_XMPP_FRAME_BYTES
            )
            .is_err(),
            "{invalid:?}"
        );
    }
}

#[test]
fn websocket_frame_honors_the_advertised_one_mib_octet_limit() {
    let oversized = format!(
        "<message xmlns='jabber:client'><body>{}</body></message>",
        "x".repeat(MAX_XMPP_FRAME_BYTES)
    );
    assert!(take_websocket_frame(
        &oversized,
        &mut XmlEntityFramer::default(),
        MAX_XMPP_FRAME_BYTES
    )
    .is_err());
}

#[test]
fn websocket_stream_headers_require_the_framing_namespace() {
    let server_open = websocket_server_open("example.test");
    let document = roxmltree::Document::parse(&server_open).unwrap();
    let root = document.root_element();
    assert_eq!(root.tag_name().namespace(), Some(WEBSOCKET_FRAMING_NS));
    assert_eq!(root.attribute("from"), Some("example.test"));
    assert_eq!(root.attribute("version"), Some("1.0"));
    assert_eq!(
        root.attribute(("http://www.w3.org/XML/1998/namespace", "lang")),
        Some("en")
    );
    assert!(!websocket_has_invalid_stream_header_namespace(
        "<open xmlns='urn:ietf:params:xml:ns:xmpp-framing'/>"
    ));
    assert!(!websocket_has_invalid_stream_header_namespace(
        "<message xmlns='jabber:client'/>"
    ));
    assert!(websocket_has_invalid_stream_header_namespace(
        "<open xmlns='jabber:client'/>"
    ));
    assert!(websocket_has_invalid_stream_header_namespace("<close/>"));
    assert!(!websocket_close_has_content(
        "<close xmlns='urn:ietf:params:xml:ns:xmpp-framing'/>"
    ));
    assert!(websocket_close_has_content(
        "<close xmlns='urn:ietf:params:xml:ns:xmpp-framing'> </close>"
    ));
    assert!(websocket_close_has_content(
        "<close xmlns='urn:ietf:params:xml:ns:xmpp-framing'><x/></close>"
    ));
}

#[tokio::test]
async fn tcp_initial_header_failure_opens_errors_and_closes_the_stream() {
    let (mut client, mut server) = tokio::io::duplex(4096);
    tcp_fatal_error(
        &mut server,
        "example.test",
        true,
        &crate::xmpp::xml_util::stream_error("invalid-namespace"),
    )
    .await
    .unwrap();
    drop(server);
    let mut received = String::new();
    client.read_to_string(&mut received).await.unwrap();
    assert!(received.starts_with("<stream:stream from='example.test'"));
    assert!(received.contains("<invalid-namespace"));
    assert!(received.ends_with("</stream:stream>"));
}

#[tokio::test]
async fn tcp_backend_failure_is_a_terminal_internal_server_error_on_wire() {
    let (mut client, mut server) = tokio::io::duplex(4096);
    tcp_fatal_error(
        &mut server,
        "example.test",
        false,
        &crate::xmpp::xml_util::stream_error("internal-server-error"),
    )
    .await
    .unwrap();
    drop(server);
    let mut received = String::new();
    client.read_to_string(&mut received).await.unwrap();
    assert!(received.contains("<internal-server-error"));
    assert!(received.ends_with("</stream:stream>"));
}

#[tokio::test]
async fn tcp_terminal_write_failure_returns_instead_of_hanging() {
    let (client, mut server) = tokio::io::duplex(1);
    drop(client);
    let result = tokio::time::timeout(
        Duration::from_millis(250),
        tcp_fatal_error(
            &mut server,
            "example.test",
            false,
            &crate::xmpp::xml_util::stream_error("internal-server-error"),
        ),
    )
    .await;
    assert!(result.is_ok(), "terminal write exceeded the test bound");
    assert!(result.unwrap().is_err());
}
