use super::*;

fn response_body_text(response: &BoshHttpResponse) -> &str {
    std::str::from_utf8(response.body.as_ref())
        .expect("BOSH responses are built from server-owned UTF-8 XML")
}

fn response_test_governor() -> Arc<crate::services::sm_capacity::SmMemoryGovernor> {
    crate::services::sm_capacity::SmMemoryGovernor::new(
        1024 * 1024,
        256 * 1024,
        16,
        256 * 1024,
        Arc::new(crate::services::sm_capacity::SmCapacityMetrics::default()),
    )
    .unwrap()
}

#[test]
fn creation_and_auth_flow_shapes_are_strict() {
    let creation = parse_body(
        "<body xmlns='http://jabber.org/protocol/httpbind' rid='1573741820' to='example.test' wait='60' hold='1' ver='1.11' xml:lang='ja' xmpp:version='1.0' xmlns:xmpp='urn:xmpp:xbosh'/>",
        64,
    )
    .unwrap();
    assert_eq!(creation.rid, 1_573_741_820);
    assert!(creation.sid.is_none());
    assert_eq!(creation.xmpp_version.as_deref(), Some("1.0"));
    assert_eq!(creation.language.as_deref(), Some("ja"));

    let auth = parse_body(
        "<body xmlns='http://jabber.org/protocol/httpbind' rid='1573741821' sid='secret'><auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='PLAIN'>AA==</auth></body>",
        64,
    )
    .unwrap();
    assert_eq!(auth.payloads.len(), 1);
    assert!(auth.payloads[0].contains("urn:ietf:params:xml:ns:xmpp-sasl"));
}

#[test]
fn restart_terminate_and_pause_shapes_are_unambiguous() {
    let restart = parse_body(
        "<body xmlns='http://jabber.org/protocol/httpbind' xmlns:xmpp='urn:xmpp:xbosh' rid='12' sid='s' to='example.test' xmpp:restart='true'/>",
        64,
    )
    .unwrap();
    assert!(restart.restart);
    assert!(!restart.terminate);
    assert_eq!(bosh_request_shape_error(&restart, false), None);
    assert_eq!(
        validated_bosh_restart_target(restart.to.as_deref(), "example.test"),
        Ok("example.test".to_owned())
    );
    assert_eq!(
        validated_bosh_restart_target(Some("LOCALHOST"), "localhost"),
        Ok("localhost".to_owned())
    );
    assert_eq!(
        validated_bosh_restart_target(Some("elsewhere.test"), "example.test"),
        Err("improper-addressing")
    );

    let terminate = parse_body(
        "<body xmlns='http://jabber.org/protocol/httpbind' rid='13' sid='s' type='terminate'><presence xmlns='jabber:client' type='unavailable'/></body>",
        64,
    )
    .unwrap();
    assert!(terminate.terminate);
    assert_eq!(terminate.payloads.len(), 1);

    assert!(parse_body(
        "<body xmlns='http://jabber.org/protocol/httpbind' rid='14' sid='s' pause='60'><presence/></body>",
        64,
    )
    .is_ok());
}

#[test]
fn rejects_restricted_xml_unknown_attributes_and_body_text() {
    for body in [
        "<body xmlns='http://jabber.org/protocol/httpbind' rid='1' evil='x'/>",
        "<body xmlns='http://jabber.org/protocol/httpbind' rid='1'>text</body>",
        "<body xmlns='http://jabber.org/protocol/httpbind' rid='1'><!--x--></body>",
        "<body xmlns='http://jabber.org/protocol/httpbind' rid='1'>&xxe;</body>",
        "<evil xmlns='http://jabber.org/protocol/httpbind' rid='1'/>",
        "<body xmlns='http://jabber.org/protocol/httpbind' rid='1' secure='true'/>",
        "<body xmlns='http://jabber.org/protocol/httpbind' rid='1' content='text/html'/>",
        "<body xmlns='http://jabber.org/protocol/httpbind' rid='1' content='text/xml; charset=utf-7'/>",
    ] {
        assert!(parse_body(body, 64).is_err(), "accepted {body}");
    }
    assert!(parse_body(
        "<?xml version='1.0' encoding='UTF-8'?><body xmlns='http://jabber.org/protocol/httpbind' rid='1'/>",
        64,
    )
    .is_ok());
}

#[test]
fn request_and_stanza_limits_are_enforced() {
    let body =
        "<body xmlns='http://jabber.org/protocol/httpbind' rid='1' sid='s'><iq/><iq/></body>";
    assert_eq!(parse_body(body, 1).unwrap_err(), "policy-violation");
    let oversized_stanza = format!(
        "<body xmlns='http://jabber.org/protocol/httpbind' rid='2' sid='s'><message><body>{}</body></message></body>",
        "x".repeat(crate::xmpp::MAX_XMPP_FRAME_BYTES)
    );
    assert_eq!(
        parse_body(&oversized_stanza, 64).unwrap_err(),
        "policy-violation"
    );
    assert!(parse_body(&"x".repeat(4 * 1024 * 1024 + 1), 64).is_err());
    assert!(parse_body(
        "<body xmlns='http://jabber.org/protocol/httpbind' rid='9007199254740991'/>",
        64
    )
    .is_err());
    assert!(parse_body(
        "<body xmlns='http://jabber.org/protocol/httpbind' rid='9007199254740991' sid='s' type='terminate'/>",
        64
    )
    .is_ok());
}

#[test]
fn structural_complexity_is_rejected_before_bosh_dom_processing() {
    // `parse_body` deliberately routes the complete HTTP body through the
    // same XmlEntityFramer used by TCP, WebSocket, S2S and components
    // before calling roxmltree::Document::parse. These inputs are small in
    // bytes but otherwise create disproportionate DOM/attribute state.
    let element_flood = format!(
        "<body xmlns='http://jabber.org/protocol/httpbind' rid='2' sid='s'><message>{}</message></body>",
        "<x/>".repeat(20_000)
    );
    assert!(element_flood.len() < 4 * 1024 * 1024);
    assert!(parse_body(&element_flood, 64).is_err());

    let attributes = (0..=128)
        .map(|index| format!(" a{index}='x'"))
        .collect::<String>();
    let attribute_flood = format!(
        "<body xmlns='http://jabber.org/protocol/httpbind' rid='3' sid='s'><message{attributes}/></body>"
    );
    assert!(parse_body(&attribute_flood, 64).is_err());
}

#[test]
fn sid_keys_are_secret_and_session_fixation_resistant() {
    let manager = BoshManager::new(4, 2);
    let first = manager.sid_key("attacker-selected");
    let second = manager.sid_key("attacker-selected-2");
    assert_ne!(first, second);
    assert_ne!(
        first.as_slice(),
        Sha256::digest(b"attacker-selected").as_slice()
    );
}

#[tokio::test]
async fn request_cap_is_exactly_two() {
    let handle = BoshHandle {
        commands: mpsc::channel(1).0,
        requests: Arc::new(Semaphore::new(2)),
        control_request: Arc::new(Semaphore::new(1)),
        overactivity: CancellationToken::new(),
    };
    let first = Arc::clone(&handle.requests).try_acquire_owned().unwrap();
    let second = Arc::clone(&handle.requests).try_acquire_owned().unwrap();
    assert!(Arc::clone(&handle.requests).try_acquire_owned().is_err());
    assert!(Arc::clone(&handle.control_request)
        .try_acquire_owned()
        .is_ok());
    drop(first);
    assert!(Arc::clone(&handle.requests).try_acquire_owned().is_ok());
    drop(second);
}

fn overactivity_test_request(attributes: &str) -> BoshRequest {
    parse_body(
        &format!(
            "<body xmlns='http://jabber.org/protocol/httpbind' rid='2' sid='overactivity-test' {attributes}/>"
        ),
        64,
    )
    .unwrap()
}

fn overactivity_test_session() -> (BoshManager, BoshHandle, mpsc::Receiver<BoshCommand>) {
    let manager = BoshManager::new(1, 1);
    let (commands, receiver) = mpsc::channel(4);
    let handle = BoshHandle {
        commands,
        requests: Arc::new(Semaphore::new(2)),
        control_request: Arc::new(Semaphore::new(1)),
        overactivity: CancellationToken::new(),
    };
    manager
        .inner
        .sessions
        .insert(manager.sid_key("overactivity-test"), handle.clone());
    (manager, handle, receiver)
}

fn queue_overactivity_test_request(handle: &BoshHandle) -> oneshot::Receiver<BoshHttpResponse> {
    let (response, receiver) = oneshot::channel();
    assert!(handle
        .commands
        .try_send(BoshCommand::Request {
            request: Box::new(overactivity_test_request("")),
            response,
        })
        .is_ok());
    receiver
}

#[test]
fn overactivity_rejected_normal_request_does_not_wait_for_full_mailbox() {
    let (manager, handle, receiver) = overactivity_test_session();
    let _requests = Arc::clone(&handle.requests)
        .try_acquire_many_owned(2)
        .unwrap();
    for _ in 0..4 {
        // An enqueued request outlives its cancelled HTTP responder.
        drop(queue_overactivity_test_request(&handle));
    }
    let response = manager
        .request(overactivity_test_request(""))
        .now_or_never()
        .expect("overactivity rejection must finish without a mailbox waiter");
    assert!(response_body_text(&response).contains("policy-violation"));
    assert!(handle.overactivity.is_cancelled());
    assert_eq!(receiver.len(), 4);
    assert_eq!(handle.requests.available_permits(), 0);
    assert_eq!(handle.control_request.available_permits(), 1);
}

#[test]
fn overactivity_rejected_pause_and_terminate_do_not_wait_for_full_mailbox() {
    for attributes in ["pause='1'", "type='terminate'"] {
        let (manager, handle, receiver) = overactivity_test_session();
        let _requests = Arc::clone(&handle.requests)
            .try_acquire_many_owned(2)
            .unwrap();
        let _control = Arc::clone(&handle.control_request)
            .try_acquire_owned()
            .unwrap();
        for _ in 0..4 {
            drop(queue_overactivity_test_request(&handle));
        }
        let response = manager
            .request(overactivity_test_request(attributes))
            .now_or_never()
            .expect("extra-control rejection must finish without a mailbox waiter");
        assert!(response_body_text(&response).contains("policy-violation"));
        assert!(handle.overactivity.is_cancelled());
        assert_eq!(receiver.len(), 4);
        assert_eq!(handle.control_request.available_permits(), 0);
    }
}

#[test]
fn overactivity_rejections_coalesce_and_survive_caller_drop() {
    let (manager, handle, receiver) = overactivity_test_session();
    let actor_signal = handle.overactivity.clone();
    let requests = Arc::clone(&handle.requests)
        .try_acquire_many_owned(2)
        .unwrap();
    assert!(manager
        .request(overactivity_test_request(""))
        .now_or_never()
        .is_some());
    drop(requests);
    for _ in 0..64 {
        let response = manager
            .request(overactivity_test_request(""))
            .now_or_never()
            .expect("a signalled session must not start another request");
        assert!(response_body_text(&response).contains("policy-violation"));
        handle.overactivity.cancel();
    }
    assert_eq!(receiver.len(), 0);
    assert_eq!(handle.requests.available_permits(), 2);
    drop(handle);
    drop(manager);
    assert!(actor_signal.is_cancelled());
}

#[test]
fn overactivity_signal_precedes_queued_requests() {
    let (_manager, handle, mut receiver) = overactivity_test_session();
    let mut response = queue_overactivity_test_request(&handle);
    handle.overactivity.cancel();
    assert!(matches!(
        next_bosh_command(&mut receiver, &handle.overactivity).now_or_never(),
        Some(Some(BoshCommand::Overactivity))
    ));
    assert_eq!(receiver.len(), 1);
    assert!(matches!(
        response.try_recv(),
        Err(oneshot::error::TryRecvError::Empty)
    ));
}

#[test]
fn overactivity_signal_survives_cancelled_wait_and_precedes_channel_close() {
    let (sender, mut receiver) = mpsc::channel(1);
    let overactivity = CancellationToken::new();
    // Dropping a pending selection must not consume a later signal.
    assert!(next_bosh_command(&mut receiver, &overactivity)
        .now_or_never()
        .is_none());
    overactivity.cancel();
    drop(sender);
    assert!(matches!(
        next_bosh_command(&mut receiver, &overactivity).now_or_never(),
        Some(Some(BoshCommand::Overactivity))
    ));
}

#[test]
fn overactivity_signal_wakes_an_already_pending_selection() {
    use std::future::Future;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::{Context, Poll, Wake, Waker};

    struct WakeCount(AtomicUsize);
    impl Wake for WakeCount {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    let (_sender, mut receiver) = mpsc::channel(1);
    let overactivity = CancellationToken::new();
    let wake_count = Arc::new(WakeCount(AtomicUsize::new(0)));
    let waker = Waker::from(Arc::clone(&wake_count));
    let mut context = Context::from_waker(&waker);
    let mut selection = Box::pin(next_bosh_command(&mut receiver, &overactivity));
    assert!(selection.as_mut().poll(&mut context).is_pending());
    overactivity.cancel();
    assert!(wake_count.0.load(Ordering::SeqCst) > 0);
    assert!(matches!(
        selection.as_mut().poll(&mut context),
        Poll::Ready(Some(BoshCommand::Overactivity))
    ));
}

#[test]
fn overactivity_preserves_selected_operation_before_next_command() {
    let (_manager, handle, mut receiver) = overactivity_test_session();
    let mut selected_response = queue_overactivity_test_request(&handle);
    let mut queued_response = queue_overactivity_test_request(&handle);
    let (complete, completion) = oneshot::channel();
    // Model the actor's select-then-await boundary with a finite local
    // operation. This does not exercise protocol or durable finalization.
    let mut operation = Box::pin(async {
        let Some(BoshCommand::Request { response, .. }) =
            next_bosh_command(&mut receiver, &handle.overactivity).await
        else {
            panic!("the first request must be selected before overload");
        };
        completion.await.unwrap();
        let _ = response.send(terminal_response("selected-operation-completed"));
        next_bosh_command(&mut receiver, &handle.overactivity).await
    });
    assert!(operation.as_mut().now_or_never().is_none());
    handle.overactivity.cancel();
    assert!(operation.as_mut().now_or_never().is_none());
    assert!(matches!(
        selected_response.try_recv(),
        Err(oneshot::error::TryRecvError::Empty)
    ));
    complete.send(()).unwrap();
    assert!(matches!(
        operation.as_mut().now_or_never(),
        Some(Some(BoshCommand::Overactivity))
    ));
    drop(operation);
    assert!(response_body_text(&selected_response.try_recv().unwrap())
        .contains("selected-operation-completed"));
    assert_eq!(receiver.len(), 1);
    assert!(matches!(
        queued_response.try_recv(),
        Err(oneshot::error::TryRecvError::Empty)
    ));
}

#[test]
fn request_body_reads_are_globally_load_shed() {
    let manager = BoshManager::new(4, 1);
    let permit = manager.try_body_read().unwrap();
    assert!(manager.try_body_read().is_none());
    drop(permit);
    assert!(manager.try_body_read().is_some());
}

#[test]
fn rid_window_buffers_only_one_out_of_order_request() {
    assert_eq!(classify_rid(101, 101), RidDisposition::Expected);
    assert_eq!(classify_rid(101, 102), RidDisposition::BufferedOneAhead);
    assert_eq!(classify_rid(101, 100), RidDisposition::Old);
    assert_eq!(classify_rid(101, 103), RidDisposition::OutsideWindow);
}

#[test]
fn client_response_ack_cannot_discard_an_unsent_response() {
    assert!(valid_client_response_ack(true, 12, 14, Some(12)));
    assert!(!valid_client_response_ack(true, 12, 14, Some(13)));
    assert!(!valid_client_response_ack(true, 14, 14, Some(14)));
    assert!(!valid_client_response_ack(false, 12, 14, Some(12)));
    assert!(valid_client_response_ack(false, 12, 14, None));
}

#[test]
fn parses_and_normalizes_bosh_sha1_keys() {
    let creation = parse_body(
        "<body xmlns='http://jabber.org/protocol/httpbind' rid='1' to='example.test' newkey='AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'/>",
        64,
    )
    .unwrap();
    assert_eq!(
        creation.newkey.as_deref(),
        Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
    );
    assert!(creation.key.is_none());
    assert!(parse_body(
        "<body xmlns='http://jabber.org/protocol/httpbind' rid='1' to='example.test' key='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'/>",
        64,
    )
    .is_err());
    assert!(parse_body(
        "<body xmlns='http://jabber.org/protocol/httpbind' rid='2' sid='s' key='short'/>",
        64,
    )
    .is_err());
}

#[test]
fn verifies_and_rotates_the_bosh_key_sequence() {
    fn digest_hex(value: &str) -> String {
        Sha1::digest(value.as_bytes())
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }

    let k0 = "0123456789abcdef0123456789abcdef01234567";
    let k1 = digest_hex(k0);
    let k2 = digest_hex(&k1);
    let mut expected = Some(k2);
    assert!(advance_bosh_key_sequence(&mut expected, Some(&k1), None));
    assert_eq!(expected.as_deref(), Some(k1.as_str()));

    let replacement = "abcdef0123456789abcdef0123456789abcdef01";
    assert!(advance_bosh_key_sequence(
        &mut expected,
        Some(k0),
        Some(replacement),
    ));
    assert_eq!(expected.as_deref(), Some(replacement));
    assert!(!advance_bosh_key_sequence(&mut expected, None, None));
    assert!(!advance_bosh_key_sequence(
        &mut expected,
        Some("ffffffffffffffffffffffffffffffffffffffff"),
        None,
    ));

    let mut unprotected = None;
    assert!(advance_bosh_key_sequence(&mut unprotected, None, None));
    assert!(!advance_bosh_key_sequence(
        &mut unprotected,
        None,
        Some(replacement),
    ));
}

#[test]
fn duplicate_rid_replays_only_an_identical_request() {
    let request = parse_body(
        "<body xmlns='http://jabber.org/protocol/httpbind' rid='12' sid='s'/>",
        64,
    )
    .unwrap();
    let response = BoshHttpResponse {
        body: Bytes::from(
            "<body xmlns='http://jabber.org/protocol/httpbind'><iq/></body>".to_owned(),
        ),
        content_type: "text/xml; charset=utf-8".to_owned(),
    };
    let mut replay = VecDeque::from([CachedResponse {
        rid: request.rid,
        fingerprint: request.fingerprint,
        response: response.clone(),
        durable_ownership: Arc::new(crate::xmpp::outbound::BoshResponseOwnership {
            c2s_message_ids: vec![uuid::Uuid::from_u128(7)],
            mix_delivery_ids: Vec::new(),
        }),
        transport_receipts: Vec::new(),
        owned_at: Instant::now(),
        response_bytes: response.body.len(),
        replays: 0,
    }]);
    let (replayed, terminate, durable_ownership) = replay_response(&mut replay, &request).unwrap();
    assert!(!terminate);
    assert_eq!(replayed.body, response.body);
    assert_eq!(
        durable_ownership.c2s_message_ids,
        vec![uuid::Uuid::from_u128(7)]
    );
    assert!(durable_ownership.mix_delivery_ids.is_empty());

    let changed = parse_body(
        "<body xmlns='http://jabber.org/protocol/httpbind' rid='12' sid='s'><presence/></body>",
        64,
    )
    .unwrap();
    let (rejected, terminate, durable_ownership) = replay_response(&mut replay, &changed).unwrap();
    assert!(terminate);
    assert!(durable_ownership.is_empty());
    assert!(response_body_text(&rejected).contains("condition='bad-request'"));

    let mut bounded = VecDeque::from([CachedResponse {
        rid: request.rid,
        fingerprint: request.fingerprint,
        response,
        durable_ownership: Arc::new(crate::xmpp::outbound::BoshResponseOwnership::default()),
        transport_receipts: Vec::new(),
        owned_at: Instant::now(),
        response_bytes: 64,
        replays: MAX_RESPONSE_REPLAYS,
    }]);
    let now = Instant::now();
    assert!(!bosh_unacknowledged_limit_exceeded(&bounded, 1, now));
    assert!(bosh_unacknowledged_limit_exceeded(
        &bounded,
        MAX_UNACKNOWLEDGED_RESPONSE_BYTES,
        now
    ));
    let mut count_limited = bounded.clone();
    count_limited.push_back(bounded.front().unwrap().clone());
    assert!(bosh_unacknowledged_limit_exceeded(&count_limited, 1, now));
    count_limited.pop_back();
    count_limited.front_mut().unwrap().owned_at = now - MAX_RESPONSE_ACK_AGE;
    assert!(bosh_unacknowledged_limit_exceeded(&count_limited, 1, now));
    let (rejected, terminate, durable_ownership) = replay_response(&mut bounded, &request).unwrap();
    assert!(terminate);
    assert!(durable_ownership.is_empty());
    assert!(response_body_text(&rejected).contains("condition='policy-violation'"));
}

#[test]
fn response_payload_preserves_durable_fences_until_rid_binding() {
    let delivery = crate::xmpp::outbound::DurableDelivery {
        recipient_id: uuid::Uuid::from_u128(1),
        message_id: uuid::Uuid::from_u128(2),
        claim_id: Some(uuid::Uuid::from_u128(3)),
    };
    let first = crate::xmpp::outbound::OutboundItem::durable(
        "<message id='durable'/>".to_owned(),
        delivery,
    );
    let second = crate::xmpp::outbound::OutboundItem::plain("<presence/>".to_owned());
    let mut bytes = first.stanza.len() + second.stanza.len();
    let mut output = VecDeque::from([first.clone(), second.clone()]);
    let governor = response_test_governor();
    let (payload, sources, receipts, holds, selected) =
        take_response_payload(&mut output, &mut bytes, 4_096, &governor).unwrap();
    assert_eq!(payload, format!("{}{}", first.stanza, second.stanza));
    assert_eq!(
        sources,
        vec![crate::xmpp::outbound::TransportOwnershipSource::C2s(
            delivery
        )]
    );
    assert!(receipts.is_empty());
    assert!(holds.is_empty());
    assert_eq!(selected.len(), 2);
    assert_eq!(bytes, 0);
    assert!(output.is_empty());

    let oversized = crate::xmpp::outbound::OutboundItem::durable("<message/>".repeat(32), delivery);
    let mut bytes = oversized.stanza.len();
    let mut output = VecDeque::from([oversized.clone()]);
    assert!(take_response_payload(&mut output, &mut bytes, 256, &governor).is_err());
    assert_eq!(
        output.front().map(|item| &item.stanza),
        Some(&oversized.stanza)
    );
    assert_eq!(bytes, output.front().unwrap().stanza.len());
}

#[test]
fn superseded_bosh_source_is_removed_without_losing_other_response_items() {
    let stale = crate::xmpp::outbound::DurableDelivery {
        recipient_id: uuid::Uuid::from_u128(1),
        message_id: uuid::Uuid::from_u128(2),
        claim_id: Some(uuid::Uuid::from_u128(3)),
    };
    let survivor = crate::xmpp::outbound::DurableDelivery {
        message_id: uuid::Uuid::from_u128(4),
        ..stale
    };
    let (receipt, mut received) = mpsc::unbounded_channel();
    let mut output = VecDeque::from([
        crate::xmpp::outbound::OutboundItem::with_transport_receipt(
            "<presence id='before'/>".to_owned(),
            receipt,
        ),
        crate::xmpp::outbound::OutboundItem::durable("<message id='stale'/>".to_owned(), stale),
        crate::xmpp::outbound::OutboundItem::durable(
            "<message id='survivor'/>".to_owned(),
            survivor,
        ),
        crate::xmpp::outbound::OutboundItem::plain("<presence id='after'/>".to_owned()),
    ]);
    let mut bytes = output.iter().map(|item| item.stanza.len()).sum();
    let (_, _, abandoned_receipts, _, selected) =
        take_response_payload(&mut output, &mut bytes, 4_096, &response_test_governor()).unwrap();
    drop(abandoned_receipts);
    assert!(received.try_recv().is_err());
    assert!(restore_response_items(
        &mut output,
        &mut bytes,
        selected,
        Some(stale.message_id)
    ));
    assert_eq!(
        bytes,
        output.iter().map(|item| item.stanza.len()).sum::<usize>()
    );
    let (payload, sources, receipts, _, _) =
        take_response_payload(&mut output, &mut bytes, 4_096, &response_test_governor()).unwrap();
    assert_eq!(
        payload,
        "<presence id='before'/><message id='survivor'/><presence id='after'/>"
    );
    assert_eq!(
        sources,
        vec![crate::xmpp::outbound::TransportOwnershipSource::C2s(
            survivor
        )]
    );
    assert_eq!(receipts.len(), 1);
    receipts[0].send(()).unwrap();
    assert!(received.try_recv().is_ok());
    assert!(received.try_recv().is_err());
}

#[test]
fn only_exact_typed_supersession_allows_bosh_response_rebuild() {
    let message_id = uuid::Uuid::from_u128(42);
    let superseded =
        anyhow::Error::new(crate::xmpp::outbound::DurableDeliverySuperseded { message_id })
            .context("bind BOSH response");
    assert_eq!(superseded_bosh_message_id(&superseded), Some(message_id));
    for error in [
        anyhow::anyhow!("database timeout"),
        anyhow::anyhow!("durable delivery claim changed before BOSH response binding"),
    ] {
        assert_eq!(superseded_bosh_message_id(&error), None);
    }
}

#[test]
fn response_payload_keeps_typed_mix_source_until_durable_rid_binding() {
    let c2s = crate::xmpp::outbound::DurableDelivery {
        recipient_id: uuid::Uuid::from_u128(11),
        message_id: uuid::Uuid::from_u128(12),
        claim_id: Some(uuid::Uuid::from_u128(13)),
    };
    let mix = crate::xmpp::outbound::MixDelivery {
        delivery_id: uuid::Uuid::from_u128(21),
        lease_token: uuid::Uuid::from_u128(22),
    };
    let c2s_item =
        crate::xmpp::outbound::OutboundItem::durable("<message id='c2s'/>".to_owned(), c2s);
    let (mix_item, _handoff) =
        crate::xmpp::outbound::OutboundItem::durable_mix("<message id='mix'/>".to_owned(), mix);
    let mut output = VecDeque::from([c2s_item.clone(), mix_item.clone()]);
    let mut bytes = output.iter().map(|item| item.stanza.len()).sum();

    let (payload, sources, receipts, holds, selected) =
        take_response_payload(&mut output, &mut bytes, 4_096, &response_test_governor()).unwrap();

    assert_eq!(payload, format!("{}{}", c2s_item.stanza, mix_item.stanza));
    assert_eq!(
        sources,
        vec![
            crate::xmpp::outbound::TransportOwnershipSource::C2s(c2s),
            crate::xmpp::outbound::TransportOwnershipSource::Mix(mix),
        ]
    );
    assert!(receipts.is_empty());
    assert!(holds.is_empty());
    assert_eq!(selected.len(), 2);
    assert!(output.is_empty());
    assert_eq!(bytes, 0);
}

#[test]
fn response_payload_keeps_resume_control_and_replay_before_late_suffix() {
    // Resume processing pushes these entries before it starts the
    // post-transport route-publication task. A stanza accepted by that
    // task is therefore necessarily appended behind the complete replay,
    // even if the task runs before this HTTP response is assembled.
    let control = crate::xmpp::outbound::OutboundItem::plain(
        "<resumed xmlns='urn:xmpp:sm:3' h='0' previd='session'/>".to_owned(),
    );
    let replay = crate::xmpp::outbound::OutboundItem::plain(
        "<message id='durable-replay'><body>old</body></message>".to_owned(),
    );
    let suffix = crate::xmpp::outbound::OutboundItem::plain(
        "<message id='volatile-suffix'><body>new</body></message>".to_owned(),
    );
    let mut output = VecDeque::from([control.clone(), replay.clone(), suffix.clone()]);
    let mut bytes = output.iter().map(|item| item.stanza.len()).sum();
    let (payload, _, _, _, _) =
        take_response_payload(&mut output, &mut bytes, 4_096, &response_test_governor()).unwrap();
    assert_eq!(
        payload,
        format!("{}{}{}", control.stanza, replay.stanza, suffix.stanza)
    );
}

#[test]
fn resume_auth_control_marker_is_atomic_and_control_only() {
    for activate_route in [false, true] {
        let payload = || ResumeTransportParts {
            control: "<resumed xmlns='urn:xmpp:sm:3'/>".to_owned(),
            post_control: vec!["<features/>".to_owned()],
            replay: vec!["<message id='replay'/>".to_owned()],
            activate_route,
            auth_publication: activate_route.then(|| {
                crate::xmpp::auth_publication::fixture_control(
                    "<resumed xmlns='urn:xmpp:sm:3'/>",
                    uuid::Uuid::from_u128(701),
                )
                .0
            }),
            transient_capacity: Vec::new(),
        };
        let prefix = "<presence/>";
        for (max_stanzas, max_bytes) in [(3, 4096), (4, prefix.len())] {
            let mut output = VecDeque::from([crate::xmpp::outbound::OutboundItem::plain(
                prefix.to_owned(),
            )]);
            let mut bytes = prefix.len();
            let pointer = output[0].stanza.as_ptr();
            assert!(!queue_bosh_resume_payload(
                &mut output,
                &mut bytes,
                max_stanzas,
                max_bytes,
                payload(),
            ));
            assert_eq!(output.len(), 1);
            assert_eq!(output[0].stanza.as_ptr(), pointer);
            assert_eq!(bytes, prefix.len());
            assert!(!output[0].is_bosh_auth_control());
        }

        let mut output = VecDeque::from([crate::xmpp::outbound::OutboundItem::plain(
            prefix.to_owned(),
        )]);
        let mut bytes = prefix.len();
        assert!(queue_bosh_resume_payload(
            &mut output,
            &mut bytes,
            4,
            4096,
            payload(),
        ));
        assert_eq!(
            output
                .iter()
                .map(|item| item.stanza.as_str())
                .collect::<Vec<_>>(),
            [
                prefix,
                "<resumed xmlns='urn:xmpp:sm:3'/>",
                "<features/>",
                "<message id='replay'/>"
            ]
        );
        assert_eq!(
            output
                .iter()
                .map(crate::xmpp::outbound::OutboundItem::is_bosh_auth_control)
                .collect::<Vec<_>>(),
            [false, activate_route, false, false]
        );
        assert_eq!(
            bytes,
            output.iter().map(|item| item.stanza.len()).sum::<usize>()
        );
    }
}

#[test]
fn bosh_response_and_transport_drop_retain_then_release_resume_capacity() {
    let metrics = Arc::new(crate::services::sm_capacity::SmCapacityMetrics::default());
    let governor = crate::services::sm_capacity::SmMemoryGovernor::new(
        1024 * 1024,
        256 * 1024,
        16,
        256 * 1024,
        Arc::clone(&metrics),
    )
    .unwrap();
    let source = VecDeque::from([crate::xmpp::outbound::SmUnackedStanza::plain(
        "<message id='resume'><body>".to_owned() + &"x".repeat(4_096) + "</body></message>",
    )]);
    let action = crate::xmpp::protocol::ResumePayload::from_sm_unacked(
        &governor,
        "<resumed xmlns='urn:xmpp:sm:3' h='0' previd='session'/>".to_owned(),
        Vec::new(),
        &source,
        false,
    )
    .unwrap();
    let mut output = VecDeque::new();
    let mut bytes = 0;
    assert!(queue_bosh_resume_payload(
        &mut output,
        &mut bytes,
        16,
        64 * 1024,
        action.into_transport_parts(),
    ));
    let (body, _, _, holds, _) =
        take_response_payload(&mut output, &mut bytes, 64 * 1024, &governor).unwrap();
    assert!(output.is_empty());
    assert!(!holds.is_empty());
    let cached = BoshHttpResponse {
        body: bosh_response_bytes(body, holds),
        content_type: "text/xml; charset=utf-8".to_owned(),
    };
    let transport = cors_response(StatusCode::OK, cached.clone());
    drop(cached);
    assert!(
        metrics
            .reserved_bytes
            .load(std::sync::atomic::Ordering::Relaxed)
            > 0
    );
    // Dropping the HTTP response models both a completed body and a
    // failed/cancelled Hyper transport; the ref-counted Bytes owner keeps
    // the RAII holds alive through either path.
    drop(transport);
    assert_eq!(
        metrics
            .reserved_bytes
            .load(std::sync::atomic::Ordering::Relaxed),
        0
    );
}

#[tokio::test]
async fn duplicate_pending_rid_releases_old_http_request_and_keeps_newest() {
    let request = parse_body(
        "<body xmlns='http://jabber.org/protocol/httpbind' rid='2' sid='s'/>",
        64,
    )
    .unwrap();
    let (old_tx, old_rx) = oneshot::channel();
    let mut pending = PendingRequest {
        request: request.clone(),
        responders: vec![old_tx],
    };
    let (new_tx, mut new_rx) = oneshot::channel();
    assert!(replace_duplicate_responders(
        &mut pending,
        &request,
        new_tx,
        "text/xml"
    ));
    assert!(response_body_text(&old_rx.await.unwrap()).contains("type='error'"));
    assert!(matches!(
        new_rx.try_recv(),
        Err(tokio::sync::oneshot::error::TryRecvError::Empty)
    ));
    pending
        .responders
        .pop()
        .unwrap()
        .send(BoshHttpResponse {
            body: Bytes::from("latest"),
            content_type: "text/xml".to_owned(),
        })
        .unwrap();
    assert_eq!(new_rx.await.unwrap().body.as_ref(), b"latest");
}

#[test]
fn inactivity_runs_only_without_a_held_request() {
    let now = Instant::now();
    let limit = Duration::from_secs(30);
    assert_eq!(inactivity_deadline(now, limit, false), Some(now + limit));
    assert_eq!(inactivity_deadline(now, limit, true), None);
}

#[test]
fn out_of_order_request_is_released_at_the_negotiated_wait_deadline() {
    let now = Instant::now();
    let mut request = parse_body(
        "<body xmlns='http://jabber.org/protocol/httpbind' rid='102' sid='s'/>",
        64,
    )
    .unwrap();
    request.received_at = now - Duration::from_secs(6);
    let mut buffered = BTreeMap::from([(
        102,
        PendingRequest {
            request,
            responders: Vec::new(),
        },
    )]);
    assert_eq!(
        take_expired_buffered(&mut buffered, Duration::from_secs(5), now).len(),
        1
    );
    assert!(buffered.is_empty());
}

#[test]
fn remote_stream_errors_and_maximum_rid_acknowledgements_are_well_formed() {
    // XEP-0124 section 13 specifies an empty type='terminate' body.
    // `newkey` is client-to-connection-manager key-sequence state and is
    // never reflected in the termination acknowledgement.
    let graceful = bosh_body_element(None, true, None).finish();
    assert!(graceful.contains("type='terminate'"));
    assert!(!graceful.contains("newkey="));

    let remote = bosh_body_element(Some("remote-stream-error"), true, None).finish();
    assert!(remote.contains("type='terminate'"));
    assert!(remote.contains("condition='remote-stream-error'"));
    assert!(remote.contains("xmlns:stream='http://etherx.jabber.org/streams'"));

    let ack = bosh_body_element(None, false, Some(MAX_RID)).finish();
    assert!(ack.contains(&format!("ack='{MAX_RID}'")));
}

#[test]
fn response_ack_never_claims_an_out_of_order_rid_across_a_gap() {
    fn pending(request: BoshRequest) -> PendingRequest {
        PendingRequest {
            request,
            responders: Vec::new(),
        }
    }

    let ahead = parse_body(
        "<body xmlns='http://jabber.org/protocol/httpbind' rid='102' sid='s'/>",
        64,
    )
    .unwrap();
    let mut buffered = BTreeMap::from([(102, pending(ahead))]);
    assert_eq!(highest_contiguous_buffered_rid(101, 102, &buffered), None);

    let expected = parse_body(
        "<body xmlns='http://jabber.org/protocol/httpbind' rid='101' sid='s'/>",
        64,
    )
    .unwrap();
    buffered.insert(101, pending(expected));
    assert_eq!(
        highest_contiguous_buffered_rid(101, 102, &buffered),
        Some(102)
    );
}

#[test]
fn secure_transport_requires_a_trusted_https_proxy() {
    let peer: IpAddr = "127.0.0.1".parse().unwrap();
    let mut headers = HeaderMap::new();
    headers.insert("x-forwarded-proto", HeaderValue::from_static("https"));
    assert!(secure_proxy_request(peer, &headers, &[peer]));
    assert!(!secure_proxy_request(peer, &headers, &[]));
    headers.insert("x-forwarded-proto", HeaderValue::from_static("https, http"));
    assert!(!secure_proxy_request(peer, &headers, &[peer]));
    headers.insert("x-forwarded-proto", HeaderValue::from_static("https"));
    headers.append("x-forwarded-proto", HeaderValue::from_static("https"));
    assert!(!secure_proxy_request(peer, &headers, &[peer]));
    headers.insert("x-forwarded-proto", HeaderValue::from_static("http"));
    assert!(!secure_proxy_request(peer, &headers, &[peer]));
}

#[test]
fn request_headers_ignore_media_type_but_reject_compression_and_ambiguity() {
    let mut headers = HeaderMap::new();
    assert!(supported_request_headers(&headers));
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/xml; charset=utf-8"),
    );
    assert!(supported_request_headers(&headers));
    headers.insert(header::CONTENT_ENCODING, HeaderValue::from_static("gzip"));
    assert!(!supported_request_headers(&headers));
    headers.remove(header::CONTENT_ENCODING);
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("text/html"));
    assert!(supported_request_headers(&headers));
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("text/xml"));
    headers.append(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/xml"),
    );
    assert!(!supported_request_headers(&headers));
}

#[tokio::test]
async fn cors_is_scoped_and_cache_safe() {
    let response = http_bind_options().await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert_eq!(response.headers()[header::ACCESS_CONTROL_ALLOW_ORIGIN], "*");
    assert_eq!(
        response.headers()[header::ACCESS_CONTROL_ALLOW_METHODS],
        "POST, OPTIONS"
    );
}

#[test]
fn terminal_xml_escapes_untrusted_conditions() {
    let response = terminal_response("bad' condition");
    assert!(response_body_text(&response).contains("bad&apos; condition"));
    assert!(!response_body_text(&response).contains("condition='bad' condition'"));
}

#[test]
fn bosh_version_negotiation_is_bounded() {
    assert_eq!(negotiated_bosh_version(Some("1.6")), "1.6");
    assert_eq!(negotiated_bosh_version(Some("1.99")), "1.11");
    assert_eq!(negotiated_bosh_version(Some("garbage")), "1.11");
    assert!(parse_body(
        "<body xmlns='http://jabber.org/protocol/httpbind' rid='1' ver='garbage'/>",
        64
    )
    .is_err());
}

#[test]
fn wait_negotiation_respects_the_client_and_server_caps() {
    assert_eq!(negotiated_wait(None, 60), 60);
    assert_eq!(negotiated_wait(Some(0), 60), 0);
    assert_eq!(negotiated_wait(Some(120), 60), 60);
    assert_eq!(negotiated_hold(Some(1), 0), 0);
    assert_eq!(negotiated_hold(Some(2), 60), 1);
}

#[test]
fn polling_interval_uses_http_arrival_time_and_exact_boundary() {
    let now = Instant::now();
    assert!(within_polling_interval(
        now,
        now + Duration::from_secs(4),
        Duration::from_secs(5)
    ));
    assert!(!within_polling_interval(
        now,
        now + Duration::from_secs(5),
        Duration::from_secs(5)
    ));
    assert!(!within_polling_interval(
        now + Duration::from_secs(1),
        now,
        Duration::from_secs(5)
    ));
}

#[test]
fn held_empty_overactivity_exempts_pause_terminate_and_payload_requests() {
    let now = Instant::now();
    let mut previous = parse_body(
        "<body xmlns='http://jabber.org/protocol/httpbind' rid='10' sid='s'/>",
        64,
    )
    .unwrap();
    let mut current = parse_body(
        "<body xmlns='http://jabber.org/protocol/httpbind' rid='11' sid='s'/>",
        64,
    )
    .unwrap();
    previous.received_at = now;
    current.received_at = now + Duration::from_secs(1);
    assert!(too_frequent_held_empty_request(
        &previous,
        &current,
        Duration::from_secs(5)
    ));

    current.pause = Some(30);
    assert!(!too_frequent_held_empty_request(
        &previous,
        &current,
        Duration::from_secs(5)
    ));
    current.pause = None;
    current.terminate = true;
    assert!(!too_frequent_held_empty_request(
        &previous,
        &current,
        Duration::from_secs(5)
    ));
    current.terminate = false;
    current.payloads.push("<presence/>".to_owned());
    assert!(!too_frequent_held_empty_request(
        &previous,
        &current,
        Duration::from_secs(5)
    ));
}
