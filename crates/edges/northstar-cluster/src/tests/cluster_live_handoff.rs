use super::*;
use northstar_message_application::messaging::{
    DirectMessageRoutePort, DirectMessageRouter, DirectRouteDelivery, DirectRouteOutcome,
    DirectRouteRequest, DirectRouteTarget, ExactMessageRoutePort, FullJidFallbackPort,
    OnlineRoutePort, OnlineRouteResult,
};
use northstar_stream::outbound::{RouteEnqueue, RouteSendError};

const RESERVED: NodeDeliveryContract = NodeDeliveryContract::DurableC2sReserved {
    recipient_id: ORIGINAL,
    message_id: MESSAGE,
    initial_claim_id: MESSAGE,
};

fn request(contract: NodeDeliveryContract, version: &str) -> serde_json::Value {
    serde_json::json!({
        "protocol_version": version,
        "target": TARGET,
        "stanza": STANZA,
        "delivery": contract,
        "primary_one_to_one": true,
    })
}

#[test]
fn initial_claim_round_trips_and_original_contract_still_decodes() {
    let source = initial_source();
    let contract = outbound_delivery_contract(STANZA, TARGET, Some(source), None)
        .unwrap()
        .unwrap();
    assert_eq!(contract, RESERVED);
    let envelope = request(contract, EXACT_MESSAGE_DELIVERY_VERSION);
    assert_eq!(
        envelope["delivery"],
        serde_json::json!({
            "reliability": "durable_c2s_reserved",
            "recipient_id": ORIGINAL,
            "message_id": MESSAGE,
            "initial_claim_id": MESSAGE,
        })
    );
    assert_eq!(
        requested_node_message_delivery(&envelope, true).unwrap(),
        Some(RequestedNodeMessageDelivery::Explicit(RESERVED))
    );
    assert!(
        requested_node_message_delivery(&request(contract, NODE_PROTOCOL_VERSION), true).is_err()
    );

    let unclaimed = DurableDelivery {
        claim_id: None,
        ..source
    };
    assert_eq!(
        outbound_delivery_contract(STANZA, TARGET, Some(unclaimed), None).unwrap(),
        Some(DURABLE)
    );
    assert_eq!(
        requested_node_message_delivery(&request(DURABLE, "13"), true).unwrap(),
        Some(RequestedNodeMessageDelivery::Explicit(DURABLE))
    );
    assert!(outbound_delivery_contract(
        STANZA,
        TARGET,
        Some(DurableDelivery {
            claim_id: Some(Uuid::from_u128(99)),
            ..source
        }),
        None
    )
    .is_err());
}

struct OldPeer {
    receipt: NodeDeliveryReceipt,
    rearmed: Mutex<Vec<DurableDelivery>>,
}

impl OnlineRoutePort for OldPeer {
    type Item = OutboundItem;
    type Session = ();

    fn try_local(&self, _: &(), _: RouteEnqueue) -> Result<(), RouteSendError> {
        unreachable!("no local routes")
    }

    fn record_local_accept(&self, _: bool) {
        unreachable!("no local routes")
    }

    async fn route_available_remote(&self, _: &str, _: &str, _: Option<DurableDelivery>) -> bool {
        unreachable!("chat selects one remote primary")
    }

    async fn route_remote_primary(
        &self,
        _: &str,
        _: &str,
        delivery: Option<DurableDelivery>,
    ) -> OnlineRouteResult {
        assert_eq!(delivery, Some(initial_source()));
        OnlineRouteResult {
            delivered: self.receipt.delivered,
            accepted_full_jid: self.receipt.accepted_full_jid.clone(),
        }
    }
}

impl FullJidFallbackPort for OldPeer {
    fn fallback_sessions(&self, _: &str) -> Vec<(String, ())> {
        unreachable!("the target is bare")
    }

    fn available_priority(&self, _: &()) -> Option<i16> {
        unreachable!("no local routes")
    }

    fn priority(&self, _: &()) -> i16 {
        unreachable!("no local routes")
    }

    async fn privacy_allows_fallback(&self, _: &(), _: &str) -> Result<bool> {
        unreachable!("the target is bare")
    }

    fn post_accept_failed(&self) {
        unreachable!("a negative receipt is an ordinary unrouted result")
    }
}

impl DirectMessageRoutePort for OldPeer {
    fn direct_route_mode(&self) -> northstar_message_core::DirectPostCommitMode {
        northstar_message_core::DirectPostCommitMode::Live
    }

    fn clustered_direct_routes(&self) -> bool {
        true
    }

    async fn rearm_direct_route(&self, delivery: DurableDelivery) {
        self.rearmed.lock().unwrap().push(delivery);
    }
}

impl ExactMessageRoutePort for OldPeer {}

fn initial_source() -> DurableDelivery {
    DurableDelivery {
        recipient_id: ORIGINAL,
        message_id: MESSAGE,
        claim_id: Some(MESSAGE),
    }
}

#[tokio::test]
async fn old_peer_rejection_is_a_correlated_negative_receipt_and_rearms() {
    let request_id = Uuid::new_v4().to_string();
    let nonce = format!("{}{}", Uuid::new_v4(), Uuid::new_v4());
    let expected = DeliveryAckExpectation {
        request_id: &request_id,
        nonce: &nonce,
        node_id: "peer",
        target_jid: TARGET,
        primary: true,
        delivery: Some(RESERVED),
        require_delivery_contract: true,
        mix_capable_only: false,
        transport_receipt_required: false,
        mix_transport_receipt_required: false,
    };
    let mut ack = serde_json::json!({
        "request_id": request_id, "nonce": nonce, "node_id": "peer",
        "delivered": 0, "accepted_full_jid": null,
    });
    let receipt = validated_exact_message_ack(&ack.to_string(), expected).unwrap();
    assert!(receipt.acknowledged && !receipt.delivered);
    let peer = OldPeer {
        receipt,
        rearmed: Mutex::default(),
    };
    let outcome = DirectMessageRouter::route(
        &peer,
        DirectRouteRequest {
            message_type: "chat",
            target: DirectRouteTarget::Bare(TARGET),
            sender: "alice@example.test/Tablet",
            recipient_id: ORIGINAL,
            stanza: STANZA,
            delivery: DirectRouteDelivery::Committed(initial_source()),
            approved_targets: &[],
            enforce_direct_health: true,
        },
    )
    .await
    .unwrap();
    assert_eq!(outcome, DirectRouteOutcome::Unrouted);
    assert_eq!(*peer.rearmed.lock().unwrap(), [initial_source()]);
    ack["nonce"] = serde_json::json!("wrong");
    assert!(validated_exact_message_ack(&ack.to_string(), expected).is_none());
    ack["nonce"] = serde_json::json!(nonce);
    ack["delivered"] = serde_json::json!(1);
    ack["accepted_full_jid"] = serde_json::json!(ORIGINAL_JID);
    assert!(validated_exact_message_ack(&ack.to_string(), expected).is_none());
    ack["delivery"] = serde_json::json!(RESERVED);
    assert!(
        validated_exact_message_ack(&ack.to_string(), expected)
            .unwrap()
            .delivered
    );
}

#[tokio::test]
async fn reserved_delivery_refuses_rotated_and_released_claims() {
    let claim = Arc::new(Mutex::new(Some(MESSAGE)));
    let fixture = DirectDeliveryFixture::with_claim(Arc::clone(&claim));
    let mut output = fixture.add_session(ORIGINAL_JID, ORIGINAL, 1);
    let envelope = request(RESERVED, EXACT_MESSAGE_DELIVERY_VERSION);
    assert_eq!(
        fixture
            .dispatch
            .test_direct_message_delivery(
                &fixture.admission,
                &fixture.policy,
                &fixture.mix_caps,
                &envelope,
            )
            .await,
        (1, Some(ORIGINAL_JID.to_owned()), Some(RESERVED))
    );
    assert_eq!(
        output.try_recv().unwrap().durable_source,
        Some(TransportOwnershipSource::C2s(DurableDelivery {
            recipient_id: ORIGINAL,
            message_id: MESSAGE,
            claim_id: Some(MESSAGE)
        },))
    );
    let mut wrong_payload = envelope.clone();
    wrong_payload["stanza"] = serde_json::json!(STANZA.replace("hello", "changed"));
    assert_eq!(
        fixture
            .dispatch
            .test_direct_message_delivery(
                &fixture.admission,
                &fixture.policy,
                &fixture.mix_caps,
                &wrong_payload,
            )
            .await,
        (0, None, None)
    );
    for changed in [Some(Uuid::from_u128(99)), None] {
        *claim.lock().unwrap() = changed;
        assert_eq!(
            fixture
                .dispatch
                .test_direct_message_delivery(
                    &fixture.admission,
                    &fixture.policy,
                    &fixture.mix_caps,
                    &envelope,
                )
                .await,
            (0, None, None)
        );
        assert!(output.try_recv().is_err());
    }
}

#[tokio::test]
async fn captured_route_refuses_replacement_generation_change_and_unbind() {
    use northstar_message_application::messaging::ExactMessageRoute;
    use northstar_stream::local_routes::session_table::LocalSessionTable;

    let fixture = DirectDeliveryFixture::new();
    let mut original = fixture.add_session(ORIGINAL_JID, ORIGINAL, 1);
    let route = ExactMessageRoute {
        full_jid: ORIGINAL_JID.to_owned(),
        account_id: ORIGINAL,
        auth_generation: 1,
        connection_id: ORIGINAL,
        node_id: None,
    };
    let routes = LocalSessionTable::new(Arc::clone(&fixture.mix_caps.sessions));
    let offer = || {
        routes
            .try_send_exact_message_route(
                &route,
                northstar_stream::outbound::RouteEnqueue::unobserved(OutboundItem::plain(
                    STANZA.to_owned(),
                )),
            )
            .is_ok()
    };
    let mut envelope = request(
        NodeDeliveryContract::Volatile {},
        EXACT_MESSAGE_DELIVERY_VERSION,
    );
    envelope["expected_user_id"] = serde_json::json!(ORIGINAL);
    envelope["expected_auth_generation"] = serde_json::json!(1);
    envelope["expected_connections"] = serde_json::json!({(ORIGINAL_JID): ORIGINAL});
    let deliver = || {
        fixture.dispatch.test_direct_message_delivery(
            &fixture.admission,
            &fixture.policy,
            &fixture.mix_caps,
            &envelope,
        )
    };
    assert!(offer());
    assert_eq!(deliver().await.0, 1);
    assert_eq!(original.try_recv().unwrap().stanza, STANZA);
    assert_eq!(original.try_recv().unwrap().stanza, STANZA);

    let original_session = fixture.mix_caps.sessions.remove(ORIGINAL_JID).unwrap().1;
    let (replacement, mut output) =
        test_online_session(ORIGINAL, 1, Uuid::from_u128(99), "Phone", 4);
    replacement.available.store(true, Ordering::Relaxed);
    fixture
        .mix_caps
        .sessions
        .insert(ORIGINAL_JID.to_owned(), replacement);
    assert!(!offer());
    assert_eq!(deliver().await.0, 0);
    assert!(output.try_recv().is_err());

    let mut changed = original_session;
    changed.auth_generation = 2;
    fixture
        .mix_caps
        .sessions
        .insert(ORIGINAL_JID.to_owned(), changed);
    assert!(!offer());
    assert_eq!(deliver().await.0, 0);
    fixture.mix_caps.sessions.remove(ORIGINAL_JID).unwrap();
    assert!(!offer());
    assert_eq!(deliver().await.0, 0);
    assert!(original.try_recv().is_err());
}

#[tokio::test]
async fn remote_bare_primary_skips_negative_resource_without_affecting_full_jid() {
    let fixture = DirectDeliveryFixture::new();
    let mut output = fixture.add_session(ORIGINAL_JID, ORIGINAL, -1);
    for (target, expected) in [(TARGET, 0), (ORIGINAL_JID, 1)] {
        let mut envelope = request(NodeDeliveryContract::Volatile {}, NODE_PROTOCOL_VERSION);
        let options = crate::routing::primary_message_options(target);
        envelope["target"] = serde_json::json!(target);
        envelope["primary_one_to_one"] = serde_json::json!(options.primary);
        envelope["available_nonnegative_only"] =
            serde_json::json!(options.available_nonnegative_only);
        assert_eq!(
            fixture
                .dispatch
                .test_direct_message_delivery(
                    &fixture.admission,
                    &fixture.policy,
                    &fixture.mix_caps,
                    &envelope,
                )
                .await
                .0,
            expected
        );
    }
    assert_eq!(output.try_recv().unwrap().stanza, STANZA);
    assert!(output.try_recv().is_err());
}

#[tokio::test]
async fn remote_headline_fanout_skips_negative_resource() {
    let fixture = DirectDeliveryFixture::new();
    let mut negative = fixture.add_session(ORIGINAL_JID, ORIGINAL, -1);
    let mut envelope = request(NodeDeliveryContract::Volatile {}, NODE_PROTOCOL_VERSION);
    let options = crate::message_routing::exact::exact_route_mode(TARGET, true);
    envelope["target"] = serde_json::json!(TARGET);
    envelope["available_only"] = serde_json::json!(options.available_only);
    envelope["available_nonnegative_only"] = serde_json::json!(options.available_nonnegative_only);
    assert_eq!(
        fixture
            .dispatch
            .test_direct_message_delivery(
                &fixture.admission,
                &fixture.policy,
                &fixture.mix_caps,
                &envelope,
            )
            .await
            .0,
        0
    );
    assert!(negative.try_recv().is_err());
}
