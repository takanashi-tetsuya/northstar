use super::*;
use crate::message_routing::carbons::{count_unacknowledged_carbon, exact_carbon_receipt};
use northstar_message_application::telemetry::{
    PersonalMessageTelemetry, PersonalMessageTelemetryCells,
};
use std::sync::atomic::AtomicU64;

fn envelope(target: &str, stanza: &str) -> serde_json::Value {
    serde_json::json!({
        "target": target,
        "stanza": stanza,
        "protocol_version": EXACT_MESSAGE_DELIVERY_VERSION,
        "carbons_only": true,
        "delivery": NodeDeliveryContract::Volatile {},
        "expected_user_id": ORIGINAL,
        "expected_auth_generation": 1,
        "expected_connections": { (ORIGINAL_JID): ORIGINAL },
    })
}

fn wrapper() -> String {
    northstar_message_core::validation::carbon_message("received", TARGET, TARGET, STANZA).unwrap()
}

async fn deliver(fixture: &DirectDeliveryFixture, envelope: &serde_json::Value) -> usize {
    fixture
        .dispatch
        .test_direct_message_delivery(
            &fixture.admission,
            &fixture.policy,
            &fixture.mix_caps,
            envelope,
        )
        .await
        .0
}

fn enable_carbon(fixture: &DirectDeliveryFixture, jid: &str) {
    fixture
        .mix_caps
        .sessions
        .get(jid)
        .unwrap()
        .carbons
        .store(true, Ordering::Release);
}

fn fixture(
    pause: Option<Arc<(tokio::sync::Notify, tokio::sync::Notify)>>,
) -> DirectDeliveryFixture {
    let fixture = DirectDeliveryFixture::new();
    *fixture.message_ports.1.lock().unwrap() = Some(super::super::unused_ports::CarbonPolicy {
        account: ORIGINAL,
        pause,
    });
    fixture
}

#[tokio::test]
async fn exact_carbon_envelope_reaches_only_the_named_opted_in_connection() {
    let fixture = fixture(None);
    let mut output = fixture.add_session(ORIGINAL_JID, ORIGINAL, 0);
    let mut other = fixture.add_session(RECREATED_JID, ORIGINAL, 0);
    assert_eq!(deliver(&fixture, &envelope(TARGET, &wrapper())).await, 0);
    assert!(output.try_recv().is_err());
    enable_carbon(&fixture, ORIGINAL_JID);
    enable_carbon(&fixture, RECREATED_JID);
    assert_eq!(deliver(&fixture, &envelope(TARGET, &wrapper())).await, 1);
    let item = output.try_recv().unwrap();
    assert_eq!(
        roxmltree::Document::parse(&item.stanza)
            .unwrap()
            .root_element()
            .attribute("to"),
        Some(ORIGINAL_JID)
    );
    assert!(item.durable_source.is_none());
    assert!(other.try_recv().is_err());
}

#[tokio::test]
async fn remote_disable_while_policy_is_pending_skips_queue() {
    let pause = Arc::new((tokio::sync::Notify::new(), tokio::sync::Notify::new()));
    let fixture = fixture(Some(Arc::clone(&pause)));
    let mut output = fixture.add_session(ORIGINAL_JID, ORIGINAL, 0);
    enable_carbon(&fixture, ORIGINAL_JID);
    let carbon = envelope(TARGET, &wrapper());
    let (delivered, ()) = tokio::join!(deliver(&fixture, &carbon), async {
        pause.0.notified().await;
        fixture
            .mix_caps
            .sessions
            .get(ORIGINAL_JID)
            .unwrap()
            .carbons
            .store(false, Ordering::Release);
        pause.1.notify_one();
    });
    assert_eq!(delivered, 0);
    assert!(output.try_recv().is_err());
}

#[tokio::test]
async fn remote_replacement_is_not_in_the_captured_carbon_audience() {
    let fixture = fixture(None);
    let mut original = fixture.add_session(ORIGINAL_JID, ORIGINAL, 0);
    enable_carbon(&fixture, ORIGINAL_JID);
    let (replacement, mut output) = test_online_session(ORIGINAL, 1, RECREATED, "Phone", 4);
    replacement.carbons.store(true, Ordering::Release);
    fixture
        .mix_caps
        .sessions
        .insert(ORIGINAL_JID.to_owned(), replacement);
    assert_eq!(deliver(&fixture, &envelope(TARGET, &wrapper())).await, 0);
    assert!(original.try_recv().is_err());
    assert!(output.try_recv().is_err());
}

#[test]
fn v13_negative_receipt_counts_as_dropped_not_as_an_opt_out() {
    let ack = serde_json::json!({
        "request_id": "request", "nonce": "nonce", "node_id": "peer",
        "delivered": 0, "accepted_full_jid": null,
    });
    let expected = DeliveryAckExpectation {
        request_id: "request",
        nonce: "nonce",
        node_id: "peer",
        target_jid: TARGET,
        primary: false,
        delivery: Some(NodeDeliveryContract::Volatile {}),
        require_delivery_contract: true,
        mix_capable_only: false,
        transport_receipt_required: false,
        mix_transport_receipt_required: false,
    };
    let receipt = validated_exact_message_ack(&ack.to_string(), expected).unwrap();
    let receipt = exact_carbon_receipt(&serde_json::from_value(ack).unwrap(), receipt);
    let metrics = northstar_telemetry::metrics::Metrics::default();
    let drops = AtomicU64::new(0);
    let telemetry = PersonalMessageTelemetry::new(PersonalMessageTelemetryCells {
        routing_duration: &metrics.routing_duration_seconds,
        rate_limited: &drops,
        abuse_backend_failures: &drops,
        messages_routed: &drops,
        post_accept_failures: &drops,
        durable_queue_acceptances: &drops,
        volatile_queue_acceptances: &drops,
        carbon_delivery_failures: &drops,
        carbon_target_timeouts: &drops,
        cluster_legacy_acceptances: &drops,
    });
    assert!(!receipt.delivered);
    if !receipt.acknowledged {
        count_unacknowledged_carbon(&telemetry);
    }
    assert_eq!(drops.load(Ordering::Relaxed), 1);
}
