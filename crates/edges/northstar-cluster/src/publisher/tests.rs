use super::*;
use crate::tests::{seed_test_peer_authority, verification_manager};
use northstar_roster_core::RosterEventSource;
use northstar_security::cluster_bus::{test_configuration_pair, SignedClusterEnvelope};
use northstar_time::{DateTime, Utc};

const ISSUED_AT: i64 = 1_800_000_000;

struct FixedPublicationEvents(AtomicU64);

impl RosterEventSource for FixedPublicationEvents {
    fn now(&self) -> DateTime<Utc> {
        DateTime::from_timestamp(ISSUED_AT, 0).expect("valid fixture timestamp")
    }

    fn new_protocol_id(&self) -> uuid::Uuid {
        uuid::Uuid::from_u128(u128::from(self.0.fetch_add(1, Ordering::Relaxed)))
    }
}

#[test]
fn injected_envelope_timestamp_and_request_id_remain_signed() {
    static EVENTS: FixedPublicationEvents = FixedPublicationEvents(AtomicU64::new(42));

    let namespace = "example.test";
    let (sender_security, receiver_security) = test_configuration_pair(namespace);
    let sender = verification_manager(namespace, sender_security);
    let receiver = verification_manager(namespace, Arc::clone(&receiver_security));
    seed_test_peer_authority(&sender, &receiver);
    let mut control = sender.correlated_control_sender();
    control.publisher.events = &EVENTS;
    let request_id = control.new_request_id();
    assert_eq!(request_id, "00000000-0000-0000-0000-00000000002a");
    let channel = control.publisher.key(format!("node:{}", receiver.node_id));
    let raw = control
        .publisher
        .sign_payload(
            &receiver.node_id,
            &channel,
            serde_json::json!({
                "target": "alice@example.test",
                "stanza": "<message/>",
                "request_id": request_id.as_str(),
            }),
        )
        .unwrap();
    let envelope: SignedClusterEnvelope = serde_json::from_str(&raw).unwrap();
    assert_eq!(envelope.issued_at, ISSUED_AT);
    assert_eq!(envelope.expires_at, ISSUED_AT + 10);
    assert_eq!(envelope.request_id.as_deref(), Some(request_id.as_str()));
    assert_eq!(envelope.event_id, request_id);
    envelope
        .verify(
            namespace,
            &receiver.node_id,
            &channel,
            Some(&sender.node_id),
            &receiver_security.peers(),
            ISSUED_AT,
        )
        .unwrap();
}
