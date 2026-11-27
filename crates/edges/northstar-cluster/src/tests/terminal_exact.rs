use super::*;
use crate::node_delivery::build_node_delivery_payload;
use std::collections::BTreeMap;

const AVAILABLE: &str = "<presence from='alice@example.test/Tablet' to='bob@example.test'/>";
const UNAVAILABLE: &str =
    "<presence from='alice@example.test/Tablet' to='bob@example.test' type='unavailable'/>";

fn payload(
    kind: Option<ExactControlKind>,
    generation: i64,
    connection: Uuid,
    stanza: &str,
) -> serde_json::Value {
    let control = kind.map(|kind| ExactControl {
        kind,
        account_id: ORIGINAL,
        auth_generation: generation,
        expected_connections: BTreeMap::from([(ORIGINAL_JID.to_owned(), connection)]),
        roster_version: None,
        blocklist_revision: None,
        remote_peer: None,
        source: Some(ExactControlSource {
            account_id: Uuid::from_u128(55),
            auth_generation: 9,
            connection_id: Uuid::from_u128(56),
            full_jid: "alice@example.test/Tablet".to_owned(),
        }),
        sequence: None,
    });
    build_node_delivery_payload(
        TARGET,
        stanza,
        NodeDeliveryOptions {
            exact_control: control.as_ref(),
            ..NodeDeliveryOptions::default()
        },
        None,
        &[],
        None,
        ("request", "nonce"),
    )
}

async fn deliver(
    fixture: &DirectDeliveryFixture,
    json: serde_json::Value,
) -> Option<(usize, Option<String>)> {
    fixture
        .dispatch
        .test_exact_control_delivery(
            &fixture.admission,
            &fixture.policy,
            &fixture.mix_caps,
            &json,
        )
        .await
}

#[tokio::test]
async fn old_directed_and_terminal_controls_are_rejected() {
    let fixture = DirectDeliveryFixture::new();
    let mut receiver = fixture.add_session(ORIGINAL_JID, ORIGINAL, 0);
    for stanza in [AVAILABLE, UNAVAILABLE] {
        let mut legacy = payload(None, 1, ORIGINAL, stanza);
        assert_eq!(deliver(&fixture, legacy.clone()).await, None);
        legacy["available_only"] = serde_json::json!(true);
        assert_eq!(deliver(&fixture, legacy).await, None);
    }
    assert!(receiver.try_recv().is_err());
}

#[tokio::test]
async fn terminal_presence_uses_only_the_captured_route_and_generation() {
    let fixture = DirectDeliveryFixture::new();
    let mut receiver = fixture.add_session(ORIGINAL_JID, ORIGINAL, 0);
    let mut sibling = fixture.add_session(RECREATED_JID, ORIGINAL, 0);
    for (kind, stanza) in [
        (ExactControlKind::DirectedPresence, AVAILABLE),
        (ExactControlKind::UnavailablePresence, UNAVAILABLE),
        (ExactControlKind::TeardownUnavailable, UNAVAILABLE),
    ] {
        assert_eq!(
            deliver(&fixture, payload(Some(kind), 1, ORIGINAL, stanza)).await,
            Some((1, Some(ORIGINAL_JID.to_owned())))
        );
        receiver.try_recv().unwrap();
        for (generation, connection) in [(2, ORIGINAL), (1, RECREATED)] {
            assert_eq!(
                deliver(
                    &fixture,
                    payload(Some(kind), generation, connection, stanza)
                )
                .await,
                Some((0, None))
            );
        }
        assert!(receiver.try_recv().is_err());
        assert!(sibling.try_recv().is_err());
    }
}
