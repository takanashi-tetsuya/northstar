use super::*;
use crate::node_delivery::build_node_delivery_payload;
use serde_json::{json, Value};

const OWNER: Uuid = Uuid::from_u128(616);
const SOURCE: &str = "alice@example.test/Tablet";
const SIBLING: &str = "bob@example.test/Sibling";
const UNAVAILABLE: &str = "bob@example.test/Unavailable";
const OLD: &str = "bob@example.test/Old";
const AVAILABLE: &str = "<presence from='alice@example.test/Tablet' to='bob@example.test'/>";
const APPROVAL: &str =
    "<presence from='alice@example.test' to='bob@example.test' type='subscribed'/>";

async fn deliver(fixture: &DirectDeliveryFixture, json: &Value) -> Option<(usize, Option<String>)> {
    fixture
        .dispatch
        .test_exact_control_delivery(&fixture.admission, &fixture.policy, &fixture.mix_caps, json)
        .await
}

fn control(kind: ExactControlKind, routes: &[(&str, Uuid)]) -> ExactControl {
    ExactControl {
        kind,
        account_id: ORIGINAL,
        auth_generation: 1,
        expected_connections: routes
            .iter()
            .map(|&(jid, id)| (jid.to_owned(), id))
            .collect(),
        source: (kind != ExactControlKind::SubscriptionPresence).then(|| ExactControlSource {
            account_id: OWNER,
            auth_generation: 1,
            connection_id: OWNER,
            full_jid: SOURCE.to_owned(),
        }),
        roster_version: None,
        blocklist_revision: None,
        remote_peer: None,
        sequence: None,
    }
}

fn payload(target: &str, stanza: &str, options: NodeDeliveryOptions<'_>) -> Value {
    build_node_delivery_payload(
        target,
        stanza,
        options,
        None,
        &[],
        None,
        ("request", "nonce"),
    )
}

#[tokio::test]
async fn old_presence_controls_are_rejected() {
    let fixture = DirectDeliveryFixture::new();
    let mut recipient = fixture.add_session(ORIGINAL_JID, ORIGINAL, 0);
    for (flag, stanza) in [
        ("current_presence_replay", AVAILABLE),
        ("available_only", AVAILABLE),
        ("probe_response", AVAILABLE),
        ("presence_probe", AVAILABLE),
        ("presence_subscription", APPROVAL),
    ] {
        let mut json = json!({
            "protocol_version": NODE_PROTOCOL_VERSION,
            "target": TARGET,
            "stanza": stanza,
        });
        json[flag] = json!(true);
        assert_eq!(deliver(&fixture, &json).await, None, "{flag}");
    }
    assert!(recipient.try_recv().is_err());
}

#[tokio::test]
async fn v15_presence_delivers_only_to_the_captured_connection_and_generation() {
    let fixture = DirectDeliveryFixture::new();
    let mut captured = fixture.add_session(ORIGINAL_JID, ORIGINAL, 0);
    let mut sibling = fixture.add_session(SIBLING, ORIGINAL, 0);
    for kind in [
        ExactControlKind::CurrentPresenceReplay,
        ExactControlKind::AvailablePresence,
        ExactControlKind::ProbeResponse,
    ] {
        let mut control = control(kind, &[(ORIGINAL_JID, ORIGINAL)]);
        let exact_payload = |control: &ExactControl| {
            payload(
                TARGET,
                AVAILABLE,
                NodeDeliveryOptions {
                    exact_control: Some(control),
                    ..NodeDeliveryOptions::default()
                },
            )
        };
        assert_eq!(
            deliver(&fixture, &exact_payload(&control)).await,
            Some((1, Some(ORIGINAL_JID.to_owned())))
        );
        assert!(captured.try_recv().is_ok());
        assert!(sibling.try_recv().is_err());

        control.auth_generation += 1;
        assert_eq!(
            deliver(&fixture, &exact_payload(&control)).await,
            Some((0, None))
        );
        control.auth_generation -= 1;
        control
            .expected_connections
            .insert(ORIGINAL_JID.to_owned(), RECREATED);
        assert_eq!(
            deliver(&fixture, &exact_payload(&control)).await,
            Some((0, None))
        );
        assert!(captured.try_recv().is_err());
    }
}

#[tokio::test]
async fn v15_subscription_fans_out_only_to_captured_available_resources() {
    let fixture = DirectDeliveryFixture::new();
    let mut captured = fixture.add_session(ORIGINAL_JID, ORIGINAL, 0);
    let mut sibling = fixture.add_session(SIBLING, ORIGINAL, 0);
    let mut unavailable = fixture.add_session(UNAVAILABLE, ORIGINAL, 0);
    let mut replacement = fixture.add_session(OLD, ORIGINAL, 0);
    fixture
        .mix_caps
        .sessions
        .get(UNAVAILABLE)
        .unwrap()
        .available
        .store(false, Ordering::Release);
    let authority = ClusterPresenceAuthority {
        owner_id: OWNER,
        owner_auth_generation: 1,
        recipient_id: ORIGINAL,
        recipient_auth_generation: 1,
    };
    let control = control(
        ExactControlKind::SubscriptionPresence,
        &[
            (ORIGINAL_JID, ORIGINAL),
            (UNAVAILABLE, ORIGINAL),
            (OLD, RECREATED),
        ],
    );
    let json = payload(
        TARGET,
        APPROVAL,
        NodeDeliveryOptions {
            exact_control: Some(&control),
            presence_authority: Some(authority),
            ..NodeDeliveryOptions::default()
        },
    );
    assert_eq!(json["protocol_version"], EXACT_CONTROL_DELIVERY_VERSION);
    assert_eq!(json["presence_subscription"], false);
    let result = fixture
        .dispatch
        .test_subscription_after_authority_validation(
            &fixture.admission,
            &fixture.policy,
            &fixture.mix_caps,
            &json,
            authority,
        )
        .await;
    assert_eq!(result, Some((1, Some(ORIGINAL_JID.to_owned()))));
    assert!(captured.try_recv().is_ok());
    assert!(sibling.try_recv().is_err());
    assert!(unavailable.try_recv().is_err());
    assert!(replacement.try_recv().is_err());
}
