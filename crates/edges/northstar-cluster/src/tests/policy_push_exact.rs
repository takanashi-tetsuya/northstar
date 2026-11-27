use super::*;
use crate::account_routing::require_policy_push_ack;
use crate::node_delivery::build_node_delivery_payload;
use crate::routing::policy_push_control;
use northstar_message_application::messaging::ExactMessageRoute;
use serde_json::Value;

const CAPTURED: Uuid = Uuid::from_u128(65);
const REPLACEMENT: Uuid = Uuid::from_u128(66);
const BLOCK: &str =
    "<iq type='set'><block xmlns='urn:xmpp:blocking'><item jid='eve@example.test'/></block></iq>";
const PRIVACY: &str =
    "<iq type='set'><query xmlns='jabber:iq:privacy'><list name='work'/></query></iq>";

fn captured_route(target: &str, node: &str) -> ExactMessageRoute {
    ExactMessageRoute {
        full_jid: target.into(),
        account_id: ORIGINAL,
        auth_generation: 1,
        connection_id: CAPTURED,
        node_id: Some(node.into()),
        priority: None,
        available: None,
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

async fn deliver(fixture: &DirectDeliveryFixture, json: &Value) -> Option<(usize, Option<String>)> {
    fixture
        .dispatch
        .test_exact_control_delivery(&fixture.admission, &fixture.policy, &fixture.mix_caps, json)
        .await
}

fn add_observer(
    fixture: &DirectDeliveryFixture,
    target: &str,
    connection_id: Uuid,
) -> (
    northstar_stream::local_routes::session::OnlineSession,
    mpsc::Receiver<OutboundItem>,
) {
    let (_, resource) = target.split_once('/').unwrap();
    let (session, output) = test_online_session(ORIGINAL, 1, connection_id, resource, 4);
    session.blocklist_requested.store(true, Ordering::Release);
    session.privacy_requested.store(true, Ordering::Release);
    fixture
        .mix_caps
        .sessions
        .insert(target.to_owned(), session.clone());
    (session, output)
}

#[tokio::test]
async fn inverse_node_notifications_only_wake_ordered_blocklist_observation() {
    let first_node = DirectDeliveryFixture::new();
    let second_node = DirectDeliveryFixture::new();
    let (first, mut first_output) = add_observer(&first_node, ORIGINAL_JID, CAPTURED);
    let (second, mut second_output) = add_observer(&second_node, RECREATED_JID, CAPTURED);
    let first_epoch = first.blocklist_observation.begin_snapshot();
    let second_epoch = second.blocklist_observation.begin_snapshot();
    assert!(first.blocklist_observation.finish_snapshot(first_epoch, 0));
    assert!(second
        .blocklist_observation
        .finish_snapshot(second_epoch, 0));

    for (fixture, target, node, session, epoch) in [
        (&first_node, ORIGINAL_JID, "node-a", first, first_epoch),
        (&second_node, RECREATED_JID, "node-b", second, second_epoch),
    ] {
        let mut wake = session.blocklist_observation.subscribe();
        for revision in [2, 1] {
            let control = policy_push_control(
                &captured_route(target, node),
                ExactControlKind::BlocklistPush,
                Some(revision),
            );
            let json = payload(
                target,
                BLOCK,
                NodeDeliveryOptions {
                    exact_control: Some(&control),
                    ..NodeDeliveryOptions::default()
                },
            );
            assert_eq!(json["protocol_version"], "15");
            assert_eq!(
                deliver(fixture, &json).await,
                Some((1, Some(target.into())))
            );
            assert_eq!(wake.has_changed().unwrap(), revision == 2);
            drop(wake.borrow_and_update());
            assert_eq!(session.blocklist_observation.cursor(epoch), Some(0));
        }
    }
    assert!(first_output.try_recv().is_err());
    assert!(second_output.try_recv().is_err());
}

#[tokio::test]
async fn legacy_v13_policy_pushes_are_rejected_even_for_interested_resources() {
    let fixture = DirectDeliveryFixture::new();
    let (session, mut output) = add_observer(&fixture, ORIGINAL_JID, CAPTURED);
    session.blocklist_observation.begin_snapshot();
    for (blocklist, stanza) in [(true, BLOCK), (false, PRIVACY)] {
        let json = payload(
            ORIGINAL_JID,
            stanza,
            NodeDeliveryOptions {
                blocklist_requested_only: blocklist,
                privacy_requested_only: !blocklist,
                ..NodeDeliveryOptions::default()
            },
        );
        assert_eq!(json["protocol_version"], "13");
        assert_eq!(deliver(&fixture, &json).await, None);
    }
    assert!(output.try_recv().is_err());
}

#[tokio::test]
async fn privacy_and_blocklist_push_do_not_follow_a_replacement_or_sibling() {
    let fixture = DirectDeliveryFixture::new();
    let (session, mut captured) = add_observer(&fixture, ORIGINAL_JID, CAPTURED);
    let (_, mut sibling) = add_observer(&fixture, RECREATED_JID, REPLACEMENT);
    session.blocklist_observation.begin_snapshot();
    let route = captured_route(ORIGINAL_JID, "node-b");
    let privacy = policy_push_control(&route, ExactControlKind::PrivacyPush, None);
    let privacy_payload = payload(
        ORIGINAL_JID,
        PRIVACY,
        NodeDeliveryOptions {
            exact_control: Some(&privacy),
            ..NodeDeliveryOptions::default()
        },
    );
    assert_eq!(
        deliver(&fixture, &privacy_payload).await,
        Some((1, Some(ORIGINAL_JID.into())))
    );
    assert!(captured.try_recv().unwrap().stanza.contains("name='work'"));
    fixture.mix_caps.sessions.remove(ORIGINAL_JID).unwrap();
    let (session, mut replacement) = add_observer(&fixture, ORIGINAL_JID, REPLACEMENT);
    session.blocklist_observation.begin_snapshot();
    let wake = session.blocklist_observation.subscribe();
    let blocklist = policy_push_control(&route, ExactControlKind::BlocklistPush, Some(1));
    let blocklist_payload = payload(
        ORIGINAL_JID,
        BLOCK,
        NodeDeliveryOptions {
            exact_control: Some(&blocklist),
            ..NodeDeliveryOptions::default()
        },
    );
    for json in [privacy_payload, blocklist_payload] {
        assert_eq!(deliver(&fixture, &json).await, Some((0, None)));
    }
    assert!(!wake.has_changed().unwrap());
    assert!(replacement.try_recv().is_err());
    assert!(sibling.try_recv().is_err());
}

#[tokio::test]
async fn zero_policy_push_ack_is_a_reportable_route_failure() {
    let cluster = ClusterManager::new(None, "example.test", None, None, None, None)
        .await
        .unwrap();
    let route = captured_route(ORIGINAL_JID, "node-b");
    for receipt in [
        cluster.send_to_node_blocklist(&route, 1, BLOCK).await,
        cluster.send_to_node_privacy(&route, PRIVACY).await,
    ] {
        assert!(!*receipt.as_ref().unwrap());
        let error = require_policy_push_ack(receipt, ORIGINAL_JID).unwrap_err();
        assert!(error.to_string().contains(ORIGINAL_JID));
    }
}
