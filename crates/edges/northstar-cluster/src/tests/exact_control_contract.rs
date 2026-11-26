use super::*;
use crate::node_delivery::build_node_delivery_payload;
use roxmltree::Document;
use serde_json::{json, Value};
use std::collections::BTreeMap;

const SOURCE_JID: &str = "alice@remote.test/Tablet";
const CAPTURED: Uuid = Uuid::from_u128(51);
const OTHER: Uuid = Uuid::from_u128(52);
const ROSTER: &str = "<iq xmlns='jabber:client' type='set' id='original'><query xmlns='jabber:iq:roster' ver='42'><item jid='room@mix.example.test'/></query></iq>";
const ANNOTATED_ROSTER: &str = "<iq xmlns='jabber:client' type='set' id='original'><query xmlns='jabber:iq:roster' ver='42'><item jid='room@mix.example.test'><channel xmlns='urn:xmpp:mix:roster:0' participant-id='original-participant'/></item></query></iq>";
const BLOCK: &str =
    "<iq type='set'><block xmlns='urn:xmpp:blocking'><item jid='alice@remote.test'/></block></iq>";
const PRIVACY: &str =
    "<iq type='set'><query xmlns='jabber:iq:privacy'><list name='quiet'/></query></iq>";
const AVAILABLE: &str = "<presence from='alice@remote.test/Tablet'/>";
const UNAVAILABLE: &str = "<presence from='alice@remote.test/Tablet' type='unavailable'/>";
const SUBSCRIPTION: &str = "<presence from='alice@remote.test/Tablet' type='subscribed'/>";
const WRONG_PRESENCE_SHAPE: &str = "<message from='alice@remote.test/Tablet'/>";

fn exact_control(kind: ExactControlKind) -> ExactControl {
    use ExactControlKind::*;

    let source = match kind {
        AvailablePresence
        | DirectedPresence
        | UnavailablePresence
        | CurrentPresenceReplay
        | ProbeResponse
        | TeardownUnavailable
        | BlockingPresence => Some(ExactControlSource {
            account_id: Uuid::from_u128(60),
            auth_generation: 0,
            connection_id: Uuid::from_u128(61),
            full_jid: SOURCE_JID.to_owned(),
        }),
        _ => None,
    };
    ExactControl {
        kind,
        account_id: ORIGINAL,
        auth_generation: 1,
        expected_connections: BTreeMap::from([(ORIGINAL_JID.to_owned(), CAPTURED)]),
        roster_version: (kind == RosterPush).then_some(42),
        blocklist_revision: (kind == BlocklistPush).then_some(9),
        remote_peer: (kind == FederatedInboundPresence).then(|| "remote.test".to_owned()),
        source,
        sequence: None,
    }
}

#[test]
fn exact_control_version_is_newer_and_uses_the_v14_peer_gate() {
    let version: u16 = EXACT_CONTROL_DELIVERY_VERSION.parse().unwrap();
    assert!(version > EXACT_MESSAGE_DELIVERY_VERSION.parse::<u16>().unwrap());
    assert!(version > NODE_PROTOCOL_VERSION.parse::<u16>().unwrap());
    assert!(supports_exact_control(Some(NODE_PROTOCOL_VERSION)));
    for peer in [None, Some("12"), Some("14"), Some("15"), Some("invalid")] {
        assert!(!supports_exact_control(peer));
    }
}

#[test]
fn every_exact_control_kind_checks_its_shape_and_required_metadata() {
    use ExactControlKind::*;

    for (kind, valid, wrong) in [
        (RosterPush, ROSTER, PRIVACY),
        (BlocklistPush, BLOCK, PRIVACY),
        (PrivacyPush, PRIVACY, ROSTER),
        (SubscriptionPresence, SUBSCRIPTION, AVAILABLE),
        (CurrentPresenceReplay, AVAILABLE, UNAVAILABLE),
        (AvailablePresence, AVAILABLE, UNAVAILABLE),
        (DirectedPresence, AVAILABLE, WRONG_PRESENCE_SHAPE),
        (UnavailablePresence, UNAVAILABLE, AVAILABLE),
        (ProbeResponse, AVAILABLE, WRONG_PRESENCE_SHAPE),
        (BlockingPresence, UNAVAILABLE, WRONG_PRESENCE_SHAPE),
        (TeardownUnavailable, UNAVAILABLE, AVAILABLE),
        (FederatedInboundPresence, AVAILABLE, WRONG_PRESENCE_SHAPE),
    ] {
        let control = exact_control(kind);
        let stanza = Document::parse(valid).unwrap();
        assert!(
            validate_exact_control(&control, TARGET, &stanza).is_ok(),
            "{kind:?}"
        );
        assert!(
            validate_exact_control(&control, ORIGINAL_JID, &stanza).is_ok(),
            "{kind:?}"
        );
        let wrong = Document::parse(wrong).unwrap();
        assert!(
            validate_exact_control(&control, TARGET, &wrong).is_err(),
            "{kind:?}"
        );
        let mut wrong_version = control.clone();
        wrong_version.roster_version = if kind == RosterPush { None } else { Some(42) };
        assert!(
            validate_exact_control(&wrong_version, TARGET, &stanza).is_err(),
            "{kind:?}"
        );
        let mut wrong_revision = control.clone();
        wrong_revision.blocklist_revision = if kind == BlocklistPush { None } else { Some(9) };
        assert!(
            validate_exact_control(&wrong_revision, TARGET, &stanza).is_err(),
            "{kind:?}"
        );
        let mut wrong_peer = control.clone();
        wrong_peer.remote_peer = if kind == FederatedInboundPresence {
            None
        } else {
            Some("remote.test".to_owned())
        };
        assert!(
            validate_exact_control(&wrong_peer, TARGET, &stanza).is_err(),
            "{kind:?}"
        );
        if control.source.is_some() {
            let mut wrong_source = control;
            wrong_source.source.as_mut().unwrap().full_jid = "alice@remote.test/Phone".to_owned();
            assert!(
                validate_exact_control(&wrong_source, TARGET, &stanza).is_err(),
                "{kind:?}"
            );
            wrong_source.source = None;
            assert!(
                validate_exact_control(&wrong_source, TARGET, &stanza).is_err(),
                "{kind:?}"
            );
        }
    }
}

#[test]
fn exact_controls_check_jids_account_fences_and_positive_versions() {
    let mut control = exact_control(ExactControlKind::RosterPush);
    let roster = Document::parse(ROSTER).unwrap();
    for routes in [
        BTreeMap::new(),
        BTreeMap::from([(TARGET.to_owned(), CAPTURED)]),
        BTreeMap::from([("other@example.test/Phone".to_owned(), CAPTURED)]),
        BTreeMap::from([("Bob@example.test/Phone".to_owned(), CAPTURED)]),
        BTreeMap::from([(ORIGINAL_JID.to_owned(), Uuid::nil())]),
    ] {
        let invalid = ExactControl {
            expected_connections: routes,
            ..control.clone()
        };
        assert!(validate_exact_control(&invalid, TARGET, &roster).is_err());
    }
    control
        .expected_connections
        .insert(RECREATED_JID.to_owned(), OTHER);
    assert!(validate_exact_control(&control, TARGET, &roster).is_ok());
    assert!(validate_exact_control(&control, ORIGINAL_JID, &roster).is_err());
    for invalid in [
        ExactControl {
            auth_generation: -1,
            ..control.clone()
        },
        ExactControl {
            account_id: Uuid::nil(),
            ..control.clone()
        },
        ExactControl {
            roster_version: Some(0),
            ..control.clone()
        },
        ExactControl {
            roster_version: Some(43),
            ..control
        },
    ] {
        assert!(validate_exact_control(&invalid, TARGET, &roster).is_err());
    }
    let mut blocklist = exact_control(ExactControlKind::BlocklistPush);
    for stanza in [
        "<iq type='set'><unblock xmlns='urn:xmpp:blocking'><item jid='alice@remote.test'/></unblock></iq>",
        "<iq type='set'><unblock xmlns='urn:xmpp:blocking'/></iq>",
    ] {
        assert!(validate_exact_control(&blocklist, TARGET, &Document::parse(stanza).unwrap()).is_ok());
    }
    blocklist.blocklist_revision = Some(0);
    assert!(validate_exact_control(&blocklist, TARGET, &Document::parse(BLOCK).unwrap()).is_err());
    let mut federated = exact_control(ExactControlKind::FederatedInboundPresence);
    let presence = Document::parse(AVAILABLE).unwrap();
    for peer in [
        "alice@remote.test",
        "remote.test/Tablet",
        "invalid domain.test",
    ] {
        federated.remote_peer = Some(peer.to_owned());
        assert!(validate_exact_control(&federated, TARGET, &presence).is_err());
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
async fn sender_refuses_to_combine_exact_controls_and_message_delivery() {
    let cluster = ClusterManager::new(None, "example.test", None, None, None, None)
        .await
        .unwrap();
    let sender = cluster.node_delivery();
    let control = exact_control(ExactControlKind::RosterPush);
    let options = NodeDeliveryOptions {
        exact_control: Some(&control),
        ..NodeDeliveryOptions::default()
    };
    assert!(sender
        .send_to_node_receipt("node-b", TARGET, ROSTER, options)
        .await
        .is_ok());
    let message_routes = NodeDeliveryOptions {
        exact_message_routes: Some(&control.expected_connections),
        ..options
    };
    let durable = NodeDeliveryOptions {
        durable_delivery: Some(DurableDelivery {
            recipient_id: ORIGINAL,
            message_id: MESSAGE,
            claim_id: None,
        }),
        ..options
    };
    for (stanza, options) in [
        (ROSTER, message_routes),
        (ROSTER, durable),
        (STANZA, options),
    ] {
        assert!(sender
            .send_to_node_receipt("node-b", TARGET, stanza, options)
            .await
            .is_err());
    }
}

#[test]
fn v15_sender_payload_carries_the_control_and_existing_fences() {
    let control = exact_control(ExactControlKind::RosterPush);
    let json = payload(
        TARGET,
        ROSTER,
        NodeDeliveryOptions {
            exact_control: Some(&control),
            ..NodeDeliveryOptions::default()
        },
    );
    assert_eq!(json["protocol_version"], "15");
    assert_eq!(json["exact_control"], json!(control));
    assert_eq!(json["exact_control"]["kind"], "roster_push");
    assert_eq!(json["expected_user_id"], json!(ORIGINAL));
    assert_eq!(json["expected_auth_generation"], 1);
    assert_eq!(
        json["expected_connections"],
        json!(control.expected_connections)
    );
    assert_eq!(json["roster_requested_only"], true);
    assert_eq!(json["roster_version"], 42);
    assert!(json["delivery"].is_null());
}

#[test]
fn v13_roster_payload_bytes_match_the_existing_wire_shape() {
    // Same roster input and recipient fence as roster_push_keeps_original_user_version_and_annotation.
    let json = payload(
        "alice@example.test",
        ROSTER,
        NodeDeliveryOptions {
            expected_user_id: Some(Uuid::from_u128(43)),
            roster_requested_only: true,
            roster_version: Some(42),
            roster_annotated_stanza: Some(ANNOTATED_ROSTER),
            ..NodeDeliveryOptions::default()
        },
    );
    let original = concat!(
        r#"{"ack_nonce":"nonce","available_nonnegative_only":false,"available_only":false,"#,
        r#""blocklist_requested_only":false,"carbon_muc_nick":null,"carbon_muc_room":null,"#,
        r#""carbons_only":false,"current_presence_replay":false,"delivery":null,"#,
        r#""exclude_jid":null,"exclude_jids":[],"expected_auth_generation":null,"#,
        r#""expected_user_id":"00000000-0000-0000-0000-00000000002b","mix_capable_only":false,"#,
        r#""mix_transport_receipt_required":false,"presence_authority_version":null,"#,
        r#""presence_owner_auth_generation":null,"presence_owner_id":null,"#,
        r#""presence_recipient_auth_generation":null,"presence_recipient_id":null,"#,
        r#""presence_subscription":false,"primary_one_to_one":false,"privacy_requested_only":false,"#,
        r#""protocol_version":"13","request_id":"request","#,
        r#""roster_annotated_stanza":"<iq xmlns='jabber:client' type='set' id='original'><query xmlns='jabber:iq:roster' ver='42'><item jid='room@mix.example.test'><channel xmlns='urn:xmpp:mix:roster:0' participant-id='original-participant'/></item></query></iq>","#,
        r#""roster_requested_only":true,"roster_version":42,"#,
        r#""stanza":"<iq xmlns='jabber:client' type='set' id='original'><query xmlns='jabber:iq:roster' ver='42'><item jid='room@mix.example.test'/></query></iq>","#,
        r#""target":"alice@example.test","transport_receipt_required":false}"#,
    );
    assert_eq!(json.to_string(), original);
}

fn add_roster_session(
    fixture: &DirectDeliveryFixture,
    jid: &str,
    connection_id: Uuid,
) -> mpsc::Receiver<OutboundItem> {
    let (_, resource) = jid.split_once('/').unwrap();
    let (session, output) = test_online_session(ORIGINAL, 1, connection_id, resource, 4);
    session.roster_requested.store(true, Ordering::Release);
    assert!(fixture
        .mix_caps
        .sessions
        .insert(jid.to_owned(), session)
        .is_none());
    output
}

async fn deliver(fixture: &DirectDeliveryFixture, json: &Value) -> Option<(usize, Option<String>)> {
    fixture
        .dispatch
        .test_exact_control_delivery(&fixture.admission, &fixture.policy, &fixture.mix_caps, json)
        .await
}

#[tokio::test]
async fn listener_rejects_malformed_v15_and_fences_roster_delivery_by_connection() {
    let fixture = DirectDeliveryFixture::new();
    let mut captured = add_roster_session(&fixture, ORIGINAL_JID, CAPTURED);
    let mut other = add_roster_session(&fixture, RECREATED_JID, OTHER);
    let control = exact_control(ExactControlKind::RosterPush);
    let json = payload(
        TARGET,
        ROSTER,
        NodeDeliveryOptions {
            exact_control: Some(&control),
            ..NodeDeliveryOptions::default()
        },
    );
    for (path, replacement) in [
        ("/exact_control", Value::Null),
        ("/exact_control/roster_version", Value::Null),
        ("/exact_control/blocklist_revision", json!(1)),
        ("/exact_control/remote_peer", json!("remote.test")),
        ("/exact_control/kind", json!("invalid")),
        ("/expected_user_id", Value::Null),
        ("/expected_user_id", json!(OTHER)),
        ("/expected_auth_generation", Value::Null),
        ("/expected_auth_generation", json!(2)),
        ("/expected_connections", Value::Null),
        ("/expected_connections", json!({ (ORIGINAL_JID): OTHER })),
        ("/roster_requested_only", json!(false)),
        ("/roster_requested_only", json!("true")),
        ("/blocklist_requested_only", json!(true)),
        ("/privacy_requested_only", json!(true)),
        ("/current_presence_replay", json!(true)),
        ("/presence_subscription", json!(true)),
        ("/carbons_only", json!(true)),
        ("/mix_capable_only", json!(true)),
        ("/delivery", json!({ "reliability": "volatile" })),
        ("/transport_receipt_required", json!(true)),
        ("/mix_transport_receipt_required", json!(true)),
        ("/stanza", json!(PRIVACY)),
        ("/stanza", json!("<iq")),
    ] {
        let mut invalid = json.clone();
        *invalid.pointer_mut(path).unwrap() = replacement;
        assert_eq!(deliver(&fixture, &invalid).await, None, "{path}");
    }
    let mut invalid = json.clone();
    invalid["exact_control"]["unexpected"] = json!(true);
    assert_eq!(deliver(&fixture, &invalid).await, None);
    assert!(captured.try_recv().is_err());
    assert!(other.try_recv().is_err());

    assert_eq!(
        deliver(&fixture, &json).await,
        Some((1, Some(ORIGINAL_JID.to_owned())))
    );
    captured.try_recv().unwrap();
    assert!(other.try_recv().is_err());

    let legacy = payload(
        TARGET,
        ROSTER,
        NodeDeliveryOptions {
            expected_user_id: Some(ORIGINAL),
            roster_requested_only: true,
            roster_version: Some(42),
            ..NodeDeliveryOptions::default()
        },
    );
    assert_eq!(deliver(&fixture, &legacy).await.unwrap().0, 2);
    captured.try_recv().unwrap();
    other.try_recv().unwrap();

    fixture.mix_caps.sessions.remove(ORIGINAL_JID).unwrap();
    let mut replacement = add_roster_session(&fixture, ORIGINAL_JID, OTHER);
    assert_eq!(deliver(&fixture, &json).await, Some((0, None)));
    assert!(replacement.try_recv().is_err());
    assert!(other.try_recv().is_err());
}
