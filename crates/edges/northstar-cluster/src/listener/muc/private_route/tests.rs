use super::*;
use northstar_stream::local_routes::muc::MucOccupantEndpoint;
use serde_json::json;
use uuid::Uuid;

const ROOM: &str = "room@muc.local.test";

fn route() -> MucOccupantRoute {
    MucOccupantRoute {
        nick: "Mod".into(),
        full_jid: "owner@remote.test/Phone".into(),
        connection_id: Uuid::from_u128(1),
        cluster_epoch: Uuid::from_u128(2),
    }
}

fn envelope(route: &MucOccupantRoute) -> serde_json::Value {
    json!({ "target_nick": route.nick, "envelope_version": MUC_EXACT_ROUTE_ENVELOPE_VERSION,
            "target_route": route })
}

fn install(endpoints: &ClusterMucDeliveryEndpoints, route: &MucOccupantRoute) {
    let occupant = MucOccupant {
        nick: route.nick.clone(),
        room_jid: ROOM.into(),
        full_jid: route.full_jid.clone(),
        connection_id: route.connection_id,
        cluster_epoch: route.cluster_epoch,
        endpoint: MucOccupantEndpoint::Federated {
            connection_id: route.connection_id,
            authenticated_domain: "remote.test".into(),
        },
        affiliation: "owner".into(),
        role: "moderator".into(),
        room_non_anonymous: false,
        occupant_id: "opaque".into(),
        sm_session_id: None,
        payload: String::new(),
    };
    endpoints.occupants.insert(
        northstar_room_core::stanza::muc_occupant_key(ROOM, &route.nick),
        occupant,
    );
}

#[test]
fn exact_recipient_matches_then_drops_on_nick_reuse() {
    let endpoints = ClusterMucDeliveryEndpoints {
        sessions: Default::default(),
        occupants: Default::default(),
    };
    let original = route();
    let payload = envelope(&original);
    let decoded = decode(&payload).unwrap();
    assert!(decoded.recipient(&endpoints, ROOM).is_none());
    install(&endpoints, &original);
    assert_eq!(
        decoded.recipient(&endpoints, ROOM).unwrap().connection_id,
        original.connection_id
    );
    let replacement = MucOccupantRoute {
        cluster_epoch: Uuid::from_u128(3),
        ..original
    };
    install(&endpoints, &replacement);
    assert!(decoded.recipient(&endpoints, ROOM).is_none());
}

#[test]
fn moderator_requirement_uses_the_database_result_not_the_cache() {
    let original = route();
    let mut payload = envelope(&original);
    payload["require_role"] = json!("moderator");
    let decoded = decode(&payload).unwrap();
    assert_eq!(decoded.required_moderator(), Some(&original));
    assert!(!decoded.role_allows(&[]));
    assert!(decoded.role_allows(std::slice::from_ref(&original)));
    let replacement = MucOccupantRoute {
        cluster_epoch: Uuid::from_u128(3),
        ..original
    };
    assert!(!decoded.role_allows(&[replacement]));
    payload["require_role"] = json!("participant");
    assert!(decode(&payload).is_none());
}

#[test]
fn only_unversioned_envelopes_can_use_the_legacy_nick() {
    let endpoints = ClusterMucDeliveryEndpoints {
        sessions: Default::default(),
        occupants: Default::default(),
    };
    let original = route();
    install(&endpoints, &original);
    let legacy = json!({ "target_nick": original.nick });
    assert!(decode(&legacy)
        .unwrap()
        .recipient(&endpoints, ROOM)
        .is_some());
    for declared in [json!(2), json!(1), json!(null)] {
        assert!(
            decode(&json!({ "envelope_version": declared, "target_nick": original.nick }))
                .is_none()
        );
    }
}
