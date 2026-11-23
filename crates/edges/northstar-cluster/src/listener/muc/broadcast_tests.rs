use super::*;
use crate::listener::envelope::decode_muc_broadcast_audience;
use northstar_room_core::occupancy::{MucOccupantRoute, MUC_EXACT_ROUTE_ENVELOPE_VERSION};
use northstar_stream::local_routes::muc::{MucOccupant, MucOccupantEndpoint};
use std::{collections::BTreeSet, sync::Arc};
use uuid::Uuid;

const ROOM: &str = "room@conference.example.test";

fn route(nick: &str, incarnation: u128) -> MucOccupantRoute {
    MucOccupantRoute {
        nick: nick.to_owned(),
        full_jid: format!("{nick}@example.test/phone"),
        connection_id: Uuid::from_u128(1),
        cluster_epoch: Uuid::from_u128(incarnation),
    }
}

fn endpoints(routes: &[MucOccupantRoute]) -> ClusterMucDeliveryEndpoints {
    let endpoints = ClusterMucDeliveryEndpoints {
        sessions: Arc::default(),
        occupants: Arc::default(),
    };
    for route in routes {
        let occupant = MucOccupant {
            full_jid: route.full_jid.clone(),
            room_jid: ROOM.to_owned(),
            nick: route.nick.clone(),
            endpoint: MucOccupantEndpoint::Federated {
                authenticated_domain: "example.test".to_owned(),
                connection_id: route.connection_id,
            },
            affiliation: "none".to_owned(),
            role: "participant".to_owned(),
            room_non_anonymous: false,
            occupant_id: String::new(),
            cluster_epoch: route.cluster_epoch,
            connection_id: route.connection_id,
            sm_session_id: None,
            payload: String::new(),
        };
        endpoints.occupants.insert(
            northstar_room_core::stanza::muc_occupant_key(ROOM, &route.nick),
            occupant,
        );
    }
    endpoints
}

#[test]
fn version_two_broadcast_matches_only_the_committed_incarnations() {
    let exact = route("alice", 1);
    let endpoints = endpoints(&[exact.clone(), route("bob", 3), route("new", 4)]);
    let payload = serde_json::json!({
        "target": ROOM,
        "muc_broadcast": true,
        "stanza": "<message/>",
        "envelope_version": MUC_EXACT_ROUTE_ENVELOPE_VERSION,
        "audience": [&exact, &route("bob", 2)],
    });
    let decoded = decode_muc_broadcast_audience(&payload).unwrap();
    let recipients = broadcast_recipients(&endpoints, ROOM, decoded.as_deref());
    assert_eq!(recipients.len(), 1);
    let received = &recipients[0];
    assert_eq!(received.full_jid, exact.full_jid);
    assert_eq!(received.connection_id, exact.connection_id);
    assert_eq!(received.cluster_epoch, exact.cluster_epoch);
}

#[test]
fn legacy_broadcast_still_uses_the_current_roster() {
    let endpoints = endpoints(&[route("alice", 1), route("bob", 3), route("new", 4)]);
    let payload =
        serde_json::json!({"target": ROOM, "muc_broadcast": true, "stanza": "<message/>"});
    let decoded = decode_muc_broadcast_audience(&payload).unwrap();
    assert!(decoded.is_none());
    let nicks: BTreeSet<_> = broadcast_recipients(&endpoints, ROOM, decoded.as_deref())
        .into_iter()
        .map(|occupant| occupant.nick)
        .collect();
    assert_eq!(
        nicks,
        BTreeSet::from(["alice", "bob", "new"].map(str::to_owned))
    );
}

#[test]
fn malformed_versioned_broadcast_does_not_fall_back_to_the_roster() {
    let missing = serde_json::json!({"envelope_version": MUC_EXACT_ROUTE_ENVELOPE_VERSION});
    let unknown = serde_json::json!({"envelope_version": 999, "audience": [route("alice", 1)]});
    let inexact = serde_json::json!({
        "envelope_version": MUC_EXACT_ROUTE_ENVELOPE_VERSION,
        "audience": [route("alice", 0)],
    });
    for payload in [missing, unknown, inexact] {
        assert!(decode_muc_broadcast_audience(&payload).is_err());
    }
}
