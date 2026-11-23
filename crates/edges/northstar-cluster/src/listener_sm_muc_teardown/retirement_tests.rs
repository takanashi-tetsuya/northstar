use super::*;
use dashmap::DashMap;
use northstar_room_application::muc_service::{MucRoomIncarnation, RetiredMucOccupant};
use northstar_room_core::stanza::muc_occupant_key;
use northstar_stream::local_routes::muc::{MucOccupant, MucOccupantEndpoint};
use northstar_stream::outbound::OutboundSender;
use std::sync::Arc;
use uuid::Uuid;

#[test]
fn sm_retirement_removes_exact_routes_only() {
    let local = SmTeardownLocalEffects {
        occupants: Arc::new(DashMap::new()),
        suspended_muc_sessions: Arc::new(DashMap::new()),
    };
    let (sender, _receiver) = tokio::sync::mpsc::channel(1);
    let old = MucOccupant {
        full_jid: "alice@example.test/Phone".to_owned(),
        room_jid: "room@conference.example.test".to_owned(),
        nick: "Alice".to_owned(),
        endpoint: MucOccupantEndpoint::Local(OutboundSender::new(sender)),
        affiliation: "none".to_owned(),
        role: "participant".to_owned(),
        room_non_anonymous: false,
        occupant_id: "opaque".to_owned(),
        cluster_epoch: Uuid::from_u128(1),
        connection_id: Uuid::from_u128(2),
        sm_session_id: None,
        payload: String::new(),
    };
    let mut still_projected = old.clone();
    still_projected.nick = "Bob".to_owned();
    still_projected.full_jid = "bob@example.test/Phone".to_owned();
    still_projected.cluster_epoch = Uuid::from_u128(3);
    let retirement = CommittedRoomRetirement {
        room: MucRoomIncarnation {
            room_id: Uuid::from_u128(4),
            room_epoch: Uuid::from_u128(5),
        },
        localpart: "room".to_owned(),
        operation_id: Uuid::from_u128(6),
        occupants: [&old, &still_projected]
            .into_iter()
            .map(|occupant| RetiredMucOccupant {
                route: MucOccupantRoute::from(LocalMucOccupantIdentity::from(occupant)),
                status_codes: &[],
            })
            .collect(),
    };
    let key = muc_occupant_key(&old.room_jid, &old.nick);
    let projected_key = muc_occupant_key(&old.room_jid, &still_projected.nick);
    let mut replacement = old.clone();
    replacement.cluster_epoch = Uuid::from_u128(7);
    local.occupants.insert(key.clone(), replacement.clone());
    local
        .occupants
        .insert(projected_key.clone(), still_projected);
    remove_retirement(&local, &DashMap::new(), &old.room_jid, &retirement);
    assert!(!local.occupants.contains_key(&projected_key));
    assert_eq!(
        local.occupants.get(&key).unwrap().cluster_epoch,
        replacement.cluster_epoch
    );
}
