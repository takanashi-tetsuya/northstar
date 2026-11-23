use super::*;
use northstar_room_application::muc_service::{
    LocalMucOccupantIdentity, MucRoomIncarnation, RetiredMucOccupant,
};
use northstar_room_core::{occupancy::MucOccupantRoute, stanza::muc_occupant_key};
use uuid::Uuid;

#[test]
fn expiry_consumes_only_committed_routes_after_recreation() {
    let local = LockedMucExpiryLocal {
        sessions: Arc::new(DashMap::new()),
        occupants: Arc::new(DashMap::new()),
    };
    let old = super::tests::occupant(
        "alice@example.test/Phone",
        Uuid::from_u128(1),
        Uuid::from_u128(2),
    );
    let mut remaining_old = old.clone();
    remaining_old.nick = "Bob".to_owned();
    remaining_old.full_jid = "bob@example.test/Phone".to_owned();
    remaining_old.cluster_epoch = Uuid::from_u128(3);
    let retirement = CommittedRoomRetirement {
        room: MucRoomIncarnation {
            room_id: Uuid::from_u128(4),
            room_epoch: Uuid::from_u128(5),
        },
        localpart: "room".to_owned(),
        operation_id: Uuid::from_u128(6),
        occupants: [&old, &remaining_old]
            .into_iter()
            .map(|occupant| RetiredMucOccupant {
                route: MucOccupantRoute::from(LocalMucOccupantIdentity::from(occupant)),
                status_codes: &[],
            })
            .collect(),
    };
    let key = muc_occupant_key(&old.room_jid, &old.nick);
    let old_key = muc_occupant_key(&old.room_jid, &remaining_old.nick);
    local
        .occupants
        .insert(old_key.clone(), remaining_old.clone());
    let mut newcomer = old.clone();
    newcomer.cluster_epoch = Uuid::from_u128(7);
    local.occupants.insert(key.clone(), newcomer.clone());
    let removed = local.take_retirement(&retirement, &old.room_jid);
    assert_eq!(removed.len(), 1);
    assert_eq!(removed[0].cluster_epoch, remaining_old.cluster_epoch);
    assert!(!local.occupants.contains_key(&old_key));
    assert_eq!(
        local.occupants.get(&key).unwrap().cluster_epoch,
        newcomer.cluster_epoch
    );
}
