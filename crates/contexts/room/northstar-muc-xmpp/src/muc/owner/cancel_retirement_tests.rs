use crate::locked_room_expiry::take_retired_occupants;
use dashmap::DashMap;
use northstar_room_application::muc_service::{
    CommittedRoomRetirement, LocalMucOccupantIdentity, MucRoomIncarnation, RetiredMucOccupant,
};
use northstar_room_core::{occupancy::MucOccupantRoute, stanza::muc_occupant_key};
use northstar_stream::local_routes::muc_table::remove_local_muc_occupant_exact_from;
use uuid::Uuid;

#[test]
fn cancel_does_not_remove_or_notify_newcomer_at_reused_nick() {
    let old = crate::locked_room_expiry::tests::occupant(
        "alice@example.test/Phone",
        Uuid::from_u128(1),
        Uuid::from_u128(2),
    );
    let retirement = CommittedRoomRetirement {
        room: MucRoomIncarnation {
            room_id: Uuid::from_u128(3),
            room_epoch: Uuid::from_u128(4),
        },
        localpart: "room".to_owned(),
        operation_id: Uuid::from_u128(5),
        occupants: vec![RetiredMucOccupant {
            route: MucOccupantRoute::from(LocalMucOccupantIdentity::from(&old)),
            status_codes: &[],
        }],
    };
    let key = muc_occupant_key(&old.room_jid, &old.nick);
    let occupants = DashMap::new();
    let mut newcomer = old.clone();
    newcomer.cluster_epoch = Uuid::from_u128(6);
    occupants.insert(key.clone(), newcomer.clone());
    assert!(
        take_retired_occupants(&retirement, &old.room_jid, |identity| {
            remove_local_muc_occupant_exact_from(&occupants, identity)
        })
        .is_empty()
    );
    assert_eq!(
        occupants.get(&key).unwrap().cluster_epoch,
        newcomer.cluster_epoch
    );

    let still_projected = DashMap::new();
    still_projected.insert(key, old.clone());
    let removed = take_retired_occupants(&retirement, &old.room_jid, |identity| {
        remove_local_muc_occupant_exact_from(&still_projected, identity)
    });
    assert_eq!(removed.len(), 1);
    assert_eq!(removed[0].cluster_epoch, old.cluster_epoch);
}
