use super::*;
use northstar_room_core::occupancy::MucOccupantRoute;

impl MucLifecycleRepository for Repository {
    unused_ports! {
        expire_locked_room_exact(room_id: Uuid) -> Option<CommittedRoomRetirement>;
        cancel_locked_room_exact(room_id: Uuid, actor_full_jid: &str) -> Option<CommittedRoomRetirement>;
        retire_room(room_id: Uuid) -> Option<CommittedRoomRetirement>;
        retire_empty_temporary_room(room: MucRoomIncarnation, expected_config_version: Option<i64>) -> Option<CommittedRoomRetirement>;
        departed_room(localpart: &str, route: &MucOccupantRoute) -> Option<MucRoomIncarnation>;
    }
}
