use super::*;
use northstar_room_core::occupancy::MucOccupantRoute;

impl MucLifecycleRepository for Repository {
    unused_async! {
        fn expire_locked_room_exact(&self, room_id: Uuid) -> Result<Option<CommittedRoomRetirement>>;
        fn cancel_locked_room_exact(&self, room_id: Uuid, actor_full_jid: &str) -> Result<Option<CommittedRoomRetirement>>;
        fn retire_room(&self, room_id: Uuid) -> Result<Option<CommittedRoomRetirement>>;
        fn retire_empty_temporary_room(&self, room: MucRoomIncarnation, expected_config_version: Option<i64>) -> Result<Option<CommittedRoomRetirement>>;
        fn departed_room(&self, localpart: &str, route: &MucOccupantRoute) -> Result<Option<MucRoomIncarnation>>;
    }
}
