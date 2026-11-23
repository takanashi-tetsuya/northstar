use super::*;
use northstar_room_core::occupancy::MucOccupantRoute;

impl<E: RoomEffects> MucLifecycleRepository for PostgresMucRepository<E> {
    async fn expire_locked_room_exact(
        &self,
        room_id: Uuid,
    ) -> Result<Option<CommittedRoomRetirement>> {
        crate::muc::delete_expired_locked_muc_room(&self.pool, room_id).await
    }

    async fn cancel_locked_room_exact(
        &self,
        room_id: Uuid,
        actor_full_jid: &str,
    ) -> Result<Option<CommittedRoomRetirement>> {
        crate::muc::cancel_locked_muc_room(&self.pool, room_id, actor_full_jid).await
    }

    async fn retire_room(&self, room_id: Uuid) -> Result<Option<CommittedRoomRetirement>> {
        crate::muc::delete_muc_room(&self.pool, room_id).await
    }

    async fn retire_empty_temporary_room(
        &self,
        room: MucRoomIncarnation,
        expected_config_version: Option<i64>,
    ) -> Result<Option<CommittedRoomRetirement>> {
        crate::muc::delete_temporary_muc_room(&self.pool, room, expected_config_version).await
    }

    async fn departed_room(
        &self,
        localpart: &str,
        route: &MucOccupantRoute,
    ) -> Result<Option<MucRoomIncarnation>> {
        crate::muc::muc_departed_room(&self.pool, localpart, route, None).await
    }
}
