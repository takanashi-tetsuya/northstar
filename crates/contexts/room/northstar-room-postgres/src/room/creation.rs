use super::{map_capacity_error, PostgresMucRepository, RoomEffects};
use anyhow::Result;
use northstar_room_application::muc_service::{MucRoomDeadlineRepository, MucRoomRead};
use uuid::Uuid;

impl<E: RoomEffects> MucRoomDeadlineRepository for PostgresMucRepository<E> {
    async fn room_for_command(&self, localpart: &str) -> Result<Option<MucRoomRead>> {
        Ok(crate::muc::load_muc_room_for_command(&self.pool, localpart)
            .await?
            .as_ref()
            .map(crate::muc::muc_room_read_from_row))
    }

    async fn reserve_local_room(
        &self,
        room_id: Uuid,
        localpart: &str,
        creator_id: Uuid,
        creator_full_jid: &str,
    ) -> Result<(MucRoomRead, bool)> {
        let (row, created) = crate::muc::reserve_local_muc_room(
            &self.pool,
            room_id,
            localpart,
            creator_id,
            creator_full_jid,
        )
        .await
        .map_err(map_capacity_error)?;
        Ok((crate::muc::muc_room_read_from_row(&row), created))
    }

    async fn reserve_federated_room(
        &self,
        room_id: Uuid,
        localpart: &str,
        creator_full_jid: &str,
    ) -> Result<(MucRoomRead, bool)> {
        let (row, created) = crate::muc::reserve_federated_muc_room(
            &self.pool,
            room_id,
            localpart,
            creator_full_jid,
        )
        .await
        .map_err(map_capacity_error)?;
        Ok((crate::muc::muc_room_read_from_row(&row), created))
    }
}
