use super::{MucRepository, MucRoomRead, MucService};
use anyhow::Result;
use std::future::Future;
use uuid::Uuid;

/// Room command snapshots carry the deadline evaluated in the room read.
pub trait MucRoomDeadlineRepository {
    fn room_for_command(
        &self,
        localpart: &str,
    ) -> impl Future<Output = Result<Option<MucRoomRead>>> + Send;

    fn reserve_local_room(
        &self,
        room_id: Uuid,
        localpart: &str,
        creator_id: Uuid,
        creator_full_jid: &str,
    ) -> impl Future<Output = Result<(MucRoomRead, bool)>> + Send;

    fn reserve_federated_room(
        &self,
        room_id: Uuid,
        localpart: &str,
        creator_full_jid: &str,
    ) -> impl Future<Output = Result<(MucRoomRead, bool)>> + Send;
}

impl MucRoomRead {
    pub fn can_configure_locked_room(&self, actor_full_jid: &str) -> bool {
        !self.configuration_expired
            && self.room.configuration_owner_jid.as_deref() == Some(actor_full_jid)
    }
}

impl<R: MucRepository> MucService<R> {
    /// Load a room for a command, including initializing its secret on legacy rows.
    pub async fn room_for_command(&self, localpart: &str) -> Result<Option<MucRoomRead>> {
        self.repository.room_for_command(localpart).await
    }
}
