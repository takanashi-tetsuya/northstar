//! Temporary-room cleanup after an exact local occupant departure.

use super::AppState;
use crate::{db::room::PostgresMucRepository, services::muc::MucService};
use anyhow::Result;

pub(crate) struct SessionCleanupRooms {
    rooms: MucService<PostgresMucRepository>,
}

impl AppState {
    pub(crate) fn session_cleanup_rooms(&self) -> SessionCleanupRooms {
        SessionCleanupRooms {
            rooms: self.muc_service.clone(),
        }
    }
}

impl SessionCleanupRooms {
    pub(crate) async fn delete_temporary_room(&self, room_jid: &str) -> Result<()> {
        let localpart = super::localpart(room_jid);
        let Some(room) = self.rooms.room(localpart).await? else {
            return Ok(());
        };
        let _ = self
            .rooms
            .delete_temporary_room(room.id, room.room_epoch, room.config_version)
            .await?;
        Ok(())
    }
}
