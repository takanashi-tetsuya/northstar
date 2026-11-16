//! Temporary-room cleanup after an exact local occupant departure.

use crate::node::ServerNode;
use anyhow::Result;
use northstar_room_application::muc_service::MucService;
use northstar_workflows::room_effects::PostgresMucRepository;

pub(crate) struct SessionCleanupRooms {
    rooms: MucService<PostgresMucRepository>,
}

impl ServerNode {
    pub(crate) fn session_cleanup_rooms(&self) -> SessionCleanupRooms {
        SessionCleanupRooms {
            rooms: self.room.muc_service.clone(),
        }
    }
}

impl SessionCleanupRooms {
    pub(crate) async fn delete_temporary_room(&self, room_jid: &str) -> Result<()> {
        self.rooms.delete_temporary_room_by_jid(room_jid).await
    }
}
