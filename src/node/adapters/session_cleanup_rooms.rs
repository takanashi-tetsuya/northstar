//! Temporary-room cleanup after an exact local occupant departure.

use crate::node::ServerNode;
use anyhow::Result;
use northstar_room_application::muc_service::{
    CommittedRoomRetirement, MucRoomIncarnation, MucService,
};
use northstar_room_core::occupancy::MucOccupantRoute;
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
    pub(crate) async fn departed_room(
        &self,
        room_jid: &str,
        route: &MucOccupantRoute,
    ) -> Result<Option<MucRoomIncarnation>> {
        self.rooms.departed_room(room_jid, route).await
    }

    pub(crate) async fn delete_temporary_room(
        &self,
        room: MucRoomIncarnation,
    ) -> Result<Option<CommittedRoomRetirement>> {
        self.rooms.retire_empty_temporary_room(room).await
    }
}
