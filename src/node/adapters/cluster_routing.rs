//! Authoritative room occupants for client discovery.

use crate::node::ServerNode;
use anyhow::Result;
use northstar_room_application::muc_service::{MucRoomView, MucRoomViewKind, MucRoomViewer};

impl ServerNode {
    pub(crate) async fn discovery_room_occupants(
        &self,
        localpart: &str,
        viewer_full_jid: Option<&str>,
    ) -> Result<MucRoomView> {
        self.room
            .muc_service()
            .room_view(
                localpart,
                MucRoomViewer {
                    full_jid: viewer_full_jid,
                    principal: None,
                    federated: false,
                    occupancy: None,
                },
                MucRoomViewKind::Items,
            )
            .await
    }
}
