//! Room occupants for discovery: the cluster cache merged with this node's occupants.

use crate::node::ServerNode;
use anyhow::Result;

impl ServerNode {
    pub(crate) async fn discovery_room_occupants(
        &self,
        room_jid: &str,
    ) -> Result<Vec<crate::node::SerializableMucOccupant>> {
        let cached_json = self
            .cluster
            .get_muc_occupants(room_jid)
            .await?
            .into_values();
        let local = self
            .room
            .muc_occupants
            .muc_occupants_for(room_jid)
            .into_iter()
            .map(|(_, occupant)| crate::node::SerializableMucOccupant::from(&occupant));
        Ok(northstar_muc_xmpp::discovery::merge_discovery_occupants(
            cached_json,
            local,
        ))
    }
}
