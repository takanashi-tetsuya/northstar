//! Room occupants for discovery: the cluster cache merged with this node's occupants.

use super::AppState;
use anyhow::Result;

impl AppState {
    /// Discovery combines the disposable cluster cache with this node's
    /// current occupants, then returns a stable nickname order for paging.
    pub(crate) async fn discovery_room_occupants(
        &self,
        room_jid: &str,
    ) -> Result<Vec<super::SerializableMucOccupant>> {
        let mut occupants = self
            .cluster
            .get_muc_occupants(room_jid)
            .await?
            .into_values()
            .filter_map(|json| serde_json::from_str::<super::SerializableMucOccupant>(&json).ok())
            .map(|occupant| (occupant.nick.clone(), occupant))
            .collect::<std::collections::HashMap<_, _>>();
        for (_, occupant) in self.muc_occupants_for(room_jid) {
            let occupant = super::SerializableMucOccupant::from(&occupant);
            occupants.insert(occupant.nick.clone(), occupant);
        }
        let mut occupants = occupants.into_values().collect::<Vec<_>>();
        occupants.sort_by(|left, right| left.nick.cmp(&right.nick));
        Ok(occupants)
    }
}
