//! Redis projection for committed MUC joins and exact departures.

use crate::ClusterManager;
use anyhow::Result;
use northstar_room_application::muc_service::SerializableMucOccupant;
use northstar_room_core::occupancy::MucJoinCacheAttempt;
use northstar_stream::local_routes::muc::MucOccupant;

impl ClusterManager {
    /// PostgreSQL owns the join. Refresh and try to publish its disposable
    /// Redis projection in the same order as the committed join path.
    pub async fn cache_committed_muc_join(
        &self,
        occupant: &SerializableMucOccupant,
        capacity: usize,
    ) -> Result<MucJoinCacheAttempt> {
        let refresh = self.get_muc_occupants(&occupant.room_jid).await.map(|_| ());
        let json = serde_json::to_string(occupant)?;
        let registration = self
            .try_register_muc_occupant(&occupant.room_jid, &occupant.nick, &json, capacity)
            .await;
        Ok(MucJoinCacheAttempt {
            refresh,
            registration,
        })
    }

    /// A delayed departure or unpublished join must not erase a newer actor
    /// that reused the same nickname.
    pub async fn remove_exact_muc_soft_state(&self, occupant: &MucOccupant) -> Result<bool> {
        if !self.muc_redis_transport_enabled() {
            return Ok(false);
        }
        self.unregister_muc_occupant_epoch(
            &occupant.room_jid,
            &occupant.nick,
            occupant.cluster_epoch,
            occupant.connection_id,
        )
        .await
    }
}
