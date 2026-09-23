//! Redis projection for committed MUC joins and exact departures.

use super::{AppState, MucOccupant, SerializableMucOccupant};
use crate::cluster::MucRegistration;
use anyhow::Result;

pub(crate) struct MucJoinCacheAttempt {
    pub(crate) refresh: Result<()>,
    pub(crate) registration: Result<MucRegistration>,
}

impl AppState {
    /// PostgreSQL owns the join. Refresh and try to publish its disposable
    /// Redis projection in the same order as the committed join path.
    pub(crate) async fn cache_committed_muc_join(
        &self,
        occupant: &SerializableMucOccupant,
        capacity: usize,
    ) -> Result<MucJoinCacheAttempt> {
        let refresh = self
            .cluster
            .get_muc_occupants(&occupant.room_jid)
            .await
            .map(|_| ());
        let json = serde_json::to_string(occupant)?;
        let registration = self
            .cluster
            .try_register_muc_occupant(&occupant.room_jid, &occupant.nick, &json, capacity)
            .await;
        Ok(MucJoinCacheAttempt {
            refresh,
            registration,
        })
    }

    /// A delayed departure or unpublished join must not erase a newer actor
    /// that reused the same nickname.
    pub(crate) async fn remove_exact_muc_soft_state(&self, occupant: &MucOccupant) -> Result<bool> {
        self.cluster
            .unregister_muc_occupant_epoch(
                &occupant.room_jid,
                &occupant.nick,
                occupant.cluster_epoch,
                occupant.connection_id,
            )
            .await
    }
}
