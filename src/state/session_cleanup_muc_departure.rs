//! Cluster effects for one exact local MUC departure.

use super::AppState;
use crate::cluster::ClusterMucDeparture;
use crate::{
    db,
    services::muc::{ClusterMucOccupancyDepartureService, ClusterMucTransitionOutcome},
};
use anyhow::Result;

/// One exact PostgreSQL withdrawal for a quiesced C2S MUC actor. The
/// application cleanup has no access to the database pool or owner-node ID.
pub(crate) struct SessionCleanupPgMucDeparture {
    service: ClusterMucOccupancyDepartureService<
        db::room::PostgresClusterMucOccupancyDepartureRepository,
    >,
    node_id: String,
}

impl SessionCleanupPgMucDeparture {
    pub(crate) async fn leave_exact(
        &self,
        room_jid: &str,
        departed: &super::MucOccupant,
    ) -> Result<Option<ClusterMucTransitionOutcome>> {
        let Some(target) = self
            .service
            .find_exact_for_disconnect(
                room_jid,
                &departed.full_jid,
                &departed.nick,
                departed.cluster_epoch,
                departed.connection_id,
                &self.node_id,
            )
            .await?
        else {
            return Ok(None);
        };
        let result = self
            .service
            .leave_exact_for_disconnect(departed.connection_id, &target, &self.node_id)
            .await?;
        Ok(Some(result.outcome))
    }
}

impl AppState {
    pub(crate) fn session_cleanup_muc_departure(&self) -> ClusterMucDeparture {
        self.cluster.muc_departure()
    }

    pub(crate) fn session_cleanup_pg_muc_departure(&self) -> Option<SessionCleanupPgMucDeparture> {
        (self.muc_pg_authority_enabled() && !self.cluster_workers_enabled()).then(|| {
            SessionCleanupPgMucDeparture {
                service: ClusterMucOccupancyDepartureService::new(
                    db::room::PostgresClusterMucOccupancyDepartureRepository::new(
                        self.pool.clone(),
                    ),
                ),
                node_id: self.muc_cluster_node_id().to_owned(),
            }
        })
    }
}
