//! Cluster effects for one exact local MUC departure.

use crate::node::ServerNode;
use anyhow::Result;
use northstar_cluster::ClusterMucDeparture;
use northstar_room_application::muc_service::{
    ClusterMucOccupancyDepartureService, ClusterMucTransitionOutcome,
};

/// One exact PostgreSQL withdrawal for a quiesced C2S MUC actor. The
/// application cleanup has no access to the database pool or owner-node ID.
pub(crate) struct SessionCleanupPgMucDeparture {
    service: ClusterMucOccupancyDepartureService<
        northstar_room_postgres::room::PostgresClusterMucOccupancyDepartureRepository,
    >,
    node_id: String,
}

impl SessionCleanupPgMucDeparture {
    pub(crate) async fn leave_exact(
        &self,
        room_jid: &str,
        departed: &crate::node::MucOccupant,
    ) -> Result<Option<ClusterMucTransitionOutcome>> {
        self.service
            .leave_exact_departure(
                room_jid,
                &departed.full_jid,
                &departed.nick,
                departed.cluster_epoch,
                departed.connection_id,
                &self.node_id,
            )
            .await
    }
}

impl ServerNode {
    pub(crate) fn session_cleanup_muc_departure(&self) -> ClusterMucDeparture {
        self.cluster.muc_departure()
    }

    pub(crate) fn session_cleanup_pg_muc_departure(&self) -> Option<SessionCleanupPgMucDeparture> {
        self.cluster.standalone_pg_muc_authority().then(|| {
            SessionCleanupPgMucDeparture {
                service: ClusterMucOccupancyDepartureService::new(
                    northstar_room_postgres::room::PostgresClusterMucOccupancyDepartureRepository::new(
                        self.pool.clone(),
                    ),
                ),
                node_id: self.cluster.muc_cluster_node_id().to_owned(),
            }
        })
    }
}
