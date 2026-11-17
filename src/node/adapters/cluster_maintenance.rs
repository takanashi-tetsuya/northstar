//! Cluster maintenance handles and the local projections (`cluster::maintenance_locals`) built from the composition root.

use crate::node::ServerNode;
use northstar_cluster::maintenance_locals::ClusterMaintenanceLocals;
use std::sync::Arc;

impl ServerNode {
    pub(crate) fn cluster_maintenance_handles(
        &self,
    ) -> (
        northstar_cluster::ClusterMaintenanceControl,
        northstar_cluster::ClusterMaintenanceRedis,
    ) {
        (
            self.cluster.maintenance_control(),
            self.cluster.maintenance_redis(),
        )
    }

    pub(crate) fn cluster_maintenance_locals(&self) -> ClusterMaintenanceLocals {
        ClusterMaintenanceLocals {
            sessions: Arc::clone(self.session.live().sessions()),
            occupants: Arc::clone(&self.room.muc_occupants),
            metrics: Arc::clone(&self.metrics),
        }
    }
}
