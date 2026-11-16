//! Cluster maintenance handles and the local projections (`cluster::maintenance_locals`) built from the composition root.

use crate::cluster::maintenance_locals::ClusterMaintenanceLocals;
use crate::node::ServerNode;
use std::sync::Arc;

impl ServerNode {
    pub(crate) fn cluster_maintenance_handles(
        &self,
    ) -> (
        crate::cluster::ClusterMaintenanceControl,
        crate::cluster::ClusterMaintenanceRedis,
    ) {
        (
            self.cluster.maintenance_control(),
            self.cluster.maintenance_redis(),
        )
    }

    pub(crate) fn cluster_maintenance_locals(&self) -> ClusterMaintenanceLocals {
        ClusterMaintenanceLocals {
            sessions: Arc::clone(&self.sessions),
            occupants: Arc::clone(&self.room.muc_occupants),
            metrics: Arc::clone(&self.metrics),
        }
    }
}
