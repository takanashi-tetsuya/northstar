//! Builds the cluster listener's suspended-MUC teardown (`cluster::listener_sm_muc_teardown`).

use crate::node::adapters::cluster_adapters::PostgresClusterAdapters;
use crate::node::ServerNode;
use northstar_cluster::listener_sm_muc_teardown::ClusterListenerSmMucTeardown;

impl ServerNode {
    pub(crate) fn cluster_listener_sm_muc_teardown(
        &self,
    ) -> ClusterListenerSmMucTeardown<PostgresClusterAdapters> {
        ClusterListenerSmMucTeardown {
            local: self.sm_teardown_local_effects(),
            redis: self.cluster.sm_muc_teardown_projection(),
            rooms: self.room.sm_teardown_muc_service().clone(),
            delivery: self.muc_delivery_context(),
            local_domain: self.config.domain.clone(),
        }
    }
}
