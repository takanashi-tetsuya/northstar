//! Builds the cluster listener's suspended-MUC teardown (`cluster::listener_sm_muc_teardown`).

use super::AppState;
use crate::cluster::listener_sm_muc_teardown::ClusterListenerSmMucTeardown;

impl AppState {
    pub(crate) fn cluster_listener_sm_muc_teardown(&self) -> ClusterListenerSmMucTeardown {
        ClusterListenerSmMucTeardown {
            local: self.sm_teardown_local_effects(),
            redis: self.cluster.sm_muc_teardown_projection(),
            rooms: self.sm_teardown_muc_service(),
            delivery: self.muc_delivery_context(),
            local_domain: self.config.domain.clone(),
        }
    }
}
