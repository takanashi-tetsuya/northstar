//! Narrow capabilities composed for the cluster listener.

use super::AppState;
use std::sync::Arc;

impl AppState {
    pub(crate) fn cluster_listener_admission(&self) -> crate::cluster::ClusterListenerAdmission {
        self.cluster.listener_admission()
    }

    pub(crate) fn cluster_listener_security(&self) -> crate::cluster::ClusterListenerSecurity {
        self.cluster.listener_security()
    }

    pub(crate) fn cluster_listener_presence_sender(&self) -> crate::cluster::ClusterNodeDelivery {
        self.cluster.node_delivery()
    }

    pub(crate) fn cluster_listener_runtime(&self) -> crate::cluster::ClusterListenerRuntime {
        crate::cluster::ClusterListenerRuntime {
            message_policy: Arc::new(self.cluster_listener_message_policy()),
            dispatch: self.cluster_listener_dispatch(),
            muc_endpoints: self.cluster_muc_delivery_endpoints(),
            muc_delivery: self.muc_delivery_context(),
            mix_caps: self.cluster_listener_mix_caps(),
            blocking: self.cluster_listener_blocking(),
            sm_muc_teardown: self.cluster_listener_sm_muc_teardown(),
            presence_sender: Arc::new(self.cluster_listener_presence_sender()),
            security: Arc::new(self.cluster_listener_security()),
        }
    }
}
