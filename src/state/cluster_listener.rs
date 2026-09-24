//! Narrow capabilities composed for the cluster listener.

use super::AppState;

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
}
