//! Listener admission authority is composed without exposing the cluster manager.

use super::AppState;

impl AppState {
    pub(crate) fn cluster_listener_admission(&self) -> crate::cluster::ClusterListenerAdmission {
        self.cluster.listener_admission()
    }
}
