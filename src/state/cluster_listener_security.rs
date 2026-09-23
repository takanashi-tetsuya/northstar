//! Signed-envelope verification and correlated ACK authority for the listener.

use super::AppState;

impl AppState {
    pub(crate) fn cluster_listener_security(&self) -> crate::cluster::ClusterListenerSecurity {
        self.cluster.listener_security()
    }
}
