//! Signed remote presence responses for authenticated listener commands.

use super::AppState;

impl AppState {
    pub(crate) fn cluster_listener_presence_sender(&self) -> crate::cluster::ClusterNodeDelivery {
        self.cluster.node_delivery()
    }
}
