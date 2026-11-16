//! Builds the cluster MUC delivery endpoints (`cluster::muc_delivery_endpoints`) over the live route tables.

use crate::cluster::muc_delivery_endpoints::ClusterMucDeliveryEndpoints;
use crate::node::ServerNode;
use std::sync::Arc;

impl ServerNode {
    pub(crate) fn cluster_muc_delivery_endpoints(&self) -> ClusterMucDeliveryEndpoints {
        ClusterMucDeliveryEndpoints {
            sessions: Arc::clone(&self.sessions),
            occupants: Arc::clone(&self.room.muc_occupants),
        }
    }
}
