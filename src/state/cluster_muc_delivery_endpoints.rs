//! Builds the cluster MUC delivery endpoints (`cluster::muc_delivery_endpoints`) over the live route tables.

use super::AppState;
use crate::cluster::muc_delivery_endpoints::ClusterMucDeliveryEndpoints;
use std::sync::Arc;

impl AppState {
    pub(crate) fn cluster_muc_delivery_endpoints(&self) -> ClusterMucDeliveryEndpoints {
        ClusterMucDeliveryEndpoints {
            sessions: Arc::clone(&self.sessions),
            occupants: Arc::clone(&self.muc_occupants),
        }
    }
}
