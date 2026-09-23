//! Cluster effects for one exact local MUC departure.

use super::AppState;
use crate::cluster::ClusterMucDeparture;

impl AppState {
    pub(crate) fn session_cleanup_muc_departure(&self) -> ClusterMucDeparture {
        self.cluster.muc_departure()
    }
}
