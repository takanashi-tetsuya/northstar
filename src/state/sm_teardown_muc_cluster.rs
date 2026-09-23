//! Exact clustered MUC teardown after a durable SM revocation.

use super::AppState;
use crate::cluster::ClusterSmMucTeardown;

impl AppState {
    pub(super) fn sm_teardown_muc_cluster(&self) -> ClusterSmMucTeardown {
        self.cluster.sm_muc_teardown()
    }
}
