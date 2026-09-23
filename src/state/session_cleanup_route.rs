//! Exact clustered route release for a finalized local connection.

use super::AppState;
use crate::cluster::ClusterSessionRouteRelease;

impl AppState {
    pub(crate) fn session_cleanup_route_release(&self) -> ClusterSessionRouteRelease {
        self.cluster.session_route_release()
    }
}
