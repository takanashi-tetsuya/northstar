//! Cluster capabilities used to retire an account, session, or MUC endpoint.

use super::AppState;
use crate::cluster::{
    ClusterAccountTeardownNotifier, ClusterSessionRouteRelease, ClusterSmMucTeardown,
};

impl AppState {
    pub(crate) fn cluster_account_teardown_notifier(&self) -> ClusterAccountTeardownNotifier {
        self.cluster.account_teardown_notifier()
    }

    pub(crate) fn session_cleanup_route_release(&self) -> ClusterSessionRouteRelease {
        self.cluster.session_route_release()
    }

    pub(super) fn sm_teardown_muc_cluster(&self) -> ClusterSmMucTeardown {
        self.cluster.sm_muc_teardown()
    }
}
