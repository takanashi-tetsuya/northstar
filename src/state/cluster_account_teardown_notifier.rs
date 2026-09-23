//! Post-commit account and exact-session control without cluster manager access.

use super::AppState;

impl AppState {
    pub(crate) fn cluster_account_teardown_notifier(
        &self,
    ) -> crate::cluster::ClusterAccountTeardownNotifier {
        self.cluster.account_teardown_notifier()
    }
}
