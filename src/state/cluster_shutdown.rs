//! Final cluster lease release after signed publications have drained.

use super::AppState;
use anyhow::Result;
use std::time::Duration;

impl AppState {
    pub(crate) fn begin_cluster_shutdown(&self) {
        self.cluster.begin_shutdown();
    }

    /// `None` means publications did not quiesce before the deadline. The
    /// timeout covers only guard acquisition; once held, the guard remains
    /// live until the PostgreSQL instance release has completed or failed.
    pub(crate) async fn release_cluster_instance_after_publication_quiescence(
        &self,
        quiesce_timeout: Duration,
    ) -> Option<Result<()>> {
        let _publication_fence =
            tokio::time::timeout(quiesce_timeout, self.cluster.quiesce_publication())
                .await
                .ok()?;
        let release_service = self.cluster_instance_release_service();
        Some(
            self.cluster
                .release_instance_authority_with(&release_service)
                .await
                .map(|_| ()),
        )
    }
}
