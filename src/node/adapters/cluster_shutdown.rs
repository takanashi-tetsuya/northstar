//! Final cluster lease release after signed publications have drained.

use crate::node::ServerNode;
use anyhow::Result;
use std::time::Duration;

impl ServerNode {
    pub(crate) fn begin_cluster_shutdown(&self) {
        self.cluster.begin_shutdown();
    }

    pub(crate) async fn release_cluster_instance_after_publication_quiescence(
        &self,
        quiesce_timeout: Duration,
    ) -> Option<Result<()>> {
        self.cluster
            .release_instance_after_publication_quiescence(
                quiesce_timeout,
                self.session.cluster_instance_release_service(),
            )
            .await
    }
}
