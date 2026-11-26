use super::RemoteRouteFailure;
use crate::ClusterManager;
use anyhow::Result;

impl ClusterManager {
    pub async fn route_remote_blocking_presence_change(
        &self,
        owner: &str,
        targets: &[String],
        patterns: &[String],
        available: bool,
    ) -> Result<Vec<RemoteRouteFailure>> {
        let mut failures = Vec::new();
        for node_id in self.remote_resource_nodes(owner).await? {
            if let Err(error) = self
                .send_blocking_presence_change(&node_id, owner, targets, patterns, available)
                .await
            {
                failures.push(RemoteRouteFailure { node_id, error });
            }
        }
        Ok(failures)
    }
}
