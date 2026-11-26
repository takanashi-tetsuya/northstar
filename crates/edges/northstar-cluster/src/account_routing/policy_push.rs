use super::RemoteRouteFailure;
use crate::ClusterManager;
use anyhow::Result;

impl ClusterManager {
    pub async fn route_remote_blocklist_push(
        &self,
        owner: &str,
        mut push: impl FnMut() -> String + Send,
    ) -> Result<Vec<RemoteRouteFailure>> {
        let mut failures = Vec::new();
        for node_id in self.remote_resource_nodes(owner).await? {
            let stanza = push();
            if let Err(error) = self.send_to_node_blocklist(&node_id, owner, &stanza).await {
                failures.push(RemoteRouteFailure { node_id, error });
            }
        }
        Ok(failures)
    }

    pub async fn route_remote_privacy_push(
        &self,
        account: &str,
        push: &str,
    ) -> Result<Vec<RemoteRouteFailure>> {
        let mut failures = Vec::new();
        for node_id in self.remote_resource_nodes(account).await? {
            if let Err(error) = self.send_to_node_privacy(&node_id, account, push).await {
                failures.push(RemoteRouteFailure { node_id, error });
            }
        }
        Ok(failures)
    }
}
