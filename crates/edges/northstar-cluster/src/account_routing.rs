//! Account-scoped cluster delivery used by roster, privacy, and blocking.

use crate::ClusterManager;
use anyhow::Result;

pub struct RemoteRouteFailure {
    pub node_id: String,
    pub error: anyhow::Error,
}

pub enum RemoteRosterPushFailure {
    NotAccepted { node_id: String },
    Delivery(RemoteRouteFailure),
}

impl ClusterManager {
    /// Push-service notifications use deterministic node order and stop when
    /// one primary resource accepts the IQ.
    pub async fn route_push_service_notification_remote(
        &self,
        service_jid: &str,
        notification: &str,
    ) -> bool {
        let mut nodes = self.lookup_nodes(service_jid).await.unwrap_or_default();
        nodes.sort();
        for node_id in nodes {
            if node_id != self.node_id
                && self
                    .send_to_node_primary(&node_id, service_jid, notification)
                    .await
                    .is_ok_and(|receipt| receipt.delivered)
            {
                return true;
            }
        }
        false
    }

    /// Resolve only other nodes. A full-JID lookup retains the exact target
    /// semantics of the underlying session-route authority.
    pub async fn remote_resource_nodes(&self, target: &str) -> Result<Vec<String>> {
        let nodes = self.lookup_nodes(target).await?;
        Ok(nodes
            .into_iter()
            .filter(|node_id| node_id != &self.node_id)
            .collect())
    }

    pub async fn account_has_remote_resources(&self, account: &str) -> Result<bool> {
        Ok(!self.remote_resource_nodes(account).await?.is_empty())
    }

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

    /// A roster removal's subscription presence is best effort, as it was
    /// before this routing adapter. The authority fences remain unchanged.
    pub async fn route_remote_roster_removal_presence(
        &self,
        target_bare: &str,
        stanza: &str,
        authority: crate::ClusterPresenceAuthority,
    ) {
        if let Ok(nodes) = self.remote_resource_nodes(target_bare).await {
            for node_id in nodes {
                let _ = self
                    .send_to_node_presence_subscription(
                        &node_id,
                        target_bare,
                        stanza,
                        false,
                        authority,
                    )
                    .await;
            }
        }
    }

    pub async fn route_remote_available_presence_to_node(
        &self,
        node_id: &str,
        target: &str,
        stanza: &str,
    ) -> Result<bool> {
        self.send_to_node_available_presence(node_id, target, stanza)
            .await
    }
}
