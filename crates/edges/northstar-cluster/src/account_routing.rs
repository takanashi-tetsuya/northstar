//! Account-scoped cluster delivery used by roster, privacy, and blocking.

use crate::ClusterManager;
use anyhow::Result;

mod blocking_presence;
mod policy_push;
#[cfg(test)]
pub(crate) use policy_push::require_policy_push_ack;

#[cfg(test)]
pub(crate) use blocking_presence::send_blocking_pages;

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

    /// A roster removal's subscription presence is best effort, as it was
    /// before this routing adapter. The authority fences remain unchanged.
    pub async fn route_remote_roster_removal_presence(
        &self,
        target_bare: &str,
        stanza: &str,
        authority: crate::ClusterPresenceAuthority,
    ) {
        self.route_presence_subscription_remote(target_bare, stanza, authority)
            .await;
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
