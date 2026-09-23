//! Cluster routes for directed presence, subscriptions, and current-presence probes.

use super::AppState;
use crate::cluster::ClusterPresenceAuthority;
use anyhow::Result;

impl AppState {
    /// A bare presence probe treats a failed route lookup as an error, so it
    /// cannot assert that the contact is unavailable during a cluster fault.
    pub(crate) async fn presence_probe_has_remote_owner(&self, owner: &str) -> Result<bool> {
        Ok(self
            .cluster
            .lookup_nodes(owner)
            .await?
            .iter()
            .any(|node_id| node_id != &self.cluster.node_id))
    }

    /// The exact-resource subscription guard historically treats every route
    /// entry, including this node, as a matching resource.
    pub(crate) async fn subscription_full_target_has_route(&self, full_jid: &str) -> bool {
        self.cluster
            .lookup_nodes(full_jid)
            .await
            .is_ok_and(|nodes| !nodes.is_empty())
    }

    /// A directed bare-JID presence goes to available resources; an exact
    /// full JID goes to its resource even when it is unavailable.
    pub(crate) async fn route_directed_presence_remote(
        &self,
        target: &str,
        stanza: &str,
        bare_target: bool,
    ) -> bool {
        let mut delivered = false;
        if let Ok(nodes) = self.cluster.lookup_nodes(target).await {
            for node_id in nodes {
                if node_id == self.cluster.node_id {
                    continue;
                }
                let accepted = if bare_target {
                    self.cluster
                        .send_to_node_available_presence(&node_id, target, stanza)
                        .await
                        .unwrap_or(false)
                } else {
                    self.cluster
                        .send_to_node(&node_id, target, stanza, false, None)
                        .await
                        .unwrap_or(false)
                };
                delivered |= accepted;
            }
        }
        delivered
    }

    /// Subscription notifications are recovered or forwarded after their
    /// authoritative transition. Every remote node is attempted in route order.
    pub(crate) async fn route_presence_subscription_remote(
        &self,
        target: &str,
        stanza: &str,
        authority: ClusterPresenceAuthority,
    ) {
        if let Ok(nodes) = self.cluster.lookup_nodes(target).await {
            for node_id in nodes {
                if node_id != self.cluster.node_id {
                    let _ = self
                        .cluster
                        .send_to_node_presence_subscription(
                            &node_id, target, stanza, false, authority,
                        )
                        .await;
                }
            }
        }
    }

    /// Initial, roster-contact, and sibling-resource presence are volatile
    /// broadcasts. Keep routing to later nodes after one rejects a stanza.
    pub(crate) async fn broadcast_available_presence_remote(&self, target: &str, stanza: &str) {
        if let Ok(nodes) = self.cluster.lookup_nodes(target).await {
            for node_id in nodes {
                if node_id != self.cluster.node_id {
                    let _ = self
                        .cluster
                        .send_to_node_available_presence(&node_id, target, stanza)
                        .await;
                }
            }
        }
    }

    /// A full-JID probe requires a concrete account-generation authority.
    /// Route lookup failures and probe-control failures remain visible to the
    /// caller, which must not synthesize an unavailable response in that case.
    pub(crate) async fn delegate_authorized_full_presence_probe_remote(
        &self,
        owner_full: &str,
        requester: &str,
        authority: Option<ClusterPresenceAuthority>,
    ) -> Result<bool> {
        let mut delegated = false;
        for node_id in self.cluster.lookup_nodes(owner_full).await? {
            if node_id != self.cluster.node_id {
                if let Some(authority) = authority {
                    self.cluster
                        .request_presence_probe_from_node(
                            &node_id, owner_full, requester, true, authority,
                        )
                        .await?;
                    delegated = true;
                }
            }
        }
        Ok(delegated)
    }

    /// Current-presence replay is best effort after local replay. Count and
    /// log every failed remote control request, including route lookup failure.
    pub(crate) async fn replay_current_presence_from_remote_owners(
        &self,
        owner_lookup: &str,
        recipient: &str,
        availability_only: bool,
        authority: ClusterPresenceAuthority,
    ) {
        match self.cluster.lookup_nodes(owner_lookup).await {
            Ok(nodes) => {
                for node_id in nodes {
                    if node_id == self.cluster.node_id {
                        continue;
                    }
                    if let Err(error) = self
                        .cluster
                        .request_presence_probe_from_node(
                            &node_id,
                            owner_lookup,
                            recipient,
                            availability_only,
                            authority,
                        )
                        .await
                    {
                        self.presence_probe_telemetry().failed();
                        tracing::warn!(?error, owner = %owner_lookup, %recipient, %node_id, "cross-node current-presence replay failed");
                    }
                }
            }
            Err(error) => {
                self.presence_probe_telemetry().failed();
                tracing::warn!(?error, owner = %owner_lookup, %recipient, "could not resolve current-presence owner nodes");
            }
        }
    }
}
