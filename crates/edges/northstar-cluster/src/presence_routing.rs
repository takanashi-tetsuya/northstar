//! Cluster routes for directed presence, subscriptions, and current-presence probes.

use crate::ClusterManager;
use crate::ClusterPresenceAuthority;
use anyhow::Result;
use std::sync::atomic::{AtomicU64, Ordering};

mod federated_inbound;
mod probe;
pub use federated_inbound::{FederatedPresenceOwner, FederatedPresenceRequest};
pub(crate) use probe::CapturedPresenceProbe;

/// Failure to replay current presence across a cluster route.
pub struct PresenceProbeTelemetry<'a> {
    failures: &'a AtomicU64,
}

impl<'a> PresenceProbeTelemetry<'a> {
    pub fn new(failures: &'a AtomicU64) -> Self {
        Self { failures }
    }

    pub fn failed(&self) {
        self.failures.fetch_add(1, Ordering::Relaxed);
    }
}

impl ClusterManager {
    /// A bare presence probe treats a failed route lookup as an error, so it
    /// cannot assert that the contact is unavailable during a cluster fault.
    pub async fn presence_probe_has_remote_owner(&self, owner: &str) -> Result<bool> {
        Ok(self
            .lookup_nodes(owner)
            .await?
            .iter()
            .any(|node_id| node_id != &self.node_id))
    }

    /// The exact-resource subscription guard historically treats every route
    /// entry, including this node, as a matching resource.
    pub async fn subscription_full_target_has_route(&self, full_jid: &str) -> bool {
        self.lookup_nodes(full_jid)
            .await
            .is_ok_and(|nodes| !nodes.is_empty())
    }

    /// A directed bare-JID presence goes to available resources; an exact
    /// full JID goes to its resource even when it is unavailable.
    pub async fn route_directed_presence_remote(
        &self,
        target: &str,
        stanza: &str,
        bare_target: bool,
    ) -> bool {
        let mut delivered = false;
        if let Ok(nodes) = self.lookup_nodes(target).await {
            for node_id in nodes {
                if node_id == self.node_id {
                    continue;
                }
                let accepted = if bare_target {
                    self.send_to_node_available_presence(&node_id, target, stanza)
                        .await
                        .unwrap_or(false)
                } else {
                    self.send_to_node(&node_id, target, stanza, false, None)
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
    pub async fn route_presence_subscription_remote(
        &self,
        target: &str,
        stanza: &str,
        authority: ClusterPresenceAuthority,
    ) {
        if let Ok(routes) = self
            .capture_remote_message_routes(
                target,
                authority.recipient_id,
                authority.recipient_auth_generation,
            )
            .await
        {
            let nodes: std::collections::BTreeSet<_> = routes
                .iter()
                .filter_map(|route| route.node_id.as_deref())
                .collect();
            for node in nodes {
                let _ = self
                    .send_captured_subscription(node, target, stanza, authority, &routes)
                    .await;
            }
        }
    }

    /// Initial, roster-contact, and sibling-resource presence are volatile
    /// broadcasts. Keep routing to later nodes after one rejects a stanza.
    pub async fn broadcast_available_presence_remote(
        &self,
        target: &str,
        stanza: &str,
        record_failure: impl Fn() + Send,
    ) {
        let nodes = match self.lookup_nodes(target).await {
            Ok(nodes) => nodes,
            Err(error) => {
                record_failure();
                tracing::warn!(%target, %error, "could not look up cluster presence audience");
                return;
            }
        };
        for node_id in nodes {
            if node_id == self.node_id {
                continue;
            }
            if let Err(error) = self
                .send_to_node_available_presence(&node_id, target, stanza)
                .await
            {
                record_failure();
                tracing::warn!(%node_id, %target, %error, "could not route cluster broadcast presence");
            }
        }
    }
}
