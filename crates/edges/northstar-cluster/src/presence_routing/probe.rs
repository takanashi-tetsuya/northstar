use super::PresenceProbeTelemetry;
use crate::{ClusterManager, ClusterPresenceAuthority};
use anyhow::Result;

impl ClusterManager {
    /// A full-JID probe requires a concrete account-generation authority.
    /// Route lookup failures and probe-control failures remain visible to the
    /// caller, which must not synthesize an unavailable response in that case.
    pub async fn delegate_authorized_full_presence_probe_remote(
        &self,
        owner_full: &str,
        requester: &str,
        authority: Option<ClusterPresenceAuthority>,
    ) -> Result<bool> {
        let mut delegated = false;
        for node_id in self.lookup_nodes(owner_full).await? {
            if node_id != self.node_id {
                if let Some(authority) = authority {
                    self.request_presence_probe_from_node(
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
    pub async fn replay_current_presence_from_remote_owners(
        &self,
        owner_lookup: &str,
        recipient: &str,
        availability_only: bool,
        authority: ClusterPresenceAuthority,
        telemetry: &PresenceProbeTelemetry<'_>,
    ) {
        match self.lookup_nodes(owner_lookup).await {
            Ok(nodes) => {
                for node_id in nodes {
                    if node_id == self.node_id {
                        continue;
                    }
                    if let Err(error) = self
                        .request_presence_probe_from_node(
                            &node_id,
                            owner_lookup,
                            recipient,
                            availability_only,
                            authority,
                        )
                        .await
                    {
                        telemetry.failed();
                        tracing::warn!(?error, owner = %owner_lookup, %recipient, %node_id, "cross-node current-presence replay failed");
                    }
                }
            }
            Err(error) => {
                telemetry.failed();
                tracing::warn!(?error, owner = %owner_lookup, %recipient, "could not resolve current-presence owner nodes");
            }
        }
    }
}
