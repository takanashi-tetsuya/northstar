use super::ClusterNodeDelivery;
use crate::{ClusterListenerPresenceRoutes, NodeDeliveryOptions};
use anyhow::Result;

#[derive(Clone)]
pub struct ClusterUnavailableDelivery {
    pub(crate) routes: ClusterListenerPresenceRoutes,
    pub(crate) sender: ClusterNodeDelivery,
}

impl ClusterUnavailableDelivery {
    /// Preserve PostgreSQL route order and require the signed delivery ACK
    /// before considering a cleanup unavailable notification complete.
    pub async fn send_unavailable_to_remote_nodes(
        &self,
        target_jid: &str,
        stanza: &str,
        exclude_jid: &str,
        bare_target: bool,
    ) -> Result<()> {
        for node_id in self.routes.lookup_nodes(target_jid).await? {
            if node_id == self.routes.node_id {
                continue;
            }
            let exclusions = [exclude_jid];
            let receipt = self
                .sender
                .send_to_node_receipt(
                    &node_id,
                    target_jid,
                    stanza,
                    NodeDeliveryOptions {
                        available_only: bare_target,
                        exclude_jids: &exclusions,
                        ..NodeDeliveryOptions::default()
                    },
                )
                .await?;
            anyhow::ensure!(
                receipt.acknowledged,
                "cluster presence delivery was not acknowledged"
            );
        }
        Ok(())
    }
}
