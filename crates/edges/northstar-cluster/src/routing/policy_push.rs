use crate::delivery_contract::NodeDeliveryOptions;
use crate::ClusterManager;
use anyhow::Result;

impl ClusterManager {
    /// Deliver an XEP-0191 push only to resources that successfully requested
    /// their blocklist on this (possibly resumed) session.
    pub async fn send_to_node_blocklist(
        &self,
        node_id: &str,
        target_jid: &str,
        stanza: &str,
    ) -> Result<bool> {
        Ok(self
            .send_to_node_receipt(
                node_id,
                target_jid,
                stanza,
                NodeDeliveryOptions {
                    blocklist_requested_only: true,
                    ..NodeDeliveryOptions::default()
                },
            )
            .await?
            .delivered)
    }

    /// Deliver an XEP-0016 list-definition push only to resources that have
    /// requested privacy-list state during this logical (possibly resumed)
    /// session.
    pub async fn send_to_node_privacy(
        &self,
        node_id: &str,
        target_jid: &str,
        stanza: &str,
    ) -> Result<bool> {
        Ok(self
            .send_to_node_receipt(
                node_id,
                target_jid,
                stanza,
                NodeDeliveryOptions {
                    privacy_requested_only: true,
                    ..NodeDeliveryOptions::default()
                },
            )
            .await?
            .delivered)
    }
}
