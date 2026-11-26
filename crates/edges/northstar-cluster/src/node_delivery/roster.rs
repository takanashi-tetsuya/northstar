use super::ClusterNodeDelivery;
use crate::NodeDeliveryOptions;
use anyhow::Result;

impl ClusterNodeDelivery {
    pub async fn send_roster_push(
        &self,
        node_id: &str,
        target_jid: &str,
        expected_user_id: uuid::Uuid,
        roster_version: i64,
        stanza: &str,
        annotated_stanza: Option<&str>,
    ) -> Result<bool> {
        Ok(self
            .send_to_node_receipt(
                node_id,
                target_jid,
                stanza,
                NodeDeliveryOptions {
                    roster_requested_only: true,
                    expected_user_id: Some(expected_user_id),
                    roster_version: Some(roster_version),
                    roster_annotated_stanza: annotated_stanza,
                    ..NodeDeliveryOptions::default()
                },
            )
            .await?
            .delivered)
    }

    pub async fn send_account_removal_presence(
        &self,
        node_id: &str,
        target_jid: &str,
        stanza: &str,
    ) -> Result<bool> {
        Ok(self
            .send_to_node_receipt(node_id, target_jid, stanza, NodeDeliveryOptions::default())
            .await?
            .delivered)
    }
}
