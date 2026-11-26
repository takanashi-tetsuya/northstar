use super::ClusterNodeDelivery;
use crate::{ClusterPresenceAuthority, ClusterPresenceDelivery, NodeDeliveryOptions};
use anyhow::Result;

impl ClusterNodeDelivery {
    pub async fn send_available_presence(
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
                    available_only: true,
                    ..NodeDeliveryOptions::default()
                },
            )
            .await?
            .delivered)
    }

    pub async fn send_current_presence_replay(
        &self,
        node_id: &str,
        target_jid: &str,
        stanza: &str,
        authority: ClusterPresenceAuthority,
    ) -> Result<bool> {
        Ok(self
            .send_to_node_receipt(
                node_id,
                target_jid,
                stanza,
                NodeDeliveryOptions {
                    available_only: true,
                    expected_user_id: Some(authority.recipient_id),
                    expected_auth_generation: Some(authority.recipient_auth_generation),
                    presence_authority: Some(authority),
                    presence_delivery: Some(ClusterPresenceDelivery::CurrentReplay),
                    ..NodeDeliveryOptions::default()
                },
            )
            .await?
            .delivered)
    }
}
