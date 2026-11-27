//! Cluster routes for client IQs, personal messages, their Carbons, and direct MUC invitations.

use crate::ClusterManager;
use anyhow::Result;
use northstar_message_application::messaging::OnlineRouteResult;
use northstar_message_application::telemetry::PersonalMessageTelemetry;
use northstar_room_application::muc_service::{
    ClusterMucAffiliationSubject, ClusterMucInviteAuthority, ClusterMucPrincipal,
};
use uuid::Uuid;

pub(crate) mod carbons;
pub(crate) mod exact;
mod exact_iq;

impl ClusterManager {
    /// A failed route lookup supplies no evidence of an exact remote resource.
    pub async fn personal_message_remote_resource_exists(&self, jid: &str) -> bool {
        self.lookup_nodes(jid)
            .await
            .is_ok_and(|nodes| nodes.iter().any(|node| node != &self.node_id))
    }

    /// Client IQs addressed to a full JID stop at the first accepting node.
    pub async fn route_client_iq_to_remote_resource(&self, full_jid: &str, stanza: &str) -> bool {
        if let Ok(nodes) = self.lookup_nodes(full_jid).await {
            for node_id in nodes {
                if node_id != self.node_id
                    && self
                        .send_to_node(&node_id, full_jid, stanza, false, None)
                        .await
                        .unwrap_or(false)
                {
                    return true;
                }
            }
        }
        false
    }

    /// Fan out a bare-JID message to every available remote resource.
    pub async fn route_personal_message_to_available_remote_resources(
        &self,
        jid: &str,
        stanza: &str,
        delivery: Option<northstar_stream::outbound::DurableDelivery>,
    ) -> bool {
        let mut delivered = false;
        if let Ok(nodes) = self.lookup_nodes(jid).await {
            for node_id in nodes {
                if node_id == self.node_id {
                    continue;
                }
                let accepted = if let Some(delivery) = delivery {
                    self.send_to_node_available_durable(&node_id, jid, stanza, delivery)
                        .await
                        .unwrap_or(false)
                } else {
                    self.send_to_node_available(&node_id, jid, stanza)
                        .await
                        .unwrap_or(false)
                };
                if accepted {
                    delivered = true;
                }
            }
        }
        delivered
    }

    /// Return the full JID accepted by the first remote primary. Keep the
    /// legacy receipt treatment shared with federated message delivery.
    pub async fn route_personal_message_to_remote_primary(
        &self,
        jid: &str,
        stanza: &str,
        delivery: Option<northstar_stream::outbound::DurableDelivery>,
        telemetry: &PersonalMessageTelemetry<'_>,
    ) -> OnlineRouteResult {
        if let Ok(nodes) = self.lookup_nodes(jid).await {
            for node_id in nodes {
                if node_id == self.node_id {
                    continue;
                }
                let receipt = self
                    .send_to_node_personal_primary(&node_id, jid, stanza, delivery)
                    .await
                    .unwrap_or_default();
                if crate::s2s_routing::accepted_cluster_message_delivery(
                    telemetry, &node_id, jid, &receipt,
                ) {
                    return OnlineRouteResult {
                        delivered: true,
                        accepted_full_jid: receipt.accepted_full_jid,
                    };
                }
            }
        }
        OnlineRouteResult::default()
    }

    /// Admit the cluster mutation before constructing a direct invitation's
    /// durable authority. A single-node invitation needs no cluster fence.
    pub fn direct_muc_invite_cluster_authority(
        &self,
        operation_id: Uuid,
        room_epoch: Uuid,
        config_version: i64,
        actor_user_id: Uuid,
        actor_full_jid: &str,
        subject: ClusterMucAffiliationSubject,
    ) -> Result<Option<ClusterMucInviteAuthority>> {
        if !self.is_enabled() {
            return Ok(None);
        }
        self.admit(crate::ClusterOperation::MucMutation)?;
        Ok(Some(ClusterMucInviteAuthority {
            operation_id,
            expected_room_epoch: room_epoch,
            expected_config_version: config_version,
            actor: ClusterMucPrincipal::Local {
                user_id: actor_user_id,
                bare_jid: northstar_xmpp_types::jid_text::bare_jid(actor_full_jid).to_owned(),
            },
            actor_full_jid: actor_full_jid.to_owned(),
            actor_target: None,
            subject,
            reason: None,
        }))
    }
}
