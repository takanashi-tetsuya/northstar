//! Cluster routes for client IQs, personal messages, their Carbons, and direct MUC invitations.

use crate::ClusterManager;
use anyhow::Result;
use northstar_message_application::messaging::OnlineRouteResult;
use northstar_message_application::telemetry::PersonalMessageTelemetry;
use northstar_message_core::validation::carbon_message;
use northstar_room_application::muc_service::{
    ClusterMucAffiliationSubject, ClusterMucInviteAuthority, ClusterMucPrincipal,
};
use uuid::Uuid;

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
                let receipt = if let Some(delivery) = delivery {
                    self.send_to_node_primary_durable(&node_id, jid, stanza, delivery)
                        .await
                        .unwrap_or_default()
                } else {
                    self.send_to_node_primary(&node_id, jid, stanza)
                        .await
                        .unwrap_or_default()
                };
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

    /// Carbons are best effort after primary acceptance. Keep one attempt and
    /// one failure count per remote node, including invalid wrapper failures.
    pub async fn route_sent_carbons_to_remote_resources(
        &self,
        bare: &str,
        forwarded: &str,
        current: &str,
        delivered_self: Option<&str>,
        muc_scope: Option<(&str, &str)>,
        telemetry: &PersonalMessageTelemetry<'_>,
    ) {
        match self.lookup_nodes(bare).await {
            Ok(nodes) => {
                for node_id in nodes {
                    if node_id == self.node_id {
                        continue;
                    }
                    let Some(carbon) = carbon_message("sent", bare, bare, forwarded) else {
                        telemetry.carbon_delivery_failed();
                        tracing::error!(%node_id, %bare, direction = "sent", "suppressed an invalid cluster XEP-0280 Carbon payload");
                        continue;
                    };
                    // Version 1 peers use only the first scalar exclusion.
                    let mut exclusions = delivered_self.into_iter().collect::<Vec<_>>();
                    exclusions.push(current);
                    let routed = if let Some((room, nick)) = muc_scope {
                        self.send_to_node_muc_carbons_excluding(
                            &node_id,
                            bare,
                            &carbon,
                            &exclusions,
                            room,
                            nick,
                        )
                        .await
                    } else {
                        self.send_to_node_excluding(&node_id, bare, &carbon, true, &exclusions)
                            .await
                    };
                    if let Err(error) = routed {
                        telemetry.carbon_delivery_failed();
                        tracing::warn!(%node_id, %bare, ?error, direction = "sent", "post-accept Carbon could not be routed to a cluster peer");
                    }
                }
            }
            Err(error) => {
                telemetry.carbon_delivery_failed();
                tracing::warn!(%bare, ?error, direction = "sent", "cluster Carbon recipient lookup failed after primary acceptance");
            }
        }
    }

    pub async fn route_received_carbons_to_remote_resources(
        &self,
        recipient: &str,
        delivered: Option<&str>,
        forwarded: &str,
        telemetry: &PersonalMessageTelemetry<'_>,
    ) {
        match self.lookup_nodes(recipient).await {
            Ok(nodes) => {
                for node_id in nodes {
                    if node_id == self.node_id {
                        continue;
                    }
                    let Some(carbon) = carbon_message("received", recipient, recipient, forwarded)
                    else {
                        telemetry.carbon_delivery_failed();
                        tracing::error!(%node_id, %recipient, direction = "received", "suppressed an invalid cluster XEP-0280 Carbon payload");
                        continue;
                    };
                    if let Err(error) = self
                        .send_to_node(&node_id, recipient, &carbon, true, delivered)
                        .await
                    {
                        telemetry.carbon_delivery_failed();
                        tracing::warn!(%node_id, %recipient, ?error, direction = "received", "post-accept Carbon could not be routed to a cluster peer");
                    }
                }
            }
            Err(error) => {
                telemetry.carbon_delivery_failed();
                tracing::warn!(%recipient, ?error, direction = "received", "cluster Carbon recipient lookup failed after primary acceptance");
            }
        }
    }
}
