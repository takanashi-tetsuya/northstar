//! Cluster routes for client IQs, personal messages, and their Carbons.

use super::{AppState, OnlineSession};
use crate::outbound::DurableDelivery;
use crate::services::messaging::{OnlineRoutePort, OnlineRouteResult};
use crate::services::muc::{
    ClusterMucAffiliationSubject, ClusterMucInviteAuthority, ClusterMucPrincipal,
};
use crate::xmpp::xml_util::carbon_message;
use anyhow::Result;
use uuid::Uuid;

impl OnlineRoutePort for AppState {
    type Session = OnlineSession;

    fn try_local(
        &self,
        session: &Self::Session,
        stanza: String,
        delivery: Option<DurableDelivery>,
    ) -> bool {
        if let Some(delivery) = delivery {
            session.sender.try_send_durable(stanza, delivery).is_ok()
        } else {
            session.sender.try_send(stanza).is_ok()
        }
    }

    fn record_local_accept(&self, durable: bool) {
        self.personal_message_telemetry()
            .online_queue_result(true, durable);
    }

    async fn route_available_remote(
        &self,
        jid: &str,
        stanza: &str,
        delivery: Option<DurableDelivery>,
    ) -> bool {
        self.route_personal_message_to_available_remote_resources(jid, stanza, delivery)
            .await
    }

    async fn route_remote_primary(
        &self,
        jid: &str,
        stanza: &str,
        delivery: Option<DurableDelivery>,
    ) -> OnlineRouteResult {
        self.route_personal_message_to_remote_primary(jid, stanza, delivery)
            .await
    }
}

/// An old cluster peer may acknowledge only with a delivered count. Accept a
/// positive receipt rather than risk duplicating a stanza in offline storage.
pub(super) fn accepted_cluster_message_delivery(
    state: &AppState,
    node_id: &str,
    target: &str,
    receipt: &crate::cluster::NodeDeliveryReceipt,
) -> bool {
    if receipt.delivered && !receipt.acknowledged {
        state.personal_message_telemetry().cluster_legacy_accepted();
        tracing::warn!(%node_id, %target, "accepted legacy uncorrelated cluster message delivery acknowledgement");
    }
    receipt.delivered
}

impl AppState {
    /// A failed route lookup supplies no evidence of an exact remote resource.
    pub(crate) async fn personal_message_remote_resource_exists(&self, jid: &str) -> bool {
        self.cluster
            .lookup_nodes(jid)
            .await
            .is_ok_and(|nodes| nodes.iter().any(|node| node != &self.cluster.node_id))
    }

    /// Client IQs addressed to a full JID stop at the first accepting node.
    pub(crate) async fn route_client_iq_to_remote_resource(
        &self,
        full_jid: &str,
        stanza: &str,
    ) -> bool {
        if let Ok(nodes) = self.cluster.lookup_nodes(full_jid).await {
            for node_id in nodes {
                if node_id != self.cluster.node_id
                    && self
                        .cluster
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
    pub(crate) async fn route_personal_message_to_available_remote_resources(
        &self,
        jid: &str,
        stanza: &str,
        delivery: Option<crate::outbound::DurableDelivery>,
    ) -> bool {
        let mut delivered = false;
        if let Ok(nodes) = self.cluster.lookup_nodes(jid).await {
            for node_id in nodes {
                if node_id == self.cluster.node_id {
                    continue;
                }
                let accepted = if let Some(delivery) = delivery {
                    self.cluster
                        .send_to_node_available_durable(&node_id, jid, stanza, delivery)
                        .await
                        .unwrap_or(false)
                } else {
                    self.cluster
                        .send_to_node_available(&node_id, jid, stanza)
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
    pub(crate) async fn route_personal_message_to_remote_primary(
        &self,
        jid: &str,
        stanza: &str,
        delivery: Option<crate::outbound::DurableDelivery>,
    ) -> OnlineRouteResult {
        if let Ok(nodes) = self.cluster.lookup_nodes(jid).await {
            for node_id in nodes {
                if node_id == self.cluster.node_id {
                    continue;
                }
                let receipt = if let Some(delivery) = delivery {
                    self.cluster
                        .send_to_node_primary_durable(&node_id, jid, stanza, delivery)
                        .await
                        .unwrap_or_default()
                } else {
                    self.cluster
                        .send_to_node_primary(&node_id, jid, stanza)
                        .await
                        .unwrap_or_default()
                };
                if accepted_cluster_message_delivery(self, &node_id, jid, &receipt) {
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
    pub(crate) fn direct_muc_invite_cluster_authority(
        &self,
        operation_id: Uuid,
        room_epoch: Uuid,
        config_version: i64,
        actor_user_id: Uuid,
        actor_full_jid: &str,
        subject: ClusterMucAffiliationSubject,
    ) -> Result<Option<ClusterMucInviteAuthority>> {
        if !self.cluster.is_enabled() {
            return Ok(None);
        }
        self.cluster
            .admit(crate::cluster::ClusterOperation::MucMutation)?;
        Ok(Some(ClusterMucInviteAuthority {
            operation_id,
            expected_room_epoch: room_epoch,
            expected_config_version: config_version,
            actor: ClusterMucPrincipal::Local {
                user_id: actor_user_id,
                bare_jid: super::bare_jid(actor_full_jid).to_owned(),
            },
            actor_full_jid: actor_full_jid.to_owned(),
            actor_target: None,
            subject,
            reason: None,
        }))
    }

    pub(crate) async fn wake_committed_direct_muc_invite(&self, operation_id: Uuid) -> Result<()> {
        self.muc_service()
            .wake_committed_operation(&self.cluster, operation_id)
            .await
    }

    /// Carbons are best effort after primary acceptance. Keep one attempt and
    /// one failure count per remote node, including invalid wrapper failures.
    pub(crate) async fn route_sent_carbons_to_remote_resources(
        &self,
        bare: &str,
        forwarded: &str,
        current: &str,
        delivered_self: Option<&str>,
        muc_scope: Option<(&str, &str)>,
    ) {
        match self.cluster.lookup_nodes(bare).await {
            Ok(nodes) => {
                for node_id in nodes {
                    if node_id == self.cluster.node_id {
                        continue;
                    }
                    let Some(carbon) = carbon_message("sent", bare, bare, forwarded) else {
                        self.personal_message_telemetry().carbon_delivery_failed();
                        tracing::error!(%node_id, %bare, direction = "sent", "suppressed an invalid cluster XEP-0280 Carbon payload");
                        continue;
                    };
                    // Version 1 peers use only the first scalar exclusion.
                    let mut exclusions = delivered_self.into_iter().collect::<Vec<_>>();
                    exclusions.push(current);
                    let routed = if let Some((room, nick)) = muc_scope {
                        self.cluster
                            .send_to_node_muc_carbons_excluding(
                                &node_id,
                                bare,
                                &carbon,
                                &exclusions,
                                room,
                                nick,
                            )
                            .await
                    } else {
                        self.cluster
                            .send_to_node_excluding(&node_id, bare, &carbon, true, &exclusions)
                            .await
                    };
                    if let Err(error) = routed {
                        self.personal_message_telemetry().carbon_delivery_failed();
                        tracing::warn!(%node_id, %bare, ?error, direction = "sent", "post-accept Carbon could not be routed to a cluster peer");
                    }
                }
            }
            Err(error) => {
                self.personal_message_telemetry().carbon_delivery_failed();
                tracing::warn!(%bare, ?error, direction = "sent", "cluster Carbon recipient lookup failed after primary acceptance");
            }
        }
    }

    pub(crate) async fn route_received_carbons_to_remote_resources(
        &self,
        recipient: &str,
        delivered: Option<&str>,
        forwarded: &str,
    ) {
        match self.cluster.lookup_nodes(recipient).await {
            Ok(nodes) => {
                for node_id in nodes {
                    if node_id == self.cluster.node_id {
                        continue;
                    }
                    let Some(carbon) = carbon_message("received", recipient, recipient, forwarded)
                    else {
                        self.personal_message_telemetry().carbon_delivery_failed();
                        tracing::error!(%node_id, %recipient, direction = "received", "suppressed an invalid cluster XEP-0280 Carbon payload");
                        continue;
                    };
                    if let Err(error) = self
                        .cluster
                        .send_to_node(&node_id, recipient, &carbon, true, delivered)
                        .await
                    {
                        self.personal_message_telemetry().carbon_delivery_failed();
                        tracing::warn!(%node_id, %recipient, ?error, direction = "received", "post-accept Carbon could not be routed to a cluster peer");
                    }
                }
            }
            Err(error) => {
                self.personal_message_telemetry().carbon_delivery_failed();
                tracing::warn!(%recipient, ?error, direction = "received", "cluster Carbon recipient lookup failed after primary acceptance");
            }
        }
    }
}
