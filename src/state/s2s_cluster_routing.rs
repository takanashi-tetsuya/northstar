use super::AppState;

#[derive(Default)]
pub(crate) struct S2sRemotePrimaryDelivery {
    pub(crate) delivered: bool,
    pub(crate) accepted_full_jid: Option<String>,
}

impl AppState {
    /// A failed lookup supplies no evidence of a remote recipient route.
    pub(crate) async fn s2s_remote_recipient_route_exists(&self, jid: &str) -> bool {
        self.cluster
            .lookup_nodes(jid)
            .await
            .is_ok_and(|nodes| nodes.iter().any(|node_id| node_id != &self.cluster.node_id))
    }

    /// Preserve the full-JID subscription check's historical treatment of
    /// any route entry, including this node, as an existing resource.
    pub(crate) async fn s2s_subscription_target_route_exists(&self, full_jid: &str) -> bool {
        self.cluster
            .lookup_nodes(full_jid)
            .await
            .is_ok_and(|nodes| !nodes.is_empty())
    }

    /// Fan a bare-JID stanza out to every remote available resource. Durable
    /// delivery carries the same acknowledgement fence as the local queue.
    pub(crate) async fn route_s2s_message_to_available_remote_resources(
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

    /// Try remote primary routes in lookup order and return only the full JID
    /// actually accepted by the first delivery. Legacy uncorrelated receipts
    /// still count as accepted but cannot supply a Carbon exclusion key.
    pub(crate) async fn route_s2s_message_to_remote_primary(
        &self,
        jid: &str,
        stanza: &str,
        delivery: Option<crate::outbound::DurableDelivery>,
    ) -> S2sRemotePrimaryDelivery {
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
                if crate::xmpp::protocol::messaging::accepted_cluster_message_delivery(
                    self, &node_id, jid, &receipt,
                ) {
                    return S2sRemotePrimaryDelivery {
                        delivered: true,
                        accepted_full_jid: receipt.accepted_full_jid,
                    };
                }
            }
        }
        S2sRemotePrimaryDelivery::default()
    }

    /// An IQ result/error belongs to one full JID. Stop after the first node
    /// accepts it; never fan an uncorrelated response out to every resource.
    pub(crate) async fn route_s2s_iq_response_to_remote_resource(
        &self,
        full_jid: &str,
        stanza: &str,
    ) {
        if let Ok(nodes) = self.cluster.lookup_nodes(full_jid).await {
            for node_id in nodes {
                if node_id != self.cluster.node_id
                    && self
                        .cluster
                        .send_to_node(&node_id, full_jid, stanza, false, None)
                        .await
                        .unwrap_or(false)
                {
                    break;
                }
            }
        }
    }

    /// The first remote primary accepts a bare-JID request; full-JID requests
    /// may be accepted by more than one owning node during a route handoff.
    pub(crate) async fn route_s2s_iq_request_remote(
        &self,
        jid: &str,
        stanza: &str,
        bare_target: bool,
    ) -> bool {
        let mut delivered = false;
        if let Ok(nodes) = self.cluster.lookup_nodes(jid).await {
            for node_id in nodes {
                if node_id == self.cluster.node_id {
                    continue;
                }
                let accepted = if bare_target {
                    self.cluster
                        .send_to_node_primary(&node_id, jid, stanza)
                        .await
                        .is_ok_and(|receipt| receipt.delivered)
                } else {
                    self.cluster
                        .send_to_node(&node_id, jid, stanza, false, None)
                        .await
                        .unwrap_or(false)
                };
                if accepted {
                    delivered = true;
                    if bare_target {
                        break;
                    }
                }
            }
        }
        delivered
    }
}
