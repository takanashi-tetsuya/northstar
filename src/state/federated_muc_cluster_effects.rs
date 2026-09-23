//! Cluster effects for federated MUC messages addressed to local accounts.

use super::AppState;
use crate::cluster::NodeDeliveryReceipt;
use crate::outbound::DurableDelivery;

pub(crate) struct FederatedMucAccountRoute {
    pub(crate) accepted_full_jid: Option<String>,
}

fn accepted_primary_route(receipt: NodeDeliveryReceipt) -> Option<FederatedMucAccountRoute> {
    (receipt.delivered && receipt.acknowledged).then_some(FederatedMucAccountRoute {
        accepted_full_jid: receipt.accepted_full_jid,
    })
}

impl AppState {
    /// Forward a mediated invitation or decline to the first remote primary
    /// resource that acknowledges delivery. A durable invitation keeps its
    /// exact spool-row fence across this hand-off. Lookup and send failures
    /// are best-effort here; the caller retains its offline-storage policy.
    pub(crate) async fn route_federated_muc_account_message_remote(
        &self,
        target_jid: &str,
        stanza: &str,
        delivery: Option<DurableDelivery>,
    ) -> Option<FederatedMucAccountRoute> {
        for node_id in self
            .cluster
            .lookup_nodes(target_jid)
            .await
            .unwrap_or_default()
        {
            if node_id == self.cluster.node_id {
                continue;
            }
            let receipt = if let Some(delivery) = delivery {
                self.cluster
                    .send_to_node_primary_durable(&node_id, target_jid, stanza, delivery)
                    .await
                    .unwrap_or_default()
            } else {
                self.cluster
                    .send_to_node_primary(&node_id, target_jid, stanza)
                    .await
                    .unwrap_or_default()
            };
            if let Some(route) = accepted_primary_route(receipt) {
                return Some(route);
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::accepted_primary_route;
    use crate::cluster::NodeDeliveryReceipt;

    #[test]
    fn account_route_requires_delivery_and_acknowledgement() {
        assert!(accepted_primary_route(NodeDeliveryReceipt {
            delivered: true,
            ..NodeDeliveryReceipt::default()
        })
        .is_none());
        assert!(accepted_primary_route(NodeDeliveryReceipt {
            acknowledged: true,
            ..NodeDeliveryReceipt::default()
        })
        .is_none());
        let route = accepted_primary_route(NodeDeliveryReceipt {
            delivered: true,
            acknowledged: true,
            accepted_full_jid: Some("alice@example.test/phone".to_owned()),
            ..NodeDeliveryReceipt::default()
        })
        .expect("acknowledged primary delivery is accepted");
        assert_eq!(
            route.accepted_full_jid.as_deref(),
            Some("alice@example.test/phone")
        );
        let legacy_route = accepted_primary_route(NodeDeliveryReceipt {
            delivered: true,
            acknowledged: true,
            ..NodeDeliveryReceipt::default()
        })
        .expect("a legacy peer may acknowledge without a resource key");
        assert!(legacy_route.accepted_full_jid.is_none());
    }
}
