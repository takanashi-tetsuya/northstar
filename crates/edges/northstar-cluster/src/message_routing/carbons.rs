use crate::delivery_contract::{NodeDeliveryAck, NodeDeliveryOptions, NodeDeliveryReceipt};
use crate::ClusterManager;
use northstar_message_application::message_carbons::Direction;
use northstar_message_application::messaging::ExactMessageRoute;
use northstar_message_application::telemetry::PersonalMessageTelemetry;
use northstar_message_core::validation::carbon_message;
use std::collections::BTreeMap;
use uuid::Uuid;

pub(crate) fn exact_carbon_receipt(
    ack: &NodeDeliveryAck,
    mut receipt: NodeDeliveryReceipt,
) -> NodeDeliveryReceipt {
    if ack.delivery.is_none() {
        receipt.acknowledged = false;
    }
    receipt
}

impl ClusterManager {
    pub async fn route_sent_carbons_to_remote_resources(
        &self,
        bare: &str,
        forwarded: &str,
        routes: &[ExactMessageRoute],
        muc_scope: Option<(&str, &str)>,
        telemetry: &PersonalMessageTelemetry<'_>,
    ) {
        self.route_remote_carbons(
            bare,
            forwarded,
            Direction::Sent,
            routes,
            muc_scope,
            telemetry,
        )
        .await;
    }

    pub async fn route_received_carbons_to_remote_resources(
        &self,
        recipient: &str,
        forwarded: &str,
        routes: &[ExactMessageRoute],
        telemetry: &PersonalMessageTelemetry<'_>,
    ) {
        self.route_remote_carbons(
            recipient,
            forwarded,
            Direction::Received,
            routes,
            None,
            telemetry,
        )
        .await;
    }

    async fn route_remote_carbons(
        &self,
        bare: &str,
        forwarded: &str,
        direction: Direction,
        routes: &[ExactMessageRoute],
        muc_scope: Option<(&str, &str)>,
        telemetry: &PersonalMessageTelemetry<'_>,
    ) {
        let mut groups = BTreeMap::<_, BTreeMap<_, _>>::new();
        for route in routes {
            if let Some(node) = route
                .node_id
                .as_deref()
                .filter(|node| *node != self.node_id.as_str())
            {
                groups
                    .entry((node, route.account_id, route.auth_generation))
                    .or_default()
                    .insert(route.full_jid.clone(), route.connection_id);
            }
        }
        for ((node, account_id, generation), connections) in groups {
            let Some(carbon) = carbon_message(direction.as_str(), bare, bare, forwarded) else {
                telemetry.carbon_delivery_failed();
                tracing::error!(%node, %bare, direction = direction.as_str(), "suppressed an invalid cluster XEP-0280 Carbon payload");
                continue;
            };
            let receipt = self
                .send_to_node_receipt(
                    node,
                    bare,
                    &carbon,
                    carbon_options(account_id, generation, &connections, muc_scope),
                )
                .await;
            if !receipt.as_ref().is_ok_and(|receipt| receipt.acknowledged) {
                count_unacknowledged_carbon(telemetry);
                tracing::warn!(%node, %bare, direction = direction.as_str(), ?receipt, "post-accept Carbon could not be routed to a cluster peer");
            }
        }
    }
}

pub(crate) fn count_unacknowledged_carbon(telemetry: &PersonalMessageTelemetry<'_>) {
    telemetry.carbon_delivery_failed();
}

fn carbon_options<'a>(
    account_id: Uuid,
    auth_generation: i64,
    connections: &'a BTreeMap<String, Uuid>,
    muc_scope: Option<(&'a str, &'a str)>,
) -> NodeDeliveryOptions<'a> {
    NodeDeliveryOptions {
        carbons_only: true,
        expected_user_id: Some(account_id),
        expected_auth_generation: Some(auth_generation),
        exact_message_routes: Some(connections),
        carbon_muc_scope: muc_scope,
        ..NodeDeliveryOptions::default()
    }
}
