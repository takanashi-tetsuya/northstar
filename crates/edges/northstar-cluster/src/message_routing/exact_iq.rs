use crate::{delivery_contract::NodeDeliveryOptions, ClusterManager};
use northstar_message_application::messaging::ExactMessageRoute;

impl ClusterManager {
    pub async fn handoff_exact_iq(
        &self,
        route: &ExactMessageRoute,
        stanza: &str,
        check_only: bool,
    ) -> bool {
        let Some(node) = route
            .node_id
            .as_deref()
            .filter(|node| *node != self.node_id.as_str())
        else {
            return false;
        };
        let connections = [(route.full_jid.clone(), route.connection_id)].into();
        self.send_to_node_receipt(
            node,
            &route.full_jid,
            stanza,
            NodeDeliveryOptions {
                expected_user_id: Some(route.account_id),
                expected_auth_generation: Some(route.auth_generation),
                exact_message_routes: Some(&connections),
                exact_iq_check_only: Some(check_only),
                ..NodeDeliveryOptions::default()
            },
        )
        .await
        .is_ok_and(|receipt| {
            receipt.acknowledged
                && receipt.delivered
                && receipt.accepted_full_jid.as_deref() == Some(route.full_jid.as_str())
        })
    }
}
