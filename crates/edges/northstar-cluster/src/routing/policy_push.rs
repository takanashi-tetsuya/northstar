use crate::delivery_contract::NodeDeliveryOptions;
use crate::{ClusterManager, ExactControl, ExactControlKind};
use anyhow::Result;
use northstar_message_application::messaging::ExactMessageRoute;
use northstar_xml_builder::rewrite::set_to;

impl ClusterManager {
    /// Wake the blocklist observer on the captured exact resource.
    pub async fn send_to_node_blocklist(
        &self,
        route: &ExactMessageRoute,
        revision: i64,
        stanza: &str,
    ) -> Result<bool> {
        self.send_exact_policy_push(
            route,
            ExactControlKind::BlocklistPush,
            Some(revision),
            stanza,
        )
        .await
    }

    /// Deliver an XEP-0016 list-definition push only to resources that have
    /// requested privacy-list state during this logical (possibly resumed)
    /// session.
    pub async fn send_to_node_privacy(
        &self,
        route: &ExactMessageRoute,
        stanza: &str,
    ) -> Result<bool> {
        self.send_exact_policy_push(route, ExactControlKind::PrivacyPush, None, stanza)
            .await
    }

    async fn send_exact_policy_push(
        &self,
        route: &ExactMessageRoute,
        kind: ExactControlKind,
        blocklist_revision: Option<i64>,
        stanza: &str,
    ) -> Result<bool> {
        let node_id = route
            .node_id
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("no remote policy route"))?;
        let control = policy_push_control(route, kind, blocklist_revision);
        Ok(self
            .send_to_node_receipt(
                node_id,
                &route.full_jid,
                &set_to(stanza, &route.full_jid),
                NodeDeliveryOptions {
                    exact_control: Some(&control),
                    ..NodeDeliveryOptions::default()
                },
            )
            .await?
            .delivered)
    }
}

pub(crate) fn policy_push_control(
    route: &ExactMessageRoute,
    kind: ExactControlKind,
    blocklist_revision: Option<i64>,
) -> ExactControl {
    ExactControl {
        kind,
        account_id: route.account_id,
        auth_generation: route.auth_generation,
        expected_connections: [(route.full_jid.clone(), route.connection_id)].into(),
        roster_version: None,
        blocklist_revision,
        remote_peer: None,
        source: None,
        sequence: None,
    }
}
