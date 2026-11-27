use super::ClusterNodeDelivery;
use crate::{
    ClusterManager, ExactControl, ExactControlKind, ExactControlSource, NodeDeliveryOptions,
};
use anyhow::Result;
use northstar_roster_core::{ExactPresenceRoute, RosterActor};
use northstar_session_application::sm_teardown_presence::{ExactPresenceAcceptance, TerminalRoute};
use std::collections::BTreeMap;

#[derive(Clone)]
pub struct ClusterUnavailableDelivery {
    pub(crate) sender: ClusterNodeDelivery,
}

impl ClusterUnavailableDelivery {
    /// Send one effect to the exact connection named by the captured audience.
    pub async fn send_terminal_unavailable(
        &self,
        source: &TerminalRoute,
        target: &TerminalRoute,
        stanza: &str,
    ) -> Result<ExactPresenceAcceptance> {
        let Some(node) = target.node_id.as_deref() else {
            return Ok(ExactPresenceAcceptance::Gone);
        };
        self.sender
            .send_exact_presence(
                node,
                &ExactPresenceRoute {
                    account_id: target.account_id,
                    auth_generation: target.auth_generation,
                    connection_id: target.connection_id,
                    full_jid: target.full_jid.clone(),
                    node_id: target.node_id.clone(),
                },
                &RosterActor {
                    account_id: source.account_id,
                    auth_generation: source.auth_generation,
                    connection_id: source.connection_id,
                    full_jid: source.full_jid.clone(),
                },
                stanza,
                ExactControlKind::TeardownUnavailable,
            )
            .await
    }
}

impl ClusterManager {
    pub async fn send_exact_directed_presence(
        &self,
        route: &ExactPresenceRoute,
        source: &RosterActor,
        stanza: &str,
        unavailable: bool,
    ) -> Result<ExactPresenceAcceptance> {
        let Some(node) = route.node_id.as_deref() else {
            return Ok(ExactPresenceAcceptance::Gone);
        };
        let kind = if unavailable {
            ExactControlKind::UnavailablePresence
        } else {
            ExactControlKind::DirectedPresence
        };
        self.node_delivery()
            .send_exact_presence(node, route, source, stanza, kind)
            .await
    }
}

impl ClusterNodeDelivery {
    async fn send_exact_presence(
        &self,
        node: &str,
        route: &ExactPresenceRoute,
        source: &RosterActor,
        stanza: &str,
        kind: ExactControlKind,
    ) -> Result<ExactPresenceAcceptance> {
        let control = ExactControl {
            kind,
            account_id: route.account_id,
            auth_generation: route.auth_generation,
            expected_connections: BTreeMap::from([(route.full_jid.clone(), route.connection_id)]),
            roster_version: None,
            blocklist_revision: None,
            remote_peer: None,
            source: Some(ExactControlSource {
                account_id: source.account_id,
                auth_generation: source.auth_generation,
                connection_id: source.connection_id,
                full_jid: source.full_jid.clone(),
            }),
            sequence: None,
        };
        let receipt = self
            .send_to_node_receipt(
                node,
                &route.full_jid,
                stanza,
                NodeDeliveryOptions {
                    exact_control: Some(&control),
                    ..NodeDeliveryOptions::default()
                },
            )
            .await?;
        Ok(
            match (
                receipt.acknowledged,
                receipt.delivered,
                receipt.retryable_presence,
            ) {
                (true, true, _)
                    if receipt.accepted_full_jid.as_deref() == Some(route.full_jid.as_str()) =>
                {
                    ExactPresenceAcceptance::Accepted
                }
                (true, false, true) => ExactPresenceAcceptance::Retry,
                (true, false, false) => ExactPresenceAcceptance::Gone,
                _ => ExactPresenceAcceptance::Unknown,
            },
        )
    }
}
