use super::ClusterNodeDelivery;
use crate::{
    ClusterManager, ClusterPresenceAuthority, ExactControl, ExactControlKind, ExactControlSource,
    NodeDeliveryOptions,
};
use anyhow::Result;
use northstar_message_application::messaging::ExactMessageRoute;
use northstar_roster_core::{ExactPresenceRoute, RosterActor};

impl ClusterManager {
    pub(crate) async fn send_captured_subscription(
        &self,
        node_id: &str,
        target: &str,
        stanza: &str,
        authority: ClusterPresenceAuthority,
        routes: &[ExactMessageRoute],
    ) -> Result<bool> {
        let expected_connections: std::collections::BTreeMap<_, _> = routes
            .iter()
            .filter(|route| {
                route.node_id.as_deref() == Some(node_id) && route.available == Some(true)
            })
            .map(|route| (route.full_jid.clone(), route.connection_id))
            .collect();
        if expected_connections.is_empty() {
            return Ok(false);
        }
        let control = ExactControl {
            kind: ExactControlKind::SubscriptionPresence,
            account_id: authority.recipient_id,
            auth_generation: authority.recipient_auth_generation,
            expected_connections,
            roster_version: None,
            blocklist_revision: None,
            remote_peer: None,
            source: None,
            sequence: None,
        };
        Ok(self
            .send_to_node_receipt(
                node_id,
                target,
                stanza,
                NodeDeliveryOptions {
                    presence_authority: Some(authority),
                    exact_control: Some(&control),
                    ..NodeDeliveryOptions::default()
                },
            )
            .await?
            .delivered)
    }

    /// Sends exact presence to one captured remote route. `sequence` is the
    /// source connection's broadcast epoch, which orders CSI status slots.
    pub async fn send_exact_presence(
        &self,
        source: &RosterActor,
        recipient: &ExactPresenceRoute,
        stanza: &str,
        kind: ExactControlKind,
        available_only: bool,
        sequence: Option<u64>,
    ) -> Result<bool> {
        let Some(node) = recipient.node_id.as_deref() else {
            return Ok(false);
        };
        let mut control = presence_control(source, recipient, kind);
        control.sequence = sequence;
        Ok(self
            .send_to_node_receipt(
                node,
                &recipient.full_jid,
                stanza,
                NodeDeliveryOptions {
                    available_only,
                    exact_control: Some(&control),
                    ..NodeDeliveryOptions::default()
                },
            )
            .await?
            .delivered)
    }
}

pub(crate) fn presence_control(
    source: &RosterActor,
    recipient: &ExactPresenceRoute,
    kind: ExactControlKind,
) -> ExactControl {
    ExactControl {
        kind,
        account_id: recipient.account_id,
        auth_generation: recipient.auth_generation,
        expected_connections: [(recipient.full_jid.clone(), recipient.connection_id)].into(),
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
    }
}

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
                    legacy_directed_or_blocking_presence: true,
                    ..NodeDeliveryOptions::default()
                },
            )
            .await?
            .delivered)
    }

    pub(crate) async fn send_current_presence_replay(
        &self,
        node_id: &str,
        target_jid: &str,
        stanza: &str,
        control: &ExactControl,
    ) -> Result<bool> {
        Ok(self
            .send_to_node_receipt(
                node_id,
                target_jid,
                stanza,
                NodeDeliveryOptions {
                    exact_control: Some(control),
                    ..NodeDeliveryOptions::default()
                },
            )
            .await?
            .delivered)
    }
}
