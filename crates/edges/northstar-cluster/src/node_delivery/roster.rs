use super::ClusterNodeDelivery;
use crate::{ExactControl, ExactControlKind, NodeDeliveryOptions};
use anyhow::Result;
use northstar_roster_core::RosterVersion;
use std::collections::BTreeMap;
use uuid::Uuid;

impl ClusterNodeDelivery {
    pub async fn send_roster_push(
        &self,
        node_id: &str,
        target_jid: &str,
        (account_id, auth_generation): (Uuid, i64),
        routes: &BTreeMap<String, Uuid>,
        roster_version: RosterVersion,
        (stanza, annotated_stanza): (&str, Option<&str>),
    ) -> Result<bool> {
        let control = ExactControl {
            kind: ExactControlKind::RosterPush,
            account_id,
            auth_generation,
            expected_connections: routes.clone(),
            roster_version: Some(roster_version.0),
            blocklist_revision: None,
            remote_peer: None,
            source: None,
            sequence: None,
        };
        Ok(self
            .send_to_node_receipt(
                node_id,
                target_jid,
                stanza,
                NodeDeliveryOptions {
                    roster_requested_only: true,
                    exact_control: Some(&control),
                    roster_annotated_stanza: annotated_stanza,
                    ..NodeDeliveryOptions::default()
                },
            )
            .await?
            .delivered)
    }

    pub async fn send_account_removal_presence(
        &self,
        node_id: &str,
        target_jid: &str,
        stanza: &str,
    ) -> Result<bool> {
        Ok(self
            .send_to_node_receipt(node_id, target_jid, stanza, NodeDeliveryOptions::default())
            .await?
            .delivered)
    }
}
