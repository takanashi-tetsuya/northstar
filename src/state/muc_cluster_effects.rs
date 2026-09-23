//! Cluster authority, cache and publication commands for local MUC.

use super::{AppState, SerializableMucOccupant};
use crate::cluster::{ClusterOperation, MucRename, MucRoleChange, NodeDeliveryReceipt};
use crate::outbound::DurableDelivery;
use anyhow::Result;
use std::collections::HashMap;

pub(crate) struct MucPresencePublication<'a> {
    pub(crate) room: &'a str,
    pub(crate) occupant: &'a SerializableMucOccupant,
    pub(crate) unavailable: bool,
    pub(crate) created: bool,
    pub(crate) removal_status: Option<u16>,
    pub(crate) actor_nick: Option<&'a str>,
    pub(crate) reason: Option<&'a str>,
}

impl AppState {
    pub(crate) fn muc_cluster_enabled(&self) -> bool {
        self.cluster.is_enabled()
    }

    pub(crate) fn muc_cluster_node_id(&self) -> &str {
        &self.cluster.node_id
    }

    pub(crate) fn admit_muc_cluster_mutation(&self) -> Result<()> {
        self.cluster.admit(ClusterOperation::MucMutation)
    }

    pub(crate) async fn cached_muc_cluster_occupants(
        &self,
        room: &str,
    ) -> Result<HashMap<String, String>> {
        self.cluster.get_muc_occupants(room).await
    }

    pub(crate) async fn join_cluster_muc_room(&self, room: &str) -> Result<()> {
        self.cluster.join_muc(room).await
    }

    pub(crate) async fn publish_muc_cluster_presence_with_id(
        &self,
        room: &str,
        occupant: &SerializableMucOccupant,
        unavailable: bool,
        created: bool,
        id: Option<&str>,
    ) -> Result<()> {
        self.cluster
            .send_muc_presence(room, occupant, unavailable, created, id)
            .await
    }

    pub(crate) async fn publish_muc_cluster_nickname_change(
        &self,
        room: &str,
        before: &SerializableMucOccupant,
        after: &SerializableMucOccupant,
        id: Option<&str>,
    ) -> Result<()> {
        self.cluster
            .send_muc_nickname_change(room, before, after, id)
            .await
    }

    pub(crate) async fn rename_cluster_muc_occupant_exact(
        &self,
        room: &str,
        old_nick: &str,
        new_nick: &str,
        expected_epoch: uuid::Uuid,
        old_json: &str,
        new_json: &str,
    ) -> Result<MucRename> {
        self.cluster
            .rename_muc_occupant(room, old_nick, new_nick, expected_epoch, old_json, new_json)
            .await
    }

    pub(crate) async fn change_cluster_muc_role_exact(
        &self,
        room: &str,
        occupant: &SerializableMucOccupant,
        role: &str,
    ) -> Result<MucRoleChange> {
        self.cluster
            .change_muc_occupant_role(room, occupant, role)
            .await
    }

    pub(crate) async fn change_cluster_muc_affiliation_exact(
        &self,
        room: &str,
        occupant: &SerializableMucOccupant,
        affiliation: &str,
        role: &str,
    ) -> Result<MucRoleChange> {
        self.cluster
            .change_muc_occupant_affiliation(room, occupant, affiliation, role)
            .await
    }

    pub(crate) async fn revoke_cluster_muc_occupant_exact(
        &self,
        occupant: &SerializableMucOccupant,
        status: u16,
        actor_nick: Option<&str>,
        reason: Option<&str>,
    ) -> Result<bool> {
        self.cluster
            .evict_muc_occupant(occupant, status, actor_nick, reason)
            .await
    }

    pub(crate) fn record_muc_cluster_control_plane_failure(&self, error: &anyhow::Error) {
        self.cluster.record_control_plane_failure(error);
    }

    pub(crate) async fn publish_muc_cluster_private_message(
        &self,
        room: &str,
        nick: &str,
        stanza: &str,
        real_sender: &str,
    ) -> Result<()> {
        self.cluster
            .send_muc_private_from(room, nick, stanza, real_sender)
            .await
    }

    /// Route a room invitation or refusal to one remote primary recipient.
    /// A failed lookup or send is treated as no delivery, so the caller can
    /// retain its existing durable/offline fallback. Only an acknowledged
    /// receipt proves that a remote node accepted the message.
    pub(crate) async fn deliver_muc_primary_to_remote_node(
        &self,
        target: &str,
        stanza: &str,
        durable: Option<DurableDelivery>,
    ) -> Option<NodeDeliveryReceipt> {
        let nodes = self.cluster.lookup_nodes(target).await.ok()?;
        for node in nodes {
            if node == self.cluster.node_id {
                continue;
            }
            let receipt = match durable {
                Some(delivery) => {
                    self.cluster
                        .send_to_node_primary_durable(&node, target, stanza, delivery)
                        .await
                }
                None => {
                    self.cluster
                        .send_to_node_primary(&node, target, stanza)
                        .await
                }
            };
            match receipt {
                Ok(receipt) if receipt.delivered && receipt.acknowledged => return Some(receipt),
                _ => {}
            }
        }
        None
    }

    pub(crate) async fn publish_muc_cluster_stanza(
        &self,
        room: &str,
        stanza: &str,
        real_sender: Option<&str>,
    ) -> Result<()> {
        match real_sender {
            Some(sender) => self.cluster.send_to_muc_from(room, stanza, sender).await,
            None => self.cluster.send_to_muc(room, stanza).await,
        }
    }

    pub(crate) async fn evict_cluster_muc_occupant(
        &self,
        occupant: &SerializableMucOccupant,
        status: u16,
        actor_nick: Option<&str>,
        reason: Option<&str>,
    ) -> Result<()> {
        self.cluster
            .evict_muc_occupant(occupant, status, actor_nick, reason)
            .await
            .map(|_| ())
    }

    pub(crate) async fn leave_cluster_muc_room(&self, room: &str) -> Result<()> {
        self.cluster.leave_muc(room).await
    }

    pub(crate) async fn register_cluster_muc_occupant(
        &self,
        room: &str,
        nick: &str,
        json: &str,
    ) -> Result<bool> {
        self.cluster.register_muc_occupant(room, nick, json).await
    }

    pub(crate) async fn publish_muc_cluster_presence(
        &self,
        publication: MucPresencePublication<'_>,
    ) -> Result<()> {
        self.cluster
            .send_muc_presence_with_status(
                publication.room,
                publication.occupant,
                publication.unavailable,
                publication.created,
                None,
                publication.removal_status,
                publication.actor_nick,
                publication.reason,
            )
            .await
    }
}
