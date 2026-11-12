//! PostgreSQL occupancy mode and optional Redis routing for local MUC.

use crate::{ClusterManager, ClusterOperation};
use anyhow::Result;
use northstar_delivery_core::node_delivery::NodeDeliveryReceipt;
use northstar_room_application::muc_service::SerializableMucOccupant;
use northstar_room_core::occupancy::MucPresencePublication;
use northstar_room_core::occupancy::{MucRename, MucRoleChange};
use northstar_stream::outbound::DurableDelivery;
use std::collections::HashMap;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct MucRuntimeMode {
    pg_authority: bool,
    redis_transport: bool,
}

impl MucRuntimeMode {
    fn current(redis_enabled: bool) -> Self {
        // Room occupancy and admin mutations use PostgreSQL in both modes.
        // Redis adds cross-node routing when it is configured.
        Self {
            pg_authority: true,
            redis_transport: redis_enabled,
        }
    }
}

impl ClusterManager {
    fn muc_runtime_mode(&self) -> MucRuntimeMode {
        MucRuntimeMode::current(self.is_enabled())
    }

    pub fn muc_pg_authority_enabled(&self) -> bool {
        self.muc_runtime_mode().pg_authority
    }

    pub fn muc_redis_transport_enabled(&self) -> bool {
        self.muc_runtime_mode().redis_transport
    }

    pub fn muc_cluster_node_id(&self) -> &str {
        &self.node_id
    }

    pub fn admit_muc_pg_mutation(&self) -> Result<()> {
        if self.muc_redis_transport_enabled() {
            self.admit(ClusterOperation::MucMutation)?;
        }
        Ok(())
    }

    pub async fn cached_muc_cluster_occupants(
        &self,
        room: &str,
    ) -> Result<HashMap<String, String>> {
        if !self.muc_redis_transport_enabled() {
            return Ok(HashMap::new());
        }
        self.get_muc_occupants(room).await
    }

    pub async fn join_cluster_muc_room(&self, room: &str) -> Result<()> {
        if !self.muc_redis_transport_enabled() {
            return Ok(());
        }
        self.join_muc(room).await
    }

    pub async fn publish_muc_cluster_presence_with_id(
        &self,
        room: &str,
        occupant: &SerializableMucOccupant,
        unavailable: bool,
        created: bool,
        id: Option<&str>,
    ) -> Result<()> {
        if !self.muc_redis_transport_enabled() {
            return Ok(());
        }
        self.send_muc_presence(room, occupant, unavailable, created, id)
            .await
    }

    pub async fn publish_muc_cluster_nickname_change(
        &self,
        room: &str,
        before: &SerializableMucOccupant,
        after: &SerializableMucOccupant,
        id: Option<&str>,
    ) -> Result<()> {
        if !self.muc_redis_transport_enabled() {
            return Ok(());
        }
        self.send_muc_nickname_change(room, before, after, id).await
    }

    pub async fn rename_cluster_muc_occupant_exact(
        &self,
        room: &str,
        old_nick: &str,
        new_nick: &str,
        expected_epoch: uuid::Uuid,
        old_json: &str,
        new_json: &str,
    ) -> Result<MucRename> {
        if !self.muc_redis_transport_enabled() {
            return Ok(MucRename::Renamed);
        }
        self.rename_muc_occupant(room, old_nick, new_nick, expected_epoch, old_json, new_json)
            .await
    }

    pub async fn change_cluster_muc_role_exact(
        &self,
        room: &str,
        occupant: &SerializableMucOccupant,
        role: &str,
    ) -> Result<MucRoleChange> {
        self.change_muc_occupant_role(room, occupant, role).await
    }

    pub async fn change_cluster_muc_affiliation_exact(
        &self,
        room: &str,
        occupant: &SerializableMucOccupant,
        affiliation: &str,
        role: &str,
    ) -> Result<MucRoleChange> {
        self.change_muc_occupant_affiliation(room, occupant, affiliation, role)
            .await
    }

    pub async fn revoke_cluster_muc_occupant_exact(
        &self,
        occupant: &SerializableMucOccupant,
        status: u16,
        actor_nick: Option<&str>,
        reason: Option<&str>,
    ) -> Result<bool> {
        if !self.muc_redis_transport_enabled() {
            return Ok(true);
        }
        self.evict_muc_occupant(occupant, status, actor_nick, reason)
            .await
    }

    pub fn record_muc_cluster_control_plane_failure(&self, error: &anyhow::Error) {
        if self.muc_redis_transport_enabled() {
            self.record_control_plane_failure(error);
        }
    }

    pub async fn publish_muc_cluster_private_message(
        &self,
        room: &str,
        nick: &str,
        stanza: &str,
        real_sender: &str,
    ) -> Result<()> {
        if !self.muc_redis_transport_enabled() {
            return Ok(());
        }
        self.send_muc_private_from(room, nick, stanza, real_sender)
            .await
    }

    /// Route a room invitation or refusal to one remote primary recipient.
    /// A failed lookup or send is treated as no delivery, so the caller can
    /// retain its existing durable/offline fallback. Only an acknowledged
    /// receipt proves that a remote node accepted the message.
    pub async fn deliver_muc_primary_to_remote_node(
        &self,
        target: &str,
        stanza: &str,
        durable: Option<DurableDelivery>,
    ) -> Option<NodeDeliveryReceipt> {
        if !self.muc_redis_transport_enabled() {
            return None;
        }
        let nodes = self.lookup_nodes(target).await.ok()?;
        for node in nodes {
            if node == self.node_id {
                continue;
            }
            let receipt = match durable {
                Some(delivery) => {
                    self.send_to_node_primary_durable(&node, target, stanza, delivery)
                        .await
                }
                None => self.send_to_node_primary(&node, target, stanza).await,
            };
            match receipt {
                Ok(receipt) if receipt.delivered && receipt.acknowledged => return Some(receipt),
                _ => {}
            }
        }
        None
    }

    pub async fn publish_muc_cluster_stanza(
        &self,
        room: &str,
        stanza: &str,
        real_sender: Option<&str>,
    ) -> Result<()> {
        if !self.muc_redis_transport_enabled() {
            return Ok(());
        }
        match real_sender {
            Some(sender) => self.send_to_muc_from(room, stanza, sender).await,
            None => self.send_to_muc(room, stanza).await,
        }
    }

    pub async fn evict_cluster_muc_occupant(
        &self,
        occupant: &SerializableMucOccupant,
        status: u16,
        actor_nick: Option<&str>,
        reason: Option<&str>,
    ) -> Result<()> {
        if !self.muc_redis_transport_enabled() {
            return Ok(());
        }
        self.evict_muc_occupant(occupant, status, actor_nick, reason)
            .await
            .map(|_| ())
    }

    pub async fn leave_cluster_muc_room(&self, room: &str) -> Result<()> {
        if !self.muc_redis_transport_enabled() {
            return Ok(());
        }
        self.leave_muc(room).await
    }

    pub async fn register_cluster_muc_occupant(
        &self,
        room: &str,
        nick: &str,
        json: &str,
    ) -> Result<bool> {
        if !self.muc_redis_transport_enabled() {
            return Ok(true);
        }
        self.register_muc_occupant(room, nick, json).await
    }

    pub async fn publish_muc_cluster_presence(
        &self,
        publication: MucPresencePublication<'_>,
    ) -> Result<()> {
        if !self.muc_redis_transport_enabled() {
            return Ok(());
        }
        self.send_muc_presence_with_status(
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

#[cfg(test)]
mod tests {
    use super::MucRuntimeMode;

    #[test]
    fn current_muc_mode_keeps_pg_authority_without_redis() {
        assert_eq!(
            MucRuntimeMode::current(false),
            MucRuntimeMode {
                pg_authority: true,
                redis_transport: false,
            }
        );
        assert_eq!(
            MucRuntimeMode::current(true),
            MucRuntimeMode {
                pg_authority: true,
                redis_transport: true,
            }
        );
    }
}
