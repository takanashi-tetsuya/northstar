//! Cluster operations used by federated MUC handlers.

use crate::ClusterManager;
use anyhow::Result;
use northstar_delivery_core::node_delivery::NodeDeliveryReceipt;
use northstar_room_application::muc_service::SerializableMucOccupant;
use northstar_room_core::occupancy::FederatedMucAccountRoute;
use northstar_room_core::occupancy::{MucRename, MucRoleChange};
use northstar_stream::outbound::DurableDelivery;
use std::collections::HashMap;

fn accepted_primary_route(receipt: NodeDeliveryReceipt) -> Option<FederatedMucAccountRoute> {
    (receipt.delivered && receipt.acknowledged).then_some(FederatedMucAccountRoute {
        accepted_full_jid: receipt.accepted_full_jid,
    })
}

impl ClusterManager {
    pub fn federated_muc_admit_mutation(&self) -> Result<()> {
        self.admit_muc_pg_mutation()
    }

    pub fn federated_muc_pg_authority_enabled(&self) -> bool {
        self.muc_pg_authority_enabled()
    }

    pub fn federated_muc_redis_transport_enabled(&self) -> bool {
        self.muc_redis_transport_enabled()
    }

    pub fn federated_muc_owner_node_id(&self) -> &str {
        &self.node_id
    }

    pub async fn federated_muc_global_occupants(
        &self,
        room_jid: &str,
    ) -> Result<HashMap<String, String>> {
        if !self.federated_muc_redis_transport_enabled() {
            return Ok(HashMap::new());
        }
        self.get_muc_occupants(room_jid).await
    }

    pub async fn federated_muc_join_room(&self, room_jid: &str) -> Result<()> {
        if !self.federated_muc_redis_transport_enabled() {
            return Ok(());
        }
        self.join_muc(room_jid).await
    }

    pub async fn federated_muc_leave_room(&self, room_jid: &str) -> Result<()> {
        if !self.federated_muc_redis_transport_enabled() {
            return Ok(());
        }
        self.leave_muc(room_jid).await
    }

    pub async fn federated_muc_rename_occupant(
        &self,
        room_jid: &str,
        old_nick: &str,
        new_nick: &str,
        expected_epoch: uuid::Uuid,
        old_json: &str,
        new_json: &str,
    ) -> Result<MucRename> {
        if !self.federated_muc_redis_transport_enabled() {
            return Ok(MucRename::Renamed);
        }
        self.rename_muc_occupant(
            room_jid,
            old_nick,
            new_nick,
            expected_epoch,
            old_json,
            new_json,
        )
        .await
    }

    pub async fn federated_muc_register_occupant(
        &self,
        room_jid: &str,
        nick: &str,
        json: &str,
    ) -> Result<bool> {
        if !self.federated_muc_redis_transport_enabled() {
            return Ok(true);
        }
        self.register_muc_occupant(room_jid, nick, json).await
    }

    pub async fn federated_muc_evict_occupant(
        &self,
        occupant: &SerializableMucOccupant,
        status: u16,
        actor_nick: Option<&str>,
        reason: Option<&str>,
    ) -> Result<bool> {
        if !self.federated_muc_redis_transport_enabled() {
            return Ok(true);
        }
        self.evict_muc_occupant(occupant, status, actor_nick, reason)
            .await
    }

    pub async fn federated_muc_change_occupant_role(
        &self,
        room_jid: &str,
        occupant: &SerializableMucOccupant,
        role: &str,
    ) -> Result<MucRoleChange> {
        self.change_muc_occupant_role(room_jid, occupant, role)
            .await
    }

    pub async fn federated_muc_change_occupant_affiliation(
        &self,
        room_jid: &str,
        occupant: &SerializableMucOccupant,
        affiliation: &str,
        role: &str,
    ) -> Result<MucRoleChange> {
        self.change_muc_occupant_affiliation(room_jid, occupant, affiliation, role)
            .await
    }

    pub async fn federated_muc_change_occupant_policy(
        &self,
        room_jid: &str,
        occupant: &SerializableMucOccupant,
        role: &str,
        room_non_anonymous: bool,
    ) -> Result<MucRoleChange> {
        self.change_muc_occupant_policy(room_jid, occupant, role, room_non_anonymous)
            .await
    }

    pub async fn federated_muc_publish_presence(
        &self,
        room_jid: &str,
        occupant: &SerializableMucOccupant,
        unavailable: bool,
        created: bool,
        id: Option<&str>,
    ) -> Result<()> {
        if !self.federated_muc_redis_transport_enabled() {
            return Ok(());
        }
        self.send_muc_presence(room_jid, occupant, unavailable, created, id)
            .await
    }

    pub async fn federated_muc_publish_removal_presence(
        &self,
        room_jid: &str,
        occupant: &SerializableMucOccupant,
        status: Option<u16>,
        actor_nick: Option<&str>,
        reason: Option<&str>,
    ) -> Result<()> {
        if !self.federated_muc_redis_transport_enabled() {
            return Ok(());
        }
        self.send_muc_presence_with_status(
            room_jid, occupant, true, false, None, status, actor_nick, reason,
        )
        .await
    }

    pub async fn federated_muc_publish_nickname_change(
        &self,
        room_jid: &str,
        old_occupant: &SerializableMucOccupant,
        new_occupant: &SerializableMucOccupant,
        id: Option<&str>,
    ) -> Result<()> {
        if !self.federated_muc_redis_transport_enabled() {
            return Ok(());
        }
        self.send_muc_nickname_change(room_jid, old_occupant, new_occupant, id)
            .await
    }

    pub async fn federated_muc_publish_room_message(
        &self,
        room_jid: &str,
        stanza: &str,
        real_sender: Option<&str>,
    ) -> Result<()> {
        if !self.federated_muc_redis_transport_enabled() {
            return Ok(());
        }
        match real_sender {
            Some(sender) => self.send_to_muc_from(room_jid, stanza, sender).await,
            None => self.send_to_muc(room_jid, stanza).await,
        }
    }

    pub async fn federated_muc_publish_private_message(
        &self,
        room_jid: &str,
        target_nick: &str,
        stanza: &str,
        real_sender: &str,
    ) -> Result<()> {
        if !self.federated_muc_redis_transport_enabled() {
            return Ok(());
        }
        self.send_muc_private_from(room_jid, target_nick, stanza, real_sender)
            .await
    }

    /// Forward a mediated invitation or decline to the first remote primary
    /// resource that acknowledges delivery. A durable invitation keeps its
    /// exact spool-row fence across this hand-off. Lookup and send failures
    /// are best-effort here; the caller retains its offline-storage policy.
    pub async fn route_federated_muc_account_message_remote(
        &self,
        target_jid: &str,
        stanza: &str,
        delivery: Option<DurableDelivery>,
    ) -> Option<FederatedMucAccountRoute> {
        if !self.federated_muc_redis_transport_enabled() {
            return None;
        }
        for node_id in self.lookup_nodes(target_jid).await.unwrap_or_default() {
            if node_id == self.node_id {
                continue;
            }
            let receipt = if let Some(delivery) = delivery {
                self.send_to_node_primary_durable(&node_id, target_jid, stanza, delivery)
                    .await
                    .unwrap_or_default()
            } else {
                self.send_to_node_primary(&node_id, target_jid, stanza)
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
    use northstar_delivery_core::node_delivery::NodeDeliveryReceipt;

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
