//! Cluster MUC fan-out: room, private, presence, nickname and destruction delivery.

use super::*;

impl ClusterManager {
    pub async fn send_to_muc(&self, room_jid: &str, stanza: &str) -> Result<()> {
        self.send_to_muc_internal(room_jid, stanza, None).await
    }

    /// Best-effort signed wake after PostgreSQL committed a MUC operation.
    /// The envelope contains only immutable IDs; receivers must pull and
    /// authorize the operation/outbox row from PostgreSQL.
    pub async fn send_muc_operation_wake(
        &self,
        descriptor: &northstar_room_core::ClusterMucWakeDescriptor,
    ) -> Result<()> {
        self.sm_suspension()
            .send_muc_operation_wake(descriptor)
            .await
    }

    pub async fn send_to_muc_from(
        &self,
        room_jid: &str,
        stanza: &str,
        real_sender: &str,
    ) -> Result<()> {
        let real_sender = northstar_xmpp_types::jid::canonicalize(real_sender)?;
        self.send_to_muc_internal(room_jid, stanza, Some(&real_sender))
            .await
    }

    pub(super) async fn send_to_muc_internal(
        &self,
        room_jid: &str,
        stanza: &str,
        real_sender: Option<&str>,
    ) -> Result<()> {
        let Some(pool) = &self.pool else {
            return Ok(());
        };
        let nodes = self.active_muc_nodes(room_jid).await?;
        let payload = serde_json::json!({
            "target": room_jid,
            "stanza": stanza,
            "muc_broadcast": true,
            "real_sender": real_sender,
        });
        let mut conn = pool.get().await?;
        self.publish_muc_fan_out(&mut conn, nodes, payload).await
    }

    pub(super) async fn publish_muc_fan_out(
        &self,
        conn: &mut redis::aio::MultiplexedConnection,
        nodes: Vec<String>,
        payload: serde_json::Value,
    ) -> Result<()> {
        let mut first_error = None;
        for node_id in nodes {
            if node_id != self.node_id {
                let channel = self.key(format!("node:{node_id}"));
                // A destination-specific authority error must not suppress
                // other recipients. Each attempt still uses publish_signed's
                // admission gate: global degradation remains fail-closed.
                if let Err(error) = self
                    .publish_signed(conn, &node_id, &channel, payload.clone())
                    .await
                {
                    first_error.get_or_insert_with(|| {
                        error.context(format!("MUC volatile fan-out to node {node_id} failed"))
                    });
                }
            }
        }
        match first_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    pub async fn send_muc_private_from(
        &self,
        room_jid: &str,
        target_nick: &str,
        stanza: &str,
        real_sender: &str,
    ) -> Result<()> {
        let real_sender = northstar_xmpp_types::jid::canonicalize(real_sender)?;
        self.send_muc_private_internal(room_jid, target_nick, stanza, Some(&real_sender))
            .await
    }

    pub(super) async fn send_muc_private_internal(
        &self,
        room_jid: &str,
        target_nick: &str,
        stanza: &str,
        real_sender: Option<&str>,
    ) -> Result<()> {
        let Some(pool) = &self.pool else {
            return Ok(());
        };
        let nodes = self.active_muc_nodes(room_jid).await?;
        let payload = serde_json::json!({
            "target": room_jid,
            "muc_private": true,
            "target_nick": target_nick,
            "stanza": stanza,
            "real_sender": real_sender,
        });
        let mut conn = pool.get().await?;
        for node_id in nodes {
            if node_id != self.node_id {
                let channel = self.key(format!("node:{node_id}"));
                let _ = self
                    .publish_signed(&mut conn, &node_id, &channel, payload.clone())
                    .await?;
            }
        }
        Ok(())
    }

    pub async fn send_muc_presence(
        &self,
        room_jid: &str,
        occupant: &crate::services::muc::SerializableMucOccupant,
        unavailable: bool,
        created: bool,
        id: Option<&str>,
    ) -> Result<()> {
        self.send_muc_presence_with_status(
            room_jid,
            occupant,
            unavailable,
            created,
            id,
            None,
            None,
            None,
        )
        .await
    }

    pub async fn send_muc_nickname_change(
        &self,
        room_jid: &str,
        old_occupant: &crate::services::muc::SerializableMucOccupant,
        new_occupant: &crate::services::muc::SerializableMucOccupant,
        id: Option<&str>,
    ) -> Result<()> {
        let Some(pool) = &self.pool else {
            return Ok(());
        };
        anyhow::ensure!(
            old_occupant.cluster_epoch == new_occupant.cluster_epoch
                && old_occupant.full_jid == new_occupant.full_jid
                && old_occupant.room_jid == new_occupant.room_jid
                && old_occupant.nick != new_occupant.nick,
            "invalid clustered MUC nickname change"
        );
        let nodes = self.active_muc_nodes(room_jid).await?;
        let payload = serde_json::json!({
            "target": room_jid,
            "muc_nickname_change": true,
            "old_occupant": old_occupant,
            "new_occupant": new_occupant,
            "id": id,
        });
        let mut conn = pool.get().await?;
        for node_id in nodes {
            if node_id != self.node_id {
                let channel = self.key(format!("node:{node_id}"));
                let _ = self
                    .publish_signed(&mut conn, &node_id, &channel, payload.clone())
                    .await?;
            }
        }
        Ok(())
    }

    /// Remove all distributed occupancy state for a destroyed room and tell
    /// every node that previously hosted one of its occupants to emit the
    /// XEP-0045 destroy presence locally.
    #[allow(dead_code)] // Legacy Redis cleanup fallback; authoritative destroy uses PG/outbox.
    pub async fn destroy_muc_room(
        &self,
        room_jid: &str,
        alternate: Option<&str>,
        reason: Option<&str>,
    ) -> Result<()> {
        let room = northstar_xmpp_types::jid::canonicalize_bare(room_jid)?;
        let alternate = alternate
            .map(northstar_xmpp_types::jid::canonicalize_bare)
            .transpose()?;
        anyhow::ensure!(
            reason.is_none_or(|value| value.len() <= 4096),
            "MUC destroy reason exceeds 4096 bytes"
        );
        let Some(pool) = &self.pool else {
            return Ok(());
        };
        let mut conn = pool.get().await?;
        let occupants_key = self.key(format!("muc_occupants:{room}"));
        let owners_key = self.key(format!("muc_occupant_nodes:{room}"));
        let raw_occupants: HashMap<String, String> = conn.hgetall(&occupants_key).await?;
        let owners: HashMap<String, String> = conn.hgetall(&owners_key).await?;
        let mut identities = Vec::new();
        let mut nodes = HashSet::new();
        for (nick, raw) in &raw_occupants {
            let Ok(occupant) =
                serde_json::from_str::<crate::services::muc::SerializableMucOccupant>(raw)
            else {
                continue;
            };
            if occupant.room_jid != room || occupant.nick != *nick {
                continue;
            }
            if let Some(identity) = MucOccupancyIdentity::from_occupant(&occupant) {
                identities.push(identity);
                if let Some(owner) = owners.get(nick) {
                    nodes.insert(owner.clone());
                }
            }
        }
        let payload = serde_json::json!({
            "target": &room,
            "muc_destroy": true,
            "alternate": &alternate,
            "reason": reason,
            "occupancies": &identities,
        });
        for node_id in nodes {
            if node_id != self.node_id {
                self.send_control_to_node(&node_id, &room, payload.clone())
                    .await?;
            }
        }
        let remove_script = redis::Script::new(
            r#"
            local raw = redis.call('hget', KEYS[1], ARGV[1])
            if not raw then return 0 end
            local ok, current = pcall(cjson.decode, raw)
            if not ok or current['full_jid'] ~= ARGV[2]
                or current['cluster_epoch'] ~= ARGV[3]
                or current['connection_id'] ~= ARGV[4] then return 0 end
            redis.call('hdel', KEYS[1], ARGV[1])
            redis.call('hdel', KEYS[2], ARGV[1])
            return 1
            "#,
        );
        for identity in identities {
            let _: i32 = remove_script
                .key(&occupants_key)
                .key(&owners_key)
                .arg(identity.nick)
                .arg(identity.full_jid)
                .arg(identity.cluster_epoch.to_string())
                .arg(identity.connection_id.to_string())
                .invoke_async(&mut *conn)
                .await?;
        }
        drop(conn);
        // Empty Redis hashes disappear automatically; reconcile the companion
        // node set as well.  A concurrent new authoritative join remains
        // intact because reconciliation retains entries owned by live nodes.
        self.reconcile_muc_soft_state(&room).await?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn send_muc_presence_with_status(
        &self,
        room_jid: &str,
        occupant: &crate::services::muc::SerializableMucOccupant,
        unavailable: bool,
        created: bool,
        id: Option<&str>,
        removal_status: Option<u16>,
        actor_nick: Option<&str>,
        reason: Option<&str>,
    ) -> Result<()> {
        self.signed_publisher()
            .send_muc_presence_with_status(
                room_jid,
                occupant,
                unavailable,
                created,
                id,
                removal_status,
                actor_nick,
                reason,
            )
            .await
    }
}
