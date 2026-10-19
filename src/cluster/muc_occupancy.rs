//! Cluster MUC occupant registration, renames, role, affiliation and policy changes, resume and eviction.

use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MucRegistration {
    Joined,
    Conflict,
    Full,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MucRename {
    Renamed,
    Conflict,
    Stale,
}

#[derive(Clone)]
pub enum MucRoleChange {
    Changed(Box<crate::services::muc::SerializableMucOccupant>),
    Stale,
}

impl crate::services::muc::MucWakePort for ClusterManager {
    async fn wake(&self, descriptor: &northstar_room_core::ClusterMucWakeDescriptor) -> Result<()> {
        self.send_muc_operation_wake(descriptor).await
    }

    fn record_failure(&self, error: &anyhow::Error) {
        self.record_control_plane_failure(error);
    }
}

impl ClusterManager {
    /// Reconcile disposable Redis room indexes without consulting them for
    /// authority. Both the stable node lease and the exact process-instance
    /// lease must be live. This lets a restarted process remove its own old
    /// projection immediately instead of preserving ghosts behind a reused
    /// node ID. The O(room-size) sweep is maintenance/read-only work; stanza
    /// fan-out never invokes it.
    pub(super) async fn reconcile_muc_soft_state(&self, room_jid: &str) -> Result<()> {
        self.maintenance_redis()
            .reconcile_muc_soft_state(room_jid)
            .await
    }

    pub async fn try_register_muc_occupant(
        &self,
        room_jid: &str,
        nick: &str,
        json: &str,
        max_occupants: usize,
    ) -> Result<MucRegistration> {
        self.admit(ClusterOperation::MucMutation)?;
        let incoming: crate::services::muc::SerializableMucOccupant = serde_json::from_str(json)?;
        let canonical_room = crate::jid::canonicalize_bare(room_jid)?;
        let prepared_nick = crate::xmpp::xml_util::prepare_muc_nick(nick)?;
        anyhow::ensure!(
            incoming.room_jid == canonical_room
                && incoming.nick == prepared_nick
                && !incoming.cluster_epoch.is_nil()
                && !incoming.connection_id.is_nil(),
            "MUC registration requires an exact non-nil occupancy identity"
        );
        let Some(pool) = &self.pool else {
            return Ok(MucRegistration::Joined);
        };
        let mut conn = pool.get().await?;
        let room = canonical_room;
        let nick = prepared_nick;
        let process_instance = self.process_instance_token()?;
        let occupants_key = self.key(format!("muc_occupants:{room}"));
        let owners_key = self.key(format!("muc_occupant_nodes:{room}"));
        let nodes_key = self.key(format!("muc_nodes:{room}"));
        let instances_key = self.key(format!("muc_occupant_instances:{room}"));
        let node_counts_key = self.key(format!("muc_node_counts:{room}"));
        let alive_key = self.key(format!("node:{}:alive", self.node_id));
        let process_alive_key = self.process_alive_key()?;
        let script = redis::Script::new(
            r#"
            redis.call('set', KEYS[6], ARGV[7], 'EX', ARGV[6])
            redis.call('set', KEYS[7], ARGV[7], 'EX', ARGV[6])
            local current = redis.call('hget', KEYS[1], ARGV[1])
            local owner = redis.call('hget', KEYS[2], ARGV[1])
            local instance = redis.call('hget', KEYS[4], ARGV[1])
            if owner and instance
                and redis.call(
                    'exists', ARGV[9] .. owner .. ':' .. instance .. ':alive'
                ) == 0
            then
                redis.call('hdel', KEYS[1], ARGV[1])
                redis.call('hdel', KEYS[2], ARGV[1])
                redis.call('hdel', KEYS[4], ARGV[1])
                local count = redis.call('hincrby', KEYS[5], owner, -1)
                if count <= 0 then
                    redis.call('hdel', KEYS[5], owner)
                    redis.call('srem', KEYS[3], owner)
                end
                current = false
                owner = false
                instance = false
            end
            if current or owner or instance then
                if current == ARGV[2] and owner == ARGV[3] and instance == ARGV[4] then
                    redis.call('sadd', KEYS[3], ARGV[3])
                    redis.call('expire', KEYS[1], ARGV[8])
                    redis.call('expire', KEYS[2], ARGV[8])
                    redis.call('expire', KEYS[3], ARGV[8])
                    redis.call('expire', KEYS[4], ARGV[8])
                    redis.call('expire', KEYS[5], ARGV[8])
                    return 1
                end
                return 0
            end
            if redis.call('hlen', KEYS[1]) >= tonumber(ARGV[5]) then return -1 end
            redis.call('hset', KEYS[1], ARGV[1], ARGV[2])
            redis.call('hset', KEYS[2], ARGV[1], ARGV[3])
            redis.call('hset', KEYS[4], ARGV[1], ARGV[4])
            redis.call('hincrby', KEYS[5], ARGV[3], 1)
            redis.call('sadd', KEYS[3], ARGV[3])
            redis.call('expire', KEYS[1], ARGV[8])
            redis.call('expire', KEYS[2], ARGV[8])
            redis.call('expire', KEYS[3], ARGV[8])
            redis.call('expire', KEYS[4], ARGV[8])
            redis.call('expire', KEYS[5], ARGV[8])
            return 1
            "#,
        );
        let result: i32 = script
            .key(occupants_key)
            .key(owners_key)
            .key(nodes_key)
            .key(instances_key)
            .key(node_counts_key)
            .key(alive_key)
            .key(process_alive_key)
            .arg(&nick)
            .arg(json)
            .arg(&self.node_id)
            .arg(process_instance)
            .arg(max_occupants.max(1))
            .arg(NODE_TTL_SECONDS)
            .arg(NODE_PROTOCOL_VERSION)
            .arg(MUC_SOFT_STATE_TTL_SECONDS)
            .arg(self.key("node_instance:".to_owned()))
            .invoke_async(&mut *conn)
            .await?;
        Ok(match result {
            1 => MucRegistration::Joined,
            -1 => MucRegistration::Full,
            _ => MucRegistration::Conflict,
        })
    }

    /// Atomically move one exact MUC occupancy to a new nickname.  The
    /// serialized occupant contains a per-join UUID (`cluster_epoch`); Redis
    /// compares the entire old value and the owning node before changing any
    /// key, so a delayed rename can neither steal a nickname nor delete a
    /// newer ABA replacement on the same node.
    pub async fn rename_muc_occupant(
        &self,
        room_jid: &str,
        old_nick: &str,
        new_nick: &str,
        expected_epoch: uuid::Uuid,
        old_json: &str,
        new_json: &str,
    ) -> Result<MucRename> {
        self.admit(ClusterOperation::MucMutation)?;
        let room = crate::jid::canonicalize_bare(room_jid)?;
        let old_nick = crate::xmpp::xml_util::prepare_muc_nick(old_nick)?;
        let new_nick = crate::xmpp::xml_util::prepare_muc_nick(new_nick)?;
        anyhow::ensure!(
            old_nick != new_nick,
            "MUC nickname rename must change the nickname"
        );
        anyhow::ensure!(
            !expected_epoch.is_nil(),
            "MUC rename requires a non-nil occupancy epoch"
        );
        for (json, expected_nick) in [(old_json, old_nick.as_str()), (new_json, new_nick.as_str())]
        {
            let occupant: crate::services::muc::SerializableMucOccupant =
                serde_json::from_str(json)?;
            anyhow::ensure!(
                occupant.cluster_epoch == expected_epoch
                    && occupant.room_jid == room
                    && occupant.nick == expected_nick,
                "MUC rename payload does not describe the guarded occupancy"
            );
        }
        let old_occupant: crate::services::muc::SerializableMucOccupant =
            serde_json::from_str(old_json)?;
        let new_occupant: crate::services::muc::SerializableMucOccupant =
            serde_json::from_str(new_json)?;
        anyhow::ensure!(
            old_occupant.full_jid == new_occupant.full_jid
                && old_occupant.connection_id == new_occupant.connection_id
                && !old_occupant.connection_id.is_nil(),
            "MUC nickname rename cannot change actor or transport ownership"
        );
        let Some(pool) = &self.pool else {
            return Ok(MucRename::Renamed);
        };
        let mut conn = pool.get().await?;
        let process_instance = self.process_instance_token()?;
        let occupants_key = self.key(format!("muc_occupants:{room}"));
        let owners_key = self.key(format!("muc_occupant_nodes:{room}"));
        let nodes_key = self.key(format!("muc_nodes:{room}"));
        let instances_key = self.key(format!("muc_occupant_instances:{room}"));
        let node_counts_key = self.key(format!("muc_node_counts:{room}"));
        let alive_key = self.key(format!("node:{}:alive", self.node_id));
        let process_alive_key = self.process_alive_key()?;
        let script = redis::Script::new(
            r#"
            if redis.call('hget', KEYS[2], ARGV[1]) ~= ARGV[4] then return -1 end
            if redis.call('hget', KEYS[1], ARGV[1]) ~= ARGV[3] then return -1 end
            if redis.call('hget', KEYS[4], ARGV[1]) ~= ARGV[5] then return -1 end
            if redis.call('hexists', KEYS[1], ARGV[2]) == 1 then return 0 end
            redis.call('hset', KEYS[1], ARGV[2], ARGV[6])
            redis.call('hset', KEYS[2], ARGV[2], ARGV[4])
            redis.call('hset', KEYS[4], ARGV[2], ARGV[5])
            redis.call('hdel', KEYS[1], ARGV[1])
            redis.call('hdel', KEYS[2], ARGV[1])
            redis.call('hdel', KEYS[4], ARGV[1])
            redis.call('sadd', KEYS[3], ARGV[4])
            redis.call('set', KEYS[6], ARGV[8], 'EX', ARGV[7])
            redis.call('set', KEYS[7], ARGV[8], 'EX', ARGV[7])
            redis.call('expire', KEYS[1], ARGV[9])
            redis.call('expire', KEYS[2], ARGV[9])
            redis.call('expire', KEYS[3], ARGV[9])
            redis.call('expire', KEYS[4], ARGV[9])
            redis.call('expire', KEYS[5], ARGV[9])
            return 1
            "#,
        );
        let result: i32 = script
            .key(occupants_key)
            .key(owners_key)
            .key(nodes_key)
            .key(instances_key)
            .key(node_counts_key)
            .key(alive_key)
            .key(process_alive_key)
            .arg(&old_nick)
            .arg(&new_nick)
            .arg(old_json)
            .arg(&self.node_id)
            .arg(process_instance)
            .arg(new_json)
            .arg(NODE_TTL_SECONDS)
            .arg(NODE_PROTOCOL_VERSION)
            .arg(MUC_SOFT_STATE_TTL_SECONDS)
            .invoke_async(&mut *conn)
            .await?;
        Ok(match result {
            1 => MucRename::Renamed,
            0 => MucRename::Conflict,
            _ => MucRename::Stale,
        })
    }

    /// Atomically update the role of one exact occupancy and notify all room
    /// nodes.  Exact serialized-value comparison is an ABA guard: a delayed
    /// moderator action cannot mutate a newer occupant that reused the nick.
    pub async fn change_muc_occupant_role(
        &self,
        room_jid: &str,
        occupant: &crate::services::muc::SerializableMucOccupant,
        new_role: &str,
    ) -> Result<MucRoleChange> {
        self.admit(ClusterOperation::MucMutation)?;
        anyhow::ensure!(
            matches!(new_role, "moderator" | "participant" | "visitor"),
            "clustered role changes require moderator, participant, or visitor role"
        );
        let room = crate::jid::canonicalize_bare(room_jid)?;
        let nick = crate::xmpp::xml_util::prepare_muc_nick(&occupant.nick)?;
        anyhow::ensure!(
            occupant.room_jid == room && !occupant.cluster_epoch.is_nil(),
            "clustered voice change requires the exact non-nil occupancy epoch"
        );
        let mut updated = occupant.clone();
        updated.role = new_role.to_owned();
        let old_json = serde_json::to_string(occupant)?;
        let new_json = serde_json::to_string(&updated)?;
        let Some(pool) = &self.pool else {
            return Ok(MucRoleChange::Changed(Box::new(updated)));
        };
        let mut conn = pool.get().await?;
        let occupants_key = self.key(format!("muc_occupants:{room}"));
        let owners_key = self.key(format!("muc_occupant_nodes:{room}"));
        let script = redis::Script::new(
            r#"
            if redis.call('hexists', KEYS[2], ARGV[1]) == 0 then return 0 end
            if redis.call('hget', KEYS[1], ARGV[1]) ~= ARGV[2] then return 0 end
            redis.call('hset', KEYS[1], ARGV[1], ARGV[3])
            return 1
            "#,
        );
        let changed: i32 = script
            .key(occupants_key)
            .key(owners_key)
            .arg(&nick)
            .arg(old_json)
            .arg(new_json)
            .invoke_async(&mut *conn)
            .await?;
        if changed != 1 {
            return Ok(MucRoleChange::Stale);
        }
        let nodes = self.active_muc_nodes(&room).await?;
        let payload = serde_json::json!({
            "target": room,
            "muc_role_change": true,
            "occupant": updated,
        });
        for node_id in nodes {
            if node_id != self.node_id {
                let channel = self.key(format!("node:{node_id}"));
                let _ = self
                    .publish_signed(&mut conn, &node_id, &channel, payload.clone())
                    .await?;
            }
        }
        Ok(MucRoleChange::Changed(Box::new(updated)))
    }

    /// Atomically apply an affiliation-derived role to an exact occupancy.
    /// This is used by a room administrator on a different node; the old
    /// serialized value is the CAS token and the immutable identity fields
    /// may not change.
    pub async fn change_muc_occupant_affiliation(
        &self,
        room_jid: &str,
        occupant: &crate::services::muc::SerializableMucOccupant,
        affiliation: &str,
        role: &str,
    ) -> Result<MucRoleChange> {
        self.admit(ClusterOperation::MucMutation)?;
        anyhow::ensure!(
            matches!(affiliation, "owner" | "admin" | "member" | "none")
                && matches!(role, "moderator" | "participant" | "visitor"),
            "invalid live MUC affiliation transition"
        );
        let room = crate::jid::canonicalize_bare(room_jid)?;
        let nick = crate::xmpp::xml_util::prepare_muc_nick(&occupant.nick)?;
        anyhow::ensure!(
            occupant.room_jid == room
                && !occupant.cluster_epoch.is_nil()
                && !occupant.connection_id.is_nil(),
            "clustered affiliation change requires the exact occupancy identity"
        );
        let mut updated = occupant.clone();
        updated.affiliation = affiliation.to_owned();
        updated.role = role.to_owned();
        let old_json = serde_json::to_string(occupant)?;
        let new_json = serde_json::to_string(&updated)?;
        let Some(pool) = &self.pool else {
            return Ok(MucRoleChange::Changed(Box::new(updated)));
        };
        let mut conn = pool.get().await?;
        let occupants_key = self.key(format!("muc_occupants:{room}"));
        let owners_key = self.key(format!("muc_occupant_nodes:{room}"));
        let script = redis::Script::new(
            r#"
            if redis.call('hexists', KEYS[2], ARGV[1]) == 0 then return 0 end
            if redis.call('hget', KEYS[1], ARGV[1]) ~= ARGV[2] then return 0 end
            redis.call('hset', KEYS[1], ARGV[1], ARGV[3])
            return 1
            "#,
        );
        let changed: i32 = script
            .key(occupants_key)
            .key(owners_key)
            .arg(&nick)
            .arg(old_json)
            .arg(new_json)
            .invoke_async(&mut *conn)
            .await?;
        if changed != 1 {
            return Ok(MucRoleChange::Stale);
        }
        let nodes = self.active_muc_nodes(&room).await?;
        let payload = serde_json::json!({
            "target": room,
            "muc_role_change": true,
            "occupant": updated,
        });
        for node_id in nodes {
            if node_id != self.node_id {
                let channel = self.key(format!("node:{node_id}"));
                let _ = self
                    .publish_signed(&mut conn, &node_id, &channel, payload.clone())
                    .await?;
            }
        }
        Ok(MucRoleChange::Changed(Box::new(updated)))
    }

    /// Atomically synchronize the room-derived live policy for one exact
    /// occupancy.  Room configuration is PostgreSQL-authoritative, but the
    /// role and real-JID visibility cached in Redis and on every serving node
    /// must change together so a remote participant cannot retain voice or a
    /// stale anonymity view after an owner configuration update.
    pub async fn change_muc_occupant_policy(
        &self,
        room_jid: &str,
        occupant: &crate::services::muc::SerializableMucOccupant,
        role: &str,
        room_non_anonymous: bool,
    ) -> Result<MucRoleChange> {
        self.admit(ClusterOperation::MucMutation)?;
        anyhow::ensure!(
            matches!(role, "moderator" | "participant" | "visitor"),
            "invalid room-derived MUC role"
        );
        let room = crate::jid::canonicalize_bare(room_jid)?;
        let nick = crate::xmpp::xml_util::prepare_muc_nick(&occupant.nick)?;
        anyhow::ensure!(
            occupant.room_jid == room
                && !occupant.cluster_epoch.is_nil()
                && !occupant.connection_id.is_nil(),
            "clustered room policy change requires the exact occupancy identity"
        );
        let mut updated = occupant.clone();
        updated.role = role.to_owned();
        updated.room_non_anonymous = room_non_anonymous;
        let old_json = serde_json::to_string(occupant)?;
        let new_json = serde_json::to_string(&updated)?;
        let Some(pool) = &self.pool else {
            return Ok(MucRoleChange::Changed(Box::new(updated)));
        };
        let mut conn = pool.get().await?;
        let occupants_key = self.key(format!("muc_occupants:{room}"));
        let owners_key = self.key(format!("muc_occupant_nodes:{room}"));
        let script = redis::Script::new(
            r#"
            if redis.call('hexists', KEYS[2], ARGV[1]) == 0 then return 0 end
            if redis.call('hget', KEYS[1], ARGV[1]) ~= ARGV[2] then return 0 end
            redis.call('hset', KEYS[1], ARGV[1], ARGV[3])
            return 1
            "#,
        );
        let changed: i32 = script
            .key(occupants_key)
            .key(owners_key)
            .arg(&nick)
            .arg(old_json)
            .arg(new_json)
            .invoke_async(&mut *conn)
            .await?;
        if changed != 1 {
            return Ok(MucRoleChange::Stale);
        }
        let nodes = self.active_muc_nodes(&room).await?;
        let payload = serde_json::json!({
            "target": room,
            "muc_role_change": true,
            "occupant": updated,
        });
        for node_id in nodes {
            if node_id != self.node_id {
                let channel = self.key(format!("node:{node_id}"));
                let _ = self
                    .publish_signed(&mut conn, &node_id, &channel, payload.clone())
                    .await?;
            }
        }
        Ok(MucRoleChange::Changed(Box::new(updated)))
    }

    pub async fn register_muc_occupant(
        &self,
        room_jid: &str,
        nick: &str,
        json: &str,
    ) -> Result<bool> {
        self.maintenance_redis()
            .register_muc_occupant(room_jid, nick, json)
            .await
    }

    /// Replace the transport owner of an XEP-0198-resumed occupancy.  The
    /// complete previous value is a CAS token, while the immutable occupancy
    /// epoch and durable SM session id must remain unchanged.
    pub async fn resume_muc_occupant(
        &self,
        previous: &crate::services::muc::SerializableMucOccupant,
        resumed: &crate::services::muc::SerializableMucOccupant,
    ) -> Result<bool> {
        self.admit(ClusterOperation::Resume)?;
        anyhow::ensure!(
            previous.room_jid == resumed.room_jid
                && previous.nick == resumed.nick
                && previous.full_jid == resumed.full_jid
                && previous.cluster_epoch == resumed.cluster_epoch
                && previous.sm_session_id.is_some()
                && previous.sm_session_id == resumed.sm_session_id
                && !previous.cluster_epoch.is_nil()
                && !resumed.connection_id.is_nil(),
            "invalid MUC resume ownership transition"
        );
        let Some(pool) = &self.pool else {
            return Ok(true);
        };
        let room = crate::jid::canonicalize_bare(&resumed.room_jid)?;
        let nick = crate::xmpp::xml_util::prepare_muc_nick(&resumed.nick)?;
        let process_instance = self.process_instance_token()?;
        let mut conn = pool.get().await?;
        let occupants_key = self.key(format!("muc_occupants:{room}"));
        let owners_key = self.key(format!("muc_occupant_nodes:{room}"));
        let nodes_key = self.key(format!("muc_nodes:{room}"));
        let instances_key = self.key(format!("muc_occupant_instances:{room}"));
        let node_counts_key = self.key(format!("muc_node_counts:{room}"));
        let alive_key = self.key(format!("node:{}:alive", self.node_id));
        let process_alive_key = self.process_alive_key()?;
        let previous_json = serde_json::to_string(previous)?;
        let resumed_json = serde_json::to_string(resumed)?;
        let script = redis::Script::new(
            r#"
            local previous_owner = redis.call('hget', KEYS[2], ARGV[1])
            local previous_instance = redis.call('hget', KEYS[4], ARGV[1])
            if not previous_owner or not previous_instance then return 0 end
            if redis.call('hget', KEYS[1], ARGV[1]) ~= ARGV[4] then return 0 end
            redis.call('hset', KEYS[1], ARGV[1], ARGV[5])
            redis.call('hset', KEYS[2], ARGV[1], ARGV[2])
            redis.call('hset', KEYS[4], ARGV[1], ARGV[3])
            if previous_owner ~= ARGV[2] then
                local old_remaining = redis.call('hincrby', KEYS[5], previous_owner, -1)
                if old_remaining <= 0 then
                    redis.call('hdel', KEYS[5], previous_owner)
                    redis.call('srem', KEYS[3], previous_owner)
                end
                redis.call('hincrby', KEYS[5], ARGV[2], 1)
            end
            redis.call('sadd', KEYS[3], ARGV[2])
            redis.call('set', KEYS[6], ARGV[7], 'EX', ARGV[6])
            redis.call('set', KEYS[7], ARGV[7], 'EX', ARGV[6])
            redis.call('expire', KEYS[1], ARGV[8])
            redis.call('expire', KEYS[2], ARGV[8])
            redis.call('expire', KEYS[3], ARGV[8])
            redis.call('expire', KEYS[4], ARGV[8])
            redis.call('expire', KEYS[5], ARGV[8])
            return 1
            "#,
        );
        let resumed: i32 = script
            .key(occupants_key)
            .key(owners_key)
            .key(nodes_key)
            .key(instances_key)
            .key(node_counts_key)
            .key(alive_key)
            .key(process_alive_key)
            .arg(&nick)
            .arg(&self.node_id)
            .arg(process_instance)
            .arg(previous_json)
            .arg(resumed_json)
            .arg(NODE_TTL_SECONDS)
            .arg(NODE_PROTOCOL_VERSION)
            .arg(MUC_SOFT_STATE_TTL_SECONDS)
            .invoke_async(&mut *conn)
            .await?;
        Ok(resumed == 1)
    }

    /// Verify that Redis still grants this node the exact live occupancy.
    /// This is checked before every actor-authorized MUC operation so a lost
    /// lease or a nickname ABA cannot continue with a stale local cache.
    #[allow(dead_code)] // Protocol-v7 rolling compatibility; PG is authoritative in v9.
    pub async fn owns_muc_occupant(
        &self,
        room_jid: &str,
        nick: &str,
        cluster_epoch: uuid::Uuid,
        connection_id: uuid::Uuid,
    ) -> Result<bool> {
        anyhow::ensure!(
            !cluster_epoch.is_nil() && !connection_id.is_nil(),
            "MUC ownership validation requires non-nil identities"
        );
        let Some(pool) = &self.pool else {
            return Ok(true);
        };
        let room = crate::jid::canonicalize_bare(room_jid)?;
        let nick = crate::xmpp::xml_util::prepare_muc_nick(nick)?;
        let process_instance = self.process_instance_token()?;
        let mut conn = pool.get().await?;
        let occupants_key = self.key(format!("muc_occupants:{room}"));
        let owners_key = self.key(format!("muc_occupant_nodes:{room}"));
        let instances_key = self.key(format!("muc_occupant_instances:{room}"));
        let script = redis::Script::new(
            r#"
            if redis.call('hget', KEYS[2], ARGV[1]) ~= ARGV[2] then return 0 end
            if redis.call('hget', KEYS[3], ARGV[1]) ~= ARGV[3] then return 0 end
            local raw = redis.call('hget', KEYS[1], ARGV[1])
            if not raw then return 0 end
            local ok, current = pcall(cjson.decode, raw)
            if not ok then return 0 end
            if current['cluster_epoch'] ~= ARGV[4]
                or current['connection_id'] ~= ARGV[5] then return 0 end
            return 1
            "#,
        );
        let owned: i32 = script
            .key(occupants_key)
            .key(owners_key)
            .key(instances_key)
            .arg(&nick)
            .arg(&self.node_id)
            .arg(process_instance)
            .arg(cluster_epoch.to_string())
            .arg(connection_id.to_string())
            .invoke_async(&mut *conn)
            .await?;
        Ok(owned == 1)
    }

    /// Persist the exact suspended-SM epoch in the Redis occupant value. A
    /// teardown tombstone wins over a late disconnect task, preventing that
    /// task from recreating a ghost after PostgreSQL expiry/revocation.
    pub async fn register_suspended_muc_occupant(
        &self,
        room_jid: &str,
        nick: &str,
        sm_session_id: uuid::Uuid,
        json: &str,
    ) -> Result<bool> {
        self.sm_suspension()
            .register_suspended_muc_occupant(room_jid, nick, sm_session_id, json)
            .await
    }

    /// Remove only the exact occupancy epoch owned by this node.  This is the
    /// cleanup primitive for delayed connection Drop tasks; a nickname reused
    /// by a later join must survive the older task.
    pub async fn unregister_muc_occupant_epoch(
        &self,
        room_jid: &str,
        nick: &str,
        cluster_epoch: uuid::Uuid,
        connection_id: uuid::Uuid,
    ) -> Result<bool> {
        self.sm_muc_teardown_projection()
            .unregister_muc_occupant_epoch(room_jid, nick, cluster_epoch, connection_id)
            .await
    }

    /// Revoke one exact occupancy, acknowledging the owning node before the
    /// Redis lease is removed.  The full actor identity prevents a delayed
    /// kick/ban from touching a later user who reused the nickname.
    pub async fn evict_muc_occupant(
        &self,
        occupant: &crate::services::muc::SerializableMucOccupant,
        status: u16,
        actor_nick: Option<&str>,
        reason: Option<&str>,
    ) -> Result<bool> {
        self.admit(ClusterOperation::MucMutation)?;
        anyhow::ensure!(
            !occupant.cluster_epoch.is_nil()
                && !occupant.connection_id.is_nil()
                && reason.is_none_or(|value| value.len() <= 4096),
            "MUC eviction requires exact non-nil identity and bounded reason"
        );
        let Some(pool) = &self.pool else {
            return Ok(true);
        };
        let room = crate::jid::canonicalize_bare(&occupant.room_jid)?;
        let nick = crate::xmpp::xml_util::prepare_muc_nick(&occupant.nick)?;
        let occupants_key = self.key(format!("muc_occupants:{room}"));
        let owners_key = self.key(format!("muc_occupant_nodes:{room}"));
        let nodes_key = self.key(format!("muc_nodes:{room}"));
        let instances_key = self.key(format!("muc_occupant_instances:{room}"));
        let node_counts_key = self.key(format!("muc_node_counts:{room}"));
        let mut conn = pool.get().await?;
        let owner_script = redis::Script::new(
            r#"
            local owner = redis.call('hget', KEYS[2], ARGV[1])
            if not owner then return false end
            local raw = redis.call('hget', KEYS[1], ARGV[1])
            if not raw then return false end
            local ok, current = pcall(cjson.decode, raw)
            if not ok or current['full_jid'] ~= ARGV[2]
                or current['cluster_epoch'] ~= ARGV[3]
                or current['connection_id'] ~= ARGV[4] then return false end
            return owner
            "#,
        );
        let owner: Option<String> = owner_script
            .key(&occupants_key)
            .key(&owners_key)
            .arg(&nick)
            .arg(&occupant.full_jid)
            .arg(occupant.cluster_epoch.to_string())
            .arg(occupant.connection_id.to_string())
            .invoke_async(&mut *conn)
            .await?;
        let Some(owner) = owner else {
            return Ok(false);
        };
        if owner != self.node_id {
            let payload = serde_json::json!({
                "target": &room,
                "muc_evict": true,
                "occupant": occupant,
                "status": status,
                "actor_nick": actor_nick,
                "reason": reason,
            });
            self.send_control_to_node(&owner, &room, payload).await?;
        }
        let remove_script = redis::Script::new(
            r#"
            if redis.call('hget', KEYS[2], ARGV[1]) ~= ARGV[2] then return 0 end
            local raw = redis.call('hget', KEYS[1], ARGV[1])
            if not raw then return 0 end
            local ok, current = pcall(cjson.decode, raw)
            if not ok or current['full_jid'] ~= ARGV[3]
                or current['cluster_epoch'] ~= ARGV[4]
                or current['connection_id'] ~= ARGV[5] then return 0 end
            redis.call('hdel', KEYS[1], ARGV[1])
            redis.call('hdel', KEYS[2], ARGV[1])
            redis.call('hdel', KEYS[4], ARGV[1])
            local remaining = redis.call('hincrby', KEYS[5], ARGV[2], -1)
            if remaining <= 0 then
                redis.call('hdel', KEYS[5], ARGV[2])
                redis.call('srem', KEYS[3], ARGV[2])
            end
            if redis.call('hlen', KEYS[1]) == 0 and redis.call('hlen', KEYS[2]) == 0 then
                redis.call('del', KEYS[1], KEYS[2], KEYS[3], KEYS[4], KEYS[5])
            else
                redis.call('expire', KEYS[1], ARGV[6])
                redis.call('expire', KEYS[2], ARGV[6])
                redis.call('expire', KEYS[3], ARGV[6])
                redis.call('expire', KEYS[4], ARGV[6])
                redis.call('expire', KEYS[5], ARGV[6])
            end
            return 1
            "#,
        );
        let removed: i32 = remove_script
            .key(occupants_key)
            .key(owners_key)
            .key(nodes_key)
            .key(instances_key)
            .key(node_counts_key)
            .arg(&nick)
            .arg(owner)
            .arg(&occupant.full_jid)
            .arg(occupant.cluster_epoch.to_string())
            .arg(occupant.connection_id.to_string())
            .arg(MUC_SOFT_STATE_TTL_SECONDS)
            .invoke_async(&mut *conn)
            .await?;
        Ok(removed == 1)
    }

    pub async fn get_muc_occupants(&self, room_jid: &str) -> Result<HashMap<String, String>> {
        self.sm_muc_teardown_projection()
            .get_muc_occupants(room_jid)
            .await
    }

    pub async fn join_muc(&self, room_jid: &str) -> Result<()> {
        self.maintenance_redis().join_muc(room_jid).await
    }

    pub async fn leave_muc(&self, room_jid: &str) -> Result<()> {
        self.sm_muc_teardown_projection().leave_muc(room_jid).await
    }

    pub(super) async fn active_muc_nodes(&self, room_jid: &str) -> Result<Vec<String>> {
        self.signed_publisher().active_muc_nodes(room_jid).await
    }
}
