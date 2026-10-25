//! Account, SM session and MUC teardown notifiers, suspension, departures and session route release.

use super::*;

/// Post-commit revocation controls can discover only PostgreSQL-owned routes
/// and send exact, signed, acknowledged account/session teardowns.
#[derive(Clone)]
pub(crate) struct ClusterAccountTeardownNotifier {
    pub(super) routes: ClusterListenerPresenceRoutes,
    pub(super) sender: ClusterCorrelatedControlSender,
}

/// Exact durable SM session teardown control, without route mutation or
/// general cluster publication authority.
#[derive(Clone)]
pub(crate) struct ClusterSmSessionTeardownNotifier {
    pub(super) routes: ClusterListenerPresenceRoutes,
    pub(super) sender: ClusterCorrelatedControlSender,
}

/// Exact clustered SM MUC teardown with correlated ACKs and a fenced Redis
/// tombstone. It cannot publish arbitrary stanzas or change other occupancies.
#[derive(Clone)]
pub(crate) struct ClusterSmMucTeardown {
    pub(super) sender: ClusterCorrelatedControlSender,
}

/// Exact local occupant withdrawal followed by its signed room presence.
/// This handle cannot join a room or mutate another occupant's role.
#[derive(Clone)]
pub(crate) struct ClusterMucDeparture {
    pub(super) projection: ClusterSmMucTeardownProjection,
    pub(super) publisher: ClusterSignedPublisher,
}

impl ClusterMucDeparture {
    pub(crate) async fn publish_local_departure(
        &self,
        departed: &crate::xmpp::local_routes::muc::MucOccupant,
        was_last: bool,
    ) -> Result<()> {
        self.projection
            .unregister_muc_occupant_epoch(
                &departed.room_jid,
                &departed.nick,
                departed.cluster_epoch,
                departed.connection_id,
            )
            .await?;
        if was_last {
            self.projection.leave_muc(&departed.room_jid).await?;
        }
        self.publisher
            .send_muc_presence_with_status(
                &departed.room_jid,
                &crate::services::muc::SerializableMucOccupant::from(departed),
                true,
                false,
                None,
                None,
                None,
                None,
            )
            .await
    }
}

/// Exact SM/MUC suspension projection and committed-operation wake. It can
/// neither consume listener replay authority nor access PostgreSQL directly.
#[derive(Clone)]
pub(crate) struct ClusterSmSuspension {
    pub(super) publisher: ClusterSignedPublisher,
    pub(super) muc_outbox_notify: Arc<tokio::sync::Notify>,
}

/// Publish only a committed MUC operation wake using the shared signed
/// cluster transport; no SM suspension or route mutation authority is exposed.
#[derive(Clone)]
pub(crate) struct ClusterMucOperationWake {
    pub(super) publisher: ClusterSignedPublisher,
    pub(super) muc_outbox_notify: Arc<tokio::sync::Notify>,
}

impl ClusterAccountTeardownNotifier {
    pub(crate) async fn send_account_generation_teardown(
        &self,
        bare_jid: &str,
        user_id: uuid::Uuid,
        minimum_generation: i64,
    ) -> Result<()> {
        anyhow::ensure!(minimum_generation >= 0, "invalid auth generation");
        let bare_jid = northstar_xmpp_types::jid::canonicalize_bare(bare_jid)?;
        if !self.sender.publisher.is_enabled() {
            return Ok(());
        }
        let nodes = self.routes.lookup_nodes(&bare_jid).await?;
        let payload = serde_json::json!({
            "target": bare_jid,
            "account_generation_teardown": true,
            "user_id": user_id,
            "minimum_generation": minimum_generation,
        });
        for node_id in nodes {
            if node_id != self.routes.node_id() {
                self.sender
                    .send_control_to_node(&node_id, &bare_jid, payload.clone())
                    .await?;
            }
        }
        Ok(())
    }

    pub(crate) async fn send_session_instance_termination(
        &self,
        full_jid: &str,
        expected_connection_id: uuid::Uuid,
    ) -> Result<bool> {
        anyhow::ensure!(
            !expected_connection_id.is_nil(),
            "session termination requires a non-nil connection identity"
        );
        let full_jid = northstar_xmpp_types::jid::canonical_session_key(full_jid)?;
        if !self.sender.publisher.is_enabled() {
            return Ok(false);
        }
        let authority_pool = self
            .routes
            .authority_pool
            .get()
            .context("cluster session authority pool is unavailable")?;
        let Some(route) = crate::db::cluster_session_route_authority(
            authority_pool,
            &self.routes.namespace,
            &full_jid,
        )
        .await?
        else {
            return Ok(false);
        };
        if route.connection_uuid != expected_connection_id
            || route.owner_node_id == self.routes.node_id()
        {
            return Ok(false);
        }
        let payload = serde_json::json!({
            "target":full_jid,
            "session_termination":true,
            "connection_id":expected_connection_id,
        });
        let acknowledgement = self
            .sender
            .send_control_to_node_ack(&route.owner_node_id, &full_jid, payload)
            .await?;
        match acknowledgement.control_outcome {
            Some(ClusterControlOutcome::Matched) => Ok(true),
            Some(ClusterControlOutcome::AuthoritativelyAbsent) => Ok(false),
            Some(ClusterControlOutcome::WrongOwner) => {
                anyhow::bail!("cluster session termination reached the wrong process owner")
            }
            None => {
                anyhow::bail!("cluster session termination acknowledgement omitted its outcome")
            }
        }
    }
}

impl ClusterSmSessionTeardownNotifier {
    pub(crate) async fn send_sm_session_teardown(
        &self,
        full_jid: &str,
        sm_session_id: uuid::Uuid,
    ) -> Result<()> {
        let full_jid = northstar_xmpp_types::jid::canonical_session_key(full_jid)?;
        if !self.sender.publisher.is_enabled() {
            return Ok(());
        }
        let started = tokio::time::Instant::now();
        let nodes = self.routes.lookup_nodes(&full_jid).await;
        tracing::debug!(
            elapsed_ms = started.elapsed().as_millis(),
            success = nodes.is_ok(),
            "Redis session-route lookup completed"
        );
        let nodes = nodes?;
        let payload = serde_json::json!({
            "target": full_jid,
            "sm_session_teardown": true,
            "sm_session_id": sm_session_id,
        });
        for node_id in nodes {
            if node_id != self.routes.node_id() {
                self.sender
                    .send_control_to_node(&node_id, &full_jid, payload.clone())
                    .await?;
            }
        }
        Ok(())
    }
}

impl ClusterSmMucTeardown {
    /// Acknowledge every current room node before writing the exact SM
    /// tombstone and removing matching Redis occupancy indexes.
    pub(crate) async fn send_sm_muc_teardown(
        &self,
        room_jid: &str,
        sm_session_id: uuid::Uuid,
        occupant: &crate::services::muc::SerializableMucOccupant,
    ) -> Result<()> {
        let Some(pool) = &self.sender.publisher.pool else {
            return Ok(());
        };
        let room_jid = northstar_xmpp_types::jid::canonicalize_bare(room_jid)?;
        let nick = crate::services::xml_util::prepare_muc_nick(&occupant.nick)?;
        let nodes = self.sender.publisher.active_muc_nodes(&room_jid).await?;
        let occupants_key = self
            .sender
            .publisher
            .key(format!("muc_occupants:{room_jid}"));
        let owners_key = self
            .sender
            .publisher
            .key(format!("muc_occupant_nodes:{room_jid}"));
        let nodes_key = self.sender.publisher.key(format!("muc_nodes:{room_jid}"));
        let instances_key = self
            .sender
            .publisher
            .key(format!("muc_occupant_instances:{room_jid}"));
        let node_counts_key = self
            .sender
            .publisher
            .key(format!("muc_node_counts:{room_jid}"));
        let tombstone_key = self
            .sender
            .publisher
            .key(format!("sm_muc_teardown:{sm_session_id}"));
        let payload = serde_json::json!({
            "target": &room_jid,
            "sm_muc_teardown": true,
            "sm_session_id": sm_session_id,
            "occupant": occupant,
        });
        // Capture and acknowledge every current room node before mutating the
        // Redis ownership indexes. If the owner node removes itself first,
        // a crash could otherwise make a retry forget which live process
        // still needs the unavailable broadcast.
        for node_id in &nodes {
            if node_id != &self.sender.publisher.node_id {
                self.sender
                    .send_control_to_node(node_id, &room_jid, payload.clone())
                    .await?;
            }
        }
        let mut conn = pool.get().await?;
        let script = redis::Script::new(
            r#"
            redis.call('set', KEYS[4], '1', 'EX', ARGV[6])
            local raw = redis.call('hget', KEYS[1], ARGV[1])
            if not raw then return 0 end
            local ok, decoded = pcall(cjson.decode, raw)
            if not ok
                or decoded['sm_session_id'] ~= ARGV[2]
                or decoded['full_jid'] ~= ARGV[3]
                or decoded['cluster_epoch'] ~= ARGV[4]
                or decoded['connection_id'] ~= ARGV[5]
            then return 0 end
            local owner = redis.call('hget', KEYS[2], ARGV[1])
            redis.call('hdel', KEYS[1], ARGV[1])
            redis.call('hdel', KEYS[2], ARGV[1])
            redis.call('hdel', KEYS[5], ARGV[1])
            if owner then
                local remaining = redis.call('hincrby', KEYS[6], owner, -1)
                if remaining <= 0 then
                    redis.call('hdel', KEYS[6], owner)
                    redis.call('srem', KEYS[3], owner)
                end
            end
            if redis.call('hlen', KEYS[1]) == 0 and redis.call('hlen', KEYS[2]) == 0 then
                redis.call('del', KEYS[1], KEYS[2], KEYS[3], KEYS[5], KEYS[6])
            else
                redis.call('expire', KEYS[1], ARGV[7])
                redis.call('expire', KEYS[2], ARGV[7])
                redis.call('expire', KEYS[3], ARGV[7])
                redis.call('expire', KEYS[5], ARGV[7])
                redis.call('expire', KEYS[6], ARGV[7])
            end
            return 1
            "#,
        );
        let _: i32 = script
            .key(occupants_key)
            .key(owners_key)
            .key(nodes_key)
            .key(tombstone_key)
            .key(instances_key)
            .key(node_counts_key)
            .arg(&nick)
            .arg(sm_session_id.to_string())
            .arg(&occupant.full_jid)
            .arg(occupant.cluster_epoch.to_string())
            .arg(occupant.connection_id.to_string())
            .arg(SM_TEARDOWN_TOMBSTONE_TTL_SECONDS)
            .arg(MUC_SOFT_STATE_TTL_SECONDS)
            .invoke_async(&mut *conn)
            .await?;
        Ok(())
    }
}

impl ClusterSmSuspension {
    pub(crate) fn is_enabled(&self) -> bool {
        self.publisher.is_enabled()
    }

    pub(crate) fn node_id(&self) -> &str {
        &self.publisher.node_id
    }

    /// Refresh only the exact occupancy/SM epoch. A teardown tombstone wins
    /// over a delayed disconnect task and prevents a ghost from reappearing.
    pub(crate) async fn register_suspended_muc_occupant(
        &self,
        room_jid: &str,
        nick: &str,
        sm_session_id: uuid::Uuid,
        json: &str,
    ) -> Result<bool> {
        admit_health(&self.publisher.health, ClusterOperation::Resume)?;
        let incoming: crate::services::muc::SerializableMucOccupant = serde_json::from_str(json)?;
        anyhow::ensure!(
            incoming.sm_session_id == Some(sm_session_id)
                && !incoming.cluster_epoch.is_nil()
                && !incoming.connection_id.is_nil(),
            "suspended MUC refresh requires the exact occupancy and SM identities"
        );
        let Some(pool) = &self.publisher.pool else {
            return Ok(true);
        };
        let mut conn = pool.get().await?;
        let room = northstar_xmpp_types::jid::canonicalize_bare(room_jid)?;
        let nick = crate::services::xml_util::prepare_muc_nick(nick)?;
        let process_instance = self.publisher.process_instance_token()?;
        let occupants_key = self.publisher.key(format!("muc_occupants:{room}"));
        let owners_key = self.publisher.key(format!("muc_occupant_nodes:{room}"));
        let tombstone_key = self
            .publisher
            .key(format!("sm_muc_teardown:{sm_session_id}"));
        let nodes_key = self.publisher.key(format!("muc_nodes:{room}"));
        let instances_key = self.publisher.key(format!("muc_occupant_instances:{room}"));
        let node_counts_key = self.publisher.key(format!("muc_node_counts:{room}"));
        let alive_key = self
            .publisher
            .key(format!("node:{}:alive", self.publisher.node_id));
        let process_alive_key = self.publisher.process_alive_key()?;
        let script = redis::Script::new(
            r#"
            if redis.call('exists', KEYS[3]) == 1 then return 0 end
            if redis.call('hget', KEYS[2], ARGV[1]) ~= ARGV[2] then return 0 end
            if redis.call('hget', KEYS[5], ARGV[1]) ~= ARGV[3] then return 0 end
            local raw = redis.call('hget', KEYS[1], ARGV[1])
            if not raw then return 0 end
            local ok, current = pcall(cjson.decode, raw)
            if not ok or current['cluster_epoch'] ~= ARGV[5]
                or current['connection_id'] ~= ARGV[6] then return 0 end
            redis.call('hset', KEYS[1], ARGV[1], ARGV[4])
            redis.call('sadd', KEYS[4], ARGV[2])
            redis.call('set', KEYS[7], ARGV[8], 'EX', ARGV[7])
            redis.call('set', KEYS[8], ARGV[8], 'EX', ARGV[7])
            redis.call('expire', KEYS[1], ARGV[9])
            redis.call('expire', KEYS[2], ARGV[9])
            redis.call('expire', KEYS[4], ARGV[9])
            redis.call('expire', KEYS[5], ARGV[9])
            redis.call('expire', KEYS[6], ARGV[9])
            return 1
            "#,
        );
        let stored: i32 = script
            .key(occupants_key)
            .key(owners_key)
            .key(tombstone_key)
            .key(nodes_key)
            .key(instances_key)
            .key(node_counts_key)
            .key(alive_key)
            .key(process_alive_key)
            .arg(&nick)
            .arg(&self.publisher.node_id)
            .arg(process_instance)
            .arg(json)
            .arg(incoming.cluster_epoch.to_string())
            .arg(incoming.connection_id.to_string())
            .arg(NODE_TTL_SECONDS)
            .arg(NODE_PROTOCOL_VERSION)
            .arg(MUC_SOFT_STATE_TTL_SECONDS)
            .invoke_async(&mut *conn)
            .await?;
        Ok(stored == 1)
    }

    pub(super) async fn send_muc_operation_wake(
        &self,
        descriptor: &northstar_room_core::ClusterMucWakeDescriptor,
    ) -> Result<()> {
        send_muc_operation_wake(&self.publisher, &self.muc_outbox_notify, descriptor).await
    }
}

pub(super) async fn send_muc_operation_wake(
    publisher: &ClusterSignedPublisher,
    muc_outbox_notify: &tokio::sync::Notify,
    descriptor: &northstar_room_core::ClusterMucWakeDescriptor,
) -> Result<()> {
    if descriptor
        .target_nodes
        .iter()
        .any(|node| node == &publisher.node_id)
    {
        muc_outbox_notify.notify_one();
    }
    let Some(pool) = &publisher.pool else {
        return Ok(());
    };
    let payload = serde_json::json!({
        "target": descriptor.room_id.to_string(),
        "muc_operation_wake": true,
        "operation_id": descriptor.operation_id.to_string(),
        "database_event_id": descriptor.event_id.to_string(),
        "event_sequence": descriptor.event_sequence,
        "request_id": descriptor.operation_id.to_string(),
    });
    let mut conn = pool.get().await?;
    for node_id in &descriptor.target_nodes {
        if node_id == &publisher.node_id {
            continue;
        }
        let channel = publisher.key(format!("node:{node_id}"));
        let _ = publisher
            .publish_signed(&mut conn, node_id, &channel, payload.clone())
            .await?;
    }
    Ok(())
}

impl crate::services::muc::MucWakePort for ClusterSmSuspension {
    async fn wake(&self, descriptor: &northstar_room_core::ClusterMucWakeDescriptor) -> Result<()> {
        self.send_muc_operation_wake(descriptor).await
    }

    fn record_failure(&self, error: &anyhow::Error) {
        self.publisher.record_control_plane_failure(error);
    }
}

impl crate::services::muc::MucWakePort for ClusterMucOperationWake {
    async fn wake(&self, descriptor: &northstar_room_core::ClusterMucWakeDescriptor) -> Result<()> {
        send_muc_operation_wake(&self.publisher, &self.muc_outbox_notify, descriptor).await
    }

    fn record_failure(&self, error: &anyhow::Error) {
        self.publisher.record_control_plane_failure(error);
    }
}

/// Identity needed to authorize a signed session-termination command against
/// the PostgreSQL route. The epoch is read after the authority query, so a
/// listener never uses a stale process-instance snapshot.
#[derive(Clone)]
pub(crate) struct ClusterSessionTerminationIdentity {
    pub(super) namespace: String,
    pub(super) node_id: String,
    pub(super) instance_uuid: uuid::Uuid,
    pub(super) instance_epoch: Arc<AtomicI64>,
}

/// Exact local route release after a connection has been removed from the
/// process-local map. This handle cannot register routes or publish commands.
#[derive(Clone)]
pub(crate) struct ClusterSessionRouteRelease {
    pub(super) pool: Option<Pool<RedisConnectionManager>>,
    pub(super) authority_pool: Arc<std::sync::OnceLock<sqlx::PgPool>>,
    pub(super) namespace: String,
    pub(super) key_prefix: String,
    pub(super) node_id: String,
    pub(super) connection_uuid: uuid::Uuid,
    pub(super) instance_epoch: Arc<AtomicI64>,
}

impl ClusterSessionRouteRelease {
    pub(crate) async fn release_exact_local_session_route(
        &self,
        full_jid: &str,
        connection_id: uuid::Uuid,
    ) -> Result<()> {
        let (full_jid, bare) = session_route_keys(full_jid)?;
        let Some(pool) = &self.pool else {
            return Ok(());
        };
        let authority_pool = self
            .authority_pool
            .get()
            .context("cluster session authority pool is unavailable")?;
        let _ = crate::db::release_cluster_session_route(
            authority_pool,
            &self.namespace,
            &full_jid,
            &self.node_id,
            self.connection_uuid,
            self.instance_epoch.load(Ordering::Acquire),
            connection_id,
        )
        .await?;
        let mut conn = pool.get().await?;
        let full_key = format!("{}:session:{full_jid}", self.key_prefix);
        let bare_key = format!("{}:user_sessions:{bare}", self.key_prefix);
        let activity_key = format!("{}:session_activity", self.key_prefix);
        let instance_key = format!("{}:session_instance:{full_jid}", self.key_prefix);
        let script = redis::Script::new(
            r#"
            if redis.call('get', KEYS[1]) == ARGV[1] and redis.call('get', KEYS[4]) == ARGV[3] then
                redis.call('del', KEYS[1])
                redis.call('del', KEYS[4])
                redis.call('srem', KEYS[2], ARGV[2])
                redis.call('zrem', KEYS[3], ARGV[2])
                return 1
            end
            return 0
            "#,
        );
        let _: i32 = script
            .key(&full_key)
            .key(&bare_key)
            .key(&activity_key)
            .key(&instance_key)
            .arg(&self.node_id)
            .arg(&full_jid)
            .arg(connection_id.to_string())
            .invoke_async(&mut *conn)
            .await?;
        Ok(())
    }
}

impl ClusterSessionTerminationIdentity {
    pub(crate) fn namespace(&self) -> &str {
        &self.namespace
    }

    pub(crate) fn local_instance(
        &self,
    ) -> crate::services::session_termination_authority::LocalClusterInstance {
        crate::services::session_termination_authority::LocalClusterInstance {
            node_id: self.node_id.clone(),
            instance_uuid: self.instance_uuid,
            instance_epoch: self.instance_epoch.load(Ordering::Acquire),
        }
    }
}
