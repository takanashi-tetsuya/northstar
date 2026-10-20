//! Scoped Redis maintenance authority: session leases, MUC soft-state projection and node projection cleanup.

use super::*;

/// PostgreSQL-fenced maintenance of disposable Redis projections. This handle
/// has no signer, publication gate, PubSub client, or delivery route.
#[derive(Clone)]
pub(crate) struct ClusterMaintenanceRedis {
    pub(super) pool: Option<Pool<RedisConnectionManager>>,
    pub(super) authority_pool: Arc<std::sync::OnceLock<sqlx::PgPool>>,
    pub(super) namespace: String,
    pub(super) key_prefix: String,
    pub(super) node_id: String,
    pub(super) connection_uuid: uuid::Uuid,
    pub(super) instance_epoch: Arc<AtomicI64>,
    pub(super) peer_nodes: Vec<String>,
    pub(super) health: Arc<ClusterHealth>,
}

impl ClusterMaintenanceRedis {
    pub(super) fn key(&self, suffix: String) -> String {
        format!("{}:{suffix}", self.key_prefix)
    }

    pub(super) fn process_instance_token(&self) -> Result<String> {
        let epoch = self.instance_epoch.load(Ordering::Acquire);
        anyhow::ensure!(epoch >= 1, "cluster process instance is not authoritative");
        Ok(format!("{}.{}", self.connection_uuid.simple(), epoch))
    }

    pub(super) fn process_alive_key(&self) -> Result<String> {
        Ok(self.key(format!(
            "node_instance:{}:{}:alive",
            self.node_id,
            self.process_instance_token()?
        )))
    }

    pub(super) fn note_incompatible_peer_version(&self, node_id: &str, observed: Option<&str>) {
        note_incompatible_peer_version(&self.health, node_id, observed);
    }
}

impl ClusterMaintenanceRedis {
    pub(super) async fn touch_node(&self) -> Result<()> {
        let Some(pool) = &self.pool else {
            return Ok(());
        };
        let mut conn = pool.get().await?;
        let key = self.key(format!("node:{}:alive", self.node_id));
        let process_key = self.process_alive_key()?;
        // Version 2 peers require nonce-correlated delivery acknowledgements.
        // Keeping this in the existing liveness key makes the change safe for
        // rolling upgrades: version 1 peers still publish the legacy value.
        let script = redis::Script::new(
            r#"
            redis.call('set', KEYS[1], ARGV[1], 'EX', ARGV[2])
            redis.call('set', KEYS[2], ARGV[1], 'EX', ARGV[2])
            return 1
            "#,
        );
        let _: i32 = script
            .key(key)
            .key(process_key)
            .arg(NODE_PROTOCOL_VERSION)
            .arg(NODE_TTL_SECONDS)
            .invoke_async(&mut *conn)
            .await?;
        let mut compatible = true;
        for node_id in &self.peer_nodes {
            let observed: Option<String> =
                conn.get(self.key(format!("node:{node_id}:alive"))).await?;
            if observed
                .as_deref()
                .is_some_and(|version| version != NODE_PROTOCOL_VERSION)
            {
                compatible = false;
                self.note_incompatible_peer_version(node_id, observed.as_deref());
            }
        }
        if compatible {
            self.health
                .peer_versions_compatible
                .store(true, Ordering::Release);
        }
        Ok(())
    }

    pub(super) async fn renew_session_authority(
        &self,
        full_jid: &str,
        connection_id: uuid::Uuid,
    ) -> Result<Option<SessionRouteAuthorityToken>> {
        let (full_jid, _) = session_route_keys(full_jid)?;
        if self.pool.is_none() {
            return Ok(Some(SessionRouteAuthorityToken::NoCluster));
        }
        let authority_pool = self
            .authority_pool
            .get()
            .context("cluster session authority pool is unavailable")?;
        let owner_instance_epoch = self.instance_epoch.load(Ordering::Acquire);
        let renewed = crate::db::refresh_cluster_session_route(
            authority_pool,
            &self.namespace,
            &full_jid,
            &self.node_id,
            self.connection_uuid,
            owner_instance_epoch,
            connection_id,
            Duration::from_secs(SESSION_TTL_SECONDS),
        )
        .await?;
        Ok(renewed.then_some(SessionRouteAuthorityToken::Exact {
            owner_instance_epoch,
        }))
    }

    pub(super) async fn refresh_session_projection(
        &self,
        full_jid: &str,
        activity_age_seconds: u64,
        connection_id: uuid::Uuid,
    ) -> Result<bool> {
        let (full_jid, bare) = session_route_keys(full_jid)?;
        let Some(pool) = &self.pool else {
            return Ok(true);
        };
        let mut conn = pool.get().await?;
        let full_key = self.key(format!("session:{full_jid}"));
        let bare_key = self.key(format!("user_sessions:{bare}"));
        let activity_key = self.key("session_activity".to_owned());
        let instance_key = self.key(format!("session_instance:{full_jid}"));
        let script = redis::Script::new(
            r#"
            if redis.call('get', KEYS[1]) ~= ARGV[1] or redis.call('get', KEYS[4]) ~= ARGV[6] then return 0 end
            redis.call('expire', KEYS[1], ARGV[3])
            redis.call('expire', KEYS[4], ARGV[3])
            redis.call('sadd', KEYS[2], ARGV[2])
            redis.call('expire', KEYS[2], ARGV[4])
            local now = redis.call('time')
            redis.call('zadd', KEYS[3], tonumber(now[1])-tonumber(ARGV[5]), ARGV[2])
            redis.call('zremrangebyscore', KEYS[3], '-inf', tonumber(now[1])-tonumber(ARGV[3])-1)
            return 1
            "#,
        );
        let refreshed = script
            .key(full_key)
            .key(bare_key)
            .key(activity_key)
            .key(instance_key)
            .arg(&self.node_id)
            .arg(&full_jid)
            .arg(SESSION_TTL_SECONDS)
            .arg(USER_SET_TTL_SECONDS)
            .arg(activity_age_seconds.min(SESSION_TTL_SECONDS))
            .arg(connection_id.to_string())
            .invoke_async::<i32>(&mut *conn)
            .await?;
        Ok(refreshed == 1)
    }

    pub(super) async fn release_session_authority(
        &self,
        full_jid: &str,
        connection_id: uuid::Uuid,
        token: SessionRouteAuthorityToken,
    ) -> Result<()> {
        let (full_jid, _) = session_route_keys(full_jid)?;
        if self.pool.is_none() {
            anyhow::ensure!(
                token == SessionRouteAuthorityToken::NoCluster,
                "unexpected PostgreSQL session-route authority token without Redis"
            );
            return Ok(());
        }
        let SessionRouteAuthorityToken::Exact {
            owner_instance_epoch,
        } = token
        else {
            anyhow::bail!("cluster session-route release lacks the original instance epoch");
        };
        let authority_pool = self
            .authority_pool
            .get()
            .context("cluster session authority pool is unavailable")?;
        crate::db::release_cluster_session_route(
            authority_pool,
            &self.namespace,
            &full_jid,
            &self.node_id,
            self.connection_uuid,
            owner_instance_epoch,
            connection_id,
        )
        .await?;
        Ok(())
    }

    pub(super) async fn reconcile_muc_soft_state(&self, room_jid: &str) -> Result<()> {
        reconcile_muc_soft_state_in(self.pool.as_ref(), &self.key_prefix, room_jid).await
    }

    pub async fn register_muc_occupant(
        &self,
        room_jid: &str,
        nick: &str,
        json: &str,
    ) -> Result<bool> {
        let incoming: crate::services::muc::SerializableMucOccupant = serde_json::from_str(json)?;
        anyhow::ensure!(
            !incoming.cluster_epoch.is_nil()
                && !incoming.connection_id.is_nil()
                && incoming.room_jid == crate::jid::canonicalize_bare(room_jid)?
                && incoming.nick == crate::services::xml_util::prepare_muc_nick(nick)?,
            "MUC refresh requires the exact non-nil occupancy identity"
        );
        let Some(pool) = &self.pool else {
            return Ok(true);
        };
        let mut conn = pool.get().await?;
        let room = crate::jid::canonicalize_bare(room_jid)?;
        let nick = crate::services::xml_util::prepare_muc_nick(nick)?;
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
            local raw = redis.call('hget', KEYS[1], ARGV[1])
            local owner = redis.call('hget', KEYS[2], ARGV[1])
            local instance = redis.call('hget', KEYS[4], ARGV[1])
            local created = not raw and not owner and not instance
            if raw and owner and instance then
                if owner ~= ARGV[2] or instance ~= ARGV[3] then return 0 end
                local ok, current = pcall(cjson.decode, raw)
                if not ok then return 0 end
                if current['cluster_epoch'] ~= ARGV[5]
                    or current['connection_id'] ~= ARGV[6] then return 0 end
            elseif raw or owner or instance then
                -- Incomplete soft-state cannot authorize anything. The
                -- caller has just revalidated this exact identity against
                -- PostgreSQL, so repair only this internally inconsistent nick
                -- while keeping the O(1) owner-count index balanced.
                redis.call('hdel', KEYS[1], ARGV[1])
                redis.call('hdel', KEYS[2], ARGV[1])
                redis.call('hdel', KEYS[4], ARGV[1])
                if owner then
                    local remaining = redis.call('hincrby', KEYS[5], owner, -1)
                    if remaining <= 0 then
                        redis.call('hdel', KEYS[5], owner)
                        redis.call('srem', KEYS[3], owner)
                    end
                end
                created = true
            end
            redis.call('hset', KEYS[1], ARGV[1], ARGV[4])
            redis.call('hset', KEYS[2], ARGV[1], ARGV[2])
            redis.call('hset', KEYS[4], ARGV[1], ARGV[3])
            if created then redis.call('hincrby', KEYS[5], ARGV[2], 1) end
            redis.call('sadd', KEYS[3], ARGV[2])
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
        let refreshed: i32 = script
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
            .arg(json)
            .arg(incoming.cluster_epoch.to_string())
            .arg(incoming.connection_id.to_string())
            .arg(NODE_TTL_SECONDS)
            .arg(NODE_PROTOCOL_VERSION)
            .arg(MUC_SOFT_STATE_TTL_SECONDS)
            .invoke_async(&mut *conn)
            .await?;
        Ok(refreshed == 1)
    }

    pub async fn join_muc(&self, room_jid: &str) -> Result<()> {
        let Some(pool) = &self.pool else {
            return Ok(());
        };
        self.touch_node().await?;
        let mut conn = pool.get().await?;
        let room = crate::jid::canonicalize_bare(room_jid)?;
        let key = self.key(format!("muc_nodes:{room}"));
        let script = redis::Script::new(
            r#"
            redis.call('sadd', KEYS[1], ARGV[1])
            redis.call('expire', KEYS[1], ARGV[2])
            return 1
            "#,
        );
        let _: i32 = script
            .key(key)
            .arg(&self.node_id)
            .arg(MUC_SOFT_STATE_TTL_SECONDS)
            .invoke_async(&mut *conn)
            .await?;
        Ok(())
    }
}

impl crate::services::session_route_maintenance::SessionRouteRenewalPort
    for ClusterMaintenanceRedis
{
    async fn renew_authority(
        &self,
        full_jid: &str,
        connection_id: uuid::Uuid,
    ) -> Result<Option<SessionRouteAuthorityToken>> {
        self.renew_session_authority(full_jid, connection_id).await
    }

    async fn refresh_projection(
        &self,
        full_jid: &str,
        activity_age_seconds: u64,
        connection_id: uuid::Uuid,
    ) -> Result<bool> {
        self.refresh_session_projection(full_jid, activity_age_seconds, connection_id)
            .await
    }

    async fn release_authority(
        &self,
        full_jid: &str,
        connection_id: uuid::Uuid,
        token: SessionRouteAuthorityToken,
    ) -> Result<()> {
        self.release_session_authority(full_jid, connection_id, token)
            .await
    }
}

impl crate::services::muc::MucSoftStateProjectionPort for &ClusterMaintenanceRedis {
    async fn join_room(&self, room_jid: &str) -> Result<()> {
        self.join_muc(room_jid).await
    }

    async fn refresh_occupant(
        &self,
        room_jid: &str,
        nick: &str,
        exact_occupant_json: &str,
    ) -> Result<bool> {
        self.register_muc_occupant(room_jid, nick, exact_occupant_json)
            .await
    }

    async fn reconcile_room(&self, room_jid: &str) -> Result<()> {
        self.reconcile_muc_soft_state(room_jid).await
    }
}

impl ClusterMaintenanceControl {
    pub(super) fn record_muc_projection_failure(
        &self,
        error: crate::services::muc::MucSoftStateDegradation,
    ) -> anyhow::Error {
        // A PG-renewed snapshot can race a kick, rename or same-nick rejoin.
        // The Redis CAS must reject another exact identity, but that is not a
        // command/transport outage and must not rotate a healthy listener.
        // The caller still counts this unsuccessful projection, so an active
        // reconciliation cannot declare readiness until every refresh passes.
        let identity_conflict = matches!(
            &error,
            crate::services::muc::MucSoftStateDegradation::IdentityRejected
        );
        let error = anyhow::Error::from(error);
        if !identity_conflict {
            self.record_control_plane_failure(&error);
        }
        error
    }

    pub(super) async fn refresh_peers_with<R: ClusterAuthorityRepository>(
        &self,
        service: &ClusterAuthorityService<R>,
    ) -> Result<()> {
        self.peer_authority.refresh_peers_with(service).await
    }

    pub(super) fn readiness_error(&self) -> Option<String> {
        cluster_readiness_error(&self.health)
    }

    pub(super) fn begin_reconciliation(&self) -> Result<Option<u64>> {
        begin_cluster_reconciliation(&self.health, self.enabled)
    }

    pub(super) fn complete_reconciliation(
        &self,
        rotation_epoch: u64,
    ) -> Result<ReconciliationOutcome> {
        complete_cluster_reconciliation(&self.health, rotation_epoch)
    }

    pub(super) fn record_control_plane_failure(&self, error: &anyhow::Error) {
        record_cluster_failure(
            &self.health,
            &self.listener_rotation,
            self.enabled,
            self.failure_policy,
            ClusterFailureClass::RedisCommand,
            error,
        );
    }
}

pub(super) async fn reconcile_muc_soft_state_in(
    pool: Option<&Pool<RedisConnectionManager>>,
    key_prefix: &str,
    room_jid: &str,
) -> Result<()> {
    let Some(pool) = pool else {
        return Ok(());
    };
    let key = |suffix: String| format!("{key_prefix}:{suffix}");
    let room = crate::jid::canonicalize_bare(room_jid)?;
    let occupants_key = key(format!("muc_occupants:{room}"));
    let owners_key = key(format!("muc_occupant_nodes:{room}"));
    let nodes_key = key(format!("muc_nodes:{room}"));
    let instances_key = key(format!("muc_occupant_instances:{room}"));
    let node_counts_key = key(format!("muc_node_counts:{room}"));
    let alive_prefix = key("node:".to_owned());
    let instance_alive_prefix = key("node_instance:".to_owned());
    let mut conn = pool.get().await?;
    let script = redis::Script::new(
        r#"
        local alive_cache = {}
        local function node_is_alive(node)
            local cached = alive_cache[node]
            if cached == nil then
                cached = redis.call('exists', ARGV[1] .. node .. ':alive')
                alive_cache[node] = cached
            end
            return cached == 1
        end

        local function instance_is_alive(node, instance)
            if not instance then return false end
            local cache_key = node .. '|' .. instance
            local cached = alive_cache[cache_key]
            if cached == nil then
                cached = redis.call(
                    'exists', ARGV[2] .. node .. ':' .. instance .. ':alive'
                )
                alive_cache[cache_key] = cached
            end
            return cached == 1
        end

        local owners = redis.call('hgetall', KEYS[2])
        for index = 1, #owners, 2 do
            local nick = owners[index]
            local owner = owners[index + 1]
            local instance = redis.call('hget', KEYS[4], nick)
            if redis.call('hexists', KEYS[1], nick) == 0
                or not node_is_alive(owner)
                or not instance_is_alive(owner, instance)
            then
                redis.call('hdel', KEYS[1], nick)
                redis.call('hdel', KEYS[2], nick)
                redis.call('hdel', KEYS[4], nick)
            end
        end

        local occupants = redis.call('hgetall', KEYS[1])
        for index = 1, #occupants, 2 do
            local nick = occupants[index]
            if redis.call('hexists', KEYS[2], nick) == 0
                or redis.call('hexists', KEYS[4], nick) == 0
            then
                redis.call('hdel', KEYS[1], nick)
                redis.call('hdel', KEYS[2], nick)
                redis.call('hdel', KEYS[4], nick)
            end
        end

        for _, nick in ipairs(redis.call('hkeys', KEYS[4])) do
            if redis.call('hexists', KEYS[1], nick) == 0
                or redis.call('hexists', KEYS[2], nick) == 0
            then
                redis.call('hdel', KEYS[4], nick)
            end
        end

        local live_owner_nodes = {}
        redis.call('del', KEYS[5])
        owners = redis.call('hgetall', KEYS[2])
        for index = 1, #owners, 2 do
            local owner = owners[index + 1]
            live_owner_nodes[owner] = true
            redis.call('hincrby', KEYS[5], owner, 1)
            redis.call('sadd', KEYS[3], owner)
        end
        for _, node in ipairs(redis.call('smembers', KEYS[3])) do
            if not live_owner_nodes[node] or not node_is_alive(node) then
                redis.call('srem', KEYS[3], node)
            end
        end

        if redis.call('hlen', KEYS[1]) == 0
            and redis.call('hlen', KEYS[2]) == 0
            and redis.call('hlen', KEYS[4]) == 0
        then
            redis.call('del', KEYS[1], KEYS[2], KEYS[3], KEYS[4], KEYS[5])
            return 0
        end
        redis.call('expire', KEYS[1], ARGV[3])
        redis.call('expire', KEYS[2], ARGV[3])
        redis.call('expire', KEYS[3], ARGV[3])
        redis.call('expire', KEYS[4], ARGV[3])
        redis.call('expire', KEYS[5], ARGV[3])
        return redis.call('hlen', KEYS[1])
        "#,
    );
    let _: usize = script
        .key(occupants_key)
        .key(owners_key)
        .key(nodes_key)
        .key(instances_key)
        .key(node_counts_key)
        .arg(alive_prefix)
        .arg(instance_alive_prefix)
        .arg(MUC_SOFT_STATE_TTL_SECONDS)
        .invoke_async(&mut *conn)
        .await?;
    Ok(())
}

pub(super) async fn leave_muc_node_projection(
    pool: Option<&Pool<RedisConnectionManager>>,
    key_prefix: &str,
    node_id: &str,
    room_jid: &str,
) -> Result<()> {
    let Some(pool) = pool else {
        return Ok(());
    };
    let mut conn = pool.get().await?;
    let room = crate::jid::canonicalize_bare(room_jid)?;
    let key = |suffix: &str| format!("{key_prefix}:{suffix}");
    let owners_key = key(&format!("muc_occupant_nodes:{room}"));
    let nodes_key = key(&format!("muc_nodes:{room}"));
    let occupants_key = key(&format!("muc_occupants:{room}"));
    let instances_key = key(&format!("muc_occupant_instances:{room}"));
    let node_counts_key = key(&format!("muc_node_counts:{room}"));
    let script = redis::Script::new(
        r#"
        if tonumber(redis.call('hget', KEYS[5], ARGV[1]) or '0') > 0 then return 0 end
        redis.call('srem', KEYS[2], ARGV[1])
        if redis.call('hlen', KEYS[3]) == 0 then
            redis.call('del', KEYS[1], KEYS[2], KEYS[3], KEYS[4], KEYS[5])
        else
            redis.call('expire', KEYS[1], ARGV[2])
            redis.call('expire', KEYS[2], ARGV[2])
            redis.call('expire', KEYS[3], ARGV[2])
            redis.call('expire', KEYS[4], ARGV[2])
            redis.call('expire', KEYS[5], ARGV[2])
        end
        return 1
        "#,
    );
    let _: i32 = script
        .key(owners_key)
        .key(nodes_key)
        .key(occupants_key)
        .key(instances_key)
        .key(node_counts_key)
        .arg(node_id)
        .arg(MUC_SOFT_STATE_TTL_SECONDS)
        .invoke_async(&mut *conn)
        .await?;
    Ok(())
}
