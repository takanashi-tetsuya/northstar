//! Narrow capabilities of the listener, readiness, revocation, failure-supervisor and MUC outbox workers.

use super::*;
use crate::security::cluster_keys::ClusterReadinessAuthority;

/// MIX route discovery reads current PostgreSQL session ownership without
/// receiving publication, Redis, or session-mutation authority.
#[derive(Clone)]
pub(crate) struct ClusterMixRouteLookup {
    pub(super) routes: ClusterListenerPresenceRoutes,
}

impl ClusterMixRouteLookup {
    pub(crate) async fn lookup_nodes(&self, jid: &str) -> Result<Vec<String>> {
        self.routes.lookup_nodes(jid).await
    }

    pub(crate) fn node_id(&self) -> &str {
        self.routes.node_id()
    }
}

impl crate::services::mix::MixClusterRouteLookup for ClusterMixRouteLookup {
    fn lookup_nodes<'a>(
        &'a self,
        jid: &'a str,
    ) -> impl std::future::Future<Output = Result<Vec<String>>> + Send + 'a {
        ClusterMixRouteLookup::lookup_nodes(self, jid)
    }
}

/// The PubSub reader's connection, self-loop and generation fence. This handle
/// cannot sign a command, consume replay authority or dispatch an ACK.
#[derive(Clone)]
pub(crate) struct ClusterPubsubListenerTransport {
    pub(super) client: Option<redis::Client>,
    pub(super) pool: Option<Pool<RedisConnectionManager>>,
    pub(super) key_prefix: String,
    pub(super) node_id: String,
    pub(super) connection_uuid: uuid::Uuid,
    pub(super) instance_epoch: Arc<AtomicI64>,
    pub(super) health: Arc<ClusterHealth>,
    pub(super) listener_rotation: Arc<tokio::sync::Notify>,
    pub(super) failure_policy: Option<crate::security::cluster_bus::ClusterFailurePolicy>,
}

impl ClusterPubsubListenerTransport {
    pub(super) fn is_enabled(&self) -> bool {
        self.pool.is_some()
    }

    pub(super) fn key(&self, suffix: String) -> String {
        format!("{}:{suffix}", self.key_prefix)
    }

    pub(super) fn rotation_already_required(&self) -> bool {
        self.health.listener_generation.load(Ordering::Acquire)
            < self
                .health
                .required_listener_generation
                .load(Ordering::Acquire)
    }

    pub(super) fn record_listener_failure(&self, error: &anyhow::Error) {
        record_cluster_failure(
            &self.health,
            &self.listener_rotation,
            self.is_enabled(),
            self.failure_policy,
            ClusterFailureClass::PubSub,
            error,
        );
    }

    pub(super) fn confirm_generation(&self, generation: u64, rotation_epoch: u64) -> Result<()> {
        confirm_listener_generation(&self.health, generation, rotation_epoch)
    }
}

/// Listener-only admission after a signed envelope has passed durable replay
/// verification. This can check the current generation and match a pending
/// ACK, but cannot sign, publish or admit an envelope into PostgreSQL.
#[derive(Clone)]
pub(crate) struct ClusterListenerAdmission {
    pub(super) health: Arc<ClusterHealth>,
    pub(super) pending_acks: Arc<dashmap::DashMap<String, PendingClusterAck>>,
}

impl ClusterListenerAdmission {
    pub(super) fn validate_generation(&self, generation: u64, rotation_epoch: u64) -> Result<()> {
        validate_listener_generation_health(&self.health, generation, rotation_epoch)
    }

    pub(super) fn dispatch_pending_ack(
        &self,
        source_node: &str,
        payload: serde_json::Value,
    ) -> bool {
        dispatch_pending_ack(&self.pending_acks, source_node, payload)
    }

    pub(super) fn note_authentication_failure(&self, error: &anyhow::Error) {
        note_cluster_authentication_failure(&self.health, error);
    }

    pub(super) fn note_incompatible_peer_version(&self, node_id: &str, observed: Option<&str>) {
        note_incompatible_peer_version(&self.health, node_id, observed);
    }
}

impl ClusterListenerSecurity {
    pub(super) fn verify_current_envelope(
        &self,
        raw: &str,
        channel: &str,
        expected_source: Option<&str>,
    ) -> Result<crate::security::cluster_bus::SignedClusterEnvelope> {
        anyhow::ensure!(
            raw.len() <= MAX_CLUSTER_PAYLOAD_BYTES,
            "cluster envelope is oversized"
        );
        let security = self
            .publisher
            .security
            .as_ref()
            .context("cluster verifier is not configured")?;
        let envelope: crate::security::cluster_bus::SignedClusterEnvelope =
            serde_json::from_str(raw).context("cluster envelope is invalid JSON")?;
        envelope.verify(
            &self.publisher.namespace,
            &self.publisher.node_id,
            channel,
            expected_source,
            security.peers().as_ref(),
            chrono::Utc::now().timestamp(),
        )?;
        self.validate_verified_envelope(&envelope)?;
        Ok(envelope)
    }

    pub(super) fn validate_verified_envelope(
        &self,
        envelope: &crate::security::cluster_bus::SignedClusterEnvelope,
    ) -> Result<()> {
        let security = self
            .publisher
            .security
            .as_ref()
            .context("cluster verifier is not configured")?;
        envelope
            .current_verification_key(security.peers().as_ref(), chrono::Utc::now().timestamp())?;
        anyhow::ensure!(
            envelope.destination_connection_uuid == self.publisher.connection_uuid
                && envelope.destination_connection_epoch
                    == self.publisher.instance_epoch.load(Ordering::Acquire)
                && envelope.destination_key_id == security.current_key_id
                && envelope.destination_key_epoch == security.key_epoch,
            "cluster destination process instance or key is mismatched"
        );
        let key_authority = self
            .authorized_peer_keys
            .get(&envelope.source_node)
            .context("cluster source key has no current PostgreSQL authority cache")?;
        anyhow::ensure!(
            key_authority.accepts(&envelope.key_id, envelope.key_epoch, Instant::now()),
            "cluster source key generation is staged incorrectly, stale, or retired"
        );
        let authority = self
            .publisher
            .authorized_instances
            .get(&envelope.source_node)
            .context("cluster source process has no active PostgreSQL instance lease")?;
        anyhow::ensure!(
            authoritative_instance_matches(
                &authority,
                envelope.connection_uuid,
                envelope.connection_epoch,
                &envelope.key_id,
                envelope.key_epoch,
                Instant::now(),
            ),
            "cluster source process instance lease is stale or mismatched"
        );
        Ok(())
    }

    pub(super) async fn verify_signed_payload_persisted(
        &self,
        raw: &str,
        channel: &str,
        expected_source: Option<&str>,
    ) -> Result<crate::security::cluster_bus::SignedClusterEnvelope> {
        let envelope = self.verify_current_envelope(raw, channel, expected_source)?;
        if envelope.kind == crate::security::cluster_bus::ClusterCommandKind::Ack {
            anyhow::ensure!(
                serde_json::to_vec(&envelope.payload)?.len() <= MAX_DELIVERY_ACK_BYTES,
                "cluster acknowledgement payload is oversized"
            );
        }
        let pool = self
            .authority_pool
            .get()
            .context("cluster replay authority pool is unavailable")?;
        let admitted = match crate::db::admit_cluster_envelope_replay(
            pool,
            &self.publisher.namespace,
            &envelope,
        )
        .await
        {
            Ok(admitted) => admitted,
            Err(error) => {
                if crate::db::cluster_replay_validation_rejection(&error) {
                    // A changed event identity, stale source lease or elapsed
                    // validity window is a source-side validation rejection,
                    // not a lost local PostgreSQL authority connection.
                    self.publisher
                        .health
                        .replay_rejections
                        .fetch_add(1, Ordering::Relaxed);
                    return Err(error);
                }
                // Other PostgreSQL replay failures may mean that authority is
                // unavailable or internally inconsistent; fail closed.
                record_cluster_failure(
                    &self.publisher.health,
                    &self.publisher.listener_rotation,
                    self.publisher.is_enabled(),
                    self.publisher.failure_policy,
                    ClusterFailureClass::PostgreSqlAuthority,
                    &error,
                );
                return Err(error);
            }
        };
        if !admitted {
            self.publisher
                .health
                .replay_rejections
                .fetch_add(1, Ordering::Relaxed);
            anyhow::bail!("cluster envelope replay rejected by PostgreSQL authority");
        }
        // The durable unique fence has committed. A process-local replay
        // cache must not reject this already-consumed command afterward.
        Ok(envelope)
    }

    pub(super) async fn publish_ack(
        &self,
        admission: &ClusterListenerAdmission,
        source_node: &str,
        ack: NodeDeliveryAck,
        authority: &ListenerCommandAuthority,
    ) -> Result<()> {
        let Some(pool) = &self.publisher.pool else {
            return Ok(());
        };
        let mut conn = pool.get().await?;
        authority.validate(admission, self)?;
        let channel = self.publisher.key(format!("node:{source_node}"));
        self.publisher
            .publish_signed(&mut conn, source_node, &channel, serde_json::to_value(ack)?)
            .await?;
        Ok(())
    }
}

/// Authenticate and durably admit listener envelopes, then publish only their
/// correlated acknowledgements. This has no command routing or Redis mutation
/// authority beyond the signed ACK channel.
#[derive(Clone)]
pub(crate) struct ClusterListenerSecurity {
    pub(super) publisher: ClusterSignedPublisher,
    pub(super) authorized_peer_keys: Arc<dashmap::DashMap<String, AuthorizedPeerKeys>>,
    pub(super) authority_pool: Arc<std::sync::OnceLock<sqlx::PgPool>>,
}

/// Read-only health and exact identity view. This has no Redis, signing,
/// publication, or instance-claim authority.
#[derive(Clone)]
pub(crate) struct ClusterReadinessProbe {
    pub(super) health: Arc<ClusterHealth>,
    pub(super) authority: Option<ClusterReadinessAuthority>,
    pub(super) instance_epoch: Arc<AtomicI64>,
}

/// Exactly the cluster identity, wakeup, and fail-closed reporting authority
/// needed by the committed account-revocation consumer. No Redis client,
/// publication key, or broader cluster control plane crosses this boundary.
#[derive(Clone)]
pub(crate) struct ClusterRevocationAuthority {
    pub(super) domain: String,
    pub(super) node_id: String,
    pub(super) instance_uuid: uuid::Uuid,
    pub(super) instance_epoch: Arc<AtomicI64>,
    pub(super) notify: Arc<tokio::sync::Notify>,
    pub(super) enabled: bool,
    pub(super) failure_policy: Option<crate::security::cluster_bus::ClusterFailurePolicy>,
    pub(super) health: Arc<ClusterHealth>,
    pub(super) listener_rotation: Arc<tokio::sync::Notify>,
}

/// The failure supervisor can validate PostgreSQL identity, refresh peer
/// caches and fence cluster admission. It cannot publish, sign or issue Redis
/// commands.
#[derive(Clone)]
pub(crate) struct ClusterFailureSupervisorAuthority {
    pub(super) enabled: bool,
    pub(super) readiness: Option<ClusterReadinessAuthority>,
    pub(super) instance_epoch: Arc<AtomicI64>,
    pub(super) domain: String,
    pub(super) peer_nodes: Vec<String>,
    pub(super) expected_peer_keys: Vec<crate::security::cluster_keys::ExpectedClusterPeerKey>,
    pub(super) authorized_peer_keys: Arc<dashmap::DashMap<String, AuthorizedPeerKeys>>,
    pub(super) authorized_instances: Arc<dashmap::DashMap<String, AuthorizedClusterInstance>>,
    pub(super) health: Arc<ClusterHealth>,
    pub(super) listener_rotation: Arc<tokio::sync::Notify>,
    pub(super) failure_policy: Option<crate::security::cluster_bus::ClusterFailurePolicy>,
    pub(super) safety_lease_seconds: Option<u64>,
}

/// The maintenance worker may observe readiness and record a failed Redis
/// projection without receiving signing or publication authority.
#[derive(Clone)]
pub(crate) struct ClusterMaintenanceControl {
    pub(super) node_id: String,
    pub(super) enabled: bool,
    pub(super) peer_authority: ClusterFailureSupervisorAuthority,
    pub(super) health: Arc<ClusterHealth>,
    pub(super) listener_rotation: Arc<tokio::sync::Notify>,
    pub(super) direct_spool_notify: Arc<tokio::sync::Notify>,
    pub(super) failure_policy: Option<crate::security::cluster_bus::ClusterFailurePolicy>,
}

/// A MUC outbox worker needs only its node identity and committed wake signal
/// from the cluster control plane. Neither capability can publish a packet.
#[derive(Clone)]
pub(crate) struct ClusterMucOutboxSignal {
    pub(super) node_id: String,
    pub(super) wake: Arc<tokio::sync::Notify>,
}

/// PostgreSQL session-route discovery for listener presence probes. Redis is
/// only the command transport; it is not the authority for session ownership.
#[derive(Clone)]
pub(crate) struct ClusterListenerPresenceRoutes {
    pub(super) authority_pool: Arc<std::sync::OnceLock<sqlx::PgPool>>,
    pub(super) namespace: String,
    pub(super) node_id: String,
    pub(super) enabled: bool,
}

impl ClusterListenerPresenceRoutes {
    pub(super) async fn lookup_nodes(&self, jid: &str) -> Result<Vec<String>> {
        let jid = crate::jid::CanonicalJid::parse(jid)?;
        if !self.enabled {
            return Ok(Vec::new());
        }
        let authority_pool = self
            .authority_pool
            .get()
            .context("cluster session authority pool is unavailable")?;
        let nodes = if jid.resourcepart().is_some() {
            crate::db::cluster_session_route_authority(
                authority_pool,
                &self.namespace,
                &jid.to_string(),
            )
            .await?
            .map(|authority| authority.owner_node_id)
            .into_iter()
            .collect()
        } else {
            crate::db::cluster_session_nodes_for_bare(authority_pool, &self.namespace, &jid.bare())
                .await?
        };
        Ok(nodes)
    }

    pub(crate) async fn remote_nodes(&self, jid: &str) -> Result<Vec<String>> {
        Ok(self
            .lookup_nodes(jid)
            .await?
            .into_iter()
            .filter(|node_id| node_id != &self.node_id)
            .collect())
    }

    pub(crate) fn node_id(&self) -> &str {
        &self.node_id
    }
}

/// Disposable Redis room-membership projection used after an exact local
/// removal. The script keeps a node subscribed while any occupancy remains.
#[derive(Clone)]
pub(crate) struct ClusterListenerMucProjection {
    pub(super) pool: Option<Pool<RedisConnectionManager>>,
    pub(super) key_prefix: String,
    pub(super) node_id: String,
}

impl ClusterListenerMucProjection {
    pub(crate) async fn leave_empty_room(&self, room_jid: &str) -> Result<()> {
        leave_muc_node_projection(
            self.pool.as_ref(),
            &self.key_prefix,
            &self.node_id,
            room_jid,
        )
        .await
    }
}

/// Exact local SM-owned occupancy removal and reconciled room emptiness.
/// It cannot publish node commands or mutate PostgreSQL authority.
#[derive(Clone)]
pub(crate) struct ClusterSmMucTeardownProjection {
    pub(super) pool: Option<Pool<RedisConnectionManager>>,
    pub(super) key_prefix: String,
    pub(super) node_id: String,
    pub(super) connection_uuid: uuid::Uuid,
    pub(super) instance_epoch: Arc<AtomicI64>,
}

impl ClusterSmMucTeardownProjection {
    pub(super) fn key(&self, suffix: String) -> String {
        format!("{}:{suffix}", self.key_prefix)
    }

    pub(super) fn process_instance_token(&self) -> Result<String> {
        let epoch = self.instance_epoch.load(Ordering::Acquire);
        anyhow::ensure!(epoch >= 1, "cluster process instance is not authoritative");
        Ok(format!("{}.{}", self.connection_uuid.simple(), epoch))
    }

    pub(crate) async fn unregister_muc_occupant_epoch(
        &self,
        room_jid: &str,
        nick: &str,
        cluster_epoch: uuid::Uuid,
        connection_id: uuid::Uuid,
    ) -> Result<bool> {
        anyhow::ensure!(
            !cluster_epoch.is_nil() && !connection_id.is_nil(),
            "MUC unregister requires non-nil occupancy and connection identities"
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
        let script = redis::Script::new(
            r#"
            if redis.call('hget', KEYS[2], ARGV[1]) ~= ARGV[2] then return 0 end
            if redis.call('hget', KEYS[4], ARGV[1]) ~= ARGV[3] then return 0 end
            local raw = redis.call('hget', KEYS[1], ARGV[1])
            if not raw then return 0 end
            local ok, decoded = pcall(cjson.decode, raw)
            if not ok or decoded['cluster_epoch'] ~= ARGV[4]
                or decoded['connection_id'] ~= ARGV[5] then return 0 end
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
        let removed: i32 = script
            .key(occupants_key)
            .key(owners_key)
            .key(nodes_key)
            .key(instances_key)
            .key(node_counts_key)
            .arg(&nick)
            .arg(&self.node_id)
            .arg(process_instance)
            .arg(cluster_epoch.to_string())
            .arg(connection_id.to_string())
            .arg(MUC_SOFT_STATE_TTL_SECONDS)
            .invoke_async(&mut *conn)
            .await?;
        Ok(removed == 1)
    }

    pub(crate) async fn get_muc_occupants(
        &self,
        room_jid: &str,
    ) -> Result<HashMap<String, String>> {
        let Some(pool) = &self.pool else {
            return Ok(HashMap::new());
        };
        let room = crate::jid::canonicalize_bare(room_jid)?;
        reconcile_muc_soft_state_in(self.pool.as_ref(), &self.key_prefix, &room).await?;
        let mut conn = pool.get().await?;
        let occupants_key = self.key(format!("muc_occupants:{room}"));
        Ok(conn.hgetall(&occupants_key).await?)
    }

    pub(crate) async fn leave_muc(&self, room_jid: &str) -> Result<()> {
        leave_muc_node_projection(
            self.pool.as_ref(),
            &self.key_prefix,
            &self.node_id,
            room_jid,
        )
        .await
    }

    pub(crate) async fn room_is_empty(&self, room_jid: &str) -> Result<bool> {
        Ok(self.get_muc_occupants(room_jid).await?.is_empty())
    }
}

impl ClusterMucOutboxSignal {
    pub(super) async fn wait(&self) {
        self.wake.notified().await;
    }

    pub(crate) fn notify(&self) {
        self.wake.notify_one();
    }
}

impl ClusterFailureSupervisorAuthority {
    pub(crate) fn is_enabled(&self) -> bool {
        self.enabled
    }

    pub(crate) fn key_identity(
        &self,
    ) -> Option<&crate::security::cluster_keys::ClusterKeyDeploymentIdentity> {
        self.readiness
            .as_ref()
            .map(|readiness| &readiness.key_identity)
    }

    pub(crate) fn readiness_snapshot(&self) -> Option<ClusterReadinessAuthority> {
        let mut readiness = self.readiness.clone()?;
        readiness.instance_epoch = self.instance_epoch.load(Ordering::Acquire);
        Some(readiness)
    }

    pub(crate) async fn refresh_peers_with<R: ClusterAuthorityRepository>(
        &self,
        service: &ClusterAuthorityService<R>,
    ) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }
        refresh_peer_authority_with(
            service,
            &self.domain,
            &self.expected_peer_keys,
            &self.peer_nodes,
            &self.authorized_peer_keys,
            &self.authorized_instances,
        )
        .await
    }

    pub(crate) fn record_authority_failure(&self, error: &anyhow::Error) {
        record_cluster_failure(
            &self.health,
            &self.listener_rotation,
            self.enabled,
            self.failure_policy,
            ClusterFailureClass::PostgreSqlAuthority,
            error,
        );
    }

    pub(crate) fn failure_policy(&self) -> crate::security::cluster_bus::ClusterFailurePolicy {
        self.failure_policy
            .unwrap_or(crate::security::cluster_bus::ClusterFailurePolicy::FailClosed)
    }

    pub(crate) fn safety_lease_expired(&self) -> bool {
        let Some(seconds) = self.safety_lease_seconds else {
            return false;
        };
        self.health
            .failure_since
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .is_some_and(|since| since.elapsed() >= Duration::from_secs(seconds))
    }

    pub(crate) fn require_shutdown(&self) {
        require_cluster_shutdown(&self.health, self.enabled);
    }
}

impl ClusterRevocationAuthority {
    pub(super) fn identity(
        &self,
    ) -> crate::services::account_revocation_consumer::AccountRevocationConsumerIdentity {
        crate::services::account_revocation_consumer::AccountRevocationConsumerIdentity {
            domain: self.domain.clone(),
            node_id: self.node_id.clone(),
            instance_uuid: self.instance_uuid,
            instance_epoch: self.instance_epoch.load(Ordering::Acquire),
        }
    }

    pub(super) fn record_failure(&self, error: &anyhow::Error) {
        record_cluster_failure(
            &self.health,
            &self.listener_rotation,
            self.enabled,
            self.failure_policy,
            ClusterFailureClass::PostgreSqlAuthority,
            error,
        );
    }
}

pub(crate) struct AccountRevocationWorkerContext<R> {
    pub(super) service:
        crate::services::account_revocation_consumer::AccountRevocationConsumerService<R>,
    pub(super) routes: crate::state::AccountRevocationRoutes,
    pub(super) authority: ClusterRevocationAuthority,
}

impl<R: crate::services::account_revocation_consumer::AccountRevocationRepository>
    AccountRevocationWorkerContext<R>
{
    pub(crate) fn new(
        service: crate::services::account_revocation_consumer::AccountRevocationConsumerService<R>,
        routes: crate::state::AccountRevocationRoutes,
        authority: ClusterRevocationAuthority,
    ) -> Self {
        Self {
            service,
            routes,
            authority,
        }
    }
}

impl ClusterReadinessProbe {
    pub(crate) fn readiness_error(&self) -> Option<String> {
        cluster_readiness_error(&self.health)
    }

    pub(crate) fn authority_snapshot(&self) -> Option<ClusterReadinessAuthority> {
        self.authority.clone().map(|mut authority| {
            authority.instance_epoch = self.instance_epoch.load(Ordering::Acquire);
            authority
        })
    }
}
