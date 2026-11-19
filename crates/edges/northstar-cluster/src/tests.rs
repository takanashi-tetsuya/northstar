use super::*;
use northstar_security::cluster_keys::{
    ClusterKeyDeploymentIdentity, ClusterNodeInstance, ClusterPeerKeyAuthority,
    ExpectedClusterPeerKey,
};

pub(super) fn verification_manager(
    namespace: &str,
    security: Arc<northstar_security::cluster_bus::ClusterSecurityConfig>,
) -> ClusterManager {
    ClusterManager {
        node_id: security.node_id.clone(),
        namespace: namespace.into(),
        key_prefix: format!("northstar:{namespace}"),
        pool: None,
        client: None,
        security: Some(security),
        connection_uuid: uuid::Uuid::new_v4(),
        instance_epoch: Arc::new(AtomicI64::new(1)),
        authorized_instances: Arc::new(dashmap::DashMap::new()),
        authorized_peer_keys: Arc::new(dashmap::DashMap::new()),
        replay_cache: Arc::new(dashmap::DashMap::new()),
        replay_cache_gate: Arc::new(Mutex::new(())),
        replay_cache_next_expiry: Arc::new(AtomicI64::new(i64::MAX)),
        replay_cache_sweeps: Arc::new(AtomicU64::new(0)),
        session_store: Arc::new(std::sync::OnceLock::new()),
        health: Arc::new(ClusterHealth::disabled()),
        publication_gate: Arc::new(tokio::sync::RwLock::new(())),
        muc_outbox_notify: Arc::new(tokio::sync::Notify::new()),
        account_revocation_notify: Arc::new(tokio::sync::Notify::new()),
        direct_spool_notify: Arc::new(tokio::sync::Notify::new()),
        listener_rotation: Arc::new(tokio::sync::Notify::new()),
        pending_ack_slots: Arc::new(tokio::sync::Semaphore::new(MAX_PENDING_CLUSTER_ACKS)),
        pending_acks: Arc::new(dashmap::DashMap::new()),
    }
}

pub(super) fn listener_health_manager() -> ClusterManager {
    let namespace = "listener-health.test";
    let (_, security) = northstar_security::cluster_bus::test_configuration_pair(namespace);
    let mut manager = verification_manager(namespace, security);
    // A lazy, unused pool enables the health policy without opening Redis.
    let client = redis::Client::open("redis://127.0.0.1:1").unwrap();
    manager.pool = Some(cluster_pool_builder().build_unchecked(RedisConnectionManager { client }));
    manager.health = Arc::new(ClusterHealth::enabled());
    manager
}

pub(super) fn rename_occupant(
    epoch: uuid::Uuid,
    nick: &str,
) -> northstar_room_application::muc_service::SerializableMucOccupant {
    northstar_room_application::muc_service::SerializableMucOccupant {
        full_jid: "alice@example.test/Phone".to_owned(),
        room_jid: "room@conference.example.test".to_owned(),
        nick: nick.to_owned(),
        affiliation: "member".to_owned(),
        role: "participant".to_owned(),
        room_non_anonymous: true,
        occupant_id: "opaque".to_owned(),
        cluster_epoch: epoch,
        connection_id: uuid::Uuid::new_v4(),
        federated_domain: None,
        sm_session_id: None,
        payload: String::new(),
    }
}

/// The Redis-only MUC fixture has no PostgreSQL authority worker.  Seed
/// both sides from the same immutable key/instance values that the
/// production authority refresh would read, so it verifies the signed
/// cross-node publication instead of bypassing it.
pub(super) fn seed_test_peer_authority(receiver: &ClusterManager, sender: &ClusterManager) {
    let sender_security = sender
        .security
        .as_ref()
        .expect("Redis cluster fixture requires signing identity");
    let now = Instant::now();
    receiver.authorized_instances.insert(
        sender.node_id.clone(),
        AuthorizedClusterInstance {
            instance_uuid: sender.connection_uuid,
            instance_epoch: sender.instance_epoch.load(Ordering::Acquire),
            signing_key_id: sender_security.current_key_id.clone(),
            signing_key_epoch: sender_security.key_epoch,
            valid_until: now + Duration::from_secs(NODE_TTL_SECONDS),
            refresh_until: now + Duration::from_secs(10),
        },
    );
    receiver.authorized_peer_keys.insert(
        sender.node_id.clone(),
        AuthorizedPeerKeys {
            epoch: sender_security.key_epoch,
            current_key_id: sender_security.current_key_id.clone(),
            previous_key_id: None,
            refresh_until: now + Duration::from_secs(10),
        },
    );
}

mod delivery_contracts;
mod direct_commit_recovery;
mod health_and_listener;
mod instance_authority;
mod owner_contracts;
mod redis_soft_state;
mod signed_envelopes;
mod stanza_delivery;
