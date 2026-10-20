use crate::security::cluster_keys::ClusterReadinessAuthority;
use crate::services::cluster_authority::{ClusterAuthorityRepository, ClusterAuthorityService};
use crate::services::cluster_instance_release::{
    ClusterInstanceReleaseIdentity, ClusterInstanceReleaseRepository, ClusterInstanceReleaseService,
};
use crate::services::cluster_muc_outbox_settlement::AckOutcome;
use crate::services::node_message_contract_verifier::{
    NodeMessageContractVerifier, NodeMessageProjectionRepository, RequestedNodeMessageProjection,
    VerifiedNodeMessageProjection,
};
use crate::services::session_route_maintenance::SessionRouteAuthorityToken;
use crate::state::AppState;
use anyhow::{Context, Result};
use bb8::Pool;
use futures::{future::BoxFuture, FutureExt, StreamExt};
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;

mod authority;
mod delivery_contract;
mod health;
mod listener;
mod maintenance_redis;
mod muc_fanout;
mod muc_occupancy;
mod muc_outbox;
mod node_delivery;
mod pool;
mod publisher;
mod recovery_replay;
mod routing;
mod teardown;
mod worker_capabilities;
mod workers;

use listener::*;

use self::authority::*;
pub use self::delivery_contract::*;
pub use self::health::*;
pub(crate) use self::maintenance_redis::*;
pub use self::muc_occupancy::*;
use self::muc_outbox::*;
pub(crate) use self::node_delivery::*;
use self::publisher::*;
use self::recovery_replay::*;
pub(crate) use self::teardown::*;
pub(crate) use self::worker_capabilities::*;
pub use self::workers::*;

use pool::{
    cluster_pool_builder, open_pubsub, publish_listener_probe, subscribe_pubsub,
    RedisConnectionManager,
};

const SESSION_TTL_SECONDS: u64 = 900;
// Match the configured XEP-0198 resume-timeout upper bound. This prevents a
// very late disconnect task from recreating a Redis MUC occupant after its
// durable stream has already completed teardown.
const SM_TEARDOWN_TOMBSTONE_TTL_SECONDS: u64 = 86_400;
const USER_SET_TTL_SECONDS: u64 = 1_800;
const NODE_TTL_SECONDS: u64 = 90;
const CLUSTER_MAINTENANCE_INTERVAL_SECONDS: u64 = 30;
// Redis is only a disposable routing projection for MUC occupancy.  Keep the
// projection long enough to survive several missed maintenance ticks, but
// never leave an abandoned temporary room unbounded.  Every exact
// PostgreSQL-authoritative occupant refresh renews all three room keys
// atomically; a room with no live refresher therefore disappears by itself.
const MUC_SOFT_STATE_TTL_SECONDS: u64 = 300;
// Bound every Redis control-plane request, not only the delivery ACK wait.
// Without this, a command written while Redis is paused can remain queued and
// execute after recovery, turning a failed/expired stanza route into a late
// delivery. The command immediately preceding PUBLISH now fails closed before
// the side-effecting command is issued.
const REDIS_CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
const REDIS_IO_TIMEOUT: Duration = Duration::from_millis(500);
const CLUSTER_REDIS_POOL_MAX_SIZE: u32 = 16;
const DELIVERY_ACK_TIMEOUT: Duration = Duration::from_secs(2);
// This is the per-resource C2S ownership wait for the older exact-resource
// delivery path. MIX uses a typed durable hand-off below instead: it waits for
// an actual socket/SM/BOSH boundary and closes the one route if its caller is
// cancelled, rather than declaring ownership after this timer elapses.
const DELIVERY_TRANSPORT_RECEIPT_TIMEOUT: Duration = Duration::from_millis(500);
const MIX_CLUSTER_HANDOFF_TTL_SECONDS: u64 = 30;
const MAX_DELIVERY_ACK_BYTES: usize = 4096;
const MAX_CLUSTER_PAYLOAD_BYTES: usize = 2 * 1024 * 1024;
const MAX_DELIVERY_EXCLUSIONS: usize = 16;
const MAX_PENDING_CLUSTER_ACKS: usize = 4096;
const MAX_LISTENER_CONTINUATIONS: usize = 16;
const MUC_OUTBOX_MAX_BATCHES_PER_PASS: usize = 4;
const MUC_OUTBOX_BATCH_SIZE: i64 = 16;
const MUC_OUTBOX_PASS_BUDGET: Duration = Duration::from_secs(20);
const MUC_OUTBOX_DELIVERY_BUDGET: Duration = Duration::from_secs(5);
const CLUSTER_MAINTENANCE_BUDGET: Duration = Duration::from_secs(25);
const NODE_PROTOCOL_VERSION: &str = "13";
const DELIVERY_CONTRACT_PROTOCOL_VERSION: u16 = 13;
// Version 8 introduced the explicit volatile/durable delivery contract.
// Versions 9 through 13 retain that wire meaning while adding independent
// signed envelope, presence-authority, MIX-capability, and MIX transport
// receipt requirements. Version 13 adds an exact leased MIX source; it must
// never fall back to the version-7 stanza-id inference rules during a rolling
// upgrade.
const DELIVERY_CONTRACT_PROTOCOL_MIN: u16 = 8;
const PRESENCE_AUTHORITY_VERSION: u16 = 1;
const LEGACY_DELIVERY_PROTOCOL_MAX: u16 = 7;
#[cfg(test)]
const MAX_REPLAY_ENTRIES: usize = 65_536;

pub(crate) use northstar_message_core::{DirectPostCommitMode, DirectSpoolEligibility};

#[derive(Clone)]
pub struct ClusterManager {
    pub node_id: String,
    namespace: String,
    key_prefix: String,
    pool: Option<Pool<RedisConnectionManager>>,
    client: Option<redis::Client>,
    security: Option<Arc<crate::security::cluster_bus::ClusterSecurityConfig>>,
    connection_uuid: uuid::Uuid,
    instance_epoch: Arc<AtomicI64>,
    authorized_instances: Arc<dashmap::DashMap<String, AuthorizedClusterInstance>>,
    authorized_peer_keys: Arc<dashmap::DashMap<String, AuthorizedPeerKeys>>,
    #[cfg(test)]
    replay_cache: Arc<dashmap::DashMap<String, i64>>,
    #[cfg(test)]
    replay_cache_gate: Arc<Mutex<()>>,
    #[cfg(test)]
    replay_cache_next_expiry: Arc<AtomicI64>,
    #[cfg(test)]
    replay_cache_sweeps: Arc<AtomicU64>,
    authority_pool: Arc<std::sync::OnceLock<sqlx::PgPool>>,
    health: Arc<ClusterHealth>,
    publication_gate: Arc<tokio::sync::RwLock<()>>,
    muc_outbox_notify: Arc<tokio::sync::Notify>,
    account_revocation_notify: Arc<tokio::sync::Notify>,
    direct_spool_notify: Arc<tokio::sync::Notify>,
    listener_rotation: Arc<tokio::sync::Notify>,
    pending_ack_slots: Arc<tokio::sync::Semaphore>,
    pending_acks: Arc<dashmap::DashMap<String, PendingClusterAck>>,
}

impl ClusterManager {
    pub async fn new(
        redis_url: Option<&str>,
        namespace: &str,
        tls_ca_cert_path: Option<&std::path::Path>,
        tls_client_cert_path: Option<&std::path::Path>,
        tls_client_key_path: Option<&std::path::Path>,
        security: Option<Arc<crate::security::cluster_bus::ClusterSecurityConfig>>,
    ) -> Result<Self> {
        let namespace = crate::jid::prepare_domainpart(namespace)
            .context("cluster namespace must be a valid XMPP domain")?;
        let key_prefix = format!("northstar:{namespace}");
        let Some(redis_url) = redis_url else {
            anyhow::ensure!(
                security.is_none(),
                "cluster security configuration cannot be enabled without Redis"
            );
            let node_id = uuid::Uuid::new_v4().to_string();
            tracing::info!("Redis is not configured; running in supported single-node mode");
            return Ok(Self {
                node_id,
                namespace,
                key_prefix,
                pool: None,
                client: None,
                security: None,
                connection_uuid: uuid::Uuid::new_v4(),
                instance_epoch: Arc::new(AtomicI64::new(0)),
                authorized_instances: Arc::new(dashmap::DashMap::new()),
                authorized_peer_keys: Arc::new(dashmap::DashMap::new()),
                #[cfg(test)]
                replay_cache: Arc::new(dashmap::DashMap::new()),
                #[cfg(test)]
                replay_cache_gate: Arc::new(Mutex::new(())),
                #[cfg(test)]
                replay_cache_next_expiry: Arc::new(AtomicI64::new(i64::MAX)),
                #[cfg(test)]
                replay_cache_sweeps: Arc::new(AtomicU64::new(0)),
                authority_pool: Arc::new(std::sync::OnceLock::new()),
                health: Arc::new(ClusterHealth::disabled()),
                publication_gate: Arc::new(tokio::sync::RwLock::new(())),
                muc_outbox_notify: Arc::new(tokio::sync::Notify::new()),
                account_revocation_notify: Arc::new(tokio::sync::Notify::new()),
                direct_spool_notify: Arc::new(tokio::sync::Notify::new()),
                listener_rotation: Arc::new(tokio::sync::Notify::new()),
                pending_ack_slots: Arc::new(tokio::sync::Semaphore::new(MAX_PENDING_CLUSTER_ACKS)),
                pending_acks: Arc::new(dashmap::DashMap::new()),
            });
        };
        let security = security
            .context("Redis cluster mode requires Ed25519 signing identity and peer allowlist")?;
        let node_id = security.node_id.clone();

        let tls_files_configured = tls_ca_cert_path.is_some() || tls_client_cert_path.is_some();
        let client = if tls_files_configured {
            let root_cert = tls_ca_cert_path
                .map(|path| {
                    crate::platform::config::read_secret_file(path, "REDIS_TLS_CA_CERT_PATH")
                })
                .transpose()?
                .map(String::into_bytes);
            let client_tls = match (tls_client_cert_path, tls_client_key_path) {
                (Some(cert), Some(key)) => Some(redis::ClientTlsConfig {
                    client_cert: crate::platform::config::read_secret_file(
                        cert,
                        "REDIS_TLS_CLIENT_CERT_PATH",
                    )?
                    .into_bytes(),
                    client_key: crate::platform::config::read_secret_file(
                        key,
                        "REDIS_TLS_CLIENT_KEY_PATH",
                    )?
                    .into_bytes(),
                }),
                (None, None) => None,
                _ => anyhow::bail!(
                    "Redis TLS client certificate and key must be configured together"
                ),
            };
            redis::Client::build_with_tls(
                redis_url,
                redis::TlsCertificates {
                    client_tls,
                    root_cert,
                },
            )?
        } else {
            redis::Client::open(redis_url)?
        };
        let manager = RedisConnectionManager {
            client: client.clone(),
        };
        // `bb8` otherwise retries a failed connection acquisition for thirty
        // seconds. That outer retry defeats the per-connection Redis timeout:
        // a stanza can wait through an outage, acquire a connection after
        // recovery, and then be delivered long after the sender's request
        // should have failed closed.
        let pool = cluster_pool_builder().build(manager).await?;
        let cluster = Self {
            node_id,
            namespace,
            key_prefix,
            pool: Some(pool),
            client: Some(client),
            security: Some(security),
            connection_uuid: uuid::Uuid::new_v4(),
            instance_epoch: Arc::new(AtomicI64::new(0)),
            authorized_instances: Arc::new(dashmap::DashMap::new()),
            authorized_peer_keys: Arc::new(dashmap::DashMap::new()),
            #[cfg(test)]
            replay_cache: Arc::new(dashmap::DashMap::new()),
            #[cfg(test)]
            replay_cache_gate: Arc::new(Mutex::new(())),
            #[cfg(test)]
            replay_cache_next_expiry: Arc::new(AtomicI64::new(i64::MAX)),
            #[cfg(test)]
            replay_cache_sweeps: Arc::new(AtomicU64::new(0)),
            authority_pool: Arc::new(std::sync::OnceLock::new()),
            health: Arc::new(ClusterHealth::enabled()),
            publication_gate: Arc::new(tokio::sync::RwLock::new(())),
            muc_outbox_notify: Arc::new(tokio::sync::Notify::new()),
            account_revocation_notify: Arc::new(tokio::sync::Notify::new()),
            direct_spool_notify: Arc::new(tokio::sync::Notify::new()),
            listener_rotation: Arc::new(tokio::sync::Notify::new()),
            pending_ack_slots: Arc::new(tokio::sync::Semaphore::new(MAX_PENDING_CLUSTER_ACKS)),
            pending_acks: Arc::new(dashmap::DashMap::new()),
        };
        tracing::warn!(node_id = %cluster.node_id, "experimental Redis multi-node routing is enabled");
        Ok(cluster)
    }

    pub(crate) fn account_revocation_notify(&self) -> Arc<tokio::sync::Notify> {
        Arc::clone(&self.account_revocation_notify)
    }

    pub(crate) fn direct_spool_notify(&self) -> Arc<tokio::sync::Notify> {
        Arc::clone(&self.direct_spool_notify)
    }

    pub(crate) fn account_revocation_authority(&self) -> ClusterRevocationAuthority {
        ClusterRevocationAuthority {
            domain: self.namespace.clone(),
            node_id: self.node_id.clone(),
            instance_uuid: self.connection_uuid,
            instance_epoch: Arc::clone(&self.instance_epoch),
            notify: Arc::clone(&self.account_revocation_notify),
            enabled: self.is_enabled(),
            failure_policy: self.failure_policy(),
            health: Arc::clone(&self.health),
            listener_rotation: Arc::clone(&self.listener_rotation),
        }
    }

    pub(crate) fn failure_supervisor_authority(&self) -> ClusterFailureSupervisorAuthority {
        ClusterFailureSupervisorAuthority {
            enabled: self.is_enabled(),
            readiness: self.readiness_authority_snapshot(),
            instance_epoch: Arc::clone(&self.instance_epoch),
            domain: self.namespace.clone(),
            peer_nodes: self
                .security
                .as_ref()
                .map_or_else(Vec::new, |security| security.peer_node_ids()),
            expected_peer_keys: self
                .security
                .as_ref()
                .map_or_else(Vec::new, |security| security.peer_key_authorities()),
            authorized_peer_keys: Arc::clone(&self.authorized_peer_keys),
            authorized_instances: Arc::clone(&self.authorized_instances),
            health: Arc::clone(&self.health),
            listener_rotation: Arc::clone(&self.listener_rotation),
            failure_policy: self.failure_policy(),
            safety_lease_seconds: self
                .security
                .as_ref()
                .map(|security| security.safety_lease_seconds),
        }
    }

    pub(crate) fn maintenance_control(&self) -> ClusterMaintenanceControl {
        ClusterMaintenanceControl {
            node_id: self.node_id.clone(),
            enabled: self.is_enabled(),
            peer_authority: self.failure_supervisor_authority(),
            health: Arc::clone(&self.health),
            listener_rotation: Arc::clone(&self.listener_rotation),
            direct_spool_notify: Arc::clone(&self.direct_spool_notify),
            failure_policy: self.failure_policy(),
        }
    }

    pub(crate) fn maintenance_redis(&self) -> ClusterMaintenanceRedis {
        ClusterMaintenanceRedis {
            pool: self.pool.clone(),
            authority_pool: Arc::clone(&self.authority_pool),
            namespace: self.namespace.clone(),
            key_prefix: self.key_prefix.clone(),
            node_id: self.node_id.clone(),
            connection_uuid: self.connection_uuid,
            instance_epoch: Arc::clone(&self.instance_epoch),
            peer_nodes: self
                .security
                .as_ref()
                .map_or_else(Vec::new, |security| security.peer_node_ids()),
            health: Arc::clone(&self.health),
        }
    }

    pub(crate) fn muc_outbox_signal(&self) -> ClusterMucOutboxSignal {
        ClusterMucOutboxSignal {
            node_id: self.node_id.clone(),
            wake: Arc::clone(&self.muc_outbox_notify),
        }
    }

    fn signed_publisher(&self) -> ClusterSignedPublisher {
        ClusterSignedPublisher {
            pool: self.pool.clone(),
            namespace: self.namespace.clone(),
            key_prefix: self.key_prefix.clone(),
            node_id: self.node_id.clone(),
            security: self.security.clone(),
            connection_uuid: self.connection_uuid,
            instance_epoch: Arc::clone(&self.instance_epoch),
            authorized_instances: Arc::clone(&self.authorized_instances),
            health: Arc::clone(&self.health),
            listener_rotation: Arc::clone(&self.listener_rotation),
            failure_policy: self.failure_policy(),
            publication_gate: Arc::clone(&self.publication_gate),
        }
    }

    fn correlated_control_sender(&self) -> ClusterCorrelatedControlSender {
        ClusterCorrelatedControlSender {
            publisher: self.signed_publisher(),
            transport_ready: self.client.is_some(),
            pending_ack_slots: Arc::clone(&self.pending_ack_slots),
            pending_acks: Arc::clone(&self.pending_acks),
        }
    }

    pub(crate) fn node_delivery(&self) -> ClusterNodeDelivery {
        ClusterNodeDelivery {
            publisher: self.signed_publisher(),
            pool: self.pool.clone(),
            client: self.client.clone(),
            health: Arc::clone(&self.health),
            pending_ack_slots: Arc::clone(&self.pending_ack_slots),
            pending_acks: Arc::clone(&self.pending_acks),
        }
    }

    pub(crate) fn unavailable_delivery(&self) -> ClusterUnavailableDelivery {
        ClusterUnavailableDelivery {
            routes: self.listener_presence_routes(),
            sender: self.node_delivery(),
        }
    }

    pub(crate) fn account_teardown_notifier(&self) -> ClusterAccountTeardownNotifier {
        ClusterAccountTeardownNotifier {
            routes: self.listener_presence_routes(),
            sender: self.correlated_control_sender(),
        }
    }

    pub(crate) fn sm_session_teardown_notifier(&self) -> ClusterSmSessionTeardownNotifier {
        ClusterSmSessionTeardownNotifier {
            routes: self.listener_presence_routes(),
            sender: self.correlated_control_sender(),
        }
    }

    pub(crate) fn sm_muc_teardown(&self) -> ClusterSmMucTeardown {
        ClusterSmMucTeardown {
            sender: self.correlated_control_sender(),
        }
    }

    pub(crate) fn sm_suspension(&self) -> ClusterSmSuspension {
        ClusterSmSuspension {
            publisher: self.signed_publisher(),
            muc_outbox_notify: Arc::clone(&self.muc_outbox_notify),
        }
    }

    pub(crate) fn muc_operation_wake(&self) -> ClusterMucOperationWake {
        ClusterMucOperationWake {
            publisher: self.signed_publisher(),
            muc_outbox_notify: Arc::clone(&self.muc_outbox_notify),
        }
    }

    pub(crate) fn listener_presence_routes(&self) -> ClusterListenerPresenceRoutes {
        ClusterListenerPresenceRoutes {
            authority_pool: Arc::clone(&self.authority_pool),
            namespace: self.namespace.clone(),
            node_id: self.node_id.clone(),
            enabled: self.pool.is_some(),
        }
    }

    pub(crate) fn mix_route_lookup(&self) -> ClusterMixRouteLookup {
        ClusterMixRouteLookup {
            routes: self.listener_presence_routes(),
        }
    }

    pub(crate) fn listener_muc_projection(&self) -> ClusterListenerMucProjection {
        ClusterListenerMucProjection {
            pool: self.pool.clone(),
            key_prefix: self.key_prefix.clone(),
            node_id: self.node_id.clone(),
        }
    }

    pub(crate) fn sm_muc_teardown_projection(&self) -> ClusterSmMucTeardownProjection {
        ClusterSmMucTeardownProjection {
            pool: self.pool.clone(),
            key_prefix: self.key_prefix.clone(),
            node_id: self.node_id.clone(),
            connection_uuid: self.connection_uuid,
            instance_epoch: Arc::clone(&self.instance_epoch),
        }
    }

    pub(crate) fn muc_departure(&self) -> ClusterMucDeparture {
        ClusterMucDeparture {
            projection: self.sm_muc_teardown_projection(),
            publisher: self.signed_publisher(),
        }
    }

    pub(crate) fn session_termination_identity(&self) -> ClusterSessionTerminationIdentity {
        ClusterSessionTerminationIdentity {
            namespace: self.namespace.clone(),
            node_id: self.node_id.clone(),
            instance_uuid: self.connection_uuid,
            instance_epoch: Arc::clone(&self.instance_epoch),
        }
    }

    pub(crate) fn session_route_release(&self) -> ClusterSessionRouteRelease {
        ClusterSessionRouteRelease {
            pool: self.pool.clone(),
            authority_pool: Arc::clone(&self.authority_pool),
            namespace: self.namespace.clone(),
            key_prefix: self.key_prefix.clone(),
            node_id: self.node_id.clone(),
            connection_uuid: self.connection_uuid,
            instance_epoch: Arc::clone(&self.instance_epoch),
        }
    }

    pub(crate) fn pubsub_listener_transport(&self) -> ClusterPubsubListenerTransport {
        ClusterPubsubListenerTransport {
            client: self.client.clone(),
            pool: self.pool.clone(),
            key_prefix: self.key_prefix.clone(),
            node_id: self.node_id.clone(),
            connection_uuid: self.connection_uuid,
            instance_epoch: Arc::clone(&self.instance_epoch),
            health: Arc::clone(&self.health),
            listener_rotation: Arc::clone(&self.listener_rotation),
            failure_policy: self.failure_policy(),
        }
    }

    pub(crate) fn listener_admission(&self) -> ClusterListenerAdmission {
        ClusterListenerAdmission {
            health: Arc::clone(&self.health),
            pending_acks: Arc::clone(&self.pending_acks),
        }
    }

    pub(crate) fn listener_security(&self) -> ClusterListenerSecurity {
        ClusterListenerSecurity {
            publisher: self.signed_publisher(),
            authorized_peer_keys: Arc::clone(&self.authorized_peer_keys),
            authority_pool: Arc::clone(&self.authority_pool),
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.pool.is_some()
    }

    pub fn configure_authority_pool(&self, pool: &sqlx::PgPool) -> Result<()> {
        self.authority_pool
            .set(pool.clone())
            .map_err(|_| anyhow::anyhow!("cluster PostgreSQL authority pool was configured twice"))
    }
}

pub fn start_muc_outbox_delivery(state: Arc<AppState>, cancel: CancellationToken) {
    // The PostgreSQL maintenance half also runs in supported single-node
    // mode: lifecycle tombstones/operation IDs are still recorded there and
    // must obey the same bounded retention. With clustering disabled there
    // are no cross-node audience rows and no signing key is required.
    let worker_registry = Arc::clone(state.worker_registry());
    let context = Arc::new(state.cluster_muc_outbox_worker_context());
    worker_registry.supervise(
        "cluster-muc-outbox",
        crate::platform::workers::WorkerCriticality::Restartable,
        crate::platform::workers::WorkerMode::Continuous,
        Some(Duration::from_secs(30)),
        cancel.clone(),
        move |heartbeat| {
            let context = Arc::clone(&context);
            let cancel = cancel.clone();
            async move { run_muc_outbox_delivery(context, cancel, heartbeat).await }
        },
    );
}

#[cfg(test)]
mod listener_continuation_tests;

#[cfg(test)]
mod muc_routing_tests;

#[cfg(test)]
mod tests;

#[cfg(test)]
mod direct_admission_tests;
