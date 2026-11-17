pub(crate) mod adapters;
pub(crate) mod hosts;
pub(crate) mod modules;

/// The protocol session of the root's own host.
pub(crate) type ClientSession = northstar_stream::protocol::ProtocolSession<ServerNode>;

pub(crate) use adapters::admin_session_cleanup::AdminSessionCleanupContext;
pub(crate) use adapters::operation_muc_destroy_effects::OperationMucDestroyEffects;
pub(crate) use adapters::operation_panic_effects::OperationPanicEffects;
pub(crate) use adapters::operation_session_effects::OperationSessionEffects;
pub(crate) use adapters::operation_worker_control::OperationWorkerControl;

use crate::node::adapters::http_contexts::{
    AccountAdminContext, AdminDispatchContext, ApiQueryContext, GovernanceContext,
    InvitationAdminContext, OmemoRecoveryPollContext, OperationAdminContext, PasskeyService,
    RegistrationAdminContext, ReportModerationContext, RetentionPolicyContext, SessionAdminContext,
    UploadAdminContext, UploadService,
};
use anyhow::Context;
use dashmap::DashMap;
use hickory_resolver::TokioResolver;
use northstar_abuse_application::guard::AbuseGuard;
use northstar_abuse_policy::AbuseConfig;
use northstar_config::{
    AdminCommandPoolMode, Config, StoragePoolMode, OMEMO_RECOVERY_POOL_MAX_CONNECTIONS,
    STORAGE_POOL_MAX_CONNECTIONS,
};
use northstar_http::contexts::{
    api_queries, governance, http_body_admission, http_policy, omemo_poll, retention_policy,
    PublicDiscoveryContext,
};
use northstar_telemetry::metrics::Metrics;
use northstar_upload_application::safety::UploadSafetyGate;
use northstar_upload_application::store::{GuardedUploadStore, UploadStore};
use northstar_upload_application::UploadAuthorityGeneration;
use northstar_upload_storage::{LocalUploadStore, S3UploadSettings, S3UploadStore};
use sqlx::{pool::PoolConnection, postgres::PgConnectOptions, PgPool, Postgres};
#[cfg(test)]
use std::sync::atomic::{AtomicU8, Ordering};
use std::{
    sync::{atomic::AtomicBool, Arc},
    time::{Duration, Instant},
};
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;
use zeroize::{Zeroize, Zeroizing};

mod construction;
pub(crate) use northstar_muc_xmpp::resume::RestoredLocalMucOccupants;
pub(crate) use northstar_stream::local_routes::muc::CommittedLocalMucResume;
mod workers;

#[cfg(test)]
use self::construction::*;
use self::modules::abuse::*;
use self::modules::archive::*;
use self::modules::auth::*;
use self::modules::federation::*;
use self::modules::message::*;
use self::modules::operations::*;
use self::modules::pubsub::*;
use self::modules::room::*;
use self::modules::roster::*;
use self::modules::session::*;
use self::modules::upload::*;
use northstar_federation_application::registry::S2sConnectionRegistry;
use northstar_federation_application::write_policy::FederationWritePolicy;
use northstar_federation_core::policy::RuntimeFederationPolicy;
pub(crate) use northstar_operations_postgres::runtime_control_connection::reserve_runtime_control_connection;
use northstar_room_application::muc_service::{LocalMucOccupantIdentity, SerializableMucOccupant};
#[cfg(test)]
use northstar_room_core::occupancy::{LocalMucJoinPublication, LocalMucNicknameMove};
#[cfg(test)]
use northstar_stream::local_routes::muc::MucOccupantEndpoint;
use northstar_stream::local_routes::muc::{MucOccupant, SuspendedMucEndpoint};
#[cfg(test)]
use northstar_stream::local_routes::muc::{SuspendedMucPhase, SuspendedMucRoute};
use northstar_stream::local_routes::muc_table::*;
#[cfg(test)]
use northstar_stream::local_routes::session::SmStagedRouteClaim;
use northstar_stream::local_routes::session::{AccountRevocationRoutes, OnlineSession};
use northstar_stream::local_routes::session_table::*;
#[cfg(test)]
use northstar_stream::local_routes::suspended_muc::*;

#[allow(unused_imports)]
pub use northstar_protocol_runtime::caps::CapsKey;

pub use northstar_session_core::JoinedMucMembership;

#[cfg(test)]
mod muc_membership_snapshot_tests;

/// Application service backing the private federation outbox capability.
pub(crate) type FederationRouter =
    northstar_federation_application::outbox::FederationOutboxService<
        northstar_federation_postgres::outbox_repository::PostgresFederationOutboxRepository,
    >;

type RosterService = northstar_roster_application::RosterService<
    northstar_workflows::roster::PostgresRosterRepository,
>;

#[cfg(test)]
#[path = "node/account_revocation_route_tests.rs"]
mod account_revocation_route_tests;

pub struct ServerNode {
    config: Config,
    pool: PgPool,
    /// The upload context; see [`UploadModule`].
    upload: UploadModule,
    /// The pubsub context; see [`PubSubModule`].
    pubsub: PubSubModule,
    /// The room context; see [`RoomModule`].
    room: RoomModule,
    /// The roster context; see [`RosterModule`].
    roster: RosterModule,
    /// The message context; see [`MessageModule`].
    message: MessageModule,
    /// The federation context; see [`FederationModule`].
    federation: FederationModule,
    /// The session context; see [`SessionModule`].
    session: SessionModule,
    public_discovery_context: PublicDiscoveryContext,
    /// The archive context; see [`ArchiveModule`].
    archive: ArchiveModule,
    http_body_admission: Arc<http_body_admission::HttpBodyAdmission>,
    cluster: northstar_cluster::ClusterManager,
    bosh: Option<northstar_bosh::BoshManager>,
    sessions: LocalSessionTable,
    metrics: Arc<Metrics>,
    /// Optional credential for the dedicated observability listener. Callers
    /// can ask for an authorization decision but cannot read the token.
    metrics_bearer_token: Option<Arc<Zeroizing<String>>>,
    /// Reverse-proxy credential for the isolated administration origin. The
    /// API can ask for a constant-time decision but cannot read key bytes.
    web_admin_gateway_token: Option<Arc<Zeroizing<String>>>,
    /// Clone-shared permission for short MIX, PubSub and clustered-MUC
    /// durable-outbox database turns. It preserves a primary-pool foreground
    /// reserve without giving protocol handlers raw pool access.
    durable_outbox_database_admission:
        northstar_runtime::durable_outbox::DurableOutboxDatabaseAdmission,
    /// XEP-0115 entries are inserted only after the advertised verification
    /// string has been recomputed successfully. Unverified payloads never
    /// enter this shared cache.
    caps_cache: Arc<northstar_protocol_runtime::caps::CapsCacheIndex>,
    caps_by_jid: Arc<northstar_protocol_runtime::caps::CapsResourceIndex>,
    pending_caps: Arc<northstar_protocol_runtime::caps::PendingCapsIndex>,
    /// Cross-stream ordering authority for one authenticated federated full
    /// JID's capability lifecycle. Weak, self-cleaning entries exist only
    /// while an observer or response owns or waits for the resource.
    federated_caps_gates: Arc<northstar_protocol_runtime::caps::FederatedCapsGateIndex>,
    /// Bounded, per-full-JID single-flight boundary for XEP-0115-triggered
    /// PEP last-item delivery and verified MIX presence publication.
    caps_effect_dispatcher: Arc<northstar_protocol_runtime::caps::CapsEffectDispatcher>,
    /// Shared client connection admission authority.
    client_admission: Arc<northstar_stream::client_admission::ClientAdmission>,
    connection_actors: northstar_runtime::connection_actors::ConnectionActorRegistry,
    /// The auth context; see [`AuthModule`].
    auth: AuthModule,
    /// The operations context; see [`OperationsModule`].
    operations: OperationsModule,
    /// The anti-abuse context; see [`AbuseModule`].
    abuse: AbuseModule,
    started_at: Instant,
    process_started_at: chrono::DateTime<chrono::Utc>,
    tls_context: northstar_security::tls::TlsContext,
    service_shutdown: Arc<std::sync::OnceLock<CancellationToken>>,
    runtime_control_liveness: Arc<()>,
    workers: Arc<northstar_runtime::workers::WorkerRegistry>,
}

impl ServerNode {
    fn start_locked_muc_expiry(state: Arc<Self>, cancel: CancellationToken) {
        let weak = Arc::downgrade(
            state
                .room
                .locked_muc_expiry_context
                .get()
                .expect("locked MUC expiry context is initialized"),
        );
        state.worker_registry().supervise(
            "locked-muc-expiry",
            northstar_runtime::workers::WorkerCriticality::Restartable,
            northstar_runtime::workers::WorkerMode::Continuous,
            Some(Duration::from_secs(20)),
            cancel,
            move |heartbeat| {
                let weak = weak.clone();
                async move {
                    northstar_muc_xmpp::locked_room_expiry::run_locked_muc_expiry(weak, heartbeat)
                        .await
                }
            },
        );
    }

    fn start_runtime_control_refresh(
        state: Arc<Self>,
        connection: PoolConnection<Postgres>,
        cancel: CancellationToken,
    ) {
        let context = Arc::new(
            adapters::runtime_control_refresh::runtime_control_coordinator(&state, connection),
        );
        let max_silence = Duration::from_secs(5);
        let diagnostic_cancel = cancel.clone();
        state.worker_registry().supervise(
            "runtime-control-refresh",
            northstar_runtime::workers::WorkerCriticality::Critical,
            northstar_runtime::workers::WorkerMode::Continuous,
            Some(max_silence),
            cancel,
            move |heartbeat| {
                let context = Arc::clone(&context);
                let diagnostic_cancel = diagnostic_cancel.clone();
                async move { context.run(heartbeat, diagnostic_cancel, max_silence).await }
            },
        );
    }
}

#[cfg(test)]
#[path = "node/session_key_tests.rs"]
mod session_key_tests;

#[cfg(test)]
mod route_helper_tests;
