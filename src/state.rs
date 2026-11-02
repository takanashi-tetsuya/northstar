pub(crate) mod account_admin;
// The composition root binds transport service handles to concrete adapters.
pub(crate) type BoshReplayService = northstar_session_application::replay::ReplayService<
    northstar_session_postgres::replay_repository::PostgresReplayRepository,
>;
pub(crate) type BoshMixService = northstar_room_application::mix_service::MixService<
    northstar_workflows::room_effects::PostgresMixRepository,
>;

impl axum::extract::FromRef<Arc<AppState>> for AccountAdminContext {
    fn from_ref(state: &Arc<AppState>) -> Self {
        state.auth.account_admin_service.clone()
    }
}
impl axum::extract::FromRef<Arc<AppState>> for RegistrationAdminContext {
    fn from_ref(state: &Arc<AppState>) -> Self {
        state.auth.registration_admin_service.clone()
    }
}
impl axum::extract::FromRef<Arc<AppState>> for SessionAdminContext {
    fn from_ref(state: &Arc<AppState>) -> Self {
        state.auth.session_admin_service.clone()
    }
}

impl axum::extract::FromRef<Arc<AppState>> for AdminDispatchContext {
    fn from_ref(state: &Arc<AppState>) -> Self {
        state.operations.admin_dispatch_service.clone()
    }
}
impl axum::extract::FromRef<Arc<AppState>> for PublicDiscoveryContext {
    fn from_ref(state: &Arc<AppState>) -> Self {
        state.public_discovery_context.clone()
    }
}

pub(crate) mod capacity_maintenance;
pub(crate) type CapacityLeaseRenewalContext = capacity_maintenance::CapacityLeaseRenewalContext<
    northstar_session_postgres::capacity_maintenance_repository::PostgresCapacityMaintenanceRepository,
>;
pub(crate) type CapacityLeaseReaperContext = capacity_maintenance::CapacityLeaseReaperContext<
    northstar_session_postgres::capacity_maintenance_repository::PostgresCapacityMaintenanceRepository,
>;

impl axum::extract::FromRef<Arc<AppState>> for InvitationAdminContext {
    fn from_ref(state: &Arc<AppState>) -> Self {
        state.auth.invitation_admin_service.clone()
    }
}

impl axum::extract::FromRef<Arc<AppState>> for GovernanceContext {
    fn from_ref(state: &Arc<AppState>) -> Self {
        state.operations.governance_context.clone()
    }
}

impl axum::extract::FromRef<Arc<AppState>> for RetentionPolicyContext {
    fn from_ref(state: &Arc<AppState>) -> Self {
        state.operations.retention_policy_context.clone()
    }
}

impl axum::extract::FromRef<Arc<AppState>> for ReportModerationContext {
    fn from_ref(state: &Arc<AppState>) -> Self {
        state.operations.report_moderation_service.clone()
    }
}

impl axum::extract::FromRef<Arc<AppState>> for UploadAdminContext {
    fn from_ref(state: &Arc<AppState>) -> Self {
        state.operations.upload_admin_service.clone()
    }
}

impl axum::extract::FromRef<Arc<AppState>> for OperationAdminContext {
    fn from_ref(state: &Arc<AppState>) -> Self {
        state.operations.operation_admin_service.clone()
    }
}

impl axum::extract::FromRef<Arc<AppState>> for ReportContext {
    fn from_ref(state: &Arc<AppState>) -> Self {
        reports::ReportContext::new(
            state.report_service().clone(),
            state.api_query_service().clone(),
            Arc::clone(&state.metrics),
            state.config.trusted_proxy_ips.clone(),
        )
    }
}
pub(crate) mod account_deletion_recovery;
pub(crate) mod account_generation_teardown;
pub(crate) mod account_recovery;
mod api_query_presence;
mod metrics_context;
mod push_notification_delivery;
mod rest_endpoint_contexts;
pub(crate) use account_deletion_recovery::AccountDeletionRecoveryContext;
pub(crate) mod account_teardown_runtime;
mod admin_session_cleanup;
pub(crate) mod background_maintenance;
pub(crate) mod caps_effect_dispatch;
pub(crate) mod pep_last_items;
pub(crate) use admin_session_cleanup::AdminSessionCleanupContext;
mod admin_cluster_queries;
pub(crate) mod cluster_adapters;
pub(crate) mod cluster_direct_commit;
pub(crate) mod cluster_failure_supervisor;
mod cluster_listener;
pub(crate) mod cluster_listener_blocking;
pub(crate) mod cluster_listener_dispatch;
pub(crate) mod cluster_listener_message;
pub(crate) mod cluster_listener_mix_caps;
pub(crate) mod cluster_listener_sm_muc_teardown;
pub(crate) mod cluster_maintenance;
pub(crate) mod cluster_maintenance_context;
pub(crate) mod cluster_muc_delivery_endpoints;
pub(crate) mod cluster_muc_outbox_worker;
pub(crate) mod cluster_muc_projection;
pub(crate) mod cluster_recovery_replay;
pub(crate) mod cluster_routing;
mod cluster_shutdown;
mod cluster_teardown;
pub(crate) mod direct_spool_wake;
pub(crate) mod federated_muc_cluster_effects;
mod locked_muc_expiry;
mod message_carbon_delivery;
mod message_cluster_routing;
mod message_host;
pub(crate) mod mix_iq_relay;
pub(crate) mod mix_outbox;
pub(crate) mod mix_presence_recovery;
pub(crate) mod muc_cluster_effects;
pub(crate) mod muc_cluster_routing;
pub(crate) mod muc_delivery;
mod muc_host;
pub(crate) mod operation_island_effects;
pub(crate) mod operation_muc_destroy_effects;
pub(crate) mod operation_panic_effects;
pub(crate) use operation_island_effects::OperationIslandEffects;
pub(crate) use operation_muc_destroy_effects::OperationMucDestroyEffects;
pub(crate) use operation_panic_effects::OperationPanicEffects;
pub(crate) mod operation_session_effects;
pub(crate) use operation_session_effects::OperationSessionEffects;
pub(crate) use operation_tls_reload_effects::OperationTlsReloadEffects;
pub(crate) mod operation_tls_reload_effects;
mod operation_worker_control;
pub(crate) use operation_worker_control::OperationWorkerControl;
mod presence_cluster_routing;
pub(crate) mod pubsub_digest_worker;
pub(crate) mod pubsub_event_outbox_worker;
pub(crate) mod pubsub_notification_delivery;
mod remote_route;
mod runtime_control_refresh;
mod s2s_cluster_routing;
pub(crate) mod s2s_direct_route;
pub(crate) mod s2s_outbox_dispatch;
pub(crate) mod session_cleanup;
pub(crate) mod session_cleanup_bookkeeping;
pub(crate) mod session_cleanup_local;
pub(crate) mod session_cleanup_mix;
pub(crate) mod session_cleanup_muc_departure;
pub(crate) mod session_cleanup_presence;
pub(crate) mod session_cleanup_rooms;
pub(crate) mod session_cleanup_sm;
pub(crate) mod session_cleanup_sm_revoker;
pub(crate) mod session_cleanup_unavailable;
mod session_cluster_route;
mod sm_expiry;
mod sm_teardown_local;
mod sm_teardown_muc_projection;
pub(crate) mod sm_teardown_runtime;
mod sm_teardown_session;
pub(crate) mod standalone_muc_maintenance;
pub(crate) mod suspension;

impl axum::extract::FromRef<Arc<AppState>> for ApiQueryContext {
    fn from_ref(state: &Arc<AppState>) -> Self {
        state.api_query_context()
    }
}

use crate::api::contexts::{
    api_queries, governance, http_body_admission, http_policy, omemo_poll, reports,
    retention_policy, AccountAdminContext, AdminDispatchContext, AdminGatewayVerifier,
    ApiQueryContext, GovernanceContext, HttpTransportPolicy, InvitationAdminContext,
    OmemoRecoveryPollContext, OperationAdminContext, PasskeyService, PublicDiscoveryContext,
    RegistrationAdminContext, ReportContext, ReportModerationContext, RetentionPolicyContext,
    SessionAdminContext, UploadAdminContext, UploadService,
};
use crate::s2s::FederationRouter;
use anyhow::Context;
use dashmap::DashMap;
use hickory_resolver::{
    config::{ResolveHosts, ServerOrderingStrategy},
    net::runtime::TokioRuntimeProvider,
    system_conf::read_system_conf,
    TokioResolver,
};
use northstar_abuse_application::guard::AbuseGuard;
use northstar_abuse_policy::AbuseConfig;
use northstar_config::{
    AdminCommandPoolMode, Config, StoragePoolMode, OMEMO_RECOVERY_POOL_MAX_CONNECTIONS,
    SERVICE_CONTROL_POOL_MAX_CONNECTIONS, STORAGE_POOL_MAX_CONNECTIONS,
};
use northstar_telemetry::metrics::Metrics;
use northstar_upload_application::safety::UploadSafetyGate;
use northstar_upload_application::store::{GuardedUploadStore, UploadStore};
use northstar_upload_application::UploadAuthorityGeneration;
use northstar_upload_storage::{LocalUploadStore, S3UploadSettings, S3UploadStore};
use sqlx::{
    pool::PoolConnection,
    postgres::{PgConnectOptions, PgPoolOptions},
    PgPool, Postgres,
};
use std::{
    collections::HashSet,
    sync::{
        atomic::{AtomicBool, AtomicU8, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};
use tokio::sync::OwnedSemaphorePermit;
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;
use zeroize::{Zeroize, Zeroizing};

mod abuse_module;
mod admission_guards;
mod auth_module;
mod construction;
mod federation_dns;
mod federation_module;
mod federation_policy;
mod local_muc;
mod local_session;
mod message_module;
mod muc_resume;
mod operations_module;
mod pubsub_module;
mod room_module;
mod roster_module;
mod runtime_config;
mod runtime_contexts;
mod runtime_control;
mod service_accessors;
mod session_module;
mod suspended_muc;
mod telemetry_accessors;
mod upload_module;

use self::abuse_module::*;
pub use self::admission_guards::*;
use self::auth_module::*;
#[cfg(test)]
use self::construction::*;
use self::federation_module::*;
use self::federation_policy::*;
#[cfg(test)]
pub(crate) use self::local_muc::count_shutdown_notification_completions;
use self::message_module::*;
use self::operations_module::*;
use self::pubsub_module::*;
use self::room_module::*;
use self::roster_module::*;
pub(crate) use self::runtime_config::*;
pub(crate) use self::runtime_control::*;
use self::session_module::*;
use self::upload_module::*;
use northstar_federation_application::registry::S2sConnectionRegistry;
use northstar_federation_application::write_policy::FederationWritePolicy;
use northstar_federation_core::policy::RuntimeFederationPolicy;
use northstar_room_application::muc_service::{LocalMucOccupantIdentity, SerializableMucOccupant};
use northstar_room_core::occupancy::{LocalMucJoinPublication, LocalMucNicknameMove};
use northstar_stream::local_routes::muc::{
    MucOccupant, MucOccupantEndpoint, RestoreLocalMucOccupantsRequest, SuspendedMucEndpoint,
    SuspendedMucPhase, SuspendedMucRoute,
};
use northstar_stream::local_routes::muc_table::*;
use northstar_stream::local_routes::session::{
    AccountRevocationRoutes, OnlineSession, SmPresenceEpoch, SmStagedRouteClaim,
};
use northstar_stream::local_routes::session_table::*;
use northstar_stream::local_routes::suspended_muc::*;
use northstar_xml_builder::escape::attr_escape;
use northstar_xmpp_types::jid_text::*;

#[cfg(test)]
#[path = "state/runtime_control_startup_tests.rs"]
mod runtime_control_startup_tests;

#[cfg(test)]
#[path = "state/runtime_control_health_tests.rs"]
mod runtime_control_health_tests;

#[allow(unused_imports)]
pub use northstar_protocol_runtime::caps::CapsKey;

pub use northstar_session_core::LocalCapsEpoch;

pub use northstar_session_core::JoinedMucMembership;

#[cfg(test)]
mod muc_membership_snapshot_tests;

type RosterService = northstar_roster_application::RosterService<
    northstar_workflows::roster::PostgresRosterRepository,
>;

#[cfg(test)]
#[path = "state/account_revocation_route_tests.rs"]
mod account_revocation_route_tests;

pub struct AppState {
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
    /// XEP-0215 TURN credential authority. Long-lived key material and its
    /// bounded rate windows never cross into protocol or public state.
    mam_service: northstar_archive_application::MamService<northstar_workflows::mam_repository::PostgresMamRepository>,
    http_body_admission: Arc<http_body_admission::HttpBodyAdmission>,
    cluster: crate::cluster::ClusterManager,
    account_revocation_consumer_service:
        northstar_auth_application::account_revocation_consumer::AccountRevocationConsumerService<
            northstar_auth_postgres::account_revocation_repository::PostgresAccountRevocationRepository,
        >,
    bosh: Option<crate::bosh::BoshManager>,
    sessions: Arc<DashMap<String, OnlineSession>>,
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
    client_connections: Arc<Semaphore>,
    client_connections_by_ip: DashMap<std::net::IpAddr, usize>,
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
    registration_closed: Arc<AtomicBool>,
    service_shutdown: Arc<std::sync::OnceLock<CancellationToken>>,
    runtime_control_liveness: Arc<()>,
    workers: Arc<northstar_runtime::workers::WorkerRegistry>,
}

impl AppState {
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
                async move { locked_muc_expiry::run_locked_muc_expiry(weak, heartbeat).await }
            },
        );
    }

    fn start_runtime_control_refresh(
        state: Arc<Self>,
        connection: PoolConnection<Postgres>,
        cancel: CancellationToken,
    ) {
        let context = Arc::new(
            runtime_control_refresh::RuntimeControlRefreshContext::from_state(&state, connection),
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
#[path = "state/session_key_tests.rs"]
mod session_key_tests;

#[cfg(test)]
mod route_helper_tests;
