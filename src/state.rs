pub(crate) mod account_admin;
// The composition root binds transport service handles to concrete adapters.
pub(crate) type BoshReplayService =
    crate::services::replay::ReplayService<db::replay_repository::PostgresReplayRepository>;
pub(crate) type BoshMixService =
    crate::services::mix::MixService<db::mix_repository::PostgresMixRepository>;

impl axum::extract::FromRef<Arc<AppState>> for AccountAdminContext {
    fn from_ref(state: &Arc<AppState>) -> Self {
        state.account_admin_service.clone()
    }
}
impl axum::extract::FromRef<Arc<AppState>> for RegistrationAdminContext {
    fn from_ref(state: &Arc<AppState>) -> Self {
        state.registration_admin_service.clone()
    }
}
impl axum::extract::FromRef<Arc<AppState>> for SessionAdminContext {
    fn from_ref(state: &Arc<AppState>) -> Self {
        state.session_admin_service.clone()
    }
}

impl axum::extract::FromRef<Arc<AppState>> for AdminDispatchContext {
    fn from_ref(state: &Arc<AppState>) -> Self {
        state.admin_dispatch_service.clone()
    }
}
impl axum::extract::FromRef<Arc<AppState>> for PublicDiscoveryContext {
    fn from_ref(state: &Arc<AppState>) -> Self {
        state.public_discovery_context.clone()
    }
}

pub(crate) mod capacity_maintenance;
pub(crate) type CapacityLeaseRenewalContext = capacity_maintenance::CapacityLeaseRenewalContext<
    db::capacity_maintenance_repository::PostgresCapacityMaintenanceRepository,
>;
pub(crate) type CapacityLeaseReaperContext = capacity_maintenance::CapacityLeaseReaperContext<
    db::capacity_maintenance_repository::PostgresCapacityMaintenanceRepository,
>;

impl axum::extract::FromRef<Arc<AppState>> for InvitationAdminContext {
    fn from_ref(state: &Arc<AppState>) -> Self {
        state.invitation_admin_service.clone()
    }
}

impl axum::extract::FromRef<Arc<AppState>> for GovernanceContext {
    fn from_ref(state: &Arc<AppState>) -> Self {
        state.governance_context.clone()
    }
}

impl axum::extract::FromRef<Arc<AppState>> for RetentionPolicyContext {
    fn from_ref(state: &Arc<AppState>) -> Self {
        state.retention_policy_context.clone()
    }
}

impl axum::extract::FromRef<Arc<AppState>> for ReportModerationContext {
    fn from_ref(state: &Arc<AppState>) -> Self {
        state.report_moderation_service.clone()
    }
}

impl axum::extract::FromRef<Arc<AppState>> for UploadAdminContext {
    fn from_ref(state: &Arc<AppState>) -> Self {
        state.upload_admin_service.clone()
    }
}

impl axum::extract::FromRef<Arc<AppState>> for OperationAdminContext {
    fn from_ref(state: &Arc<AppState>) -> Self {
        state.operation_admin_service.clone()
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
pub(crate) mod mix_iq_relay;
pub(crate) mod mix_outbox;
pub(crate) mod mix_presence_recovery;
pub(crate) mod muc_cluster_effects;
pub(crate) mod muc_cluster_routing;
pub(crate) mod muc_delivery;
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
use crate::{
    db,
    s2s::FederationRouter,
    services::abuse::{AbuseConfig, AbuseGuard},
    services::upload_safety::{UploadAuthorityGeneration, UploadSafetyGate},
    storage::{GuardedUploadStore, LocalUploadStore, S3UploadSettings, S3UploadStore, UploadStore},
};
use anyhow::Context;
use dashmap::DashMap;
use hickory_resolver::{
    config::{ResolveHosts, ServerOrderingStrategy},
    net::runtime::TokioRuntimeProvider,
    system_conf::read_system_conf,
    TokioResolver,
};
use northstar_config::{
    AdminCommandPoolMode, Config, StoragePoolMode, OMEMO_RECOVERY_POOL_MAX_CONNECTIONS,
    SERVICE_CONTROL_POOL_MAX_CONNECTIONS, STORAGE_POOL_MAX_CONNECTIONS,
};
use northstar_telemetry::metrics::Metrics;
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
use tokio::sync::RwLock;
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;
use zeroize::{Zeroize, Zeroizing};

mod admission_guards;
mod construction;
mod federation_dns;
mod federation_policy;
mod local_muc;
mod local_session;
mod muc_resume;
mod omemo_poll_admission;
mod runtime_config;
mod runtime_contexts;
mod runtime_control;
mod service_accessors;
mod suspended_muc;
mod telemetry_accessors;
mod upload_runtime;

pub use self::admission_guards::*;
#[cfg(test)]
use self::construction::*;
use self::federation_policy::*;
#[cfg(test)]
pub(crate) use self::local_muc::count_shutdown_notification_completions;
pub(crate) use self::runtime_config::*;
pub(crate) use self::runtime_control::*;
use self::upload_runtime::*;
use crate::services::muc::{LocalMucOccupantIdentity, SerializableMucOccupant};
use crate::xmpp::local_routes::{
    muc::{
        LocalMucJoinPublication, LocalMucNicknameMove, MucOccupant, MucOccupantEndpoint,
        RestoreLocalMucOccupantsRequest, SuspendedMucEndpoint, SuspendedMucPhase,
        SuspendedMucRoute,
    },
    session::{AccountRevocationRoutes, OnlineSession, SmPresenceEpoch, SmStagedRouteClaim},
};
use crate::xmpp::local_routes::{muc_table::*, session_table::*, suspended_muc::*};
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

type RosterService = crate::services::roster::RosterService<db::roster::PostgresRosterRepository>;

#[cfg(test)]
#[path = "state/account_revocation_route_tests.rs"]
mod account_revocation_route_tests;

pub struct AppState {
    config: Config,
    pool: PgPool,
    /// Upload persistence alone owns this pool. Disabled mode has no storage
    /// connection; the loopback development exception reuses `pool`.
    upload_storage_pool: Option<PgPool>,
    api_query_context: ApiQueryContext,
    metrics_snapshot_service: crate::services::metrics_snapshot::MetricsSnapshotService<
        db::metrics_snapshot_repository::PostgresMetricsSnapshotRepository,
    >,
    readiness_service: crate::services::readiness::ReadinessService<
        db::readiness_repository::PostgresReadinessRepository,
    >,
    public_discovery_context: PublicDiscoveryContext,
    passkey_service: Arc<PasskeyService>,
    /// Narrow persistence/orchestration capability for XEP-0060 and PEP.
    /// Protocol handlers receive this service rather than database authority.
    pubsub_service:
        crate::services::pubsub::PubSubService<db::pubsub_repository::PostgresPubSubRepository>,
    /// Account-scoped vCard/vCard4/avatar mutation and public-profile read
    /// boundary. Profile transactions and authorization never cross into the
    /// XMPP protocol layer.
    profile_service:
        crate::services::profile::ProfileService<db::profile::PostgresProfileRepository>,
    /// XEP-0215 TURN credential authority. Long-lived key material and its
    /// bounded rate windows never cross into protocol or public state.
    extdisco_service: crate::services::extdisco::ExtDiscoService,
    /// PostgreSQL-authoritative MUC application service. Redis capabilities
    /// deliberately do not cross this boundary.
    muc_service: crate::services::muc::MucService<db::room::PostgresMucRepository>,
    /// Personal-message authorization and durable admission boundary. The
    /// protocol layer must not compose its own archive/outbox/offline writes.
    message_service:
        crate::services::messaging::MessageService<db::messaging::PostgresMessageRepository>,
    message_admission_service: crate::services::message_admission::MessageAdmissionService<
        db::message_admission_repository::PostgresMessageAdmissionRepository,
    >,
    /// XEP-0424/XEP-0444 tombstone, action archive and federation admission
    /// transaction boundary.
    retraction_service: crate::services::retractions::RetractionService<
        db::retractions::PostgresRetractionRepository,
    >,
    mam_service: crate::services::mam::MamService<db::mam::PostgresMamRepository>,
    mix_service: crate::services::mix::MixService<db::mix_repository::PostgresMixRepository>,
    sm_service: crate::services::sm::SmService<db::sm_repository::PostgresSmRepository>,
    blocking_service:
        crate::services::blocking::BlockingService<db::roster::PostgresBlockingRepository>,
    presence_service: crate::services::presence::PresenceService<
        db::presence_repository::PostgresPresenceRepository,
    >,
    replay_service:
        crate::services::replay::ReplayService<db::replay_repository::PostgresReplayRepository>,
    roster_service: RosterService,
    s2s_roster_authorization_service:
        crate::services::s2s_roster_authorization::FederatedRosterAuthorizationService<
            db::s2s_roster_authorization_repository::PostgresFederatedRosterRepository,
        >,
    s2s_outbox_dispatch_service: crate::services::s2s_outbox_dispatch::S2sOutboxDispatchService<
        db::s2s_outbox_dispatch_repository::PostgresS2sOutboxDispatchRepository,
    >,
    s2s_sm_outbox_service: crate::services::s2s_sm_outbox::SmOutboxService<
        db::s2s_sm_outbox_repository::PostgresSmOutboxRepository,
    >,
    privacy_service:
        crate::services::privacy::PrivacyService<db::privacy::PostgresPrivacyRepository>,
    private_storage_service: crate::services::private_storage::PrivateStorageService<
        db::private::PostgresPrivateStorageRepository,
    >,
    account_service:
        crate::services::account::AccountService<db::account_repository::PostgresAccountRepository>,
    login_service: crate::services::http_login::HttpLoginService<
        db::http_login_repository::PostgresHttpLoginRepository,
    >,
    http_body_admission: Arc<http_body_admission::HttpBodyAdmission>,
    password_change_service: crate::services::password_change::PasswordChangeService<
        db::password_change_repository::PostgresPasswordChangeRepository,
    >,
    /// Credential lookup, verification and XEP-0484 mutation authority. The
    /// protocol layer receives typed outcomes but neither PgPool nor the FAST
    /// derivation key.
    authentication_service: crate::services::authentication::AuthenticationService<
        db::authentication::PostgresAuthenticationRepository,
    >,
    /// XEP-0050/XEP-0133 session and execution authority. Protocol handlers
    /// never receive the backing PostgreSQL pool through this capability.
    admin_command_service: crate::services::admin_commands::AdminCommandService<
        db::admin_command_repository::PostgresAdminCommandRepository,
    >,
    push_service: crate::services::push::PushService<db::push::PostgresPushRepository>,
    cluster: crate::cluster::ClusterManager,
    account_revocation_consumer_service:
        crate::services::account_revocation_consumer::AccountRevocationConsumerService<
            db::account_revocation_repository::PostgresAccountRevocationRepository,
        >,
    bosh: Option<crate::bosh::BoshManager>,
    sessions: Arc<DashMap<String, OnlineSession>>,
    muc_occupants: Arc<DashMap<String, MucOccupant>>,
    /// Exactly one process-local suspension/resume FIFO per durable SM
    /// session.  Every room occupancy for the same client points at this Arc,
    /// preserving cross-room arrival order and enforcing one shared budget.
    suspended_muc_sessions: Arc<DashMap<uuid::Uuid, Arc<SuspendedMucEndpoint>>>,
    /// Supervised retry ownership for an exact SM suspension whose database
    /// outcome was an error or timeout. The corresponding MUC FIFO remains
    /// sealed until this queue proves a durable handoff.
    sm_suspension_recovery: Arc<crate::state::session_cleanup::SmSuspensionRecoveryQueue>,
    sm_memory_governor: Arc<crate::services::sm_capacity::SmMemoryGovernor>,
    metrics: Arc<Metrics>,
    /// Optional credential for the dedicated observability listener. Callers
    /// can ask for an authorization decision but cannot read the token.
    metrics_bearer_token: Option<Arc<Zeroizing<String>>>,
    /// Reverse-proxy credential for the isolated administration origin. The
    /// API can ask for a constant-time decision but cannot read key bytes.
    web_admin_gateway_token: Option<Arc<Zeroizing<String>>>,
    /// A fail-closed, read-only-sized pool for the unauthenticated poll
    /// capability. It cannot consume the primary 32-connection application
    /// pool during a capability flood.
    omemo_recovery_poll_context: OmemoRecoveryPollContext,
    omemo_recovery_service: crate::services::omemo_recovery::OmemoRecoveryService<
        db::omemo_recovery_repository::PostgresOmemoRecoveryRepository,
    >,
    /// Clone-shared permission for short MIX, PubSub and clustered-MUC
    /// durable-outbox database turns. It preserves a primary-pool foreground
    /// reserve without giving protocol handlers raw pool access.
    durable_outbox_database_admission:
        crate::services::durable_outbox::DurableOutboxDatabaseAdmission,
    account_admin_service: AccountAdminContext,
    registration_admin_service: RegistrationAdminContext,
    session_admin_service: SessionAdminContext,
    operation_admin_service: OperationAdminContext,
    operation_muc_destroy_service: Arc<
        crate::services::operation_muc_destroy::MucDestroyService<
            db::operation_muc_destroy_repository::PostgresMucDestroyRepository,
        >,
    >,
    locked_muc_expiry_service: crate::services::locked_muc_expiry::LockedMucExpiryService<
        db::locked_muc_expiry_repository::PostgresLockedMucExpiryRepository,
    >,
    locked_muc_expiry_context: std::sync::OnceLock<Arc<locked_muc_expiry::LockedMucExpiryContext>>,
    operation_effect_fence_service:
        crate::services::operation_effect_fence::OperationEffectFenceService<
            db::operation_effect_fence_repository::PostgresOperationEffectFenceRepository,
        >,
    operation_journal_worker_service:
        crate::services::operation_journal_worker::OperationJournalWorkerService<
            db::operation_journal_worker_repository::PostgresOperationJournalWorkerRepository,
        >,
    admin_session_cleanup_worker_service:
        crate::services::admin_session_cleanup_worker::AdminSessionCleanupWorkerService<
            db::admin_session_cleanup_worker_repository::PostgresAdminSessionCleanupRepository,
        >,
    admin_dispatch_service: AdminDispatchContext,
    upload_admin_service: UploadAdminContext,
    report_moderation_service: ReportModerationContext,
    invitation_admin_service: InvitationAdminContext,
    retention_policy_context: RetentionPolicyContext,
    governance_context: GovernanceContext,
    report_service:
        crate::services::reports::ReportService<db::report_repository::PostgresReportRepository>,
    /// XEP-0363 bearer-token and capacity admission authority. Protocol code
    /// receives typed slot outcomes, never the PostgreSQL pool.
    upload_service: Option<UploadService>,
    upload_store: Option<Arc<dyn UploadStore>>,
    upload_storage_namespace_sha256: [u8; 32],
    upload_authority_generation: UploadAuthorityGeneration,
    upload_safety_gate: Arc<UploadSafetyGate>,
    upload_startup_audits: Arc<crate::runtime::upload_worker::StartupAuditHandoff>,
    federation_outbox: FederationRouter,
    /// Full XEP-0114/XEP-0225 authentication records. `config.components`
    /// retains only redacted routing/discovery metadata after construction.
    component_credentials: Arc<[northstar_config::ComponentCredential]>,
    components: crate::s2s::components::ComponentRegistry,
    s2s_connection_registry: Arc<crate::s2s::S2sConnectionRegistry>,
    /// Shared TTL-aware resolver for SRV, CNAME, A and AAAA federation lookups.
    s2s_dns_resolver: TokioResolver,
    /// Separate locally validating DNSSEC resolver for RFC 7712. It never
    /// consults the hosts file and is absent when DANE is disabled, ensuring
    /// that an ordinary resolver answer can never be mistaken for secure
    /// TLSA material.
    s2s_dnssec_resolver: Option<TokioResolver>,
    /// XEP-0403 IQ relay correlations. Keys are server-generated opaque IQ
    /// ids, never client-controlled ids; entries are bounded and short-lived.
    pending_mix_iq: Arc<northstar_protocol_runtime::mix::MixIqRelayIndex>,
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
    dialback_secret: Zeroizing<Vec<u8>>,
    dialback_verifications: Arc<Semaphore>,
    client_connections: Arc<Semaphore>,
    client_connections_by_ip: DashMap<std::net::IpAddr, usize>,
    /// Capability-owned upload runtime. Disabled mode contains no store,
    /// semaphore, per-IP map or upload-specific numeric state.
    upload_runtime: UploadRuntime,
    /// The unauthenticated OMEMO source completion capability is bounded
    /// independently from the general API and database pool. Keys are trusted-
    /// proxy-resolved IP addresses and expire from the one-minute window.
    s2s_connections: Arc<Semaphore>,
    s2s_connection_attempts: Arc<Semaphore>,
    component_connections: Arc<Semaphore>,
    connection_actors: northstar_runtime::connection_actors::ConnectionActorRegistry,
    challenge_issue_service: crate::services::challenge_issuance::ChallengeIssueService<
        db::challenge_issuance_repository::PostgresChallengeRepository,
    >,
    challenge_cleanup_service: crate::services::challenge_issuance::ChallengeCleanupService<
        db::challenge_issuance_repository::PostgresChallengeRepository,
    >,
    sasl_login_abuse_service: crate::services::login_abuse::SaslLoginAbuseService<
        db::login_abuse_repository::PostgresSaslLoginAbuseRepository,
    >,
    passkey_login_abuse_service: Arc<
        crate::services::login_abuse::PasskeyLoginAbuseService<
            db::login_abuse_repository::PostgresPasskeyLoginAbuseRepository,
        >,
    >,
    /// Public, irreversible key IDs and the configured generation used by the
    /// readiness path to detect a node that drifted from PostgreSQL authority.
    abuse_key_deployment: Option<crate::services::abuse::records::AbuseKeyDeploymentIdentity>,
    started_at: Instant,
    process_started_at: chrono::DateTime<chrono::Utc>,
    tls_context: northstar_security::tls::TlsContext,
    /// Linearization gate for the federation kill switch. Application
    /// stanza writes hold a read guard only across the socket write; island
    /// mode transitions take the exclusive guard.
    federation_write_policy: Arc<FederationWritePolicy>,
    registration_closed: Arc<AtomicBool>,
    /// Durable XEP-0133 federation policy overlay. Static environment policy
    /// remains the outer ceiling; runtime rules may only restrict it further.
    federation_runtime_policy: Arc<arc_swap::ArcSwap<RuntimeFederationPolicy>>,
    service_shutdown: Arc<std::sync::OnceLock<CancellationToken>>,
    runtime_control_liveness: Arc<()>,
    workers: Arc<northstar_runtime::workers::WorkerRegistry>,
}

impl AppState {
    fn start_locked_muc_expiry(state: Arc<Self>, cancel: CancellationToken) {
        let weak = Arc::downgrade(
            state
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
