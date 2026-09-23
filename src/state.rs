pub(crate) mod account_admin;
pub(crate) type AccountAdminContext = crate::services::account_admin::AccountAdminService<
    db::account_admin_repository::PostgresAccountAdminRepository,
>;
pub(crate) type RegistrationAdminContext = crate::services::account_admin::RegistrationAdminService<
    db::account_admin_repository::PostgresRegistrationAdminRepository,
    account_admin::LocalRegistrationCache,
>;
pub(crate) type SessionAdminContext = crate::services::account_admin::SessionAdminService<
    db::account_admin_repository::PostgresSessionAdminRepository,
    account_admin::LocalAdminSessions,
>;
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

pub(crate) mod http_policy;
pub(crate) use http_policy::{AdminGatewayVerifier, HttpTransportPolicy, PublicDiscoveryContext};
pub(crate) type AdminDispatchContext = crate::services::admin_dispatch::AdminDispatchService<
    db::admin_dispatch_repository::PostgresAdminDispatchRepository,
>;
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

pub(crate) type InvitationAdminContext = crate::services::invitation_admin::InvitationAdminService<
    db::invitation_admin_repository::PostgresInvitationAdminRepository,
>;
impl axum::extract::FromRef<Arc<AppState>> for InvitationAdminContext {
    fn from_ref(state: &Arc<AppState>) -> Self {
        state.invitation_admin_service.clone()
    }
}

pub(crate) mod governance;
pub(crate) type GovernanceContext = governance::GovernanceContext<
    db::governance_repository::PostgresGovernanceRepository<
        crate::api::governance_cursor::SignedGovernanceCursors,
    >,
>;
impl axum::extract::FromRef<Arc<AppState>> for GovernanceContext {
    fn from_ref(state: &Arc<AppState>) -> Self {
        state.governance_context.clone()
    }
}

pub(crate) mod retention_policy;
pub(crate) type RetentionPolicyContext = retention_policy::RetentionPolicyContext<
    db::retention_policy_repository::PostgresRetentionPolicyRepository,
>;
impl axum::extract::FromRef<Arc<AppState>> for RetentionPolicyContext {
    fn from_ref(state: &Arc<AppState>) -> Self {
        state.retention_policy_context.clone()
    }
}

pub(crate) type ReportModerationContext =
    crate::services::report_moderation::ReportModerationService<
        db::report_moderation_repository::PostgresReportModerationRepository,
    >;
impl axum::extract::FromRef<Arc<AppState>> for ReportModerationContext {
    fn from_ref(state: &Arc<AppState>) -> Self {
        state.report_moderation_service.clone()
    }
}

pub(crate) type UploadAdminContext = crate::services::upload_admin::UploadAdminService<
    db::upload_admin_repository::PostgresUploadAdminRepository,
>;
impl axum::extract::FromRef<Arc<AppState>> for UploadAdminContext {
    fn from_ref(state: &Arc<AppState>) -> Self {
        state.upload_admin_service.clone()
    }
}

pub(crate) type OperationAdminContext = crate::services::operations::OperationAdminService<
    db::operation_admin_repository::PostgresOperationAdminRepository,
>;
impl axum::extract::FromRef<Arc<AppState>> for OperationAdminContext {
    fn from_ref(state: &Arc<AppState>) -> Self {
        state.operation_admin_service.clone()
    }
}

pub(crate) mod reports;
pub(crate) type ReportContext = reports::ReportContext<
    db::report_repository::PostgresReportRepository,
    db::api_queries::PostgresApiQueryRepository,
>;
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
pub(crate) mod omemo_poll;
pub(crate) type OmemoRecoveryPollContext = omemo_poll::OmemoRecoveryPollContext<
    db::omemo_recovery_repository::PostgresOmemoRecoveryPollRepository,
>;
impl axum::extract::FromRef<Arc<AppState>> for OmemoRecoveryPollContext {
    fn from_ref(state: &Arc<AppState>) -> Self {
        state.omemo_recovery_poll_context()
    }
}
pub(crate) mod api_queries;
pub(crate) mod api_session_http;
pub(crate) mod http_challenge_endpoint;
mod http_login_endpoint;
pub(crate) mod http_registration_endpoint;
pub(crate) use http_login_endpoint::HttpLoginEndpointContext;
mod passkey_login_finish;
pub(crate) use passkey_login_finish::PasskeyLoginFinishContext;
pub(crate) mod upload_http_delete;
mod upload_http_read;
pub(crate) use upload_http_read::UploadHttpReadContext;
mod metrics_context;
pub(crate) use metrics_context::MetricsContext;
mod account_generation_teardown;
mod admin_cluster_queries;
pub(crate) mod cluster_failure_supervisor;
pub(crate) mod cluster_maintenance;
pub(crate) mod cluster_muc_outbox_worker;
pub(crate) mod cluster_muc_projection;
pub(crate) mod cluster_routing;
mod cluster_shutdown;
pub(crate) mod federated_muc_cluster_effects;
mod message_cluster_routing;
pub(crate) mod mix_cluster_routing;
pub(crate) mod muc_cluster_effects;
pub(crate) mod muc_cluster_routing;
mod notification_routing;
pub(crate) mod omemo_recovery_http;
pub(crate) mod passkey_http;
mod presence_cluster_routing;
mod s2s_cluster_routing;
mod session_cluster_route;
pub(crate) mod suspension;
pub(crate) type ApiQueryContext =
    api_queries::ApiQueryContext<db::api_queries::PostgresApiQueryRepository>;

impl axum::extract::FromRef<Arc<AppState>> for ApiQueryContext {
    fn from_ref(state: &Arc<AppState>) -> Self {
        state.api_query_context()
    }
}

impl axum::extract::FromRef<Arc<AppState>> for HttpLoginEndpointContext {
    fn from_ref(state: &Arc<AppState>) -> Self {
        HttpLoginEndpointContext::from_state(state)
    }
}

impl axum::extract::FromRef<Arc<AppState>> for PasskeyLoginFinishContext {
    fn from_ref(state: &Arc<AppState>) -> Self {
        Self::new(Arc::clone(&state.passkey_service))
    }
}

impl axum::extract::FromRef<Arc<AppState>> for UploadHttpReadContext {
    fn from_ref(state: &Arc<AppState>) -> Self {
        Self::from_state(state)
    }
}

use crate::{
    abuse::{AbuseConfig, AbuseGuard},
    config::{
        AdminCommandPoolMode, Config, OMEMO_RECOVERY_POOL_MAX_CONNECTIONS,
        SERVICE_CONTROL_POOL_MAX_CONNECTIONS,
    },
    db,
    metrics::Metrics,
    s2s::FederationRouter,
    services::upload_safety::{UploadAuthorityGeneration, UploadSafetyGate},
    storage::{GuardedUploadStore, LocalUploadStore, S3UploadSettings, S3UploadStore, UploadStore},
};
use anyhow::Context;
use dashmap::{DashMap, DashSet};
use hickory_resolver::{
    config::{ResolveHosts, ServerOrderingStrategy},
    net::runtime::TokioRuntimeProvider,
    system_conf::read_system_conf,
    TokioResolver,
};
use sha2::{Digest, Sha256};
use sqlx::{
    pool::PoolConnection,
    postgres::{PgConnectOptions, PgPoolOptions},
    PgPool, Postgres,
};
use std::{
    collections::{HashSet, VecDeque},
    sync::{
        atomic::{AtomicBool, AtomicI16, AtomicU64, AtomicU8, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};
use tokio::sync::OwnedSemaphorePermit;
use tokio::sync::RwLock;
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;
use zeroize::{Zeroize, Zeroizing};

const OMEMO_POLL_CONCURRENCY: usize = 4;
const OMEMO_POLL_IP_REQUESTS_PER_MINUTE: usize = 30;
const OMEMO_POLL_MAX_ACTIVE_IPS: usize = 65_536;
/// Durable runtime policy is a safety boundary, not ordinary background work.
/// Reserve one runtime-role connection so traffic workers cannot prevent the
/// process from observing committed administration settings under a saturated
/// main pool. XEP-0133 uses the same control-plane capability when enabled,
/// but does not own the capability itself.
// This is an initial connection/SCRAM handshake budget, not the runtime
// policy polling interval. Repeatedly cancelling half-second handshakes under
// a cold-start cohort can prevent any of them from reaching authentication.
const RUNTIME_CONTROL_STARTUP_CONNECT_ATTEMPT_BUDGET: Duration = Duration::from_secs(3);
/// A process has no traffic listeners while this bounded admission window is
/// active.  It exists specifically to de-correlate a cold-start cohort from a
/// short, per-attempt pool deadline; it is not a runtime worker retry policy.
const RUNTIME_CONTROL_STARTUP_RETRY_BUDGET: Duration = Duration::from_secs(15);
const RUNTIME_CONTROL_STARTUP_RETRY_MAX_DELAY: Duration = Duration::from_millis(500);
// Auxiliary pools retain their two-second acquisition policy while serving.
// Only initial handshakes may retry, within one shared admission window.
const AUXILIARY_POOL_ACQUIRE_TIMEOUT: Duration = Duration::from_secs(2);
const AUXILIARY_POOL_STARTUP_BUDGET: Duration = Duration::from_secs(15);

/// Fixed concurrency keeps one slow transport from blocking other shutdown
/// notices without spawning tasks or increasing the root's total deadline.
pub(crate) async fn count_shutdown_notification_completions<I, F>(notifications: I) -> usize
where
    I: IntoIterator<Item = F>,
    F: std::future::Future<Output = bool>,
{
    use futures::StreamExt;
    futures::stream::iter(notifications)
        .buffer_unordered(16)
        .fold(0, |confirmed, written| async move {
            confirmed + usize::from(written)
        })
        .await
}

fn runtime_control_pool_options(config: &Config, attempt_budget: Duration) -> PgPoolOptions {
    let options = PgPoolOptions::new()
        .max_connections(SERVICE_CONTROL_POOL_MAX_CONNECTIONS)
        .min_connections(SERVICE_CONTROL_POOL_MAX_CONNECTIONS)
        .acquire_timeout(attempt_budget);
    if config.database_allow_unsafe_role_for_development {
        options
    } else {
        db::pin_public_application_schema(options)
    }
}

fn runtime_control_connect_options(database_url: &str) -> Result<PgConnectOptions, sqlx::Error> {
    Ok(database_url
        .parse::<PgConnectOptions>()?
        .application_name("northstar-runtime-control"))
}

fn runtime_control_startup_retry_delay(attempt: u32, process_id: u32) -> Duration {
    let exponent = attempt.saturating_sub(1).min(5);
    let exponential_millis = 10_u64.saturating_mul(1_u64 << exponent);
    // A process-local deterministic spread avoids another synchronized
    // connection wave without introducing shared startup state or a random
    // source into the authority boundary.
    let jitter_millis = u64::from(process_id)
        .wrapping_mul(0x9e37_79b9)
        .wrapping_add(u64::from(attempt).wrapping_mul(0x85eb_ca6b))
        % 97;
    Duration::from_millis(
        exponential_millis
            .saturating_add(jitter_millis)
            .min(RUNTIME_CONTROL_STARTUP_RETRY_MAX_DELAY.as_millis() as u64),
    )
}

async fn runtime_control_startup_connect<T, Connect, ConnectFuture>(
    deadline: tokio::time::Instant,
    connect: Connect,
) -> anyhow::Result<T>
where
    Connect: FnMut(Duration) -> ConnectFuture,
    ConnectFuture: std::future::Future<Output = Result<T, sqlx::Error>>,
{
    startup_database_connect(
        deadline,
        RUNTIME_CONTROL_STARTUP_CONNECT_ATTEMPT_BUDGET,
        "runtime-control",
        connect,
    )
    .await
}

async fn startup_database_connect<T, Connect, ConnectFuture>(
    deadline: tokio::time::Instant,
    attempt_limit: Duration,
    pool_name: &'static str,
    mut connect: Connect,
) -> anyhow::Result<T>
where
    Connect: FnMut(Duration) -> ConnectFuture,
    ConnectFuture: std::future::Future<Output = Result<T, sqlx::Error>>,
{
    let mut attempts = 0_u32;
    let admission = tokio::time::timeout_at(deadline, async {
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return Err(sqlx::Error::PoolTimedOut);
            }
            let attempt_budget = remaining.min(attempt_limit);
            attempts = attempts.saturating_add(1);
            let result = tokio::time::timeout(attempt_budget, connect(attempt_budget))
                .await
                .unwrap_or(Err(sqlx::Error::PoolTimedOut));
            match result {
                Ok(pool) => return Ok(pool),
                Err(sqlx::Error::PoolTimedOut) => {
                    let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
                    let delay = runtime_control_startup_retry_delay(attempts, std::process::id())
                        .min(remaining);
                    tokio::time::sleep(delay).await;
                }
                Err(error) => return Err(error),
            }
        }
    })
    .await
    .unwrap_or(Err(sqlx::Error::PoolTimedOut));
    admission.with_context(|| {
        format!("could not create isolated {pool_name} database pool after {attempts} bounded startup admission attempts")
    })
}

#[cfg(test)]
mod runtime_control_startup_tests {
    use super::{
        runtime_control_connect_options, runtime_control_startup_connect, startup_database_connect,
    };
    use std::sync::{
        atomic::{AtomicBool, AtomicU32, Ordering},
        Arc,
    };
    use std::time::Duration;

    #[test]
    fn control_connection_identification_preserves_url_transport_and_schema_options() {
        let url = "postgres://fixture_user@127.0.0.1:6543/fixture_db?sslmode=verify-full&application_name=caller-name&options=-csearch_path%3Dfixture_schema%2Cpublic%20-cstatement_timeout%3D5000";
        let original = url.parse::<sqlx::postgres::PgConnectOptions>().unwrap();
        let control = runtime_control_connect_options(url).unwrap();
        assert_eq!(
            control.get_application_name(),
            Some("northstar-runtime-control")
        );
        assert_eq!(original.get_application_name(), Some("caller-name"));
        assert_eq!(control.get_host(), original.get_host());
        assert_eq!(control.get_port(), original.get_port());
        assert_eq!(control.get_username(), original.get_username());
        assert_eq!(control.get_database(), original.get_database());
        assert!(matches!(
            control.get_ssl_mode(),
            sqlx::postgres::PgSslMode::VerifyFull
        ));
        assert_eq!(control.get_options(), original.get_options());
        assert_eq!(
            control.get_options(),
            Some("-csearch_path=fixture_schema,public -cstatement_timeout=5000")
        );
        assert!(runtime_control_connect_options("not a database URL").is_err());
    }

    #[tokio::test]
    async fn slow_initial_handshake_finishes_without_half_second_cancellation() {
        let attempts = AtomicU32::new(0);
        let result = runtime_control_startup_connect(
            tokio::time::Instant::now() + Duration::from_secs(15),
            |budget| {
                attempts.fetch_add(1, Ordering::Relaxed);
                assert!(budget > Duration::from_millis(500));
                assert!(budget <= Duration::from_secs(3));
                async {
                    tokio::time::sleep(Duration::from_millis(750)).await;
                    Ok(7_u32)
                }
            },
        )
        .await
        .unwrap();
        assert_eq!(result, 7);
        assert_eq!(attempts.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn remaining_admission_budget_cancels_an_incomplete_handshake() {
        struct CancellationWitness(Arc<AtomicBool>);
        impl Drop for CancellationWitness {
            fn drop(&mut self) {
                self.0.store(true, Ordering::Relaxed);
            }
        }
        let cancelled = Arc::new(AtomicBool::new(false));
        let attempts = AtomicU32::new(0);
        let result: anyhow::Result<()> = runtime_control_startup_connect(
            tokio::time::Instant::now() + Duration::from_secs(1),
            |budget| {
                attempts.fetch_add(1, Ordering::Relaxed);
                assert!(budget <= Duration::from_secs(1));
                let witness = CancellationWitness(Arc::clone(&cancelled));
                async move {
                    let _witness = witness;
                    std::future::pending().await
                }
            },
        )
        .await;
        assert!(result.is_err());
        assert!(cancelled.load(Ordering::Relaxed));
        assert_eq!(attempts.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn admission_retries_pool_timeouts_but_never_authentication_or_protocol_errors() {
        let attempts = AtomicU32::new(0);
        runtime_control_startup_connect(
            tokio::time::Instant::now() + Duration::from_secs(2),
            |_| {
                let attempt = attempts.fetch_add(1, Ordering::Relaxed);
                async move {
                    if attempt == 0 {
                        Err(sqlx::Error::PoolTimedOut)
                    } else {
                        Ok(())
                    }
                }
            },
        )
        .await
        .unwrap();
        assert_eq!(attempts.load(Ordering::Relaxed), 2);
        attempts.store(0, Ordering::Relaxed);
        let result: anyhow::Result<()> = runtime_control_startup_connect(
            tokio::time::Instant::now() + Duration::from_secs(2),
            |_| {
                attempts.fetch_add(1, Ordering::Relaxed);
                async {
                    Err(sqlx::Error::Protocol(
                        "fixture authentication rejected".into(),
                    ))
                }
            },
        )
        .await;
        assert!(result.is_err());
        assert_eq!(attempts.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn expired_admission_never_starts_a_new_connection() {
        let result: anyhow::Result<()> = runtime_control_startup_connect(
            tokio::time::Instant::now() - Duration::from_millis(1),
            |_| async { panic!("connection was attempted after its admission deadline") },
        )
        .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn auxiliary_pools_share_the_remaining_deadline_and_cancel_inflight_connect() {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
        startup_database_connect(deadline, Duration::from_secs(2), "command", |_| async {
            tokio::time::sleep(Duration::from_secs(1)).await;
            Ok(())
        })
        .await
        .unwrap();
        let result: anyhow::Result<()> =
            startup_database_connect(deadline, Duration::from_secs(2), "OMEMO", |budget| {
                assert!(budget < Duration::from_secs(2));
                std::future::pending()
            })
            .await;
        assert!(result.unwrap_err().to_string().contains("OMEMO"));
        let result: anyhow::Result<()> =
            startup_database_connect(deadline, Duration::from_secs(2), "command", |_| async {
                panic!("a later pool must not reset an exhausted shared deadline")
            })
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn auxiliary_pool_retry_preserves_its_acquisition_limit() {
        let attempts = AtomicU32::new(0);
        startup_database_connect(
            tokio::time::Instant::now() + Duration::from_secs(15),
            Duration::from_secs(2),
            "OMEMO",
            |budget| {
                assert_eq!(budget, Duration::from_secs(2));
                let attempt = attempts.fetch_add(1, Ordering::Relaxed);
                async move {
                    if attempt == 0 {
                        Err(sqlx::Error::PoolTimedOut)
                    } else {
                        Ok(())
                    }
                }
            },
        )
        .await
        .unwrap();
        assert_eq!(attempts.load(Ordering::Relaxed), 2);
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RuntimeControlPhase {
    Idle,
    SnapshotRead,
    PolicyApply,
    ServiceControlRead,
}

impl RuntimeControlPhase {
    fn label(self) -> &'static str {
        match self {
            Self::Idle => "idle",
            Self::SnapshotRead => "snapshot-read",
            Self::PolicyApply => "policy-apply",
            Self::ServiceControlRead => "service-control-read",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct RuntimeControlStall {
    phase: RuntimeControlPhase,
    phase_elapsed: Duration,
    heartbeat_elapsed: Duration,
}

/// Observation only: a stalled attempt is dropped before its supervisor sets
/// the root cancellation token. Normal root shutdown must not produce a warning.
struct RuntimeControlDiagnostics {
    phase: RuntimeControlPhase,
    phase_started: tokio::time::Instant,
    last_reported: tokio::time::Instant,
    max_silence: Duration,
    root_cancel: CancellationToken,
    #[cfg(test)]
    captured: Option<Arc<std::sync::Mutex<Vec<RuntimeControlStall>>>>,
}

impl RuntimeControlDiagnostics {
    fn new(root_cancel: CancellationToken, max_silence: Duration) -> Self {
        let now = tokio::time::Instant::now();
        Self {
            phase: RuntimeControlPhase::Idle,
            phase_started: now,
            last_reported: now,
            max_silence,
            root_cancel,
            #[cfg(test)]
            captured: None,
        }
    }

    fn enter(&mut self, phase: RuntimeControlPhase) {
        self.phase = phase;
        self.phase_started = tokio::time::Instant::now();
    }

    fn database_read(&mut self, phase: db::RuntimeControlReadPhase) {
        self.enter(match phase {
            db::RuntimeControlReadPhase::Snapshot => RuntimeControlPhase::SnapshotRead,
        });
    }

    /// Call only after the existing heartbeat report; this changes no health.
    fn reported(&mut self) {
        let now = tokio::time::Instant::now();
        self.last_reported = now;
        self.phase = RuntimeControlPhase::Idle;
        self.phase_started = now;
    }

    fn stalled(&self) -> Option<RuntimeControlStall> {
        if self.root_cancel.is_cancelled() {
            return None;
        }
        let now = tokio::time::Instant::now();
        let heartbeat_elapsed = now.saturating_duration_since(self.last_reported);
        (heartbeat_elapsed > self.max_silence).then(|| RuntimeControlStall {
            phase: self.phase,
            phase_elapsed: now.saturating_duration_since(self.phase_started),
            heartbeat_elapsed,
        })
    }
}

impl Drop for RuntimeControlDiagnostics {
    fn drop(&mut self) {
        let Some(stall) = self.stalled() else {
            return;
        };
        tracing::warn!(
            phase = stall.phase.label(),
            phase_elapsed_ms = stall.phase_elapsed.as_millis() as u64,
            heartbeat_elapsed_ms = stall.heartbeat_elapsed.as_millis() as u64,
            "runtime-control attempt dropped after heartbeat silence"
        );
        #[cfg(test)]
        if let Some(captured) = &self.captured {
            captured.lock().unwrap().push(stall);
        }
    }
}

fn report_runtime_control_health(
    heartbeat: &crate::workers::WorkerHeartbeat,
    observed_database: bool,
    error: Option<anyhow::Error>,
) {
    if let Some(error) = error {
        heartbeat.error(error);
    } else if observed_database {
        heartbeat.ok();
    } else {
        // With XEP-0133 control disabled, alternate ticks perform no query.
        // They prove scheduler liveness only, never database/ownership health.
        // Clearing an error here would let a dead reserved connection alternate
        // error/ok forever, concealing loss of the standalone retention lock.
        heartbeat.pulse();
    }
}

#[cfg(test)]
mod runtime_control_health_tests {
    use super::report_runtime_control_health;
    use crate::workers::{WorkerCriticality, WorkerMode, WorkerRegistry};
    use std::time::Duration;
    use tokio_util::sync::CancellationToken;

    #[tokio::test]
    async fn idle_ticks_cannot_reset_a_broken_control_connection() {
        let workers = WorkerRegistry::new();
        let cancel = CancellationToken::new();
        workers.supervise(
            "test-runtime-control-loss",
            WorkerCriticality::Critical,
            WorkerMode::Continuous,
            None,
            cancel.clone(),
            |heartbeat| async move {
                for _ in 0..3 {
                    report_runtime_control_health(
                        &heartbeat,
                        true,
                        Some(anyhow::anyhow!("fixture connection closed")),
                    );
                    report_runtime_control_health(&heartbeat, false, None);
                }
                std::future::pending().await
            },
        );
        tokio::time::timeout(Duration::from_secs(2), cancel.cancelled())
            .await
            .expect("idle ticks concealed a broken reserved connection");
        assert!(workers.critical_failure().is_some());
        assert!(workers
            .shutdown_and_join(&cancel, Duration::from_secs(1))
            .await
            .is_clean());
    }

    #[tokio::test]
    async fn successful_database_reads_can_restore_control_health() {
        let workers = WorkerRegistry::new();
        let cancel = CancellationToken::new();
        let (complete, mut observed) = tokio::sync::mpsc::channel(1);
        workers.supervise(
            "test-runtime-control-recovery",
            WorkerCriticality::Critical,
            WorkerMode::Continuous,
            None,
            cancel.clone(),
            move |heartbeat| {
                let complete = complete.clone();
                async move {
                    for _ in 0..2 {
                        report_runtime_control_health(
                            &heartbeat,
                            true,
                            Some(anyhow::anyhow!("fixture query failed")),
                        );
                        report_runtime_control_health(&heartbeat, false, None);
                    }
                    report_runtime_control_health(&heartbeat, true, None);
                    for _ in 0..2 {
                        report_runtime_control_health(
                            &heartbeat,
                            true,
                            Some(anyhow::anyhow!("fixture query failed")),
                        );
                        report_runtime_control_health(&heartbeat, false, None);
                    }
                    let _ = complete.send(()).await;
                    std::future::pending().await
                }
            },
        );
        tokio::time::timeout(Duration::from_secs(2), observed.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(!cancel.is_cancelled());
        assert!(workers.readiness_error().is_none());
        cancel.cancel();
        assert!(workers
            .shutdown_and_join(&cancel, Duration::from_secs(1))
            .await
            .is_clean());
    }

    fn diagnostic_guard(
        root_cancel: CancellationToken,
    ) -> (
        super::RuntimeControlDiagnostics,
        std::sync::Arc<std::sync::Mutex<Vec<super::RuntimeControlStall>>>,
    ) {
        let captured = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let mut guard = super::RuntimeControlDiagnostics::new(root_cancel, Duration::from_secs(5));
        guard.captured = Some(std::sync::Arc::clone(&captured));
        (guard, captured)
    }

    #[tokio::test]
    async fn dropped_pending_control_turn_reports_its_actual_phase() {
        use super::RuntimeControlPhase;
        for phase in [
            RuntimeControlPhase::SnapshotRead,
            RuntimeControlPhase::PolicyApply,
            RuntimeControlPhase::Idle,
            RuntimeControlPhase::ServiceControlRead,
        ] {
            let (mut guard, captured) = diagnostic_guard(CancellationToken::new());
            let (entered, observed) = tokio::sync::oneshot::channel();
            let task = tokio::spawn(async move {
                match phase {
                    RuntimeControlPhase::SnapshotRead => {
                        guard.database_read(crate::db::RuntimeControlReadPhase::Snapshot);
                    }
                    other => guard.enter(other),
                }
                guard.phase_started -= Duration::from_secs(6);
                guard.last_reported -= Duration::from_secs(6);
                entered.send(()).unwrap();
                std::future::pending::<()>().await;
                drop(guard);
            });
            observed.await.unwrap();
            task.abort();
            assert!(task.await.unwrap_err().is_cancelled());
            let reports = captured.lock().unwrap();
            assert_eq!(reports.len(), 1);
            assert_eq!(reports[0].phase, phase);
            assert!(reports[0].phase_elapsed >= Duration::from_secs(6));
            assert!(reports[0].heartbeat_elapsed >= Duration::from_secs(6));
        }
    }

    #[tokio::test]
    async fn normal_shutdown_drops_a_stalled_control_turn_without_warning() {
        let root_cancel = CancellationToken::new();
        let (mut guard, captured) = diagnostic_guard(root_cancel.clone());
        let (entered, observed) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            guard.database_read(crate::db::RuntimeControlReadPhase::Snapshot);
            guard.phase_started -= Duration::from_secs(6);
            guard.last_reported -= Duration::from_secs(6);
            entered.send(()).unwrap();
            std::future::pending::<()>().await;
            drop(guard);
        });
        observed.await.unwrap();
        root_cancel.cancel();
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        assert!(captured.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn short_control_phases_do_not_reset_total_heartbeat_silence() {
        let (mut guard, captured) = diagnostic_guard(CancellationToken::new());
        let (entered, observed) = tokio::sync::oneshot::channel();
        let (next_phase, continue_turn) = tokio::sync::oneshot::channel();
        let (changed, change_observed) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            guard.database_read(crate::db::RuntimeControlReadPhase::Snapshot);
            guard.last_reported -= Duration::from_secs(6);
            entered.send(()).unwrap();
            continue_turn.await.unwrap();
            guard.enter(super::RuntimeControlPhase::PolicyApply);
            guard.phase_started -= Duration::from_secs(2);
            changed.send(()).unwrap();
            std::future::pending::<()>().await;
            drop(guard);
        });
        observed.await.unwrap();
        next_phase.send(()).unwrap();
        change_observed.await.unwrap();
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        let reports = captured.lock().unwrap();
        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].phase, super::RuntimeControlPhase::PolicyApply);
        assert!(reports[0].phase_elapsed >= Duration::from_secs(2));
        assert!(reports[0].heartbeat_elapsed >= Duration::from_secs(6));
        assert!(reports[0].heartbeat_elapsed > reports[0].phase_elapsed);
    }

    #[tokio::test]
    async fn an_existing_health_report_resets_only_the_diagnostic_clock() {
        let (mut guard, captured) = diagnostic_guard(CancellationToken::new());
        let (entered, observed) = tokio::sync::oneshot::channel();
        let (report, continue_turn) = tokio::sync::oneshot::channel();
        let (reported, report_observed) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            guard.database_read(crate::db::RuntimeControlReadPhase::Snapshot);
            guard.last_reported -= Duration::from_secs(6);
            entered.send(()).unwrap();
            continue_turn.await.unwrap();
            guard.reported();
            reported.send(()).unwrap();
            std::future::pending::<()>().await;
            drop(guard);
        });
        observed.await.unwrap();
        report.send(()).unwrap();
        report_observed.await.unwrap();
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        assert!(captured.lock().unwrap().is_empty());
    }
}

/// Establish the one process-owned control-plane connection before the
/// traffic pool or any startup reconciliation can take database capacity.
///
/// Keeping this at the application boundary makes the ordering explicit:
/// `main` owns startup sequencing, while [`AppState`] only owns the connection
/// after startup transfers it into the coordinated runtime worker.  The
/// connection remains separate from traffic for its whole lifetime.
pub(crate) async fn reserve_runtime_control_connection(
    config: &Config,
) -> anyhow::Result<PoolConnection<Postgres>> {
    let deadline = tokio::time::Instant::now() + RUNTIME_CONTROL_STARTUP_RETRY_BUDGET;
    let connect_options = runtime_control_connect_options(&config.database_url)?;
    let runtime_control_pool = runtime_control_startup_connect(deadline, |attempt_budget| {
        runtime_control_pool_options(config, attempt_budget).connect_with(connect_options.clone())
    })
    .await?;
    // Attestation and final ownership transfer share the same absolute startup
    // deadline. A completed handshake alone never authorizes serving traffic.
    tokio::time::timeout_at(deadline, async {
        if config.database_allow_unsafe_role_for_development {
            crate::db::attest_development_database_is_loopback(&runtime_control_pool).await?;
        } else {
            crate::db::attest_runtime_role(&runtime_control_pool).await?;
        }
        runtime_control_pool
            .acquire()
            .await
            .context("could not reserve the runtime-control database connection")
    })
    .await
    .context(
        "runtime-control role attestation/reservation exceeded its startup admission deadline",
    )?
}

fn admit_omemo_poll_ip_window(window: &mut VecDeque<Instant>, now: Instant) -> bool {
    let cutoff = now.checked_sub(Duration::from_secs(60)).unwrap_or(now);
    while window.front().is_some_and(|seen| *seen <= cutoff) {
        window.pop_front();
    }
    if window.len() >= OMEMO_POLL_IP_REQUESTS_PER_MINUTE {
        return false;
    }
    window.push_back(now);
    true
}

fn admit_bounded_omemo_poll_ip(
    windows: &DashMap<std::net::IpAddr, VecDeque<Instant>>,
    admission: &std::sync::Mutex<()>,
    ip: std::net::IpAddr,
    now: Instant,
    sweep: bool,
    max_active_ips: usize,
) -> bool {
    let _admission = admission
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if sweep {
        let cutoff = now.checked_sub(Duration::from_secs(60)).unwrap_or(now);
        windows.retain(|_, window| {
            while window.front().is_some_and(|seen| *seen <= cutoff) {
                window.pop_front();
            }
            !window.is_empty()
        });
    }
    if !windows.contains_key(&ip) && windows.len() >= max_active_ips {
        return false;
    }
    let mut window = windows.entry(ip).or_default();
    admit_omemo_poll_ip_window(&mut window, now)
}

/// Stable, non-secret identity for the physical upload namespace shared by
/// every node. PostgreSQL stores this digest so a node configured for a
/// different bucket/prefix cannot serve or delete another node's objects.
/// Credential material is deliberately excluded: rotating credentials must
/// not change storage authority.
fn upload_storage_namespace_id(config: &Config) -> anyhow::Result<[u8; 32]> {
    fn field(digest: &mut Sha256, value: &str) {
        digest.update((value.len() as u64).to_be_bytes());
        digest.update(value.as_bytes());
    }

    let mut digest = Sha256::new();
    digest.update(b"northstar/upload-storage-namespace/v2\0");
    field(&mut digest, &config.upload_storage_backend);
    if config.upload_storage_backend == "local" {
        std::fs::create_dir_all(&config.upload_dir)
            .context("could not prepare UPLOAD_DIR for storage authority")?;
        let canonical = std::fs::canonicalize(&config.upload_dir)
            .context("could not canonicalize UPLOAD_DIR for storage authority")?;
        field(&mut digest, &canonical.to_string_lossy());
    } else {
        field(
            &mut digest,
            config
                .upload_s3_endpoint
                .as_deref()
                .unwrap_or("<aws-default-endpoint>"),
        );
        field(&mut digest, &config.upload_s3_region);
        field(
            &mut digest,
            config.upload_s3_bucket.as_deref().unwrap_or_default(),
        );
        field(&mut digest, &config.upload_s3_prefix);
        digest.update([
            u8::from(config.upload_s3_path_style),
            u8::from(config.upload_s3_allow_http),
        ]);
        if let Some(kms_file) = config.upload_s3_sse_kms_key_id_file.as_deref() {
            digest.update([1]);
            let mut kms = Zeroizing::new(crate::config::read_secret_file(
                kms_file,
                "UPLOAD_S3_SSE_KMS_KEY_ID_FILE",
            )?);
            field(&mut digest, kms.as_str());
            kms.zeroize();
        } else {
            digest.update([0]);
        }
    }
    Ok(digest.finalize().into())
}

#[allow(unused_imports)]
pub use northstar_protocol_runtime::caps::CapsKey;

pub use northstar_session_application::RouteIncarnationSignal;
pub use northstar_session_core::LocalCapsEpoch;

#[derive(Clone)]
pub struct OnlineSession {
    /// Stable database identity and credential epoch that authorized this
    /// transport.  Keeping both on the live route lets password changes and
    /// administrative disables revoke sessions across cluster nodes without
    /// accidentally terminating a newly recreated account with the same JID.
    pub user_id: uuid::Uuid,
    pub auth_generation: i64,
    pub user_agent_epoch: Option<i64>,
    pub connection_id: uuid::Uuid,
    /// Terminal, exact-incarnation route-removal notification. Every local
    /// compare-and-remove publishes through `AppState`, including rollback,
    /// cleanup and synchronous Drop paths.
    pub(crate) route_incarnation: Arc<RouteIncarnationSignal>,
    /// Shared with the owning protocol session. A successful SM takeover sets
    /// this before removing the old route so the old connection's Drop cannot
    /// suspend/revoke the replacement stream or remove its MUC/caps state.
    pub lifecycle: Arc<AtomicU8>,
    /// Prevents failure cleanup and an eventual Drop from decrementing the
    /// active-session gauge more than once.
    pub metrics_counted: Arc<AtomicBool>,
    /// False while authentication/bind or SM resumption is still committing.
    /// Pending routes may reserve a cluster key, but no stanza delivery path
    /// may expose the transport before the authoritative database commit.
    pub routable: Arc<AtomicBool>,
    pub sender: crate::outbound::OutboundSender,
    pub available: Arc<AtomicBool>,
    /// Per-account/resource linearization boundary for MIX presence. Explicit
    /// presence, verified-caps fallback, transport cleanup and an exact SM
    /// replacement all share this gate, so a delayed side effect cannot
    /// recreate presence after an unavailable/delete epoch. The Arc belongs
    /// to the session lifecycle; there is no process-global keyed lock table.
    pub mix_presence_gate: Arc<tokio::sync::Mutex<()>>,
    /// A successful directed MIX unavailable suppresses the conservative
    /// verified-caps fallback until a later explicit/broadcast available.
    /// Keeping this resource-scoped avoids a process-global tombstone map.
    pub mix_presence_fallback_suppressed: Arc<dashmap::DashSet<String>>,
    /// Monotonic local XEP-0115 observation epoch shared with the protocol
    /// actor and transferred only by an exact live SM replacement.
    pub caps_observation_generation: Arc<AtomicU64>,
    pub carbons: Arc<AtomicBool>,
    pub priority: Arc<AtomicI16>,
    /// Encoded XMPP `<show/>`: 0 unavailable, 1 online, 2 away, 3 chat,
    /// 4 dnd, 5 xa.  Kept per resource for PubSub subscription filtering.
    pub show: Arc<AtomicU8>,
    pub blocklist_requested: Arc<AtomicBool>,
    /// Whether this exact resource has successfully requested its roster.
    /// RFC 6121 roster pushes are sent only to interested resources, and the
    /// flag is retained across XEP-0198 session resumption.
    pub roster_requested: Arc<AtomicBool>,
    /// Per-resource initial roster synchronization fence. Committed pushes
    /// are version-buffered until the initial IQ result owns the transport.
    pub roster_sync: Arc<northstar_roster_application::RosterSyncGate>,
    /// Per-resource XEP-0405 roster annotation preference. It is deliberately
    /// not an account-wide flag: a roster get without `<annotate/>` resets it
    /// only for the requesting client.
    pub mix_roster_annotations: Arc<AtomicBool>,
    /// Session-local XEP-0016 list selection. An absent selection delegates
    /// to the durable account default.
    pub privacy_active: Arc<std::sync::RwLock<Option<String>>>,
    /// Set after this resource requests XEP-0016 state; only interested
    /// resources receive list-definition pushes.
    pub privacy_requested: Arc<AtomicBool>,
    /// RFC 6121 directed-presence recipients authorized by this exact
    /// resource for the lifetime of its presence session.
    pub directed_presence: Arc<DashSet<String>>,
    /// Last authoritative broadcast presence for RFC 6121 probes. The stanza
    /// has a server asserted `from` and no recipient-specific `to`.
    pub last_presence: Arc<std::sync::RwLock<Option<String>>>,
    pub ip: Option<std::net::IpAddr>,
    pub resource: String,
    pub user_agent_id: Option<uuid::Uuid>,
    /// Exact durable XEP-0198 epoch currently owning this transport.
    pub sm_session_id: Arc<std::sync::RwLock<Option<uuid::Uuid>>>,
    /// Exact MUC occupancies owned by this connection.  Moderation and
    /// clustered control paths share this map with the protocol actor so a
    /// kick can revoke membership immediately without waiting for the target
    /// socket to send another stanza.
    pub muc_memberships: Arc<DashMap<String, JoinedMucMembership>>,
    pub connected_at: Instant,
    pub last_activity: Arc<std::sync::RwLock<Instant>>,
    pub disconnect: CancellationToken,
}

pub use northstar_session_core::{
    staged_route_activation_allowed, JoinedMucMembership, StagedRouteActivationCheck,
    StagedRouteIdentity,
};

pub(crate) fn muc_actor_identity_matches(
    occupant: &MucOccupant,
    full_jid: &str,
    connection_id: uuid::Uuid,
    room_jid: &str,
    membership: &JoinedMucMembership,
) -> bool {
    muc_actor_epoch_matches(occupant, full_jid, connection_id, room_jid, membership)
        && matches!(occupant.endpoint, MucOccupantEndpoint::Local(_))
}

fn muc_actor_epoch_matches(
    occupant: &MucOccupant,
    full_jid: &str,
    connection_id: uuid::Uuid,
    room_jid: &str,
    membership: &JoinedMucMembership,
) -> bool {
    !connection_id.is_nil()
        && !membership.cluster_epoch.is_nil()
        && occupant.full_jid == full_jid
        && occupant.room_jid == room_jid
        && occupant.nick == membership.nick
        && occupant.connection_id == connection_id
        && occupant.cluster_epoch == membership.cluster_epoch
}

pub(crate) fn muc_departure_identity_matches(
    occupant: &MucOccupant,
    full_jid: &str,
    connection_id: uuid::Uuid,
    cluster_epoch: uuid::Uuid,
) -> bool {
    !connection_id.is_nil()
        && !cluster_epoch.is_nil()
        && occupant.full_jid == full_jid
        && occupant.connection_id == connection_id
        && occupant.cluster_epoch == cluster_epoch
}

/// Exact-identity removal guard for a suspended occupancy created by the
/// calling restore: a failure path may only ever remove the endpoint it just
/// created, never a concurrent joiner's or a winning resume's occupant.
fn suspended_occupant_is_created(
    occupant: &MucOccupant,
    created: &Arc<SuspendedMucEndpoint>,
) -> bool {
    matches!(
        &occupant.endpoint,
        MucOccupantEndpoint::Suspended(endpoint) if Arc::ptr_eq(endpoint, created)
    )
}

fn suspended_muc_resume_actor_matches(
    current: &MucOccupant,
    endpoint: &Arc<SuspendedMucEndpoint>,
    full_jid: &str,
    connection_id: uuid::Uuid,
    cluster_epoch: uuid::Uuid,
    sm_session_id: uuid::Uuid,
) -> bool {
    !connection_id.is_nil()
        && !cluster_epoch.is_nil()
        && current.full_jid == full_jid
        && current.connection_id == connection_id
        && current.cluster_epoch == cluster_epoch
        && current.sm_session_id == Some(sm_session_id)
        && matches!(
            &current.endpoint,
            MucOccupantEndpoint::Suspended(current_endpoint)
                if Arc::ptr_eq(current_endpoint, endpoint)
                    && current_endpoint.sm_session_id == sm_session_id
        )
}

pub(crate) fn muc_suspended_teardown_identity_matches(
    current: &MucOccupant,
    sm_session_id: uuid::Uuid,
    expected: &SerializableMucOccupant,
) -> bool {
    !expected.cluster_epoch.is_nil()
        && !expected.connection_id.is_nil()
        && current.sm_session_id == Some(sm_session_id)
        && current.full_jid == expected.full_jid
        && current.room_jid == expected.room_jid
        && current.nick == expected.nick
        && current.cluster_epoch == expected.cluster_epoch
        && current.connection_id == expected.connection_id
        && matches!(
            &current.endpoint,
            MucOccupantEndpoint::Suspended(endpoint)
                if endpoint.sm_session_id == sm_session_id
        )
}

pub use northstar_protocol_runtime::mix::{MixIqRelayStage, PendingMixIqRelay};

#[derive(Clone)]
pub enum MucOccupantEndpoint {
    Local(crate::outbound::OutboundSender),
    /// A local occupant whose transport disappeared while a durable XEP-0198
    /// resume window is open.  Traffic is bounded and moved into PostgreSQL;
    /// it is never sent into the dead transport channel.
    Suspended(Arc<SuspendedMucEndpoint>),
    Federated {
        authenticated_domain: String,
        connection_id: uuid::Uuid,
    },
}

pub struct SuspendedMucEndpoint {
    pub sm_session_id: uuid::Uuid,
    /// The synchronous route fence is present for the complete lifetime of an
    /// SM-associated resource, including while it is live.  A delivery holds
    /// this mutex through `try_send`, while disconnect changes Live to
    /// Transitioning under the same mutex.  Consequently no sender can observe
    /// the old transport after suspension has begun.
    route: std::sync::Mutex<SuspendedMucRoute>,
    buffer: tokio::sync::Mutex<SuspendedMucBuffer>,
    changed: tokio::sync::Notify,
    /// Shared actual-byte lease for the durable stream plus its process-local
    /// MUC suffix. Clones across room occupants reference one reservation.
    sm_capacity: std::sync::Mutex<Option<crate::services::sm_capacity::SmCapacityLease>>,
}

#[derive(Clone)]
enum SuspendedMucRoute {
    Live(crate::outbound::OutboundSender),
    /// A short synchronous hand-off. Deliveries wait rather than falling back
    /// to a stale occupant-local sender.
    Transitioning,
    Suspended,
}

struct SuspendedMucBuffer {
    phase: SuspendedMucPhase,
    /// True only when the exact snapshot used by a committed-or-ambiguous SM
    /// transaction already contains this buffer's suffix. Keeping ownership
    /// separate from the delivery phase preserves it across Sealed->Waiting
    /// resume races without making an error state writable.
    snapshot_owned: bool,
    /// Already-sequenced SM traffic consumes the same stanza and byte budget
    /// as this volatile suffix.  Charging it here prevents a disconnect with
    /// a nearly-full unacked queue from opening a second independent queue.
    base_stanzas: usize,
    base_bytes: usize,
    bytes: usize,
    stanzas: VecDeque<SuspendedMucStanza>,
}

#[derive(Clone)]
struct SuspendedMucStanza {
    source_id: uuid::Uuid,
    xml: String,
}

#[derive(Clone, Debug)]
enum SuspendedMucPhase {
    /// The route mutex owns the live sender; the suspended queue is empty.
    Dormant,
    /// Short synchronous hand-off from the old live route to the durable SM
    /// row.  Volatile admission is bounded by the complete SM budget.
    Collecting,
    /// PostgreSQL owns subsequent delivery and the process-local suffix is
    /// empty.
    Durable,
    /// Resume has fenced durable appends but has not yet received the current
    /// queue size from PostgreSQL. New delivery waits for the exact base.
    Waiting,
    /// One exact resume claim is collecting the final globally-ordered suffix.
    Resuming,
    /// A process-restart restore reserved the nickname but must reject traffic
    /// until its PostgreSQL CAS and SM checkpoint have both committed.
    Reserved,
    /// The suffix has been snapshotted for an atomic SM checkpoint.  No new
    /// traffic is acknowledged while the checkpoint is in flight.
    Committing,
    /// PostgreSQL owns the complete replay queue. The buffer is empty, but the
    /// route stays suspended until `<resumed/>` and replay reach the socket.
    CheckpointOwned,
    /// Fail-closed terminal/intermediate state.  Retained traffic remains
    /// available for durable promotion, but new volatile traffic is rejected.
    Sealed,
}

impl SuspendedMucBuffer {
    fn enqueue_volatile(&mut self, stanza: String, max_stanzas: usize, max_bytes: usize) -> bool {
        if !matches!(
            &self.phase,
            SuspendedMucPhase::Collecting | SuspendedMucPhase::Resuming
        ) {
            return false;
        }
        let Some(next_bytes) = self.bytes.checked_add(stanza.len()) else {
            return false;
        };
        let Some(total_stanzas) = self.base_stanzas.checked_add(self.stanzas.len() + 1) else {
            return false;
        };
        let Some(total_bytes) = self.base_bytes.checked_add(next_bytes) else {
            return false;
        };
        if total_stanzas > max_stanzas || total_bytes > max_bytes {
            return false;
        }
        self.bytes = next_bytes;
        self.stanzas.push_back(SuspendedMucStanza {
            source_id: uuid::Uuid::new_v4(),
            xml: stanza,
        });
        true
    }

    /// Remove only a stanza whose next owner has already accepted it.  Using
    /// the actual front length (rather than clearing/saturating the counter)
    /// keeps the byte bound exact after a first or mid-drain failure.
    fn commit_front(&mut self) {
        let stanza = self
            .stanzas
            .pop_front()
            .expect("a suspended MUC drain can commit only its current front");
        self.bytes = self
            .bytes
            .checked_sub(stanza.xml.len())
            .expect("suspended MUC byte accounting must match its queue");
    }
}

/// Promote the process-local suspension prefix to PostgreSQL in strict FIFO
/// order.  The caller owns the endpoint mutex for the complete operation, so
/// a concurrently arriving stanza can neither overtake this prefix nor race a
/// resume claim. A failed append leaves that exact stanza and every successor
/// in the buffer; only successfully committed rows are removed.
async fn promote_suspended_muc_buffer<F, Fut>(
    buffer: &mut SuspendedMucBuffer,
    mut append: F,
) -> bool
where
    F: FnMut(uuid::Uuid, String) -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    buffer.phase = SuspendedMucPhase::Sealed;
    while let Some(stanza) = buffer.stanzas.front().cloned() {
        if !append(stanza.source_id, stanza.xml).await {
            return false;
        }
        buffer.commit_front();
    }
    buffer.base_stanzas = 0;
    buffer.base_bytes = 0;
    buffer.snapshot_owned = false;
    buffer.phase = SuspendedMucPhase::Durable;
    true
}

/// Seal one session-global FIFO and clone its exact suffix for a prospective
/// SM checkpoint.  Ownership is deliberately not transferred here: if the
/// checkpoint or capacity validation fails, the original endpoint still owns
/// every byte and cleanup can promote it durably.
async fn snapshot_suspended_muc_buffer_for_resume(
    endpoint: &SuspendedMucEndpoint,
) -> Option<Vec<String>> {
    let mut buffer = endpoint.buffer.lock().await;
    if !matches!(
        &buffer.phase,
        SuspendedMucPhase::Resuming | SuspendedMucPhase::Reserved | SuspendedMucPhase::Sealed
    ) {
        return None;
    }
    buffer.phase = SuspendedMucPhase::Committing;
    Some(if buffer.snapshot_owned {
        Vec::new()
    } else {
        buffer
            .stanzas
            .iter()
            .map(|stanza| stanza.xml.clone())
            .collect()
    })
}

async fn seal_suspended_muc_buffer(endpoint: &SuspendedMucEndpoint) {
    let mut buffer = endpoint.buffer.lock().await;
    if !matches!(&buffer.phase, SuspendedMucPhase::Dormant) {
        buffer.phase = SuspendedMucPhase::Sealed;
    }
    drop(buffer);
    finalize_suspended_muc_route_transition(endpoint);
    endpoint.changed.notify_waiters();
}

fn finalize_suspended_muc_route_transition(endpoint: &SuspendedMucEndpoint) {
    let mut route = endpoint
        .route
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if matches!(&*route, SuspendedMucRoute::Transitioning) {
        *route = SuspendedMucRoute::Suspended;
    }
}

fn begin_suspended_muc_route_transition(
    endpoint: &SuspendedMucEndpoint,
    base_stanzas: usize,
    base_bytes: usize,
) {
    let transition_from_live = {
        let mut route = endpoint
            .route
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if matches!(&*route, SuspendedMucRoute::Live(_)) {
            *route = SuspendedMucRoute::Transitioning;
            true
        } else {
            false
        }
    };
    if !transition_from_live {
        return;
    }
    // The ordinary live state has an idle buffer. If a post-replay commit
    // currently owns it, keep the route fenced as Transitioning; that commit
    // observes the fence and refuses Live publication, while async cleanup
    // seals/finalizes the transition after the mutex is released.
    if let Ok(mut buffer) = endpoint.buffer.try_lock() {
        buffer.phase = SuspendedMucPhase::Collecting;
        buffer.base_stanzas = base_stanzas;
        buffer.base_bytes = base_bytes;
        buffer.bytes = 0;
        buffer.stanzas.clear();
        buffer.snapshot_owned = false;
        drop(buffer);
        finalize_suspended_muc_route_transition(endpoint);
        endpoint.changed.notify_waiters();
    }
}

fn transfer_muc_suffix_to_checkpoint(buffer: &mut SuspendedMucBuffer) -> bool {
    if !matches!(&buffer.phase, SuspendedMucPhase::Committing) {
        return false;
    }
    buffer.stanzas.clear();
    buffer.bytes = 0;
    buffer.base_stanzas = 0;
    buffer.base_bytes = 0;
    buffer.snapshot_owned = true;
    buffer.phase = SuspendedMucPhase::CheckpointOwned;
    true
}

fn complete_snapshot_owned_handoff(buffer: &mut SuspendedMucBuffer) -> bool {
    if !buffer.snapshot_owned {
        return false;
    }
    buffer.stanzas.clear();
    buffer.bytes = 0;
    buffer.base_stanzas = 0;
    buffer.base_bytes = 0;
    buffer.snapshot_owned = false;
    buffer.phase = SuspendedMucPhase::Durable;
    true
}

/// Add the volatile MUC suffix to the exact XEP-0198 snapshot which will be
/// committed by the same suspension transaction.  Validation is completed
/// before either counter or queue is mutated, so an invariant failure leaves
/// the caller's original snapshot intact and the endpoint remains its owner.
fn append_suspended_muc_suffix_to_snapshot(
    snapshot: &mut crate::services::sm::SmSessionSnapshot,
    suffix: &VecDeque<SuspendedMucStanza>,
    max_stanzas: usize,
    max_bytes: usize,
) -> anyhow::Result<()> {
    let total_stanzas = snapshot
        .unacked
        .len()
        .checked_add(suffix.len())
        .context("SM stanza count overflow while fencing a MUC disconnect")?;
    let existing_bytes = snapshot
        .unacked
        .iter()
        .try_fold(0usize, |total, entry| total.checked_add(entry.stanza.len()))
        .context("SM byte count overflow while fencing a MUC disconnect")?;
    let total_bytes = suffix.iter().try_fold(existing_bytes, |total, stanza| {
        total.checked_add(stanza.xml.len())
    });
    let total_bytes =
        total_bytes.context("MUC suffix byte count overflow while fencing a disconnect")?;
    anyhow::ensure!(
        total_stanzas <= max_stanzas && total_bytes <= max_bytes,
        "MUC disconnect suffix exceeds the global SM replay budget"
    );

    for stanza in suffix {
        snapshot.outbound_h = snapshot.outbound_h.wrapping_add(1);
        snapshot
            .unacked
            .push(crate::outbound::SmUnackedStanza::with_delivery(
                stanza.xml.clone(),
                None,
            ));
    }
    Ok(())
}

impl SuspendedMucEndpoint {
    fn try_send_live_write_notification(
        &self,
        stanza: String,
        receipt: tokio::sync::mpsc::UnboundedSender<()>,
    ) -> anyhow::Result<bool> {
        let route = self
            .route
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let SuspendedMucRoute::Live(sender) = &*route else {
            // A write-only completion cannot transfer into durable or volatile
            // SM storage, nor cross a concurrent Live-to-Transitioning fence.
            return Ok(false);
        };
        match sender.try_send_with_transport_write_receipt(stanza, receipt) {
            Ok(()) => Ok(true),
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => Ok(false),
            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                anyhow::bail!("live SM shutdown recipient queue is full")
            }
        }
    }

    #[cfg(test)]
    pub fn new(sm_session_id: uuid::Uuid) -> Self {
        Self::new_collecting(sm_session_id, 0, 0)
    }

    fn new_live(sm_session_id: uuid::Uuid, sender: crate::outbound::OutboundSender) -> Self {
        Self {
            sm_session_id,
            route: std::sync::Mutex::new(SuspendedMucRoute::Live(sender)),
            buffer: tokio::sync::Mutex::new(SuspendedMucBuffer {
                phase: SuspendedMucPhase::Dormant,
                snapshot_owned: false,
                base_stanzas: 0,
                base_bytes: 0,
                bytes: 0,
                stanzas: VecDeque::new(),
            }),
            changed: tokio::sync::Notify::new(),
            sm_capacity: std::sync::Mutex::new(None),
        }
    }

    fn new_collecting(sm_session_id: uuid::Uuid, base_stanzas: usize, base_bytes: usize) -> Self {
        Self {
            sm_session_id,
            route: std::sync::Mutex::new(SuspendedMucRoute::Suspended),
            buffer: tokio::sync::Mutex::new(SuspendedMucBuffer {
                phase: SuspendedMucPhase::Collecting,
                snapshot_owned: false,
                base_stanzas,
                base_bytes,
                bytes: 0,
                stanzas: VecDeque::new(),
            }),
            changed: tokio::sync::Notify::new(),
            sm_capacity: std::sync::Mutex::new(None),
        }
    }

    fn new_reserved(sm_session_id: uuid::Uuid, base_stanzas: usize, base_bytes: usize) -> Self {
        Self {
            sm_session_id,
            route: std::sync::Mutex::new(SuspendedMucRoute::Suspended),
            buffer: tokio::sync::Mutex::new(SuspendedMucBuffer {
                phase: SuspendedMucPhase::Reserved,
                snapshot_owned: false,
                base_stanzas,
                base_bytes,
                bytes: 0,
                stanzas: VecDeque::new(),
            }),
            changed: tokio::sync::Notify::new(),
            sm_capacity: std::sync::Mutex::new(None),
        }
    }

    fn new_durable(sm_session_id: uuid::Uuid) -> Self {
        Self {
            sm_session_id,
            route: std::sync::Mutex::new(SuspendedMucRoute::Suspended),
            buffer: tokio::sync::Mutex::new(SuspendedMucBuffer {
                phase: SuspendedMucPhase::Durable,
                snapshot_owned: false,
                base_stanzas: 0,
                base_bytes: 0,
                bytes: 0,
                stanzas: VecDeque::new(),
            }),
            changed: tokio::sync::Notify::new(),
            sm_capacity: std::sync::Mutex::new(None),
        }
    }
}

/// Publish or adopt the one process-local route gate for an exact SM epoch.
/// Callers may have observed a miss before asynchronous database work; the
/// entry operation is the only publication point and can never replace a gate
/// installed by a concurrent join, disconnect, or winning resume.
fn canonical_suspended_muc_endpoint(
    registry: &DashMap<uuid::Uuid, Arc<SuspendedMucEndpoint>>,
    sm_session_id: uuid::Uuid,
    proposed: Arc<SuspendedMucEndpoint>,
) -> Arc<SuspendedMucEndpoint> {
    match registry.entry(sm_session_id) {
        dashmap::mapref::entry::Entry::Vacant(slot) => {
            slot.insert(Arc::clone(&proposed));
            proposed
        }
        dashmap::mapref::entry::Entry::Occupied(slot) => Arc::clone(slot.get()),
    }
}

/// Restore publication is insert-only. A joiner or another exact resume that
/// won while this task awaited PostgreSQL remains authoritative.
fn insert_restored_muc_occupant(
    occupants: &DashMap<String, MucOccupant>,
    key: String,
    occupant: MucOccupant,
) -> bool {
    match occupants.entry(key) {
        dashmap::mapref::entry::Entry::Vacant(slot) => {
            slot.insert(occupant);
            true
        }
        dashmap::mapref::entry::Entry::Occupied(_) => false,
    }
}

/// Result of reattaching one resumed XEP-0198 stream's local MUC occupancies:
/// the memberships which could not be proven valid, plus the volatile
/// suspension FIFO in exact order. The caller must emit the suffix strictly
/// after `<resumed/>` and the durable unacked replay so suspended-room
/// traffic never overtakes older sequenced stanzas.
pub struct RestoredLocalMucOccupants {
    pub failures: Vec<crate::services::sm::SmMucMembership>,
    pub replay_suffix: Vec<String>,
    resume_gate: Option<Arc<SuspendedMucEndpoint>>,
    actors: Vec<RestoredMucActor>,
}

pub(crate) struct RestoreLocalMucOccupantsRequest<'a> {
    pub(crate) user: &'a crate::services::authentication::AuthenticatedAccount,
    pub(crate) full_jid: &'a str,
    pub(crate) connection_id: uuid::Uuid,
    pub(crate) sm_session_id: uuid::Uuid,
    pub(crate) memberships: &'a [crate::services::sm::SmMucMembership],
    pub(crate) base_stanzas: usize,
    pub(crate) base_bytes: usize,
}

#[derive(Clone)]
struct RestoredMucActor {
    key: String,
    full_jid: String,
    connection_id: uuid::Uuid,
    cluster_epoch: uuid::Uuid,
    sm_session_id: uuid::Uuid,
    endpoint: Arc<SuspendedMucEndpoint>,
    membership: crate::services::sm::SmMucMembership,
    resumed_cluster_target: Option<db::ClusterMucOccupancyTarget>,
}

impl RestoredLocalMucOccupants {
    pub(crate) fn planned_memberships(&self) -> Vec<crate::services::sm::SmMucMembership> {
        self.actors
            .iter()
            .map(|actor| actor.membership.clone())
            .collect()
    }

    pub(crate) fn planned_joined_rooms(&self) -> Vec<(String, JoinedMucMembership)> {
        self.actors
            .iter()
            .map(|actor| {
                (
                    actor.membership.room_jid.clone(),
                    JoinedMucMembership {
                        nick: actor.membership.nick.clone(),
                        cluster_epoch: actor.cluster_epoch,
                    },
                )
            })
            .collect()
    }
}

pub(crate) struct CommittedLocalMucResume {
    pub(crate) joined_rooms: Vec<(String, JoinedMucMembership)>,
    pub(crate) failures: Vec<crate::services::sm::SmMucMembership>,
}

#[derive(Clone)]
pub struct MucOccupant {
    pub full_jid: String,
    pub room_jid: String,
    pub nick: String,
    pub endpoint: MucOccupantEndpoint,
    pub affiliation: String,
    pub role: String,
    pub room_non_anonymous: bool,
    pub occupant_id: String,
    /// Per-occupancy ABA guard used for atomic nickname changes in Redis.
    /// This value is internal and is never exposed in XMPP stanzas.
    pub cluster_epoch: uuid::Uuid,
    /// Exact transport incarnation which owns this occupancy.  A resumed SM
    /// stream updates this value while preserving the occupancy epoch; a
    /// recreated post-crash occupancy receives a fresh epoch.
    pub connection_id: uuid::Uuid,
    /// Durable stream epoch owning this local occupant, when XEP-0198
    /// resumption is enabled.
    pub sm_session_id: Option<uuid::Uuid>,
    pub payload: String,
}

/// The process-local identity needed to remove one occupancy without touching
/// a connection that later reused its room nickname.
#[derive(Clone, Copy)]
pub(crate) struct LocalMucOccupantIdentity<'a> {
    pub room_jid: &'a str,
    pub nick: &'a str,
    pub full_jid: &'a str,
    pub connection_id: uuid::Uuid,
    pub cluster_epoch: uuid::Uuid,
}

impl<'a> From<&'a MucOccupant> for LocalMucOccupantIdentity<'a> {
    fn from(occupant: &'a MucOccupant) -> Self {
        Self {
            room_jid: &occupant.room_jid,
            nick: &occupant.nick,
            full_jid: &occupant.full_jid,
            connection_id: occupant.connection_id,
            cluster_epoch: occupant.cluster_epoch,
        }
    }
}

pub(crate) fn remove_local_muc_occupant_exact_from(
    occupants: &DashMap<String, MucOccupant>,
    identity: LocalMucOccupantIdentity<'_>,
) -> Option<MucOccupant> {
    if identity.connection_id.is_nil() || identity.cluster_epoch.is_nil() {
        return None;
    }
    let room_jid = crate::jid::canonicalize_bare(identity.room_jid).ok()?;
    let key = crate::xmpp::xml_util::muc_occupant_key(&room_jid, identity.nick);
    occupants
        .remove_if(&key, |_, current| {
            current.room_jid == room_jid
                && muc_departure_identity_matches(
                    current,
                    identity.full_jid,
                    identity.connection_id,
                    identity.cluster_epoch,
                )
        })
        .map(|(_, occupant)| occupant)
}

fn with_local_muc_occupant_exact<R>(
    occupants: &DashMap<String, MucOccupant>,
    identity: LocalMucOccupantIdentity<'_>,
    update: impl FnOnce(&mut MucOccupant) -> R,
) -> Option<R> {
    if identity.connection_id.is_nil() || identity.cluster_epoch.is_nil() {
        return None;
    }
    let room_jid = crate::jid::canonicalize_bare(identity.room_jid).ok()?;
    let key = crate::xmpp::xml_util::muc_occupant_key(&room_jid, identity.nick);
    let mut occupant = occupants.get_mut(&key)?;
    if occupant.room_jid != room_jid
        || !muc_departure_identity_matches(
            &occupant,
            identity.full_jid,
            identity.connection_id,
            identity.cluster_epoch,
        )
    {
        return None;
    }
    Some(update(&mut occupant))
}

fn set_local_muc_affiliation_exact_in(
    occupants: &DashMap<String, MucOccupant>,
    identity: LocalMucOccupantIdentity<'_>,
    affiliation: &str,
    moderated: bool,
    only_if_none: bool,
    expected_affiliation: Option<&str>,
) -> Option<MucOccupant> {
    with_local_muc_occupant_exact(occupants, identity, |current| {
        if expected_affiliation.is_some_and(|expected| current.affiliation != expected) {
            return None;
        }
        if !only_if_none || current.affiliation == "none" {
            current.affiliation = affiliation.to_owned();
            current.role = if matches!(current.affiliation.as_str(), "owner" | "admin") {
                "moderator"
            } else if moderated && current.affiliation == "none" {
                "visitor"
            } else {
                "participant"
            }
            .to_owned();
        }
        Some(current.clone())
    })
    .flatten()
}

fn set_local_muc_role_exact_in(
    occupants: &DashMap<String, MucOccupant>,
    identity: LocalMucOccupantIdentity<'_>,
    expected_role: &str,
    role: &str,
    non_anonymous: Option<bool>,
) -> Option<MucOccupant> {
    with_local_muc_occupant_exact(occupants, identity, |current| {
        if current.role != expected_role {
            return None;
        }
        current.role = role.to_owned();
        if let Some(non_anonymous) = non_anonymous {
            current.room_non_anonymous = non_anonymous;
        }
        Some(current.clone())
    })
    .flatten()
}

fn refresh_local_muc_policy_exact_in(
    occupants: &DashMap<String, MucOccupant>,
    identity: LocalMucOccupantIdentity<'_>,
    moderated: Option<bool>,
    non_anonymous: Option<bool>,
) -> Option<(MucOccupant, bool)> {
    with_local_muc_occupant_exact(occupants, identity, |current| {
        let before_role = current.role.clone();
        let before_non_anonymous = current.room_non_anonymous;
        if let Some(moderated) = moderated {
            current.role = if matches!(current.affiliation.as_str(), "owner" | "admin") {
                "moderator"
            } else if moderated && current.affiliation == "none" {
                "visitor"
            } else {
                "participant"
            }
            .to_owned();
        }
        if let Some(non_anonymous) = non_anonymous {
            current.room_non_anonymous = non_anonymous;
        }
        let changed =
            current.role != before_role || current.room_non_anonymous != before_non_anonymous;
        (current.clone(), changed)
    })
}

fn muc_presence_endpoint_matches(current: &MucOccupant, prepared: &MucOccupant) -> bool {
    match (&current.endpoint, &prepared.endpoint) {
        (MucOccupantEndpoint::Local(_), MucOccupantEndpoint::Local(_)) => true,
        (
            MucOccupantEndpoint::Federated {
                authenticated_domain: current_domain,
                connection_id: current_connection,
            },
            MucOccupantEndpoint::Federated {
                authenticated_domain: prepared_domain,
                connection_id: prepared_connection,
            },
        ) => current_domain == prepared_domain && current_connection == prepared_connection,
        (MucOccupantEndpoint::Suspended(current), MucOccupantEndpoint::Suspended(prepared)) => {
            Arc::ptr_eq(current, prepared)
        }
        _ => false,
    }
}

fn refresh_local_muc_presence_exact_in(
    occupants: &DashMap<String, MucOccupant>,
    prepared: &MucOccupant,
    apply_policy: bool,
) -> Option<MucOccupant> {
    with_local_muc_occupant_exact(occupants, prepared.into(), |current| {
        if !muc_presence_endpoint_matches(current, prepared) {
            return None;
        }
        current.payload.clone_from(&prepared.payload);
        if apply_policy {
            current.affiliation.clone_from(&prepared.affiliation);
            current.role.clone_from(&prepared.role);
            current.room_non_anonymous = prepared.room_non_anonymous;
        }
        Some(current.clone())
    })
    .flatten()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LocalMucNicknameMove {
    Published,
    AlreadyPublished,
    DeferredToReconciliation,
    OldMissing,
    CollisionRestored,
    CollisionRestoreFailed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LocalMucJoinPublication {
    Published,
    AlreadyPublished,
    Occupied,
}

fn publish_local_muc_join_if_vacant_in(
    occupants: &DashMap<String, MucOccupant>,
    joining: &MucOccupant,
) -> LocalMucJoinPublication {
    let Some(room_jid) = crate::jid::canonicalize_bare(&joining.room_jid).ok() else {
        return LocalMucJoinPublication::Occupied;
    };
    if joining.connection_id.is_nil() || joining.cluster_epoch.is_nil() {
        return LocalMucJoinPublication::Occupied;
    }
    let key = crate::xmpp::xml_util::muc_occupant_key(&room_jid, &joining.nick);
    match occupants.entry(key) {
        dashmap::mapref::entry::Entry::Vacant(entry) => {
            entry.insert(joining.clone());
            LocalMucJoinPublication::Published
        }
        dashmap::mapref::entry::Entry::Occupied(entry)
            if entry.get().room_jid == room_jid
                && entry.get().nick == joining.nick
                && muc_departure_identity_matches(
                    entry.get(),
                    &joining.full_jid,
                    joining.connection_id,
                    joining.cluster_epoch,
                ) =>
        {
            LocalMucJoinPublication::AlreadyPublished
        }
        dashmap::mapref::entry::Entry::Occupied(_) => LocalMucJoinPublication::Occupied,
    }
}

fn move_local_muc_nickname_exact_in(
    occupants: &DashMap<String, MucOccupant>,
    old: LocalMucOccupantIdentity<'_>,
    renamed: &MucOccupant,
    cluster_committed: bool,
) -> LocalMucNicknameMove {
    let Some(room_jid) = crate::jid::canonicalize_bare(old.room_jid).ok() else {
        return LocalMucNicknameMove::OldMissing;
    };
    if old.nick == renamed.nick
        || renamed.room_jid != room_jid
        || renamed.full_jid != old.full_jid
        || renamed.connection_id != old.connection_id
        || renamed.cluster_epoch != old.cluster_epoch
        || old.connection_id.is_nil()
        || old.cluster_epoch.is_nil()
    {
        return LocalMucNicknameMove::OldMissing;
    }
    let old_key = crate::xmpp::xml_util::muc_occupant_key(&room_jid, old.nick);
    let removed_old = remove_local_muc_occupant_exact_from(occupants, old);
    if removed_old.is_none() {
        return if cluster_committed {
            LocalMucNicknameMove::DeferredToReconciliation
        } else {
            LocalMucNicknameMove::OldMissing
        };
    }
    let new_key = crate::xmpp::xml_util::muc_occupant_key(&room_jid, &renamed.nick);
    let destination = match occupants.entry(new_key) {
        dashmap::mapref::entry::Entry::Vacant(entry) => {
            entry.insert(renamed.clone());
            LocalMucNicknameMove::Published
        }
        dashmap::mapref::entry::Entry::Occupied(entry)
            if entry.get().room_jid == room_jid
                && muc_departure_identity_matches(
                    entry.get(),
                    &renamed.full_jid,
                    renamed.connection_id,
                    renamed.cluster_epoch,
                ) =>
        {
            LocalMucNicknameMove::AlreadyPublished
        }
        dashmap::mapref::entry::Entry::Occupied(_) => {
            LocalMucNicknameMove::DeferredToReconciliation
        }
    };
    if destination != LocalMucNicknameMove::DeferredToReconciliation || cluster_committed {
        return destination;
    }
    let old_occupant = removed_old.expect("old occupancy was removed above");
    match occupants.entry(old_key) {
        dashmap::mapref::entry::Entry::Vacant(entry) => {
            entry.insert(old_occupant);
            LocalMucNicknameMove::CollisionRestored
        }
        dashmap::mapref::entry::Entry::Occupied(_) => LocalMucNicknameMove::CollisionRestoreFailed,
    }
}

#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub struct SerializableMucOccupant {
    pub full_jid: String,
    pub room_jid: String,
    pub nick: String,
    pub affiliation: String,
    pub role: String,
    pub room_non_anonymous: bool,
    #[serde(default)]
    pub occupant_id: String,
    #[serde(default)]
    pub cluster_epoch: uuid::Uuid,
    #[serde(default)]
    pub connection_id: uuid::Uuid,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub federated_domain: Option<String>,
    /// Internal cluster ownership epoch for a suspended XEP-0198 actor. It is
    /// never rendered into an XMPP stanza.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sm_session_id: Option<uuid::Uuid>,
    pub payload: String,
}

impl<'a> From<&'a SerializableMucOccupant> for LocalMucOccupantIdentity<'a> {
    fn from(occupant: &'a SerializableMucOccupant) -> Self {
        Self {
            room_jid: &occupant.room_jid,
            nick: &occupant.nick,
            full_jid: &occupant.full_jid,
            connection_id: occupant.connection_id,
            cluster_epoch: occupant.cluster_epoch,
        }
    }
}

impl From<&MucOccupant> for SerializableMucOccupant {
    fn from(occ: &MucOccupant) -> Self {
        Self {
            full_jid: occ.full_jid.clone(),
            room_jid: occ.room_jid.clone(),
            nick: occ.nick.clone(),
            affiliation: occ.affiliation.clone(),
            role: occ.role.clone(),
            room_non_anonymous: occ.room_non_anonymous,
            occupant_id: occ.occupant_id.clone(),
            cluster_epoch: occ.cluster_epoch,
            connection_id: occ.connection_id,
            federated_domain: match &occ.endpoint {
                MucOccupantEndpoint::Local(_) | MucOccupantEndpoint::Suspended(_) => None,
                MucOccupantEndpoint::Federated {
                    authenticated_domain,
                    ..
                } => Some(authenticated_domain.clone()),
            },
            sm_session_id: occ.sm_session_id,
            payload: occ.payload.clone(),
        }
    }
}

struct FederationWritePolicy {
    gate: RwLock<()>,
    island_mode: Arc<AtomicBool>,
}

impl FederationWritePolicy {
    fn new(island_mode: bool) -> Self {
        Self {
            gate: RwLock::new(()),
            island_mode: Arc::new(AtomicBool::new(island_mode)),
        }
    }

    fn enabled(&self) -> bool {
        self.island_mode.load(Ordering::Acquire)
    }

    async fn apply(&self, enabled: bool) {
        let _write_guard = self.gate.write().await;
        self.island_mode.store(enabled, Ordering::Release);
    }

    async fn permit(&self) -> Option<tokio::sync::RwLockReadGuard<'_, ()>> {
        let guard = self.gate.read().await;
        (!self.island_mode.load(Ordering::Acquire)).then_some(guard)
    }

    async fn refresh(&self, enabled: bool) -> bool {
        // An unchanged observation linearizes at this acquire load. It must
        // not wait behind a socket write merely to publish the same value.
        // Actual transitions still drain and fence writes under the gate.
        let previous = self.island_mode.load(Ordering::Acquire);
        if previous == enabled {
            return previous;
        }
        let _write_guard = self.gate.write().await;
        self.island_mode.swap(enabled, Ordering::AcqRel)
    }
}

#[derive(Clone)]
struct UploadAdmission {
    semaphore: Arc<Semaphore>,
    by_ip: Arc<DashMap<std::net::IpAddr, usize>>,
    max_per_ip: usize,
}

impl UploadAdmission {
    fn try_acquire_download(&self, ip: std::net::IpAddr) -> Option<UploadDownloadGuard> {
        let permit = Arc::clone(&self.semaphore).try_acquire_owned().ok()?;
        let mut count = self.by_ip.entry(ip).or_insert(0);
        if *count >= self.max_per_ip {
            let remove_zero = *count == 0;
            drop(count);
            if remove_zero {
                self.by_ip.remove(&ip);
            }
            return None;
        }
        *count += 1;
        drop(count);
        Some(UploadDownloadGuard {
            counts: Arc::clone(&self.by_ip),
            ip,
            _permit: permit,
        })
    }
}

enum UploadRuntime {
    Enabled {
        requests: UploadAdmission,
        downloads: UploadAdmission,
    },
    DrainReadOnly {
        downloads: UploadAdmission,
    },
    Disabled,
}

impl UploadRuntime {
    fn from_config(config: &crate::config::Config) -> Self {
        let downloads = || UploadAdmission {
            semaphore: Arc::new(Semaphore::new(config.upload_download_max_concurrent)),
            by_ip: Arc::new(DashMap::new()),
            max_per_ip: config.upload_download_max_per_ip,
        };
        match config.upload_mode {
            crate::config::UploadMode::Enabled => Self::Enabled {
                requests: UploadAdmission {
                    semaphore: Arc::new(Semaphore::new(32)),
                    by_ip: Arc::new(DashMap::new()),
                    max_per_ip: 4,
                },
                downloads: downloads(),
            },
            crate::config::UploadMode::DrainReadOnly => Self::DrainReadOnly {
                downloads: downloads(),
            },
            crate::config::UploadMode::Disabled => Self::Disabled,
        }
    }

    fn request_admission(&self) -> Option<&UploadAdmission> {
        match self {
            Self::Enabled { requests, .. } => Some(requests),
            Self::DrainReadOnly { .. } | Self::Disabled => None,
        }
    }

    fn download_admission(&self) -> Option<&UploadAdmission> {
        match self {
            Self::Enabled { downloads, .. } | Self::DrainReadOnly { downloads } => Some(downloads),
            Self::Disabled => None,
        }
    }
}

type PasskeyService =
    crate::services::passkeys::PasskeyService<db::passkeys::PostgresPasskeyRepository>;
type RosterService = crate::services::roster::RosterService<db::roster::PostgresRosterRepository>;
type UploadService = crate::services::upload::UploadService<db::upload::PostgresUploadRepository>;

/// A detached view of a local route for PostgreSQL credential maintenance.
/// Pending bind and resume routes are included so they can be cancelled before
/// their final activation check; no map guard survives the database read.
pub(crate) struct LocalSessionAuthoritySnapshot {
    pub(crate) full_jid: String,
    pub(crate) authority: crate::services::session_authority_sweep::SessionAuthoritySnapshot,
    pub(crate) disconnect: CancellationToken,
}

/// Captured only after instance authority is refreshed, immediately before
/// Redis route leases are renewed. This is deliberately a second snapshot.
pub(crate) struct LocalSessionLeaseSnapshot {
    pub(crate) full_jid: String,
    pub(crate) activity_age_seconds: u64,
    pub(crate) connection_id: uuid::Uuid,
    pub(crate) disconnect: CancellationToken,
}

/// Only the state needed to transfer a live SM resource's presence epoch.
pub(crate) struct SmPresenceEpoch {
    pub(crate) gate: Arc<tokio::sync::Mutex<()>>,
    pub(crate) fallback_suppressed: Arc<DashSet<String>>,
    pub(crate) caps_generation: Arc<AtomicU64>,
}

/// Result of one atomic local SM route-table inspection. Every value is owned
/// before the caller can wait on a gate, durable claim or route-removal signal.
pub(crate) enum SmStagedRouteClaim {
    Inserted,
    Conflict,
    AdoptPresenceEpoch(SmPresenceEpoch),
    Replace {
        connection_id: uuid::Uuid,
        lifecycle: Arc<AtomicU8>,
        disconnect: CancellationToken,
        route_incarnation: Arc<RouteIncarnationSignal>,
    },
}

fn local_session_authority_snapshots_in(
    sessions: &DashMap<String, OnlineSession>,
) -> Vec<LocalSessionAuthoritySnapshot> {
    sessions
        .iter()
        .map(|entry| LocalSessionAuthoritySnapshot {
            full_jid: entry.key().clone(),
            authority: crate::services::session_authority_sweep::SessionAuthoritySnapshot {
                user_id: entry.user_id,
                auth_generation: entry.auth_generation,
                device_id: entry.user_agent_id,
                device_epoch: entry.user_agent_epoch,
            },
            disconnect: entry.disconnect.clone(),
        })
        .collect()
}

fn local_session_lease_snapshots_in(
    sessions: &DashMap<String, OnlineSession>,
) -> Vec<LocalSessionLeaseSnapshot> {
    sessions
        .iter()
        .map(|entry| {
            let activity_age_seconds = entry
                .last_activity
                .read()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .elapsed()
                .as_secs();
            LocalSessionLeaseSnapshot {
                full_jid: entry.key().clone(),
                activity_age_seconds,
                connection_id: entry.connection_id,
                disconnect: entry.disconnect.clone(),
            }
        })
        .collect()
}

fn try_stage_bound_session_in(
    sessions: &DashMap<String, OnlineSession>,
    key: String,
    session: OnlineSession,
) -> bool {
    debug_assert!(!session.routable.load(Ordering::Acquire));
    match sessions.entry(key) {
        dashmap::mapref::entry::Entry::Vacant(entry) => {
            entry.insert(session);
            true
        }
        dashmap::mapref::entry::Entry::Occupied(_) => false,
    }
}

fn stage_sm_resumed_session_in(
    sessions: &DashMap<String, OnlineSession>,
    key: String,
    candidate: OnlineSession,
    claimant_user: uuid::Uuid,
    claimed_sm_id: uuid::Uuid,
    expected_gate: &Arc<tokio::sync::Mutex<()>>,
) -> SmStagedRouteClaim {
    debug_assert!(!candidate.routable.load(Ordering::Acquire));
    match sessions.entry(key) {
        dashmap::mapref::entry::Entry::Vacant(entry) => {
            entry.insert(candidate);
            SmStagedRouteClaim::Inserted
        }
        dashmap::mapref::entry::Entry::Occupied(entry) => {
            let existing = entry.get();
            let existing_sm_id = *existing
                .sm_session_id
                .read()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if !matching_sm_route(
                existing.user_id,
                existing_sm_id,
                claimant_user,
                claimed_sm_id,
            ) {
                SmStagedRouteClaim::Conflict
            } else if !Arc::ptr_eq(expected_gate, &existing.mix_presence_gate) {
                SmStagedRouteClaim::AdoptPresenceEpoch(SmPresenceEpoch {
                    gate: Arc::clone(&existing.mix_presence_gate),
                    fallback_suppressed: Arc::clone(&existing.mix_presence_fallback_suppressed),
                    caps_generation: Arc::clone(&existing.caps_observation_generation),
                })
            } else {
                SmStagedRouteClaim::Replace {
                    connection_id: existing.connection_id,
                    lifecycle: Arc::clone(&existing.lifecycle),
                    disconnect: existing.disconnect.clone(),
                    route_incarnation: Arc::clone(&existing.route_incarnation),
                }
            }
        }
    }
}

enum LocalSessionFence {
    Instance(uuid::Uuid),
    Sm(uuid::Uuid),
    Admin {
        user_id: uuid::Uuid,
        auth_generation: i64,
        connection_id: uuid::Uuid,
    },
}

pub(crate) fn local_caps_route_epoch_matches(
    current_connection_id: uuid::Uuid,
    current_generation: u64,
    routable: bool,
    cancelled: bool,
    lifecycle: u8,
    same_gate: bool,
    expected: LocalCapsEpoch,
) -> bool {
    current_connection_id == expected.connection_id
        && current_generation == expected.generation
        && routable
        && !cancelled
        && lifecycle == 0
        && same_gate
}

pub(crate) fn mix_presence_epoch_is_current(
    current_connection_id: uuid::Uuid,
    expected_connection_id: uuid::Uuid,
    current_caps_generation: u64,
    expected_caps_generation: u64,
    routable: bool,
    available: bool,
    same_gate: bool,
) -> bool {
    current_connection_id == expected_connection_id
        && current_caps_generation == expected_caps_generation
        && routable
        && available
        && same_gate
}

pub(crate) fn mix_presence_fallback_is_suppressed(
    suppressed: &DashSet<String>,
    channel_jid: &str,
) -> bool {
    suppressed.contains("*") || suppressed.contains(channel_jid)
}

pub(crate) fn matching_sm_route(
    existing_user: uuid::Uuid,
    existing_sm_id: Option<uuid::Uuid>,
    claimant_user: uuid::Uuid,
    claimed_sm_id: uuid::Uuid,
) -> bool {
    existing_user == claimant_user && existing_sm_id == Some(claimed_sm_id)
}

fn fence_local_session_in(
    sessions: &DashMap<String, OnlineSession>,
    full_jid: &str,
    fence: LocalSessionFence,
) -> bool {
    fence_local_session_if(sessions, full_jid, |session| match fence {
        LocalSessionFence::Instance(connection_id) => {
            !connection_id.is_nil() && session.connection_id == connection_id
        }
        LocalSessionFence::Sm(sm_session_id) => {
            *session
                .sm_session_id
                .read()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                == Some(sm_session_id)
        }
        LocalSessionFence::Admin {
            user_id,
            auth_generation,
            connection_id,
        } => {
            session.user_id == user_id
                && session.auth_generation == auth_generation
                && session.connection_id == connection_id
        }
    })
}

fn fence_local_session_if(
    sessions: &DashMap<String, OnlineSession>,
    full_jid: &str,
    matches: impl FnOnce(&OnlineSession) -> bool,
) -> bool {
    let Some(session) = sessions.get_mut(full_jid) else {
        return false;
    };
    if !matches(&session) {
        return false;
    }
    // Serialize the fence with two-phase route activation and revocation.
    session.routable.store(false, Ordering::Release);
    session.disconnect.cancel();
    true
}

fn cancel_local_session_if_connection_in(
    sessions: &DashMap<String, OnlineSession>,
    full_jid: &str,
    connection_id: uuid::Uuid,
) -> bool {
    let Some(session) = sessions.get(full_jid) else {
        return false;
    };
    if session.connection_id != connection_id {
        return false;
    }
    session.disconnect.cancel();
    true
}

/// The revocation worker can only fence local routes. It cannot admit,
/// replace, remove, or deliver through a session.
#[derive(Clone)]
pub(crate) struct AccountRevocationRoutes {
    sessions: Arc<DashMap<String, OnlineSession>>,
}

impl AccountRevocationRoutes {
    fn new(sessions: Arc<DashMap<String, OnlineSession>>) -> Self {
        Self { sessions }
    }

    fn revoke_in(
        sessions: &DashMap<String, OnlineSession>,
        user_id: uuid::Uuid,
        bare_account_jid: &str,
        auth_generation_exclusive: Option<i64>,
    ) -> usize {
        let Ok(bare_account_jid) = crate::jid::canonicalize_bare(bare_account_jid) else {
            return 0;
        };
        let mut revoked = 0;
        for entry in sessions.iter_mut() {
            if bare_jid(entry.key()) == bare_account_jid
                && entry.user_id == user_id
                && auth_generation_exclusive
                    .is_none_or(|generation| entry.auth_generation < generation)
            {
                entry.routable.store(false, Ordering::Release);
                entry.disconnect.cancel();
                revoked += 1;
            }
        }
        revoked
    }

    pub(crate) fn revoke(
        &self,
        user_id: uuid::Uuid,
        bare_account_jid: &str,
        auth_generation_exclusive: Option<i64>,
    ) -> usize {
        Self::revoke_in(
            &self.sessions,
            user_id,
            bare_account_jid,
            auth_generation_exclusive,
        )
    }

    pub(crate) fn fence_all(&self) {
        for session in self.sessions.iter_mut() {
            session.routable.store(false, Ordering::Release);
            session.disconnect.cancel();
        }
    }
}

#[cfg(test)]
mod account_revocation_route_tests {
    use super::*;
    use std::time::Instant;

    fn session(user_id: uuid::Uuid, generation: i64, routable: bool) -> OnlineSession {
        let connection_id = uuid::Uuid::new_v4();
        let (sender, _receiver) = tokio::sync::mpsc::channel(1);
        OnlineSession {
            user_id,
            auth_generation: generation,
            user_agent_epoch: None,
            connection_id,
            route_incarnation: RouteIncarnationSignal::new(connection_id),
            lifecycle: Arc::default(),
            metrics_counted: Arc::default(),
            routable: Arc::new(AtomicBool::new(routable)),
            sender: crate::outbound::OutboundSender::new(sender),
            available: Arc::default(),
            mix_presence_gate: Arc::default(),
            mix_presence_fallback_suppressed: Arc::default(),
            caps_observation_generation: Arc::default(),
            carbons: Arc::default(),
            priority: Arc::default(),
            show: Arc::default(),
            blocklist_requested: Arc::default(),
            roster_requested: Arc::default(),
            roster_sync: Arc::default(),
            mix_roster_annotations: Arc::default(),
            privacy_active: Arc::default(),
            privacy_requested: Arc::default(),
            directed_presence: Arc::default(),
            last_presence: Arc::default(),
            ip: None,
            resource: "fixture".into(),
            user_agent_id: None,
            sm_session_id: Arc::default(),
            muc_memberships: Arc::default(),
            connected_at: Instant::now(),
            last_activity: Arc::new(std::sync::RwLock::new(Instant::now())),
            disconnect: tokio_util::sync::CancellationToken::new(),
        }
    }

    #[test]
    fn narrow_revoker_fences_pending_old_generations_but_not_replacements() {
        let sessions = Arc::new(DashMap::new());
        let owner = uuid::Uuid::new_v4();
        sessions.insert("alice@example.test/old".into(), session(owner, 4, true));
        sessions.insert(
            "alice@example.test/pending".into(),
            session(owner, 4, false),
        );
        sessions.insert("alice@example.test/current".into(), session(owner, 5, true));
        sessions.insert(
            "alice@example.test/recreated".into(),
            session(uuid::Uuid::new_v4(), 2, true),
        );
        sessions.insert("bob@example.test/device".into(), session(owner, 1, true));

        let routes = AccountRevocationRoutes::new(Arc::clone(&sessions));
        assert_eq!(routes.revoke(owner, "alice@example.test", Some(5)), 2);
        for key in ["alice@example.test/old", "alice@example.test/pending"] {
            let entry = sessions.get(key).unwrap();
            assert!(!entry.routable.load(Ordering::Acquire));
            assert!(entry.disconnect.is_cancelled());
        }
        for key in [
            "alice@example.test/current",
            "alice@example.test/recreated",
            "bob@example.test/device",
        ] {
            let entry = sessions.get(key).unwrap();
            assert!(entry.routable.load(Ordering::Acquire));
            assert!(!entry.disconnect.is_cancelled());
        }

        routes.fence_all();
        assert!(sessions.iter().all(|entry| {
            !entry.routable.load(Ordering::Acquire) && entry.disconnect.is_cancelled()
        }));
    }

    #[test]
    fn maintenance_snapshots_include_pending_routes_and_do_not_follow_replacements() {
        let sessions = DashMap::new();
        let key = "alice@example.test/phone";
        let user_id = uuid::Uuid::new_v4();
        let device_id = uuid::Uuid::new_v4();
        let mut old = session(user_id, 4, false);
        old.user_agent_id = Some(device_id);
        old.user_agent_epoch = Some(2);
        let old_connection_id = old.connection_id;
        sessions.insert(key.into(), old);

        let authority = local_session_authority_snapshots_in(&sessions);
        assert_eq!(authority.len(), 1);
        assert_eq!(authority[0].full_jid, key);
        assert_eq!(authority[0].authority.user_id, user_id);
        assert_eq!(authority[0].authority.auth_generation, 4);
        assert_eq!(authority[0].authority.device_id, Some(device_id));
        assert_eq!(authority[0].authority.device_epoch, Some(2));

        let replacement = session(user_id, 5, true);
        let replacement_connection_id = replacement.connection_id;
        sessions.insert(key.into(), replacement);
        let lease = local_session_lease_snapshots_in(&sessions);
        assert_eq!(lease.len(), 1);
        assert_eq!(lease[0].connection_id, replacement_connection_id);
        assert_ne!(lease[0].connection_id, old_connection_id);
        authority[0].disconnect.cancel();
        assert!(!sessions.get(key).unwrap().disconnect.is_cancelled());
    }

    #[test]
    fn instance_and_occupancy_controls_cannot_cancel_rebound_routes() {
        let sessions = DashMap::new();
        let key = "alice@example.test/phone";
        let owner = uuid::Uuid::new_v4();
        let old = session(owner, 4, false);
        let old_connection_id = old.connection_id;
        sessions.insert(key.into(), old);

        assert!(!fence_local_session_in(
            &sessions,
            key,
            LocalSessionFence::Instance(uuid::Uuid::nil()),
        ));
        assert!(!fence_local_session_in(
            &sessions,
            key,
            LocalSessionFence::Instance(uuid::Uuid::new_v4()),
        ));
        assert!(!sessions.get(key).unwrap().disconnect.is_cancelled());
        assert!(fence_local_session_in(
            &sessions,
            key,
            LocalSessionFence::Instance(old_connection_id),
        ));
        assert!(sessions.get(key).unwrap().disconnect.is_cancelled());

        let rebound = session(owner, 5, true);
        sessions.insert(key.into(), rebound);
        assert!(!fence_local_session_in(
            &sessions,
            key,
            LocalSessionFence::Instance(old_connection_id),
        ));
        assert!(!cancel_local_session_if_connection_in(
            &sessions,
            key,
            old_connection_id,
        ));
        let current = sessions.get(key).unwrap();
        assert!(current.routable.load(Ordering::Acquire));
        assert!(!current.disconnect.is_cancelled());
    }

    #[test]
    fn sm_and_admin_controls_require_exact_route_identity() {
        let sessions = DashMap::new();
        let key = "alice@example.test/phone";
        let owner = uuid::Uuid::new_v4();
        let sm_session_id = uuid::Uuid::new_v4();
        let live = session(owner, 4, true);
        let connection_id = live.connection_id;
        *live.sm_session_id.write().unwrap() = Some(sm_session_id);
        sessions.insert(key.into(), live);

        assert!(!fence_local_session_in(
            &sessions,
            key,
            LocalSessionFence::Sm(uuid::Uuid::new_v4()),
        ));
        for (user_id, generation, connection) in [
            (uuid::Uuid::new_v4(), 4, connection_id),
            (owner, 5, connection_id),
            (owner, 4, uuid::Uuid::new_v4()),
        ] {
            assert!(!fence_local_session_in(
                &sessions,
                key,
                LocalSessionFence::Admin {
                    user_id,
                    auth_generation: generation,
                    connection_id: connection,
                },
            ));
        }
        assert!(sessions.get(key).unwrap().routable.load(Ordering::Acquire));
        assert!(!sessions.get(key).unwrap().disconnect.is_cancelled());
        assert!(fence_local_session_in(
            &sessions,
            key,
            LocalSessionFence::Admin {
                user_id: owner,
                auth_generation: 4,
                connection_id,
            },
        ));
        assert!(!sessions.get(key).unwrap().routable.load(Ordering::Acquire));

        let rebound = session(owner, 5, true);
        sessions.insert(key.into(), rebound);
        assert!(!fence_local_session_in(
            &sessions,
            key,
            LocalSessionFence::Sm(sm_session_id),
        ));
        assert!(!sessions.get(key).unwrap().disconnect.is_cancelled());
        *sessions.get(key).unwrap().sm_session_id.write().unwrap() = Some(sm_session_id);
        assert!(fence_local_session_in(
            &sessions,
            key,
            LocalSessionFence::Sm(sm_session_id),
        ));
        assert!(!sessions.get(key).unwrap().routable.load(Ordering::Acquire));
    }

    #[test]
    fn staged_bind_reservation_rejects_a_second_connection() {
        let sessions = DashMap::new();
        let key = "alice@example.test/phone";
        let owner = uuid::Uuid::new_v4();
        let first = session(owner, 4, false);
        let first_connection = first.connection_id;
        assert!(try_stage_bound_session_in(&sessions, key.into(), first));
        assert!(!try_stage_bound_session_in(
            &sessions,
            key.into(),
            session(owner, 4, false),
        ));
        assert_eq!(sessions.get(key).unwrap().connection_id, first_connection);
        assert!(!sessions.get(key).unwrap().routable.load(Ordering::Acquire));
    }

    #[test]
    fn sm_takeover_inspection_preserves_exact_owner_and_presence_gate() {
        let sessions = DashMap::new();
        let key = "alice@example.test/phone";
        let owner = uuid::Uuid::new_v4();
        let sm_id = uuid::Uuid::new_v4();
        let old = session(owner, 4, true);
        let old_connection = old.connection_id;
        *old.sm_session_id.write().unwrap() = Some(sm_id);
        let old_gate = Arc::clone(&old.mix_presence_gate);
        let old_signal = Arc::clone(&old.route_incarnation);
        sessions.insert(key.into(), old);
        let candidate = || session(owner, 4, false);

        assert!(matches!(
            stage_sm_resumed_session_in(
                &sessions,
                key.into(),
                candidate(),
                uuid::Uuid::new_v4(),
                sm_id,
                &old_gate,
            ),
            SmStagedRouteClaim::Conflict
        ));
        assert!(matches!(
            stage_sm_resumed_session_in(
                &sessions,
                key.into(),
                candidate(),
                owner,
                uuid::Uuid::new_v4(),
                &old_gate,
            ),
            SmStagedRouteClaim::Conflict
        ));
        let other_gate = Arc::new(tokio::sync::Mutex::new(()));
        let SmStagedRouteClaim::AdoptPresenceEpoch(epoch) = stage_sm_resumed_session_in(
            &sessions,
            key.into(),
            candidate(),
            owner,
            sm_id,
            &other_gate,
        ) else {
            panic!("SM takeover must adopt the current resource gate");
        };
        assert!(Arc::ptr_eq(&epoch.gate, &old_gate));
        let SmStagedRouteClaim::Replace {
            connection_id,
            route_incarnation,
            ..
        } = stage_sm_resumed_session_in(
            &sessions,
            key.into(),
            candidate(),
            owner,
            sm_id,
            &old_gate,
        )
        else {
            panic!("SM takeover must name the exact old connection");
        };
        assert_eq!(connection_id, old_connection);
        assert!(Arc::ptr_eq(&route_incarnation, &old_signal));
        assert_eq!(sessions.get(key).unwrap().connection_id, old_connection);

        let vacant = DashMap::new();
        assert!(matches!(
            stage_sm_resumed_session_in(&vacant, key.into(), candidate(), owner, sm_id, &old_gate,),
            SmStagedRouteClaim::Inserted
        ));
        assert_eq!(vacant.len(), 1);
    }
}

/// Private observability capability. It contains only read-only live probes
/// and the existing typed persistence service, never AppState or a mutable
/// cluster, worker, connection, upload, or SM owner.
pub(crate) struct ReadinessContext {
    connection: crate::connection_actors::ConnectionAdmissionReadiness,
    sm: crate::services::sm_capacity::SmMemoryReadiness,
    upload: crate::services::upload_safety::UploadSafetyReadiness,
    cluster: crate::cluster::ClusterReadinessProbe,
    workers: crate::workers::WorkerReadinessProbe,
    abuse_key_deployment: Option<db::AbuseKeyDeploymentIdentity>,
    persistence: crate::services::readiness::ReadinessService<
        db::readiness_repository::PostgresReadinessRepository,
    >,
}

impl ReadinessContext {
    pub(crate) fn connection_accepting(&self) -> bool {
        self.connection.is_accepting()
    }

    pub(crate) fn sm_ready(&self) -> bool {
        self.sm.is_ready()
    }

    pub(crate) fn upload_state(&self) -> crate::services::upload_safety::UploadSafetyState {
        self.upload.state()
    }

    pub(crate) fn cluster_error(&self) -> Option<String> {
        self.cluster.readiness_error()
    }

    pub(crate) fn worker_error(&self) -> Option<String> {
        self.workers.readiness_error()
    }

    pub(crate) fn cluster_authority_snapshot(
        &self,
    ) -> Option<crate::cluster::ClusterReadinessAuthority> {
        self.cluster.authority_snapshot()
    }

    pub(crate) async fn validate_persistence(
        &self,
        cluster_authority: Option<&crate::cluster::ClusterReadinessAuthority>,
    ) -> anyhow::Result<()> {
        self.persistence
            .validate_persistence(self.abuse_key_deployment.as_ref(), cluster_authority)
            .await
    }
}

#[derive(Clone, Copy)]
pub(crate) struct OfflineDeliveryLimits {
    pub(crate) max_messages: i64,
    pub(crate) max_bytes: i64,
    pub(crate) ttl_days: i64,
}

#[derive(Clone, Copy)]
pub(crate) struct SmBufferLimits {
    pub(crate) max_unacked_stanzas: usize,
    pub(crate) max_unacked_bytes: usize,
    pub(crate) max_snapshot_bytes: usize,
}

#[derive(Clone, Copy)]
pub(crate) struct SmSessionPolicy {
    pub(crate) require_same_device: bool,
    pub(crate) resume_timeout_seconds: u64,
    pub(crate) live_lease_seconds: u64,
    pub(crate) claim_lease_seconds: u64,
    pub(crate) max_per_account: usize,
    pub(crate) max_global: usize,
}

#[derive(Clone, Copy)]
pub(crate) struct BoshPolicy {
    pub(crate) max_wait_seconds: u64,
    pub(crate) inactivity_seconds: u64,
    pub(crate) polling_seconds: u64,
    pub(crate) max_pause_seconds: u64,
    pub(crate) body_read_timeout_seconds: u64,
    pub(crate) max_request_bytes: usize,
    pub(crate) max_response_bytes: usize,
    pub(crate) max_stanzas_per_request: usize,
    pub(crate) max_output_stanzas: usize,
    pub(crate) max_output_bytes: usize,
}

#[derive(Clone, Copy)]
pub(crate) struct ComponentRuntimePolicy {
    pub(crate) enabled: bool,
    pub(crate) max_connections: usize,
    pub(crate) handshake_timeout: Duration,
    pub(crate) queue_capacity: usize,
}

#[derive(Clone, Copy)]
pub(crate) struct RuntimeListenerPolicy {
    pub(crate) xmpp: std::net::SocketAddr,
    pub(crate) xmpps: std::net::SocketAddr,
    pub(crate) http: std::net::SocketAddr,
    pub(crate) metrics: std::net::SocketAddr,
    pub(crate) admin: Option<std::net::SocketAddr>,
    pub(crate) s2s: Option<std::net::SocketAddr>,
    pub(crate) s2s_tls: Option<std::net::SocketAddr>,
    pub(crate) component: std::net::SocketAddr,
}

#[derive(Clone, Copy)]
pub(crate) struct PubSubOwnerLimits {
    pub(crate) max_nodes: i64,
    pub(crate) max_storage_bytes: i64,
}

#[derive(Clone, Copy)]
pub(crate) struct Sasl2FastTokenPolicy {
    pub(crate) enabled: bool,
    pub(crate) rotation_days: i64,
    pub(crate) ttl_days: i64,
    pub(crate) strong_reauth_max_days: i64,
}

#[derive(Clone, Copy)]
pub(crate) struct AdminScramPolicy {
    pub(crate) iterations: u32,
    pub(crate) sha1_enabled: bool,
}

#[derive(Clone, Copy)]
pub(crate) struct UploadSlotLimits {
    pub(crate) max_file_bytes: u64,
    pub(crate) max_files_per_user: i64,
    pub(crate) max_bytes_per_user: i64,
    pub(crate) max_retained_files: i64,
    pub(crate) max_retained_bytes: i64,
    pub(crate) max_pending_jobs: i64,
}

pub struct AppState {
    config: Config,
    pool: PgPool,
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
    pub cluster: crate::cluster::ClusterManager,
    account_revocation_consumer_service:
        crate::services::account_revocation_consumer::AccountRevocationConsumerService<
            db::account_revocation_repository::PostgresAccountRevocationRepository,
        >,
    session_authority_sweep_service:
        crate::services::session_authority_sweep::SessionAuthoritySweepService<
            db::session_authority_sweep_repository::PostgresSessionAuthoritySweepRepository,
        >,
    session_termination_authority_service:
        crate::services::session_termination_authority::SessionTerminationAuthorityService<
            db::session_termination_authority_repository::PostgresSessionTerminationAuthorityRepository,
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
    sm_suspension_recovery: Arc<crate::services::session_cleanup::SmSuspensionRecoveryQueue>,
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
    operation_muc_destroy_service: crate::services::operation_muc_destroy::MucDestroyService<
        db::operation_muc_destroy_repository::PostgresMucDestroyRepository,
    >,
    locked_muc_expiry_service: crate::services::locked_muc_expiry::LockedMucExpiryService<
        db::locked_muc_expiry_repository::PostgresLockedMucExpiryRepository,
    >,
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
    upload_startup_audits: Arc<crate::upload_worker::StartupAuditHandoff>,
    federation_outbox: FederationRouter,
    /// Full XEP-0114/XEP-0225 authentication records. `config.components`
    /// retains only redacted routing/discovery metadata after construction.
    component_credentials: Arc<[crate::config::ComponentCredential]>,
    components: crate::components::ComponentRegistry,
    s2s_connection_registry: crate::s2s::S2sConnectionRegistry,
    /// Shared TTL-aware resolver for SRV, CNAME, A and AAAA federation lookups.
    s2s_dns_resolver: TokioResolver,
    /// Separate locally validating DNSSEC resolver for RFC 7712. It never
    /// consults the hosts file and is absent when DANE is disabled, ensuring
    /// that an ordinary resolver answer can never be mistaken for secure
    /// TLSA material.
    s2s_dnssec_resolver: Option<TokioResolver>,
    /// XEP-0403 IQ relay correlations. Keys are server-generated opaque IQ
    /// ids, never client-controlled ids; entries are bounded and short-lived.
    pending_mix_iq: northstar_protocol_runtime::mix::MixIqRelayIndex,
    /// XEP-0115 entries are inserted only after the advertised verification
    /// string has been recomputed successfully. Unverified payloads never
    /// enter this shared cache.
    caps_cache: northstar_protocol_runtime::caps::CapsCacheIndex,
    caps_by_jid: northstar_protocol_runtime::caps::CapsResourceIndex,
    pending_caps: northstar_protocol_runtime::caps::PendingCapsIndex,
    /// Cross-stream ordering authority for one authenticated federated full
    /// JID's capability lifecycle. Weak, self-cleaning entries exist only
    /// while an observer or response owns or waits for the resource.
    federated_caps_gates: northstar_protocol_runtime::caps::FederatedCapsGateIndex,
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
    connection_actors: crate::connection_actors::ConnectionActorRegistry,
    challenge_issue_service: crate::services::challenge_issuance::ChallengeIssueService<
        db::challenge_issuance_repository::PostgresChallengeRepository,
    >,
    challenge_cleanup_service: crate::services::challenge_issuance::ChallengeCleanupService<
        db::challenge_issuance_repository::PostgresChallengeRepository,
    >,
    sasl_login_abuse_service: crate::services::login_abuse::SaslLoginAbuseService<
        db::login_abuse_repository::PostgresSaslLoginAbuseRepository,
    >,
    passkey_login_abuse_service: Arc<crate::services::login_abuse::PasskeyLoginAbuseService<
        db::login_abuse_repository::PostgresPasskeyLoginAbuseRepository,
    >>,
    /// Public, irreversible key IDs and the configured generation used by the
    /// readiness path to detect a node that drifted from PostgreSQL authority.
    abuse_key_deployment: Option<db::AbuseKeyDeploymentIdentity>,
    started_at: Instant,
    process_started_at: chrono::DateTime<chrono::Utc>,
    tls_context: crate::tls::TlsContext,
    /// Linearization gate for the federation kill switch. Application
    /// stanza writes hold a read guard only across the socket write; island
    /// mode transitions take the exclusive guard.
    federation_write_policy: FederationWritePolicy,
    registration_closed: Arc<AtomicBool>,
    /// Durable XEP-0133 federation policy overlay. Static environment policy
    /// remains the outer ceiling; runtime rules may only restrict it further.
    federation_runtime_policy: arc_swap::ArcSwap<RuntimeFederationPolicy>,
    service_shutdown: std::sync::OnceLock<CancellationToken>,
    workers: Arc<crate::workers::WorkerRegistry>,
}

#[derive(Default)]
struct RuntimeFederationPolicy {
    blacklist: std::collections::HashSet<String>,
    whitelist: std::collections::HashSet<String>,
}

fn federation_rule_matches(rule: &str, entity: &crate::jid::CanonicalJid) -> bool {
    crate::jid::CanonicalJid::parse(rule).is_ok_and(|rule| {
        if rule.domainpart() != entity.domainpart() {
            false
        } else if rule.localpart().is_none() {
            true
        } else if rule.resourcepart().is_none() {
            rule.bare() == entity.bare()
        } else {
            rule == *entity
        }
    })
}

fn service_control_applies(
    process_started_at: chrono::DateTime<chrono::Utc>,
    control: &db::DurableServiceControl,
) -> bool {
    control
        .fired_at
        .is_some_and(|fired_at| process_started_at < fired_at)
}

#[derive(Debug, Eq, PartialEq)]
enum SessionLookup {
    Bare(String),
    Full(String),
}

fn session_lookup(jid: &str) -> Option<SessionLookup> {
    let jid = crate::jid::CanonicalJid::parse(jid).ok()?;
    Some(if jid.resourcepart().is_some() {
        SessionLookup::Full(jid.to_string())
    } else {
        SessionLookup::Bare(jid.bare())
    })
}

fn api_keyrings(
    current_secret: &[u8],
    previous_secret: Option<&[u8]>,
) -> anyhow::Result<(db::ApiControlKeyring, crate::api::cursor::CursorKeyring)> {
    let api_control = db::ApiControlKeyring::new(current_secret, previous_secret)
        .context("failed to derive API control keys")?;
    let api_cursor = crate::api::cursor::CursorKeyring::new(current_secret, previous_secret)
        .context("failed to derive API cursor keys")?;
    Ok((api_control, api_cursor))
}

fn encode_api_control_entropy(mut entropy: [u8; 32]) -> [u8; 64] {
    const LOWER_HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = [0_u8; 64];
    for (index, byte) in entropy.iter().copied().enumerate() {
        encoded[index * 2] = LOWER_HEX[usize::from(byte >> 4)];
        encoded[index * 2 + 1] = LOWER_HEX[usize::from(byte & 0x0f)];
    }
    entropy.zeroize();
    encoded
}

fn ephemeral_api_control_secret() -> [u8; 64] {
    use rand::RngCore;

    let mut entropy = [0_u8; 32];
    rand::thread_rng().fill_bytes(&mut entropy);
    encode_api_control_entropy(entropy)
}

impl AppState {
    pub(crate) fn record_http_rate_limited(&self) {
        self.metrics
            .rate_limited_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_http_authentication_backend_failure(&self) {
        self.metrics
            .authentication_backend_failures_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn start_upload_operation_timer(&self) -> crate::metrics::DurationTimer<'_> {
        self.metrics.upload_operation_duration_seconds.start_timer()
    }

    pub(crate) fn record_bosh_session_opened(&self) {
        self.metrics
            .bosh_sessions_total
            .fetch_add(1, Ordering::Relaxed);
        self.metrics
            .bosh_sessions_active
            .fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_bosh_session_closed(&self) {
        self.metrics
            .bosh_sessions_active
            .fetch_sub(1, Ordering::Relaxed);
    }

    pub(crate) fn record_c2s_tcp_connection(&self) {
        self.metrics
            .tcp_connections_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_c2s_websocket_connection(&self) {
        self.metrics
            .websocket_connections_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_c2s_backpressure_disconnect(&self) {
        self.metrics
            .c2s_backpressure_disconnects_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_cluster_presence_probe_failure(&self) {
        self.metrics
            .cluster_presence_probe_failures_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_tls_reload_failure(&self) {
        self.metrics
            .tls_reload_failures_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_tls_reload_revocations(&self, outcome: &crate::tls::TlsReloadOutcome) {
        self.metrics
            .tls_revocation_rechecks_total
            .fetch_add(outcome.evaluated_sessions, Ordering::Relaxed);
        self.metrics
            .tls_revocation_recheck_inconclusive_total
            .fetch_add(outcome.inconclusive_rechecks, Ordering::Relaxed);
        self.metrics
            .tls_revoked_sessions_drained_total
            .fetch_add(outcome.drained_total(), Ordering::Relaxed);
        self.metrics
            .tls_revoked_c2s_external_sessions_drained_total
            .fetch_add(outcome.drained_c2s_external, Ordering::Relaxed);
        self.metrics
            .tls_revoked_inbound_s2s_external_sessions_drained_total
            .fetch_add(outcome.drained_inbound_s2s_external, Ordering::Relaxed);
        self.metrics
            .tls_revoked_outbound_s2s_external_sessions_drained_total
            .fetch_add(outcome.drained_outbound_s2s_external, Ordering::Relaxed);
    }

    pub(crate) fn record_session_finalization_started(&self) {
        self.metrics
            .session_finalizations_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_session_finalization_failures(&self, failures: usize) {
        self.metrics
            .session_finalization_failures_total
            .fetch_add(failures as u64, Ordering::Relaxed);
    }

    pub(crate) fn start_cluster_redis_operation_timer(&self) -> crate::metrics::DurationTimer<'_> {
        self.metrics.redis_operation_duration_seconds.start_timer()
    }

    pub(crate) fn record_cluster_online_queue_acceptance(&self, durable: bool) {
        let counter = if durable {
            &self.metrics.online_queue_durable_acceptances_total
        } else {
            &self.metrics.online_queue_volatile_acceptances_total
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn federation_outbox(&self) -> &FederationRouter {
        &self.federation_outbox
    }

    pub(crate) fn cluster_authority_service(
        &self,
    ) -> crate::services::cluster_authority::ClusterAuthorityService<
        db::cluster_authority_repository::PostgresClusterAuthorityRepository,
    > {
        crate::services::cluster_authority::ClusterAuthorityService::new(
            db::cluster_authority_repository::PostgresClusterAuthorityRepository::new(
                self.pool.clone(),
            ),
        )
    }

    pub(crate) fn cluster_muc_occupancy_maintenance_service(
        &self,
    ) -> crate::services::muc::ClusterMucOccupancyMaintenanceService<
        db::room::PostgresClusterMucOccupancyMaintenanceRepository,
    > {
        crate::services::muc::ClusterMucOccupancyMaintenanceService::new(
            db::room::PostgresClusterMucOccupancyMaintenanceRepository::new(self.pool.clone()),
        )
    }

    pub(crate) fn node_message_contract_verifier(
        &self,
    ) -> crate::services::node_message_contract_verifier::NodeMessageContractVerifier<
        db::node_message_projection_repository::PostgresNodeMessageProjectionRepository,
    > {
        crate::services::node_message_contract_verifier::NodeMessageContractVerifier::new(
            db::node_message_projection_repository::PostgresNodeMessageProjectionRepository::new(
                self.pool.clone(),
            ),
        )
    }

    pub(crate) fn cluster_instance_release_service(
        &self,
    ) -> crate::services::cluster_instance_release::ClusterInstanceReleaseService<
        db::cluster_instance_release_repository::PostgresClusterInstanceReleaseRepository,
    > {
        crate::services::cluster_instance_release::ClusterInstanceReleaseService::new(
            db::cluster_instance_release_repository::PostgresClusterInstanceReleaseRepository::new(
                self.pool.clone(),
            ),
        )
    }

    pub(crate) fn tls_context(&self) -> &crate::tls::TlsContext {
        &self.tls_context
    }

    /// Validated local identity for protocol routing without exposing Config.
    pub(crate) fn local_domain(&self) -> &str {
        &self.config.domain
    }

    pub(crate) fn server_name(&self) -> &str {
        &self.config.server_name
    }

    pub(crate) fn server_info_addresses(&self) -> [(&'static str, &[String]); 6] {
        [
            ("admin-addresses", &self.config.admin_addresses),
            ("abuse-addresses", &self.config.abuse_addresses),
            ("support-addresses", &self.config.support_addresses),
            ("feedback-addresses", &self.config.feedback_addresses),
            ("sales-addresses", &self.config.sales_addresses),
            ("security-addresses", &self.config.security_addresses),
        ]
    }

    pub(crate) fn external_service_discovery_available(&self) -> bool {
        self.config.stun_service.is_some() || self.config.turn_service.is_some()
    }

    pub(crate) fn upload_public_url(&self) -> &str {
        &self.config.public_url
    }

    pub(crate) fn xmpp_external_route_domain_allowed(&self, domain: &str) -> bool {
        self.config.external_route_domain_allowed(domain)
    }

    pub(crate) fn xmpp_component_domain_configured(&self, domain: &str) -> bool {
        self.config.component_domain_configured(domain)
    }

    pub(crate) fn s2s_federation_enabled(&self) -> bool {
        self.config.federation_enabled
    }

    pub(crate) fn s2s_sasl_external_enabled(&self) -> bool {
        self.config.s2s_sasl_external_enabled
    }

    pub(crate) fn s2s_dialback_enabled(&self) -> bool {
        self.config.dialback_enabled
    }

    pub(crate) fn s2s_dane_required(&self) -> bool {
        self.config.federation_dane_mode == crate::s2s::dane::DaneMode::Required
    }

    pub(crate) fn s2s_dane_mode(&self) -> crate::s2s::dane::DaneMode {
        self.config.federation_dane_mode
    }

    pub(crate) fn s2s_dns_override(&self, domain: &str) -> Option<(std::net::SocketAddr, bool)> {
        self.config
            .federation_dns_overrides
            .iter()
            .find(|(candidate, _, _)| {
                crate::jid::prepare_domainpart(candidate).is_ok_and(|candidate| candidate == domain)
            })
            .map(|(_, address, direct_tls)| (*address, *direct_tls))
    }

    pub(crate) fn s2s_private_addresses_allowed(&self) -> bool {
        self.config.federation_allow_private_ips
    }

    pub(crate) fn s2s_component_domain_configured(&self, domain: &str) -> bool {
        self.config.component_domain_configured(domain)
    }

    pub(crate) fn s2s_ping_route_enabled(&self) -> bool {
        self.config.xmpp_extensions.route_enabled(
            northstar_xep_core::StanzaKind::IqGet,
            northstar_xep_0199::NAMESPACE,
            "ping",
        )
    }

    pub(crate) fn xmpp_route_enabled(
        &self,
        stanza: northstar_xep_core::StanzaKind,
        namespace: &str,
        local_name: &str,
    ) -> bool {
        self.config
            .xmpp_extensions
            .route_enabled(stanza, namespace, local_name)
    }

    pub(crate) fn xmpp_extension_enabled(&self, id: northstar_xep_core::XepId) -> bool {
        self.config.xmpp_extensions.enabled(id)
    }

    pub(crate) fn server_disco_features(&self) -> Vec<&'static str> {
        self.config
            .xmpp_extensions
            .server_disco_features()
            .collect()
    }

    pub(crate) fn xmpp_version_includes_os(&self) -> bool {
        self.config.xep_0092_include_os
    }

    pub(crate) fn sm_buffer_limits(&self) -> SmBufferLimits {
        SmBufferLimits {
            max_unacked_stanzas: self.config.sm_max_unacked_stanzas,
            max_unacked_bytes: self.config.sm_max_unacked_bytes,
            max_snapshot_bytes: self.config.sm_max_snapshot_bytes,
        }
    }

    pub(crate) fn bosh_policy(&self) -> BoshPolicy {
        BoshPolicy {
            max_wait_seconds: self.config.bosh_max_wait_seconds,
            inactivity_seconds: self.config.bosh_inactivity_seconds,
            polling_seconds: self.config.bosh_polling_seconds,
            max_pause_seconds: self.config.bosh_max_pause_seconds,
            body_read_timeout_seconds: self.config.bosh_body_read_timeout_seconds,
            max_request_bytes: self.config.bosh_max_request_bytes,
            max_response_bytes: self.config.bosh_max_response_bytes,
            max_stanzas_per_request: self.config.bosh_max_stanzas_per_request,
            max_output_stanzas: self.config.bosh_max_output_stanzas,
            max_output_bytes: self.config.bosh_max_output_bytes,
        }
    }

    pub(crate) fn unauthenticated_timeout(&self) -> Duration {
        Duration::from_secs(self.config.unauthenticated_timeout_seconds)
    }

    pub(crate) fn trusted_proxy_ips(&self) -> &[std::net::IpAddr] {
        &self.config.trusted_proxy_ips
    }

    pub(crate) fn runtime_listener_policy(&self) -> RuntimeListenerPolicy {
        RuntimeListenerPolicy {
            xmpp: self.config.xmpp_bind,
            xmpps: self.config.xmpps_bind,
            http: self.config.http_bind,
            metrics: self.config.metrics_bind,
            admin: self
                .config
                .web_admin_enabled
                .then_some(self.config.web_admin_bind),
            s2s: self
                .config
                .federation_enabled
                .then_some(self.config.s2s_bind),
            s2s_tls: self
                .config
                .federation_enabled
                .then_some(self.config.s2s_tls_bind),
            component: self.config.component_bind,
        }
    }

    pub(crate) fn cluster_workers_enabled(&self) -> bool {
        self.cluster.is_enabled()
    }

    pub(crate) fn cluster_pubsub_listener_transport(
        &self,
    ) -> crate::cluster::ClusterPubsubListenerTransport {
        self.cluster.pubsub_listener_transport()
    }

    pub(crate) fn test_listener_activation_policy(
        &self,
    ) -> crate::test_activation::TestActivationPolicy<'_> {
        crate::test_activation::TestActivationPolicy {
            enabled: self.config.test_listener_activation,
            destination: self.config.test_readiness_file.as_deref(),
            nonce: self.config.test_readiness_nonce.as_deref(),
        }
    }

    pub(crate) fn sm_session_policy(&self) -> SmSessionPolicy {
        SmSessionPolicy {
            require_same_device: self.config.sm_require_same_device,
            resume_timeout_seconds: self.config.sm_resume_timeout_seconds,
            live_lease_seconds: self.config.sm_live_lease_seconds,
            claim_lease_seconds: self.config.sm_claim_lease_seconds,
            max_per_account: self.config.max_sessions_per_account,
            max_global: self.config.sm_max_resumable_sessions,
        }
    }

    pub(crate) fn sm_ip_binding(&self) -> &str {
        &self.config.sm_ip_binding
    }

    pub(crate) fn c2s_resource_bind_timeout_seconds(&self) -> u64 {
        self.config.resource_bind_timeout_seconds
    }

    pub(crate) fn c2s_scram_sha1_enabled(&self) -> bool {
        self.config.scram_sha1_enabled
    }

    pub(crate) fn admin_scram_policy(&self) -> AdminScramPolicy {
        AdminScramPolicy {
            iterations: self.config.scram_iterations,
            sha1_enabled: self.config.scram_sha1_enabled,
        }
    }

    pub(crate) fn admin_activity_idle_seconds(&self) -> u64 {
        self.config.admin_idle_seconds
    }

    pub(crate) fn xmpp_service_control_enabled(&self) -> bool {
        self.config.enable_xmpp_service_control
    }

    pub(crate) fn mix_muc_mirror_enabled(&self) -> bool {
        self.config.mix_muc_mirror_enabled
    }

    pub(crate) fn xmpp_http_upload_enabled(&self) -> bool {
        self.config.upload_mode.admits_new_uploads()
            && self.xmpp_extension_enabled(northstar_xep_0363::XEP_ID)
    }

    pub(crate) fn upload_slot_limits(&self) -> UploadSlotLimits {
        UploadSlotLimits {
            max_file_bytes: self.config.upload_max_bytes,
            max_files_per_user: self.config.upload_max_files_per_user,
            max_bytes_per_user: self.config.upload_max_bytes_per_user,
            max_retained_files: self.config.upload_storage_max_retained_files,
            max_retained_bytes: self.config.upload_storage_max_retained_bytes,
            max_pending_jobs: self.config.upload_storage_max_pending_jobs,
        }
    }

    pub(crate) fn sasl2_fast_token_policy(&self) -> Sasl2FastTokenPolicy {
        Sasl2FastTokenPolicy {
            enabled: self.config.fast_token_enabled,
            rotation_days: self.config.fast_token_rotation_days,
            ttl_days: self.config.fast_token_ttl_days,
            strong_reauth_max_days: self.config.fast_strong_reauth_max_days,
        }
    }

    pub(crate) fn capacity_session_lease_seconds(&self) -> u64 {
        self.config.capacity_session_lease_seconds
    }

    pub(crate) fn pubsub_owner_limits(&self) -> PubSubOwnerLimits {
        PubSubOwnerLimits {
            max_nodes: self.config.pubsub_max_nodes_per_owner,
            max_storage_bytes: self.config.pubsub_max_storage_bytes_per_owner,
        }
    }

    pub(crate) fn pep_account_quotas(&self) -> crate::services::pubsub::PepQuotas {
        crate::services::pubsub::PepQuotas {
            max_nodes: self.config.pep_max_nodes_per_account,
            max_storage_bytes: self.config.pep_max_storage_bytes_per_account,
        }
    }

    pub(crate) fn validate_routed_message(
        &self,
        root: roxmltree::Node<'_, '_>,
    ) -> Result<(), &'static str> {
        crate::xmpp::xml_util::validate_routed_message(root, &self.config.xmpp_extensions)
    }

    pub(crate) fn archive_requires_encryption(&self) -> bool {
        self.config.require_encrypted_archive
    }

    pub(crate) fn muc_mam_retention_days(&self) -> i64 {
        self.config.muc_mam_retention_days
    }

    pub(crate) fn offline_delivery_limits(&self) -> OfflineDeliveryLimits {
        OfflineDeliveryLimits {
            max_messages: self.config.offline_max_messages_per_account,
            max_bytes: self.config.offline_max_bytes_per_account,
            ttl_days: self.config.offline_message_ttl_days,
        }
    }

    pub(crate) fn metrics_context(&self) -> MetricsContext {
        MetricsContext::from_state(self)
    }

    pub(crate) fn account_deletion_recovery_telemetry(
        &self,
    ) -> crate::account_recovery::AccountDeletionRecoveryTelemetry<'_> {
        crate::account_recovery::AccountDeletionRecoveryTelemetry::new(
            &self.metrics.account_deletion_recovery_success_total,
            &self.metrics.account_deletion_recovery_failures_total,
            &self.metrics.account_deletion_recovery_lease_losses_total,
        )
    }

    pub(crate) fn broadcast_routes(&self) -> crate::operation_runtime::LocalBroadcastRoutes {
        crate::operation_runtime::LocalBroadcastRoutes::new(
            Arc::clone(&self.sessions),
            self.config.domain.clone(),
            self.cluster.node_id.clone(),
        )
    }

    pub(crate) fn session_kick_routes(&self) -> crate::operation_runtime::LocalSessionKickRoutes {
        crate::operation_runtime::LocalSessionKickRoutes::new(Arc::clone(&self.sessions))
    }

    pub(crate) fn generation_cleanup_routes(
        &self,
    ) -> crate::operation_runtime::LocalGenerationCleanupRoutes {
        crate::operation_runtime::LocalGenerationCleanupRoutes::new(Arc::clone(&self.sessions))
    }

    pub(crate) fn panic_disconnect_routes(
        &self,
    ) -> crate::operation_runtime::LocalPanicDisconnectRoutes {
        crate::operation_runtime::LocalPanicDisconnectRoutes::new(Arc::clone(&self.sessions))
    }

    pub(crate) fn muc_telemetry(&self) -> crate::xmpp::capabilities::MucTelemetry<'_> {
        crate::xmpp::capabilities::MucTelemetry::new(
            &self.metrics.muc_post_commit_delivery_failures_total,
            &self.metrics.post_accept_side_effect_failures_total,
            &self.metrics.cluster_muc_authority_rejections_total,
            &self.metrics.online_queue_durable_acceptances_total,
            &self.metrics.online_queue_volatile_acceptances_total,
            &self.metrics.messages_routed_total,
            &self.metrics.capacity_reservations_rejected_total,
        )
    }

    pub(crate) fn mix_post_commit_telemetry(
        &self,
    ) -> crate::xmpp::capabilities::MixPostCommitTelemetry<'_> {
        crate::xmpp::capabilities::MixPostCommitTelemetry::new(
            &self.metrics.mix_post_commit_delivery_failures_total,
            &self.metrics.post_accept_side_effect_failures_total,
        )
    }

    pub(crate) fn caps_effect_telemetry(
        &self,
    ) -> crate::xmpp::capabilities::CapsEffectTelemetry<'_> {
        crate::xmpp::capabilities::CapsEffectTelemetry::new(
            &self.metrics.caps_effect_coalesced_total,
            &self.metrics.caps_effect_queue_saturated_total,
            &self.metrics.caps_effect_failures_total,
            &self.metrics.caps_effect_latency_seconds,
        )
    }

    pub(crate) fn presence_probe_telemetry(
        &self,
    ) -> crate::xmpp::capabilities::PresenceProbeTelemetry<'_> {
        crate::xmpp::capabilities::PresenceProbeTelemetry::new(
            &self.metrics.cluster_presence_probe_failures_total,
        )
    }

    pub(crate) fn inbound_stanza_telemetry(
        &self,
    ) -> crate::xmpp::capabilities::InboundStanzaTelemetry<'_> {
        crate::xmpp::capabilities::InboundStanzaTelemetry::new(&self.metrics.stanzas_in_total)
    }

    pub(crate) fn post_accept_failure_telemetry(
        &self,
    ) -> crate::xmpp::capabilities::PostAcceptFailureTelemetry<'_> {
        crate::xmpp::capabilities::PostAcceptFailureTelemetry::new(
            &self.metrics.post_accept_side_effect_failures_total,
        )
    }

    pub(crate) fn push_subscription_telemetry(
        &self,
    ) -> crate::xmpp::capabilities::PushSubscriptionTelemetry<'_> {
        crate::xmpp::capabilities::PushSubscriptionTelemetry::new(
            &self.metrics.rate_limited_total,
            &self.metrics.push_subscriptions_rate_limited_total,
        )
    }

    pub(crate) fn push_delivery_telemetry(
        &self,
    ) -> crate::xmpp::capabilities::PushDeliveryTelemetry<'_> {
        crate::xmpp::capabilities::PushDeliveryTelemetry::new(
            &self.metrics.push_notifications_failed_total,
            &self.metrics.push_notifications_routed_total,
            &self.metrics.push_notifications_attempted_total,
        )
    }

    pub(crate) fn registration_telemetry(
        &self,
    ) -> crate::xmpp::capabilities::RegistrationTelemetry<'_> {
        crate::xmpp::capabilities::RegistrationTelemetry::new(
            &self.metrics.anti_abuse_backend_failures_total,
            &self.metrics.registrations_total,
            &self.metrics.rate_limited_total,
            &self.metrics.capacity_reservations_rejected_total,
        )
    }

    pub(crate) fn account_abuse_telemetry(
        &self,
    ) -> crate::xmpp::capabilities::AccountAbuseTelemetry<'_> {
        crate::xmpp::capabilities::AccountAbuseTelemetry::new(
            &self.metrics.anti_abuse_backend_failures_total,
            &self.metrics.rate_limited_total,
        )
    }

    pub(crate) fn session_bind_telemetry(
        &self,
    ) -> crate::xmpp::capabilities::SessionBindTelemetry<'_> {
        crate::xmpp::capabilities::SessionBindTelemetry::new(
            &self.metrics.capacity_reservations_rejected_total,
            &self.metrics.active_sessions,
        )
    }

    pub(crate) fn sm_session_telemetry(&self) -> crate::xmpp::capabilities::SmSessionTelemetry<'_> {
        crate::xmpp::capabilities::SmSessionTelemetry::new(
            &self.metrics.capacity_reservations_rejected_total,
            &self.metrics.active_sessions,
        )
    }

    pub(crate) fn sasl2_authentication_telemetry(
        &self,
    ) -> crate::xmpp::capabilities::Sasl2AuthenticationTelemetry<'_> {
        crate::xmpp::capabilities::Sasl2AuthenticationTelemetry::new(
            &self.metrics.authentication_duration_seconds,
            &self.metrics.fast_credential_integrity_failures_total,
            &self.metrics.authentication_backend_failures_total,
        )
    }

    pub(crate) fn c2s_authentication_telemetry(
        &self,
    ) -> crate::xmpp::capabilities::C2sAuthenticationTelemetry<'_> {
        crate::xmpp::capabilities::C2sAuthenticationTelemetry::new(
            &self.metrics.authentication_backend_failures_total,
            &self.metrics.fast_credential_integrity_failures_total,
            &self.metrics.authentication_failures_total,
            &self.metrics.rate_limited_total,
        )
    }

    pub(crate) fn outbound_stanza_telemetry(
        &self,
    ) -> crate::xmpp::capabilities::OutboundStanzaTelemetry<'_> {
        crate::xmpp::capabilities::OutboundStanzaTelemetry::new(&self.metrics.stanzas_out_total)
    }

    pub(crate) fn session_drop_fallback_telemetry(
        &self,
    ) -> crate::xmpp::capabilities::SessionDropFallbackTelemetry<'_> {
        crate::xmpp::capabilities::SessionDropFallbackTelemetry::new(
            &self.metrics.session_drop_fallbacks_total,
        )
    }

    pub(crate) fn c2s_post_action_telemetry(
        &self,
    ) -> crate::xmpp::capabilities::PostActionTelemetry<'_> {
        crate::xmpp::capabilities::PostActionTelemetry::new(
            &self.metrics.post_action_tasks_started_total,
            &self.metrics.post_action_tasks_completed_total,
            &self.metrics.post_action_tasks_panicked_total,
            &self.metrics.post_action_tasks_aborted_total,
            &self.metrics.post_action_capacity_rejections_total,
        )
    }

    pub(crate) fn personal_message_telemetry(
        &self,
    ) -> crate::xmpp::capabilities::PersonalMessageTelemetry<'_> {
        crate::xmpp::capabilities::PersonalMessageTelemetry::new(
            crate::xmpp::capabilities::PersonalMessageTelemetryCells {
                routing_duration: &self.metrics.routing_duration_seconds,
                rate_limited: &self.metrics.rate_limited_total,
                abuse_backend_failures: &self.metrics.anti_abuse_backend_failures_total,
                messages_routed: &self.metrics.messages_routed_total,
                post_accept_failures: &self.metrics.post_accept_side_effect_failures_total,
                durable_queue_acceptances: &self.metrics.online_queue_durable_acceptances_total,
                volatile_queue_acceptances: &self.metrics.online_queue_volatile_acceptances_total,
                carbon_delivery_failures: &self.metrics.carbon_post_accept_delivery_failures_total,
                carbon_target_timeouts: &self.metrics.carbon_fanout_target_timeouts_total,
                cluster_legacy_acceptances: &self.metrics.cluster_legacy_delivery_acceptances_total,
            },
        )
    }

    pub(crate) fn federated_muc_telemetry(
        &self,
    ) -> crate::xmpp::capabilities::FederatedMucTelemetry<'_> {
        crate::xmpp::capabilities::FederatedMucTelemetry::new(
            &self.metrics.muc_post_commit_delivery_failures_total,
            &self.metrics.post_accept_side_effect_failures_total,
            &self.metrics.capacity_reservations_rejected_total,
            &self.metrics.online_queue_durable_acceptances_total,
            &self.metrics.online_queue_volatile_acceptances_total,
            &self.metrics.messages_routed_total,
        )
    }

    pub(crate) fn pep_telemetry(&self) -> crate::xmpp::capabilities::PepTelemetry<'_> {
        crate::xmpp::capabilities::PepTelemetry::new(
            &self.metrics.pep_items_published_total,
            &self.metrics.pep_items_retracted_total,
            &self.metrics.pep_retrievals_total,
        )
    }

    pub(crate) fn pubsub_outbox_telemetry(
        &self,
    ) -> crate::xmpp::capabilities::PubSubOutboxTelemetry<'_> {
        crate::xmpp::capabilities::PubSubOutboxTelemetry::new(
            &self.metrics.outbox_delivery_duration_seconds,
            &self.metrics.pubsub_event_outbox_pending_rows,
            &self.metrics.pubsub_event_outbox_pending_bytes,
            &self.metrics.pubsub_event_outbox_dead_letter_rows,
        )
    }

    pub(crate) fn component_telemetry(&self) -> crate::components::ComponentTelemetry<'_> {
        crate::components::ComponentTelemetry::new(
            &self.metrics.component_connections_active,
            &self.metrics.outbox_delivery_duration_seconds,
            &self.metrics.component_failures_total,
            &self.metrics.component_deliveries_total,
            &self.metrics.s2s_outbox_lease_lost_total,
        )
    }

    pub(crate) fn s2s_online_queue_telemetry(
        &self,
    ) -> crate::s2s::telemetry::OnlineQueueAcceptanceTelemetry<'_> {
        crate::s2s::telemetry::OnlineQueueAcceptanceTelemetry::new(
            &self.metrics.online_queue_durable_acceptances_total,
            &self.metrics.online_queue_volatile_acceptances_total,
        )
    }

    pub(crate) fn s2s_accepted_history_telemetry(
        &self,
    ) -> crate::s2s::telemetry::AcceptedHistoryTelemetry<'_> {
        crate::s2s::telemetry::AcceptedHistoryTelemetry::new(
            &self.metrics.post_accept_side_effect_failures_total,
        )
    }

    pub(crate) fn s2s_outbox_delivery_telemetry(
        &self,
    ) -> crate::s2s::telemetry::OutboxDeliveryTelemetry<'_> {
        crate::s2s::telemetry::OutboxDeliveryTelemetry::new(
            &self.metrics.outbox_delivery_duration_seconds,
        )
    }

    pub(crate) fn s2s_inbound_connection_telemetry(
        &self,
    ) -> crate::s2s::telemetry::InboundConnectionTelemetry<'_> {
        crate::s2s::telemetry::InboundConnectionTelemetry::new(
            &self.metrics.federation_inbound_connections_total,
            &self.metrics.federation_inbound_active,
        )
    }

    pub(crate) fn s2s_inbound_delivery_telemetry(
        &self,
    ) -> crate::s2s::telemetry::InboundDeliveryTelemetry<'_> {
        crate::s2s::telemetry::InboundDeliveryTelemetry::new(
            &self.metrics.post_accept_side_effect_failures_total,
            &self.metrics.messages_routed_total,
        )
    }

    pub(crate) fn s2s_outbound_disposition_telemetry(
        &self,
    ) -> crate::s2s::telemetry::OutboundDispositionTelemetry<'_> {
        crate::s2s::telemetry::OutboundDispositionTelemetry::new(
            &self.metrics.federation_failures_total,
            &self.metrics.s2s_outbox_lease_lost_total,
            &self.metrics.federation_outbound_deliveries_total,
            &self.metrics.s2s_outbox_permanent_failures_total,
            &self.metrics.s2s_outbox_expired_total,
            &self.metrics.s2s_outbox_retries_total,
        )
    }

    pub(crate) fn background_housekeeping_counters(
        &self,
    ) -> crate::services::background_housekeeping::BackgroundHousekeepingCounters {
        crate::services::background_housekeeping::BackgroundHousekeepingCounters::new(
            Arc::clone(&self.metrics.retention_moderation_cases_deleted_total),
            Arc::clone(&self.metrics.background_maintenance_failures_total),
        )
    }

    pub(crate) fn background_housekeeping_context(
        &self,
        counters: crate::services::background_housekeeping::BackgroundHousekeepingCounters,
    ) -> crate::services::background_housekeeping::BackgroundHousekeepingContext<
        db::background_housekeeping_repository::PostgresBackgroundHousekeepingRepository,
    > {
        crate::services::background_housekeeping::BackgroundHousekeepingContext::new(
            db::background_housekeeping_repository::PostgresBackgroundHousekeepingRepository::new(
                self.pool.clone(),
            ),
            self.config.moderation_retention_days,
            self.config.retention_cleanup_batch_size,
            counters,
        )
    }

    pub(crate) fn retention_context(
        &self,
    ) -> crate::retention::RetentionContext<db::retention::PostgresMaintenanceRepository> {
        crate::retention::RetentionContext::new(
            db::retention::PostgresMaintenanceRepository::new(self.pool.clone()),
            crate::retention::RetentionPolicy::from_config(&self.config),
            crate::retention::RetentionCounters::from_metrics(&self.metrics),
        )
    }

    pub(crate) fn retention_worker_max_silence(&self) -> Duration {
        Duration::from_secs(
            self.config
                .retention_cleanup_interval_seconds
                .saturating_mul(2)
                .saturating_add(60),
        )
    }

    pub(crate) fn subscription_cleanup_context(
        &self,
    ) -> crate::subscription_cleanup::SubscriptionCleanupContext<
        db::retention::PostgresMaintenanceRepository,
    > {
        crate::subscription_cleanup::SubscriptionCleanupContext::new(
            db::retention::PostgresMaintenanceRepository::new(self.pool.clone()),
            Arc::clone(&self.metrics.subscription_cleanup),
        )
    }

    pub(crate) fn abuse_key_authority_probe(
        &self,
    ) -> crate::services::readiness::AbuseKeyAuthorityProbe<
        db::readiness_repository::PostgresReadinessRepository,
    > {
        self.readiness_service.abuse_key_authority_probe()
    }

    pub(crate) fn readiness_context(&self) -> ReadinessContext {
        ReadinessContext {
            connection: self.connection_actors.readiness_probe(),
            sm: self.sm_memory_governor.readiness_probe(),
            upload: self.upload_safety_gate.readiness_probe(),
            cluster: self.cluster.readiness_probe(),
            workers: self.workers.readiness_probe(),
            abuse_key_deployment: self.abuse_key_deployment.clone(),
            persistence: self.readiness_service.clone(),
        }
    }

    pub(crate) fn http_transport_policy(&self) -> HttpTransportPolicy {
        HttpTransportPolicy::new(
            self.config.trusted_proxy_ips.clone(),
            Arc::clone(&self.metrics),
        )
    }

    pub(crate) fn admin_gateway_verifier(&self) -> AdminGatewayVerifier {
        AdminGatewayVerifier::new(self.web_admin_gateway_token.clone())
    }

    pub(crate) fn capacity_lease_renewal_context(&self) -> CapacityLeaseRenewalContext {
        capacity_maintenance::CapacityLeaseRenewalContext::new(
            crate::services::capacity_maintenance::CapacityMaintenanceService::new(
                db::capacity_maintenance_repository::PostgresCapacityMaintenanceRepository::new(
                    self.pool.clone(),
                ),
            ),
            Arc::clone(&self.sessions),
            Arc::clone(&self.metrics),
            Duration::from_secs(self.config.capacity_session_heartbeat_seconds),
            self.config.capacity_session_lease_seconds,
        )
    }

    /// Process-local XEP-0124/XEP-0206 session authority. Transport handlers
    /// may submit bounded manager operations but cannot replace the manager.
    pub(crate) fn bosh_manager(&self) -> &crate::bosh::BoshManager {
        self.bosh
            .as_ref()
            .expect("BOSH routes exist only when the capability runtime is enabled")
    }

    /// Cached ordinary DNS resolver used only by the federation discovery
    /// layer. Keeping it private prevents unrelated code from bypassing the
    /// S2S endpoint-validation path.
    pub(crate) fn s2s_dns_resolver(&self) -> &TokioResolver {
        &self.s2s_dns_resolver
    }

    /// Locally validating resolver dedicated to DANE policy construction.
    pub(crate) fn s2s_dnssec_resolver(&self) -> Option<&TokioResolver> {
        self.s2s_dnssec_resolver.as_ref()
    }

    /// Admit one bounded authoritative dialback verification without exposing
    /// or allowing replacement of the underlying global semaphore.
    pub(crate) fn try_acquire_dialback_verification(
        &self,
    ) -> std::result::Result<OwnedSemaphorePermit, tokio::sync::TryAcquireError> {
        Arc::clone(&self.dialback_verifications).try_acquire_owned()
    }

    /// Admit one process-local federation connection while keeping the global
    /// capacity semaphore replace-proof and unavailable to unrelated code.
    pub(crate) fn try_acquire_s2s_connection(
        &self,
    ) -> std::result::Result<OwnedSemaphorePermit, tokio::sync::TryAcquireError> {
        Arc::clone(&self.s2s_connections).try_acquire_owned()
    }

    /// Wait for one bounded outbound federation dial attempt. Returning the
    /// original acquire error preserves the caller's existing timeout and
    /// closed-semaphore diagnostics.
    pub(crate) async fn acquire_s2s_connection_attempt(
        &self,
    ) -> std::result::Result<OwnedSemaphorePermit, tokio::sync::AcquireError> {
        Arc::clone(&self.s2s_connection_attempts)
            .acquire_owned()
            .await
    }

    /// Owner-fenced process-local S2S route registry. Its API returns cloned
    /// senders and value snapshots only; callers cannot obtain DashMap guards.
    pub(crate) fn s2s_connection_registry(&self) -> &crate::s2s::S2sConnectionRegistry {
        &self.s2s_connection_registry
    }

    /// Admit an inbound component socket without exposing the semaphore as a
    /// generally clonable capability.
    pub(crate) fn try_acquire_component_connection(
        &self,
    ) -> std::result::Result<OwnedSemaphorePermit, tokio::sync::TryAcquireError> {
        Arc::clone(&self.component_connections).try_acquire_owned()
    }

    /// Wait for a component slot while preserving cancellation through the
    /// caller's `select!` and the original closed-semaphore error.
    pub(crate) async fn acquire_component_connection(
        &self,
    ) -> std::result::Result<OwnedSemaphorePermit, tokio::sync::AcquireError> {
        Arc::clone(&self.component_connections)
            .acquire_owned()
            .await
    }

    /// Read the federation kill switch with acquire ordering so a caller that
    /// observes an applied value also observes the preceding policy update.
    pub(crate) fn island_mode_enabled(&self) -> bool {
        self.federation_write_policy.enabled()
    }

    /// Apply an authoritative island-mode value with the release ordering used
    /// by runtime administration.
    pub(crate) async fn apply_island_mode(&self, enabled: bool) {
        self.federation_write_policy.apply(enabled).await;
    }

    /// Acquire the application-stanza write boundary and revalidate island
    /// mode after route admission. The caller holds the returned guard over
    /// the socket write, making a completed policy transition linearizable.
    pub(crate) async fn federation_delivery_permit(
        &self,
    ) -> Option<tokio::sync::RwLockReadGuard<'_, ()>> {
        self.federation_write_policy.permit().await
    }

    /// Refresh the cached island-mode value and return the previous value.
    /// Unchanged observations do not wait for socket writes. Actual changes
    /// take the exclusive delivery guard, drain in-flight stanza writes, and
    /// fence queued writers until they can observe the new policy.
    async fn refresh_island_mode(&self, enabled: bool) -> bool {
        self.federation_write_policy.refresh(enabled).await
    }

    /// Read the public-registration kill switch with acquire ordering.
    pub(crate) fn registration_is_closed(&self) -> bool {
        self.config.registration_dependency_locked()
            || self.registration_closed.load(Ordering::Acquire)
    }

    pub(crate) fn registration_mode(&self) -> crate::config::RegistrationMode {
        if self.registration_is_closed() {
            crate::config::RegistrationMode::Closed
        } else {
            self.config.configured_registration_mode()
        }
    }

    pub(crate) fn registration_requires_invitation(&self) -> bool {
        self.registration_mode() == crate::config::RegistrationMode::InvitationOnly
    }

    pub(crate) fn http_registration_availability(
        &self,
    ) -> crate::services::account::HttpRegistrationAvailability {
        crate::services::account::HttpRegistrationAvailability::new(
            Arc::clone(&self.registration_closed),
            self.config.registration_dependency_locked(),
            self.config.configured_registration_mode()
                == crate::config::RegistrationMode::InvitationOnly,
        )
    }

    /// Apply the authoritative registration setting with release ordering.
    pub(crate) fn apply_registration_closed(&self, closed: bool) {
        self.registration_closed.store(
            closed || self.config.registration_dependency_locked(),
            Ordering::Release,
        );
    }

    /// Evaluate one resource's session-local XEP-0016 selection (or the
    /// account default when no active list is selected). Callers must apply
    /// XEP-0191 first; a blocking hit is never overridden by an allow rule.
    /// Stanza paths that still hold a storage-level kind convert it at this
    /// boundary; the service layer owns the mapping.
    pub async fn privacy_allows_session(
        &self,
        session: &OnlineSession,
        peer: &str,
        kind: impl Into<crate::services::privacy::PrivacyStanzaKind>,
    ) -> anyhow::Result<bool> {
        let active = session
            .privacy_active
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        self.message_service
            .privacy_allows_session(
                session.user_id,
                session.connection_id,
                active.as_deref(),
                peer,
                kind.into(),
            )
            .await
    }

    pub async fn new(
        mut config: Config,
        pool: PgPool,
        federation: FederationRouter,
        components: crate::components::ComponentRegistry,
        runtime_control_connection: PoolConnection<Postgres>,
        worker_cancel: CancellationToken,
    ) -> anyhow::Result<Arc<Self>> {
        // This one-shot credential was consumed by ensure_bootstrap_admin
        // before AppState construction. Never retain it on shared state.
        if let Some(mut password) = config.raw.bootstrap_admin_password.take() {
            password.zeroize();
        }
        let metrics_bearer_token = config.metrics_bearer_token.take();
        let web_admin_gateway_token = config.web_admin_gateway_token.take();
        let component_credentials: Arc<[crate::config::ComponentCredential]> =
            std::mem::take(&mut config.components).into();
        config.components = component_credentials
            .iter()
            .cloned()
            .map(|mut credential| {
                credential.secret_value = None;
                credential.secret_file = None;
                credential.secret_sha256.zeroize();
                credential
            })
            .collect();
        let mut previous_api_control_secret = config.api_control_previous_secret.take();
        let (api_control, api_cursor) = if let Some(mut current_secret) =
            config.api_control_secret.take()
        {
            let keyrings = api_keyrings(
                current_secret.as_bytes(),
                previous_api_control_secret.as_deref().map(str::as_bytes),
            );
            current_secret.zeroize();
            if let Some(previous_secret) = &mut previous_api_control_secret {
                previous_secret.zeroize();
            }
            keyrings?
        } else {
            anyhow::ensure!(
                config.api_control_allow_ephemeral
                    && config.redis_url.is_none()
                    && config.http_bind.ip().is_loopback()
                    && (!config.web_admin_enabled || config.web_admin_bind.ip().is_loopback())
                    && (config.domain == "localhost"
                        || config.domain.ends_with(".localhost")
                        || config.domain.ends_with(".test")),
                "API_CONTROL_SECRET_FILE is required outside an explicitly opted-in single-node loopback development deployment"
            );
            tracing::warn!(
                "API_CONTROL_SECRET_FILE is unset; REST idempotency and pagination cursors use a process-local key, so encrypted replays and issued cursors will not survive restart"
            );
            // Generate exactly one process-local root secret, then derive the
            // independent API-control and cursor subkeys from it. Generating
            // inside either keyring would make their lifetimes diverge. Encode
            // the 256-bit entropy as lowercase hex because mounted text
            // secrets and both keyrings deliberately reject NUL bytes.
            let mut process_secret = ephemeral_api_control_secret();
            let keyrings = api_keyrings(&process_secret, None);
            process_secret.zeroize();
            keyrings?
        };
        let api_control = Arc::new(api_control);
        let startup_phase = crate::logging::StartupPhase::begin("mix_delivery_capacity_audit");
        db::audit_mix_delivery_capacity_ledger(&pool)
            .await
            .context("MIX delivery capacity ledger failed startup reconciliation")?;
        startup_phase.complete();
        let startup_phase = crate::logging::StartupPhase::begin("mix_pam_capacity_audit");
        db::audit_mix_pam_operation_capacity(&pool)
            .await
            .context("MIX-PAM operation capacity authority failed startup audit")?;
        startup_phase.complete();
        let upload_startup_phase =
            crate::logging::StartupPhase::begin("upload_storage_initialization");
        let upload_startup_audits;
        let (upload_safety_gate, upload_namespace, upload_authority_generation, upload_store) =
            if config.upload_mode.keeps_storage_runtime() {
                let upload_safety_gate = UploadSafetyGate::new();
                let upload_namespace = upload_storage_namespace_id(&config)?;
                let startup_phase =
                    crate::logging::StartupPhase::begin("upload_namespace_and_policy");
                let namespace_generation = db::validate_upload_storage_backend(
                    &pool,
                    &config.upload_storage_backend,
                    &upload_namespace,
                )
                .await
                .context("upload storage backend does not match durable metadata")?;
                let (capacity_policy_generation, recovery_draining) =
                    db::validate_upload_capacity_policy(
                        &pool,
                        config.upload_storage_max_pending_jobs,
                        config.upload_storage_max_retained_files,
                        config.upload_storage_max_retained_bytes,
                    )
                    .await
                    .context(
                        "upload capacity policy does not match durable deployment authority",
                    )?;
                let upload_authority_generation = UploadAuthorityGeneration {
                    namespace: namespace_generation,
                    capacity_policy: capacity_policy_generation,
                };
                startup_phase.complete();
                let startup_phase = crate::logging::StartupPhase::begin("upload_authority_audit");
                let authority_audit_started_at = tokio::time::Instant::now();
                let authority_audit = db::audit_upload_capacity_authority(
                    &pool,
                    config.upload_storage_max_pending_jobs,
                    config.upload_storage_max_retained_files,
                    config.upload_storage_max_retained_bytes,
                )
                .await
                .context("could not prove upload authority catalog and ACL invariants")?;
                if authority_audit.violation_count() != 0 {
                    upload_safety_gate.mark_capacity_authority_unsafe(Arc::<str>::from(format!(
                        "upload authority catalog/ACL audit found {} violations",
                        authority_audit.violation_count()
                    )));
                    anyhow::bail!(
                        "upload authority catalog/ACL audit found {} violations",
                        authority_audit.violation_count()
                    );
                }
                startup_phase.complete();
                let startup_phase =
                    crate::logging::StartupPhase::begin("upload_ledger_reconciliation");
                let ledger_audit_started_at = tokio::time::Instant::now();
                let capacity_reconciliation = db::reconcile_upload_capacity_ledger(&pool)
                    .await
                    .context("could not reconcile upload capacity facts before storage startup")?;
                if capacity_reconciliation.mismatch_count() != 0 {
                    upload_safety_gate.mark_ledger_mismatch(Arc::<str>::from(format!(
                        "upload capacity ledger differs from {} durable facts",
                        capacity_reconciliation.mismatch_count()
                    )));
                    anyhow::bail!(
                        "upload capacity ledger differs from {} durable facts",
                        capacity_reconciliation.mismatch_count()
                    );
                }
                startup_phase.complete();
                upload_safety_gate.establish(upload_authority_generation, recovery_draining);
                let upload_store: Arc<dyn UploadStore> = match config
                    .upload_storage_backend
                    .as_str()
                {
                    "local" => {
                        let local = Arc::new(
                            LocalUploadStore::new(config.upload_dir.clone())
                                .with_safety_gate(Arc::clone(&upload_safety_gate)),
                        );
                        let guarded = Arc::new(GuardedUploadStore::new(
                            local.clone(),
                            Arc::clone(&upload_safety_gate),
                        ));
                        // This bounded local enumeration is retained only for legacy
                        // pre-0091 partials. S3 reconciliation never lists a bucket;
                        // every stage is represented by a PostgreSQL job.
                        let mut abandoned_stages = 0_u64;
                        let startup_stages =
                            tokio::time::timeout(Duration::from_secs(10), local.staging_attempts())
                                .await
                                .context("upload staging scan exceeded its startup time budget")?
                                .context("failed to enumerate upload staging files")?;
                        // Enumeration is bounded above, but every candidate still
                        // needs an authoritative lease lookup and may need one exact
                        // unlink. Keep the complete reconciliation phase under one
                        // wall-clock budget so thousands of crash remnants cannot
                        // hold readiness indefinitely through sequential queries.
                        let startup_cleanup_deadline =
                            tokio::time::Instant::now() + Duration::from_secs(30);
                        for (object_id, claim_token) in startup_stages {
                            let remaining = startup_cleanup_deadline
                            .checked_duration_since(tokio::time::Instant::now())
                            .context(
                                "upload staging reconciliation exceeded its startup time budget",
                            )?;
                            if tokio::time::timeout(
                            remaining,
                            db::upload_claim_is_live(&pool, object_id, claim_token),
                        )
                        .await
                        .context(
                            "upload staging lease verification exceeded its startup time budget",
                        )?
                        .context("failed to verify an upload staging lease")?
                        {
                            continue;
                        }
                            let remaining = startup_cleanup_deadline
                            .checked_duration_since(tokio::time::Instant::now())
                            .context(
                                "upload staging reconciliation exceeded its startup time budget",
                            )?;
                            if tokio::time::timeout(
                                remaining,
                                guarded.abort(
                                    &object_id.to_string(),
                                    &claim_token.to_string(),
                                    None,
                                ),
                            )
                            .await
                            .context("upload staging deletion exceeded its startup time budget")?
                            .context("failed to remove an abandoned upload stage")?
                            {
                                abandoned_stages = abandoned_stages.saturating_add(1);
                            }
                        }
                        if abandoned_stages > 0 {
                            tracing::warn!(
                                abandoned_stages,
                                "removed upload stages left by a previous process"
                            );
                        }
                        guarded
                    }
                    "s3" => {
                        let inner: Arc<dyn UploadStore> = Arc::new(
                            S3UploadStore::new(S3UploadSettings {
                                endpoint: config.upload_s3_endpoint.clone(),
                                region: config.upload_s3_region.clone(),
                                bucket: config
                                    .upload_s3_bucket
                                    .clone()
                                    .context("S3 upload bucket is missing after validation")?,
                                prefix: config.upload_s3_prefix.clone(),
                                path_style: config.upload_s3_path_style,
                                allow_http: config.upload_s3_allow_http,
                                ambient_credentials: config.upload_s3_credential_mode == "ambient",
                                credential_bundle_file: config
                                    .upload_s3_credential_bundle_file
                                    .clone(),
                                access_key_id_file: config.upload_s3_access_key_id_file.clone(),
                                secret_access_key_file: config
                                    .upload_s3_secret_access_key_file
                                    .clone(),
                                session_token_file: config.upload_s3_session_token_file.clone(),
                                sse_kms_key_id_file: config.upload_s3_sse_kms_key_id_file.clone(),
                            })?
                            .with_safety_gate(Arc::clone(&upload_safety_gate)),
                        );
                        Arc::new(GuardedUploadStore::new(
                            inner,
                            Arc::clone(&upload_safety_gate),
                        ))
                    }
                    _ => unreachable!("upload backend was validated by Config"),
                };
                upload_startup_audits =
                    crate::upload_worker::StartupAuditHandoff::after_successful_audits(
                        upload_authority_generation,
                        [
                            config.upload_storage_max_pending_jobs,
                            config.upload_storage_max_retained_files,
                            config.upload_storage_max_retained_bytes,
                        ],
                        authority_audit_started_at,
                        ledger_audit_started_at,
                    );
                (
                    upload_safety_gate,
                    upload_namespace,
                    upload_authority_generation,
                    Some(upload_store),
                )
            } else {
                let durable_upload_state_exists = db::durable_upload_state_exists(&pool)
                    .await
                    .context("could not verify that disabled upload storage is empty")?;
                anyhow::ensure!(
                    !durable_upload_state_exists,
                    "UPLOAD_MODE=disabled requires empty durable upload state; use drain_read_only until historical downloads and cleanup jobs have drained"
                );
                tracing::info!(
                    "upload capability disabled; skipping storage authority, object-store and reconciliation initialization"
                );
                upload_startup_audits = crate::upload_worker::StartupAuditHandoff::default();
                (
                    UploadSafetyGate::disabled(),
                    [0_u8; 32],
                    UploadAuthorityGeneration {
                        namespace: 0,
                        capacity_policy: 0,
                    },
                    None,
                )
            };
        upload_startup_phase.complete();
        let extdisco_service = crate::services::extdisco::ExtDiscoService::new(
            config.domain.clone(),
            config.stun_service.clone(),
            config.turn_service.clone(),
            config.raw.turn_shared_secret.take(),
            config.turn_credentials_ttl_seconds,
            config.turn_credential_requests_per_minute,
        );
        let abuse_state_hmac_key = config.raw.abuse_state_hmac_key.take().map(Zeroizing::new);
        let abuse_state_hmac_previous_key = config
            .raw
            .abuse_state_hmac_previous_key
            .take()
            .map(Zeroizing::new);
        if abuse_state_hmac_key.is_none() {
            let listeners_are_loopback = [
                config.xmpp_bind,
                config.xmpps_bind,
                config.http_bind,
                config.metrics_bind,
                config.s2s_bind,
                config.s2s_tls_bind,
                config.component_bind,
            ]
            .iter()
            .all(|address| address.ip().is_loopback())
                && (!config.web_admin_enabled || config.web_admin_bind.ip().is_loopback());
            anyhow::ensure!(
                config.abuse_state_allow_ephemeral
                    && config.redis_url.is_none()
                    && listeners_are_loopback
                    && (config.domain == "localhost"
                        || config.domain.ends_with(".localhost")
                        || config.domain.ends_with(".test")),
                "ABUSE_STATE_HMAC_KEY_FILE is required unless every listener is loopback-only and ABUSE_STATE_ALLOW_EPHEMERAL=true explicitly enables single-node development mode"
            );
        }
        // The overlap phase deliberately keeps the previous generation as the
        // primary durable writer so old-only nodes can verify challenges and
        // deduplicate admissions.  `retire_previous` is the DB-authorized
        // fence after which every node switches its primary to the new key.
        let write_abuse_artifacts_with_previous =
            abuse_state_hmac_previous_key.is_some() && !config.abuse_state_hmac_retire_previous;
        let abuse = Arc::new(AbuseGuard::new_persistent_for_deployment(
            AbuseConfig {
                base_work_factor: config.pow_base_work_factor,
                max_work_factor: config.pow_max_work_factor,
                window: Duration::from_secs(config.abuse_window_seconds),
                cooldown_step: Duration::from_secs(config.abuse_cooldown_seconds),
                max_wait: Duration::from_secs(config.abuse_max_wait_seconds),
                message_free_burst: config.abuse_message_free_burst,
                approximate_max_device_seconds: config.pow_max_device_seconds,
            },
            pool.clone(),
            abuse_state_hmac_key
                .as_ref()
                .map(|secret| secret.as_bytes()),
            abuse_state_hmac_previous_key
                .as_ref()
                .map(|secret| secret.as_bytes()),
            write_abuse_artifacts_with_previous,
            config.pow_v1_compatibility_until,
        ));
        // Inline key material is accepted only by the explicit disposable
        // loopback development profile. Mounted persistent keys, including
        // every Redis/non-loopback deployment, participate in DB authority.
        let abuse_key_deployment = config.abuse_state_hmac_key_file.as_ref().map(|_| {
            let (current_key_id, previous_key_id) = abuse.deployment_key_ids();
            db::AbuseKeyDeploymentIdentity {
                xmpp_domain: config.domain.clone(),
                epoch: config.abuse_state_hmac_key_epoch,
                current_key_id: current_key_id.to_owned(),
                previous_key_id: previous_key_id.map(str::to_owned),
                retire_previous: config.abuse_state_hmac_retire_previous,
                minimum_overlap: abuse.minimum_key_rotation_overlap(),
            }
        });
        let tls = crate::tls::ReloadableTlsConfig::new(
            &config.tls_cert_path,
            &config.tls_key_path,
            &config.domain,
            config.federation_extra_root_cert_path.as_deref(),
            config.c2s_client_trust_root_cert_path.as_deref(),
            config.federation_crl_path.as_deref(),
            config.c2s_client_crl_path.as_deref(),
        )
        .context("failed to load and validate TLS identity")?;
        let open_registration = config.open_registration;
        let dialback_secret = if let Some(secret) =
            config.raw.dialback_secret.take().map(Zeroizing::new)
        {
            Zeroizing::new(secret.as_bytes().to_vec())
        } else {
            use rand::RngCore;
            let mut secret = Zeroizing::new(vec![0_u8; 32]);
            rand::thread_rng().fill_bytes(&mut secret);
            if config.dialback_enabled {
                tracing::warn!(
                    "DIALBACK_SECRET is unset; using a process-local secret (set a mounted secret for deterministic multi-node operation)"
                );
            }
            secret
        };
        let fast_token_secret = Arc::new(
            if let Some(secret) = config.raw.fast_token_secret.take().map(Zeroizing::new) {
                Zeroizing::new(secret.as_bytes().to_vec())
            } else {
                anyhow::ensure!(
                    config.fast_token_enabled
                        && config.raw.fast_token_allow_ephemeral_for_development,
                    "FAST key is unavailable after configuration validation"
                );
                use rand::RngCore;
                let mut secret = Zeroizing::new(vec![0_u8; 32]);
                rand::thread_rng().fill_bytes(&mut secret);
                tracing::warn!(
                    "explicit loopback development mode is using an ephemeral FAST key; XEP-0484 tokens change on restart"
                );
                secret
            },
        );
        let dummy_scram_secret = Arc::new(if let Some(secret) = config.dummy_scram_secret.take() {
            Zeroizing::new(secret.as_bytes().to_vec())
        } else {
            anyhow::ensure!(
                config.raw.dummy_scram_allow_ephemeral_for_development,
                "dummy SCRAM key is unavailable after configuration validation"
            );
            use rand::RngCore;
            let mut secret = Zeroizing::new(vec![0_u8; 32]);
            rand::thread_rng().fill_bytes(&mut secret);
            tracing::warn!(
                "explicit loopback development mode is using an independent ephemeral dummy SCRAM key; unknown-account challenge material changes on restart"
            );
            secret
        });
        anyhow::ensure!(
            !crate::auth::constant_time_bytes_eq(
                fast_token_secret.as_slice(),
                dummy_scram_secret.as_slice(),
            ),
            "FAST and dummy SCRAM master keys must be independent"
        );
        let client_connections = Arc::new(Semaphore::new(config.max_client_connections));
        let s2s_connections = Arc::new(Semaphore::new(config.max_s2s_connections));
        let s2s_connection_attempts = Arc::new(Semaphore::new(config.max_s2s_connections));
        let component_connections = Arc::new(Semaphore::new(config.max_component_connections));
        let connection_actors =
            crate::connection_actors::ConnectionActorRegistry::for_transport_limits(
                config.max_client_connections,
                config.max_s2s_connections,
                config.max_component_connections,
            )
            .context("configured connection actor capacity is invalid")?;
        let sm_capacity_metrics =
            Arc::new(crate::services::sm_capacity::SmCapacityMetrics::default());
        let sm_memory_governor = crate::services::sm_capacity::SmMemoryGovernor::new(
            config.sm_memory_budget_bytes,
            config.sm_recovery_max_bytes,
            config.sm_recovery_max_jobs,
            config.sm_max_snapshot_bytes,
            Arc::clone(&sm_capacity_metrics),
        )?;
        let (resolver_config, mut resolver_options) =
            read_system_conf().context("failed to read the system DNS resolver configuration")?;
        resolver_options.try_tcp_on_error = true;
        resolver_options.server_ordering_strategy = ServerOrderingStrategy::RoundRobin;
        resolver_options.cache_size = 1024;
        let mut dnssec_options = resolver_options.clone();
        dnssec_options.validate = true;
        dnssec_options.use_hosts_file = ResolveHosts::Never;
        dnssec_options.preserve_intermediates = true;
        dnssec_options.positive_max_ttl = Some(Duration::from_secs(24 * 60 * 60));
        dnssec_options.negative_max_ttl = Some(Duration::from_secs(5 * 60));
        let s2s_dns_resolver = TokioResolver::builder_with_config(
            resolver_config.clone(),
            TokioRuntimeProvider::default(),
        )
        .with_options(resolver_options)
        .build()
        .context("failed to initialize the asynchronous DNS resolver")?;
        let s2s_dnssec_resolver = (config.federation_dane_mode != crate::s2s::dane::DaneMode::Off)
            .then(|| {
                TokioResolver::builder_with_config(resolver_config, TokioRuntimeProvider::default())
                    .with_options(dnssec_options)
                    .build()
                    .context("failed to initialize the locally validating DNSSEC resolver")
            })
            .transpose()?;

        // Transfer the Redis endpoint and signing capability out of the
        // broadly shared Config before constructing AppState.  ClusterManager
        // is their sole runtime owner; keeping a second copy in `state.config`
        // would let unrelated protocol code regain a long-lived secret by
        // reaching through configuration.
        let mut redis_url = config.raw.redis_url.take();
        let cluster_security = config.cluster_security.take();
        let cluster = crate::cluster::ClusterManager::new(
            redis_url.as_deref(),
            &config.domain,
            config.raw.redis_tls_ca_cert_path.as_deref(),
            config.raw.redis_tls_client_cert_path.as_deref(),
            config.raw.redis_tls_client_key_path.as_deref(),
            cluster_security,
        )
        .await
        .context("failed to connect to Redis for cluster manager")?;
        if let Some(redis_url) = &mut redis_url {
            redis_url.zeroize();
            redis_url.clear();
        }
        cluster.configure_authority_pool(&pool)?;
        if let Some(identity) = cluster.key_authority_identity() {
            db::reconcile_cluster_key_deployment_before_instance_claim(&pool, &identity)
                .await
                .context("cluster signing-key authority preparation failed")?;
            for peer in cluster.peer_key_authority_identities() {
                db::reconcile_cluster_peer_key_deployment(&pool, &peer)
                    .await
                    .with_context(|| {
                        format!(
                            "configured cluster peer {} key authority is inconsistent",
                            peer.node_id
                        )
                    })?;
            }
            cluster
                .claim_instance_authority(&pool)
                .await
                .context("cluster node ID is already owned by another live process")?;
            db::reconcile_cluster_key_deployment(&pool, &identity)
                .await
                .context("cluster signing-key authority finalization failed")?;
            cluster
                .refresh_instance_authority(&pool)
                .await
                .context("could not load peer cluster instance authority")?;
        }
        cluster
            .activate()
            .await
            .context("failed to publish the initial signed cluster node lease")?;
        db::initialize_admin_runtime_settings(
            &pool,
            false,
            !open_registration,
            config.registration_dependency_locked(),
        )
        .await?;
        let (island_mode, registration_closed) = db::admin_runtime_settings(&pool).await?;
        let registration_closed = Arc::new(AtomicBool::new(registration_closed));
        let process_started_at = db::admin_service_control_startup_time(&pool).await?;
        let (runtime_blacklist, runtime_whitelist) = db::federation_runtime_rules(&pool).await?;

        db::recover_remote_pam_after_restart(&pool)
            .await
            .context("failed to recover pending MIX-PAM federation operations")?;
        let mix_presence_recovery = db::prepare_mix_presence_after_restart(&pool, &config.domain)
            .await
            .context("failed to prepare XEP-0403 presence recovery")?;
        if config.mix_muc_mirror_enabled {
            let mix_domain = format!("mix.{}", config.domain);
            let linked = db::reconcile_mix_muc_mirrors(&pool, &mix_domain, &config.domain)
                .await
                .context("failed to reconcile XEP-0408 MIX/MUC mirror associations")?;
            tracing::info!(linked, "XEP-0408 partial MIX/MUC mirror mode enabled");
        }

        if let Some(identity) = &abuse_key_deployment {
            db::reconcile_abuse_key_deployment(&pool, identity)
                .await
                .context("anti-abuse HMAC deployment consistency check failed")?;
        }

        let bosh = config.bosh_enabled.then(|| {
            crate::bosh::BoshManager::new(
                config.bosh_max_sessions,
                config.bosh_max_concurrent_body_reads,
            )
        });
        let upload_runtime = UploadRuntime::from_config(&config);
        let sm_recovery_max_jobs = config.sm_recovery_max_jobs;
        let sm_recovery_max_bytes = config.sm_recovery_max_bytes;
        let message_content_identity = abuse.personal_message_content_keyring();
        let retraction_content_identity = abuse.personal_retraction_content_keyring();
        let mix_message_content_identity = abuse.mix_message_content_keyring();
        let mix_retraction_content_identity = abuse.mix_retraction_content_keyring();
        // Durable outbox workers share one application-owned admission
        // capability. This leaves a primary-pool connection for foreground
        // protocol traffic even during simultaneous MIX, PubSub and MUC
        // recovery.
        let durable_outbox_database_admission =
            crate::services::durable_outbox::DurableOutboxDatabaseAdmission::for_primary_pool(
                config.database_max_connections,
            );
        let message_service = crate::services::messaging::MessageService::new(
            db::messaging::PostgresMessageRepository::new(
                pool.clone(),
                message_content_identity,
                config.domain.clone(),
                config.offline_max_messages_per_account,
                config.offline_max_bytes_per_account,
                config.offline_message_ttl_days,
            ),
            config.require_encrypted_archive,
        );
        let retraction_service = crate::services::retractions::RetractionService::new(
            db::retractions::PostgresRetractionRepository::new(pool.clone()),
            retraction_content_identity,
            config.domain.clone(),
        );
        let metrics = Arc::new(Metrics::default());
        let account_service = crate::services::account::AccountService::new(
            db::account_repository::PostgresAccountRepository::new(
                pool.clone(),
                config.domain.clone(),
                Arc::clone(&abuse),
            )
            .with_api_control(Arc::clone(&api_control)),
            config.configured_registration_mode()
                == crate::config::RegistrationMode::InvitationOnly,
            config.registration_rate_per_hour,
            config.scram_iterations,
            config.scram_sha1_enabled,
        );
        let login_service = crate::services::http_login::HttpLoginService::new(
            db::http_login_repository::PostgresHttpLoginRepository::new(
                pool.clone(),
                Arc::clone(&abuse),
                Arc::clone(&api_control),
                crate::services::http_login::HttpLoginPolicy {
                    domain: config.domain.clone(),
                    scram_iterations: config.scram_iterations,
                    scram_sha1_enabled: config.scram_sha1_enabled,
                    session_ttl_hours: config.session_ttl_hours,
                },
                metrics.clone() as Arc<dyn crate::services::http_login::LoginFailureMetrics>,
            ),
        );
        let password_change_service = crate::services::password_change::PasswordChangeService::new(
            db::password_change_repository::PostgresPasswordChangeRepository::new(
                pool.clone(),
                Arc::clone(&api_control),
                Arc::clone(&abuse),
            ),
            config.scram_iterations,
            config.scram_sha1_enabled,
        );
        let dummy_scram_iteration_profiles =
            crate::db::scram_iteration_profiles(&pool, config.scram_iterations)
                .await
                .context("failed to load dummy SCRAM iteration profiles")?;
        let authentication_service = crate::services::authentication::AuthenticationService::new_with_dummy_scram_iteration_profiles(
                db::authentication::PostgresAuthenticationRepository::new(pool.clone(), Arc::clone(&fast_token_secret)),
                dummy_scram_secret,
                config.scram_iterations,
                dummy_scram_iteration_profiles,
                config.scram_sha1_enabled,
            );
        let pubsub_service =
            crate::services::pubsub::PubSubService::new_with_durable_outbox_database_admission(
                db::pubsub_repository::PostgresPubSubRepository::new(pool.clone(), &config.domain),
                pool.options().get_max_connections(),
                durable_outbox_database_admission.clone(),
            );
        let profile_service = crate::services::profile::ProfileService::with_mutation_admission(
            db::profile::PostgresProfileRepository::new(pool.clone(), config.domain.clone()),
            pubsub_service.mutation_admission(),
        );
        let mam_service = crate::services::mam::MamService::new(
            db::mam::PostgresMamRepository::new(pool.clone()),
            crate::services::mam::FederatedMamOutboxLimits {
                ttl_seconds: config.s2s_outbox_ttl_seconds,
                max_rows: config.s2s_outbox_max_rows,
                max_bytes: config.s2s_outbox_max_bytes,
                max_per_domain: config.s2s_outbox_max_per_domain,
            },
            federation.outbox_wakeup(),
        );
        let upload_service = config.upload_mode.keeps_storage_runtime().then(|| {
            crate::services::upload::UploadService::new(
                db::upload::PostgresUploadRepository::new(pool.clone()),
                Arc::clone(&upload_safety_gate),
                config.upload_max_bytes,
            )
        });
        let privacy_service = crate::services::privacy::PrivacyService::new(
            db::privacy::PostgresPrivacyRepository::new(pool.clone()),
        );
        let replay_service = crate::services::replay::ReplayService::new(
            db::replay_repository::PostgresReplayRepository::new(pool.clone()),
            &config.domain,
            config.offline_message_ttl_days,
        );
        let passkey_service = Arc::new(PasskeyService::new(
            db::passkeys::PostgresPasskeyRepository::new(pool.clone(), fast_token_secret.clone()),
            crate::services::passkeys::PasskeyConfig {
                enabled: config.web_client_enabled && config.fast_token_enabled,
                public_url: config.public_url.clone(),
                domain: config.domain.clone(),
                scram_iterations: config.scram_iterations,
                scram_sha1_enabled: config.scram_sha1_enabled,
                fast_token_ttl_days: config.fast_token_ttl_days,
                fast_strong_reauth_max_days: config.fast_strong_reauth_max_days,
                session_ttl_hours: config.session_ttl_hours,
            },
        ));
        let roster_service =
            RosterService::new(db::roster::PostgresRosterRepository::new(pool.clone()));
        let private_storage_service = crate::services::private_storage::PrivateStorageService::new(
            db::private::PostgresPrivateStorageRepository::new(pool.clone()),
            config.pep_max_nodes_per_account,
            config.pep_max_storage_bytes_per_account,
        );
        let auxiliary_pool_deadline = tokio::time::Instant::now() + AUXILIARY_POOL_STARTUP_BUDGET;
        let command_pool = match config.admin_command_pool_mode {
            // The explicit loopback-only exception has no independent
            // PostgreSQL principal.  A second PgPool with the same unsafe
            // credential would add pressure without adding a capability
            // boundary, so share the already-attested primary pool instead.
            AdminCommandPoolMode::SharedUnsafeDevelopment => pool.clone(),
            AdminCommandPoolMode::DedicatedProductionRole => {
                let command_pool_options = crate::db::pin_public_application_schema(
                    PgPoolOptions::new()
                        .max_connections(4)
                        .min_connections(0)
                        .acquire_timeout(AUXILIARY_POOL_ACQUIRE_TIMEOUT),
                );
                let command_pool = startup_database_connect(
                    auxiliary_pool_deadline,
                    AUXILIARY_POOL_ACQUIRE_TIMEOUT,
                    "XEP-0133 command",
                    |_| {
                        command_pool_options
                            .clone()
                            .connect(&config.admin_command_database_url)
                    },
                )
                .await?;
                tokio::time::timeout_at(auxiliary_pool_deadline, async {
                    crate::db::attest_admin_command_role(&command_pool).await?;
                    anyhow::Ok(())
                })
                .await
                .context("command role attestation exceeded its startup admission deadline")??;
                command_pool
            }
        };
        let omemo_recovery_pool_options = PgPoolOptions::new()
            .max_connections(OMEMO_RECOVERY_POOL_MAX_CONNECTIONS)
            .min_connections(0)
            .acquire_timeout(AUXILIARY_POOL_ACQUIRE_TIMEOUT);
        let omemo_recovery_pool_options = if config.database_allow_unsafe_role_for_development {
            omemo_recovery_pool_options
        } else {
            crate::db::pin_public_application_schema(omemo_recovery_pool_options)
        };
        let omemo_recovery_poll_pool = startup_database_connect(
            auxiliary_pool_deadline,
            AUXILIARY_POOL_ACQUIRE_TIMEOUT,
            "OMEMO recovery poll",
            |_| {
                omemo_recovery_pool_options
                    .clone()
                    .connect(&config.database_url)
            },
        )
        .await?;
        let sm_authority_schema = db::current_application_schema(&pool)
            .await
            .context("could not determine the SM authority schema")?;
        let mut sm_authority_connect_options = config
            .database_url
            .parse::<PgConnectOptions>()
            .context("could not parse the SM authority listener database URL")?;
        if !config.database_allow_unsafe_role_for_development {
            sm_authority_connect_options =
                sm_authority_connect_options.options([("search_path", "public")]);
        }
        let sm_service = crate::services::sm::SmService::new(
            db::sm_repository::PostgresSmRepository::new(
                pool.clone(),
                Arc::clone(&fast_token_secret),
            ),
            sm_authority_schema.clone(),
        )?;
        // The MIX wake broker validates the same schema identity that the
        // dedicated PostgreSQL listener attests below.  It never trusts a
        // notification as delivery authority; schema matching only prevents
        // a shared database's unrelated schema from creating local scan load.
        let mix_service = crate::services::mix::MixService::new_with_outbox_database_admission(
            db::mix_repository::PostgresMixRepository::new(pool.clone()),
            mix_message_content_identity,
            mix_retraction_content_identity,
            durable_outbox_database_admission.clone(),
            sm_authority_schema,
        )?;
        config.raw.database_url.zeroize();
        config.raw.database_url.clear();
        config.raw.admin_command_database_url.zeroize();
        config.raw.admin_command_database_url.clear();
        let muc_service = crate::services::muc::MucService::new(
            db::room::PostgresMucRepository::new(pool.clone()),
            config.domain.clone(),
        );
        let sessions = Arc::new(DashMap::new());
        let muc_occupants = Arc::new(DashMap::new());
        let started_at = Instant::now();
        let api_cursor = Arc::new(api_cursor);
        let federation_write_policy = FederationWritePolicy::new(island_mode);
        let public_discovery_context = PublicDiscoveryContext::new(
            http_policy::PublicDiscoveryPolicy {
                domain: config.domain.clone(),
                public_url: config.public_url.clone(),
                trusted_proxy_ips: config.trusted_proxy_ips.clone(),
                websocket_allowed_origins: config.websocket_allowed_origins.clone(),
                configured_registration_mode: config.configured_registration_mode(),
                registration_dependency_locked: config.registration_dependency_locked(),
                require_encrypted_archive: config.require_encrypted_archive,
                federation_configured: config.federation_enabled,
                rest_api_enabled: config.rest_api_enabled,
                websocket_enabled: config.websocket_enabled,
                bosh_enabled: config.bosh_enabled,
                web_client_enabled: config.web_client_enabled,
                passkeys_enabled: config.web_client_enabled
                    && config.fast_token_enabled
                    && crate::services::passkeys::relying_party(&config.public_url).is_ok(),
                web_admin_enabled: config.web_admin_enabled,
                upload_mode: config.upload_mode,
                upload_max_bytes: config.upload_max_bytes,
                upload_download_max_bytes: config.upload_download_max_bytes,
                pow_max_work_factor: config.pow_max_work_factor,
                pow_max_device_seconds: config.pow_max_device_seconds,
                xep_0487_ips: config.xep_0487_ips.clone(),
                xep_0487_ttl_seconds: config.xep_0487_ttl_seconds,
                xep_0487_priority: config.xep_0487_priority,
                xep_0487_weight: config.xep_0487_weight,
                xmpps_port: config.xmpps_bind.port(),
                s2s_tls_port: config.s2s_tls_bind.port(),
            },
            Arc::clone(&registration_closed),
            Arc::clone(&federation_write_policy.island_mode),
        );
        let api_query_context = api_queries::ApiQueryContext::new(
            crate::services::api_queries::ApiQueryService::new(
                db::api_queries::PostgresApiQueryRepository::new(pool.clone()),
            ),
            Arc::clone(&api_cursor),
            api_queries::ApiQueryRuntime {
                domain: config.domain.clone(),
                node_id: cluster.node_id.clone(),
                require_encrypted_archive: config.require_encrypted_archive,
                federation_configured: config.federation_enabled,
                configured_registration_mode: config.configured_registration_mode(),
                registration_dependency_locked: config.registration_dependency_locked(),
                registration_closed: Arc::clone(&registration_closed),
                island_mode: Arc::clone(&federation_write_policy.island_mode),
                sessions: Arc::clone(&sessions),
                occupants: Arc::clone(&muc_occupants),
                metrics: Arc::clone(&metrics),
                started_at,
            },
        );
        let omemo_recovery_poll_context = omemo_poll::OmemoRecoveryPollContext::new(
            crate::services::omemo_recovery::OmemoRecoveryPollService::new(
                db::omemo_recovery_repository::PostgresOmemoRecoveryPollRepository::new(
                    omemo_recovery_poll_pool,
                ),
            ),
            config.domain.clone(),
            config.trusted_proxy_ips.clone(),
            Arc::clone(&metrics),
        );
        let admin_mutations = db::admin_mutations::AdminMutationStore::new(
            pool.clone(),
            Arc::clone(&api_control),
            cluster.admission(),
        );
        let account_admin_service = crate::services::account_admin::AccountAdminService::new(
            db::account_admin_repository::PostgresAccountAdminRepository::new(
                admin_mutations.clone(),
            ),
        );
        let registration_admin_service =
            crate::services::account_admin::RegistrationAdminService::new(
                db::account_admin_repository::PostgresRegistrationAdminRepository::new(
                    admin_mutations.clone(),
                    pool.clone(),
                ),
                account_admin::LocalRegistrationCache::new(
                    config.registration_dependency_locked(),
                    Arc::clone(&registration_closed),
                ),
            );
        let session_admin_service = crate::services::account_admin::SessionAdminService::new(
            db::account_admin_repository::PostgresSessionAdminRepository::new(
                admin_mutations.clone(),
            ),
            account_admin::LocalAdminSessions::new(Arc::clone(&sessions)),
        );
        let operation_admin_service = crate::services::operations::OperationAdminService::new(
            db::operation_admin_repository::PostgresOperationAdminRepository::new(
                admin_mutations.clone(),
            ),
        );
        let operation_muc_destroy_service =
            crate::services::operation_muc_destroy::MucDestroyService::new(
                db::operation_muc_destroy_repository::PostgresMucDestroyRepository::new(
                    pool.clone(),
                ),
                config.domain.clone(),
            );
        let locked_muc_expiry_service =
            crate::services::locked_muc_expiry::LockedMucExpiryService::new(
                db::locked_muc_expiry_repository::PostgresLockedMucExpiryRepository::new(
                    pool.clone(),
                ),
            );
        let operation_effect_fence_service =
            crate::services::operation_effect_fence::OperationEffectFenceService::new(
                db::operation_effect_fence_repository::PostgresOperationEffectFenceRepository::new(
                    pool.clone(),
                ),
            );
        let operation_journal_worker_service =
            crate::services::operation_journal_worker::OperationJournalWorkerService::new(
                db::operation_journal_worker_repository::PostgresOperationJournalWorkerRepository::new(
                    pool.clone(),
                ),
            );
        let s2s_outbox_dispatch_service =
            crate::services::s2s_outbox_dispatch::S2sOutboxDispatchService::new(
                db::s2s_outbox_dispatch_repository::PostgresS2sOutboxDispatchRepository::new(
                    pool.clone(),
                ),
                crate::services::s2s_outbox_dispatch::S2sOutboxDispatchPolicy {
                    claim_batch: config.s2s_outbox_claim_batch,
                    lease_seconds: config.s2s_outbox_lease_seconds,
                    retry_base_seconds: config.s2s_outbox_retry_base_seconds,
                    retry_max_seconds: config.s2s_outbox_retry_max_seconds,
                    max_attempts: config.s2s_outbox_max_attempts,
                },
            );
        let admin_session_cleanup_worker_service =
            crate::services::admin_session_cleanup_worker::AdminSessionCleanupWorkerService::new(
                db::admin_session_cleanup_worker_repository::PostgresAdminSessionCleanupRepository::new(pool.clone()),
            );
        let admin_dispatch_service = crate::services::admin_dispatch::AdminDispatchService::new(
            db::admin_dispatch_repository::PostgresAdminDispatchRepository::new(
                admin_mutations.clone(),
            ),
            config.domain.clone(),
        );
        let upload_admin_service = crate::services::upload_admin::UploadAdminService::new(
            db::upload_admin_repository::PostgresUploadAdminRepository::new(
                admin_mutations.clone(),
            ),
        );
        let report_moderation_service =
            crate::services::report_moderation::ReportModerationService::new(
                db::report_moderation_repository::PostgresReportModerationRepository::new(
                    admin_mutations.clone(),
                ),
            );
        let retention_policy_context = retention_policy::RetentionPolicyContext::new(
            crate::services::retention_policy::RetentionPolicyService::new(
                db::retention_policy_repository::PostgresRetentionPolicyRepository::new(
                    pool.clone(),
                    Arc::clone(&api_control),
                ),
                crate::services::retention_policy::RetentionPolicyLimits {
                    personal_mam_days: config.mam_retention_days,
                    offline_message_days: config.offline_message_ttl_days,
                    moderation_evidence_days: config.moderation_retention_days,
                },
                config.muc_mam_retention_days,
            ),
            Arc::clone(&metrics),
        );
        let governance_context = governance::GovernanceContext::new(
            crate::services::governance::GovernanceService::new(
                db::governance_repository::PostgresGovernanceRepository::new(
                    pool.clone(),
                    admin_mutations.clone(),
                    Arc::clone(&api_control),
                    crate::api::governance_cursor::SignedGovernanceCursors::new(Arc::clone(
                        &api_cursor,
                    )),
                ),
            ),
            Arc::clone(&metrics),
        );
        let invitation_admin_service =
            crate::services::invitation_admin::InvitationAdminService::new(
                db::invitation_admin_repository::PostgresInvitationAdminRepository::new(
                    admin_mutations,
                ),
            );
        let report_service = crate::services::reports::ReportService::new(
            db::report_repository::PostgresReportRepository::new(
                pool.clone(),
                Arc::clone(&api_control),
                Arc::clone(&abuse),
            ),
        );
        let message_admission_service =
            crate::services::message_admission::MessageAdmissionService::new(
                db::message_admission_repository::PostgresMessageAdmissionRepository::new(
                    Arc::clone(&abuse),
                    pool.clone(),
                ),
            );
        let account_revocation_consumer_service =
            crate::services::account_revocation_consumer::AccountRevocationConsumerService::new(
                db::account_revocation_repository::PostgresAccountRevocationRepository::new(
                    pool.clone(),
                ),
            );
        let session_authority_sweep_service =
            crate::services::session_authority_sweep::SessionAuthoritySweepService::new(
                db::session_authority_sweep_repository::PostgresSessionAuthoritySweepRepository::new(
                    pool.clone(),
                ),
            );
        let session_termination_authority_service =
            crate::services::session_termination_authority::SessionTerminationAuthorityService::new(
                db::session_termination_authority_repository::PostgresSessionTerminationAuthorityRepository::new(
                    pool.clone(),
                ),
            );
        let state = Arc::new(Self {
            config,
            api_query_context,
            metrics_snapshot_service:
                crate::services::metrics_snapshot::MetricsSnapshotService::new(
                    db::metrics_snapshot_repository::PostgresMetricsSnapshotRepository::new(
                        pool.clone(),
                    ),
                ),
            readiness_service: crate::services::readiness::ReadinessService::new(
                db::readiness_repository::PostgresReadinessRepository::new(pool.clone()),
            ),
            public_discovery_context,
            omemo_recovery_service: crate::services::omemo_recovery::OmemoRecoveryService::new(
                db::omemo_recovery_repository::PostgresOmemoRecoveryRepository::new(pool.clone()),
            ),
            pubsub_service,
            profile_service,
            extdisco_service,
            muc_service,
            message_service,
            message_admission_service,
            retraction_service,
            mam_service,
            mix_service,
            sm_service,
            blocking_service: crate::services::blocking::BlockingService::new(
                db::roster::PostgresBlockingRepository::new(pool.clone()),
            ),
            presence_service: crate::services::presence::PresenceService::new(
                db::presence_repository::PostgresPresenceRepository::new(pool.clone()),
            ),
            replay_service,
            roster_service,
            s2s_roster_authorization_service:
                crate::services::s2s_roster_authorization::FederatedRosterAuthorizationService::new(
                    db::s2s_roster_authorization_repository::PostgresFederatedRosterRepository::new(
                        pool.clone(),
                    ),
                ),
            s2s_outbox_dispatch_service,
            s2s_sm_outbox_service: crate::services::s2s_sm_outbox::SmOutboxService::new(
                db::s2s_sm_outbox_repository::PostgresSmOutboxRepository::new(pool.clone()),
            ),
            passkey_service,
            privacy_service,
            private_storage_service,
            account_service,
            login_service,
            password_change_service,
            authentication_service,
            admin_command_service: crate::services::admin_commands::AdminCommandService::new(
                db::admin_command_repository::PostgresAdminCommandRepository::new(
                    pool.clone(),
                    command_pool,
                ),
            ),
            push_service: crate::services::push::PushService::new(
                db::push::PostgresPushRepository::new(pool.clone()),
            ),
            pool,
            cluster,
            account_revocation_consumer_service,
            session_authority_sweep_service,
            session_termination_authority_service,
            bosh,
            sessions,
            muc_occupants,
            suspended_muc_sessions: Arc::new(DashMap::new()),
            sm_suspension_recovery:
                crate::services::session_cleanup::SmSuspensionRecoveryQueue::new(
                    sm_recovery_max_jobs,
                    sm_recovery_max_bytes,
                    Arc::clone(&sm_capacity_metrics),
                    Arc::clone(&sm_memory_governor),
                ),
            sm_memory_governor,
            metrics,
            metrics_bearer_token,
            web_admin_gateway_token,
            omemo_recovery_poll_context,
            durable_outbox_database_admission,
            report_service,
            account_admin_service,
            registration_admin_service,
            session_admin_service,
            operation_admin_service,
            operation_muc_destroy_service,
            locked_muc_expiry_service,
            operation_effect_fence_service,
            operation_journal_worker_service,
            admin_session_cleanup_worker_service,
            admin_dispatch_service,
            upload_admin_service,
            report_moderation_service,
            invitation_admin_service,
            retention_policy_context,
            governance_context,
            upload_service,
            upload_store,
            upload_storage_namespace_sha256: upload_namespace,
            upload_authority_generation,
            upload_safety_gate,
            upload_startup_audits: Arc::new(upload_startup_audits),
            federation_outbox: federation,
            component_credentials,
            components,
            s2s_connection_registry: crate::s2s::S2sConnectionRegistry::default(),
            s2s_dns_resolver,
            s2s_dnssec_resolver,
            pending_mix_iq: northstar_protocol_runtime::mix::MixIqRelayIndex::new(),
            caps_cache: northstar_protocol_runtime::caps::CapsCacheIndex::new(),
            caps_by_jid: northstar_protocol_runtime::caps::CapsResourceIndex::new(),
            pending_caps: northstar_protocol_runtime::caps::PendingCapsIndex::new(),
            federated_caps_gates: northstar_protocol_runtime::caps::FederatedCapsGateIndex::new(),
            caps_effect_dispatcher: northstar_protocol_runtime::caps::CapsEffectDispatcher::new(),
            dialback_secret,
            dialback_verifications: Arc::new(Semaphore::new(64)),
            client_connections,
            client_connections_by_ip: DashMap::new(),
            upload_runtime,
            s2s_connections,
            s2s_connection_attempts,
            component_connections,
            connection_actors,
            challenge_issue_service:
                crate::services::challenge_issuance::ChallengeIssueService::new(
                    db::challenge_issuance_repository::PostgresChallengeRepository::new(
                        Arc::clone(&abuse),
                    ),
                ),
            challenge_cleanup_service:
                crate::services::challenge_issuance::ChallengeCleanupService::new(
                    db::challenge_issuance_repository::PostgresChallengeRepository::new(
                        Arc::clone(&abuse),
                    ),
                ),
            sasl_login_abuse_service: crate::services::login_abuse::SaslLoginAbuseService::new(
                db::login_abuse_repository::PostgresSaslLoginAbuseRepository::new(Arc::clone(
                    &abuse,
                )),
            ),
            passkey_login_abuse_service: Arc::new(
                crate::services::login_abuse::PasskeyLoginAbuseService::new(
                    db::login_abuse_repository::PostgresPasskeyLoginAbuseRepository::new(
                        Arc::clone(&abuse),
                    ),
                ),
            ),
            abuse_key_deployment,
            started_at,
            process_started_at,
            tls_context: crate::tls::TlsContext::new(tls),
            federation_write_policy,
            registration_closed,
            federation_runtime_policy: arc_swap::ArcSwap::from_pointee(RuntimeFederationPolicy {
                blacklist: runtime_blacklist.into_iter().collect(),
                whitelist: runtime_whitelist.into_iter().collect(),
            }),
            service_shutdown: std::sync::OnceLock::new(),
            workers: crate::workers::WorkerRegistry::new(),
        });
        state.worker_registry().register_observer(
            "session-cleanup",
            crate::workers::WorkerCriticality::Restartable,
        );
        db::authority_listener::start_database_authority_listener(
            state.sm_service().authority_broker(),
            state.mix_service().delivery_wake_broker(),
            state.cluster.account_revocation_notify(),
            sm_authority_connect_options,
            Arc::clone(state.worker_registry()),
            worker_cancel.clone(),
        );
        if state
            .config
            .xmpp_extensions
            .enabled(northstar_xep_0115::XEP_ID)
        {
            crate::xmpp::protocol::caps::start_caps_effect_dispatcher(
                Arc::clone(&state),
                worker_cancel.clone(),
            );
        }
        crate::services::session_cleanup::start_sm_suspension_recovery(
            Arc::new(state.sm_suspension_context()),
            Arc::clone(state.worker_registry()),
            Arc::clone(&state.sm_suspension_recovery),
            worker_cancel.clone(),
        );
        crate::xmpp::protocol::mix::start_mix_presence_recovery(
            Arc::clone(&state),
            mix_presence_recovery.0,
            mix_presence_recovery.1,
            worker_cancel.clone(),
        );
        crate::xmpp::protocol::mix::start_mix_iq_relay_expiry(
            Arc::clone(&state),
            worker_cancel.clone(),
        );
        crate::xmpp::protocol::mix::start_mix_delivery_outbox(
            Arc::clone(&state),
            worker_cancel.clone(),
        );
        crate::xmpp::protocol::pubsub::start_pubsub_digest_delivery(
            Arc::clone(&state),
            worker_cancel.clone(),
        );
        crate::xmpp::protocol::pubsub::start_pubsub_event_outbox_delivery(
            Arc::clone(&state),
            worker_cancel.clone(),
        );
        crate::cluster::start_muc_outbox_delivery(Arc::clone(&state), worker_cancel.clone());
        Self::start_locked_muc_expiry(Arc::clone(&state), worker_cancel.clone());
        // Both durable policy snapshots deliberately share the single reserved
        // control-plane connection.  They must therefore be refreshed by one
        // sequential worker: two independently supervised workers can turn a
        // CPU-saturated process into its own connection-pool contention.
        Self::start_runtime_control_refresh(
            Arc::clone(&state),
            runtime_control_connection,
            worker_cancel,
        );
        Ok(state)
    }

    pub(crate) fn worker_registry(&self) -> &Arc<crate::workers::WorkerRegistry> {
        &self.workers
    }

    pub(crate) fn sm_suspension_context(
        &self,
    ) -> suspension::SmSuspensionContext<db::sm_suspension::PostgresSmSuspensionRepository> {
        suspension::SmSuspensionContext::new(
            db::sm_suspension::PostgresSmSuspensionRepository::new(self.pool.clone()),
            crate::services::sm_suspension::SmSuspensionLimits {
                max_stanzas: self.config.sm_max_unacked_stanzas,
                max_bytes: self.config.sm_max_unacked_bytes,
            },
            Arc::clone(&self.muc_occupants),
            Arc::clone(&self.suspended_muc_sessions),
            self.cluster.clone(),
        )
    }

    pub(crate) fn sm_suspension_recovery_queue(
        &self,
    ) -> &Arc<crate::services::session_cleanup::SmSuspensionRecoveryQueue> {
        &self.sm_suspension_recovery
    }

    pub(crate) fn sm_memory_governor(
        &self,
    ) -> &Arc<crate::services::sm_capacity::SmMemoryGovernor> {
        &self.sm_memory_governor
    }

    pub(crate) fn connection_actors(&self) -> &crate::connection_actors::ConnectionActorRegistry {
        &self.connection_actors
    }

    pub(crate) fn caps_effect_dispatcher(
        &self,
    ) -> &Arc<northstar_protocol_runtime::caps::CapsEffectDispatcher> {
        &self.caps_effect_dispatcher
    }

    pub(crate) fn pending_mix_iq(&self) -> &northstar_protocol_runtime::mix::MixIqRelayIndex {
        &self.pending_mix_iq
    }

    pub(crate) fn caps_cache(&self) -> &northstar_protocol_runtime::caps::CapsCacheIndex {
        &self.caps_cache
    }

    pub(crate) fn caps_by_jid(&self) -> &northstar_protocol_runtime::caps::CapsResourceIndex {
        &self.caps_by_jid
    }

    pub(crate) fn pending_caps(&self) -> &northstar_protocol_runtime::caps::PendingCapsIndex {
        &self.pending_caps
    }

    pub(crate) fn federated_caps_gates(
        &self,
    ) -> &northstar_protocol_runtime::caps::FederatedCapsGateIndex {
        &self.federated_caps_gates
    }

    pub(crate) fn abuse_key_deployment(&self) -> Option<&db::AbuseKeyDeploymentIdentity> {
        self.abuse_key_deployment.as_ref()
    }

    pub(crate) fn upload_store(&self) -> &dyn UploadStore {
        self.upload_store
            .as_deref()
            .expect("upload routes and workers require an enabled or draining runtime")
    }

    pub(crate) fn upload_retention_seconds(&self) -> u64 {
        self.config.upload_retention_seconds
    }

    pub(crate) fn upload_download_read_timeout(&self) -> Duration {
        Duration::from_secs(self.config.upload_download_read_timeout_seconds)
    }

    pub(crate) fn upload_download_max_duration(&self) -> Duration {
        Duration::from_secs(self.config.upload_download_max_seconds)
    }

    pub(crate) fn admin_gateway_authentication_enabled(&self) -> bool {
        self.web_admin_gateway_token.is_some()
    }

    pub(crate) fn public_http_bind_address(&self) -> std::net::SocketAddr {
        self.config.http_bind
    }

    pub(crate) fn admin_http_bind_address(&self) -> std::net::SocketAddr {
        self.config.web_admin_bind
    }

    pub(crate) fn has_component_credentials(&self) -> bool {
        !self.component_credentials.is_empty()
    }

    pub(crate) fn component_runtime_policy(&self) -> ComponentRuntimePolicy {
        ComponentRuntimePolicy {
            enabled: self.config.components_enabled,
            max_connections: self.config.max_component_connections,
            handshake_timeout: Duration::from_secs(self.config.component_handshake_timeout_seconds),
            queue_capacity: self.config.component_queue_capacity,
        }
    }

    /// Authenticated external-component ownership and wake-up authority.
    /// The registry exposes only owner-fenced operations; its concurrent map
    /// remains encapsulated inside the component subsystem.
    pub(crate) fn component_registry(&self) -> &crate::components::ComponentRegistry {
        &self.components
    }

    /// Redacted configured routing domains used by observability and the S2S
    /// outbox exclusion query. Preserve the original Vec semantics, including
    /// configuration order and any duplicates across credentials.
    pub(crate) fn configured_component_domains(&self) -> Vec<String> {
        self.config
            .components
            .iter()
            .flat_map(|credential| credential.allowed_domains.iter().cloned())
            .collect()
    }

    pub(crate) fn component_connect_credentials(&self) -> Vec<crate::config::ComponentCredential> {
        self.component_credentials
            .iter()
            .filter(|credential| {
                credential.connection == crate::config::ComponentConnectionMode::Connect
            })
            .cloned()
            .collect()
    }

    pub(crate) fn accepts_component_connections(&self) -> bool {
        self.component_credentials.iter().any(|credential| {
            credential.connection == crate::config::ComponentConnectionMode::Accept
        })
    }

    pub(crate) fn component_authentication_credential(
        &self,
        domain: &str,
    ) -> Option<crate::config::ComponentCredential> {
        let domain = crate::jid::prepare_domainpart(domain).ok()?;
        self.component_credentials
            .iter()
            .find(|credential| {
                credential
                    .allowed_domains
                    .iter()
                    .any(|allowed| allowed == &domain)
            })
            .cloned()
    }

    pub(crate) fn upload_safety_gate(&self) -> &Arc<UploadSafetyGate> {
        &self.upload_safety_gate
    }

    pub(crate) fn upload_maintenance_context(
        &self,
    ) -> Option<
        crate::upload_worker::UploadMaintenanceContext<
            db::upload_maintenance::PostgresUploadMaintenanceRepository,
        >,
    > {
        Some(crate::upload_worker::UploadMaintenanceContext::new(
            db::upload_maintenance::PostgresUploadMaintenanceRepository::new(self.pool.clone()),
            Arc::clone(self.upload_store.as_ref()?),
            crate::upload_worker::UploadMaintenancePolicy {
                max_pending_jobs: self.config.upload_storage_max_pending_jobs,
                max_retained_files: self.config.upload_storage_max_retained_files,
                max_retained_bytes: self.config.upload_storage_max_retained_bytes,
                retention_seconds: self.config.upload_retention_seconds,
                namespace_sha256: self.upload_storage_namespace_sha256,
                generation: self.upload_authority_generation,
            },
            Arc::clone(&self.upload_safety_gate),
            Arc::clone(&self.upload_startup_audits),
            Arc::clone(&self.metrics),
        ))
    }

    pub(crate) fn upload_service(&self) -> &UploadService {
        self.upload_service
            .as_ref()
            .expect("upload routes require an enabled or draining storage runtime")
    }

    pub(crate) fn api_session_service(
        &self,
    ) -> crate::services::api_sessions::ApiSessionService<
        db::api_session_repository::PostgresApiSessionRepository,
    > {
        crate::services::api_sessions::ApiSessionService::new(
            db::api_session_repository::PostgresApiSessionRepository::new(self.pool.clone()),
        )
    }

    pub(crate) fn challenge_issue_service(
        &self,
    ) -> &crate::services::challenge_issuance::ChallengeIssueService<
        db::challenge_issuance_repository::PostgresChallengeRepository,
    > {
        &self.challenge_issue_service
    }

    pub(crate) fn challenge_cleanup_service(
        &self,
    ) -> &crate::services::challenge_issuance::ChallengeCleanupService<
        db::challenge_issuance_repository::PostgresChallengeRepository,
    > {
        &self.challenge_cleanup_service
    }

    pub(crate) fn sasl_login_abuse_service(
        &self,
    ) -> &crate::services::login_abuse::SaslLoginAbuseService<
        db::login_abuse_repository::PostgresSaslLoginAbuseRepository,
    > {
        &self.sasl_login_abuse_service
    }

    pub(crate) fn public_discovery_context(&self) -> &PublicDiscoveryContext {
        &self.public_discovery_context
    }

    pub(crate) fn report_service(
        &self,
    ) -> &crate::services::reports::ReportService<db::report_repository::PostgresReportRepository>
    {
        &self.report_service
    }

    pub(crate) fn api_query_service(
        &self,
    ) -> &crate::services::api_queries::ApiQueryService<db::api_queries::PostgresApiQueryRepository>
    {
        self.api_query_context.api_query_service()
    }

    pub(crate) fn api_query_context(&self) -> ApiQueryContext {
        self.api_query_context.clone()
    }

    pub(crate) fn pubsub_service(
        &self,
    ) -> &crate::services::pubsub::PubSubService<db::pubsub_repository::PostgresPubSubRepository>
    {
        &self.pubsub_service
    }

    pub(crate) fn profile_service(
        &self,
    ) -> &crate::services::profile::ProfileService<db::profile::PostgresProfileRepository> {
        &self.profile_service
    }

    pub(crate) fn mix_service(
        &self,
    ) -> &crate::services::mix::MixService<db::mix_repository::PostgresMixRepository> {
        &self.mix_service
    }

    pub(crate) fn extdisco_service(&self) -> &crate::services::extdisco::ExtDiscoService {
        &self.extdisco_service
    }

    pub(crate) fn muc_service(
        &self,
    ) -> &crate::services::muc::MucService<db::room::PostgresMucRepository> {
        &self.muc_service
    }

    pub(crate) fn message_service(
        &self,
    ) -> &crate::services::messaging::MessageService<db::messaging::PostgresMessageRepository> {
        &self.message_service
    }

    pub(crate) fn message_admission_service(
        &self,
    ) -> &crate::services::message_admission::MessageAdmissionService<
        db::message_admission_repository::PostgresMessageAdmissionRepository,
    > {
        &self.message_admission_service
    }

    pub(crate) fn retraction_service(
        &self,
    ) -> &crate::services::retractions::RetractionService<
        db::retractions::PostgresRetractionRepository,
    > {
        &self.retraction_service
    }

    pub(crate) fn mam_service(
        &self,
    ) -> &crate::services::mam::MamService<db::mam::PostgresMamRepository> {
        &self.mam_service
    }

    pub(crate) fn sm_service(
        &self,
    ) -> &crate::services::sm::SmService<db::sm_repository::PostgresSmRepository> {
        &self.sm_service
    }

    pub(crate) fn blocking_service(
        &self,
    ) -> &crate::services::blocking::BlockingService<db::roster::PostgresBlockingRepository> {
        &self.blocking_service
    }

    pub(crate) fn presence_service(
        &self,
    ) -> &crate::services::presence::PresenceService<
        db::presence_repository::PostgresPresenceRepository,
    > {
        &self.presence_service
    }

    pub(crate) fn replay_service(
        &self,
    ) -> &crate::services::replay::ReplayService<db::replay_repository::PostgresReplayRepository>
    {
        &self.replay_service
    }

    pub(crate) fn roster_service(&self) -> &RosterService {
        &self.roster_service
    }

    pub(crate) fn s2s_roster_authorization_service(
        &self,
    ) -> &crate::services::s2s_roster_authorization::FederatedRosterAuthorizationService<
        db::s2s_roster_authorization_repository::PostgresFederatedRosterRepository,
    > {
        &self.s2s_roster_authorization_service
    }

    pub(crate) fn account_revocation_worker_context(
        &self,
    ) -> crate::cluster::AccountRevocationWorkerContext<
        db::account_revocation_repository::PostgresAccountRevocationRepository,
    > {
        crate::cluster::AccountRevocationWorkerContext::new(
            self.account_revocation_consumer_service.clone(),
            AccountRevocationRoutes::new(Arc::clone(&self.sessions)),
            self.cluster.account_revocation_authority(),
        )
    }

    pub(crate) fn session_authority_sweep_service(
        &self,
    ) -> &crate::services::session_authority_sweep::SessionAuthoritySweepService<
        db::session_authority_sweep_repository::PostgresSessionAuthoritySweepRepository,
    > {
        &self.session_authority_sweep_service
    }

    pub(crate) fn session_termination_authority_service(
        &self,
    ) -> &crate::services::session_termination_authority::SessionTerminationAuthorityService<
        db::session_termination_authority_repository::PostgresSessionTerminationAuthorityRepository,
    > {
        &self.session_termination_authority_service
    }

    pub(crate) fn s2s_outbox_dispatch_service(
        &self,
    ) -> &crate::services::s2s_outbox_dispatch::S2sOutboxDispatchService<
        db::s2s_outbox_dispatch_repository::PostgresS2sOutboxDispatchRepository,
    > {
        &self.s2s_outbox_dispatch_service
    }

    pub(crate) fn s2s_sm_outbox_service(
        &self,
    ) -> &crate::services::s2s_sm_outbox::SmOutboxService<
        db::s2s_sm_outbox_repository::PostgresSmOutboxRepository,
    > {
        &self.s2s_sm_outbox_service
    }

    pub(crate) fn privacy_service(
        &self,
    ) -> &crate::services::privacy::PrivacyService<db::privacy::PostgresPrivacyRepository> {
        &self.privacy_service
    }

    pub(crate) fn private_storage_service(
        &self,
    ) -> &crate::services::private_storage::PrivateStorageService<
        db::private::PostgresPrivateStorageRepository,
    > {
        &self.private_storage_service
    }

    pub(crate) fn account_service(
        &self,
    ) -> &crate::services::account::AccountService<db::account_repository::PostgresAccountRepository>
    {
        &self.account_service
    }

    pub(crate) fn password_change_service(
        &self,
    ) -> &crate::services::password_change::PasswordChangeService<
        db::password_change_repository::PostgresPasswordChangeRepository,
    > {
        &self.password_change_service
    }

    pub(crate) fn operation_muc_destroy_service(
        &self,
    ) -> &crate::services::operation_muc_destroy::MucDestroyService<
        db::operation_muc_destroy_repository::PostgresMucDestroyRepository,
    > {
        &self.operation_muc_destroy_service
    }

    pub(crate) async fn wake_committed_muc_operation(
        &self,
        operation_id: uuid::Uuid,
    ) -> anyhow::Result<()> {
        self.muc_service()
            .wake_committed_operation(&self.cluster, operation_id)
            .await
    }

    pub(crate) async fn publish_local_muc_departure(
        &self,
        departed: &MucOccupant,
        was_last: bool,
    ) -> anyhow::Result<()> {
        self.cluster
            .unregister_muc_occupant_epoch(
                &departed.room_jid,
                &departed.nick,
                departed.cluster_epoch,
                departed.connection_id,
            )
            .await?;
        if was_last {
            self.cluster.leave_muc(&departed.room_jid).await?;
        }
        self.cluster
            .send_muc_presence(
                &departed.room_jid,
                &SerializableMucOccupant::from(departed),
                true,
                false,
                None,
            )
            .await
    }

    pub(crate) async fn route_account_removal_presence_local(&self, recipient: &str, stanza: &str) {
        for (_, session) in self.session_entries_for(recipient) {
            let _ = session.sender.try_send(stanza.to_owned());
        }
        if let Ok(nodes) = self.cluster.lookup_nodes(recipient).await {
            for node_id in nodes {
                if node_id != self.cluster.node_id {
                    let _ = self
                        .cluster
                        .send_to_node(&node_id, recipient, stanza, false, None)
                        .await;
                }
            }
        }
    }

    pub(crate) fn locked_muc_expiry_service(
        &self,
    ) -> &crate::services::locked_muc_expiry::LockedMucExpiryService<
        db::locked_muc_expiry_repository::PostgresLockedMucExpiryRepository,
    > {
        &self.locked_muc_expiry_service
    }

    pub(crate) fn operation_effect_fence_service(
        &self,
    ) -> &crate::services::operation_effect_fence::OperationEffectFenceService<
        db::operation_effect_fence_repository::PostgresOperationEffectFenceRepository,
    > {
        &self.operation_effect_fence_service
    }

    pub(crate) fn operation_journal_worker_service(
        &self,
    ) -> &crate::services::operation_journal_worker::OperationJournalWorkerService<
        db::operation_journal_worker_repository::PostgresOperationJournalWorkerRepository,
    > {
        &self.operation_journal_worker_service
    }

    pub(crate) fn admin_session_cleanup_worker_service(
        &self,
    ) -> &crate::services::admin_session_cleanup_worker::AdminSessionCleanupWorkerService<
        db::admin_session_cleanup_worker_repository::PostgresAdminSessionCleanupRepository,
    > {
        &self.admin_session_cleanup_worker_service
    }

    pub(crate) fn authentication_service(
        &self,
    ) -> &crate::services::authentication::AuthenticationService<
        db::authentication::PostgresAuthenticationRepository,
    > {
        &self.authentication_service
    }

    pub(crate) fn admin_command_service(
        &self,
    ) -> &crate::services::admin_commands::AdminCommandService<
        db::admin_command_repository::PostgresAdminCommandRepository,
    > {
        &self.admin_command_service
    }

    pub(crate) fn push_service(
        &self,
    ) -> &crate::services::push::PushService<db::push::PostgresPushRepository> {
        &self.push_service
    }

    pub(crate) fn derive_dialback_key(
        &self,
        receiving_domain: &str,
        originating_domain: &str,
        stream_id: &str,
    ) -> String {
        crate::s2s::dialback::key(
            self.dialback_secret.as_slice(),
            receiving_domain,
            originating_domain,
            stream_id,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn finalize_resource_binding(
        &self,
        connection_id: uuid::Uuid,
        user_id: uuid::Uuid,
        expected_auth_generation: i64,
        full_jid: &str,
        device_id: Option<uuid::Uuid>,
        fast_plan: Option<&crate::services::authentication::FastCommitPlan>,
    ) -> anyhow::Result<crate::services::sm::BindingFinalizationOutcome> {
        self.sm_service
            .finalize_binding(
                connection_id,
                user_id,
                expected_auth_generation,
                full_jid,
                self.config.capacity_session_lease_seconds,
                device_id,
                fast_plan,
            )
            .await
    }

    pub(crate) async fn finalize_sm_resume(
        &self,
        request: crate::services::sm::SmResumeFinalizationRequest<'_>,
    ) -> anyhow::Result<crate::services::sm::SmResumeFinalizationOutcome> {
        self.sm_service.finalize_resume(request).await
    }

    fn start_locked_muc_expiry(state: Arc<Self>, cancel: CancellationToken) {
        let weak = Arc::downgrade(&state);
        state.worker_registry().supervise(
            "locked-muc-expiry",
            crate::workers::WorkerCriticality::Restartable,
            crate::workers::WorkerMode::Continuous,
            Some(Duration::from_secs(20)),
            cancel,
            move |heartbeat| {
                let weak = weak.clone();
                async move {
                    let mut interval = tokio::time::interval(Duration::from_secs(5));
                    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                    loop {
                        interval.tick().await;
                        let Some(state) = weak.upgrade() else {
                            return Ok(());
                        };
                        let expired = match state
                            .locked_muc_expiry_service()
                            .expire_locked_rooms(100)
                            .await
                        {
                            Ok(expired) => expired,
                            Err(error) => {
                                heartbeat.error(&error);
                                tracing::error!(
                                    ?error,
                                    "could not expire abandoned locked MUC rooms"
                                );
                                continue;
                            }
                        };
                        heartbeat.ok();
                        for localpart in expired {
                            let room_jid =
                                format!("{}@conference.{}", localpart, state.config.domain);
                            for (key, occupant) in state.muc_occupants_for(&room_jid) {
                                let serializable = SerializableMucOccupant::from(&occupant);
                                state.remove_live_muc_membership(&serializable);
                                state.muc_occupants.remove_if(&key, |_, current| {
                                    current.cluster_epoch == occupant.cluster_epoch
                                        && current.connection_id == occupant.connection_id
                                });
                                if !state.cluster.is_enabled() {
                                    let unavailable = crate::xmpp::xml_util::muc_destroy_presence(
                                        &serializable,
                                        None,
                                        None,
                                    );
                                    let _ =
                                        state.deliver_to_muc_occupant(&occupant, unavailable).await;
                                }
                            }
                            // The expiry transaction committed the tombstone
                            // and terminal outbox. Cluster nodes
                            // catch it up from PostgreSQL; emitting the legacy
                            // Redis destroy command would reintroduce a second
                            // executable authority.
                        }
                    }
                }
            },
        );
    }

    fn start_runtime_control_refresh(
        state: Arc<Self>,
        connection: PoolConnection<Postgres>,
        cancel: CancellationToken,
    ) {
        let weak = Arc::downgrade(&state);
        let connection = Arc::new(tokio::sync::Mutex::new(Some(connection)));
        let max_silence = Duration::from_secs(5);
        let diagnostic_cancel = cancel.clone();
        state.worker_registry().supervise(
            "runtime-control-refresh",
            crate::workers::WorkerCriticality::Critical,
            crate::workers::WorkerMode::Continuous,
            Some(max_silence),
            cancel,
            move |heartbeat| {
                let weak = weak.clone();
                let connection = Arc::clone(&connection);
                let diagnostic_cancel = diagnostic_cancel.clone();
                async move {
                    let mut diagnostics =
                        RuntimeControlDiagnostics::new(diagnostic_cancel, max_silence);
                    let mut connection = connection.lock().await.take().ok_or_else(|| {
                        anyhow::anyhow!(
                            "runtime-control coordinator was restarted after its reserved connection ended"
                        )
                    })?;
                    // This coordinator is the sole owner of the one reserved
                    // control-plane connection. It serializes committed
                    // administration, federation, and (when enabled) service
                    // control reads instead of allowing its own workers to
                    // contend for that connection.
                    let mut interval = tokio::time::interval(Duration::from_millis(500));
                    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                    let mut refresh_policy = true;
                    let mut acted_service_control = None;
                    loop {
                        interval.tick().await;
                        let Some(state) = weak.upgrade() else {
                            return Ok(());
                        };

                        let mut first_error = None;
                        let mut observed_database = false;
                        if refresh_policy {
                            observed_database = true;
                            match db::runtime_control_snapshot(&mut connection, |phase| {
                                diagnostics.database_read(phase)
                            })
                            .await
                            {
                                Ok((island_mode, registration_closed, blacklist, whitelist)) => {
                                    diagnostics.enter(RuntimeControlPhase::PolicyApply);
                                    let was_island = state.refresh_island_mode(island_mode).await;
                                    state.apply_registration_closed(registration_closed);
                                    if island_mode && !was_island {
                                        state
                                            .s2s_connection_registry()
                                            .clear_outbound_for_island_mode();
                                    }
                                    state.replace_runtime_federation_cache(blacklist, whitelist);
                                }
                                Err(error) => {
                                    tracing::error!(
                                        ?error,
                                        "could not refresh durable administration settings"
                                    );
                                    first_error = Some(error);
                                }
                            }

                        }

                        if state.config.enable_xmpp_service_control
                            && state.service_shutdown.get().is_some()
                        {
                            observed_database = true;
                            diagnostics.enter(RuntimeControlPhase::ServiceControlRead);
                            match db::poll_admin_service_control(&mut connection).await {
                                Ok(Some(control))
                                    if service_control_applies(
                                        state.process_started_at,
                                        &control,
                                    ) && acted_service_control != Some(control.generation) =>
                                {
                                    acted_service_control = Some(control.generation);
                                    tracing::warn!(
                                        operation = %control.action,
                                        generation = %control.generation,
                                        execute_at = %control.execute_at,
                                        expires_at = %control.expires_at,
                                        "executing durable cluster-wide service control"
                                    );
                                    if let Some(shutdown) = state.service_shutdown.get() {
                                        shutdown.cancel();
                                    }
                                }
                                Ok(_) => {}
                                Err(error) => {
                                    tracing::error!(
                                        ?error,
                                        "could not poll durable cluster-wide service control"
                                    );
                                    if first_error.is_none() {
                                        first_error = Some(error);
                                    }
                                }
                            }
                        }

                        report_runtime_control_health(&heartbeat, observed_database, first_error);
                        diagnostics.reported();
                        refresh_policy = !refresh_policy;
                    }
                }
            },
        );
    }

    pub fn federation_domain_allowed(&self, domain: &str) -> bool {
        let Ok(domain) = crate::jid::prepare_domainpart(domain) else {
            return false;
        };
        let policy = self.federation_runtime_policy.load();
        let domain_denied = policy.blacklist.iter().any(|entry| {
            crate::jid::CanonicalJid::parse(entry)
                .is_ok_and(|jid| jid.localpart().is_none() && jid.domainpart() == domain)
        });
        let domain_admitted = policy.whitelist.is_empty()
            || policy.whitelist.iter().any(|entry| {
                crate::jid::CanonicalJid::parse(entry).is_ok_and(|jid| jid.domainpart() == domain)
            });
        self.config.federation_domain_allowed(&domain) && !domain_denied && domain_admitted
    }

    /// Apply XEP-0133 entity rules using XEP-0016-style JID specificity: a
    /// domain rule matches the whole domain, a bare JID matches all of its
    /// resources, and a full JID matches exactly one resource.
    pub fn federation_entity_allowed(&self, entity: &str) -> bool {
        let Ok(entity) = crate::jid::CanonicalJid::parse(entity) else {
            return false;
        };
        if !self.config.federation_domain_allowed(entity.domainpart()) {
            return false;
        }
        let policy = self.federation_runtime_policy.load();
        let matches = |rule: &str| federation_rule_matches(rule, &entity);
        !policy.blacklist.iter().any(|entry| matches(entry))
            && (policy.whitelist.is_empty() || policy.whitelist.iter().any(|entry| matches(entry)))
    }

    pub fn replace_runtime_federation_cache(&self, blacklist: Vec<String>, whitelist: Vec<String>) {
        self.federation_runtime_policy
            .store(Arc::new(RuntimeFederationPolicy {
                blacklist: blacklist.into_iter().collect(),
                whitelist: whitelist.into_iter().collect(),
            }));
    }

    pub fn install_service_shutdown(
        self: &Arc<Self>,
        cancel: CancellationToken,
    ) -> anyhow::Result<()> {
        self.service_shutdown
            .set(cancel)
            .map_err(|_| anyhow::anyhow!("service shutdown control was already installed"))?;
        Ok(())
    }

    pub fn service_control_available(&self) -> bool {
        self.config.enable_xmpp_service_control && self.service_shutdown.get().is_some()
    }

    /// Cancel only the local route incarnation whose PostgreSQL MUC occupancy
    /// has been found stale. A replacement under the same JID remains intact.
    pub(crate) fn cancel_local_session_if_connection(
        &self,
        full_jid: &str,
        connection_id: uuid::Uuid,
    ) -> bool {
        cancel_local_session_if_connection_in(&self.sessions, full_jid, connection_id)
    }

    /// Called only after the durable cluster-instance authority check.
    pub(crate) fn fence_local_session_instance(
        &self,
        full_jid: &str,
        connection_id: uuid::Uuid,
    ) -> bool {
        fence_local_session_in(
            &self.sessions,
            full_jid,
            LocalSessionFence::Instance(connection_id),
        )
    }

    pub(crate) fn fence_local_sm_session(&self, full_jid: &str, sm_session_id: uuid::Uuid) -> bool {
        fence_local_session_in(
            &self.sessions,
            full_jid,
            LocalSessionFence::Sm(sm_session_id),
        )
    }

    pub(crate) fn fence_local_admin_session(
        &self,
        full_jid: &str,
        user_id: uuid::Uuid,
        auth_generation: i64,
        connection_id: uuid::Uuid,
    ) -> bool {
        fence_local_session_in(
            &self.sessions,
            full_jid,
            LocalSessionFence::Admin {
                user_id,
                auth_generation,
                connection_id,
            },
        )
    }

    /// Reserve a non-routable bind candidate under the same map entry guard
    /// that rejects a concurrent bind or resume for this full JID.
    pub(crate) fn try_stage_bound_session(&self, key: String, session: OnlineSession) -> bool {
        try_stage_bound_session_in(&self.sessions, key, session)
    }

    pub(crate) fn staged_session_is_current(
        &self,
        key: &str,
        connection_id: uuid::Uuid,
        user_id: uuid::Uuid,
        auth_generation: i64,
        lifecycle: &Arc<AtomicU8>,
    ) -> bool {
        self.sessions.get(key).is_some_and(|session| {
            session.connection_id == connection_id
                && session.user_id == user_id
                && session.auth_generation == auth_generation
                && Arc::ptr_eq(&session.lifecycle, lifecycle)
                && !session.disconnect.is_cancelled()
                && session.lifecycle.load(Ordering::Acquire) == 0
        })
    }

    pub(crate) fn publish_user_agent_epoch_if_current(
        &self,
        key: &str,
        connection_id: uuid::Uuid,
        user_id: uuid::Uuid,
        auth_generation: i64,
        lifecycle: &Arc<AtomicU8>,
        user_agent_epoch: Option<i64>,
    ) -> bool {
        let Some(mut session) = self.sessions.get_mut(key) else {
            return false;
        };
        if session.connection_id != connection_id
            || session.user_id != user_id
            || session.auth_generation != auth_generation
            || !Arc::ptr_eq(&session.lifecycle, lifecycle)
            || session.disconnect.is_cancelled()
            || session.lifecycle.load(Ordering::Acquire) != 0
        {
            return false;
        }
        session.user_agent_epoch = user_agent_epoch;
        true
    }

    /// A carbon preference is session-local and must be visible to fan-out
    /// before its IQ result is sent to the same connection.
    pub(crate) fn set_local_carbons_for_connection(
        &self,
        key: &str,
        connection_id: uuid::Uuid,
        enabled: bool,
    ) -> bool {
        let Some(route) = self.sessions.get(key) else {
            return false;
        };
        if route.connection_id != connection_id {
            return false;
        }
        route.carbons.store(enabled, Ordering::Release);
        true
    }

    pub(crate) fn sm_pending_route_removal_signal(
        &self,
        key: &str,
        old_connection_id: uuid::Uuid,
        user_id: uuid::Uuid,
        sm_session_id: uuid::Uuid,
        cancel_live_route: bool,
    ) -> Option<tokio::sync::watch::Receiver<bool>> {
        let session = self.sessions.get(key)?;
        let exact_sm = session
            .sm_session_id
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .is_some_and(|current| current == sm_session_id);
        if session.connection_id != old_connection_id || session.user_id != user_id || !exact_sm {
            return None;
        }
        if cancel_live_route {
            session.disconnect.cancel();
        }
        Some(session.route_incarnation.subscribe())
    }

    pub(crate) fn sm_presence_epoch(&self, key: &str) -> Option<SmPresenceEpoch> {
        self.sessions.get(key).map(|session| SmPresenceEpoch {
            gate: Arc::clone(&session.mix_presence_gate),
            fallback_suppressed: Arc::clone(&session.mix_presence_fallback_suppressed),
            caps_generation: Arc::clone(&session.caps_observation_generation),
        })
    }

    /// Inspect/insert inside one DashMap entry operation. The caller owns the
    /// returned gate and route-incarnation handles before any async wait.
    pub(crate) fn stage_sm_resumed_session(
        &self,
        key: String,
        candidate: OnlineSession,
        claimant_user: uuid::Uuid,
        claimed_sm_id: uuid::Uuid,
        expected_gate: &Arc<tokio::sync::Mutex<()>>,
    ) -> SmStagedRouteClaim {
        stage_sm_resumed_session_in(
            &self.sessions,
            key,
            candidate,
            claimant_user,
            claimed_sm_id,
            expected_gate,
        )
    }

    /// The command protocol receives only the delivered account identities,
    /// not mutable access to the session table.
    pub(crate) fn send_local_announcement(
        &self,
        stanza: &str,
    ) -> std::collections::BTreeSet<String> {
        let mut recipients = std::collections::BTreeSet::new();
        for entry in self.sessions.iter() {
            if entry.routable.load(Ordering::Acquire)
                && entry.available.load(Ordering::Acquire)
                && entry.priority.load(Ordering::Acquire) >= 0
                && entry.sender.try_send(stanza.to_owned()).is_ok()
            {
                if let Ok(bare) = crate::jid::canonical_bare_key(entry.key()) {
                    recipients.insert(bare);
                }
            }
        }
        recipients
    }

    pub(crate) fn local_online_bare_jids(&self) -> std::collections::BTreeSet<String> {
        self.sessions
            .iter()
            .filter(|entry| entry.routable.load(Ordering::Acquire))
            .filter_map(|entry| crate::jid::canonical_bare_key(entry.key()).ok())
            .collect()
    }

    pub(crate) fn local_activity_bare_jids(
        &self,
        idle_after: Duration,
    ) -> (
        std::collections::BTreeSet<String>,
        std::collections::BTreeSet<String>,
    ) {
        let mut online = std::collections::BTreeSet::new();
        let mut active = std::collections::BTreeSet::new();
        for entry in self.sessions.iter() {
            if !entry.routable.load(Ordering::Acquire) {
                continue;
            }
            let Ok(bare) = crate::jid::canonical_bare_key(entry.key()) else {
                continue;
            };
            online.insert(bare.clone());
            if entry
                .last_activity
                .read()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .elapsed()
                < idle_after
            {
                active.insert(bare);
            }
        }
        (online, active)
    }

    /// Initial key snapshot for an account presence probe. The protocol then
    /// rechecks each incarnation after its privacy/database awaits.
    pub(crate) fn local_presence_owner_keys(&self) -> Vec<String> {
        self.sessions
            .iter()
            .map(|entry| entry.key().clone())
            .collect()
    }

    pub(crate) fn local_presence_owner_candidate(
        &self,
        key: &str,
        user_id: uuid::Uuid,
        auth_generation: i64,
    ) -> Option<OnlineSession> {
        self.sessions.get(key).and_then(|session| {
            (session.routable.load(Ordering::Acquire)
                && session.user_id == user_id
                && session.auth_generation == auth_generation
                && session.available.load(Ordering::Relaxed))
            .then(|| session.value().clone())
        })
    }

    pub(crate) fn local_presence_owner_if_current(
        &self,
        key: &str,
        expected: &OnlineSession,
        user_id: uuid::Uuid,
        auth_generation: i64,
    ) -> Option<OnlineSession> {
        self.sessions.get(key).and_then(|current| {
            (current.connection_id == expected.connection_id
                && Arc::ptr_eq(&current.route_incarnation, &expected.route_incarnation)
                && current.user_id == user_id
                && current.auth_generation == auth_generation
                && current.routable.load(Ordering::Acquire)
                && current.available.load(Ordering::Relaxed))
            .then(|| current.value().clone())
        })
    }

    pub(crate) fn send_presence_if_owner_current(
        &self,
        key: &str,
        expected: &OnlineSession,
        user_id: uuid::Uuid,
        auth_generation: i64,
        recipient: &crate::outbound::OutboundSender,
        presence: &str,
    ) -> bool {
        let Some(current) = self.sessions.get(key) else {
            return false;
        };
        if current.connection_id != expected.connection_id
            || !Arc::ptr_eq(&current.route_incarnation, &expected.route_incarnation)
            || current.user_id != user_id
            || current.auth_generation != auth_generation
            || !current.routable.load(Ordering::Acquire)
            || !current.available.load(Ordering::Relaxed)
        {
            return false;
        }
        recipient.try_send(presence.to_owned()).is_ok()
    }

    pub(crate) fn local_caps_epoch_is_current(
        &self,
        full_jid: &str,
        epoch: LocalCapsEpoch,
        expected_gate: Option<&Arc<tokio::sync::Mutex<()>>>,
    ) -> bool {
        self.sessions.get(full_jid).is_some_and(|session| {
            local_caps_route_epoch_matches(
                session.connection_id,
                session.caps_observation_generation.load(Ordering::Acquire),
                session.routable.load(Ordering::Acquire),
                session.disconnect.is_cancelled(),
                session.lifecycle.load(Ordering::Acquire),
                expected_gate.is_none_or(|gate| Arc::ptr_eq(&session.mix_presence_gate, gate)),
                epoch,
            )
        })
    }

    pub(crate) fn local_caps_sender_if_current(
        &self,
        full_jid: &str,
        epoch: LocalCapsEpoch,
    ) -> Option<crate::outbound::OutboundSender> {
        self.sessions.get(full_jid).and_then(|session| {
            local_caps_route_epoch_matches(
                session.connection_id,
                session.caps_observation_generation.load(Ordering::Acquire),
                session.routable.load(Ordering::Acquire),
                session.disconnect.is_cancelled(),
                session.lifecycle.load(Ordering::Acquire),
                true,
                epoch,
            )
            .then(|| session.sender.clone())
        })
    }

    pub(crate) fn local_caps_observer_connection_is_current(
        &self,
        full_jid: &str,
        connection_id: uuid::Uuid,
        expected_gate: &Arc<tokio::sync::Mutex<()>>,
    ) -> bool {
        self.sessions.get(full_jid).is_some_and(|session| {
            session.connection_id == connection_id
                && Arc::ptr_eq(&session.mix_presence_gate, expected_gate)
                && session.routable.load(Ordering::Acquire)
                && !session.disconnect.is_cancelled()
                && session.lifecycle.load(Ordering::Acquire) == 0
        })
    }

    pub(crate) fn local_mix_presence_gate(
        &self,
        full_jid: &str,
        connection_id: uuid::Uuid,
    ) -> Option<Arc<tokio::sync::Mutex<()>>> {
        self.sessions
            .get(full_jid)
            .filter(|session| session.connection_id == connection_id)
            .map(|session| Arc::clone(&session.mix_presence_gate))
    }

    pub(crate) fn local_mix_presence_epoch_state(
        &self,
        full_jid: &str,
        expected_connection_id: uuid::Uuid,
        expected_caps_generation: u64,
        expected_gate: &Arc<tokio::sync::Mutex<()>>,
        channel_jid: &str,
    ) -> Option<(bool, bool)> {
        self.sessions.get(full_jid).map(|session| {
            (
                mix_presence_epoch_is_current(
                    session.connection_id,
                    expected_connection_id,
                    session.caps_observation_generation.load(Ordering::Acquire),
                    expected_caps_generation,
                    session.routable.load(Ordering::Acquire),
                    session.available.load(Ordering::Acquire),
                    Arc::ptr_eq(&session.mix_presence_gate, expected_gate),
                ),
                mix_presence_fallback_is_suppressed(
                    &session.mix_presence_fallback_suppressed,
                    channel_jid,
                ),
            )
        })
    }

    pub(crate) fn local_mix_presence_route_is_current(
        &self,
        full_jid: &str,
        expected_connection_id: uuid::Uuid,
        expected_gate: &Arc<tokio::sync::Mutex<()>>,
        require_available: bool,
    ) -> bool {
        self.sessions.get(full_jid).is_some_and(|session| {
            session.connection_id == expected_connection_id
                && Arc::ptr_eq(&session.mix_presence_gate, expected_gate)
                && session.routable.load(Ordering::Acquire)
                && (!require_available || session.available.load(Ordering::Acquire))
                && !session.disconnect.is_cancelled()
                && session.lifecycle.load(Ordering::Acquire) == 0
        })
    }

    pub fn sessions_for(&self, jid: &str) -> Vec<OnlineSession> {
        let Some(lookup) = session_lookup(jid) else {
            return Vec::new();
        };
        match lookup {
            SessionLookup::Full(full) => self
                .sessions
                .get(&full)
                .filter(|entry| entry.routable.load(Ordering::Acquire))
                .map(|entry| vec![entry.value().clone()])
                .unwrap_or_default(),
            SessionLookup::Bare(bare) => self
                .sessions
                .iter()
                .filter(|entry| {
                    bare_jid(entry.key()) == bare.as_str() && entry.routable.load(Ordering::Acquire)
                })
                .map(|entry| entry.value().clone())
                .collect(),
        }
    }

    pub fn session_entries_for(&self, jid: &str) -> Vec<(String, OnlineSession)> {
        let Some(lookup) = session_lookup(jid) else {
            return Vec::new();
        };
        match lookup {
            SessionLookup::Full(full) => self
                .sessions
                .get(&full)
                .filter(|entry| entry.routable.load(Ordering::Acquire))
                .map(|entry| vec![(entry.key().clone(), entry.value().clone())])
                .unwrap_or_default(),
            SessionLookup::Bare(bare) => self
                .sessions
                .iter()
                .filter(|entry| {
                    bare_jid(entry.key()) == bare.as_str() && entry.routable.load(Ordering::Acquire)
                })
                .map(|entry| (entry.key().clone(), entry.value().clone()))
                .collect(),
        }
    }

    /// Publish only the exact staged route incarnation that survived every
    /// authorization and lifecycle fence.  The DashMap write guard provides
    /// a local linearization point with account/session revocation helpers;
    /// the cancellation/lifecycle recheck after publication also closes a
    /// concurrent out-of-band transport cancellation window.
    pub(crate) fn activate_session_if_current(
        &self,
        full_jid: &str,
        connection_id: uuid::Uuid,
        user_id: uuid::Uuid,
        auth_generation: i64,
        lifecycle: &Arc<AtomicU8>,
        disconnect: &CancellationToken,
    ) -> bool {
        let Some(session) = self.sessions.get_mut(full_jid) else {
            return false;
        };
        if !staged_route_activation_allowed(StagedRouteActivationCheck {
            session: StagedRouteIdentity {
                connection_id: session.connection_id,
                user_id: session.user_id,
                auth_generation: session.auth_generation,
            },
            expected: StagedRouteIdentity {
                connection_id,
                user_id,
                auth_generation,
            },
            same_lifecycle: Arc::ptr_eq(&session.lifecycle, lifecycle),
            lifecycle_state: session.lifecycle.load(Ordering::Acquire),
            session_cancelled: session.disconnect.is_cancelled(),
            owner_cancelled: disconnect.is_cancelled(),
        }) {
            return false;
        }
        session.routable.store(true, Ordering::Release);
        if session.lifecycle.load(Ordering::Acquire) != 0
            || session.disconnect.is_cancelled()
            || disconnect.is_cancelled()
        {
            session.routable.store(false, Ordering::Release);
            return false;
        }
        true
    }

    /// Cancel local account routes, including non-routable two-phase bind or
    /// resume candidates.  Public lookup helpers intentionally hide those
    /// candidates, so authorization revocation must iterate the authority map
    /// itself and set `routable=false` under the same per-entry write guard
    /// used by activation.
    pub(crate) fn revoke_local_account_routes(
        &self,
        user_id: uuid::Uuid,
        bare_account_jid: &str,
        auth_generation_exclusive: Option<i64>,
    ) -> usize {
        AccountRevocationRoutes::revoke_in(
            &self.sessions,
            user_id,
            bare_account_jid,
            auth_generation_exclusive,
        )
    }

    /// Remove exactly one local route incarnation. Every rollback and Drop
    /// path must use this instead of an unconditional DashMap removal: a late
    /// old connection must never delete a newly bound/resumed replacement.
    pub fn remove_session_if_connection(
        &self,
        key: &str,
        connection_id: uuid::Uuid,
    ) -> Option<OnlineSession> {
        let (_, removed) = self
            .sessions
            .remove_if(key, |_, session| session.connection_id == connection_id)?;
        debug_assert_eq!(removed.route_incarnation.connection_id(), connection_id);
        // Publish immediately after the exact compare-and-remove.  Any route
        // inserted between removal and this notification is a new incarnation;
        // waiters re-read `sessions` and must not mistake that ABA for vacancy.
        removed.route_incarnation.publish_removed();
        self.caps_effect_dispatcher
            .cancel_local(key, removed.connection_id);
        self.caps_by_jid
            .remove_local_resource(key, removed.connection_id);
        self.pending_caps
            .remove_local_resource(key, removed.connection_id);
        if removed.metrics_counted.swap(false, Ordering::AcqRel) {
            self.metrics.active_sessions.fetch_sub(1, Ordering::Relaxed);
        }
        Some(removed)
    }

    pub fn muc_occupants_for(&self, room_jid: &str) -> Vec<(String, MucOccupant)> {
        let Ok(room_jid) = crate::jid::canonicalize_bare(room_jid) else {
            return Vec::new();
        };
        self.muc_occupants
            .iter()
            .filter(|entry| entry.value().room_jid == room_jid)
            .map(|entry| (entry.key().clone(), entry.value().clone()))
            .collect()
    }

    pub(crate) fn local_muc_occupant_by_nick(
        &self,
        room_jid: &str,
        nick: &str,
    ) -> Option<MucOccupant> {
        let room_jid = crate::jid::canonicalize_bare(room_jid).ok()?;
        let key = crate::xmpp::xml_util::muc_occupant_key(&room_jid, nick);
        self.muc_occupants
            .get(&key)
            .filter(|occupant| occupant.room_jid == room_jid)
            .map(|occupant| occupant.value().clone())
    }

    pub(crate) fn local_muc_occupant_exact(
        &self,
        identity: LocalMucOccupantIdentity<'_>,
    ) -> Option<MucOccupant> {
        with_local_muc_occupant_exact(&self.muc_occupants, identity, |current| current.clone())
    }

    /// Refresh presence fields only while this exact transport still owns the
    /// nickname. Keep the current endpoint so an SM suspension cannot be undone.
    pub(crate) fn refresh_local_muc_presence_exact(
        &self,
        prepared: &MucOccupant,
        apply_policy: bool,
    ) -> Option<MucOccupant> {
        refresh_local_muc_presence_exact_in(&self.muc_occupants, prepared, apply_policy)
    }

    /// Move a nickname after the caller's room gate or PG transition. A local
    /// collision restores the exact removed old value; a committed cluster
    /// collision leaves the other incarnation untouched for reconciliation.
    pub(crate) fn move_local_muc_nickname_exact(
        &self,
        old: LocalMucOccupantIdentity<'_>,
        renamed: &MucOccupant,
        cluster_committed: bool,
    ) -> LocalMucNicknameMove {
        move_local_muc_nickname_exact_in(&self.muc_occupants, old, renamed, cluster_committed)
    }

    /// Publish a join under one map shard lock without replacing a later
    /// transport that acquired the same nickname.
    pub(crate) fn publish_local_muc_join_if_vacant(
        &self,
        joining: &MucOccupant,
    ) -> LocalMucJoinPublication {
        publish_local_muc_join_if_vacant_in(&self.muc_occupants, joining)
    }

    /// Compare and remove under one map shard lock. Callers retain the removed
    /// value for any post-removal delivery; no map guard crosses an await.
    pub(crate) fn remove_local_muc_occupant_exact(
        &self,
        identity: LocalMucOccupantIdentity<'_>,
    ) -> Option<MucOccupant> {
        remove_local_muc_occupant_exact_from(&self.muc_occupants, identity)
    }

    /// Apply a registration or admin affiliation change to the same live
    /// occupancy that was authorized. The returned snapshot holds no map lock.
    pub(crate) fn set_local_muc_affiliation_exact(
        &self,
        identity: LocalMucOccupantIdentity<'_>,
        affiliation: &str,
        moderated: bool,
        only_if_none: bool,
        expected_affiliation: Option<&str>,
    ) -> Option<MucOccupant> {
        set_local_muc_affiliation_exact_in(
            &self.muc_occupants,
            identity,
            affiliation,
            moderated,
            only_if_none,
            expected_affiliation,
        )
    }

    /// Change only the role and optional room visibility of an exact occupant.
    pub(crate) fn set_local_muc_role_exact(
        &self,
        identity: LocalMucOccupantIdentity<'_>,
        expected_role: &str,
        role: &str,
        non_anonymous: Option<bool>,
    ) -> Option<MucOccupant> {
        set_local_muc_role_exact_in(
            &self.muc_occupants,
            identity,
            expected_role,
            role,
            non_anonymous,
        )
    }

    /// Recompute policy fields from the current affiliation, preserving
    /// transport, presence payload and any other concurrently refreshed data.
    pub(crate) fn refresh_local_muc_policy_exact(
        &self,
        identity: LocalMucOccupantIdentity<'_>,
        moderated: Option<bool>,
        non_anonymous: Option<bool>,
    ) -> Option<(MucOccupant, bool)> {
        refresh_local_muc_policy_exact_in(&self.muc_occupants, identity, moderated, non_anonymous)
    }

    /// Revoke the exact live protocol actor membership represented by an
    /// occupant.  All four identities are required so a delayed kick or
    /// teardown cannot affect a later connection or a reused nickname.
    pub fn remove_live_muc_membership(&self, occupant: &SerializableMucOccupant) -> bool {
        let Ok(full_jid) = crate::jid::canonical_session_key(&occupant.full_jid) else {
            return false;
        };
        let Some(session) = self.sessions.get(&full_jid) else {
            return false;
        };
        if occupant.connection_id.is_nil() || session.connection_id != occupant.connection_id {
            return false;
        }
        session
            .muc_memberships
            .remove_if(&occupant.room_jid, |_, membership| {
                membership.nick == occupant.nick
                    && membership.cluster_epoch == occupant.cluster_epoch
                    && !membership.cluster_epoch.is_nil()
            })
            .is_some()
    }

    /// Resolve a room membership only when it is still owned by the exact
    /// live transport and occupancy incarnation.  A room/nickname pair is
    /// deliberately insufficient because both values can be reused after a
    /// kick, disconnect, or resume race.
    pub fn validated_local_muc_occupant(
        &self,
        full_jid: &str,
        connection_id: uuid::Uuid,
        room_jid: &str,
        membership: &JoinedMucMembership,
    ) -> Option<MucOccupant> {
        if connection_id.is_nil() || membership.cluster_epoch.is_nil() {
            return None;
        }
        let full_jid = crate::jid::canonical_session_key(full_jid).ok()?;
        let room_jid = crate::jid::canonicalize_bare(room_jid).ok()?;
        let session = self.sessions.get(&full_jid)?;
        if session.connection_id != connection_id
            || !session
                .muc_memberships
                .get(&room_jid)
                .is_some_and(|current| current.value() == membership)
        {
            return None;
        }
        drop(session);
        let key = crate::xmpp::xml_util::muc_occupant_key(&room_jid, &membership.nick);
        self.muc_occupants
            .get(&key)
            .filter(|occupant| {
                muc_actor_identity_matches(
                    occupant,
                    &full_jid,
                    connection_id,
                    &room_jid,
                    membership,
                )
            })
            .map(|occupant| occupant.value().clone())
    }

    pub async fn deliver_to_muc_occupant(&self, occupant: &MucOccupant, stanza: String) -> bool {
        self.deliver_to_muc_occupant_inner(occupant, stanza, None, None)
            .await
    }

    /// Deliver one durable clustered policy event and wait until the endpoint
    /// owns it recoverably (SM/BOSH/suspended storage) or its socket write has
    /// completed. A successful `try_send` alone is deliberately insufficient.
    pub(crate) async fn deliver_to_muc_occupant_with_receipt(
        &self,
        occupant: &MucOccupant,
        stanza: String,
        delivery: &db::ClusterMucOutboxDelivery,
    ) -> anyhow::Result<bool> {
        let (receipt, mut received) = tokio::sync::mpsc::unbounded_channel();
        let accepted = self
            .deliver_to_muc_occupant_inner(occupant, stanza, Some(receipt), None)
            .await;
        if !accepted {
            return Ok(false);
        }
        let mut renew = tokio::time::interval(Duration::from_secs(10));
        renew.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                result = received.recv() => return Ok(result.is_some()),
                _ = renew.tick() => {
                    anyhow::ensure!(
                        db::renew_cluster_muc_outbox_claim(
                            &self.pool, delivery, Duration::from_secs(30)
                        ).await?,
                        "cluster MUC transport receipt lost its exact outbox claim"
                    );
                }
            }
        }
    }

    async fn deliver_to_muc_occupant_inner(
        &self,
        occupant: &MucOccupant,
        stanza: String,
        receipt: Option<tokio::sync::mpsc::UnboundedSender<()>>,
        write_receipt: Option<tokio::sync::mpsc::UnboundedSender<()>>,
    ) -> bool {
        let senders = roxmltree::Document::parse(&stanza)
            .ok()
            .map(|document| {
                let root = document.root_element();
                let mut senders = root
                    .attribute("from")
                    .and_then(|sender| crate::jid::canonicalize(sender).ok())
                    .into_iter()
                    .collect::<Vec<_>>();
                if root.tag_name().name() == "presence" {
                    senders.extend(root.descendants().filter_map(|node| {
                        (node.is_element()
                            && node.tag_name().name() == "item"
                            && node.tag_name().namespace()
                                == Some("http://jabber.org/protocol/muc#user"))
                        .then(|| node.attribute("jid"))
                        .flatten()
                        .and_then(|jid| crate::jid::canonicalize(jid).ok())
                    }));
                }
                senders.sort_unstable();
                senders.dedup();
                senders
            })
            .unwrap_or_default();
        if !senders.is_empty() {
            let blocked = self
                .blocked_muc_recipient_accounts(std::slice::from_ref(occupant), &senders)
                .await;
            if crate::jid::canonical_bare_key(&occupant.full_jid)
                .is_ok_and(|owner| blocked.contains(&owner))
            {
                return false;
            }
        }
        self.deliver_to_muc_occupant_unchecked_result_with_receipt(
            occupant,
            stanza,
            receipt,
            write_receipt,
        )
        .await
        .unwrap_or_else(|error| {
            tracing::warn!(?error, "failed to deliver a MUC stanza");
            false
        })
    }

    /// Rebuild only the delivery endpoint for an immutable clustered MUC
    /// audience row. This never restores membership in the live maps and
    /// never grants authorization: it exists so a committed terminal event
    /// (kick/ban/destroy/policy eviction) remains deliverable after a process
    /// crash even though PostgreSQL has already revoked the occupancy.
    pub(crate) fn cluster_muc_recipient_from_snapshot(
        &self,
        snapshot: &db::ClusterMucAudienceSnapshot,
        room_jid: &str,
        room_non_anonymous: bool,
        occupant_id: String,
    ) -> Option<MucOccupant> {
        let endpoint = match snapshot.identity_kind.as_str() {
            "local" => {
                if let Some(session) = self.sessions.get(&snapshot.full_jid) {
                    if session.connection_id == snapshot.connection_uuid
                        && snapshot.local_user_id == Some(session.user_id)
                    {
                        MucOccupantEndpoint::Local(session.sender.clone())
                    } else {
                        drop(session);
                        let sm_session_id = snapshot.sm_session_id?;
                        MucOccupantEndpoint::Suspended(Arc::new(SuspendedMucEndpoint::new_durable(
                            sm_session_id,
                        )))
                    }
                } else {
                    let sm_session_id = snapshot.sm_session_id?;
                    MucOccupantEndpoint::Suspended(Arc::new(SuspendedMucEndpoint::new_durable(
                        sm_session_id,
                    )))
                }
            }
            "federated" => MucOccupantEndpoint::Federated {
                authenticated_domain: snapshot.authenticated_domain.clone()?,
                connection_id: snapshot.connection_uuid,
            },
            _ => return None,
        };
        Some(MucOccupant {
            full_jid: snapshot.full_jid.clone(),
            room_jid: room_jid.to_owned(),
            nick: snapshot.nick.clone(),
            endpoint,
            affiliation: snapshot.affiliation.clone(),
            role: snapshot.role.clone(),
            room_non_anonymous,
            occupant_id,
            cluster_epoch: snapshot.occupant_incarnation,
            connection_id: snapshot.connection_uuid,
            sm_session_id: snapshot.sm_session_id,
            // Audience snapshots intentionally omit the recipient's previous
            // presence payload; endpoint reconstruction is delivery-only and
            // must not recreate advertised soft state.
            payload: String::new(),
        })
    }

    /// Batch XEP-0191 filter for MUC fan-out. Database failure is fail-closed
    /// for local occupants so a transient outage cannot leak a blocked room or
    /// real sender; remote occupants remain the responsibility of their home
    /// server.
    pub async fn blocked_muc_recipient_accounts(
        &self,
        occupants: &[MucOccupant],
        stanza_senders: &[String],
    ) -> std::collections::HashSet<String> {
        let occupant_jids = occupants
            .iter()
            .map(|occupant| occupant.full_jid.clone())
            .collect::<Vec<_>>();
        match db::blocked_local_accounts_for_candidates(
            &self.pool,
            &self.config.domain,
            &occupant_jids,
            stanza_senders,
        )
        .await
        {
            Ok(blocked) => blocked,
            Err(error) => {
                tracing::warn!(
                    ?error,
                    "failed MUC recipient blocklist lookup; denying local delivery"
                );
                occupant_jids
                    .iter()
                    .filter_map(|jid| crate::jid::CanonicalJid::parse(jid).ok())
                    .filter(|jid| jid.domainpart() == self.config.domain)
                    .map(|jid| jid.bare())
                    .collect()
            }
        }
    }

    /// Use only after `blocked_muc_recipient_accounts` covered the exact
    /// visible and real senders for this fan-out batch.
    pub async fn deliver_to_muc_occupant_unchecked(
        &self,
        occupant: &MucOccupant,
        stanza: String,
    ) -> bool {
        self.deliver_to_muc_occupant_unchecked_result(occupant, stanza)
            .await
            .unwrap_or_else(|error| {
                tracing::warn!(?error, "failed to deliver a MUC stanza");
                false
            })
    }

    async fn deliver_to_muc_occupant_unchecked_result(
        &self,
        occupant: &MucOccupant,
        stanza: String,
    ) -> anyhow::Result<bool> {
        self.deliver_to_muc_occupant_unchecked_result_with_receipt(occupant, stanza, None, None)
            .await
    }

    async fn deliver_to_muc_occupant_unchecked_result_with_receipt(
        &self,
        occupant: &MucOccupant,
        stanza: String,
        receipt: Option<tokio::sync::mpsc::UnboundedSender<()>>,
        write_receipt: Option<tokio::sync::mpsc::UnboundedSender<()>>,
    ) -> anyhow::Result<bool> {
        // Installing the session gate precedes the per-room endpoint swaps.
        // Consulting it first makes that multi-entry transition atomic from
        // every delivery path's point of view and preserves one cross-room
        // FIFO from the first quiesced stanza onward.
        let session_gate = if matches!(
            &occupant.endpoint,
            MucOccupantEndpoint::Local(_) | MucOccupantEndpoint::Suspended(_)
        ) {
            let sm_session_id = occupant.sm_session_id.or_else(|| {
                self.sessions.get(&occupant.full_jid).and_then(|session| {
                    if session.connection_id != occupant.connection_id {
                        return None;
                    }
                    let sm_session_id = *session
                        .sm_session_id
                        .read()
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                    sm_session_id
                })
            });
            sm_session_id.and_then(|sm_session_id| {
                self.suspended_muc_sessions
                    .get(&sm_session_id)
                    .map(|endpoint| Arc::clone(&endpoint))
            })
        } else {
            None
        };
        let privacy_peer_kind = roxmltree::Document::parse(&stanza)
            .ok()
            .and_then(|document| {
                let root = document.root_element();
                let kind = match root.tag_name().name() {
                    "message" => db::PrivacyStanzaKind::Message,
                    "iq" => db::PrivacyStanzaKind::Iq,
                    "presence" => db::PrivacyStanzaKind::PresenceIn,
                    _ => return None,
                };
                let peer = root
                    .attribute("from")
                    .and_then(|from| crate::jid::canonicalize(from).ok())?;
                Some((peer, kind))
            });
        if let Some((peer, kind)) = privacy_peer_kind.as_ref() {
            if let Some(suspended) = &session_gate {
                if db::privacy_denies_for_sm_session(
                    &self.pool,
                    suspended.sm_session_id,
                    peer,
                    *kind,
                )
                .await?
                .unwrap_or(true)
                {
                    return Ok(false);
                }
            } else {
                match &occupant.endpoint {
                    MucOccupantEndpoint::Local(_) => {
                        let Some(session) =
                            self.sessions_for(&occupant.full_jid).into_iter().next()
                        else {
                            return Ok(false);
                        };
                        if !self.privacy_allows_session(&session, peer, *kind).await? {
                            return Ok(false);
                        }
                    }
                    MucOccupantEndpoint::Suspended(suspended) => {
                        if db::privacy_denies_for_sm_session(
                            &self.pool,
                            suspended.sm_session_id,
                            peer,
                            *kind,
                        )
                        .await?
                        .unwrap_or(true)
                        {
                            return Ok(false);
                        }
                    }
                    MucOccupantEndpoint::Federated { .. } => {}
                }
            }
        }
        if write_receipt.is_some() {
            let membership = JoinedMucMembership {
                nick: occupant.nick.clone(),
                cluster_epoch: occupant.cluster_epoch,
            };
            if self
                .validated_local_muc_occupant(
                    &occupant.full_jid,
                    occupant.connection_id,
                    &occupant.room_jid,
                    &membership,
                )
                .is_none()
            {
                return Ok(false);
            }
        }
        if let Some(suspended) = session_gate {
            return self
                .deliver_to_suspended_muc_endpoint(&suspended, stanza, receipt, write_receipt)
                .await;
        }
        match &occupant.endpoint {
            MucOccupantEndpoint::Local(sender) if write_receipt.is_some() => {
                let receipt = write_receipt.expect("write receipt was present");
                match sender.try_send_with_transport_write_receipt(stanza, receipt) {
                    Ok(()) => Ok(true),
                    Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => Ok(false),
                    Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                        anyhow::bail!("local MUC shutdown recipient queue is full")
                    }
                }
            }
            MucOccupantEndpoint::Local(sender) => match receipt {
                Some(receipt) => match sender.try_send_with_transport_receipt(stanza, receipt) {
                    Ok(()) => Ok(true),
                    Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => Ok(false),
                    Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                        anyhow::bail!("local MUC recipient queue is full")
                    }
                },
                None => match sender.try_send(stanza) {
                    Ok(()) => Ok(true),
                    Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => Ok(false),
                    Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                        anyhow::bail!("local MUC recipient queue is full")
                    }
                },
            },
            MucOccupantEndpoint::Suspended(suspended) => {
                self.deliver_to_suspended_muc_endpoint(suspended, stanza, receipt, None)
                    .await
            }
            MucOccupantEndpoint::Federated {
                authenticated_domain,
                ..
            } => {
                anyhow::ensure!(
                    self.federation_outbox
                        .send(authenticated_domain, stanza, None)
                        .await,
                    "federation queue rejected MUC stanza"
                );
                if let Some(receipt) = receipt {
                    let _ = receipt.send(());
                }
                Ok(true)
            }
        }
    }

    async fn deliver_to_suspended_muc_endpoint(
        &self,
        suspended: &Arc<SuspendedMucEndpoint>,
        stanza: String,
        receipt: Option<tokio::sync::mpsc::UnboundedSender<()>>,
        write_receipt: Option<tokio::sync::mpsc::UnboundedSender<()>>,
    ) -> anyhow::Result<bool> {
        if let Some(receipt) = write_receipt {
            return suspended.try_send_live_write_notification(stanza, receipt);
        }
        let mut stanza = Some(stanza);
        let mut receipt = receipt;
        let volatile_source_id = uuid::Uuid::new_v4();
        loop {
            // Live delivery and Live->Transitioning use this exact synchronous
            // mutex. There is no check/send window in which cleanup can install
            // a fence behind an already-approved old transport write.
            let wait_for_route = {
                let route = suspended
                    .route
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                match &*route {
                    SuspendedMucRoute::Live(sender) => {
                        let stanza = stanza.take().expect("MUC delivery owns one stanza");
                        return match receipt.take() {
                            Some(receipt) => sender
                                .try_send_with_transport_receipt(stanza, receipt)
                                .map(|_| true)
                                .map_err(|error| {
                                    anyhow::anyhow!(
                                        "resuming MUC recipient queue rejected stanza: {error}"
                                    )
                                }),
                            None => match sender.try_send(stanza) {
                                Ok(()) => Ok(true),
                                Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => Ok(false),
                                Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                                    anyhow::bail!("resuming MUC recipient queue is full")
                                }
                            },
                        };
                    }
                    SuspendedMucRoute::Transitioning => true,
                    SuspendedMucRoute::Suspended => false,
                }
            };
            if wait_for_route {
                // Transitioning is a synchronous critical section; yielding is
                // sufficient and avoids a lost-wakeup window around Notify.
                tokio::task::yield_now().await;
                continue;
            }

            let mut buffer = suspended.buffer.lock().await;
            match buffer.phase.clone() {
                SuspendedMucPhase::Dormant => {
                    // Commit publishes Dormant before switching the synchronous
                    // route to Live. Loop through the route fence once more.
                    drop(buffer);
                }
                SuspendedMucPhase::Collecting | SuspendedMucPhase::Resuming => {
                    anyhow::ensure!(
                        receipt.is_none(),
                        "cluster MUC outbox cannot transfer ownership to a volatile suspended buffer"
                    );
                    let stanza_ref = stanza.as_deref().expect("MUC delivery owns one stanza");
                    let next_bytes = buffer
                        .bytes
                        .checked_add(stanza_ref.len())
                        .ok_or_else(|| anyhow::anyhow!("suspended MUC byte count overflow"))?;
                    let total_stanzas = buffer
                        .base_stanzas
                        .checked_add(buffer.stanzas.len() + 1)
                        .ok_or_else(|| {
                        anyhow::anyhow!("suspended MUC stanza count overflow")
                    })?;
                    let total_bytes = buffer
                        .base_bytes
                        .checked_add(next_bytes)
                        .ok_or_else(|| anyhow::anyhow!("suspended MUC byte count overflow"))?;
                    anyhow::ensure!(
                        total_stanzas <= self.config.sm_max_unacked_stanzas
                            && total_bytes <= self.config.sm_max_unacked_bytes,
                        "suspended MUC recipient queue is unavailable or full"
                    );
                    let capacity = suspended
                        .sm_capacity
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .clone()
                        .ok_or_else(|| {
                            self.sm_memory_governor.mark_invariant_failure();
                            anyhow::anyhow!("suspended MUC route has no SM memory reservation")
                        })?;
                    let growth = std::mem::size_of::<SuspendedMucStanza>()
                        .checked_add(stanza_ref.len())
                        .ok_or_else(|| anyhow::anyhow!("suspended MUC allocation overflow"))?;
                    capacity.try_grow_by(growth).map_err(|error| {
                        anyhow::anyhow!("suspended MUC memory admission rejected: {error}")
                    })?;
                    anyhow::ensure!(
                        buffer.enqueue_volatile(
                            stanza.take().expect("MUC delivery owns one stanza"),
                            self.config.sm_max_unacked_stanzas,
                            self.config.sm_max_unacked_bytes,
                        ),
                        "suspended MUC recipient queue is unavailable or full"
                    );
                    return Ok(true);
                }
                SuspendedMucPhase::Durable => {
                    // Keep the session-global endpoint mutex across the append.
                    // A resume claim cannot overtake this stanza, and every room
                    // shares the same SM sequence owner.
                    let stored = db::append_suspended_sm_stanza(
                        &self.pool,
                        suspended.sm_session_id,
                        volatile_source_id,
                        stanza.as_deref().expect("MUC delivery owns one stanza"),
                        self.config.sm_max_unacked_stanzas,
                        self.config.sm_max_unacked_bytes,
                    )
                    .await?;
                    if stored {
                        stanza.take();
                        if let Some(receipt) = receipt.take() {
                            let _ = receipt.send(());
                        }
                    }
                    return Ok(stored);
                }
                SuspendedMucPhase::Waiting
                | SuspendedMucPhase::Reserved
                | SuspendedMucPhase::Committing
                | SuspendedMucPhase::CheckpointOwned
                | SuspendedMucPhase::Sealed => {
                    // These are ownership transitions, not delivery failures.
                    // Register the waiter while the phase mutex is still held
                    // so a concurrent notification cannot be missed.
                    let notified = suspended.changed.notified();
                    tokio::pin!(notified);
                    notified.as_mut().enable();
                    drop(buffer);
                    notified.await;
                }
            }
        }
    }

    pub fn acquire_client_connection(
        self: &Arc<Self>,
        ip: std::net::IpAddr,
    ) -> Option<ClientConnectionGuard> {
        let permit = Arc::clone(&self.client_connections)
            .try_acquire_owned()
            .ok()?;
        {
            let mut count = self.client_connections_by_ip.entry(ip).or_insert(0);
            if *count >= self.config.max_connections_per_ip {
                let remove_zero = *count == 0;
                drop(count);
                if remove_zero {
                    self.client_connections_by_ip.remove(&ip);
                }
                return None;
            }
            *count += 1;
        }
        Some(ClientConnectionGuard {
            state: Arc::clone(self),
            ip,
            _permit: permit,
        })
    }

    pub fn acquire_upload_request(
        self: &Arc<Self>,
        ip: std::net::IpAddr,
    ) -> Option<UploadRequestGuard> {
        let admission = self.upload_runtime.request_admission()?;
        let permit = Arc::clone(&admission.semaphore).try_acquire_owned().ok()?;
        {
            let mut count = admission.by_ip.entry(ip).or_insert(0);
            if *count >= admission.max_per_ip {
                let remove_zero = *count == 0;
                drop(count);
                if remove_zero {
                    admission.by_ip.remove(&ip);
                }
                return None;
            }
            *count += 1;
        }
        Some(UploadRequestGuard {
            counts: Arc::clone(&admission.by_ip),
            ip,
            _permit: permit,
        })
    }

    pub(crate) fn omemo_recovery_service(
        &self,
    ) -> &crate::services::omemo_recovery::OmemoRecoveryService<
        db::omemo_recovery_repository::PostgresOmemoRecoveryRepository,
    > {
        &self.omemo_recovery_service
    }
    pub(crate) fn omemo_recovery_poll_context(&self) -> OmemoRecoveryPollContext {
        self.omemo_recovery_poll_context.clone()
    }

    /// Revoke local account routes and request durable SM revocation.
    /// Remote nodes receive the generation fence over Redis, with a 30-second
    /// maintenance sweep as fallback while PostgreSQL remains available.
    pub async fn disconnect_account(&self, user_id: uuid::Uuid, bare_account_jid: &str) {
        self.revoke_local_account_routes(user_id, bare_account_jid, None);
        if let Err(error) = self.revoke_user_sm_sessions_with_teardown(user_id).await {
            tracing::error!(?error, %user_id, "failed to revoke durable SM sessions");
        }
        // Credentials are already committed. Log a Redis notification failure
        // and let the generation sweep retry without failing the mutation.
        let generation = match db::find_user_by_id(&self.pool, user_id).await {
            Ok(Some(user)) => user.auth_generation,
            Ok(None) => i64::MAX,
            Err(error) => {
                tracing::error!(?error, %user_id, "could not load the post-mutation auth generation");
                return;
            }
        };
        if let Err(error) = self
            .cluster
            .send_account_generation_teardown(bare_account_jid, user_id, generation)
            .await
        {
            tracing::error!(
                ?error,
                %user_id,
                auth_generation = generation,
                "cross-node account revocation was not acknowledged; maintenance will retry"
            );
        }
    }

    /// Revoke only transports authenticated before a committed authorization
    /// fence.  Unlike `disconnect_account`, this remains safe when the control
    /// is delayed or replayed after the replacement browser has logged in.
    pub async fn disconnect_account_before_auth_generation(
        &self,
        user_id: uuid::Uuid,
        bare_account_jid: &str,
        auth_generation_exclusive: i64,
    ) {
        self.account_generation_teardown_sequence()
            .run(
                user_id,
                bare_account_jid,
                auth_generation_exclusive,
                || {
                    self.revoke_user_sm_sessions_before_auth_generation_with_teardown(
                        user_id,
                        auth_generation_exclusive,
                    )
                },
                || {
                    self.cluster.send_account_generation_teardown(
                        bare_account_jid,
                        user_id,
                        auth_generation_exclusive,
                    )
                },
            )
            .await;
    }

    pub async fn revoke_user_sm_sessions_with_teardown(
        &self,
        user_id: uuid::Uuid,
    ) -> anyhow::Result<usize> {
        let lease = self.config.sm_claim_lease_seconds.max(1);
        let deadline =
            tokio::time::Instant::now() + std::time::Duration::from_secs(lease.saturating_add(2));
        let mut total = 0usize;
        loop {
            let batch = db::take_user_sm_sessions_for_teardown(&self.pool, user_id, lease).await?;
            total = total.saturating_add(batch.snapshots.len());
            for snapshot in batch.snapshots {
                self.perform_and_finalize_sm_teardown(snapshot).await?;
            }
            if batch.pending == 0 && db::count_user_sm_rows(&self.pool, user_id).await? == 0 {
                return Ok(total);
            }
            anyhow::ensure!(
                tokio::time::Instant::now() < deadline,
                "durable SM account teardown claims did not quiesce before the deadline"
            );
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
    }

    async fn revoke_user_sm_sessions_before_auth_generation_with_teardown(
        &self,
        user_id: uuid::Uuid,
        auth_generation_exclusive: i64,
    ) -> anyhow::Result<usize> {
        let lease = self.config.sm_claim_lease_seconds.max(1);
        let deadline =
            tokio::time::Instant::now() + std::time::Duration::from_secs(lease.saturating_add(2));
        let mut total = 0usize;
        loop {
            let batch = db::take_user_sm_sessions_before_auth_generation_for_teardown(
                &self.pool,
                user_id,
                auth_generation_exclusive,
                lease,
            )
            .await?;
            total = total.saturating_add(batch.snapshots.len());
            for snapshot in batch.snapshots {
                self.perform_and_finalize_sm_teardown(snapshot).await?;
            }
            if batch.pending == 0
                && db::count_user_sm_rows_before_auth_generation(
                    &self.pool,
                    user_id,
                    auth_generation_exclusive,
                )
                .await?
                    == 0
            {
                return Ok(total);
            }
            anyhow::ensure!(
                tokio::time::Instant::now() < deadline,
                "generation-fenced SM teardown claims did not quiesce before the deadline"
            );
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
    }

    /// Atomically acquire and tear down every expired durable SM stream.
    /// PostgreSQL skips a still-live resume claim, ensuring that activation
    /// and expiry can never both own the same presence session.
    pub async fn cleanup_expired_sm_sessions(&self) -> anyhow::Result<usize> {
        let mut total = 0usize;
        let mut first_error = None;
        loop {
            let snapshots = db::cleanup_expired_sm_sessions(
                &self.pool,
                self.config.sm_claim_lease_seconds.max(1),
            )
            .await?;
            let batch = snapshots.len();
            total = total.saturating_add(batch);
            for snapshot in snapshots {
                // An unclean process/transport failure can leave `resumable`
                // false until the live lease expires. Expiry is final in
                // either representation and therefore owns teardown.
                if let Err(error) = self.perform_and_finalize_sm_teardown(snapshot).await {
                    tracing::warn!(
                        ?error,
                        "expired SM teardown will be retried after its lease"
                    );
                    first_error.get_or_insert(error);
                }
            }
            if batch < 256 {
                break;
            }
            tokio::task::yield_now().await;
        }
        if let Some(error) = first_error {
            return Err(error);
        }
        Ok(total)
    }

    pub async fn revoke_sm_session_with_teardown(&self, id: uuid::Uuid) -> anyhow::Result<()> {
        if let Some(snapshot) = db::take_sm_session_for_teardown(
            &self.pool,
            id,
            self.config.sm_claim_lease_seconds.max(1),
        )
        .await?
        {
            self.perform_and_finalize_sm_teardown(snapshot).await?;
        }
        Ok(())
    }

    pub async fn revoke_all_sm_sessions_with_teardown(&self) -> anyhow::Result<usize> {
        let lease = self.config.sm_claim_lease_seconds.max(1);
        let deadline =
            tokio::time::Instant::now() + std::time::Duration::from_secs(lease.saturating_add(2));
        let mut total = 0usize;
        loop {
            let batch = db::take_all_sm_sessions_for_teardown(&self.pool, lease).await?;
            total = total.saturating_add(batch.snapshots.len());
            for snapshot in batch.snapshots {
                self.perform_and_finalize_sm_teardown(snapshot).await?;
            }
            if batch.pending == 0 && db::count_all_sm_rows(&self.pool).await? == 0 {
                return Ok(total);
            }
            anyhow::ensure!(
                tokio::time::Instant::now() < deadline,
                "global durable SM teardown claims did not quiesce before the deadline"
            );
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
    }

    async fn perform_and_finalize_sm_teardown(
        &self,
        snapshot: db::SmTeardownSnapshot,
    ) -> anyhow::Result<()> {
        self.teardown_sm_snapshot(&snapshot).await?;
        anyhow::ensure!(
            db::finalize_sm_teardown(&self.pool, snapshot.session_id, snapshot.teardown_token)
                .await?,
            "durable SM teardown lease was lost before finalization"
        );
        Ok(())
    }

    async fn teardown_sm_snapshot(&self, snapshot: &db::SmTeardownSnapshot) -> anyhow::Result<()> {
        let Ok(full_jid) = crate::jid::canonical_session_key(&snapshot.full_jid) else {
            tracing::warn!(sm_session_id = %snapshot.session_id, "discarded invalid durable SM teardown JID");
            anyhow::bail!("invalid durable SM teardown JID");
        };
        let actor_bare = bare_jid(&full_jid).to_owned();

        if let Some(session) = self.sessions.get_mut(&full_jid) {
            let matches = *session
                .sm_session_id
                .read()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                == Some(snapshot.session_id);
            if matches {
                session.routable.store(false, Ordering::Release);
                session.disconnect.cancel();
            }
        }
        self.cluster
            .send_sm_session_teardown(&full_jid, snapshot.session_id)
            .await?;

        let mut first_error = None;

        if snapshot.available {
            let unavailable = format!(
                "<presence xmlns='jabber:client' from='{}' type='unavailable'/>",
                attr_escape(&full_jid)
            );
            let mut routed = HashSet::new();
            let roster = db::roster(&self.pool, snapshot.user_id).await?;
            for (jid, _, subscription, _) in roster {
                if matches!(subscription.as_str(), "from" | "both") && routed.insert(jid.clone()) {
                    if let Err(error) = self
                        .route_unavailable_with_policy(
                            snapshot.user_id,
                            snapshot.active_privacy_list.as_deref(),
                            &full_jid,
                            &unavailable,
                            &jid,
                        )
                        .await
                    {
                        first_error.get_or_insert(error);
                    }
                }
            }

            // Other resources of the same account are part of the same
            // presence session audience, independent of roster privacy.
            if let Err(error) = self
                .route_sm_unavailable_unchecked(&full_jid, &unavailable, &actor_bare, false)
                .await
            {
                first_error.get_or_insert(error);
            }

            for target in &snapshot.directed_presence {
                if routed.insert(target.clone()) {
                    if let Err(error) = self
                        .route_unavailable_with_policy(
                            snapshot.user_id,
                            snapshot.active_privacy_list.as_deref(),
                            &full_jid,
                            &unavailable,
                            target,
                        )
                        .await
                    {
                        first_error.get_or_insert(error);
                    }
                }
            }
        }

        let mut memberships = HashSet::new();
        for membership in &snapshot.joined_rooms {
            let Ok(room_jid) = crate::jid::canonicalize_bare(&membership.room_jid) else {
                continue;
            };
            let Ok(nick) = crate::xmpp::xml_util::prepare_muc_nick(&membership.nick) else {
                continue;
            };
            if !memberships.insert((room_jid.clone(), nick.clone())) {
                continue;
            }
            let occupant = self
                .sm_teardown_muc_occupant(
                    snapshot.session_id,
                    snapshot.user_id,
                    &full_jid,
                    &room_jid,
                    &nick,
                )
                .await?;
            if let Err(error) = self
                .cluster
                .send_sm_muc_teardown(&room_jid, snapshot.session_id, &occupant)
                .await
            {
                tracing::warn!(?error, %room_jid, "failed to publish clustered SM MUC teardown");
                first_error.get_or_insert(error);
            }
            if let Err(error) = self
                .teardown_suspended_muc_membership(snapshot.session_id, &occupant)
                .await
            {
                first_error.get_or_insert(error);
            }
        }
        if let Some(error) = first_error {
            return Err(error);
        }
        self.suspended_muc_sessions.remove(&snapshot.session_id);
        Ok(())
    }

    pub(crate) async fn route_unavailable_with_policy(
        &self,
        owner_id: uuid::Uuid,
        active_privacy_list: Option<&str>,
        from: &str,
        unavailable: &str,
        target: &str,
    ) -> anyhow::Result<()> {
        if db::is_blocked_for_account(&self.pool, owner_id, bare_jid(from), target).await? {
            return Ok(());
        }
        if db::privacy_denies(
            &self.pool,
            owner_id,
            active_privacy_list,
            target,
            db::PrivacyStanzaKind::PresenceOut,
        )
        .await?
        {
            return Ok(());
        }
        let Ok(target_jid) = crate::jid::CanonicalJid::parse(target) else {
            anyhow::bail!("invalid SM teardown presence target");
        };
        if target_jid.domainpart() == self.config.domain {
            if let Some(username) = target_jid.localpart() {
                match db::find_enabled_user(&self.pool, username).await? {
                    Some(recipient) => {
                        if db::is_blocked_for_account(
                            &self.pool,
                            recipient.id,
                            &target_jid.bare(),
                            from,
                        )
                        .await?
                        {
                            return Ok(());
                        }
                    }
                    None => return Ok(()),
                }
            }
        }
        self.route_sm_unavailable_unchecked(from, unavailable, target, true)
            .await
    }

    async fn route_sm_unavailable_unchecked(
        &self,
        from: &str,
        unavailable: &str,
        target: &str,
        recipient_privacy: bool,
    ) -> anyhow::Result<()> {
        let Ok(target_jid) = crate::jid::CanonicalJid::parse(target) else {
            anyhow::bail!("invalid SM teardown presence target");
        };
        let canonical_target = target_jid.to_string();
        let delivery = crate::xmpp::xml_util::set_to(unavailable, &canonical_target);
        if target_jid.domainpart() == self.config.domain {
            let mut recipients = self.session_entries_for(&canonical_target);
            if target_jid.resourcepart().is_none() {
                recipients.retain(|(_, session)| {
                    session.available.load(std::sync::atomic::Ordering::Relaxed)
                });
            }
            recipients.retain(|(jid, _)| jid != from);
            for (jid, recipient) in recipients {
                if recipient_privacy
                    && !self
                        .privacy_allows_session(&recipient, from, db::PrivacyStanzaKind::PresenceIn)
                        .await?
                {
                    continue;
                }
                if let Err(tokio::sync::mpsc::error::TrySendError::Full(_)) = recipient
                    .sender
                    .try_send(crate::xmpp::xml_util::set_to(unavailable, &jid))
                {
                    anyhow::bail!("local SM unavailable recipient queue is full");
                }
            }
            for node_id in self.cluster.lookup_nodes(&canonical_target).await? {
                if node_id == self.cluster.node_id {
                    continue;
                }
                if target_jid.resourcepart().is_none() {
                    self.cluster
                        .send_to_node_available_presence_confirmed_excluding(
                            &node_id,
                            &canonical_target,
                            &delivery,
                            Some(from),
                        )
                        .await?;
                } else {
                    self.cluster
                        .send_to_node_confirmed(&node_id, &canonical_target, &delivery, Some(from))
                        .await?;
                }
            }
        } else if self
            .config
            .external_route_domain_allowed(target_jid.domainpart())
        {
            anyhow::ensure!(
                self.federation_outbox
                    .send(target_jid.domainpart(), delivery, Some(from.to_owned()))
                    .await,
                "federation queue rejected SM unavailable presence"
            );
        }
        Ok(())
    }

    async fn sm_teardown_muc_occupant(
        &self,
        sm_session_id: uuid::Uuid,
        user_id: uuid::Uuid,
        full_jid: &str,
        room_jid: &str,
        nick: &str,
    ) -> anyhow::Result<SerializableMucOccupant> {
        let key = crate::xmpp::xml_util::muc_occupant_key(room_jid, nick);
        if let Some(occupant) = self.muc_occupants.get(&key).filter(|occupant| {
            occupant.full_jid == full_jid
                && occupant.room_jid == room_jid
                && occupant.nick == nick
                && !occupant.cluster_epoch.is_nil()
                && !occupant.connection_id.is_nil()
                && matches!(
                    &occupant.endpoint,
                    MucOccupantEndpoint::Suspended(endpoint)
                        if endpoint.sm_session_id == sm_session_id
                )
        }) {
            return Ok(SerializableMucOccupant::from(&*occupant));
        }
        let room = db::muc_room(&self.pool, localpart(room_jid)).await?;
        let affiliation = if let Some(room) = &room {
            db::muc_affiliation(&self.pool, room.id, user_id)
                .await?
                .unwrap_or_else(|| "none".to_owned())
        } else {
            "none".to_owned()
        };
        let role = if matches!(affiliation.as_str(), "owner" | "admin") {
            "moderator"
        } else {
            "participant"
        };
        Ok(SerializableMucOccupant {
            full_jid: full_jid.to_owned(),
            room_jid: room_jid.to_owned(),
            nick: nick.to_owned(),
            affiliation,
            role: role.to_owned(),
            room_non_anonymous: room.as_ref().is_none_or(|room| room.non_anonymous),
            occupant_id: room
                .as_ref()
                .map(|room| {
                    crate::xmpp::xml_util::muc_occupant_id(
                        &room.occupant_id_secret,
                        bare_jid(full_jid),
                    )
                })
                .unwrap_or_default(),
            cluster_epoch: uuid::Uuid::new_v4(),
            connection_id: uuid::Uuid::nil(),
            federated_domain: None,
            sm_session_id: Some(sm_session_id),
            payload: String::new(),
        })
    }

    /// Remove one exact suspended actor and publish the already-authorized
    /// unavailable event to this node's room occupants. Called both by the DB
    /// teardown owner and by authenticated Redis cluster fanout.
    pub async fn teardown_suspended_muc_membership(
        &self,
        sm_session_id: uuid::Uuid,
        occupant: &SerializableMucOccupant,
    ) -> anyhow::Result<usize> {
        let key = crate::xmpp::xml_util::muc_occupant_key(&occupant.room_jid, &occupant.nick);
        let removed = self.muc_occupants.remove_if(&key, |_, current| {
            muc_suspended_teardown_identity_matches(current, sm_session_id, occupant)
        });
        if removed.is_some() {
            self.cluster
                .unregister_muc_occupant_epoch(
                    &occupant.room_jid,
                    &occupant.nick,
                    occupant.cluster_epoch,
                    occupant.connection_id,
                )
                .await?;
        }
        let remaining = self.muc_occupants_for(&occupant.room_jid);
        let occupant_jids = remaining
            .iter()
            .map(|(_, target)| target.full_jid.clone())
            .collect::<Vec<_>>();
        let visible_sender = format!("{}/{}", occupant.room_jid, occupant.nick);
        let blocked = db::blocked_local_accounts_for_candidates(
            &self.pool,
            &self.config.domain,
            &occupant_jids,
            &[visible_sender, occupant.full_jid.clone()],
        )
        .await?;
        let mut delivered = 0;
        for (_, target) in &remaining {
            if crate::jid::canonical_bare_key(&target.full_jid)
                .is_ok_and(|owner| blocked.contains(&owner))
            {
                continue;
            }
            let presence = crate::xmpp::xml_util::muc_presence_stanza(
                occupant,
                &target.full_jid,
                true,
                false,
                false,
                None,
                occupant.room_non_anonymous || target.role == "moderator",
            );
            delivered += usize::from(
                self.deliver_to_muc_occupant_unchecked_result(target, presence)
                    .await?,
            );
        }
        if remaining.is_empty() {
            self.cluster.leave_muc(&occupant.room_jid).await?;
        }
        let globally_empty = self
            .cluster
            .get_muc_occupants(&occupant.room_jid)
            .await?
            .is_empty();
        if globally_empty && remaining.is_empty() {
            if let Some(room) = db::muc_room(&self.pool, localpart(&occupant.room_jid)).await? {
                db::delete_temporary_muc_room(
                    &self.pool,
                    room.id,
                    room.room_epoch,
                    room.config_version,
                )
                .await?;
            }
        }
        Ok(delivered)
    }

    /// Give live locally-owned MUC endpoints XEP-0045 system-shutdown status.
    /// Count only completed TCP/WS writes or BOSH client response ACKs; SM
    /// persistence alone cannot satisfy this process-local completion. The
    /// root supervises the whole loop under one bounded, cancellable window.
    pub async fn notify_muc_system_shutdown(&self) -> usize {
        let occupants = self
            .muc_occupants
            .iter()
            .filter(|entry| matches!(&entry.value().endpoint, MucOccupantEndpoint::Local(_)))
            .map(|entry| entry.value().clone())
            .collect::<Vec<_>>();
        count_shutdown_notification_completions(occupants.into_iter().map(|occupant| async move {
            let serialized = SerializableMucOccupant::from(&occupant);
            let stanza = crate::xmpp::xml_util::muc_presence_stanza_with_status(
                &serialized,
                &occupant.full_jid,
                true,
                true,
                false,
                None,
                true,
                Some(332),
                None,
                None,
            );
            let (receipt, mut received) = tokio::sync::mpsc::unbounded_channel();
            self.deliver_to_muc_occupant_inner(&occupant, stanza, None, Some(receipt))
                .await
                && received.recv().await.is_some()
        }))
        .await
    }

    pub fn suspend_local_muc_occupants(
        &self,
        full_jid: &str,
        connection_id: uuid::Uuid,
        sm_session_id: uuid::Uuid,
        memberships: &DashMap<String, JoinedMucMembership>,
        base_stanzas: usize,
        base_bytes: usize,
    ) -> Vec<Arc<SuspendedMucEndpoint>> {
        self.sm_suspension_context().suspend_local_muc_occupants(
            full_jid,
            connection_id,
            sm_session_id,
            memberships,
            base_stanzas,
            base_bytes,
        )
    }

    /// Associate MUC occupants which were joined before SM enable with the
    /// newly-created durable stream epoch and update their Redis control
    /// records. This also makes active-session revocation exact and immune to
    /// nick reuse races.
    pub async fn associate_local_muc_sm_session(
        &self,
        full_jid: &str,
        connection_id: uuid::Uuid,
        sm_session_id: uuid::Uuid,
        memberships: &DashMap<String, JoinedMucMembership>,
    ) {
        // Install the session-global gate even when the resource has not joined
        // a room yet. Future joins carry `sm_session_id` and therefore route
        // through this same Arc from their first stanza onward.
        let Some(live_sender) = self.sessions.get(full_jid).and_then(|session| {
            (session.connection_id == connection_id).then(|| session.sender.clone())
        }) else {
            tracing::warn!(%full_jid, %connection_id, %sm_session_id,
                "could not install the live SM MUC route gate");
            return;
        };
        let proposed = Arc::new(SuspendedMucEndpoint::new_live(sm_session_id, live_sender));
        let _endpoint =
            canonical_suspended_muc_endpoint(&self.suspended_muc_sessions, sm_session_id, proposed);
        for membership in memberships {
            let room_jid = membership.key();
            let membership = membership.value();
            let key = crate::xmpp::xml_util::muc_occupant_key(room_jid, &membership.nick);
            let serializable = {
                let Some(mut occupant) = self.muc_occupants.get_mut(&key) else {
                    continue;
                };
                if !muc_actor_identity_matches(
                    &occupant,
                    full_jid,
                    connection_id,
                    room_jid,
                    membership,
                ) {
                    continue;
                }
                occupant.sm_session_id = Some(sm_session_id);
                SerializableMucOccupant::from(&*occupant)
            };
            let encoded = serde_json::to_string(&serializable).unwrap_or_default();
            if self.cluster.is_enabled() {
                let association = async {
                    let room =
                        db::muc_room(&self.pool, crate::state::localpart(&serializable.room_jid))
                            .await?
                            .context("SM association references a missing MUC room")?;
                    let target = db::cluster_muc_occupancy_target(
                        &self.pool,
                        room.id,
                        serializable.cluster_epoch,
                        serializable.connection_id,
                    )
                    .await?
                    .context("SM association lost its exact MUC occupancy")?;
                    anyhow::ensure!(
                        db::associate_cluster_muc_sm_session(
                            &self.pool,
                            &target,
                            &self.cluster.node_id,
                            sm_session_id,
                        )
                        .await?,
                        "SM association lost its PG occupancy fence"
                    );
                    Ok::<_, anyhow::Error>(())
                }
                .await;
                if let Err(error) = association {
                    tracing::warn!(?error, room=%serializable.room_jid, nick=%serializable.nick,
                        "failed to associate PG-authoritative MUC occupancy with SM epoch");
                }
            }
            if let Err(error) = self
                .cluster
                .register_suspended_muc_occupant(
                    &serializable.room_jid,
                    &serializable.nick,
                    sm_session_id,
                    &encoded,
                )
                .await
            {
                tracing::warn!(?error, room = %serializable.room_jid, nick = %serializable.nick, "failed to associate clustered MUC occupant with SM epoch");
            }
        }
    }

    pub async fn mark_suspended_muc_durable(
        &self,
        endpoints: Vec<Arc<SuspendedMucEndpoint>>,
    ) -> bool {
        self.sm_suspension_context()
            .mark_suspended_muc_durable(endpoints)
            .await
    }

    pub async fn pause_suspended_muc_delivery(
        &self,
        sm_session_id: uuid::Uuid,
    ) -> Vec<Arc<SuspendedMucEndpoint>> {
        let mut endpoints = self
            .muc_occupants
            .iter()
            .filter_map(|occupant| match &occupant.endpoint {
                MucOccupantEndpoint::Suspended(endpoint)
                    if endpoint.sm_session_id == sm_session_id =>
                {
                    Some(Arc::clone(endpoint))
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        if let Some(endpoint) = self.suspended_muc_sessions.get(&sm_session_id) {
            endpoints.push(Arc::clone(&endpoint));
        }
        let mut seen = HashSet::new();
        endpoints.retain(|endpoint| seen.insert(Arc::as_ptr(endpoint) as usize));
        if let Some(endpoint) = endpoints.first() {
            match self.suspended_muc_sessions.entry(sm_session_id) {
                dashmap::mapref::entry::Entry::Vacant(slot) => {
                    slot.insert(Arc::clone(endpoint));
                }
                dashmap::mapref::entry::Entry::Occupied(_) => {}
            }
        }
        for endpoint in &endpoints {
            let transition_from_live = {
                let mut route = endpoint
                    .route
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                if matches!(&*route, SuspendedMucRoute::Live(_)) {
                    *route = SuspendedMucRoute::Transitioning;
                    true
                } else {
                    false
                }
            };
            let mut buffer = endpoint.buffer.lock().await;
            buffer.phase = match buffer.phase.clone() {
                SuspendedMucPhase::Durable
                | SuspendedMucPhase::Collecting
                | SuspendedMucPhase::Resuming
                | SuspendedMucPhase::Sealed => SuspendedMucPhase::Waiting,
                SuspendedMucPhase::Reserved => SuspendedMucPhase::Reserved,
                SuspendedMucPhase::Dormant => SuspendedMucPhase::Waiting,
                SuspendedMucPhase::Waiting
                | SuspendedMucPhase::Committing
                | SuspendedMucPhase::CheckpointOwned => SuspendedMucPhase::Sealed,
            };
            drop(buffer);
            if transition_from_live {
                *endpoint
                    .route
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner()) =
                    SuspendedMucRoute::Suspended;
            }
            endpoint.changed.notify_waiters();
        }
        endpoints
    }

    /// Install the exact post-finalization replay base. `claim_resume` is only
    /// a preliminary snapshot: acknowledgements may advance before the
    /// PostgreSQL activation CAS returns. Keeping the endpoint in `Waiting`
    /// until this method prevents that stale claim size from opening excess
    /// stanza or byte budget.
    pub async fn begin_suspended_muc_resume(
        &self,
        endpoints: &[Arc<SuspendedMucEndpoint>],
        base_stanzas: usize,
        base_bytes: usize,
    ) -> bool {
        let mut complete = true;
        let mut seen = HashSet::new();
        for endpoint in endpoints {
            if !seen.insert(Arc::as_ptr(endpoint) as usize) {
                continue;
            }
            let mut buffer = endpoint.buffer.lock().await;
            match buffer.phase.clone() {
                SuspendedMucPhase::Waiting | SuspendedMucPhase::Sealed => {
                    buffer.base_stanzas = base_stanzas;
                    buffer.base_bytes = base_bytes;
                    buffer.phase = SuspendedMucPhase::Resuming;
                }
                SuspendedMucPhase::Reserved => {
                    buffer.base_stanzas = base_stanzas;
                    buffer.base_bytes = base_bytes;
                }
                _ => complete = false,
            }
            drop(buffer);
            endpoint.changed.notify_waiters();
        }
        complete
    }

    pub async fn seal_suspended_muc_endpoints(&self, endpoints: &[Arc<SuspendedMucEndpoint>]) {
        self.sm_suspension_context()
            .seal_suspended_muc_endpoints(endpoints)
            .await
    }

    pub(crate) fn retain_suspended_sm_capacity(
        &self,
        endpoints: &[Arc<SuspendedMucEndpoint>],
        capacity: crate::services::sm_capacity::SmCapacityLease,
    ) {
        self.sm_suspension_context()
            .retain_suspended_sm_capacity(endpoints, capacity)
    }

    pub(crate) fn clear_suspended_sm_capacity(&self, endpoints: &[Arc<SuspendedMucEndpoint>]) {
        for endpoint in endpoints {
            endpoint
                .sm_capacity
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take();
        }
    }

    /// Freeze the one session-global disconnect suffix before the exact SM
    /// suspension transaction and append it directly to that transaction's
    /// snapshot while holding the endpoint mutex. The endpoint retains its
    /// byte-for-byte backup until PostgreSQL confirms ownership. New delivery
    /// waits instead of creating an uncommitted process-crash window.
    pub async fn snapshot_suspended_muc_for_disconnect(
        &self,
        endpoints: &[Arc<SuspendedMucEndpoint>],
        snapshot: &mut crate::services::sm::SmSessionSnapshot,
    ) -> anyhow::Result<()> {
        self.sm_suspension_context()
            .snapshot_suspended_muc_for_disconnect(endpoints, snapshot)
            .await
    }

    /// Reattach only memberships that can still be proven valid. Existing
    /// suspended actors are swapped in place; after a process restart a new
    /// actor is recreated without join broadcast or history replay. The
    /// volatile suspension FIFO moves into the returned replay suffix so the
    /// resumed stream emits it strictly after `<resumed/>` and the durable
    /// unacked replay.
    pub async fn restore_local_muc_occupants(
        &self,
        request: RestoreLocalMucOccupantsRequest<'_>,
    ) -> RestoredLocalMucOccupants {
        let RestoreLocalMucOccupantsRequest {
            user,
            full_jid,
            connection_id,
            sm_session_id,
            memberships,
            base_stanzas,
            base_bytes,
        } = request;
        let Ok(full_jid) = crate::jid::canonical_session_key(full_jid) else {
            return RestoredLocalMucOccupants {
                failures: memberships.to_vec(),
                replay_suffix: Vec::new(),
                resume_gate: None,
                actors: Vec::new(),
            };
        };
        if connection_id.is_nil() {
            return RestoredLocalMucOccupants {
                failures: memberships.to_vec(),
                replay_suffix: Vec::new(),
                resume_gate: None,
                actors: Vec::new(),
            };
        }
        let muc_domain =
            crate::jid::prepare_domainpart(&format!("conference.{}", self.config.domain))
                .expect("configured XMPP domain must form a valid MUC domain");
        let mut failures = Vec::new();
        let mut actors = Vec::new();
        let mut resume_gate = self
            .suspended_muc_sessions
            .get(&sm_session_id)
            .map(|endpoint| Arc::clone(&endpoint));
        for membership in memberships {
            let (Ok(room_jid), Ok(nick)) = (
                crate::jid::canonicalize_bare(&membership.room_jid),
                crate::xmpp::xml_util::prepare_muc_nick(&membership.nick),
            ) else {
                failures.push(membership.clone());
                continue;
            };
            if jid_domain(&room_jid) != Some(muc_domain.as_str()) {
                failures.push(membership.clone());
                continue;
            }
            let Ok(Some(initial_room)) = self
                .muc_service()
                .local_room_snapshot(localpart(&room_jid))
                .await
            else {
                failures.push(membership.clone());
                continue;
            };
            let key = crate::xmpp::xml_util::muc_occupant_key(&room_jid, &nick);
            // Single-node join, rename and SM restore publish into the same
            // room-local map. Existing suspended actors already own a slot
            // and bypass the new-admission capacity check; a post-restart
            // recreation must compete under the same gate as a fresh join so
            // delayed resumes cannot overfill the room.
            let _local_resume_guard = if self.cluster.is_enabled() {
                None
            } else {
                Some(self.muc_service().lock_local_join(initial_room.id).await)
            };
            let Ok(Some(room)) = self
                .muc_service()
                .local_room_snapshot(localpart(&room_jid))
                .await
            else {
                failures.push(membership.clone());
                continue;
            };
            if room.id != initial_room.id
                || room.room_epoch != initial_room.room_epoch
                || room.config_version != initial_room.config_version
            {
                failures.push(membership.clone());
                continue;
            }
            let affiliation = match self.muc_service().local_affiliation(room.id, user.id).await {
                Ok(value) => value.unwrap_or_else(|| "none".to_owned()),
                Err(error) => {
                    tracing::warn!(?error, "failed to reauthorize resumed MUC membership");
                    failures.push(membership.clone());
                    continue;
                }
            };
            if affiliation == "outcast" || (room.members_only && affiliation == "none") {
                failures.push(membership.clone());
                continue;
            }
            match self
                .muc_service()
                .local_nick_reserved_for_other(room.id, user.id, &nick)
                .await
            {
                Ok(false) => {}
                Ok(true) => {
                    failures.push(membership.clone());
                    continue;
                }
                Err(error) => {
                    tracing::warn!(?error, room=%room_jid, %nick,
                        "failed to revalidate a reserved nickname during SM resume");
                    failures.push(membership.clone());
                    continue;
                }
            }
            let role = if matches!(affiliation.as_str(), "owner" | "admin") {
                "moderator"
            } else if room.moderated && affiliation == "none" {
                "visitor"
            } else {
                "participant"
            }
            .to_owned();

            // From here through the final Entry publication the single-node
            // room gate remains held, so the exact room policy, nickname and
            // capacity decision cannot be invalidated by join/rename/config.
            if room.configuration_is_expired(chrono::Utc::now()) {
                failures.push(membership.clone());
                continue;
            };
            if let Some(occupant) = self.muc_occupants.get(&key) {
                let previous = SerializableMucOccupant::from(&*occupant);
                let endpoint = match &occupant.endpoint {
                    MucOccupantEndpoint::Suspended(endpoint)
                        if endpoint.sm_session_id == sm_session_id =>
                    {
                        Some(Arc::clone(endpoint))
                    }
                    _ => None,
                };
                let owned = occupant.full_jid == full_jid && endpoint.is_some();
                if !owned {
                    failures.push(membership.clone());
                    continue;
                }
                let endpoint = endpoint.expect("checked above");
                drop(occupant);
                let canonical_endpoint = canonical_suspended_muc_endpoint(
                    &self.suspended_muc_sessions,
                    sm_session_id,
                    Arc::clone(&endpoint),
                );
                if !Arc::ptr_eq(&canonical_endpoint, &endpoint)
                    || resume_gate
                        .as_ref()
                        .is_some_and(|current| !Arc::ptr_eq(current, &endpoint))
                {
                    failures.push(membership.clone());
                    continue;
                }
                resume_gate = Some(Arc::clone(&endpoint));

                let resumed_cluster_target = if self.cluster.is_enabled() {
                    let resume = async {
                        let target = db::cluster_muc_occupancy_target(
                            &self.pool,
                            room.id,
                            previous.cluster_epoch,
                            previous.connection_id,
                        )
                        .await?
                        .context("SM resume lost its exact suspended MUC occupancy")?;
                        let next_epoch = target
                            .connection_epoch
                            .checked_add(1)
                            .context("MUC connection epoch overflow")?;
                        let operation_id = uuid::Uuid::new_v4();
                        let outcome = db::transition_cluster_muc_occupancy(
                            &self.pool,
                            operation_id,
                            &target,
                            "resume",
                            &self.cluster.node_id,
                            Some(connection_id),
                            Some(next_epoch),
                            Some(sm_session_id),
                            Duration::from_secs(90),
                        )
                        .await?;
                        anyhow::ensure!(
                            matches!(
                                outcome,
                                db::ClusterMucTransitionOutcome::Applied
                                    | db::ClusterMucTransitionOutcome::Replay
                            ),
                            "PG MUC resume rejected stale occupancy: {outcome:?}"
                        );
                        if let Err(error) = self
                            .muc_service()
                            .wake_committed_operation(&self.cluster, operation_id)
                            .await
                        {
                            tracing::warn!(?error, %operation_id, room=%room_jid,
                                "MUC resume wake failed; PG outbox polling will catch up");
                        }
                        let mut resumed = target;
                        resumed.connection_uuid = connection_id;
                        resumed.connection_epoch = next_epoch;
                        Ok::<_, anyhow::Error>(resumed)
                    }
                    .await;
                    match resume {
                        Ok(target) => Some(target),
                        Err(error) => {
                            tracing::warn!(?error, room=%room_jid, nick=%nick,
                                "could not commit PG-authoritative MUC resume");
                            failures.push(membership.clone());
                            continue;
                        }
                    }
                } else {
                    None
                };
                let Some(mut occupant) = self.muc_occupants.get_mut(&key) else {
                    if let Some(target) = &resumed_cluster_target {
                        self.compensate_resumed_muc_target(target, sm_session_id)
                            .await;
                    }
                    failures.push(membership.clone());
                    continue;
                };
                if !matches!(
                    &occupant.endpoint,
                    MucOccupantEndpoint::Suspended(current)
                        if Arc::ptr_eq(current, &endpoint)
                            && current.sm_session_id == sm_session_id
                ) || occupant.full_jid != full_jid
                    || occupant.connection_id != previous.connection_id
                    || occupant.cluster_epoch != previous.cluster_epoch
                    || occupant.sm_session_id != Some(sm_session_id)
                {
                    drop(occupant);
                    if let Some(target) = &resumed_cluster_target {
                        self.compensate_resumed_muc_target(target, sm_session_id)
                            .await;
                    }
                    failures.push(membership.clone());
                    continue;
                }
                occupant.connection_id = connection_id;
                occupant.sm_session_id = Some(sm_session_id);
                occupant.affiliation = affiliation;
                occupant.role = role;
                occupant.room_non_anonymous = room.non_anonymous;
                let serializable = SerializableMucOccupant::from(&*occupant);
                drop(occupant);
                match self
                    .cluster
                    .resume_muc_occupant(&previous, &serializable)
                    .await
                {
                    Ok(true) => {}
                    Ok(false) | Err(_) if !self.cluster.is_enabled() => {
                        self.muc_occupants.remove_if(&key, |_, current| {
                            current.full_jid == full_jid
                                && current.cluster_epoch == serializable.cluster_epoch
                                && current.connection_id == connection_id
                                && matches!(
                                    &current.endpoint,
                                    MucOccupantEndpoint::Suspended(current)
                                        if Arc::ptr_eq(current, &endpoint)
                                )
                        });
                        if let Some(target) = &resumed_cluster_target {
                            self.compensate_resumed_muc_target(target, sm_session_id)
                                .await;
                        }
                        failures.push(membership.clone());
                        continue;
                    }
                    Ok(false) | Err(_) => {
                        tracing::warn!(room=%room_jid, nick=%nick,
                            "PG MUC resume committed but Redis soft-state refresh failed");
                    }
                }
                actors.push(RestoredMucActor {
                    key,
                    full_jid: full_jid.clone(),
                    connection_id,
                    cluster_epoch: serializable.cluster_epoch,
                    sm_session_id,
                    endpoint,
                    membership: crate::services::sm::SmMucMembership { room_jid, nick },
                    resumed_cluster_target,
                });
                continue;
            }

            if !self.cluster.is_enabled() {
                let privileged = matches!(affiliation.as_str(), "owner" | "admin");
                let effective_capacity = room.max_occupants as usize + usize::from(privileged) * 10;
                if self.muc_occupants_for(&room_jid).len() >= effective_capacity {
                    failures.push(membership.clone());
                    continue;
                }
            }

            let cluster_authority = if self.cluster.is_enabled() {
                let authority = match db::suspended_cluster_muc_occupancy(
                    &self.pool,
                    room.id,
                    room.room_epoch,
                    sm_session_id,
                    &full_jid,
                    &nick,
                )
                .await
                {
                    Ok(Some(authority)) => authority,
                    Ok(None) | Err(_) => {
                        failures.push(membership.clone());
                        continue;
                    }
                };
                Some(authority)
            } else {
                None
            };

            let proposed_endpoint = resume_gate.clone().unwrap_or_else(|| {
                Arc::new(SuspendedMucEndpoint::new_reserved(
                    sm_session_id,
                    base_stanzas,
                    base_bytes,
                ))
            });
            let created_endpoint = canonical_suspended_muc_endpoint(
                &self.suspended_muc_sessions,
                sm_session_id,
                proposed_endpoint,
            );
            if resume_gate
                .as_ref()
                .is_some_and(|current| !Arc::ptr_eq(current, &created_endpoint))
            {
                failures.push(membership.clone());
                continue;
            }
            resume_gate = Some(Arc::clone(&created_endpoint));

            let occupant = MucOccupant {
                full_jid: full_jid.clone(),
                room_jid: room_jid.clone(),
                nick: nick.clone(),
                endpoint: MucOccupantEndpoint::Suspended(Arc::clone(&created_endpoint)),
                affiliation,
                role,
                room_non_anonymous: room.non_anonymous,
                occupant_id: crate::xmpp::xml_util::muc_occupant_id(
                    &room.occupant_id_secret,
                    bare_jid(&full_jid),
                ),
                cluster_epoch: cluster_authority
                    .as_ref()
                    .map(|authority| authority.occupant_incarnation)
                    .unwrap_or_else(uuid::Uuid::new_v4),
                connection_id,
                sm_session_id: Some(sm_session_id),
                payload: cluster_authority
                    .as_ref()
                    .map(|authority| authority.presence_payload.clone())
                    .unwrap_or_default(),
            };
            let serializable = SerializableMucOccupant::from(&occupant);
            // A concurrent join or a winning resume may have created the same
            // (room, nick) occupancy while the restore awaited PostgreSQL.
            if !insert_restored_muc_occupant(&self.muc_occupants, key.clone(), occupant) {
                failures.push(membership.clone());
                continue;
            }

            let resumed_cluster_target = if let Some(authority) = cluster_authority.as_ref() {
                let target = db::ClusterMucOccupancyTarget::from(authority);
                let Some(next_epoch) = target.connection_epoch.checked_add(1) else {
                    self.muc_occupants.remove_if(&key, |_, occupant| {
                        suspended_occupant_is_created(occupant, &created_endpoint)
                            && occupant.full_jid == full_jid
                            && occupant.connection_id == connection_id
                    });
                    failures.push(membership.clone());
                    continue;
                };
                let operation_id = uuid::Uuid::new_v4();
                match db::transition_cluster_muc_occupancy(
                    &self.pool,
                    operation_id,
                    &target,
                    "resume",
                    &self.cluster.node_id,
                    Some(connection_id),
                    Some(next_epoch),
                    Some(sm_session_id),
                    Duration::from_secs(90),
                )
                .await
                {
                    Ok(db::ClusterMucTransitionOutcome::Applied)
                    | Ok(db::ClusterMucTransitionOutcome::Replay) => {
                        if let Err(error) = self
                            .muc_service()
                            .wake_committed_operation(&self.cluster, operation_id)
                            .await
                        {
                            tracing::warn!(?error, %operation_id, room=%room_jid,
                                "MUC resume wake failed; PG outbox polling will catch up");
                        }
                        let mut resumed = target;
                        resumed.connection_uuid = connection_id;
                        resumed.connection_epoch = next_epoch;
                        Some(resumed)
                    }
                    Ok(outcome) => {
                        tracing::warn!(?outcome, room=%room_jid, nick=%nick,
                            "PG MUC restart resume rejected the reserved local actor");
                        self.muc_occupants.remove_if(&key, |_, occupant| {
                            suspended_occupant_is_created(occupant, &created_endpoint)
                                && occupant.full_jid == full_jid
                                && occupant.connection_id == connection_id
                        });
                        failures.push(membership.clone());
                        continue;
                    }
                    Err(error) => {
                        tracing::warn!(?error, room=%room_jid, nick=%nick,
                            "PG MUC restart resume failed after local reservation");
                        self.muc_occupants.remove_if(&key, |_, occupant| {
                            suspended_occupant_is_created(occupant, &created_endpoint)
                                && occupant.full_jid == full_jid
                                && occupant.connection_id == connection_id
                        });
                        failures.push(membership.clone());
                        continue;
                    }
                }
            } else {
                None
            };

            let refresh = if let Some(authority) = cluster_authority.as_ref() {
                let previous = SerializableMucOccupant {
                    full_jid: authority.full_jid.clone(),
                    room_jid: room_jid.clone(),
                    nick: authority.nick.clone(),
                    affiliation: authority.affiliation.clone(),
                    role: authority.role.clone(),
                    room_non_anonymous: room.non_anonymous,
                    occupant_id: crate::xmpp::xml_util::muc_occupant_id(
                        &room.occupant_id_secret,
                        bare_jid(&authority.full_jid),
                    ),
                    cluster_epoch: authority.occupant_incarnation,
                    connection_id: authority.connection_uuid,
                    federated_domain: None,
                    sm_session_id: authority.sm_session_id,
                    payload: authority.presence_payload.clone(),
                };
                self.cluster
                    .resume_muc_occupant(&previous, &serializable)
                    .await
            } else {
                Ok(true)
            };
            if !matches!(refresh, Ok(true)) {
                tracing::warn!(room=%room_jid, nick=%nick,
                    "PG MUC restart resume committed but Redis soft-state refresh failed");
            }
            actors.push(RestoredMucActor {
                key,
                full_jid: full_jid.clone(),
                connection_id,
                cluster_epoch: serializable.cluster_epoch,
                sm_session_id,
                endpoint: created_endpoint,
                membership: crate::services::sm::SmMucMembership { room_jid, nick },
                resumed_cluster_target,
            });
        }

        let replay_suffix = if let Some(endpoint) = &resume_gate {
            match snapshot_suspended_muc_buffer_for_resume(endpoint).await {
                Some(stanzas) => stanzas,
                None => {
                    for actor in &actors {
                        if let Some(target) = &actor.resumed_cluster_target {
                            self.compensate_resumed_muc_target(target, actor.sm_session_id)
                                .await;
                        }
                        self.muc_occupants.remove_if(&actor.key, |_, current| {
                            current.full_jid == actor.full_jid
                                && current.connection_id == actor.connection_id
                                && current.cluster_epoch == actor.cluster_epoch
                                && current.sm_session_id == Some(actor.sm_session_id)
                                && matches!(
                                    &current.endpoint,
                                    MucOccupantEndpoint::Suspended(current_endpoint)
                                        if Arc::ptr_eq(current_endpoint, &actor.endpoint)
                                )
                        });
                    }
                    failures.extend(actors.iter().map(|actor| actor.membership.clone()));
                    actors.clear();
                    Vec::new()
                }
            }
        } else {
            Vec::new()
        };
        RestoredLocalMucOccupants {
            failures,
            replay_suffix,
            resume_gate,
            actors,
        }
    }

    async fn compensate_resumed_muc_target(
        &self,
        target: &db::ClusterMucOccupancyTarget,
        sm_session_id: uuid::Uuid,
    ) {
        if !self.cluster.is_enabled() {
            return;
        }
        let operation_id = uuid::Uuid::new_v4();
        match db::transition_cluster_muc_occupancy(
            &self.pool,
            operation_id,
            target,
            "suspend",
            &self.cluster.node_id,
            None,
            None,
            Some(sm_session_id),
            Duration::from_secs(90),
        )
        .await
        {
            Ok(db::ClusterMucTransitionOutcome::Applied)
            | Ok(db::ClusterMucTransitionOutcome::Replay) => {
                if let Err(error) = self
                    .muc_service()
                    .wake_committed_operation(&self.cluster, operation_id)
                    .await
                {
                    tracing::warn!(?error, %operation_id,
                        "MUC resume compensation wake failed; PG polling will converge");
                }
            }
            Ok(outcome) => tracing::warn!(?outcome, room_id=%target.room_id,
                "MUC resume compensation no longer owned the exact PG actor"),
            Err(error) => tracing::error!(?error, room_id=%target.room_id,
                "failed to re-suspend a PG MUC actor after local resume failure"),
        }
    }

    /// Transfer the volatile suffix to the exact live SM checkpoint. The
    /// queue is cleared only after PostgreSQL accepted that checkpoint, while
    /// the endpoint mutex still excludes both delivery and transport
    /// publication. A later socket failure therefore re-suspends the snapshot
    /// without appending a duplicate copy of the suffix.
    pub async fn checkpoint_local_muc_resume(&self, restored: &RestoredLocalMucOccupants) -> bool {
        let Some(endpoint) = restored.resume_gate.as_ref() else {
            return true;
        };
        let mut buffer = endpoint.buffer.lock().await;
        if !transfer_muc_suffix_to_checkpoint(&mut buffer) {
            buffer.phase = SuspendedMucPhase::Sealed;
            endpoint.changed.notify_waiters();
            return false;
        }
        endpoint.changed.notify_waiters();
        true
    }

    /// Publish a restore plan only after the `<resumed/>` control and complete
    /// replay have reached the transport. The endpoint mutex is held while all
    /// exact actors are swapped, so an arriving stanza observes either the
    /// sealed gate or the final live route, never a partially transferred FIFO.
    pub async fn commit_local_muc_resume(
        &self,
        restored: RestoredLocalMucOccupants,
        sender: &crate::outbound::OutboundSender,
        capacity: crate::services::sm_capacity::SmCapacityLease,
    ) -> CommittedLocalMucResume {
        let RestoredLocalMucOccupants {
            mut failures,
            replay_suffix: _,
            resume_gate,
            actors,
        } = restored;
        let Some(endpoint) = resume_gate else {
            return CommittedLocalMucResume {
                joined_rooms: Vec::new(),
                failures,
            };
        };
        let recovery_connection_id = actors
            .first()
            .map(|actor| actor.connection_id)
            .unwrap_or_else(uuid::Uuid::nil);

        let mut committed = Vec::new();
        let mut failed_actors = Vec::new();
        let mut stale_suspended = Vec::new();
        let mut published = false;
        {
            // Keep both publication fences in a lexical scope that ends
            // before any compensation I/O. In particular, a std mutex guard
            // must never become part of the Send future used by deferred SM
            // resume completion.
            let mut buffer = endpoint.buffer.lock().await;
            let mut route = endpoint
                .route
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if matches!(&buffer.phase, SuspendedMucPhase::CheckpointOwned)
                && matches!(&*route, SuspendedMucRoute::Suspended)
            {
                for actor in actors {
                    let activated =
                        self.muc_occupants
                            .get_mut(&actor.key)
                            .is_some_and(|mut current| {
                                if suspended_muc_resume_actor_matches(
                                    &current,
                                    &actor.endpoint,
                                    &actor.full_jid,
                                    actor.connection_id,
                                    actor.cluster_epoch,
                                    actor.sm_session_id,
                                ) {
                                    current.endpoint = MucOccupantEndpoint::Local(sender.clone());
                                    true
                                } else {
                                    false
                                }
                            });
                    if activated {
                        committed.push((
                            actor.membership.room_jid.clone(),
                            JoinedMucMembership {
                                nick: actor.membership.nick.clone(),
                                cluster_epoch: actor.cluster_epoch,
                            },
                        ));
                    } else {
                        failures.push(actor.membership.clone());
                        failed_actors.push(actor);
                    }
                }

                stale_suspended = self
                    .muc_occupants
                    .iter()
                    .filter_map(|current| match &current.endpoint {
                        MucOccupantEndpoint::Suspended(current_endpoint)
                            if Arc::ptr_eq(current_endpoint, &endpoint) =>
                        {
                            Some((
                                current.key().clone(),
                                SerializableMucOccupant::from(&*current),
                            ))
                        }
                        _ => None,
                    })
                    .collect();
                for (key, expected) in &stale_suspended {
                    self.muc_occupants.remove_if(key, |_, current| {
                        muc_suspended_teardown_identity_matches(
                            current,
                            endpoint.sm_session_id,
                            expected,
                        ) && matches!(
                            &current.endpoint,
                            MucOccupantEndpoint::Suspended(current_endpoint)
                                if Arc::ptr_eq(current_endpoint, &endpoint)
                        )
                    });
                }
                buffer.stanzas.clear();
                buffer.bytes = 0;
                buffer.base_stanzas = 0;
                buffer.base_bytes = 0;
                buffer.snapshot_owned = false;
                buffer.phase = SuspendedMucPhase::Dormant;
                *route = SuspendedMucRoute::Live(sender.clone());
                published = true;
                // Keep the route fence locked until the async buffer mutex is
                // released. A concurrent disconnect can then observe Live only
                // after `try_lock()` is guaranteed to succeed; no publication
                // window can panic or reset a partially committed FIFO.
                drop(buffer);
                drop(route);
                endpoint.changed.notify_waiters();
            } else {
                failures.extend(actors.iter().map(|actor| actor.membership.clone()));
                failed_actors = actors;
                if !matches!(&buffer.phase, SuspendedMucPhase::Dormant) {
                    buffer.phase = SuspendedMucPhase::Sealed;
                }
                endpoint.changed.notify_waiters();
                drop(buffer);
                drop(route);
            }
        }
        for actor in failed_actors {
            if let Some(target) = actor.resumed_cluster_target {
                self.compensate_resumed_muc_target(&target, actor.sm_session_id)
                    .await;
            }
        }
        for (_, expected) in stale_suspended {
            if let Err(error) = self
                .cluster
                .unregister_muc_occupant_epoch(
                    &expected.room_jid,
                    &expected.nick,
                    expected.cluster_epoch,
                    expected.connection_id,
                )
                .await
            {
                tracing::warn!(?error, room=%expected.room_jid, nick=%expected.nick,
                    "failed to remove stale suspended MUC soft state after resume");
            }
        }
        if !published
            && !self
                .mark_suspended_muc_durable(vec![Arc::clone(&endpoint)])
                .await
        {
            let queued = self.sm_suspension_recovery_queue().enqueue_promote(
                recovery_connection_id,
                endpoint.sm_session_id,
                vec![Arc::clone(&endpoint)],
                capacity,
            );
            if !queued {
                self.sm_memory_governor().mark_invariant_failure();
                seal_suspended_muc_buffer(&endpoint).await;
                let _ = self
                    .revoke_sm_session_with_teardown(endpoint.sm_session_id)
                    .await;
            }
        }
        failures.sort_by(|left, right| {
            (&left.room_jid, &left.nick).cmp(&(&right.room_jid, &right.nick))
        });
        failures.dedup();
        CommittedLocalMucResume {
            joined_rooms: committed,
            failures,
        }
    }

    /// Roll a failed restore back to a suspended actor without taking suffix
    /// ownership away from its sole durable source. `snapshot_backed` is true
    /// only after the protocol session itself contains the staged suffix; in
    /// that case successful connection cleanup clears this backup instead of
    /// appending it again.
    pub async fn abort_local_muc_resume(
        &self,
        restored: &RestoredLocalMucOccupants,
        snapshot_backed: bool,
    ) {
        let Some(endpoint) = restored.resume_gate.as_ref() else {
            return;
        };
        {
            let mut buffer = endpoint.buffer.lock().await;
            buffer.snapshot_owned |= snapshot_backed;
            buffer.phase = SuspendedMucPhase::Sealed;
        }
        endpoint.changed.notify_waiters();

        for actor in &restored.actors {
            if let Some(target) = &actor.resumed_cluster_target {
                self.compensate_resumed_muc_target(target, actor.sm_session_id)
                    .await;
            }
            let suspended = self.muc_occupants.get(&actor.key).and_then(|current| {
                suspended_muc_resume_actor_matches(
                    &current,
                    &actor.endpoint,
                    &actor.full_jid,
                    actor.connection_id,
                    actor.cluster_epoch,
                    actor.sm_session_id,
                )
                .then(|| SerializableMucOccupant::from(&*current))
            });
            if let Some(suspended) = suspended {
                let encoded = serde_json::to_string(&suspended).unwrap_or_default();
                if let Err(error) = self
                    .cluster
                    .register_suspended_muc_occupant(
                        &suspended.room_jid,
                        &suspended.nick,
                        actor.sm_session_id,
                        &encoded,
                    )
                    .await
                {
                    tracing::warn!(?error, room=%suspended.room_jid, nick=%suspended.nick,
                        "failed to restore suspended MUC soft state after resume rollback");
                }
            }
        }
    }
}

pub struct ClientConnectionGuard {
    state: Arc<AppState>,
    ip: std::net::IpAddr,
    _permit: OwnedSemaphorePermit,
}

pub struct UploadRequestGuard {
    counts: Arc<DashMap<std::net::IpAddr, usize>>,
    ip: std::net::IpAddr,
    _permit: OwnedSemaphorePermit,
}

pub struct UploadDownloadGuard {
    counts: Arc<DashMap<std::net::IpAddr, usize>>,
    ip: std::net::IpAddr,
    _permit: OwnedSemaphorePermit,
}

impl Drop for UploadDownloadGuard {
    fn drop(&mut self) {
        if let Some(mut count) = self.counts.get_mut(&self.ip) {
            *count = count.saturating_sub(1);
            drop(count);
            self.counts.remove_if(&self.ip, |_, count| *count == 0);
        }
    }
}

impl Drop for UploadRequestGuard {
    fn drop(&mut self) {
        if let Some(mut count) = self.counts.get_mut(&self.ip) {
            *count = count.saturating_sub(1);
            drop(count);
            self.counts.remove_if(&self.ip, |_, count| *count == 0);
        }
    }
}

impl Drop for ClientConnectionGuard {
    fn drop(&mut self) {
        if let Some(mut count) = self.state.client_connections_by_ip.get_mut(&self.ip) {
            *count = count.saturating_sub(1);
            drop(count);
            self.state
                .client_connections_by_ip
                .remove_if(&self.ip, |_, count| *count == 0);
        }
    }
}

pub fn bare_jid(jid: &str) -> &str {
    jid.split('/').next().unwrap_or(jid)
}

pub fn localpart(jid: &str) -> &str {
    bare_jid(jid).split('@').next().unwrap_or(jid)
}

pub fn jid_domain(jid: &str) -> Option<&str> {
    bare_jid(jid).split_once('@').map(|(_, domain)| domain)
}

pub fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

pub fn attr_escape(value: &str) -> String {
    xml_escape(value)
}

#[cfg(test)]
mod session_key_tests {
    use super::{
        admit_bounded_omemo_poll_ip, admit_omemo_poll_ip_window, api_keyrings,
        append_suspended_muc_suffix_to_snapshot, begin_suspended_muc_route_transition,
        canonical_suspended_muc_endpoint, complete_snapshot_owned_handoff,
        encode_api_control_entropy, ephemeral_api_control_secret, federation_rule_matches,
        insert_restored_muc_occupant, move_local_muc_nickname_exact_in, muc_actor_identity_matches,
        muc_departure_identity_matches, muc_suspended_teardown_identity_matches,
        promote_suspended_muc_buffer, publish_local_muc_join_if_vacant_in,
        refresh_local_muc_policy_exact_in, refresh_local_muc_presence_exact_in,
        remove_local_muc_occupant_exact_from, runtime_control_startup_retry_delay,
        seal_suspended_muc_buffer, service_control_applies, session_lookup,
        set_local_muc_affiliation_exact_in, set_local_muc_role_exact_in,
        snapshot_suspended_muc_buffer_for_resume, staged_route_activation_allowed,
        suspended_muc_resume_actor_matches, suspended_occupant_is_created,
        transfer_muc_suffix_to_checkpoint, FederationWritePolicy, JoinedMucMembership,
        LocalMucJoinPublication, LocalMucNicknameMove, LocalMucOccupantIdentity, MucOccupant,
        MucOccupantEndpoint, RouteIncarnationSignal, SerializableMucOccupant, SessionLookup,
        StagedRouteActivationCheck, StagedRouteIdentity, SuspendedMucBuffer, SuspendedMucEndpoint,
        SuspendedMucPhase, SuspendedMucRoute,
    };
    use dashmap::DashMap;
    use std::collections::{BTreeSet, VecDeque};
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    };
    use std::time::{Duration, Instant};

    #[test]
    fn runtime_control_startup_backoff_is_bounded_and_decorrelates_processes() {
        let first = runtime_control_startup_retry_delay(1, 17);
        assert!(first >= Duration::from_millis(10));
        assert!(first <= Duration::from_millis(500));

        let saturated = runtime_control_startup_retry_delay(128, 17);
        assert!(saturated <= Duration::from_millis(500));
        assert!(saturated >= first);

        let delays = (10_u32..110)
            .map(|process_id| runtime_control_startup_retry_delay(3, process_id))
            .collect::<BTreeSet<_>>();
        assert!(
            delays.len() > 16,
            "a cold-start cohort must not retry in one synchronized wave"
        );
    }

    #[test]
    fn live_sm_shutdown_write_receipt_does_not_cross_the_suspension_fence() {
        let (sender, mut outbound) = tokio::sync::mpsc::channel(2);
        let endpoint = SuspendedMucEndpoint::new_live(
            uuid::Uuid::new_v4(),
            crate::outbound::OutboundSender::new(sender),
        );
        let (receipt, mut completion) = tokio::sync::mpsc::unbounded_channel();
        assert!(endpoint
            .try_send_live_write_notification("<presence/>".to_owned(), receipt)
            .unwrap());
        let item = outbound.try_recv().unwrap();
        item.confirm_transport_ownership();
        assert!(matches!(
            completion.try_recv(),
            Err(tokio::sync::mpsc::error::TryRecvError::Empty)
        ));
        item.confirm_transport_write();
        assert_eq!(completion.try_recv(), Ok(()));

        begin_suspended_muc_route_transition(&endpoint, 0, 0);
        let (receipt, mut completion) = tokio::sync::mpsc::unbounded_channel();
        assert!(!endpoint
            .try_send_live_write_notification("<presence/>".to_owned(), receipt)
            .unwrap());
        assert!(matches!(
            completion.try_recv(),
            Err(tokio::sync::mpsc::error::TryRecvError::Disconnected)
        ));
        assert!(matches!(
            outbound.try_recv(),
            Err(tokio::sync::mpsc::error::TryRecvError::Disconnected)
        ));
        assert_eq!(endpoint.buffer.try_lock().unwrap().bytes, 0);
    }

    #[test]
    fn suspended_sm_shutdown_write_receipt_is_never_persisted_or_confirmed() {
        for endpoint in [
            SuspendedMucEndpoint::new_collecting(uuid::Uuid::new_v4(), 0, 0),
            SuspendedMucEndpoint::new_durable(uuid::Uuid::new_v4()),
        ] {
            let (receipt, mut completion) = tokio::sync::mpsc::unbounded_channel();
            assert!(!endpoint
                .try_send_live_write_notification("<presence/>".to_owned(), receipt)
                .unwrap());
            assert!(matches!(
                completion.try_recv(),
                Err(tokio::sync::mpsc::error::TryRecvError::Disconnected)
            ));
            assert!(endpoint.buffer.try_lock().unwrap().stanzas.is_empty());
        }
    }

    #[test]
    fn route_removal_signal_retains_the_exact_terminal_state_for_late_subscribers() {
        let connection_id = uuid::Uuid::new_v4();
        let signal = RouteIncarnationSignal::new(connection_id);
        signal.publish_removed();

        let late = signal.subscribe();
        assert_eq!(signal.connection_id(), connection_id);
        assert!(
            *late.borrow(),
            "subscribing after compare-and-remove must not lose the terminal event"
        );
    }

    #[tokio::test]
    async fn unchanged_island_refresh_does_not_wait_for_held_read_guard() {
        use std::future::Future;
        use std::task::{Context, Poll, Waker};

        for enabled in [false, true] {
            let policy = FederationWritePolicy::new(enabled);
            let held_read = if enabled {
                // A raw reader also proves the true no-op does not acquire
                // the exclusive gate; delivery itself is already forbidden.
                policy.gate.read().await
            } else {
                policy.permit().await.expect("federation starts enabled")
            };
            let mut refresh = std::pin::pin!(policy.refresh(enabled));
            let mut context = Context::from_waker(Waker::noop());
            assert_eq!(refresh.as_mut().poll(&mut context), Poll::Ready(enabled));
            assert_eq!(policy.enabled(), enabled);
            drop(held_read);
        }
    }

    #[tokio::test]
    async fn island_refresh_transition_fences_queued_delivery_despite_concurrent_noop() {
        use std::future::Future;
        use std::task::{Context, Poll, Waker};

        let policy = FederationWritePolicy::new(false);
        let held_read = policy.permit().await.expect("federation starts enabled");
        let mut transition = std::pin::pin!(policy.refresh(true));
        let mut queued_delivery = std::pin::pin!(policy.permit());
        let mut context = Context::from_waker(Waker::noop());
        assert_eq!(transition.as_mut().poll(&mut context), Poll::Pending);
        assert!(queued_delivery.as_mut().poll(&mut context).is_pending());

        let mut unchanged = std::pin::pin!(policy.refresh(false));
        assert_eq!(unchanged.as_mut().poll(&mut context), Poll::Ready(false));
        assert!(!policy.enabled());
        assert_eq!(transition.as_mut().poll(&mut context), Poll::Pending);
        assert!(queued_delivery.as_mut().poll(&mut context).is_pending());

        drop(held_read);
        assert_eq!(transition.as_mut().poll(&mut context), Poll::Ready(false));
        assert!(policy.enabled());
        assert!(matches!(
            queued_delivery.as_mut().poll(&mut context),
            Poll::Ready(None)
        ));
    }

    #[tokio::test]
    async fn island_refresh_reopening_waits_for_gate_and_returns_locked_previous_value() {
        use std::future::Future;
        use std::task::{Context, Poll, Waker};

        for concurrent_apply in [false, true] {
            let policy = FederationWritePolicy::new(true);
            let held_read = policy.gate.read().await;
            let mut earlier_apply = std::pin::pin!(policy.apply(false));
            let mut context = Context::from_waker(Waker::noop());
            if concurrent_apply {
                assert_eq!(earlier_apply.as_mut().poll(&mut context), Poll::Pending);
            }
            let mut transition = std::pin::pin!(policy.refresh(false));
            let mut queued_delivery = std::pin::pin!(policy.permit());
            assert_eq!(transition.as_mut().poll(&mut context), Poll::Pending);
            assert!(queued_delivery.as_mut().poll(&mut context).is_pending());
            assert!(policy.enabled());

            drop(held_read);
            if concurrent_apply {
                assert_eq!(earlier_apply.as_mut().poll(&mut context), Poll::Ready(()));
                assert!(queued_delivery.as_mut().poll(&mut context).is_pending());
            }
            // The slow path returns the swap's value after the exclusive
            // wait, including when an earlier apply changed the initial read.
            assert_eq!(
                transition.as_mut().poll(&mut context),
                Poll::Ready(!concurrent_apply)
            );
            assert!(!policy.enabled());
            assert!(matches!(
                queued_delivery.as_mut().poll(&mut context),
                Poll::Ready(Some(_))
            ));
        }
    }

    #[tokio::test]
    async fn island_mode_transition_waits_for_and_fences_federation_writes() {
        let policy = Arc::new(FederationWritePolicy::new(false));
        let permit = policy.permit().await.expect("federation starts enabled");
        let transition_policy = Arc::clone(&policy);
        let transition = tokio::spawn(async move {
            transition_policy.apply(true).await;
        });

        tokio::task::yield_now().await;
        assert!(
            !transition.is_finished(),
            "the kill switch must wait for an in-flight socket-write boundary"
        );
        drop(permit);
        tokio::time::timeout(Duration::from_secs(1), transition)
            .await
            .expect("island transition completes after the write boundary")
            .expect("island transition task succeeds");
        assert!(policy.enabled());
        assert!(
            policy.permit().await.is_none(),
            "queued writers must observe island mode after the transition"
        );

        policy.apply(false).await;
        assert!(policy.permit().await.is_some());
    }

    #[test]
    fn omemo_poll_active_ip_cap_is_linearizable() {
        let windows = Arc::new(dashmap::DashMap::new());
        let admission = Arc::new(std::sync::Mutex::new(()));
        let barrier = Arc::new(std::sync::Barrier::new(33));
        let now = Instant::now();
        let accepted = std::thread::scope(|scope| {
            let mut workers = Vec::new();
            for suffix in 1_u8..=32 {
                let windows = Arc::clone(&windows);
                let admission = Arc::clone(&admission);
                let barrier = Arc::clone(&barrier);
                workers.push(scope.spawn(move || {
                    barrier.wait();
                    admit_bounded_omemo_poll_ip(
                        &windows,
                        &admission,
                        std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, suffix)),
                        now,
                        false,
                        4,
                    )
                }));
            }
            barrier.wait();
            workers
                .into_iter()
                .map(|worker| worker.join().expect("poll admission thread completes"))
                .filter(|accepted| *accepted)
                .count()
        });
        assert_eq!(accepted, 4);
        assert_eq!(windows.len(), 4);
    }

    fn suspended_buffer(stanzas: &[&str]) -> SuspendedMucBuffer {
        let mut buffer = SuspendedMucBuffer {
            phase: SuspendedMucPhase::Collecting,
            snapshot_owned: false,
            base_stanzas: 0,
            base_bytes: 0,
            bytes: 0,
            stanzas: VecDeque::new(),
        };
        for stanza in stanzas {
            assert!(buffer.enqueue_volatile((*stanza).to_owned(), 32, 4096));
        }
        buffer
    }

    fn queued(buffer: &SuspendedMucBuffer) -> Vec<&str> {
        buffer
            .stanzas
            .iter()
            .map(|stanza| stanza.xml.as_str())
            .collect()
    }

    fn sm_snapshot(outbound_h: u32, unacked: &[&str]) -> crate::services::sm::SmSessionSnapshot {
        crate::services::sm::SmSessionSnapshot {
            inbound_h: 0,
            outbound_h,
            acked_h: 0,
            available: true,
            carbons: false,
            priority: 0,
            blocklist_requested: false,
            roster_requested: false,
            active_privacy_list: None,
            privacy_requested: false,
            peer_ip: std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            user_agent_id: None,
            joined_rooms: Vec::new(),
            directed_presence: Vec::new(),
            last_presence: None,
            unacked: unacked
                .iter()
                .map(|stanza| crate::outbound::SmUnackedStanza::plain((*stanza).to_owned()))
                .collect(),
        }
    }

    #[test]
    fn disconnect_snapshot_preserves_fifo_budget_and_counter_wrap() {
        let mut snapshot = sm_snapshot(u32::MAX, &["old"]);
        let mut suffix = VecDeque::new();
        suffix.push_back(super::SuspendedMucStanza {
            source_id: uuid::Uuid::new_v4(),
            xml: "room-a".to_owned(),
        });
        suffix.push_back(super::SuspendedMucStanza {
            source_id: uuid::Uuid::new_v4(),
            xml: "room-b".to_owned(),
        });
        append_suspended_muc_suffix_to_snapshot(&mut snapshot, &suffix, 3, "oldroom-aroom-b".len())
            .expect("the complete session FIFO fits exactly");
        assert_eq!(snapshot.outbound_h, 1);
        assert_eq!(
            snapshot
                .unacked
                .iter()
                .map(|entry| entry.stanza.as_str())
                .collect::<Vec<_>>(),
            vec!["old", "room-a", "room-b"]
        );
        assert!(snapshot
            .unacked
            .iter()
            .all(|entry| entry.durable_delivery().is_none()));

        let before_h = snapshot.outbound_h;
        let before = snapshot.unacked.clone();
        assert!(
            append_suspended_muc_suffix_to_snapshot(&mut snapshot, &suffix, 4, usize::MAX).is_err()
        );
        assert_eq!(snapshot.outbound_h, before_h);
        assert_eq!(snapshot.unacked, before);
    }

    #[tokio::test]
    async fn suspended_muc_durable_promotion_retains_first_and_mid_failure_exactly() {
        let mut first_failure = suspended_buffer(&["first", "second"]);
        let expected_bytes = "first".len() + "second".len();
        let mut outcomes = VecDeque::from([false]);
        let mut attempted = Vec::new();
        assert!(
            !promote_suspended_muc_buffer(&mut first_failure, |_source_id, stanza| {
                attempted.push(stanza);
                std::future::ready(outcomes.pop_front().unwrap())
            })
            .await
        );
        assert_eq!(attempted, vec!["first".to_owned()]);
        assert_eq!(queued(&first_failure), vec!["first", "second"]);
        assert_eq!(first_failure.bytes, expected_bytes);
        assert!(matches!(&first_failure.phase, SuspendedMucPhase::Sealed));
        assert!(!first_failure.enqueue_volatile("newer".to_owned(), 32, 4096));

        let mut mid_failure = suspended_buffer(&["first", "middle", "last"]);
        let mut outcomes = VecDeque::from([true, false]);
        let mut attempted = Vec::new();
        assert!(
            !promote_suspended_muc_buffer(&mut mid_failure, |source_id, stanza| {
                attempted.push((source_id, stanza));
                std::future::ready(outcomes.pop_front().unwrap())
            })
            .await
        );
        assert_eq!(
            attempted
                .iter()
                .map(|(_, stanza)| stanza.as_str())
                .collect::<Vec<_>>(),
            vec!["first", "middle"]
        );
        let ambiguous_source_id = attempted[1].0;
        assert_eq!(queued(&mid_failure), vec!["middle", "last"]);
        assert_eq!(mid_failure.bytes, "middle".len() + "last".len());
        assert!(matches!(&mid_failure.phase, SuspendedMucPhase::Sealed));

        let mut outcomes = VecDeque::from([true, true]);
        let mut retried = Vec::new();
        assert!(
            promote_suspended_muc_buffer(&mut mid_failure, |source_id, stanza| {
                retried.push((source_id, stanza));
                std::future::ready(outcomes.pop_front().unwrap())
            })
            .await
        );
        assert_eq!(retried[0].0, ambiguous_source_id);
        assert_eq!(
            retried
                .iter()
                .map(|(_, stanza)| stanza.as_str())
                .collect::<Vec<_>>(),
            vec!["middle", "last"]
        );
        assert!(mid_failure.stanzas.is_empty());
        assert_eq!(mid_failure.bytes, 0);
        assert!(matches!(&mid_failure.phase, SuspendedMucPhase::Durable));
    }

    #[tokio::test]
    async fn suspended_muc_checkpoint_snapshot_keeps_ownership_until_commit() {
        let endpoint = Arc::new(SuspendedMucEndpoint::new(uuid::Uuid::new_v4()));
        {
            let mut buffer = endpoint.buffer.lock().await;
            assert!(buffer.enqueue_volatile("older-1".to_owned(), 8, 4096));
            assert!(buffer.enqueue_volatile("older-2".to_owned(), 8, 4096));
            buffer.phase = SuspendedMucPhase::Resuming;
        }
        let snapshot = snapshot_suspended_muc_buffer_for_resume(&endpoint)
            .await
            .expect("resuming gate can be checkpointed");
        assert_eq!(snapshot, vec!["older-1".to_owned(), "older-2".to_owned()]);
        {
            let mut buffer = endpoint.buffer.lock().await;
            assert_eq!(queued(&buffer), vec!["older-1", "older-2"]);
            assert!(matches!(&buffer.phase, SuspendedMucPhase::Committing));
            assert!(!buffer.enqueue_volatile("racing".to_owned(), 8, 4096));
        }
        // A failed durable checkpoint seals the original owner without taking
        // or clearing a byte, so cleanup can still promote the exact FIFO.
        seal_suspended_muc_buffer(&endpoint).await;
        {
            let buffer = endpoint.buffer.lock().await;
            assert!(matches!(&buffer.phase, SuspendedMucPhase::Sealed));
            assert_eq!(queued(&buffer), vec!["older-1", "older-2"]);
        }
    }

    #[tokio::test]
    async fn checkpoint_owned_suffix_is_cleared_once_and_never_promoted_again() {
        let endpoint = Arc::new(SuspendedMucEndpoint::new(uuid::Uuid::new_v4()));
        {
            let mut buffer = endpoint.buffer.lock().await;
            assert!(buffer.enqueue_volatile("one".to_owned(), 8, 4096));
            assert!(buffer.enqueue_volatile("two".to_owned(), 8, 4096));
            buffer.phase = SuspendedMucPhase::Resuming;
        }
        assert_eq!(
            snapshot_suspended_muc_buffer_for_resume(&endpoint).await,
            Some(vec!["one".to_owned(), "two".to_owned()])
        );
        {
            let mut buffer = endpoint.buffer.lock().await;
            assert!(transfer_muc_suffix_to_checkpoint(&mut buffer));
            assert!(buffer.stanzas.is_empty());
            assert_eq!(buffer.bytes, 0);
            assert!(matches!(&buffer.phase, SuspendedMucPhase::CheckpointOwned));
            assert!(complete_snapshot_owned_handoff(&mut buffer));
            assert!(buffer.stanzas.is_empty());
            assert!(matches!(&buffer.phase, SuspendedMucPhase::Durable));
            assert!(!complete_snapshot_owned_handoff(&mut buffer));
        }
    }

    #[tokio::test]
    async fn ambiguous_suspend_commit_can_be_claimed_without_replaying_backup_twice() {
        let endpoint = Arc::new(SuspendedMucEndpoint::new(uuid::Uuid::new_v4()));
        {
            let mut buffer = endpoint.buffer.lock().await;
            assert!(buffer.enqueue_volatile("already-in-db".to_owned(), 8, 4096));
            buffer.snapshot_owned = true;
            buffer.phase = SuspendedMucPhase::Resuming;
        }
        assert_eq!(
            snapshot_suspended_muc_buffer_for_resume(&endpoint).await,
            Some(Vec::new()),
            "the claimed PostgreSQL queue, not its retained backup, is replayed"
        );
        {
            let mut buffer = endpoint.buffer.lock().await;
            assert!(buffer.snapshot_owned);
            assert_eq!(queued(&buffer), vec!["already-in-db"]);
            assert!(transfer_muc_suffix_to_checkpoint(&mut buffer));
            assert!(buffer.stanzas.is_empty());
            assert!(complete_snapshot_owned_handoff(&mut buffer));
            assert!(!buffer.snapshot_owned);
            assert!(matches!(&buffer.phase, SuspendedMucPhase::Durable));
        }
    }

    #[tokio::test]
    async fn disconnect_fence_survives_a_busy_checkpoint_buffer_without_clearing_it() {
        let (raw_sender, _receiver) = tokio::sync::mpsc::channel(2);
        let endpoint = Arc::new(SuspendedMucEndpoint::new_live(
            uuid::Uuid::new_v4(),
            crate::outbound::OutboundSender::new(raw_sender),
        ));
        let mut buffer = endpoint.buffer.lock().await;
        buffer.phase = SuspendedMucPhase::CheckpointOwned;
        buffer.snapshot_owned = true;
        begin_suspended_muc_route_transition(&endpoint, 7, 700);
        {
            let route = endpoint
                .route
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            assert!(matches!(&*route, SuspendedMucRoute::Transitioning));
        }
        assert!(buffer.snapshot_owned);
        assert!(matches!(&buffer.phase, SuspendedMucPhase::CheckpointOwned));
        drop(buffer);

        seal_suspended_muc_buffer(&endpoint).await;
        let buffer = endpoint.buffer.lock().await;
        assert!(buffer.snapshot_owned);
        assert!(matches!(&buffer.phase, SuspendedMucPhase::Sealed));
        let route = endpoint
            .route
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        assert!(matches!(&*route, SuspendedMucRoute::Suspended));
    }

    #[test]
    fn live_route_send_and_transition_share_one_linearization_fence() {
        let (raw_sender, mut receiver) = tokio::sync::mpsc::channel(2);
        let endpoint = Arc::new(SuspendedMucEndpoint::new_live(
            uuid::Uuid::new_v4(),
            crate::outbound::OutboundSender::new(raw_sender),
        ));
        let barrier = Arc::new(std::sync::Barrier::new(2));
        std::thread::scope(|scope| {
            let live = endpoint
                .route
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let transition_endpoint = Arc::clone(&endpoint);
            let transition_barrier = Arc::clone(&barrier);
            let transition = scope.spawn(move || {
                transition_barrier.wait();
                let mut route = transition_endpoint
                    .route
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                *route = SuspendedMucRoute::Transitioning;
            });
            barrier.wait();
            let SuspendedMucRoute::Live(sender) = &*live else {
                panic!("the route starts live");
            };
            sender
                .try_send("before-fence".to_owned())
                .expect("the write linearizes before transition");
            drop(live);
            transition.join().expect("transition thread completes");
        });
        let delivered = receiver.try_recv().expect("pre-fence stanza is delivered");
        assert_eq!(delivered.stanza, "before-fence");
        let route = endpoint
            .route
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        assert!(matches!(&*route, SuspendedMucRoute::Transitioning));
    }

    #[tokio::test]
    async fn one_sm_gate_preserves_cross_room_fifo_and_global_budget() {
        let endpoint = Arc::new(SuspendedMucEndpoint::new_collecting(
            uuid::Uuid::new_v4(),
            2,
            8,
        ));
        {
            let mut buffer = endpoint.buffer.lock().await;
            assert!(buffer.enqueue_volatile("A".to_owned(), 3, 9));
            assert!(!buffer.enqueue_volatile("B".to_owned(), 4, 9));
            buffer.base_stanzas = 0;
            buffer.base_bytes = 0;
            assert!(buffer.enqueue_volatile("room-b:1".to_owned(), 8, 4096));
            assert!(buffer.enqueue_volatile("room-a:2".to_owned(), 8, 4096));
            buffer.phase = SuspendedMucPhase::Resuming;
        }
        assert_eq!(
            snapshot_suspended_muc_buffer_for_resume(&endpoint)
                .await
                .unwrap(),
            vec!["A".to_owned(), "room-b:1".to_owned(), "room-a:2".to_owned()]
        );
    }

    #[test]
    fn suspended_removal_matches_only_the_exact_created_endpoint() {
        let session = uuid::Uuid::new_v4();
        let created = Arc::new(SuspendedMucEndpoint::new(session));
        let same_session_other_endpoint = Arc::new(SuspendedMucEndpoint::new(session));
        let mut occupant = test_muc_occupant(
            "alice@example.test/Phone",
            uuid::Uuid::new_v4(),
            uuid::Uuid::new_v4(),
        );
        occupant.endpoint = MucOccupantEndpoint::Suspended(same_session_other_endpoint);
        // Two distinct endpoints may share one SM session id; only the exact
        // Arc this restore created may ever be removed by its failure path.
        assert!(!suspended_occupant_is_created(&occupant, &created));
        occupant.endpoint = MucOccupantEndpoint::Suspended(Arc::clone(&created));
        assert!(suspended_occupant_is_created(&occupant, &created));
    }

    #[test]
    fn stale_registry_miss_adopts_the_concurrent_canonical_resume_gate() {
        let registry = Arc::new(dashmap::DashMap::new());
        let session_id = uuid::Uuid::new_v4();
        assert!(registry.get(&session_id).is_none());
        let barrier = Arc::new(std::sync::Barrier::new(3));
        let endpoints = std::thread::scope(|scope| {
            let mut workers = Vec::new();
            for _ in 0..2 {
                let registry = Arc::clone(&registry);
                let barrier = Arc::clone(&barrier);
                workers.push(scope.spawn(move || {
                    let proposed = Arc::new(SuspendedMucEndpoint::new_reserved(session_id, 0, 0));
                    barrier.wait();
                    canonical_suspended_muc_endpoint(&registry, session_id, proposed)
                }));
            }
            barrier.wait();
            workers
                .into_iter()
                .map(|worker| worker.join().unwrap())
                .collect::<Vec<_>>()
        });
        assert!(Arc::ptr_eq(&endpoints[0], &endpoints[1]));
        assert_eq!(registry.len(), 1);
    }

    #[test]
    fn stale_restore_miss_never_overwrites_a_concurrent_joiner() {
        let occupants = dashmap::DashMap::new();
        let key = "room@example.test\0nick".to_owned();
        assert!(occupants.get(&key).is_none());
        let joiner_connection = uuid::Uuid::new_v4();
        occupants.insert(
            key.clone(),
            test_muc_occupant(
                "alice@example.test/Joiner",
                joiner_connection,
                uuid::Uuid::new_v4(),
            ),
        );
        let restored = test_muc_occupant(
            "alice@example.test/Restored",
            uuid::Uuid::new_v4(),
            uuid::Uuid::new_v4(),
        );
        assert!(!insert_restored_muc_occupant(
            &occupants,
            key.clone(),
            restored
        ));
        assert_eq!(
            occupants.get(&key).unwrap().connection_id,
            joiner_connection
        );
    }

    #[tokio::test]
    async fn restart_reserved_and_checkpoint_owned_gates_accept_no_volatile_suffix() {
        let endpoint = SuspendedMucEndpoint::new_reserved(uuid::Uuid::new_v4(), 0, 0);
        let mut buffer = endpoint.buffer.lock().await;
        assert!(matches!(&buffer.phase, SuspendedMucPhase::Reserved));
        assert!(!buffer.enqueue_volatile("during-db-await".to_owned(), 8, 4096));
        buffer.phase = SuspendedMucPhase::CheckpointOwned;
        assert!(!buffer.enqueue_volatile("before-resumed".to_owned(), 8, 4096));
        let route = endpoint
            .route
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        assert!(matches!(&*route, SuspendedMucRoute::Suspended));
    }

    #[test]
    fn resumed_muc_actor_swap_rejects_every_aba_identity_change() {
        let sm_session_id = uuid::Uuid::new_v4();
        let connection_id = uuid::Uuid::new_v4();
        let cluster_epoch = uuid::Uuid::new_v4();
        let endpoint = Arc::new(SuspendedMucEndpoint::new(sm_session_id));
        let mut occupant =
            test_muc_occupant("alice@example.test/Phone", connection_id, cluster_epoch);
        occupant.sm_session_id = Some(sm_session_id);
        occupant.endpoint = MucOccupantEndpoint::Suspended(Arc::clone(&endpoint));
        let matches = |endpoint, full_jid, connection_id, cluster_epoch| {
            suspended_muc_resume_actor_matches(
                &occupant,
                endpoint,
                full_jid,
                connection_id,
                cluster_epoch,
                sm_session_id,
            )
        };
        assert!(matches(
            &endpoint,
            "alice@example.test/Phone",
            connection_id,
            cluster_epoch
        ));
        let unrelated_endpoint = Arc::new(SuspendedMucEndpoint::new(sm_session_id));
        assert!(!matches(
            &unrelated_endpoint,
            "alice@example.test/Phone",
            connection_id,
            cluster_epoch
        ));
        assert!(!matches(
            &endpoint,
            "alice@example.test/Other",
            connection_id,
            cluster_epoch
        ));
        assert!(!matches(
            &endpoint,
            "alice@example.test/Phone",
            uuid::Uuid::new_v4(),
            cluster_epoch
        ));
        assert!(!matches(
            &endpoint,
            "alice@example.test/Phone",
            connection_id,
            uuid::Uuid::new_v4()
        ));
    }

    #[tokio::test]
    async fn suspended_muc_promotion_mutex_orders_concurrent_admission_after_the_prefix() {
        let endpoint = Arc::new(SuspendedMucEndpoint::new(uuid::Uuid::new_v4()));
        {
            let mut buffer = endpoint.buffer.lock().await;
            assert!(buffer.enqueue_volatile("older-1".to_owned(), 8, 4096));
            assert!(buffer.enqueue_volatile("older-2".to_owned(), 8, 4096));
        }
        let started = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        let order = Arc::new(Mutex::new(Vec::new()));
        let calls = Arc::new(AtomicUsize::new(0));
        let promote_endpoint = Arc::clone(&endpoint);
        let promote_started = Arc::clone(&started);
        let promote_release = Arc::clone(&release);
        let promote_order = Arc::clone(&order);
        let promote_calls = Arc::clone(&calls);
        let promotion = tokio::spawn(async move {
            let mut buffer = promote_endpoint.buffer.lock().await;
            promote_suspended_muc_buffer(&mut buffer, move |_source_id, stanza| {
                let started = Arc::clone(&promote_started);
                let release = Arc::clone(&promote_release);
                let order = Arc::clone(&promote_order);
                let call = promote_calls.fetch_add(1, Ordering::SeqCst);
                async move {
                    order.lock().unwrap().push(stanza);
                    if call == 0 {
                        started.notify_one();
                        release.notified().await;
                    }
                    true
                }
            })
            .await
        });
        started.notified().await;
        assert!(endpoint.buffer.try_lock().is_err());

        let writer_endpoint = Arc::clone(&endpoint);
        let writer_order = Arc::clone(&order);
        let writer = tokio::spawn(async move {
            let buffer = writer_endpoint.buffer.lock().await;
            assert!(matches!(&buffer.phase, SuspendedMucPhase::Durable));
            writer_order.lock().unwrap().push("newer".to_owned());
        });
        release.notify_one();
        assert!(promotion.await.unwrap());
        writer.await.unwrap();
        assert_eq!(
            *order.lock().unwrap(),
            vec![
                "older-1".to_owned(),
                "older-2".to_owned(),
                "newer".to_owned()
            ]
        );
    }

    #[test]
    fn staged_route_cannot_reactivate_after_identity_or_revocation_fence_changes() {
        let connection = uuid::Uuid::new_v4();
        let user = uuid::Uuid::new_v4();
        let allowed = |actual_connection,
                       actual_user,
                       actual_generation,
                       same_lifecycle,
                       lifecycle_state,
                       session_cancelled,
                       owner_cancelled| {
            staged_route_activation_allowed(StagedRouteActivationCheck {
                session: StagedRouteIdentity {
                    connection_id: actual_connection,
                    user_id: actual_user,
                    auth_generation: actual_generation,
                },
                expected: StagedRouteIdentity {
                    connection_id: connection,
                    user_id: user,
                    auth_generation: 7,
                },
                same_lifecycle,
                lifecycle_state,
                session_cancelled,
                owner_cancelled,
            })
        };
        assert!(allowed(connection, user, 7, true, 0, false, false));
        assert!(!allowed(
            uuid::Uuid::new_v4(),
            user,
            7,
            true,
            0,
            false,
            false
        ));
        assert!(!allowed(connection, user, 6, true, 0, false, false));
        assert!(!allowed(connection, user, 7, false, 0, false, false));
        assert!(!allowed(connection, user, 7, true, 1, false, false));
        assert!(!allowed(connection, user, 7, true, 0, true, false));
        assert!(!allowed(connection, user, 7, true, 0, false, true));
    }

    #[test]
    fn omemo_poll_ip_window_is_sliding_and_bounded() {
        let started = Instant::now();
        let mut window = VecDeque::new();
        for offset in 0..super::OMEMO_POLL_IP_REQUESTS_PER_MINUTE {
            assert!(admit_omemo_poll_ip_window(
                &mut window,
                started + Duration::from_millis(offset as u64),
            ));
        }
        assert!(!admit_omemo_poll_ip_window(
            &mut window,
            started + Duration::from_secs(1),
        ));
        assert!(admit_omemo_poll_ip_window(
            &mut window,
            started + Duration::from_secs(61),
        ));
        assert_eq!(window.len(), 1);
    }

    fn test_muc_occupant(
        full_jid: &str,
        connection_id: uuid::Uuid,
        cluster_epoch: uuid::Uuid,
    ) -> MucOccupant {
        let (sender, _receiver) = tokio::sync::mpsc::channel(1);
        MucOccupant {
            full_jid: full_jid.to_owned(),
            room_jid: "room@conference.example.test".to_owned(),
            nick: "Alice".to_owned(),
            endpoint: MucOccupantEndpoint::Local(crate::outbound::OutboundSender::new(sender)),
            affiliation: "member".to_owned(),
            role: "participant".to_owned(),
            room_non_anonymous: true,
            occupant_id: "opaque".to_owned(),
            cluster_epoch,
            connection_id,
            sm_session_id: None,
            payload: String::new(),
        }
    }

    #[test]
    fn kicked_session_without_occupant_cannot_authorize_a_message() {
        let connection_id = uuid::Uuid::new_v4();
        let membership = JoinedMucMembership {
            nick: "Alice".to_owned(),
            cluster_epoch: uuid::Uuid::new_v4(),
        };
        let occupant: Option<&MucOccupant> = None;
        assert!(!occupant.is_some_and(|occupant| {
            muc_actor_identity_matches(
                occupant,
                "alice@example.test/Phone",
                connection_id,
                "room@conference.example.test",
                &membership,
            )
        }));
    }

    #[test]
    fn reused_nickname_does_not_authorize_the_old_session() {
        let old_connection = uuid::Uuid::new_v4();
        let old_membership = JoinedMucMembership {
            nick: "Alice".to_owned(),
            cluster_epoch: uuid::Uuid::new_v4(),
        };
        let replacement = test_muc_occupant(
            "bob@example.test/Laptop",
            uuid::Uuid::new_v4(),
            uuid::Uuid::new_v4(),
        );
        assert!(!muc_actor_identity_matches(
            &replacement,
            "alice@example.test/Phone",
            old_connection,
            "room@conference.example.test",
            &old_membership,
        ));
    }

    #[test]
    fn delayed_old_drop_cannot_remove_a_reused_nickname() {
        let old_connection = uuid::Uuid::new_v4();
        let old_epoch = uuid::Uuid::new_v4();
        let replacement = test_muc_occupant(
            "alice@example.test/Phone",
            uuid::Uuid::new_v4(),
            uuid::Uuid::new_v4(),
        );
        assert!(!muc_departure_identity_matches(
            &replacement,
            "alice@example.test/Phone",
            old_connection,
            old_epoch,
        ));
    }

    #[test]
    fn exact_muc_removal_preserves_a_reused_nickname() {
        let old_connection = uuid::Uuid::new_v4();
        let old_epoch = uuid::Uuid::new_v4();
        let replacement = test_muc_occupant(
            "alice@example.test/Phone",
            uuid::Uuid::new_v4(),
            uuid::Uuid::new_v4(),
        );
        let key = crate::xmpp::xml_util::muc_occupant_key(&replacement.room_jid, &replacement.nick);
        let occupants = DashMap::new();
        occupants.insert(key.clone(), replacement.clone());

        let stale = LocalMucOccupantIdentity {
            room_jid: &replacement.room_jid,
            nick: &replacement.nick,
            full_jid: &replacement.full_jid,
            connection_id: old_connection,
            cluster_epoch: old_epoch,
        };
        assert!(remove_local_muc_occupant_exact_from(&occupants, stale).is_none());
        assert_eq!(
            occupants.get(&key).unwrap().connection_id,
            replacement.connection_id
        );

        let exact = LocalMucOccupantIdentity::from(&replacement);
        assert!(remove_local_muc_occupant_exact_from(
            &occupants,
            LocalMucOccupantIdentity {
                connection_id: uuid::Uuid::nil(),
                ..exact
            },
        )
        .is_none());
        assert!(remove_local_muc_occupant_exact_from(&occupants, exact).is_some());
        assert!(!occupants.contains_key(&key));
    }

    #[test]
    fn joining_again_cannot_overwrite_a_reused_nickname() {
        let old = test_muc_occupant(
            "alice@example.test/Phone",
            uuid::Uuid::new_v4(),
            uuid::Uuid::new_v4(),
        );
        let mut replacement = old.clone();
        replacement.connection_id = uuid::Uuid::new_v4();
        replacement.cluster_epoch = uuid::Uuid::new_v4();
        let key = crate::xmpp::xml_util::muc_occupant_key(&old.room_jid, &old.nick);
        let occupants = DashMap::new();

        assert_eq!(
            publish_local_muc_join_if_vacant_in(&occupants, &old),
            LocalMucJoinPublication::Published
        );
        assert_eq!(
            publish_local_muc_join_if_vacant_in(&occupants, &old),
            LocalMucJoinPublication::AlreadyPublished
        );
        assert!(remove_local_muc_occupant_exact_from(
            &occupants,
            LocalMucOccupantIdentity::from(&old)
        )
        .is_some());
        assert_eq!(
            publish_local_muc_join_if_vacant_in(&occupants, &replacement),
            LocalMucJoinPublication::Published
        );
        assert_eq!(
            publish_local_muc_join_if_vacant_in(&occupants, &old),
            LocalMucJoinPublication::Occupied
        );
        let stale_snapshot = replacement.clone();
        let mut later = replacement.clone();
        later.connection_id = uuid::Uuid::new_v4();
        later.cluster_epoch = uuid::Uuid::new_v4();
        occupants.insert(key.clone(), later.clone());
        assert!(remove_local_muc_occupant_exact_from(
            &occupants,
            LocalMucOccupantIdentity::from(&stale_snapshot)
        )
        .is_none());
        assert_eq!(
            publish_local_muc_join_if_vacant_in(&occupants, &old),
            LocalMucJoinPublication::Occupied,
            "a failed exact eviction must leave the later actor untouched"
        );
        assert!(remove_local_muc_occupant_exact_from(
            &occupants,
            LocalMucOccupantIdentity::from(&old)
        )
        .is_none());
        assert_eq!(
            occupants.get(&key).unwrap().connection_id,
            later.connection_id
        );
    }

    #[test]
    fn delayed_committed_join_does_not_evict_a_later_published_incarnation() {
        // A can commit in PG, then lose authority while awaiting a Redis
        // operation. B can subsequently commit and publish the same nickname.
        // A's late local publication must leave B intact for exact PG checks.
        let join_a = test_muc_occupant(
            "alice@example.test/Phone",
            uuid::Uuid::new_v4(),
            uuid::Uuid::new_v4(),
        );
        let join_b = test_muc_occupant(
            "bob@example.test/Laptop",
            uuid::Uuid::new_v4(),
            uuid::Uuid::new_v4(),
        );
        let key = crate::xmpp::xml_util::muc_occupant_key(&join_a.room_jid, &join_a.nick);
        let occupants = DashMap::new();

        assert_eq!(
            publish_local_muc_join_if_vacant_in(&occupants, &join_b),
            LocalMucJoinPublication::Published
        );
        assert_eq!(
            publish_local_muc_join_if_vacant_in(&occupants, &join_a),
            LocalMucJoinPublication::Occupied
        );
        let current = occupants.get(&key).unwrap();
        assert_eq!(current.full_jid, join_b.full_jid);
        assert_eq!(current.connection_id, join_b.connection_id);
        assert_eq!(current.cluster_epoch, join_b.cluster_epoch);
    }

    #[test]
    fn exact_muc_profile_updates_reject_a_reused_nickname() {
        let old = test_muc_occupant(
            "alice@example.test/Phone",
            uuid::Uuid::new_v4(),
            uuid::Uuid::new_v4(),
        );
        let mut replacement =
            test_muc_occupant(&old.full_jid, uuid::Uuid::new_v4(), uuid::Uuid::new_v4());
        replacement.affiliation = "none".to_owned();
        replacement.role = "visitor".to_owned();
        let key = crate::xmpp::xml_util::muc_occupant_key(&old.room_jid, &old.nick);
        let occupants = DashMap::new();
        occupants.insert(key.clone(), replacement.clone());

        let stale = LocalMucOccupantIdentity::from(&old);
        assert!(
            set_local_muc_affiliation_exact_in(&occupants, stale, "owner", true, false, None,)
                .is_none()
        );
        assert!(
            set_local_muc_role_exact_in(&occupants, stale, "visitor", "participant", None)
                .is_none()
        );
        assert!(
            refresh_local_muc_policy_exact_in(&occupants, stale, Some(false), Some(true)).is_none()
        );
        let current = occupants.get(&key).unwrap();
        assert_eq!(current.connection_id, replacement.connection_id);
        assert_eq!(current.affiliation, "none");
        assert_eq!(current.role, "visitor");
    }

    #[test]
    fn exact_muc_updates_preserve_registration_and_presence_fields() {
        let mut occupant = test_muc_occupant(
            "alice@example.test/Phone",
            uuid::Uuid::new_v4(),
            uuid::Uuid::new_v4(),
        );
        occupant.affiliation = "none".to_owned();
        occupant.role = "visitor".to_owned();
        occupant.payload = "<show>away</show>".to_owned();
        let suspended = Arc::new(SuspendedMucEndpoint::new(uuid::Uuid::new_v4()));
        occupant.endpoint = MucOccupantEndpoint::Suspended(Arc::clone(&suspended));
        let key = crate::xmpp::xml_util::muc_occupant_key(&occupant.room_jid, &occupant.nick);
        let occupants = DashMap::new();
        occupants.insert(key.clone(), occupant.clone());
        let identity = LocalMucOccupantIdentity::from(&occupant);

        let unchanged = set_local_muc_affiliation_exact_in(
            &occupants,
            identity,
            "member",
            true,
            true,
            Some("member"),
        );
        assert!(
            unchanged.is_none(),
            "the expected affiliation is an ABA guard"
        );
        let registered =
            set_local_muc_affiliation_exact_in(&occupants, identity, "member", true, true, None)
                .unwrap();
        assert_eq!(registered.affiliation, "member");
        assert_eq!(registered.role, "participant");
        let still_registered =
            set_local_muc_affiliation_exact_in(&occupants, identity, "owner", true, true, None)
                .unwrap();
        assert_eq!(still_registered.affiliation, "member");
        assert_eq!(still_registered.role, "participant");
        let (policy, changed) =
            refresh_local_muc_policy_exact_in(&occupants, identity, Some(false), Some(false))
                .unwrap();
        assert!(changed);
        assert_eq!(policy.payload, "<show>away</show>");
        assert!(
            matches!(policy.endpoint, MucOccupantEndpoint::Suspended(ref endpoint) if Arc::ptr_eq(endpoint, &suspended))
        );
        assert!(!policy.room_non_anonymous);
        assert!(
            set_local_muc_role_exact_in(&occupants, identity, "visitor", "moderator", None)
                .is_none()
        );
    }

    #[test]
    fn presence_refresh_rejects_reused_or_suspended_transport() {
        let old = test_muc_occupant(
            "alice@example.test/Phone",
            uuid::Uuid::new_v4(),
            uuid::Uuid::new_v4(),
        );
        let mut prepared = old.clone();
        prepared.payload = "<show>chat</show>".to_owned();
        let mut replacement =
            test_muc_occupant(&old.full_jid, uuid::Uuid::new_v4(), uuid::Uuid::new_v4());
        replacement.payload = "<show>away</show>".to_owned();
        let key = crate::xmpp::xml_util::muc_occupant_key(&old.room_jid, &old.nick);
        let occupants = DashMap::new();
        occupants.insert(key.clone(), replacement.clone());
        assert!(refresh_local_muc_presence_exact_in(&occupants, &prepared, true).is_none());
        assert_eq!(occupants.get(&key).unwrap().payload, replacement.payload);

        let mut suspended = old.clone();
        suspended.endpoint = MucOccupantEndpoint::Suspended(Arc::new(SuspendedMucEndpoint::new(
            uuid::Uuid::new_v4(),
        )));
        occupants.insert(key.clone(), suspended);
        assert!(refresh_local_muc_presence_exact_in(&occupants, &prepared, true).is_none());
        assert!(matches!(
            &occupants.get(&key).unwrap().endpoint,
            MucOccupantEndpoint::Suspended(_)
        ));
    }

    #[test]
    fn nickname_move_restores_local_actor_and_defers_cluster_collision() {
        let old = test_muc_occupant(
            "alice@example.test/Phone",
            uuid::Uuid::new_v4(),
            uuid::Uuid::new_v4(),
        );
        let mut renamed = old.clone();
        renamed.nick = "Bob".to_owned();
        let mut other = test_muc_occupant(
            "bob@example.test/Laptop",
            uuid::Uuid::new_v4(),
            uuid::Uuid::new_v4(),
        );
        other.nick = renamed.nick.clone();
        let old_key = crate::xmpp::xml_util::muc_occupant_key(&old.room_jid, &old.nick);
        let new_key = crate::xmpp::xml_util::muc_occupant_key(&renamed.room_jid, &renamed.nick);
        let occupants = DashMap::new();
        occupants.insert(old_key.clone(), old.clone());
        occupants.insert(new_key.clone(), other.clone());

        assert_eq!(
            move_local_muc_nickname_exact_in(
                &occupants,
                LocalMucOccupantIdentity::from(&old),
                &renamed,
                false,
            ),
            LocalMucNicknameMove::CollisionRestored
        );
        assert_eq!(
            occupants.get(&old_key).unwrap().connection_id,
            old.connection_id
        );
        assert_eq!(
            occupants.get(&new_key).unwrap().connection_id,
            other.connection_id
        );

        assert_eq!(
            move_local_muc_nickname_exact_in(
                &occupants,
                LocalMucOccupantIdentity::from(&old),
                &renamed,
                true,
            ),
            LocalMucNicknameMove::DeferredToReconciliation
        );
        assert!(!occupants.contains_key(&old_key));
        assert_eq!(
            occupants.get(&new_key).unwrap().connection_id,
            other.connection_id
        );

        occupants.remove(&new_key);
        assert_eq!(
            move_local_muc_nickname_exact_in(
                &occupants,
                LocalMucOccupantIdentity::from(&old),
                &renamed,
                true,
            ),
            LocalMucNicknameMove::DeferredToReconciliation
        );
        assert!(!occupants.contains_key(&new_key));
        occupants.insert(old_key, old.clone());
        assert_eq!(
            move_local_muc_nickname_exact_in(
                &occupants,
                LocalMucOccupantIdentity::from(&old),
                &renamed,
                false,
            ),
            LocalMucNicknameMove::Published
        );
        assert_eq!(
            occupants.get(&new_key).unwrap().connection_id,
            old.connection_id
        );
    }

    #[test]
    fn delayed_suspended_teardown_cannot_remove_resumed_connection() {
        let sm_session_id = uuid::Uuid::new_v4();
        let old_connection_id = uuid::Uuid::new_v4();
        let new_connection_id = uuid::Uuid::new_v4();
        let cluster_epoch = uuid::Uuid::new_v4();
        let mut current =
            test_muc_occupant("alice@example.test/Phone", old_connection_id, cluster_epoch);
        current.sm_session_id = Some(sm_session_id);
        current.endpoint =
            MucOccupantEndpoint::Suspended(Arc::new(SuspendedMucEndpoint::new(sm_session_id)));
        let stale_teardown = SerializableMucOccupant::from(&current);
        assert!(muc_suspended_teardown_identity_matches(
            &current,
            sm_session_id,
            &stale_teardown,
        ));

        let (sender, _receiver) = tokio::sync::mpsc::channel(1);
        current.endpoint = MucOccupantEndpoint::Local(crate::outbound::OutboundSender::new(sender));
        current.connection_id = new_connection_id;
        assert_eq!(current.cluster_epoch, stale_teardown.cluster_epoch);
        assert!(!muc_suspended_teardown_identity_matches(
            &current,
            sm_session_id,
            &stale_teardown,
        ));
    }

    #[test]
    fn full_session_lookup_is_exact_while_bare_lookup_is_canonical() {
        assert_eq!(
            session_lookup("ALICE@Example.test/Phone"),
            Some(SessionLookup::Full("alice@example.test/Phone".to_owned()))
        );
        assert_eq!(
            session_lookup("alice@example.test/phone"),
            Some(SessionLookup::Full("alice@example.test/phone".to_owned()))
        );
        assert_ne!(
            session_lookup("alice@example.test/Phone"),
            session_lookup("alice@example.test/phone")
        );
        assert_eq!(
            session_lookup("ALICE@Example.test"),
            Some(SessionLookup::Bare("alice@example.test".to_owned()))
        );
        assert_eq!(
            session_lookup("A\u{30a}LICE@B\u{fc}CHER.Example./DeviceA\u{30a}"),
            Some(SessionLookup::Full(
                "\u{e5}lice@b\u{fc}cher.example/Device\u{c5}".to_owned()
            ))
        );
        assert_eq!(session_lookup("alice@example.test/\u{0007}"), None);
        assert_eq!(session_lookup("alice@@example.test/Phone"), None);
    }

    #[test]
    fn cluster_muc_epoch_is_backward_compatible_and_exact() {
        let legacy = serde_json::json!({
            "full_jid": "alice@example.test/Phone",
            "room_jid": "room@conference.example.test",
            "nick": "Alice",
            "affiliation": "member",
            "role": "participant",
            "room_non_anonymous": true,
            "occupant_id": "opaque",
            "payload": ""
        });
        let legacy: SerializableMucOccupant = serde_json::from_value(legacy).unwrap();
        assert_eq!(legacy.sm_session_id, None);
        assert!(legacy.cluster_epoch.is_nil());

        let id = uuid::Uuid::new_v4();
        let current = SerializableMucOccupant {
            sm_session_id: Some(id),
            ..legacy
        };
        let round_trip: SerializableMucOccupant =
            serde_json::from_str(&serde_json::to_string(&current).unwrap()).unwrap();
        assert_eq!(round_trip.sm_session_id, Some(id));
    }

    #[test]
    fn federation_entity_rules_follow_domain_bare_and_full_jid_specificity() {
        let phone = crate::jid::CanonicalJid::parse("alice@remote.example/Phone").unwrap();
        let laptop = crate::jid::CanonicalJid::parse("alice@remote.example/Laptop").unwrap();
        let bob = crate::jid::CanonicalJid::parse("bob@remote.example/Phone").unwrap();
        assert!(federation_rule_matches("remote.example", &phone));
        assert!(federation_rule_matches("alice@remote.example", &phone));
        assert!(federation_rule_matches(
            "alice@remote.example/Phone",
            &phone
        ));
        assert!(!federation_rule_matches(
            "alice@remote.example/Phone",
            &laptop
        ));
        assert!(!federation_rule_matches("alice@remote.example", &bob));
        assert!(!federation_rule_matches("other.example", &phone));
    }

    #[test]
    fn service_control_only_stops_processes_started_before_the_fire_epoch() {
        let fired_at = chrono::Utc::now();
        let control = crate::db::DurableServiceControl {
            generation: uuid::Uuid::new_v4(),
            action: "restart".to_owned(),
            execute_at: fired_at - chrono::Duration::seconds(1),
            fired_at: Some(fired_at),
            expires_at: fired_at + chrono::Duration::minutes(5),
        };
        assert!(service_control_applies(
            fired_at - chrono::Duration::seconds(1),
            &control
        ));
        assert!(!service_control_applies(fired_at, &control));
        assert!(!service_control_applies(
            fired_at + chrono::Duration::seconds(1),
            &control
        ));
        let pending = crate::db::DurableServiceControl {
            fired_at: None,
            ..control
        };
        assert!(!service_control_applies(
            fired_at - chrono::Duration::seconds(1),
            &pending
        ));
    }

    #[test]
    fn api_cursor_rotation_uses_the_shared_api_secret_overlap() {
        use crate::api::cursor::{CursorBinding, CursorDirection, CursorPosition, CursorValue};

        let old_secret = b"old-shared-api-secret-000000000001";
        let current_secret = b"new-shared-api-secret-000000000002";
        let (_old_control, old_cursor) = api_keyrings(old_secret, None).unwrap();
        let binding = CursorBinding {
            endpoint: "admin/users",
            principal_scope: b"admin-account-id",
            filter_scope: b"enabled=true",
            sort: "created_at-id",
            direction: CursorDirection::Forward,
            node_incarnation: uuid::Uuid::nil(),
        };
        let position = CursorPosition {
            last: vec![CursorValue::I64(7)],
        };
        let token = old_cursor.issue(&binding, &position, 1_000, 300).unwrap();

        let (_rotating_control, rotating_cursor) =
            api_keyrings(current_secret, Some(old_secret)).unwrap();
        assert_eq!(
            rotating_cursor.verify(&token, &binding, 1_100).unwrap(),
            position
        );

        let (_current_control, current_cursor) = api_keyrings(current_secret, None).unwrap();
        assert!(current_cursor.verify(&token, &binding, 1_100).is_err());
    }

    #[test]
    fn ephemeral_api_control_secret_is_fixed_lowercase_hex() {
        let secret = ephemeral_api_control_secret();
        assert_eq!(secret.len(), 64);
        assert!(secret
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte)));
        assert!(!secret.contains(&0));
        assert!(api_keyrings(&secret, None).is_ok());
    }

    #[test]
    fn nul_containing_entropy_is_encoded_before_keyring_validation() {
        let mut entropy = [0_u8; 32];
        entropy[1] = 0xff;
        entropy[31] = 0x80;
        assert!(api_keyrings(&entropy, None).is_err());

        let encoded = encode_api_control_entropy(entropy);
        assert_eq!(&encoded[..4], b"00ff");
        assert_eq!(&encoded[62..], b"80");
        assert!(!encoded.contains(&0));
        assert!(api_keyrings(&encoded, None).is_ok());
    }
}
