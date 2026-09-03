use crate::api::*;
use axum::body::Body;
use axum::http::{HeaderMap, StatusCode};
use axum::{
    extract::{ConnectInfo, State, WebSocketUpgrade},
    http::header,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use serde_json::Value;
use sqlx::Row;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};
#[cfg(test)]
use subtle::ConstantTimeEq;
use tokio::sync::{Mutex, Semaphore};

use crate::error::{AppError, Result};
use crate::state::AppState;
use crate::xmpp;

type DatabaseMetricsSnapshot = (
    i64,
    crate::db::S2sOutboxSnapshot,
    crate::db::ApiOperationSnapshot,
    crate::db::AdminSessionCleanupSnapshot,
    (i64, i64, i64),
    crate::db::DataGovernanceSnapshot,
    crate::db::DeploymentCapacitySnapshot,
);

/// Minimal capability set for the private observability listener. Keeping
/// authentication, concurrency control and caching outside `AppState` avoids
/// giving the public API router authority to expose database-backed metrics.
pub struct MetricsEndpointState {
    app: Arc<AppState>,
    gate: Semaphore,
    cache: Mutex<Option<(Instant, String)>>,
}

const READINESS_CACHE_TTL: Duration = Duration::from_secs(2);
const READINESS_GATE_WAIT: Duration = Duration::from_millis(200);
const READINESS_PROBE_TIMEOUT: Duration = Duration::from_millis(1500);
// Cleanup retries cap at a 300-second backoff. Allow one full capped interval
// plus recovery margin, but do not advertise readiness forever when committed
// credential or connection revocations are not converging.
const ADMIN_CLEANUP_MAX_READY_AGE_SECONDS: f64 = 600.0;
const ADMIN_CLEANUP_MAX_READY_ATTEMPTS: i64 = 9;

#[derive(Clone)]
enum ReadinessSnapshot {
    Ready,
    Unavailable(&'static str),
}

/// A bounded readiness capability. It deliberately owns no database pool of
/// its own: one single-flight probe may use the application's authoritative
/// pool, while anonymous duplicates consume only the short cache or fail fast.
pub struct ReadyEndpointState {
    app: Arc<AppState>,
    gate: Semaphore,
    cache: Mutex<Option<(Instant, ReadinessSnapshot)>>,
}

impl ReadyEndpointState {
    pub fn new(app: Arc<AppState>) -> Arc<Self> {
        Arc::new(Self {
            app,
            gate: Semaphore::new(1),
            cache: Mutex::new(None),
        })
    }

    async fn cached(&self) -> Option<ReadinessSnapshot> {
        self.cache
            .lock()
            .await
            .as_ref()
            .filter(|(created, _)| created.elapsed() < READINESS_CACHE_TTL)
            .map(|(_, snapshot)| snapshot.clone())
    }
}

impl MetricsEndpointState {
    pub fn new(app: Arc<AppState>) -> Arc<Self> {
        Arc::new(Self {
            app,
            gate: Semaphore::new(1),
            cache: Mutex::new(None),
        })
    }

    async fn cached(&self) -> Option<String> {
        self.cache
            .lock()
            .await
            .as_ref()
            .filter(|(created, _)| created.elapsed() < Duration::from_secs(5))
            .map(|(_, body)| body.clone())
    }
}

pub async fn health() -> &'static str {
    "ok"
}

const API_DOCS_CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";
const API_DOCS_HTML: &str = r#"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="referrer" content="no-referrer">
  <title>Northstar REST API</title>
  <link rel="icon" type="image/png" sizes="32x32" href="/api/docs/assets/5.32.14/favicon-32x32.png">
  <link rel="stylesheet" href="/api/docs/assets/5.32.14/swagger-ui.css">
</head>
<body>
  <div id="swagger-ui"></div>
  <script src="/api/docs/assets/5.32.14/swagger-ui-bundle.js"></script>
  <script src="/api/docs/assets/5.32.14/northstar-swagger-initializer.js"></script>
</body>
</html>
"#;

/// Serve the exact checked-in OpenAPI contract from the same origin as the
/// API. It is intentionally not generated at runtime, so CI can compare the
/// reviewed contract with the router before a release is built.
pub async fn openapi_document() -> Response {
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/yaml; charset=utf-8")
        .header(header::CACHE_CONTROL, "no-store, max-age=0")
        .header(
            "content-security-policy",
            "default-src 'none'; frame-ancestors 'none'",
        )
        .body(Body::from(include_str!("../../docs/openapi.yaml")))
        .expect("static OpenAPI response is valid")
}

/// Read-only, self-hosted Swagger UI. Submission and authorization controls
/// are disabled in the pinned initializer even for administrators; this keeps
/// bearer tokens out of documentation state and turns the UI into a contract
/// browser rather than an alternate control plane.
pub async fn api_docs() -> Response {
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
        .header(header::CACHE_CONTROL, "no-store, max-age=0")
        .header("content-security-policy", API_DOCS_CSP)
        .body(Body::from(API_DOCS_HTML))
        .expect("static API documentation response is valid")
}

pub async fn ready(
    State(endpoint): State<Arc<ReadyEndpointState>>,
) -> Result<&'static str, AppError> {
    if let Some(error) = current_runtime_readiness_error(&endpoint.app) {
        return Err(AppError::Unavailable(error.into()));
    }
    if let Some(snapshot) = endpoint.cached().await {
        return readiness_response(snapshot);
    }
    let permit = tokio::time::timeout(READINESS_GATE_WAIT, endpoint.gate.acquire())
        .await
        .map_err(|_| AppError::Unavailable("readiness probe is busy".into()))?
        .map_err(|_| AppError::Unavailable("readiness probe is unavailable".into()))?;
    // The cache is deliberately only for database work. Re-check cheap,
    // process-local safety authorities after waiting for the single-flight
    // gate so an old Ready snapshot cannot mask a worker or cluster failure.
    if let Some(error) = current_runtime_readiness_error(&endpoint.app) {
        drop(permit);
        return Err(AppError::Unavailable(error.into()));
    }
    if let Some(snapshot) = endpoint.cached().await {
        drop(permit);
        return readiness_response(snapshot);
    }
    let snapshot = probe_readiness(&endpoint.app).await;
    *endpoint.cache.lock().await = Some((Instant::now(), snapshot.clone()));
    drop(permit);
    readiness_response(snapshot)
}

fn current_runtime_readiness_error(state: &AppState) -> Option<&'static str> {
    if !state.sm_memory_governor().is_ready() {
        return Some("XEP-0198 memory or recovery capacity is not ready");
    }
    if !upload_storage_ready(state.upload_safety_gate().state()) {
        return Some("upload storage authority is not ready");
    }
    if state.cluster.readiness_error().is_some() {
        return Some("cluster policy is not ready");
    }
    if state.worker_registry().readiness_error().is_some() {
        return Some("background workers are not ready");
    }
    None
}

fn readiness_response(snapshot: ReadinessSnapshot) -> Result<&'static str, AppError> {
    match snapshot {
        ReadinessSnapshot::Ready => Ok("ready"),
        ReadinessSnapshot::Unavailable(message) => Err(AppError::Unavailable(message.into())),
    }
}

fn upload_storage_ready(state: crate::services::upload_safety::UploadSafetyState) -> bool {
    matches!(
        state,
        crate::services::upload_safety::UploadSafetyState::Disabled
            | crate::services::upload_safety::UploadSafetyState::Healthy
            | crate::services::upload_safety::UploadSafetyState::RecoveryDraining
    )
}

async fn probe_readiness(state: &AppState) -> ReadinessSnapshot {
    let persistence_probe = async {
        if let Some(identity) = state.abuse_key_deployment() {
            crate::db::validate_abuse_key_deployment(&state.pool, identity).await?;
        } else {
            sqlx::query_scalar::<_, i32>("SELECT 1")
                .fetch_one(&state.pool)
                .await?;
        }
        if let Some(identity) = state.cluster.key_authority_identity() {
            crate::db::validate_cluster_key_deployment(&state.pool, &identity).await?;
            state
                .cluster
                .validate_instance_authority(&state.pool)
                .await?;
        }
        let cleanup = crate::db::admin_session_cleanup_snapshot(&state.pool).await?;
        anyhow::ensure!(
            admin_session_cleanup_ready(&cleanup),
            "administrator session-cleanup authority is inconsistent, full, or not converging"
        );
        Ok::<_, anyhow::Error>(())
    };
    match tokio::time::timeout(READINESS_PROBE_TIMEOUT, persistence_probe).await {
        Ok(Ok(())) => {
            if !state.sm_memory_governor().is_ready() {
                return ReadinessSnapshot::Unavailable(
                    "XEP-0198 memory or recovery capacity is not ready",
                );
            }
            let upload_state = state.upload_safety_gate().state();
            if !upload_storage_ready(upload_state) {
                tracing::warn!(?upload_state, "readiness upload authority probe failed");
                return ReadinessSnapshot::Unavailable("upload storage authority is not ready");
            }
            if let Some(error) = state.cluster.readiness_error() {
                tracing::warn!(%error, "readiness cluster policy probe failed");
                return ReadinessSnapshot::Unavailable("cluster policy is not ready");
            }
            if let Some(error) = state.worker_registry().readiness_error() {
                tracing::warn!(%error, "readiness worker probe failed");
                ReadinessSnapshot::Unavailable("background workers are not ready")
            } else {
                ReadinessSnapshot::Ready
            }
        }
        Ok(Err(error)) => {
            tracing::error!(?error, "readiness persistence authority probe failed");
            ReadinessSnapshot::Unavailable("database or persisted security authority is not ready")
        }
        Err(_) => ReadinessSnapshot::Unavailable("readiness persistence authority probe timed out"),
    }
}

fn admin_session_cleanup_ready(cleanup: &crate::db::AdminSessionCleanupSnapshot) -> bool {
    cleanup.pending >= 0
        && cleanup.running >= 0
        && cleanup.capacity > 0
        && cleanup.queued == cleanup.pending.saturating_add(cleanup.running)
        && cleanup.queued < cleanup.capacity
        && (cleanup.queued == 0
            || (cleanup.oldest_age_seconds <= ADMIN_CLEANUP_MAX_READY_AGE_SECONDS
                && cleanup.maximum_attempts < ADMIN_CLEANUP_MAX_READY_ATTEMPTS))
}

pub async fn metrics(
    State(endpoint): State<Arc<MetricsEndpointState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Response {
    if !metrics_request_authorized(&endpoint.app, peer.ip(), &headers) {
        let mut response = (StatusCode::UNAUTHORIZED, "unauthorized\n").into_response();
        response.headers_mut().insert(
            header::WWW_AUTHENTICATE,
            "Bearer realm=\"northstar-metrics\"".parse().unwrap(),
        );
        return response;
    }
    if let Some(body) = endpoint.cached().await {
        return metrics_response(body);
    }
    let permit =
        match tokio::time::timeout(Duration::from_millis(250), endpoint.gate.acquire()).await {
            Ok(Ok(permit)) => permit,
            _ => return (StatusCode::SERVICE_UNAVAILABLE, "collector busy\n").into_response(),
        };
    if let Some(body) = endpoint.cached().await {
        drop(permit);
        return metrics_response(body);
    }
    let body = collect_metrics(&endpoint.app).await;
    *endpoint.cache.lock().await = Some((Instant::now(), body.clone()));
    drop(permit);
    metrics_response(body)
}

fn metrics_request_authorized(state: &AppState, peer: IpAddr, headers: &HeaderMap) -> bool {
    state.metrics_request_authorized(peer, metrics_bearer_candidate(headers))
}

fn metrics_bearer_candidate(headers: &HeaderMap) -> Option<&str> {
    // Reject duplicate field-lines instead of selecting whichever value
    // HeaderMap happens to return first.  Proxies and origin servers are not
    // guaranteed to make the same choice for a non-list Authorization field;
    // accepting one of several values would therefore create a credential
    // smuggling boundary on the only remotely reachable metrics profile.
    let mut authorizations = headers.get_all(header::AUTHORIZATION).iter();
    let authorization = authorizations.next()?;
    if authorizations.next().is_some() {
        return None;
    }
    let authorization = authorization.to_str().ok()?;
    let mut fields = authorization.split_ascii_whitespace();
    let scheme = fields.next()?;
    let candidate = fields.next()?;
    if !scheme.eq_ignore_ascii_case("Bearer") || fields.next().is_some() {
        return None;
    }
    Some(candidate)
}

#[cfg(test)]
fn metrics_credentials_authorized(
    expected: Option<&str>,
    peer: IpAddr,
    headers: &HeaderMap,
) -> bool {
    let Some(expected) = expected else {
        return peer.is_loopback();
    };
    metrics_bearer_candidate(headers).is_some_and(|candidate| {
        candidate.len() == expected.len()
            && bool::from(candidate.as_bytes().ct_eq(expected.as_bytes()))
    })
}

fn metrics_response(body: String) -> Response {
    (
        [
            (header::CONTENT_TYPE, "text/plain; version=0.0.4"),
            (header::CACHE_CONTROL, "no-store"),
        ],
        body,
    )
        .into_response()
}

async fn collect_metrics(state: &AppState) -> String {
    let ping_started = std::time::Instant::now();
    let database_up = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        sqlx::query_scalar::<_, i32>("SELECT 1").fetch_one(&state.pool),
    )
    .await
    .is_ok_and(|result| result.is_ok());
    let database_ping_duration = ping_started.elapsed();
    state
        .metrics
        .database_operation_duration_seconds
        .observe(database_ping_duration);
    let database_ping_seconds = database_ping_duration.as_secs_f64();
    let component_domains = state.configured_component_domains();
    let collector = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        collect_database_metrics_snapshot(&state.pool, &component_domains),
    )
    .await;
    let collector = match collector {
        Ok(Ok(snapshot)) => Some(snapshot),
        Ok(Err(error)) => {
            tracing::debug!(?error, "database metrics snapshot failed");
            None
        }
        Err(_) => {
            tracing::debug!("database metrics snapshot exceeded its total deadline");
            None
        }
    };
    let tls_material = state.tls.current();
    let tls_not_after = tls_material.leaf_not_after_unix;
    let tls_generation = tls_material.generation;
    let certificate_sessions = state.tls.certificate_session_metrics();
    let now_unix = chrono::Utc::now().timestamp();
    let tls_seconds_remaining = tls_not_after.saturating_sub(now_unix).max(0);
    let cluster = state.cluster.metrics_snapshot();
    let mut body = state.metrics.render();
    body.push_str(&format!(
        concat!(
            "# TYPE xmpp_database_up gauge\n",
            "xmpp_database_up {}\n",
            "# TYPE xmpp_database_ping_duration_seconds gauge\n",
            "xmpp_database_ping_duration_seconds {:.6}\n",
            "# TYPE xmpp_database_pool_connections gauge\n",
            "xmpp_database_pool_connections {}\n",
            "# TYPE xmpp_database_pool_idle_connections gauge\n",
            "xmpp_database_pool_idle_connections {}\n",
            "# TYPE xmpp_database_pool_max_connections gauge\n",
            "xmpp_database_pool_max_connections {}\n",
            "# TYPE xmpp_s2s_outbox_max_rows gauge\n",
            "xmpp_s2s_outbox_max_rows {}\n",
            "# TYPE xmpp_s2s_outbox_max_bytes gauge\n",
            "xmpp_s2s_outbox_max_bytes {}\n",
            "# TYPE xmpp_s2s_outbox_max_per_domain gauge\n",
            "xmpp_s2s_outbox_max_per_domain {}\n",
            "# TYPE xmpp_muc_occupants gauge\n",
            "xmpp_muc_occupants {}\n",
            "# TYPE xmpp_federation_outbound_workers gauge\n",
            "xmpp_federation_outbound_workers {}\n",
            "# TYPE xmpp_uptime_seconds gauge\n",
            "xmpp_uptime_seconds {}\n",
            "# TYPE xmpp_tls_certificate_not_after_seconds gauge\n",
            "xmpp_tls_certificate_not_after_seconds {}\n",
            "# TYPE xmpp_tls_certificate_seconds_until_expiry gauge\n",
            "xmpp_tls_certificate_seconds_until_expiry {}\n",
            "# TYPE xmpp_tls_generation gauge\n",
            "xmpp_tls_generation {}\n",
            "# TYPE xmpp_tls_certificate_authenticated_sessions gauge\n",
            "xmpp_tls_certificate_authenticated_sessions {}\n",
            "# TYPE xmpp_tls_c2s_external_sessions gauge\n",
            "xmpp_tls_c2s_external_sessions {}\n",
            "# TYPE xmpp_tls_inbound_s2s_external_sessions gauge\n",
            "xmpp_tls_inbound_s2s_external_sessions {}\n",
            "# TYPE xmpp_tls_outbound_s2s_external_sessions gauge\n",
            "xmpp_tls_outbound_s2s_external_sessions {}\n",
            "# TYPE xmpp_cluster_operational_state gauge\n",
            "xmpp_cluster_operational_state {}\n",
            "# TYPE xmpp_cluster_listener_generation gauge\n",
            "xmpp_cluster_listener_generation {}\n",
            "# TYPE xmpp_cluster_authentication_failures_total counter\n",
            "xmpp_cluster_authentication_failures_total {}\n",
            "# TYPE xmpp_cluster_replay_rejections_total counter\n",
            "xmpp_cluster_replay_rejections_total {}\n",
            "# TYPE xmpp_cluster_degraded_transitions_total counter\n",
            "xmpp_cluster_degraded_transitions_total {}\n",
            "# TYPE xmpp_cluster_incompatible_peer_versions_total counter\n",
            "xmpp_cluster_incompatible_peer_versions_total {}\n"
        ),
        u8::from(database_up),
        database_ping_seconds,
        state.pool.size(),
        state.pool.num_idle(),
        state.config.database_max_connections,
        state.config.s2s_outbox_max_rows,
        state.config.s2s_outbox_max_bytes,
        state.config.s2s_outbox_max_per_domain,
        state.muc_occupants.len(),
        state.s2s_connection_registry().outbound_count(),
        state.uptime().as_secs(),
        tls_not_after,
        tls_seconds_remaining,
        tls_generation,
        certificate_sessions.active,
        certificate_sessions.c2s_external,
        certificate_sessions.inbound_s2s_external,
        certificate_sessions.outbound_s2s_external,
        cluster.state,
        cluster.listener_generation,
        cluster.authentication_failures,
        cluster.replay_rejections,
        cluster.degraded_transitions,
        cluster.incompatible_peer_versions,
    ));
    body.push_str(&render_password_work_metrics(
        crate::password_work::rejections_total(),
    ));
    body.push_str(&render_database_collector(collector.as_ref()));
    let governor = state.sm_memory_governor();
    let sm_metrics = governor.metrics();
    let recovery = state.sm_suspension_recovery_queue().snapshot();
    body.push_str(&format!(
        concat!(
            "# TYPE xmpp_sm_memory_reserved_bytes gauge\n",
            "xmpp_sm_memory_reserved_bytes {}\n",
            "# TYPE xmpp_sm_memory_limit_bytes gauge\n",
            "xmpp_sm_memory_limit_bytes {}\n",
            "# TYPE xmpp_sm_memory_peak_reserved_bytes gauge\n",
            "xmpp_sm_memory_peak_reserved_bytes {}\n",
            "# TYPE xmpp_sm_capacity_admission_rejections_total counter\n",
            "xmpp_sm_capacity_admission_rejections_total {}\n",
            "# TYPE xmpp_sm_capacity_invariant_failures_total counter\n",
            "xmpp_sm_capacity_invariant_failures_total {}\n",
            "# TYPE xmpp_sm_recovery_queue_jobs gauge\n",
            "xmpp_sm_recovery_queue_jobs {}\n",
            "# TYPE xmpp_sm_recovery_queue_job_limit gauge\n",
            "xmpp_sm_recovery_queue_job_limit {}\n",
            "# TYPE xmpp_sm_recovery_queue_bytes gauge\n",
            "xmpp_sm_recovery_queue_bytes {}\n",
            "# TYPE xmpp_sm_recovery_queue_byte_limit gauge\n",
            "xmpp_sm_recovery_queue_byte_limit {}\n",
            "# TYPE xmpp_sm_recovery_queue_oldest_age_seconds gauge\n",
            "xmpp_sm_recovery_queue_oldest_age_seconds {}\n"
        ),
        sm_metrics
            .reserved_bytes
            .load(std::sync::atomic::Ordering::Relaxed),
        governor.max_bytes(),
        sm_metrics
            .peak_reserved_bytes
            .load(std::sync::atomic::Ordering::Relaxed),
        sm_metrics
            .admission_rejections_total
            .load(std::sync::atomic::Ordering::Relaxed),
        sm_metrics
            .invariant_failures_total
            .load(std::sync::atomic::Ordering::Relaxed),
        recovery.jobs,
        governor.max_recovery_jobs(),
        recovery.bytes,
        governor.max_recovery_bytes(),
        recovery.oldest_age_seconds,
    ));
    body
}

/// Collect every database-backed metric through one read-only transaction.
///
/// Prometheus scrapes must not fan out over the application's shared pool: a
/// seven-way `try_join!` could occupy most or all connections in a deliberately
/// small deployment. PostgreSQL's repeatable-read snapshot also prevents the
/// individual gauges from describing mutually impossible points in time.
async fn collect_database_metrics_snapshot(
    pool: &sqlx::PgPool,
    component_domains: &[String],
) -> anyhow::Result<DatabaseMetricsSnapshot> {
    let mut transaction = pool.begin().await?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        .execute(&mut *transaction)
        .await?;

    let sm_sessions: i64 = sqlx::query_scalar("SELECT northstar_sm_count('active',NULL,NULL,NULL)")
        .fetch_one(&mut *transaction)
        .await?;

    let row = sqlx::query(
        "WITH active AS MATERIALIZED (
            SELECT target_domain, stanza, created_at, next_attempt_at,
                   locked_until, enqueue_sequence
            FROM s2s_outbox
            WHERE expires_at > NOW()
        ), domain_heads AS (
            SELECT DISTINCT ON (target_domain)
                   target_domain, next_attempt_at, locked_until
            FROM active
            ORDER BY target_domain, enqueue_sequence
        )
        SELECT
            (SELECT COUNT(*)::BIGINT FROM active) AS pending_rows,
            (SELECT COALESCE(SUM(octet_length(stanza)), 0)::BIGINT FROM active) AS pending_bytes,
            (SELECT COALESCE(EXTRACT(EPOCH FROM (NOW() - MIN(created_at))), 0)::DOUBLE PRECISION FROM active) AS oldest_age_seconds,
            (SELECT COUNT(*)::BIGINT FROM active WHERE locked_until > NOW()) AS locked_rows,
            (SELECT COUNT(*)::BIGINT FROM active WHERE target_domain = ANY($1::TEXT[])) AS component_pending_rows,
            (SELECT COUNT(*)::BIGINT FROM domain_heads
             WHERE next_attempt_at <= NOW()
               AND (locked_until IS NULL OR locked_until <= NOW())) AS due_rows",
    )
    .bind(component_domains)
    .fetch_one(&mut *transaction)
    .await?;
    let s2s = crate::db::S2sOutboxSnapshot {
        pending_rows: row.try_get("pending_rows")?,
        pending_bytes: row.try_get("pending_bytes")?,
        oldest_age_seconds: row.try_get::<f64, _>("oldest_age_seconds")?.max(0.0),
        due_rows: row.try_get("due_rows")?,
        locked_rows: row.try_get("locked_rows")?,
        component_pending_rows: row.try_get("component_pending_rows")?,
    };

    let row = sqlx::query(
        "SELECT
            COUNT(*) FILTER (WHERE status='pending')::BIGINT AS pending,
            COUNT(*) FILTER (WHERE status='running')::BIGINT AS running,
            COUNT(*) FILTER (WHERE status='indeterminate')::BIGINT AS indeterminate,
            COALESCE(EXTRACT(EPOCH FROM (
                clock_timestamp() - MIN(created_at) FILTER (
                    WHERE status IN ('pending','running')
                )
            )),0)::FLOAT8 AS oldest_active_age_seconds
         FROM api_operation_journal",
    )
    .fetch_one(&mut *transaction)
    .await?;
    let operations = crate::db::ApiOperationSnapshot {
        pending: row.try_get("pending")?,
        running: row.try_get("running")?,
        indeterminate: row.try_get("indeterminate")?,
        oldest_active_age_seconds: row.try_get::<f64, _>("oldest_active_age_seconds")?.max(0.0),
    };

    let row = sqlx::query(
        "SELECT pending,running,oldest_age_seconds,maximum_attempts,queued,capacity
           FROM northstar_admin_session_cleanup_snapshot()",
    )
    .fetch_one(&mut *transaction)
    .await?;
    let cleanup = crate::db::AdminSessionCleanupSnapshot {
        pending: row.try_get("pending")?,
        running: row.try_get("running")?,
        oldest_age_seconds: row.try_get("oldest_age_seconds")?,
        maximum_attempts: row.try_get("maximum_attempts")?,
        queued: row.try_get("queued")?,
        capacity: row.try_get("capacity")?,
    };

    let pending_reports: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM abuse_reports WHERE status IN ('submitted','reviewing')",
    )
    .fetch_one(&mut *transaction)
    .await?;
    let pending_appeals: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM abuse_appeals WHERE status IN ('submitted','reviewing')",
    )
    .fetch_one(&mut *transaction)
    .await?;
    let active_invitations: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM invitation_tokens WHERE revoked_at IS NULL
           AND (expires_at IS NULL OR expires_at > NOW()) AND use_count < max_uses",
    )
    .fetch_one(&mut *transaction)
    .await?;

    let (
        active_holds,
        preserved_offline_records,
        active_export_leases,
        expired_incomplete_export_leases,
    ): (i64, i64, i64, i64) = sqlx::query_as(
        "SELECT
            (SELECT COUNT(*) FROM legal_holds WHERE released_at IS NULL)::BIGINT,
            (SELECT COUNT(*) FROM legal_hold_offline_snapshots)::BIGINT,
            (SELECT COUNT(*) FROM governance_export_leases
              WHERE completed_at IS NULL AND expires_at > clock_timestamp())::BIGINT,
            (SELECT COUNT(*) FROM governance_export_leases
              WHERE completed_at IS NULL AND expires_at <= clock_timestamp())::BIGINT",
    )
    .fetch_one(&mut *transaction)
    .await?;
    let governance = crate::db::DataGovernanceSnapshot {
        active_holds,
        preserved_offline_records,
        active_export_leases,
        expired_incomplete_export_leases,
    };

    let row = sqlx::query(
        "SELECT
            (SELECT configuration_epoch FROM deployment_capacity_limits WHERE singleton) configuration_epoch,
            COALESCE(SUM(used) FILTER (WHERE resource_kind='account'),0)::pg_catalog.int8 accounts_used,
            COALESCE(SUM(capacity) FILTER (WHERE resource_kind='account'),0)::pg_catalog.int8 accounts_limit,
            COALESCE(SUM(used) FILTER (WHERE resource_kind='muc_room'),0)::pg_catalog.int8 muc_rooms_used,
            COALESCE(SUM(capacity) FILTER (WHERE resource_kind='muc_room'),0)::pg_catalog.int8 muc_rooms_limit,
            COALESCE(SUM(used) FILTER (WHERE resource_kind='live_session'),0)::pg_catalog.int8 live_sessions_used,
            COALESCE(SUM(capacity) FILTER (WHERE resource_kind='live_session'),0)::pg_catalog.int8 live_sessions_limit,
            COALESCE(SUM(used) FILTER (WHERE resource_kind='sm_session'),0)::pg_catalog.int8 resumable_sessions_used,
            COALESCE(SUM(capacity) FILTER (WHERE resource_kind='sm_session'),0)::pg_catalog.int8 resumable_sessions_limit,
            (SELECT muc_rooms_per_owner_limit FROM deployment_capacity_limits WHERE singleton) muc_rooms_per_owner_limit,
            (SELECT sessions_per_account_limit FROM deployment_capacity_limits WHERE singleton) sessions_per_account_limit
         FROM deployment_capacity_shards",
    )
    .fetch_one(&mut *transaction)
    .await?;
    let capacity = crate::db::DeploymentCapacitySnapshot {
        configuration_epoch: row.try_get("configuration_epoch")?,
        accounts_used: row.try_get("accounts_used")?,
        accounts_limit: row.try_get("accounts_limit")?,
        muc_rooms_used: row.try_get("muc_rooms_used")?,
        muc_rooms_limit: row.try_get("muc_rooms_limit")?,
        live_sessions_used: row.try_get("live_sessions_used")?,
        live_sessions_limit: row.try_get("live_sessions_limit")?,
        resumable_sessions_used: row.try_get("resumable_sessions_used")?,
        resumable_sessions_limit: row.try_get("resumable_sessions_limit")?,
        muc_rooms_per_owner_limit: row.try_get("muc_rooms_per_owner_limit")?,
        sessions_per_account_limit: row.try_get("sessions_per_account_limit")?,
    };

    transaction.commit().await?;
    Ok((
        sm_sessions,
        s2s,
        operations,
        cleanup,
        (pending_reports, pending_appeals, active_invitations),
        governance,
        capacity,
    ))
}

fn render_password_work_metrics(rejections_total: u64) -> String {
    format!(
        concat!(
            "# HELP xmpp_password_work_rejections_total Password hashing or verification requests rejected by the bounded CPU admission gate.\n",
            "# TYPE xmpp_password_work_rejections_total counter\n",
            "xmpp_password_work_rejections_total {}\n"
        ),
        rejections_total
    )
}

fn render_database_collector(snapshot: Option<&DatabaseMetricsSnapshot>) -> String {
    let mut body = format!(
        "# TYPE xmpp_database_collector_up gauge\nxmpp_database_collector_up {}\n",
        u8::from(snapshot.is_some())
    );
    let Some((
        resumable_sessions,
        outbox,
        operations,
        admin_cleanup,
        moderation,
        governance,
        capacity,
    )) = snapshot
    else {
        return body;
    };
    body.push_str(&format!(
        concat!(
            "# TYPE xmpp_resumable_sessions gauge\n",
            "xmpp_resumable_sessions {}\n",
            "# TYPE xmpp_s2s_outbox_pending_rows gauge\n",
            "xmpp_s2s_outbox_pending_rows {}\n",
            "# TYPE xmpp_s2s_outbox_pending_bytes gauge\n",
            "xmpp_s2s_outbox_pending_bytes {}\n",
            "# TYPE xmpp_s2s_outbox_oldest_age_seconds gauge\n",
            "xmpp_s2s_outbox_oldest_age_seconds {:.6}\n",
            "# TYPE xmpp_s2s_outbox_due_rows gauge\n",
            "xmpp_s2s_outbox_due_rows {}\n",
            "# TYPE xmpp_s2s_outbox_locked_rows gauge\n",
            "xmpp_s2s_outbox_locked_rows {}\n",
            "# TYPE xmpp_component_outbox_pending_rows gauge\n",
            "xmpp_component_outbox_pending_rows {}\n",
            "# TYPE xmpp_api_operations_pending gauge\n",
            "xmpp_api_operations_pending {}\n",
            "# TYPE xmpp_api_operations_running gauge\n",
            "xmpp_api_operations_running {}\n",
            "# TYPE xmpp_api_operations_indeterminate gauge\n",
            "xmpp_api_operations_indeterminate {}\n",
            "# TYPE xmpp_api_operations_oldest_active_age_seconds gauge\n",
            "xmpp_api_operations_oldest_active_age_seconds {:.6}\n",
            "# TYPE xmpp_admin_session_cleanup_pending gauge\n",
            "xmpp_admin_session_cleanup_pending {}\n",
            "# TYPE xmpp_admin_session_cleanup_running gauge\n",
            "xmpp_admin_session_cleanup_running {}\n",
            "# TYPE xmpp_admin_session_cleanup_oldest_age_seconds gauge\n",
            "xmpp_admin_session_cleanup_oldest_age_seconds {:.6}\n",
            "# TYPE xmpp_admin_session_cleanup_maximum_attempts gauge\n",
            "xmpp_admin_session_cleanup_maximum_attempts {}\n",
            "# TYPE xmpp_admin_session_cleanup_capacity_used gauge\n",
            "xmpp_admin_session_cleanup_capacity_used {}\n",
            "# TYPE xmpp_admin_session_cleanup_capacity_limit gauge\n",
            "xmpp_admin_session_cleanup_capacity_limit {}\n",
            "# TYPE xmpp_moderation_pending_reports gauge\n",
            "xmpp_moderation_pending_reports {}\n",
            "# TYPE xmpp_moderation_pending_appeals gauge\n",
            "xmpp_moderation_pending_appeals {}\n",
            "# TYPE xmpp_active_invitation_tokens gauge\n",
            "xmpp_active_invitation_tokens {}\n",
            "# TYPE xmpp_legal_holds_active gauge\n",
            "xmpp_legal_holds_active {}\n",
            "# TYPE xmpp_legal_hold_preserved_offline_records gauge\n",
            "xmpp_legal_hold_preserved_offline_records {}\n",
            "# TYPE xmpp_governance_export_leases_active gauge\n",
            "xmpp_governance_export_leases_active {}\n",
            "# TYPE xmpp_governance_export_leases_expired_incomplete gauge\n",
            "xmpp_governance_export_leases_expired_incomplete {}\n",
            "# TYPE xmpp_capacity_accounts_used gauge\n",
            "xmpp_capacity_accounts_used {}\n",
            "# TYPE xmpp_capacity_accounts_limit gauge\n",
            "xmpp_capacity_accounts_limit {}\n",
            "# TYPE xmpp_capacity_muc_rooms_used gauge\n",
            "xmpp_capacity_muc_rooms_used {}\n",
            "# TYPE xmpp_capacity_muc_rooms_limit gauge\n",
            "xmpp_capacity_muc_rooms_limit {}\n",
            "# TYPE xmpp_capacity_live_sessions_used gauge\n",
            "xmpp_capacity_live_sessions_used {}\n",
            "# TYPE xmpp_capacity_live_sessions_limit gauge\n",
            "xmpp_capacity_live_sessions_limit {}\n",
            "# TYPE xmpp_capacity_resumable_sessions_used gauge\n",
            "xmpp_capacity_resumable_sessions_used {}\n",
            "# TYPE xmpp_capacity_resumable_sessions_limit gauge\n",
            "xmpp_capacity_resumable_sessions_limit {}\n",
            "# TYPE xmpp_capacity_configuration_epoch gauge\n",
            "xmpp_capacity_configuration_epoch {}\n",
            "# TYPE xmpp_capacity_muc_rooms_per_owner_limit gauge\n",
            "xmpp_capacity_muc_rooms_per_owner_limit {}\n",
            "# TYPE xmpp_capacity_sessions_per_account_limit gauge\n",
            "xmpp_capacity_sessions_per_account_limit {}\n"
        ),
        resumable_sessions,
        outbox.pending_rows,
        outbox.pending_bytes,
        outbox.oldest_age_seconds,
        outbox.due_rows,
        outbox.locked_rows,
        outbox.component_pending_rows,
        operations.pending,
        operations.running,
        operations.indeterminate,
        operations.oldest_active_age_seconds,
        admin_cleanup.pending,
        admin_cleanup.running,
        admin_cleanup.oldest_age_seconds,
        admin_cleanup.maximum_attempts,
        admin_cleanup.queued,
        admin_cleanup.capacity,
        moderation.0,
        moderation.1,
        moderation.2,
        governance.active_holds,
        governance.preserved_offline_records,
        governance.active_export_leases,
        governance.expired_incomplete_export_leases,
        capacity.accounts_used,
        capacity.accounts_limit,
        capacity.muc_rooms_used,
        capacity.muc_rooms_limit,
        capacity.live_sessions_used,
        capacity.live_sessions_limit,
        capacity.resumable_sessions_used,
        capacity.resumable_sessions_limit,
        capacity.configuration_epoch,
        capacity.muc_rooms_per_owner_limit,
        capacity.sessions_per_account_limit,
    ));
    body
}

pub async fn websocket(
    ws: WebSocketUpgrade,
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Response {
    if !secure_websocket_request(
        peer.ip(),
        &headers,
        &state.config.trusted_proxy_ips,
        &state.config.public_url,
    ) {
        return (
            axum::http::StatusCode::BAD_REQUEST,
            "the XMPP WebSocket endpoint requires a secure WSS transport",
        )
            .into_response();
    }
    if !allowed_websocket_origin(
        &headers,
        &state.config.public_url,
        &state.config.websocket_allowed_origins,
    ) {
        return (
            axum::http::StatusCode::FORBIDDEN,
            "the WebSocket Origin is not permitted",
        )
            .into_response();
    }
    if !offers_xmpp_subprotocol(&headers) {
        return (
            axum::http::StatusCode::BAD_REQUEST,
            "the xmpp WebSocket subprotocol is required",
        )
            .into_response();
    }
    let peer_ip = client_ip(peer.ip(), &headers, &state);
    let Some(connection_guard) = state.acquire_client_connection(peer_ip) else {
        return axum::http::StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    ws.protocols(["xmpp"])
        .max_message_size(1024 * 1024)
        .max_frame_size(1024 * 1024)
        .on_upgrade(move |socket| async move {
            let actors = state.connection_actors().clone();
            let actor_shutdown = actors.shutdown_token().child_token();
            let result = actors.try_spawn(
                crate::connection_actors::ConnectionActorKind::C2sWebSocket,
                Some(peer_ip.to_string()),
                async move {
                    let _connection_guard = connection_guard;
                    xmpp::websocket_connection(socket, state, peer_ip, actor_shutdown).await;
                },
            );
            if let Err(error) = result {
                tracing::debug!(%peer_ip, ?error, "rejected WebSocket connection actor admission");
            }
        })
}

fn secure_websocket_request(
    peer_ip: IpAddr,
    headers: &HeaderMap,
    trusted: &[IpAddr],
    public_url: &str,
) -> bool {
    let mut forwarded = headers.get_all("x-forwarded-proto").iter();
    match (forwarded.next(), forwarded.next()) {
        (None, None) => {
            // Plain `ws://` is a development-only exception. Tying it to an
            // explicitly loopback PUBLIC_URL prevents a production reverse
            // proxy that forgot X-Forwarded-Proto from silently downgrading
            // every external XMPP login to a transport the protocol treats
            // as encrypted.
            peer_ip.is_loopback() && development_loopback_url(public_url)
        }
        (Some(value), None) => {
            trusted.contains(&peer_ip)
                && value.to_str().ok().is_some_and(|value| {
                    !value.contains(',') && value.trim().eq_ignore_ascii_case("https")
                })
        }
        _ => false,
    }
}

fn development_loopback_url(public_url: &str) -> bool {
    let Ok(uri) = public_url.parse::<axum::http::Uri>() else {
        return false;
    };
    uri.scheme_str()
        .is_some_and(|scheme| scheme.eq_ignore_ascii_case("http"))
        && uri
            .authority()
            .is_some_and(|authority| origin_host_is_loopback(authority.host()))
}

fn allowed_websocket_origin(
    headers: &HeaderMap,
    public_url: &str,
    configured_origins: &[String],
) -> bool {
    let mut origins = headers.get_all(header::ORIGIN).iter();
    let origin = match (origins.next(), origins.next()) {
        (None, None) => return true,
        (Some(origin), None) => match origin.to_str() {
            Ok(origin) if !origin.contains(',') && origin.len() <= 2_048 => origin,
            _ => return false,
        },
        _ => return false,
    };
    let Some(origin) = crate::config::canonical_web_origin(origin) else {
        return false;
    };
    crate::config::canonical_public_web_origin(public_url).as_ref() == Some(&origin)
        || configured_origins
            .iter()
            .any(|configured| configured == &origin)
}

fn origin_host_is_loopback(host: &str) -> bool {
    let host = host
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
        .unwrap_or(host);
    host.eq_ignore_ascii_case("localhost")
        || host
            .strip_suffix(".localhost")
            .is_some_and(|prefix| !prefix.is_empty())
        || host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
}

fn offers_xmpp_subprotocol(headers: &HeaderMap) -> bool {
    headers
        .get_all(header::SEC_WEBSOCKET_PROTOCOL)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .any(|protocol| protocol.trim() == "xmpp")
}

pub async fn public_config(State(state): State<Arc<AppState>>) -> Json<Value> {
    let registration_mode = state.registration_mode();
    let open_registration = registration_mode != crate::config::RegistrationMode::Closed;
    let registration_mode = match registration_mode {
        crate::config::RegistrationMode::Closed => "closed",
        crate::config::RegistrationMode::Open => "open",
        crate::config::RegistrationMode::InvitationOnly => "invitation",
    };
    let federation_enabled = state.config.federation_enabled && !state.island_mode_enabled();
    Json(json!({
        "domain":state.config.domain,
        "public_url":state.config.public_url,
        "open_registration":open_registration,
        "invitation_required":state.registration_requires_invitation(),
        "registration_mode":registration_mode,
        "registration_dependency_locked":state.registration_opening_is_dependency_locked(),
        "archive_policy":if state.config.require_encrypted_archive {"encrypted_only"} else {"all"},
        "websocket_path":state.config.websocket_enabled.then_some("/xmpp-websocket")
        ,"bosh_path":(state.config.bosh_enabled && state.config.public_url.starts_with("https://")).then_some("/http-bind")
        ,"upload_max_bytes":state.config.upload_mode.admits_new_uploads().then_some(state.config.upload_max_bytes)
        ,"upload_download_max_bytes":state.config.upload_mode.keeps_storage_runtime().then_some(state.config.upload_download_max_bytes)
        ,"upload_service":state.config.upload_mode.admits_new_uploads().then(||format!("upload.{}",state.config.domain))
        ,"muc_service":format!("conference.{}",state.config.domain)
        ,"federation_enabled":federation_enabled
        ,"pow_max_work_factor":state.config.pow_max_work_factor
        ,"pow_approximate_max_device_seconds":state.config.pow_max_device_seconds
        ,"capabilities":{
            "rest_api":state.config.rest_api_enabled,
            "websocket":state.config.websocket_enabled,
            "bosh":state.config.bosh_enabled,
            "web_client":state.config.web_client_enabled,
            "web_administration":state.config.web_admin_enabled,
            "invitation_registration":state.config.web_client_enabled,
            "upload_admission":state.config.upload_mode.admits_new_uploads(),
            "upload_download":state.config.upload_mode.keeps_storage_runtime(),
            "upload_mode":match state.config.upload_mode {
                crate::config::UploadMode::Enabled => "enabled",
                crate::config::UploadMode::DrainReadOnly => "drain_read_only",
                crate::config::UploadMode::Disabled => "disabled",
            }
        }
    }))
}

pub async fn host_meta_xml(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let origin = request_base_url(
        peer.ip(),
        &headers,
        &state.config.trusted_proxy_ips,
        &state.config.domain,
        &state.config.public_url,
    );
    let ws_href = state
        .config
        .websocket_enabled
        .then(|| secure_websocket_url(&origin));
    let bosh_href = advertised_bosh_url(state.config.bosh_enabled, &state.config.public_url);

    let bosh_link = bosh_href.as_deref().map_or_else(String::new, |href| {
        format!(
            "\x20\x20<Link rel=\"urn:xmpp:alt-connections:xbosh\" href=\"{}\" />\n",
            crate::state::attr_escape(href)
        )
    });
    let websocket_link = ws_href.as_deref().map_or_else(String::new, |href| {
        format!(
            "\x20\x20<Link rel=\"urn:xmpp:alt-connections:websocket\" href=\"{}\" />\n",
            crate::state::attr_escape(href)
        )
    });
    let xml = format!(
        "<?xml version='1.0' encoding='utf-8'?>\n\
         <XRD xmlns='http://docs.oasis-open.org/ns/xri/xrd-1.0'>\n\
         {}{}\
         </XRD>",
        websocket_link, bosh_link,
    );

    (
        [
            (header::CONTENT_TYPE, "application/xrd+xml"),
            (header::ACCESS_CONTROL_ALLOW_ORIGIN, "*"),
            (header::CACHE_CONTROL, "public, max-age=300"),
        ],
        xml,
    )
}

pub async fn host_meta_json(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let origin = request_base_url(
        peer.ip(),
        &headers,
        &state.config.trusted_proxy_ips,
        &state.config.domain,
        &state.config.public_url,
    );
    let ws_href = state
        .config
        .websocket_enabled
        .then(|| secure_websocket_url(&origin));
    let bosh_href = advertised_bosh_url(state.config.bosh_enabled, &state.config.public_url);
    let federation_enabled = state.config.federation_enabled && !state.island_mode_enabled();
    let json_body = host_meta_json_document(
        ws_href.as_deref(),
        bosh_href.as_deref(),
        &state.config.domain,
        &state.config.xep_0487_ips,
        state.config.xep_0487_ttl_seconds,
        state.config.xep_0487_priority,
        state.config.xep_0487_weight,
        state.config.xmpps_bind.port(),
        federation_enabled.then_some(state.config.s2s_tls_bind.port()),
    );
    let cache_control = header::HeaderValue::from_str(&format!(
        "public, max-age={}",
        if state.config.xep_0487_ips.is_empty() {
            300
        } else {
            state.config.xep_0487_ttl_seconds
        }
    ))
    .expect("validated XEP-0487 TTL always forms a valid header");

    (
        [
            (
                header::CONTENT_TYPE,
                header::HeaderValue::from_static("application/jrd+json"),
            ),
            (
                header::ACCESS_CONTROL_ALLOW_ORIGIN,
                header::HeaderValue::from_static("*"),
            ),
            (header::CACHE_CONTROL, cache_control),
        ],
        Json(json_body),
    )
}

#[allow(clippy::too_many_arguments)]
fn host_meta_json_document(
    ws_href: Option<&str>,
    bosh_href: Option<&str>,
    domain: &str,
    ips: &[IpAddr],
    ttl_seconds: u64,
    priority: u16,
    weight: u16,
    c2s_tls_port: u16,
    s2s_tls_port: Option<u16>,
) -> Value {
    if ips.is_empty() {
        let mut links = Vec::new();
        if let Some(ws_href) = ws_href {
            links.push(json!({
                "rel": "urn:xmpp:alt-connections:websocket",
                "href": ws_href
            }));
        }
        if let Some(bosh_href) = bosh_href {
            links.push(json!({
                "rel": "urn:xmpp:alt-connections:xbosh",
                "href": bosh_href
            }));
        }
        return json!({ "links": links });
    }

    let ips = ips.iter().map(ToString::to_string).collect::<Vec<_>>();
    let mut links = Vec::new();
    if let Some(ws_href) = ws_href {
        links.push(json!({
            "rel": "urn:xmpp:alt-connections:websocket",
            "href": ws_href,
            "ips": &ips,
            "priority": priority,
            "weight": weight,
            "sni": domain
        }));
    }
    if let Some(bosh_href) = bosh_href {
        links.push(json!({
            "rel": "urn:xmpp:alt-connections:xbosh",
            "href": bosh_href,
            "ips": &ips,
            "priority": priority,
            "weight": weight,
            "sni": domain
        }));
    }
    if c2s_tls_port != 0 {
        links.push(json!({
            "rel": "urn:xmpp:alt-connections:tls",
            "port": c2s_tls_port,
            "ips": &ips,
            "priority": priority,
            "weight": weight,
            "sni": domain
        }));
    }
    if let Some(port) = s2s_tls_port.filter(|port| *port != 0) {
        links.push(json!({
            "rel": "urn:xmpp:alt-connections:s2s-tls",
            "port": port,
            "ips": &ips,
            "priority": priority,
            "weight": weight,
            "sni": domain
        }));
    }
    json!({
        "xmpp": { "ttl": ttl_seconds },
        "links": links
    })
}

fn secure_websocket_url(origin: &str) -> String {
    let authority = origin
        .strip_prefix("https://")
        .or_else(|| origin.strip_prefix("http://"))
        .unwrap_or(origin)
        .trim_end_matches('/');
    format!("wss://{authority}/xmpp-websocket")
}

fn advertised_bosh_url(enabled: bool, public_url: &str) -> Option<String> {
    (enabled && public_url.starts_with("https://"))
        .then(|| format!("{}/http-bind", public_url.trim_end_matches('/')))
}

fn request_base_url(
    peer_ip: IpAddr,
    headers: &HeaderMap,
    trusted_proxy_ips: &[IpAddr],
    domain: &str,
    public_url: &str,
) -> String {
    let is_trusted = trusted_proxy_ips.contains(&peer_ip);

    let host = if is_trusted {
        headers
            .get("x-forwarded-host")
            .and_then(|h| h.to_str().ok())
            .or_else(|| headers.get(header::HOST).and_then(|h| h.to_str().ok()))
    } else {
        headers.get(header::HOST).and_then(|h| h.to_str().ok())
    };

    let forwarded_scheme = if is_trusted {
        headers
            .get("x-forwarded-proto")
            .and_then(|h| h.to_str().ok())
            .or_else(|| {
                headers
                    .get("x-forwarded-scheme")
                    .and_then(|h| h.to_str().ok())
            })
            .unwrap_or("https")
    } else {
        "https"
    };
    let scheme = match forwarded_scheme {
        "http" | "https" => forwarded_scheme,
        _ => "https",
    };

    if let Some(host) = host {
        if let Ok(authority) = axum::http::uri::Authority::from_str(host) {
            let host_name = authority.host();
            if is_trusted
                || host_name.eq_ignore_ascii_case(domain)
                || host_name.eq_ignore_ascii_case("localhost")
            {
                return format!("{scheme}://{authority}");
            }
        }
    }

    public_url.to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn readiness_snapshots_are_typed_and_the_probe_budget_is_short() {
        assert!(readiness_response(ReadinessSnapshot::Ready).is_ok());
        assert!(readiness_response(ReadinessSnapshot::Unavailable("not ready")).is_err());
        assert!(READINESS_CACHE_TTL <= Duration::from_secs(2));
        assert!(READINESS_GATE_WAIT < READINESS_PROBE_TIMEOUT);
        assert!(READINESS_PROBE_TIMEOUT < Duration::from_secs(2));
    }

    #[test]
    fn readiness_checks_runtime_authorities_before_reusing_the_database_cache() {
        let source = include_str!("system.rs");
        let ready = source
            .split("pub async fn ready(")
            .nth(1)
            .expect("ready handler exists")
            .split("fn current_runtime_readiness_error")
            .next()
            .expect("runtime readiness helper follows ready handler");
        let first_runtime_check = ready
            .find("current_runtime_readiness_error(&endpoint.app)")
            .expect("ready handler checks current runtime health");
        let first_cache_read = ready
            .find("endpoint.cached().await")
            .expect("ready handler uses its database cache");
        assert!(first_runtime_check < first_cache_read);
        assert_eq!(
            ready
                .matches("current_runtime_readiness_error(&endpoint.app)")
                .count(),
            2,
            "runtime health must be checked both before and after waiting for the gate"
        );
    }

    #[test]
    fn database_metrics_use_one_read_only_transaction_without_pool_fanout() {
        let source = include_str!("system.rs");
        let collector = source
            .split("async fn collect_database_metrics_snapshot(")
            .nth(1)
            .expect("database metrics collector exists")
            .split("fn render_password_work_metrics")
            .next()
            .expect("collector precedes metric rendering");
        assert_eq!(collector.matches("pool.begin().await?").count(), 1);
        assert!(collector.contains("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY"));
        assert!(!collector.contains("tokio::try_join!"));
        assert!(collector.contains("transaction.commit().await?"));
        assert!(collector.matches("&mut *transaction").count() >= 8);
    }

    #[test]
    fn upload_readiness_is_fail_closed_but_allows_bounded_recovery_drain() {
        use crate::services::upload_safety::UploadSafetyState;

        assert!(upload_storage_ready(UploadSafetyState::Disabled));
        assert!(upload_storage_ready(UploadSafetyState::Healthy));
        assert!(upload_storage_ready(UploadSafetyState::RecoveryDraining));
        for unsafe_state in [
            UploadSafetyState::Unproven,
            UploadSafetyState::NamespaceUnsafe,
            UploadSafetyState::CapacityAuthorityUnsafe,
            UploadSafetyState::LedgerMismatch,
        ] {
            assert!(!upload_storage_ready(unsafe_state));
        }
    }

    #[test]
    fn admin_cleanup_readiness_requires_capacity_and_convergence() {
        let healthy = crate::db::AdminSessionCleanupSnapshot {
            pending: 1,
            running: 0,
            oldest_age_seconds: ADMIN_CLEANUP_MAX_READY_AGE_SECONDS,
            maximum_attempts: ADMIN_CLEANUP_MAX_READY_ATTEMPTS - 1,
            queued: 1,
            capacity: 100_000,
        };
        assert!(admin_session_cleanup_ready(&healthy));

        assert!(!admin_session_cleanup_ready(
            &crate::db::AdminSessionCleanupSnapshot {
                oldest_age_seconds: ADMIN_CLEANUP_MAX_READY_AGE_SECONDS + 0.001,
                ..healthy
            }
        ));
        assert!(!admin_session_cleanup_ready(
            &crate::db::AdminSessionCleanupSnapshot {
                maximum_attempts: ADMIN_CLEANUP_MAX_READY_ATTEMPTS,
                ..healthy
            }
        ));
        assert!(!admin_session_cleanup_ready(
            &crate::db::AdminSessionCleanupSnapshot {
                pending: 100_000,
                queued: 100_000,
                ..healthy
            }
        ));
        assert!(!admin_session_cleanup_ready(
            &crate::db::AdminSessionCleanupSnapshot {
                running: 1,
                ..healthy
            }
        ));
        assert!(admin_session_cleanup_ready(
            &crate::db::AdminSessionCleanupSnapshot {
                pending: 0,
                oldest_age_seconds: 0.0,
                maximum_attempts: 0,
                queued: 0,
                ..healthy
            }
        ));
    }

    #[test]
    fn default_reverse_proxy_does_not_publish_database_readiness() {
        let caddy = include_str!("../../deploy/Caddyfile");
        assert!(caddy.contains("@private_observability path /metrics /readyz"));
        assert!(caddy.contains("respond @private_observability 404"));
    }

    #[tokio::test]
    async fn api_documentation_is_same_origin_read_only_and_strictly_isolated() {
        let response = api_docs().await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(header::CACHE_CONTROL).unwrap(),
            "no-store, max-age=0"
        );
        let csp = response
            .headers()
            .get("content-security-policy")
            .unwrap()
            .to_str()
            .unwrap();
        for required in [
            "default-src 'none'",
            "script-src 'self'",
            "connect-src 'self'",
            "object-src 'none'",
            "form-action 'none'",
            "frame-ancestors 'none'",
        ] {
            assert!(csp.contains(required), "documentation CSP lost {required}");
        }
        assert!(!csp.contains("unsafe-inline"));
        assert!(!csp.contains("unsafe-eval"));
        let body = axum::body::to_bytes(response.into_body(), 32 * 1024)
            .await
            .unwrap();
        let body = std::str::from_utf8(&body).unwrap();
        assert!(body.contains("/api/docs/assets/5.32.14/swagger-ui-bundle.js"));
        assert!(body.contains("/api/docs/assets/5.32.14/swagger-ui.css"));
        assert!(body.contains("northstar-swagger-initializer.js"));
        assert!(!body.contains("http://"));
        assert!(!body.contains("https://"));
        assert!(!body.contains("localStorage"));

        let response = openapi_document().await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE).unwrap(),
            "application/yaml; charset=utf-8"
        );
        let body = axum::body::to_bytes(response.into_body(), 2 * 1024 * 1024)
            .await
            .unwrap();
        assert_eq!(body.as_ref(), include_bytes!("../../docs/openapi.yaml"));
    }

    #[test]
    fn metrics_require_loopback_or_the_exact_constant_time_bearer_boundary() {
        let loopback: IpAddr = "127.0.0.1".parse().unwrap();
        let public: IpAddr = "192.0.2.10".parse().unwrap();
        let empty = HeaderMap::new();
        assert!(metrics_credentials_authorized(None, loopback, &empty));
        assert!(!metrics_credentials_authorized(None, public, &empty));

        let token = "0123456789abcdef0123456789abcdef";
        assert!(!metrics_credentials_authorized(
            Some(token),
            loopback,
            &empty
        ));
        for value in [
            token,
            "0123456789abcdef0123456789abcdee",
            "0123456789abcdef0123456789abcdef0",
        ] {
            let mut headers = HeaderMap::new();
            headers.insert(
                header::AUTHORIZATION,
                format!("Bearer {value}").parse().unwrap(),
            );
            assert_eq!(
                metrics_credentials_authorized(Some(token), public, &headers),
                value == token
            );
        }

        let mut mixed_case = HeaderMap::new();
        mixed_case.insert(
            header::AUTHORIZATION,
            format!("bEaReR {token}").parse().unwrap(),
        );
        assert!(metrics_credentials_authorized(
            Some(token),
            public,
            &mixed_case
        ));

        let mut duplicate = HeaderMap::new();
        duplicate.append(
            header::AUTHORIZATION,
            format!("Bearer {token}").parse().unwrap(),
        );
        duplicate.append(
            header::AUTHORIZATION,
            format!("Bearer {token}").parse().unwrap(),
        );
        assert!(!metrics_credentials_authorized(
            Some(token),
            public,
            &duplicate
        ));

        let mut extra_field = HeaderMap::new();
        extra_field.insert(
            header::AUTHORIZATION,
            format!("Bearer {token} ignored").parse().unwrap(),
        );
        assert!(!metrics_credentials_authorized(
            Some(token),
            public,
            &extra_field
        ));
    }

    #[test]
    fn websocket_requires_the_exact_xmpp_subprotocol_token() {
        let mut headers = HeaderMap::new();
        headers.append(
            header::SEC_WEBSOCKET_PROTOCOL,
            "chat, xmpp".parse().unwrap(),
        );
        assert!(offers_xmpp_subprotocol(&headers));

        for value in ["", "chat", "XMPP", "xmpp2", "not-xmpp"] {
            let mut headers = HeaderMap::new();
            if !value.is_empty() {
                headers.insert(header::SEC_WEBSOCKET_PROTOCOL, value.parse().unwrap());
            }
            assert!(!offers_xmpp_subprotocol(&headers), "accepted {value:?}");
        }
    }

    #[test]
    fn websocket_requires_wss_except_for_direct_loopback_development() {
        let loopback: IpAddr = "127.0.0.1".parse().unwrap();
        let proxy: IpAddr = "10.0.0.2".parse().unwrap();
        let public: IpAddr = "192.0.2.1".parse().unwrap();
        assert!(secure_websocket_request(
            loopback,
            &HeaderMap::new(),
            &[],
            "http://localhost:8080"
        ));
        assert!(!secure_websocket_request(
            loopback,
            &HeaderMap::new(),
            &[],
            "https://chat.example"
        ));
        assert!(!secure_websocket_request(
            public,
            &HeaderMap::new(),
            &[],
            "http://localhost:8080"
        ));

        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-proto", "https".parse().unwrap());
        assert!(secure_websocket_request(
            proxy,
            &headers,
            &[proxy],
            "https://chat.example"
        ));
        assert!(!secure_websocket_request(
            public,
            &headers,
            &[proxy],
            "https://chat.example"
        ));
        headers.insert("x-forwarded-proto", "http".parse().unwrap());
        assert!(!secure_websocket_request(
            proxy,
            &headers,
            &[proxy],
            "https://chat.example"
        ));
        headers.insert("x-forwarded-proto", "https,http".parse().unwrap());
        assert!(!secure_websocket_request(
            proxy,
            &headers,
            &[proxy],
            "https://chat.example"
        ));
    }

    #[test]
    fn websocket_origin_policy_accepts_native_and_secure_web_clients() {
        assert!(allowed_websocket_origin(
            &HeaderMap::new(),
            "https://chat.example",
            &[]
        ));
        for (origin, public_url, configured) in [
            (
                "https://chat.example",
                "https://chat.example/client",
                &[][..],
            ),
            ("https://chat.example:443", "https://chat.example", &[][..]),
            (
                "https://web.example:8443",
                "https://chat.example",
                &["https://web.example:8443".to_owned()][..],
            ),
            ("http://localhost:18080", "http://localhost:18080", &[][..]),
            ("http://127.0.0.1:18080", "http://127.0.0.1:18080", &[][..]),
            ("http://[::1]:18080", "http://[::1]:18080", &[][..]),
        ] {
            let mut headers = HeaderMap::new();
            headers.insert(header::ORIGIN, origin.parse().unwrap());
            assert!(
                allowed_websocket_origin(&headers, public_url, configured),
                "rejected {origin}"
            );
        }
    }

    #[test]
    fn websocket_origin_policy_rejects_opaque_insecure_or_ambiguous_origins() {
        for origin in [
            "null",
            "http://example.org",
            "ftp://example.org",
            "https://user@example.org",
            "https://example.org/path",
            "https://example.org?query",
            "https://example.org:99999",
            "https://example.org, https://evil.example",
            "https://evil.example",
            "https://chat.example:8443",
        ] {
            let mut headers = HeaderMap::new();
            headers.insert(header::ORIGIN, origin.parse().unwrap());
            assert!(
                !allowed_websocket_origin(&headers, "https://chat.example", &[]),
                "accepted {origin}"
            );
        }
        let mut headers = HeaderMap::new();
        headers.append(header::ORIGIN, "https://one.example".parse().unwrap());
        headers.append(header::ORIGIN, "https://two.example".parse().unwrap());
        assert!(!allowed_websocket_origin(
            &headers,
            "https://one.example",
            &[]
        ));
    }
    use std::str::FromStr;

    #[test]
    fn test_request_base_url_untrusted_ip() {
        let mut headers = HeaderMap::new();
        headers.insert(header::HOST, "evil.com".parse().unwrap());
        headers.insert("x-forwarded-host", "example.com".parse().unwrap());

        let url = request_base_url(
            IpAddr::from_str("192.168.1.1").unwrap(),
            &headers,
            &[IpAddr::from_str("10.0.0.1").unwrap()],
            "example.com",
            "https://example.com:8443",
        );
        // Untrusted IP with evil.com Host should fallback to public_url
        assert_eq!(url, "https://example.com:8443");
    }

    #[test]
    fn test_request_base_url_untrusted_ip_matching_domain() {
        let mut headers = HeaderMap::new();
        headers.insert(header::HOST, "example.com:443".parse().unwrap());

        let url = request_base_url(
            IpAddr::from_str("192.168.1.1").unwrap(),
            &headers,
            &[IpAddr::from_str("10.0.0.1").unwrap()],
            "example.com",
            "https://example.com",
        );
        // Untrusted IP but Host matches domain, so allowed.
        assert_eq!(url, "https://example.com:443");
    }

    #[test]
    fn test_request_base_url_trusted_ip() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-host", "api.example.com".parse().unwrap());
        headers.insert("x-forwarded-proto", "http".parse().unwrap());

        let url = request_base_url(
            IpAddr::from_str("10.0.0.1").unwrap(),
            &headers,
            &[IpAddr::from_str("10.0.0.1").unwrap()],
            "example.com",
            "https://example.com",
        );
        // Trusted IP gets to use x-forwarded-*
        assert_eq!(url, "http://api.example.com");
    }

    #[test]
    fn rejects_untrusted_ipv6_confusion_and_forwarded_scheme_injection() {
        let mut headers = HeaderMap::new();
        headers.insert(header::HOST, "example.com.evil:443".parse().unwrap());
        headers.insert("x-forwarded-proto", "javascript".parse().unwrap());
        let url = request_base_url(
            IpAddr::from_str("192.0.2.1").unwrap(),
            &headers,
            &[],
            "example.com",
            "https://example.com",
        );
        assert_eq!(url, "https://example.com");
    }

    #[test]
    fn xep_0156_always_advertises_a_secure_websocket_url() {
        assert_eq!(
            secure_websocket_url("http://localhost:18080"),
            "wss://localhost:18080/xmpp-websocket"
        );
    }

    #[test]
    fn xep_0156_bosh_is_advertised_only_when_enabled_over_https() {
        assert_eq!(advertised_bosh_url(false, "https://example.org"), None);
        assert_eq!(advertised_bosh_url(true, "http://example.org"), None);
        assert_eq!(
            advertised_bosh_url(true, "https://example.org/"),
            Some("https://example.org/http-bind".to_owned())
        );
    }

    #[test]
    fn xep_0487_is_only_asserted_with_explicit_public_ips() {
        let legacy = host_meta_json_document(
            Some("wss://example.org/xmpp-websocket"),
            None,
            "example.org",
            &[],
            300,
            10,
            50,
            5223,
            Some(5270),
        );
        assert!(legacy.get("xmpp").is_none());
        assert_eq!(legacy["links"].as_array().unwrap().len(), 1);

        let with_bosh = host_meta_json_document(
            Some("wss://example.org/xmpp-websocket"),
            Some("https://example.org/http-bind"),
            "example.org",
            &[],
            300,
            10,
            50,
            5223,
            Some(5270),
        );
        assert_eq!(with_bosh["links"].as_array().unwrap().len(), 2);
        assert_eq!(
            with_bosh["links"][1]["rel"],
            "urn:xmpp:alt-connections:xbosh"
        );

        let direct_tls_only = host_meta_json_document(
            None,
            None,
            "example.org",
            &["192.0.2.10".parse().unwrap()],
            300,
            10,
            50,
            5223,
            Some(5270),
        );
        assert_eq!(direct_tls_only["links"].as_array().unwrap().len(), 2);
        assert_eq!(
            direct_tls_only["links"][0]["rel"],
            "urn:xmpp:alt-connections:tls"
        );

        let modern = host_meta_json_document(
            Some("wss://example.org/xmpp-websocket"),
            None,
            "example.org",
            &[
                "192.0.2.10".parse().unwrap(),
                "2001:db8::10".parse().unwrap(),
            ],
            600,
            10,
            50,
            5223,
            Some(5270),
        );
        assert_eq!(modern["xmpp"]["ttl"], 600);
        let links = modern["links"].as_array().unwrap();
        assert_eq!(links.len(), 3);
        for link in links {
            assert_eq!(link["sni"], "example.org");
            assert_eq!(link["priority"], 10);
            assert_eq!(link["weight"], 50);
            assert_eq!(link["ips"].as_array().unwrap().len(), 2);
        }
        assert_eq!(links[1]["port"], 5223);
        assert_eq!(links[2]["port"], 5270);
    }

    #[test]
    fn failed_database_collector_does_not_publish_plausible_zeroes() {
        let failed = render_database_collector(None);
        assert!(failed.contains("xmpp_database_collector_up 0\n"));
        for absent in [
            "xmpp_resumable_sessions ",
            "xmpp_s2s_outbox_pending_rows ",
            "xmpp_s2s_outbox_pending_bytes ",
            "xmpp_s2s_outbox_oldest_age_seconds ",
            "xmpp_s2s_outbox_due_rows ",
            "xmpp_s2s_outbox_locked_rows ",
            "xmpp_component_outbox_pending_rows ",
            "xmpp_api_operations_pending ",
            "xmpp_api_operations_running ",
            "xmpp_api_operations_indeterminate ",
            "xmpp_api_operations_oldest_active_age_seconds ",
            "xmpp_admin_session_cleanup_pending ",
            "xmpp_admin_session_cleanup_running ",
            "xmpp_admin_session_cleanup_oldest_age_seconds ",
            "xmpp_admin_session_cleanup_maximum_attempts ",
            "xmpp_admin_session_cleanup_capacity_used ",
            "xmpp_admin_session_cleanup_capacity_limit ",
            "xmpp_moderation_pending_reports ",
            "xmpp_moderation_pending_appeals ",
            "xmpp_active_invitation_tokens ",
            "xmpp_legal_holds_active ",
            "xmpp_legal_hold_preserved_offline_records ",
            "xmpp_governance_export_leases_active ",
            "xmpp_governance_export_leases_expired_incomplete ",
            "xmpp_capacity_accounts_used ",
            "xmpp_capacity_accounts_limit ",
            "xmpp_capacity_muc_rooms_used ",
            "xmpp_capacity_muc_rooms_limit ",
            "xmpp_capacity_live_sessions_used ",
            "xmpp_capacity_live_sessions_limit ",
            "xmpp_capacity_resumable_sessions_used ",
            "xmpp_capacity_resumable_sessions_limit ",
            "xmpp_capacity_configuration_epoch ",
            "xmpp_capacity_muc_rooms_per_owner_limit ",
            "xmpp_capacity_sessions_per_account_limit ",
        ] {
            assert!(
                !failed.contains(absent),
                "published a fake zero for {absent}"
            );
        }

        let snapshot = crate::db::S2sOutboxSnapshot {
            pending_rows: 11,
            pending_bytes: 12_345,
            oldest_age_seconds: 67.5,
            due_rows: 2,
            locked_rows: 3,
            component_pending_rows: 4,
        };
        let operations = crate::db::ApiOperationSnapshot {
            pending: 6,
            running: 7,
            indeterminate: 8,
            oldest_active_age_seconds: 91.25,
        };
        let healthy = render_database_collector(Some(&(
            5,
            snapshot,
            operations,
            crate::db::AdminSessionCleanupSnapshot {
                pending: 27,
                running: 28,
                oldest_age_seconds: 29.5,
                maximum_attempts: 30,
                queued: 55,
                capacity: 100_000,
            },
            (9, 10, 11),
            crate::db::DataGovernanceSnapshot {
                active_holds: 12,
                preserved_offline_records: 13,
                active_export_leases: 14,
                expired_incomplete_export_leases: 15,
            },
            crate::db::DeploymentCapacitySnapshot {
                configuration_epoch: 16,
                accounts_used: 17,
                accounts_limit: 18,
                muc_rooms_used: 19,
                muc_rooms_limit: 20,
                live_sessions_used: 21,
                live_sessions_limit: 22,
                resumable_sessions_used: 23,
                resumable_sessions_limit: 24,
                muc_rooms_per_owner_limit: 25,
                sessions_per_account_limit: 26,
            },
        )));
        for expected in [
            "xmpp_database_collector_up 1\n",
            "xmpp_resumable_sessions 5\n",
            "xmpp_s2s_outbox_pending_rows 11\n",
            "xmpp_s2s_outbox_pending_bytes 12345\n",
            "xmpp_s2s_outbox_oldest_age_seconds 67.500000\n",
            "xmpp_s2s_outbox_due_rows 2\n",
            "xmpp_s2s_outbox_locked_rows 3\n",
            "xmpp_component_outbox_pending_rows 4\n",
            "xmpp_api_operations_pending 6\n",
            "xmpp_api_operations_running 7\n",
            "xmpp_api_operations_indeterminate 8\n",
            "xmpp_api_operations_oldest_active_age_seconds 91.250000\n",
            "xmpp_admin_session_cleanup_pending 27\n",
            "xmpp_admin_session_cleanup_running 28\n",
            "xmpp_admin_session_cleanup_oldest_age_seconds 29.500000\n",
            "xmpp_admin_session_cleanup_maximum_attempts 30\n",
            "xmpp_admin_session_cleanup_capacity_used 55\n",
            "xmpp_admin_session_cleanup_capacity_limit 100000\n",
            "xmpp_moderation_pending_reports 9\n",
            "xmpp_moderation_pending_appeals 10\n",
            "xmpp_active_invitation_tokens 11\n",
            "xmpp_legal_holds_active 12\n",
            "xmpp_legal_hold_preserved_offline_records 13\n",
            "xmpp_governance_export_leases_active 14\n",
            "xmpp_governance_export_leases_expired_incomplete 15\n",
            "xmpp_capacity_accounts_used 17\n",
            "xmpp_capacity_accounts_limit 18\n",
            "xmpp_capacity_muc_rooms_used 19\n",
            "xmpp_capacity_muc_rooms_limit 20\n",
            "xmpp_capacity_live_sessions_used 21\n",
            "xmpp_capacity_live_sessions_limit 22\n",
            "xmpp_capacity_resumable_sessions_used 23\n",
            "xmpp_capacity_resumable_sessions_limit 24\n",
            "xmpp_capacity_configuration_epoch 16\n",
            "xmpp_capacity_muc_rooms_per_owner_limit 25\n",
            "xmpp_capacity_sessions_per_account_limit 26\n",
        ] {
            assert!(healthy.contains(expected), "missing {expected}");
        }
    }

    #[test]
    fn password_work_rejections_are_exported_as_a_counter() {
        let rendered = render_password_work_metrics(17);
        assert!(rendered.contains(
            "# HELP xmpp_password_work_rejections_total Password hashing or verification requests rejected by the bounded CPU admission gate.\n"
        ));
        assert!(rendered.contains("# TYPE xmpp_password_work_rejections_total counter\n"));
        assert!(rendered.contains("xmpp_password_work_rejections_total 17\n"));
    }

    #[test]
    fn openapi_contract_lists_exact_router_methods() {
        use std::collections::BTreeSet;

        let document = include_str!("../../docs/openapi.yaml");
        assert!(document.starts_with("openapi: 3.1.0\n"));
        assert!(document.contains("\npaths:\n"));
        assert!(document.contains("\ncomponents:\n"));
        assert!(!document.contains('\t'));

        let mut current_path = None;
        let mut documented = BTreeSet::new();
        for line in document.lines() {
            if let Some(path) = line
                .strip_prefix("  ")
                .and_then(|line| line.strip_suffix(':'))
                .filter(|line| line.starts_with('/'))
            {
                current_path = Some(path);
                continue;
            }
            if line == "components:" {
                current_path = None;
                continue;
            }
            let Some(path) = current_path else { continue };
            let method = match line {
                "    get:" => Some("GET"),
                "    post:" => Some("POST"),
                "    put:" => Some("PUT"),
                "    patch:" => Some("PATCH"),
                "    delete:" => Some("DELETE"),
                "    options:" => Some("OPTIONS"),
                _ => None,
            };
            if let Some(method) = method {
                documented.insert(format!("{method} {path}"));
            }
        }

        let router_source = include_str!("mod.rs");
        let mut router_contract = BTreeSet::new();
        let mut search_from = 0;
        while let Some(relative) = router_source[search_from..].find(".route(") {
            let route_offset = search_from + relative;
            let opening = route_offset + ".route".len();
            let mut depth = 0_u32;
            let mut quoted = false;
            let mut escaped = false;
            let mut closing = None;
            for (offset, character) in router_source[opening..].char_indices() {
                if quoted {
                    if escaped {
                        escaped = false;
                    } else if character == '\\' {
                        escaped = true;
                    } else if character == '"' {
                        quoted = false;
                    }
                    continue;
                }
                match character {
                    '"' => quoted = true,
                    '(' => depth = depth.saturating_add(1),
                    ')' => {
                        depth = depth.saturating_sub(1);
                        if depth == 0 {
                            closing = Some(opening + offset);
                            break;
                        }
                    }
                    _ => {}
                }
            }
            let closing = closing.expect("balanced route call");
            let call = &router_source[opening + 1..closing];
            let quote = call.find('"').expect("route path opening quote");
            let path_tail = &call[quote + 1..];
            let path_end = path_tail.find('"').expect("route path closing quote");
            let path = &path_tail[..path_end];
            let handler = &path_tail[path_end + 1..];
            for (method, needles) in [
                ("GET", [" get(", ".get("]),
                ("POST", [" post(", ".post("]),
                ("PUT", [" put(", ".put("]),
                ("PATCH", [" patch(", ".patch("]),
                ("DELETE", [" delete(", ".delete("]),
                ("OPTIONS", [" options(", ".options("]),
            ] {
                if needles.iter().any(|needle| handler.contains(needle)) {
                    router_contract.insert(format!("{method} {path}"));
                }
            }
            search_from = closing + 1;
        }
        assert!(!router_contract.is_empty(), "router parser found no routes");
        assert_eq!(documented, router_contract);

        for required_contract in [
            "schema: { $ref: \"#/components/schemas/ReportModerationPatch\" }",
            "schema: { $ref: \"#/components/schemas/AppealModerationPatch\" }",
            "additionalProperties: false",
            "name: cursor",
            "OperationTarget:",
        ] {
            assert!(document.contains(required_contract));
        }
        assert!(
            !document.contains("name: offset"),
            "offset pagination must not reappear in the public contract"
        );
    }
}
