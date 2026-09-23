//! Narrow, live observability capability for the private metrics listener.
//! The HTTP endpoint never receives application state, route mutation handles,
//! cluster control authority, or a raw PostgreSQL pool.

use super::{AppState, MucOccupant};
use crate::cluster::ClusterMetricsProbe;
use crate::db::metrics_snapshot_repository::PostgresMetricsSnapshotRepository;
use crate::s2s::S2sOutboundCountProbe;
use crate::services::metrics_snapshot::{
    DatabaseMetricsSnapshot, DatabasePoolStatus, MetricsSnapshotService, ProcessGaugeSnapshot,
    SmRecoveryGaugeSnapshot,
};
use crate::tls::TlsMetricsProbe;
use dashmap::DashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

#[derive(Clone)]
pub(crate) struct MetricsContext {
    bearer_token: Option<Arc<Zeroizing<String>>>,
    persistence: MetricsSnapshotService<PostgresMetricsSnapshotRepository>,
    registry: MetricsRenderProbe,
    component_domains: Vec<String>,
    limits: MetricsLimits,
    tls: TlsMetricsProbe,
    cluster: ClusterMetricsProbe,
    muc_occupant_count: MucOccupancyCountProbe<MucOccupant>,
    s2s_outbound_count: S2sOutboundCountProbe,
    sm: SmRecoveryMetricsProbe,
    started_at: Instant,
    bind_fallback: SocketAddr,
}

#[derive(Clone)]
struct MetricsRenderProbe {
    registry: Arc<crate::metrics::Metrics>,
}

/// Auditable count-only view of local MUC occupancy. The underlying map is
/// private and no mutation or occupant lookup is exposed to the endpoint.
#[derive(Clone)]
struct MucOccupancyCountProbe<T> {
    occupants: Arc<DashMap<String, T>>,
}

impl<T> MucOccupancyCountProbe<T> {
    fn count(&self) -> usize {
        self.occupants.len()
    }
}

impl MetricsRenderProbe {
    fn render(&self) -> String {
        self.registry.render()
    }

    fn record_database_ping(&self, duration: Duration) {
        self.registry
            .database_operation_duration_seconds
            .observe(duration);
    }
}

#[derive(Clone, Copy)]
struct MetricsLimits {
    database_max_connections: u32,
    s2s_outbox_max_rows: i64,
    s2s_outbox_max_bytes: i64,
    s2s_outbox_max_per_domain: i64,
}

/// Snapshot-only view of the SM governor and recovery queue. Neither mutable
/// authority is exposed through MetricsContext's interface.
#[derive(Clone)]
struct SmRecoveryMetricsProbe {
    governor: Arc<crate::services::sm_capacity::SmMemoryGovernor>,
    recovery: Arc<crate::services::session_cleanup::SmSuspensionRecoveryQueue>,
}

impl SmRecoveryMetricsProbe {
    fn snapshot(&self) -> SmRecoveryGaugeSnapshot {
        let metrics = self.governor.metrics();
        let recovery = self.recovery.snapshot();
        SmRecoveryGaugeSnapshot {
            reserved_bytes: metrics.reserved_bytes.load(Ordering::Relaxed),
            limit_bytes: self.governor.max_bytes(),
            peak_reserved_bytes: metrics.peak_reserved_bytes.load(Ordering::Relaxed),
            admission_rejections_total: metrics.admission_rejections_total.load(Ordering::Relaxed),
            invariant_failures_total: metrics.invariant_failures_total.load(Ordering::Relaxed),
            recovery_jobs: recovery.jobs,
            recovery_job_limit: self.governor.max_recovery_jobs(),
            recovery_bytes: recovery.bytes,
            recovery_byte_limit: self.governor.max_recovery_bytes(),
            recovery_oldest_age_seconds: recovery.oldest_age_seconds,
        }
    }
}

impl MetricsContext {
    pub(super) fn from_state(state: &AppState) -> Self {
        Self {
            bearer_token: state.metrics_bearer_token.clone(),
            persistence: state.metrics_snapshot_service.clone(),
            registry: MetricsRenderProbe {
                registry: Arc::clone(&state.metrics),
            },
            // The configured list is immutable after startup. Keep original
            // order and duplicates for the component outbox query.
            component_domains: state.configured_component_domains(),
            limits: MetricsLimits {
                database_max_connections: state.config.database_max_connections,
                s2s_outbox_max_rows: state.config.s2s_outbox_max_rows,
                s2s_outbox_max_bytes: state.config.s2s_outbox_max_bytes,
                s2s_outbox_max_per_domain: state.config.s2s_outbox_max_per_domain,
            },
            tls: state.tls_context.metrics_probe(),
            cluster: state.cluster.metrics_probe(),
            muc_occupant_count: MucOccupancyCountProbe {
                occupants: Arc::clone(&state.muc_occupants),
            },
            s2s_outbound_count: state.s2s_connection_registry.outbound_count_probe(),
            sm: SmRecoveryMetricsProbe {
                governor: Arc::clone(&state.sm_memory_governor),
                recovery: Arc::clone(&state.sm_suspension_recovery),
            },
            started_at: state.started_at,
            bind_fallback: state.config.metrics_bind,
        }
    }

    pub(crate) fn bind_fallback(&self) -> SocketAddr {
        self.bind_fallback
    }

    pub(crate) fn authorized(&self, peer: IpAddr, candidate: Option<&str>) -> bool {
        metrics_credentials_authorized(
            self.bearer_token.as_deref().map(|token| token.as_str()),
            peer,
            candidate,
        )
    }

    pub(crate) async fn ping(&self) -> anyhow::Result<()> {
        self.persistence.ping().await
    }

    pub(crate) fn pool_status(&self) -> DatabasePoolStatus {
        self.persistence.pool_status()
    }

    pub(crate) async fn collect(&self) -> anyhow::Result<DatabaseMetricsSnapshot> {
        self.persistence.collect(&self.component_domains).await
    }

    pub(crate) fn record_database_ping(&self, duration: Duration) {
        self.registry.record_database_ping(duration);
    }

    pub(crate) fn process_snapshot(&self) -> ProcessGaugeSnapshot {
        let (tls_not_after, tls_generation) = self.tls.leaf_status();
        let certificate_sessions = self.tls.certificate_session_metrics();
        let now_unix = chrono::Utc::now().timestamp();
        let tls_seconds_remaining = tls_not_after.saturating_sub(now_unix).max(0);
        let cluster = self.cluster.snapshot();
        let base_metrics = self.registry.render();
        ProcessGaugeSnapshot {
            base_metrics,
            database_max_connections: self.limits.database_max_connections,
            s2s_outbox_max_rows: self.limits.s2s_outbox_max_rows,
            s2s_outbox_max_bytes: self.limits.s2s_outbox_max_bytes,
            s2s_outbox_max_per_domain: self.limits.s2s_outbox_max_per_domain,
            muc_occupants: self.muc_occupant_count.count(),
            federation_outbound_workers: self.s2s_outbound_count.count(),
            uptime_seconds: self.started_at.elapsed().as_secs(),
            tls_not_after,
            tls_seconds_remaining,
            tls_generation,
            certificate_sessions,
            cluster,
        }
    }

    pub(crate) fn sm_snapshot(&self) -> SmRecoveryGaugeSnapshot {
        self.sm.snapshot()
    }
}

fn metrics_credentials_authorized(
    expected: Option<&str>,
    peer: IpAddr,
    candidate: Option<&str>,
) -> bool {
    let Some(expected) = expected else {
        return peer.is_loopback();
    };
    candidate.is_some_and(|candidate| {
        candidate.len() == expected.len()
            && bool::from(candidate.as_bytes().ct_eq(expected.as_bytes()))
    })
}

#[cfg(test)]
mod tests {
    use super::{metrics_credentials_authorized, MucOccupancyCountProbe};
    use dashmap::DashMap;
    use std::sync::Arc;

    #[test]
    fn muc_count_probe_reads_live_map_without_exposing_occupants() {
        let occupants = Arc::new(DashMap::new());
        let probe = MucOccupancyCountProbe {
            occupants: Arc::clone(&occupants),
        };
        assert_eq!(probe.count(), 0);
        occupants.insert("room\0user".to_owned(), 1_u8);
        assert_eq!(probe.count(), 1);
        occupants.remove("room\0user");
        assert_eq!(probe.count(), 0);
    }

    #[test]
    fn configured_bearer_is_required_even_on_loopback_and_compared_exactly() {
        let loopback = "127.0.0.1".parse().unwrap();
        let remote = "192.0.2.10".parse().unwrap();
        let secret = "0123456789abcdef0123456789abcdef";
        assert!(metrics_credentials_authorized(None, loopback, None));
        assert!(!metrics_credentials_authorized(None, remote, Some(secret)));
        assert!(!metrics_credentials_authorized(
            Some(secret),
            loopback,
            None
        ));
        assert!(metrics_credentials_authorized(
            Some(secret),
            remote,
            Some(secret)
        ));
        assert!(!metrics_credentials_authorized(
            Some(secret),
            remote,
            Some("0123456789abcdef0123456789abcdee")
        ));
        assert!(!metrics_credentials_authorized(
            Some(secret),
            remote,
            Some("0123456789abcdef0123456789abcdef0")
        ));
    }
}
