//! Narrow, live observability capability for the private metrics listener.
//! The HTTP endpoint never receives application state, route mutation handles,
//! cluster control authority, or a raw PostgreSQL pool.

use crate::cluster::ClusterMetricsProbe;
use crate::db::metrics_snapshot_repository::PostgresMetricsSnapshotRepository;
use crate::s2s::S2sOutboundCountProbe;
use crate::security::tls::TlsMetricsProbe;
use crate::services::metrics_snapshot::{
    DatabaseMetricsSnapshot, DatabasePoolStatus, MetricsSnapshotService, ProcessGaugeSnapshot,
    SmRecoveryGaugeSnapshot,
};
use dashmap::DashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

#[derive(Clone)]
pub(crate) struct MetricsContext {
    pub(crate) bearer_token: Option<Arc<Zeroizing<String>>>,
    pub(crate) persistence: MetricsSnapshotService<PostgresMetricsSnapshotRepository>,
    pub(crate) registry: MetricsRenderProbe,
    pub(crate) component_domains: Vec<String>,
    pub(crate) limits: MetricsLimits,
    pub(crate) tls: TlsMetricsProbe,
    pub(crate) cluster: ClusterMetricsProbe,
    pub(crate) muc_occupant_count: MucOccupancyCountProbe,
    pub(crate) s2s_outbound_count: S2sOutboundCountProbe,
    pub(crate) sm: Arc<dyn SmRecoveryGauges>,
    pub(crate) started_at: Instant,
    pub(crate) bind_fallback: SocketAddr,
}

#[derive(Clone)]
pub(crate) struct MetricsRenderProbe {
    pub(crate) registry: Arc<crate::platform::metrics::Metrics>,
}

/// The number of entries in a live map; keys and values stay private to the owner.
pub(crate) trait OccupancyCount: Send + Sync {
    fn occupancy_count(&self) -> usize;
}

impl<T: Send + Sync> OccupancyCount for DashMap<String, T> {
    fn occupancy_count(&self) -> usize {
        self.len()
    }
}

/// Auditable count-only view of local MUC occupancy. The underlying map is
/// private and no mutation or occupant lookup is exposed to the endpoint.
#[derive(Clone)]
pub(crate) struct MucOccupancyCountProbe {
    occupants: Arc<dyn OccupancyCount>,
}

impl MucOccupancyCountProbe {
    pub(crate) fn new(occupants: Arc<dyn OccupancyCount>) -> Self {
        Self { occupants }
    }

    fn count(&self) -> usize {
        self.occupants.occupancy_count()
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
pub(crate) struct MetricsLimits {
    pub(crate) database_max_connections: u32,
    pub(crate) s2s_outbox_max_rows: i64,
    pub(crate) s2s_outbox_max_bytes: i64,
    pub(crate) s2s_outbox_max_per_domain: i64,
}

/// Snapshot-only view of the SM governor and recovery queue.
pub(crate) trait SmRecoveryGauges: Send + Sync {
    fn sm_recovery_snapshot(&self) -> SmRecoveryGaugeSnapshot;
}

impl MetricsContext {
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
        self.sm.sm_recovery_snapshot()
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
    use super::{metrics_credentials_authorized, MucOccupancyCountProbe, OccupancyCount};
    use dashmap::DashMap;
    use std::sync::Arc;

    #[test]
    fn muc_count_probe_reads_live_map_without_exposing_occupants() {
        let occupants = Arc::new(DashMap::new());
        let probe = MucOccupancyCountProbe::new(Arc::clone(&occupants) as Arc<dyn OccupancyCount>);
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
