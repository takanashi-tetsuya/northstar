//! One coherent, read-only PostgreSQL metrics projection.
//! The service owns the use case; only the repository can open its transaction.
use std::future::Future;

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub(crate) struct S2sOutboxSnapshot {
    pub pending_rows: i64,
    pub pending_bytes: i64,
    pub oldest_age_seconds: f64,
    pub due_rows: i64,
    pub locked_rows: i64,
    pub component_pending_rows: i64,
}
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub(crate) struct ApiOperationSnapshot {
    pub pending: i64,
    pub running: i64,
    pub indeterminate: i64,
    pub oldest_active_age_seconds: f64,
}
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub(crate) struct AdminSessionCleanupSnapshot {
    pub pending: i64,
    pub running: i64,
    pub oldest_age_seconds: f64,
    pub maximum_attempts: i64,
    pub queued: i64,
    pub capacity: i64,
}
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub(crate) struct DataGovernanceSnapshot {
    pub active_holds: i64,
    pub preserved_offline_records: i64,
    pub active_export_leases: i64,
    pub expired_incomplete_export_leases: i64,
}
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub(crate) struct DeploymentCapacitySnapshot {
    pub configuration_epoch: i64,
    pub accounts_used: i64,
    pub accounts_limit: i64,
    pub muc_rooms_used: i64,
    pub muc_rooms_limit: i64,
    pub live_sessions_used: i64,
    pub live_sessions_limit: i64,
    pub resumable_sessions_used: i64,
    pub resumable_sessions_limit: i64,
    pub muc_rooms_per_owner_limit: i64,
    pub sessions_per_account_limit: i64,
}

pub(crate) type DatabaseMetricsSnapshot = (
    i64,
    S2sOutboxSnapshot,
    ApiOperationSnapshot,
    AdminSessionCleanupSnapshot,
    (i64, i64, i64),
    DataGovernanceSnapshot,
    DeploymentCapacitySnapshot,
);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DatabasePoolStatus {
    pub(crate) connections: u32,
    pub(crate) idle_connections: usize,
}

/// Copy-only process gauges. Neither the HTTP adapter nor this renderer owns
/// the live config, cluster, MUC map, metrics registry, or SM governor.
pub(crate) struct ProcessGaugeSnapshot {
    pub(crate) base_metrics: String,
    pub(crate) database_max_connections: u32,
    pub(crate) s2s_outbox_max_rows: i64,
    pub(crate) s2s_outbox_max_bytes: i64,
    pub(crate) s2s_outbox_max_per_domain: i64,
    pub(crate) muc_occupants: usize,
    pub(crate) federation_outbound_workers: usize,
    pub(crate) uptime_seconds: u64,
    pub(crate) tls_not_after: i64,
    pub(crate) tls_seconds_remaining: i64,
    pub(crate) tls_generation: u64,
    pub(crate) certificate_sessions: crate::tls::CertificateSessionMetrics,
    pub(crate) cluster: crate::cluster::ClusterMetricsSnapshot,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SmRecoveryGaugeSnapshot {
    pub(crate) reserved_bytes: u64,
    pub(crate) limit_bytes: usize,
    pub(crate) peak_reserved_bytes: u64,
    pub(crate) admission_rejections_total: u64,
    pub(crate) invariant_failures_total: u64,
    pub(crate) recovery_jobs: usize,
    pub(crate) recovery_job_limit: usize,
    pub(crate) recovery_bytes: usize,
    pub(crate) recovery_byte_limit: usize,
    pub(crate) recovery_oldest_age_seconds: u64,
}

pub(crate) trait MetricsSnapshotRepository: Send + Sync {
    fn ping(&self) -> impl Future<Output = anyhow::Result<()>> + Send;
    fn pool_status(&self) -> DatabasePoolStatus;
    fn collect(
        &self,
        component_domains: &[String],
    ) -> impl Future<Output = anyhow::Result<DatabaseMetricsSnapshot>> + Send;
}

#[derive(Clone)]
pub(crate) struct MetricsSnapshotService<R> {
    repository: R,
}
impl<R: MetricsSnapshotRepository> MetricsSnapshotService<R> {
    pub(crate) fn new(repository: R) -> Self {
        Self { repository }
    }
    pub(crate) async fn ping(&self) -> anyhow::Result<()> {
        self.repository.ping().await
    }
    pub(crate) fn pool_status(&self) -> DatabasePoolStatus {
        self.repository.pool_status()
    }
    pub(crate) async fn collect(
        &self,
        component_domains: &[String],
    ) -> anyhow::Result<DatabaseMetricsSnapshot> {
        self.repository.collect(component_domains).await
    }
}

/// Preserve the original Prometheus label names, order, and scalar formatting.
pub(crate) fn render_process_gauges(
    database_up: bool,
    database_ping_seconds: f64,
    pool_status: DatabasePoolStatus,
    snapshot: &ProcessGaugeSnapshot,
) -> String {
    let mut body = snapshot.base_metrics.clone();
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
        pool_status.connections,
        pool_status.idle_connections,
        snapshot.database_max_connections,
        snapshot.s2s_outbox_max_rows,
        snapshot.s2s_outbox_max_bytes,
        snapshot.s2s_outbox_max_per_domain,
        snapshot.muc_occupants,
        snapshot.federation_outbound_workers,
        snapshot.uptime_seconds,
        snapshot.tls_not_after,
        snapshot.tls_seconds_remaining,
        snapshot.tls_generation,
        snapshot.certificate_sessions.active,
        snapshot.certificate_sessions.c2s_external,
        snapshot.certificate_sessions.inbound_s2s_external,
        snapshot.certificate_sessions.outbound_s2s_external,
        snapshot.cluster.state,
        snapshot.cluster.listener_generation,
        snapshot.cluster.authentication_failures,
        snapshot.cluster.replay_rejections,
        snapshot.cluster.degraded_transitions,
        snapshot.cluster.incompatible_peer_versions,
    ));
    body
}

pub(crate) fn render_sm_recovery_gauges(snapshot: &SmRecoveryGaugeSnapshot) -> String {
    let mut body = String::new();
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
        snapshot.reserved_bytes,
        snapshot.limit_bytes,
        snapshot.peak_reserved_bytes,
        snapshot.admission_rejections_total,
        snapshot.invariant_failures_total,
        snapshot.recovery_jobs,
        snapshot.recovery_job_limit,
        snapshot.recovery_bytes,
        snapshot.recovery_byte_limit,
        snapshot.recovery_oldest_age_seconds,
    ));
    body
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn process_gauges_render_exact_copied_values_in_existing_order() {
        let snapshot = ProcessGaugeSnapshot {
            base_metrics: "base_counter 11\n".into(),
            database_max_connections: 37,
            s2s_outbox_max_rows: 101,
            s2s_outbox_max_bytes: 102,
            s2s_outbox_max_per_domain: 103,
            muc_occupants: 7,
            federation_outbound_workers: 8,
            uptime_seconds: 9,
            tls_not_after: 400,
            tls_seconds_remaining: 20,
            tls_generation: 3,
            certificate_sessions: crate::tls::CertificateSessionMetrics {
                active: 4,
                c2s_external: 5,
                inbound_s2s_external: 6,
                outbound_s2s_external: 7,
            },
            cluster: crate::cluster::ClusterMetricsSnapshot {
                state: 2,
                listener_generation: 12,
                authentication_failures: 13,
                replay_rejections: 14,
                degraded_transitions: 15,
                incompatible_peer_versions: 16,
            },
        };
        let rendered = render_process_gauges(
            false,
            0.125,
            DatabasePoolStatus {
                connections: 2,
                idle_connections: 1,
            },
            &snapshot,
        );
        assert!(rendered.starts_with("base_counter 11\n# TYPE xmpp_database_up gauge\n"));
        for line in [
            "xmpp_database_up 0\n",
            "xmpp_database_ping_duration_seconds 0.125000\n",
            "xmpp_database_pool_connections 2\n",
            "xmpp_database_pool_idle_connections 1\n",
            "xmpp_database_pool_max_connections 37\n",
            "xmpp_s2s_outbox_max_rows 101\n",
            "xmpp_s2s_outbox_max_bytes 102\n",
            "xmpp_s2s_outbox_max_per_domain 103\n",
            "xmpp_muc_occupants 7\n",
            "xmpp_federation_outbound_workers 8\n",
            "xmpp_uptime_seconds 9\n",
            "xmpp_tls_certificate_not_after_seconds 400\n",
            "xmpp_tls_certificate_seconds_until_expiry 20\n",
            "xmpp_tls_generation 3\n",
            "xmpp_tls_certificate_authenticated_sessions 4\n",
            "xmpp_tls_c2s_external_sessions 5\n",
            "xmpp_tls_inbound_s2s_external_sessions 6\n",
            "xmpp_tls_outbound_s2s_external_sessions 7\n",
            "xmpp_cluster_operational_state 2\n",
            "xmpp_cluster_listener_generation 12\n",
            "xmpp_cluster_authentication_failures_total 13\n",
            "xmpp_cluster_replay_rejections_total 14\n",
            "xmpp_cluster_degraded_transitions_total 15\n",
            "xmpp_cluster_incompatible_peer_versions_total 16\n",
        ] {
            assert!(rendered.contains(line), "missing {line:?}");
        }
        assert!(
            rendered.find("xmpp_muc_occupants 7\n").unwrap()
                < rendered.find("xmpp_cluster_operational_state 2\n").unwrap()
        );
    }

    #[test]
    fn sm_gauges_render_late_snapshot_values() {
        let rendered = render_sm_recovery_gauges(&SmRecoveryGaugeSnapshot {
            reserved_bytes: 10,
            limit_bytes: 11,
            peak_reserved_bytes: 12,
            admission_rejections_total: 13,
            invariant_failures_total: 14,
            recovery_jobs: 15,
            recovery_job_limit: 16,
            recovery_bytes: 17,
            recovery_byte_limit: 18,
            recovery_oldest_age_seconds: 19,
        });
        assert!(rendered.starts_with("# TYPE xmpp_sm_memory_reserved_bytes gauge\n"));
        assert!(rendered.contains("xmpp_sm_memory_reserved_bytes 10\n"));
        assert!(rendered.contains("xmpp_sm_recovery_queue_oldest_age_seconds 19\n"));
        assert!(
            rendered
                .find("xmpp_sm_capacity_invariant_failures_total 14\n")
                .unwrap()
                < rendered.find("xmpp_sm_recovery_queue_jobs 15\n").unwrap()
        );
    }
}
