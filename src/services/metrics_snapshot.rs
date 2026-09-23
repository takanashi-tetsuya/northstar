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

pub(crate) trait MetricsSnapshotRepository: Send + Sync {
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
    pub(crate) async fn collect(
        &self,
        component_domains: &[String],
    ) -> anyhow::Result<DatabaseMetricsSnapshot> {
        self.repository.collect(component_domains).await
    }
}
