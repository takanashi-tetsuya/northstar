//! Deployment-wide live-session lease renewal and elected expiry cleanup.
use anyhow::Result;
use std::collections::HashSet;
use uuid::Uuid;

pub(crate) trait CapacityMaintenanceRepository: Send + Sync {
    fn renew_live_connections(
        &self,
        connection_ids: &[Uuid],
        lease_seconds: u64,
    ) -> impl std::future::Future<Output = Result<HashSet<Uuid>>> + Send;

    fn try_reap_expired(
        &self,
        limit: i64,
    ) -> impl std::future::Future<Output = Result<Option<u64>>> + Send;
}

#[derive(Clone)]
pub(crate) struct CapacityMaintenanceService<R> {
    repository: R,
}

impl<R: CapacityMaintenanceRepository> CapacityMaintenanceService<R> {
    pub(crate) fn new(repository: R) -> Self {
        Self { repository }
    }

    pub(crate) async fn renew_live_connections(
        &self,
        connection_ids: &[Uuid],
        lease_seconds: u64,
    ) -> Result<HashSet<Uuid>> {
        self.repository
            .renew_live_connections(connection_ids, lease_seconds)
            .await
    }

    pub(crate) async fn try_reap_expired(&self, limit: i64) -> Result<Option<u64>> {
        self.repository.try_reap_expired(limit).await
    }
}
