//! Deployment-wide live-session lease renewal and elected expiry cleanup.
use anyhow::Result;
use std::collections::HashSet;
use uuid::Uuid;

pub trait CapacityMaintenanceRepository: Send + Sync {
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
pub struct CapacityMaintenanceService<R> {
    repository: R,
}

impl<R: CapacityMaintenanceRepository> CapacityMaintenanceService<R> {
    pub fn new(repository: R) -> Self {
        Self { repository }
    }

    pub async fn renew_live_connections(
        &self,
        connection_ids: &[Uuid],
        lease_seconds: u64,
    ) -> Result<HashSet<Uuid>> {
        self.repository
            .renew_live_connections(connection_ids, lease_seconds)
            .await
    }

    pub async fn try_reap_expired(&self, limit: i64) -> Result<Option<u64>> {
        self.repository.try_reap_expired(limit).await
    }
}
