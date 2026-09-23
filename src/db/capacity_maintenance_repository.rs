//! PostgreSQL owns lease renewal and the reaper's advisory-lock transaction.
use crate::services::capacity_maintenance::CapacityMaintenanceRepository;
use anyhow::Result;
use sqlx::PgPool;
use std::collections::HashSet;
use uuid::Uuid;

#[derive(Clone)]
pub(crate) struct PostgresCapacityMaintenanceRepository {
    pool: PgPool,
}

impl PostgresCapacityMaintenanceRepository {
    pub(crate) fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

impl CapacityMaintenanceRepository for PostgresCapacityMaintenanceRepository {
    async fn renew_live_connections(
        &self,
        connection_ids: &[Uuid],
        lease_seconds: u64,
    ) -> Result<HashSet<Uuid>> {
        super::refresh_live_session_leases(&self.pool, connection_ids, lease_seconds).await
    }

    async fn try_reap_expired(&self, limit: i64) -> Result<Option<u64>> {
        super::try_cleanup_expired_live_session_leases(&self.pool, limit).await
    }
}
