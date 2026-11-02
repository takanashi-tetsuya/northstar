//! PostgreSQL owns lease renewal and the reaper's advisory-lock transaction.
use anyhow::Result;
use northstar_session_application::capacity_maintenance::CapacityMaintenanceRepository;
use sqlx::PgPool;
use std::collections::HashSet;
use uuid::Uuid;

#[derive(Clone)]
pub struct PostgresCapacityMaintenanceRepository {
    pool: PgPool,
}

impl PostgresCapacityMaintenanceRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

impl CapacityMaintenanceRepository for PostgresCapacityMaintenanceRepository {
    async fn renew_live_connections(
        &self,
        connection_ids: &[Uuid],
        lease_seconds: u64,
    ) -> Result<HashSet<Uuid>> {
        crate::capacity::refresh_live_session_leases(&self.pool, connection_ids, lease_seconds)
            .await
    }

    async fn try_reap_expired(&self, limit: i64) -> Result<Option<u64>> {
        crate::capacity::try_cleanup_expired_live_session_leases(&self.pool, limit).await
    }
}
