//! PostgreSQL adapter for the existing cluster replay maintenance routines.

use crate::services::cluster_replay_maintenance::ClusterReplayMaintenanceRepository;
use anyhow::Result;
use sqlx::PgPool;

pub(crate) struct PostgresClusterReplayMaintenanceRepository {
    pool: PgPool,
}

impl PostgresClusterReplayMaintenanceRepository {
    pub(crate) fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

impl ClusterReplayMaintenanceRepository for PostgresClusterReplayMaintenanceRepository {
    async fn cleanup_replays(&self, limit: i32) -> Result<u64> {
        super::cleanup_cluster_envelope_replays(&self.pool, limit).await
    }

    async fn validate_capacity_authority(&self) -> Result<()> {
        super::validate_cluster_replay_capacity_authority(&self.pool).await
    }
}
