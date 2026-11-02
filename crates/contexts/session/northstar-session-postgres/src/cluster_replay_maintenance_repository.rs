//! PostgreSQL adapter for the existing cluster replay maintenance routines.

use anyhow::Result;
use northstar_session_application::cluster_replay_maintenance::ClusterReplayMaintenanceRepository;
use sqlx::PgPool;

pub struct PostgresClusterReplayMaintenanceRepository {
    pool: PgPool,
}

impl PostgresClusterReplayMaintenanceRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

impl ClusterReplayMaintenanceRepository for PostgresClusterReplayMaintenanceRepository {
    async fn cleanup_replays(&self, limit: i32) -> Result<u64> {
        crate::cluster_keys::cleanup_cluster_envelope_replays(&self.pool, limit).await
    }

    async fn validate_capacity_authority(&self) -> Result<()> {
        crate::cluster_session_route::validate_cluster_replay_capacity_authority(&self.pool).await
    }
}
