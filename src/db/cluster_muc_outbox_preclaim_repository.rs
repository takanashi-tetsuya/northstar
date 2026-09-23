//! PostgreSQL adapter for the two independent pre-claim maintenance steps.

use crate::db;
use crate::services::cluster_muc_outbox_preclaim::ClusterMucOutboxPreclaimRepository;
use anyhow::Result;
use sqlx::PgPool;

pub(crate) struct PostgresClusterMucOutboxPreclaimRepository {
    pool: PgPool,
}

impl PostgresClusterMucOutboxPreclaimRepository {
    pub(crate) fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

impl ClusterMucOutboxPreclaimRepository for PostgresClusterMucOutboxPreclaimRepository {
    async fn expire_occupancies(&self, room_limit: i64) -> Result<u64> {
        db::expire_cluster_muc_occupancies(&self.pool, room_limit).await
    }

    async fn dead_letter_expired(&self, limit: i64) -> Result<u64> {
        db::dead_letter_expired_cluster_muc_outbox(&self.pool, limit).await
    }
}
