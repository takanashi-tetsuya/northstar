//! PostgreSQL adapter for the three independent clustered-MUC housekeeping calls.

use anyhow::Result;
use northstar_room_application::cluster_muc_outbox_housekeeping::{
    ClusterMucOutboxGaugeSnapshot, ClusterMucOutboxHousekeepingRepository,
};
use sqlx::PgPool;

pub struct PostgresClusterMucOutboxHousekeepingRepository {
    pool: PgPool,
}

impl PostgresClusterMucOutboxHousekeepingRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

impl ClusterMucOutboxHousekeepingRepository for PostgresClusterMucOutboxHousekeepingRepository {
    async fn purge_expired_dead_letters(&self, limit: i64) -> Result<u64> {
        crate::cluster_muc::cleanup_cluster_muc_dead_letters(&self.pool, limit).await
    }

    async fn purge_history(&self, retention_days: i64, limit: i64) -> Result<(u64, u64)> {
        crate::cluster_muc::cleanup_cluster_muc_history(&self.pool, retention_days, limit).await
    }

    async fn snapshot(&self) -> Result<ClusterMucOutboxGaugeSnapshot> {
        let snapshot = crate::cluster_muc::cluster_muc_outbox_snapshot(&self.pool).await?;
        Ok(ClusterMucOutboxGaugeSnapshot {
            queued_rows: snapshot.queued_rows,
            dead_letter_rows: snapshot.dead_letter_rows,
            oldest_age_seconds: snapshot.oldest_age_seconds,
        })
    }
}
