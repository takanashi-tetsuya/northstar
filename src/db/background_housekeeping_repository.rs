//! PostgreSQL adapter for the five independent background cleanup commands.

use crate::services::background_housekeeping::BackgroundHousekeepingRepository;
use anyhow::Result;
use sqlx::PgPool;

pub(crate) struct PostgresBackgroundHousekeepingRepository {
    pool: PgPool,
}

impl PostgresBackgroundHousekeepingRepository {
    pub(crate) fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

impl BackgroundHousekeepingRepository for PostgresBackgroundHousekeepingRepository {
    async fn purge_resolved_moderation(&self, retention_days: i64, batch_size: i64) -> Result<u64> {
        crate::db::purge_resolved_moderation_batch(&self.pool, retention_days, batch_size).await
    }

    async fn cleanup_expired_sessions(&self) -> Result<u64> {
        crate::db::cleanup_expired_sessions(&self.pool).await
    }

    async fn cleanup_expired_idempotency(&self, batch_size: i64) -> Result<u64> {
        crate::db::cleanup_expired_idempotency(&self.pool, batch_size).await
    }

    async fn cleanup_fast_tokens(&self) -> Result<u64> {
        crate::db::cleanup_fast_tokens(&self.pool).await
    }

    async fn cleanup_expired_login_epoch_stages(&self, batch_size: i64) -> Result<u64> {
        crate::db::cleanup_expired_user_agent_login_epoch_stages(&self.pool, batch_size).await
    }
}
