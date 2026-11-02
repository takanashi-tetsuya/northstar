//! PostgreSQL adapter for the five independent background cleanup commands.

use anyhow::Result;
use northstar_operations_application::background_housekeeping::BackgroundHousekeepingRepository;
use sqlx::PgPool;

pub struct PostgresBackgroundHousekeepingRepository {
    pool: PgPool,
}

impl PostgresBackgroundHousekeepingRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

impl BackgroundHousekeepingRepository for PostgresBackgroundHousekeepingRepository {
    async fn purge_resolved_moderation(&self, retention_days: i64, batch_size: i64) -> Result<u64> {
        northstar_operations_postgres::reports::purge_resolved_moderation_batch(
            &self.pool,
            retention_days,
            batch_size,
        )
        .await
    }

    async fn cleanup_expired_sessions(&self) -> Result<u64> {
        northstar_auth_postgres::users::cleanup_expired_sessions(&self.pool).await
    }

    async fn cleanup_expired_idempotency(&self, batch_size: i64) -> Result<u64> {
        northstar_operations_postgres::api_control::cleanup_expired_idempotency(
            &self.pool, batch_size,
        )
        .await
    }

    async fn cleanup_fast_tokens(&self) -> Result<u64> {
        northstar_auth_postgres::fast::cleanup_fast_tokens(&self.pool).await
    }

    async fn cleanup_expired_login_epoch_stages(&self, batch_size: i64) -> Result<u64> {
        northstar_auth_postgres::users::cleanup_expired_user_agent_login_epoch_stages(
            &self.pool, batch_size,
        )
        .await
    }
}
