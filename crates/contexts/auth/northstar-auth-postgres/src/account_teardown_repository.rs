//! PostgreSQL adapter for committed account authorization generations.

use anyhow::Result;
use northstar_auth_application::account_teardown::AccountGenerationRepository;
use sqlx::PgPool;
use uuid::Uuid;

pub struct PostgresAccountGenerationRepository {
    pool: PgPool,
}

impl PostgresAccountGenerationRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

impl AccountGenerationRepository for PostgresAccountGenerationRepository {
    async fn generation(&self, user_id: Uuid) -> Result<Option<i64>> {
        Ok(
            sqlx::query_scalar::<_, i64>("SELECT auth_generation FROM users WHERE id=$1")
                .bind(user_id)
                .fetch_optional(&self.pool)
                .await?,
        )
    }
}
