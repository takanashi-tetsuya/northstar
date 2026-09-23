//! PostgreSQL adapter for the existing locked-room expiry transaction.

use crate::services::locked_muc_expiry::LockedMucExpiryRepository;
use anyhow::Result;
use sqlx::PgPool;

pub(crate) struct PostgresLockedMucExpiryRepository {
    pool: PgPool,
}

impl PostgresLockedMucExpiryRepository {
    pub(crate) fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

impl LockedMucExpiryRepository for PostgresLockedMucExpiryRepository {
    async fn expire_locked_rooms(&self, limit: i64) -> Result<Vec<String>> {
        super::delete_expired_locked_muc_rooms(&self.pool, limit).await
    }
}
