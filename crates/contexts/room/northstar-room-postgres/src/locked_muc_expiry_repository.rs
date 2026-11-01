//! PostgreSQL adapter for the existing locked-room expiry transaction.

use anyhow::Result;
use northstar_room_application::locked_muc_expiry::LockedMucExpiryRepository;
use sqlx::PgPool;

#[derive(Clone)]
pub struct PostgresLockedMucExpiryRepository {
    pool: PgPool,
}

impl PostgresLockedMucExpiryRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

impl LockedMucExpiryRepository for PostgresLockedMucExpiryRepository {
    async fn expire_locked_rooms(&self, limit: i64) -> Result<Vec<String>> {
        crate::muc::delete_expired_locked_muc_rooms(&self.pool, limit).await
    }
}
