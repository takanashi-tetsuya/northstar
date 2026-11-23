//! PostgreSQL adapter for the existing locked-room expiry transaction.

use anyhow::Result;
use northstar_room_application::locked_muc_expiry::LockedMucExpiryRepository;
use northstar_room_application::muc_service::CommittedRoomRetirement;
use northstar_room_core::MucTimeSources;
use sqlx::PgPool;

#[derive(Clone)]
pub struct PostgresLockedMucExpiryRepository {
    pool: PgPool,
    time_sources: MucTimeSources,
}

impl PostgresLockedMucExpiryRepository {
    pub fn new(pool: PgPool) -> Self {
        Self::new_with_time_sources(pool, MucTimeSources::default())
    }

    pub fn new_with_time_sources(pool: PgPool, time_sources: MucTimeSources) -> Self {
        Self { pool, time_sources }
    }
}

impl LockedMucExpiryRepository for PostgresLockedMucExpiryRepository {
    async fn expire_locked_rooms(&self, limit: i64) -> Result<Vec<CommittedRoomRetirement>> {
        crate::muc::expire_locked_muc_rooms_with_ids(&self.pool, limit, &self.time_sources).await
    }
}
