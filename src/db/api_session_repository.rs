use crate::services::api_sessions::ApiSessionRepository;
use anyhow::Result;
use sqlx::PgPool;
use uuid::Uuid;

pub(crate) struct PostgresApiSessionRepository {
    pool: PgPool,
}

impl PostgresApiSessionRepository {
    pub(crate) fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

impl ApiSessionRepository for PostgresApiSessionRepository {
    async fn logout(&self, bearer: &str, request_id: Uuid) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        super::delete_api_session_audited_in_tx(&mut tx, bearer, request_id).await?;
        tx.commit().await?;
        Ok(())
    }
}
