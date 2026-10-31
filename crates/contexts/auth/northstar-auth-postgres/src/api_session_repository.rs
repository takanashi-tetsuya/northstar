use anyhow::Result;
use northstar_auth_application::api_sessions::ApiSessionRepository;
use sqlx::PgPool;
use uuid::Uuid;

pub struct PostgresApiSessionRepository {
    pool: PgPool,
}

impl PostgresApiSessionRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

impl ApiSessionRepository for PostgresApiSessionRepository {
    async fn logout(&self, bearer: &str, request_id: Uuid) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        crate::users::delete_api_session_audited_in_tx(&mut tx, bearer, request_id).await?;
        tx.commit().await?;
        Ok(())
    }
}
