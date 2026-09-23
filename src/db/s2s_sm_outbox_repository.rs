//! PostgreSQL implementation of fenced S2S stream-management claims.

use crate::services::s2s_sm_outbox::{SmOutboxClaim, SmOutboxRepository};
use anyhow::Result;
use sqlx::PgPool;

pub(crate) struct PostgresSmOutboxRepository {
    pool: PgPool,
}

impl PostgresSmOutboxRepository {
    pub(crate) fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

impl SmOutboxRepository for PostgresSmOutboxRepository {
    async fn renew(&self, claim: SmOutboxClaim, lease_seconds: u64) -> Result<bool> {
        crate::db::renew_s2s_outbox_lease(&self.pool, claim.id, claim.lock_token, lease_seconds)
            .await
    }

    async fn complete(&self, claim: SmOutboxClaim) -> Result<bool> {
        crate::db::complete_s2s_outbox(&self.pool, claim.id, claim.lock_token).await
    }
}
