//! PostgreSQL implementation of fenced S2S stream-management claims.

use anyhow::Result;
use northstar_federation_application::sm_outbox::{SmOutboxClaim, SmOutboxRepository};
use sqlx::PgPool;

pub struct PostgresSmOutboxRepository {
    pool: PgPool,
}

impl PostgresSmOutboxRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

impl SmOutboxRepository for PostgresSmOutboxRepository {
    async fn renew(&self, claim: SmOutboxClaim, lease_seconds: u64) -> Result<bool> {
        crate::renew_s2s_outbox_lease(&self.pool, claim.id, claim.lock_token, lease_seconds).await
    }

    async fn complete(&self, claim: SmOutboxClaim) -> Result<bool> {
        crate::complete_s2s_outbox_for_sm(&self.pool, claim.id, claim.lock_token).await
    }
}
