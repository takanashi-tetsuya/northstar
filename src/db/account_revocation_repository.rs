//! PostgreSQL adapter for the exact-instance account revocation outbox.

use crate::services::account_revocation_consumer::{
    AccountRevocationConsumerIdentity, AccountRevocationEvent, AccountRevocationRepository,
};
use anyhow::Result;
use sqlx::PgPool;
use uuid::Uuid;

pub(crate) struct PostgresAccountRevocationRepository {
    pool: PgPool,
}

impl PostgresAccountRevocationRepository {
    pub(crate) fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

impl AccountRevocationRepository for PostgresAccountRevocationRepository {
    async fn pending(
        &self,
        identity: &AccountRevocationConsumerIdentity,
    ) -> Result<Vec<AccountRevocationEvent>> {
        Ok(crate::db::account_revocations::pending(
            &self.pool,
            &identity.domain,
            &identity.node_id,
            identity.instance_uuid,
            identity.instance_epoch,
        )
        .await?
        .into_iter()
        .map(|event| AccountRevocationEvent {
            user_id: event.user_id,
            username: event.username,
            before_generation: event.before_generation,
            account_deleted: event.account_deleted,
            revision: event.revision,
        })
        .collect())
    }

    async fn acknowledge(
        &self,
        identity: &AccountRevocationConsumerIdentity,
        revisions: &[Uuid],
    ) -> Result<()> {
        crate::db::account_revocations::acknowledge(
            &self.pool,
            &identity.domain,
            &identity.node_id,
            identity.instance_uuid,
            identity.instance_epoch,
            revisions,
        )
        .await
    }

    async fn cleanup(&self) -> Result<()> {
        crate::db::account_revocations::cleanup(&self.pool).await
    }
}
