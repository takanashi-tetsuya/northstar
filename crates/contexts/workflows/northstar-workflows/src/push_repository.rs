//! PostgreSQL adapter for Push subscription, claim and handoff authority.

use anyhow::Result;
use northstar_message_application::push::*;
use northstar_message_core::ActorGenerationFence;
use northstar_message_postgres::push as postgres;
use sqlx::PgPool;
use uuid::Uuid;
#[derive(Clone)]
pub struct PostgresPushRepository {
    pool: PgPool,
}
impl PostgresPushRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}
impl PushRepository for PostgresPushRepository {
    async fn enable(
        &self,
        actor: ActorGenerationFence,
        service_jid: &str,
        node: &str,
        options: Option<&str>,
    ) -> Result<PushEnableOutcome> {
        postgres::enable_push_subscription(&self.pool, actor, service_jid, node, options).await
    }
    async fn disable(
        &self,
        actor: ActorGenerationFence,
        service_jid: &str,
        node: Option<&str>,
    ) -> Result<Option<u64>> {
        postgres::disable_owned_push_subscriptions(&self.pool, actor, service_jid, node).await
    }
    async fn claim_batch(&self, user_id: Uuid) -> Result<PushBatch> {
        postgres::claim_push_deliveries(&self.pool, user_id).await
    }
    async fn mark_unroutable(&self, request_id: Uuid) -> Result<()> {
        postgres::mark_push_unroutable(&self.pool, request_id).await
    }
    async fn complete_response(
        &self,
        request_id: Uuid,
        sender_bare: &str,
        kind: PushResponseKind,
    ) -> Result<PushResponseOutcome> {
        postgres::complete_push_response(&self.pool, request_id, sender_bare, kind).await
    }
    async fn disable_from_service(
        &self,
        target_username: &str,
        service_jid: &str,
        node: &str,
    ) -> Result<bool> {
        let Some(recipient) =
            northstar_auth_postgres::users::find_user(&self.pool, target_username).await?
        else {
            return Ok(false);
        };
        Ok(
            postgres::disable_push_subscriptions(&self.pool, recipient.id, service_jid, Some(node))
                .await?
                > 0,
        )
    }
}

impl PushHandoffAuthority for PostgresPushRepository {
    async fn validate_handoff(&self, user_id: Uuid, delivery: &PushDelivery) -> Result<bool> {
        postgres::validate_push_handoff(&self.pool, user_id, delivery).await
    }
}
