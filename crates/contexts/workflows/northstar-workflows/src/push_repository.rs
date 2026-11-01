//! The push repository, which also counts the account's pending subscriptions.

use anyhow::Result;
use northstar_message_application::push::*;
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
        user_id: Uuid,
        service_jid: &str,
        node: &str,
        options: Option<&str>,
    ) -> Result<PushEnableOutcome> {
        Ok(
            match northstar_message_postgres::push::enable_push_subscription(
                &self.pool,
                user_id,
                service_jid,
                node,
                options,
            )
            .await?
            {
                northstar_message_postgres::push::PushEnableOutcome::Enabled => {
                    PushEnableOutcome::Enabled
                }
                northstar_message_postgres::push::PushEnableOutcome::QuotaExceeded => {
                    PushEnableOutcome::QuotaExceeded
                }
                northstar_message_postgres::push::PushEnableOutcome::RateLimited => {
                    PushEnableOutcome::RateLimited
                }
            },
        )
    }
    async fn disable(&self, user_id: Uuid, service_jid: &str, node: Option<&str>) -> Result<u64> {
        northstar_message_postgres::push::disable_push_subscriptions(
            &self.pool,
            user_id,
            service_jid,
            node,
        )
        .await
    }
    async fn claim_batch(&self, user_id: Uuid) -> Result<PushBatch> {
        let message_count =
            northstar_message_postgres::offline::offline_message_count(&self.pool, user_id).await?;
        let pending_subscription_count =
            northstar_roster_postgres::roster::pending_presence_subscription_count(
                &self.pool, user_id,
            )
            .await?;
        let deliveries =
            northstar_message_postgres::push::claim_push_deliveries(&self.pool, user_id)
                .await?
                .into_iter()
                .map(|delivery| PushDelivery {
                    request_id: delivery.request_id,
                    service_jid: delivery.service_jid,
                    node: delivery.node,
                    options: delivery.options,
                })
                .collect();
        Ok(PushBatch {
            message_count,
            pending_subscription_count,
            deliveries,
        })
    }
    async fn mark_unroutable(&self, request_id: Uuid) -> Result<()> {
        northstar_message_postgres::push::mark_push_unroutable(&self.pool, request_id).await
    }
    async fn complete_response(
        &self,
        request_id: Uuid,
        sender_bare: &str,
        kind: PushResponseKind,
    ) -> Result<PushResponseOutcome> {
        let kind = match kind {
            PushResponseKind::Success => {
                northstar_message_postgres::push::PushResponseKind::Success
            }
            PushResponseKind::PermanentError => {
                northstar_message_postgres::push::PushResponseKind::PermanentError
            }
        };
        Ok(
            match northstar_message_postgres::push::complete_push_response(
                &self.pool,
                request_id,
                sender_bare,
                kind,
            )
            .await?
            {
                northstar_message_postgres::push::PushResponseOutcome::Completed => {
                    PushResponseOutcome::Completed
                }
                northstar_message_postgres::push::PushResponseOutcome::SubscriptionDisabled => {
                    PushResponseOutcome::SubscriptionDisabled
                }
                northstar_message_postgres::push::PushResponseOutcome::SenderMismatch => {
                    PushResponseOutcome::SenderMismatch
                }
                northstar_message_postgres::push::PushResponseOutcome::Unknown => {
                    PushResponseOutcome::Unknown
                }
            },
        )
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
            northstar_message_postgres::push::disable_push_subscriptions(
                &self.pool,
                recipient.id,
                service_jid,
                Some(node),
            )
            .await?
                > 0,
        )
    }
}
