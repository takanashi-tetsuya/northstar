//! XEP-0357 application boundary.
//!
//! Protocol code validates XML and routes the resulting notification. This
//! service owns subscription authorization, coalescing, response correlation
//! and all PostgreSQL capabilities used by the push workflow.

use crate::db;
use anyhow::Result;
use sqlx::PgPool;
use uuid::Uuid;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PushEnableOutcome {
    Enabled,
    QuotaExceeded,
    RateLimited,
}

#[derive(Clone, Debug)]
pub(crate) struct PushDelivery {
    pub(crate) request_id: Uuid,
    pub(crate) service_jid: String,
    pub(crate) node: String,
    pub(crate) options: Option<String>,
}

#[derive(Debug)]
pub(crate) struct PushBatch {
    pub(crate) message_count: i64,
    pub(crate) pending_subscription_count: i64,
    pub(crate) deliveries: Vec<PushDelivery>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PushResponseKind {
    Success,
    PermanentError,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PushResponseOutcome {
    Completed,
    SubscriptionDisabled,
    SenderMismatch,
    Unknown,
}

#[derive(Clone)]
pub(crate) struct PushService {
    pool: PgPool,
}

impl PushService {
    pub(crate) fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub(crate) async fn enable(
        &self,
        user_id: Uuid,
        service_jid: &str,
        node: &str,
        options: Option<&str>,
    ) -> Result<PushEnableOutcome> {
        Ok(
            match db::enable_push_subscription(&self.pool, user_id, service_jid, node, options)
                .await?
            {
                db::PushEnableOutcome::Enabled => PushEnableOutcome::Enabled,
                db::PushEnableOutcome::QuotaExceeded => PushEnableOutcome::QuotaExceeded,
                db::PushEnableOutcome::RateLimited => PushEnableOutcome::RateLimited,
            },
        )
    }

    pub(crate) async fn disable(
        &self,
        user_id: Uuid,
        service_jid: &str,
        node: Option<&str>,
    ) -> Result<u64> {
        db::disable_push_subscriptions(&self.pool, user_id, service_jid, node).await
    }

    pub(crate) async fn claim_batch(&self, user_id: Uuid) -> Result<PushBatch> {
        let message_count = db::offline_message_count(&self.pool, user_id).await?;
        let pending_subscription_count =
            db::pending_presence_subscription_count(&self.pool, user_id).await?;
        let deliveries = db::claim_push_deliveries(&self.pool, user_id)
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

    pub(crate) async fn mark_unroutable(&self, request_id: Uuid) -> Result<()> {
        db::mark_push_unroutable(&self.pool, request_id).await
    }

    pub(crate) async fn complete_response(
        &self,
        request_id: Uuid,
        sender_bare: &str,
        kind: PushResponseKind,
    ) -> Result<PushResponseOutcome> {
        let kind = match kind {
            PushResponseKind::Success => db::PushResponseKind::Success,
            PushResponseKind::PermanentError => db::PushResponseKind::PermanentError,
        };
        Ok(
            match db::complete_push_response(&self.pool, request_id, sender_bare, kind).await? {
                db::PushResponseOutcome::Completed => PushResponseOutcome::Completed,
                db::PushResponseOutcome::SubscriptionDisabled => {
                    PushResponseOutcome::SubscriptionDisabled
                }
                db::PushResponseOutcome::SenderMismatch => PushResponseOutcome::SenderMismatch,
                db::PushResponseOutcome::Unknown => PushResponseOutcome::Unknown,
            },
        )
    }

    /// Authorize and apply a push-service initiated disable by deleting the
    /// exact account/service/node tuple. Avoiding a list-then-delete sequence
    /// removes a needless TOCTOU window and keeps subscription details out of
    /// the stanza layer.
    pub(crate) async fn disable_from_service(
        &self,
        target_username: &str,
        service_jid: &str,
        node: &str,
    ) -> Result<bool> {
        let Some(recipient) = db::find_user(&self.pool, target_username).await? else {
            return Ok(false);
        };
        Ok(
            db::disable_push_subscriptions(&self.pool, recipient.id, service_jid, Some(node))
                .await?
                > 0,
        )
    }
}
