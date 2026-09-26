//! XEP-0357 application boundary.
//!
//! Exposes subscription authorization, delivery claims and response correlation
//! through typed repository operations. A transport adapter owns XML and routing.

use anyhow::Result;
use std::future::Future;
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

#[derive(Clone, Copy)]
pub(crate) struct PushNotificationCounts {
    pub(crate) message_count: i64,
    pub(crate) pending_subscription_count: i64,
}

/// Transport-specific routing and telemetry for a claimed Push notification.
/// The application service owns claim, settlement and per-item ordering.
pub(crate) trait PushNotificationRouter: Send + Sync {
    fn route(
        &self,
        delivery: &PushDelivery,
        counts: PushNotificationCounts,
    ) -> impl Future<Output = Result<bool>> + Send;
    fn routed(&self);
    fn failed(&self);
    fn attempted(&self);
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

pub(crate) trait PushRepository: Send + Sync {
    fn enable(
        &self,
        user_id: Uuid,
        service_jid: &str,
        node: &str,
        options: Option<&str>,
    ) -> impl std::future::Future<Output = Result<PushEnableOutcome>> + Send;
    fn disable(
        &self,
        user_id: Uuid,
        service_jid: &str,
        node: Option<&str>,
    ) -> impl std::future::Future<Output = Result<u64>> + Send;
    fn claim_batch(
        &self,
        user_id: Uuid,
    ) -> impl std::future::Future<Output = Result<PushBatch>> + Send;
    fn mark_unroutable(
        &self,
        request_id: Uuid,
    ) -> impl std::future::Future<Output = Result<()>> + Send;
    fn complete_response(
        &self,
        request_id: Uuid,
        sender_bare: &str,
        kind: PushResponseKind,
    ) -> impl std::future::Future<Output = Result<PushResponseOutcome>> + Send;
    fn disable_from_service(
        &self,
        target_username: &str,
        service_jid: &str,
        node: &str,
    ) -> impl std::future::Future<Output = Result<bool>> + Send;
}
#[derive(Clone)]
pub(crate) struct PushService<R> {
    repository: R,
}
impl<R: PushRepository> PushService<R> {
    pub(crate) fn new(repository: R) -> Self {
        Self { repository }
    }
    pub(crate) async fn enable(
        &self,
        user_id: Uuid,
        service_jid: &str,
        node: &str,
        options: Option<&str>,
    ) -> Result<PushEnableOutcome> {
        self.repository
            .enable(user_id, service_jid, node, options)
            .await
    }
    pub(crate) async fn disable(
        &self,
        user_id: Uuid,
        service_jid: &str,
        node: Option<&str>,
    ) -> Result<u64> {
        self.repository.disable(user_id, service_jid, node).await
    }
    /// Dispatch only after the originating message has been accepted. A route
    /// failure is settled before the next claimed subscription is attempted;
    /// persistence errors stop the batch just as they did in the wire adapter.
    pub(crate) async fn dispatch_after_commit<T: PushNotificationRouter>(
        &self,
        user_id: Uuid,
        router: &T,
    ) -> Result<()> {
        let batch = self.repository.claim_batch(user_id).await?;
        let counts = PushNotificationCounts {
            message_count: batch.message_count,
            pending_subscription_count: batch.pending_subscription_count,
        };
        for delivery in batch.deliveries {
            if router.route(&delivery, counts).await? {
                router.routed();
            } else {
                self.repository.mark_unroutable(delivery.request_id).await?;
                router.failed();
                tracing::debug!(
                    service = %delivery.service_jid,
                    has_options = delivery.options.is_some(),
                    "push service could not be routed"
                );
            }
            router.attempted();
        }
        Ok(())
    }
    pub(crate) async fn complete_response(
        &self,
        request_id: Uuid,
        sender_bare: &str,
        kind: PushResponseKind,
    ) -> Result<PushResponseOutcome> {
        self.repository
            .complete_response(request_id, sender_bare, kind)
            .await
    }
    pub(crate) async fn disable_from_service(
        &self,
        target_username: &str,
        service_jid: &str,
        node: &str,
    ) -> Result<bool> {
        self.repository
            .disable_from_service(target_username, service_jid, node)
            .await
    }
}

#[cfg(test)]
#[path = "push_tests.rs"]
mod post_commit_tests;
