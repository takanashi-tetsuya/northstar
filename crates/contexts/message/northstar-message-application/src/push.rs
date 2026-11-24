//! XEP-0357 application boundary.
//!
//! Exposes subscription authorization, delivery claims and response correlation
//! through typed repository operations. A transport adapter owns XML and routing.

use anyhow::Result;
use northstar_message_core::{ActorGenerationFence, AuthenticatedMessageActor};
use std::future::Future;
use uuid::Uuid;

mod handoff;
pub use handoff::PushHandoffAuthority;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PushEnableOutcome {
    Enabled,
    QuotaExceeded,
    RateLimited,
    AccountUnavailable,
}

#[derive(Clone, Debug)]
pub struct PushDelivery {
    pub request_id: Uuid,
    pub service_jid: String,
    pub node: String,
    pub options: Option<String>,
}

#[derive(Debug)]
pub struct PushBatch {
    pub message_count: i64,
    pub pending_subscription_count: i64,
    pub deliveries: Vec<PushDelivery>,
}

#[derive(Clone, Copy)]
pub struct PushNotificationCounts {
    pub message_count: i64,
    pub pending_subscription_count: i64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PushHandoffOutcome {
    /// A route accepted the IQ, not a confirmation from the Push Service.
    QueueAccepted,
    Unroutable,
    StaleClaim,
}

/// Transport-specific routing and telemetry for a claimed Push notification.
/// The application service owns claim, settlement and per-item ordering.
pub trait PushNotificationRouter: Send + Sync {
    fn route(
        &self,
        authority: &impl PushHandoffAuthority,
        user_id: Uuid,
        delivery: &PushDelivery,
        counts: PushNotificationCounts,
    ) -> impl Future<Output = Result<PushHandoffOutcome>> + Send;
    fn queue_accepted(&self);
    fn failed(&self);
    fn attempted(&self);
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PushResponseKind {
    Success,
    PermanentError,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PushResponseOutcome {
    Completed,
    SubscriptionDisabled,
    SenderMismatch,
    Unknown,
}

pub trait PushRepository: PushHandoffAuthority {
    fn enable(
        &self,
        actor: ActorGenerationFence,
        service_jid: &str,
        node: &str,
        options: Option<&str>,
    ) -> impl std::future::Future<Output = Result<PushEnableOutcome>> + Send;
    fn disable(
        &self,
        actor: ActorGenerationFence,
        service_jid: &str,
        node: Option<&str>,
    ) -> impl std::future::Future<Output = Result<Option<u64>>> + Send;
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
pub struct PushService<R> {
    repository: R,
}
impl<R: PushRepository> PushService<R> {
    pub fn new(repository: R) -> Self {
        Self { repository }
    }
    pub async fn enable(
        &self,
        actor: &AuthenticatedMessageActor,
        service_jid: &str,
        node: &str,
        options: Option<&str>,
    ) -> Result<PushEnableOutcome> {
        self.repository
            .enable(actor.fence(), service_jid, node, options)
            .await
    }
    pub async fn disable(
        &self,
        actor: &AuthenticatedMessageActor,
        service_jid: &str,
        node: Option<&str>,
    ) -> Result<Option<u64>> {
        self.repository
            .disable(actor.fence(), service_jid, node)
            .await
    }
    /// Dispatch only after the originating message has been accepted. A route
    /// failure is settled before the next claimed subscription is attempted;
    /// persistence errors stop the batch just as they did in the wire adapter.
    pub async fn dispatch_after_commit<T: PushNotificationRouter>(
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
            match router
                .route(&self.repository, user_id, &delivery, counts)
                .await?
            {
                PushHandoffOutcome::QueueAccepted => router.queue_accepted(),
                PushHandoffOutcome::Unroutable => {
                    self.repository.mark_unroutable(delivery.request_id).await?;
                    router.failed();
                    tracing::debug!(
                        service = %delivery.service_jid,
                        has_options = delivery.options.is_some(),
                        "push service could not be routed"
                    );
                }
                PushHandoffOutcome::StaleClaim => continue,
            }
            router.attempted();
        }
        Ok(())
    }
    pub async fn complete_response(
        &self,
        request_id: Uuid,
        sender_bare: &str,
        kind: PushResponseKind,
    ) -> Result<PushResponseOutcome> {
        self.repository
            .complete_response(request_id, sender_bare, kind)
            .await
    }
    pub async fn disable_from_service(
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
