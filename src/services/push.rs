//! XEP-0357 application boundary.
//!
//! Exposes subscription authorization, delivery claims and response correlation
//! through typed repository operations. The protocol adapter owns XML and routing.

use anyhow::Result;
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
    pub(crate) async fn claim_batch(&self, user_id: Uuid) -> Result<PushBatch> {
        self.repository.claim_batch(user_id).await
    }
    pub(crate) async fn mark_unroutable(&self, request_id: Uuid) -> Result<()> {
        self.repository.mark_unroutable(request_id).await
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
