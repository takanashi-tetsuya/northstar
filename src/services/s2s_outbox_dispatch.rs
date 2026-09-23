//! Durable S2S dispatch capability. Network writes and live-route ownership
//! stay with transport; each queue mutation is a fenced repository operation.
use anyhow::{Context, Result};
use northstar_federation_core::{ExpiredS2sOutboxItem, S2sOutboxItem};
use uuid::Uuid;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OutboxFailureDisposition {
    RetryScheduled,
    Expired,
    Dropped,
    LeaseLost,
}

/// A non-authoritative observation. The caller still validates the live route
/// and exact attempt before issuing the conditional wake operation.
pub(crate) struct RouteRecoveryHead {
    pub(crate) id: Uuid,
    pub(crate) target_domain: String,
    pub(crate) stanza: String,
    pub(crate) attempt_count: i32,
    pub(crate) retry_due: bool,
    pub(crate) claim_in_flight: bool,
}

pub(crate) trait S2sOutboxDispatchRepository: Send + Sync {
    fn renew(
        &self,
        id: Uuid,
        token: Uuid,
        lease_seconds: u64,
    ) -> impl std::future::Future<Output = Result<bool>> + Send;
    fn complete(
        &self,
        id: Uuid,
        token: Uuid,
    ) -> impl std::future::Future<Output = Result<bool>> + Send;
    fn fail(
        &self,
        item: &S2sOutboxItem,
        error: &str,
        retry_base_seconds: u64,
        retry_max_seconds: u64,
        max_attempts: i32,
        permanent: bool,
    ) -> impl std::future::Future<Output = Result<OutboxFailureDisposition>> + Send;
    fn expire(
        &self,
        limit: i64,
    ) -> impl std::future::Future<Output = Result<Vec<ExpiredS2sOutboxItem>>> + Send;
    fn claim_excluding_domains(
        &self,
        limit: i64,
        lease_seconds: u64,
        excluded_domains: &[String],
    ) -> impl std::future::Future<Output = Result<Vec<S2sOutboxItem>>> + Send;
    fn claim_for_domains(
        &self,
        limit: i64,
        lease_seconds: u64,
        domains: &[String],
    ) -> impl std::future::Future<Output = Result<Vec<S2sOutboxItem>>> + Send;
    fn route_head(
        &self,
        domain: &str,
    ) -> impl std::future::Future<Output = Result<Option<RouteRecoveryHead>>> + Send;
    fn wake_route_head(
        &self,
        id: Uuid,
        domain: &str,
        attempt_count: i32,
    ) -> impl std::future::Future<Output = Result<bool>> + Send;
}

#[derive(Clone, Copy)]
pub(crate) struct S2sOutboxDispatchPolicy {
    pub(crate) claim_batch: i64,
    pub(crate) lease_seconds: u64,
    pub(crate) retry_base_seconds: u64,
    pub(crate) retry_max_seconds: u64,
    pub(crate) max_attempts: i32,
}

#[derive(Clone)]
pub(crate) struct S2sOutboxDispatchService<R> {
    repository: R,
    policy: S2sOutboxDispatchPolicy,
}

impl<R: S2sOutboxDispatchRepository> S2sOutboxDispatchService<R> {
    pub(crate) fn new(repository: R, policy: S2sOutboxDispatchPolicy) -> Self {
        Self { repository, policy }
    }

    pub(crate) fn lease_seconds(&self) -> u64 {
        self.policy.lease_seconds
    }

    pub(crate) fn recovery_batch_limit(&self) -> Result<usize> {
        usize::try_from(self.policy.claim_batch)
            .context("S2S outbox recovery batch must be nonnegative")
    }

    pub(crate) async fn renew(&self, id: Uuid, token: Uuid) -> Result<bool> {
        self.repository
            .renew(id, token, self.policy.lease_seconds)
            .await
    }

    pub(crate) async fn complete(&self, id: Uuid, token: Uuid) -> Result<bool> {
        self.repository.complete(id, token).await
    }

    pub(crate) async fn fail(
        &self,
        item: &S2sOutboxItem,
        error: &str,
        permanent: bool,
    ) -> Result<OutboxFailureDisposition> {
        self.repository
            .fail(
                item,
                error,
                self.policy.retry_base_seconds,
                self.policy.retry_max_seconds,
                self.policy.max_attempts,
                permanent,
            )
            .await
    }

    pub(crate) async fn expire(&self) -> Result<Vec<ExpiredS2sOutboxItem>> {
        self.repository.expire(self.policy.claim_batch).await
    }

    pub(crate) async fn claim_excluding_domains(
        &self,
        excluded_domains: &[String],
    ) -> Result<Vec<S2sOutboxItem>> {
        self.repository
            .claim_excluding_domains(
                self.policy.claim_batch,
                self.policy.lease_seconds,
                excluded_domains,
            )
            .await
    }

    /// Components claim one row at a time only when their socket is ready;
    /// the caller supplies that explicit batch size rather than dispatcher policy.
    pub(crate) async fn claim_for_domains(
        &self,
        limit: i64,
        domains: &[String],
    ) -> Result<Vec<S2sOutboxItem>> {
        self.repository
            .claim_for_domains(limit, self.policy.lease_seconds, domains)
            .await
    }

    pub(crate) async fn route_head(&self, domain: &str) -> Result<Option<RouteRecoveryHead>> {
        self.repository.route_head(domain).await
    }

    pub(crate) async fn wake_route_head(
        &self,
        id: Uuid,
        domain: &str,
        attempt_count: i32,
    ) -> Result<bool> {
        self.repository
            .wake_route_head(id, domain, attempt_count)
            .await
    }
}
