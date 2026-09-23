//! REST login application port. Transport builds the canonical request identity;
//! persistence owns the guard, credential verification, and session transaction.
use crate::abuse::{GuardError, PowIntent, PowProof};
use crate::services::api_mutations::{IdempotencyRequest, IdempotentResponse, StoredApiResponse};
use anyhow::Result;

/// Narrow instrumentation capability for verifier-integrity events that must
/// be counted at detection, even if a later transaction cannot commit.
pub(crate) trait LoginFailureMetrics: Send + Sync {
    fn record_authentication_backend_failure(&self);
}

impl LoginFailureMetrics for crate::metrics::Metrics {
    fn record_authentication_backend_failure(&self) {
        self.authentication_backend_failures_total
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
}

#[derive(Clone)]
pub(crate) struct HttpLoginPolicy {
    pub(crate) domain: String,
    pub(crate) scram_iterations: u32,
    pub(crate) scram_sha1_enabled: bool,
    pub(crate) session_ttl_hours: i64,
}

pub(crate) struct HttpLoginRequest<'a> {
    pub(crate) idempotency: IdempotencyRequest<'a>,
    pub(crate) username: &'a str,
    pub(crate) password: &'a str,
    pub(crate) subject: &'a str,
    pub(crate) actors: &'a [String],
    pub(crate) proof: Option<&'a PowProof>,
    pub(crate) intent: &'a PowIntent,
}

pub(crate) enum HttpLoginOutcome {
    Committed(StoredApiResponse),
    Replay(IdempotentResponse),
    Unauthorized,
    AbuseDenied(GuardError),
    PasswordWorkOverloaded,
    BackendUnavailable,
    IdempotencyConflict,
    ReplayInvalidated,
    Busy(u64),
    CapacityLimited(u64),
    InProgress(u64),
    LeaseLost,
}

pub(crate) trait HttpLoginRepository: Send + Sync {
    fn login(
        &self,
        request: HttpLoginRequest<'_>,
    ) -> impl std::future::Future<Output = Result<HttpLoginOutcome>> + Send;
    fn record_invalid_login(
        &self,
        actors: &[String],
    ) -> impl std::future::Future<Output = Result<()>> + Send;
}

#[derive(Clone)]
pub(crate) struct HttpLoginService<R> {
    repository: R,
}

impl<R: HttpLoginRepository> HttpLoginService<R> {
    pub(crate) fn new(repository: R) -> Self {
        Self { repository }
    }

    pub(crate) async fn login(&self, request: HttpLoginRequest<'_>) -> Result<HttpLoginOutcome> {
        if request.username.is_empty()
            || request.username.len() > 1024
            || request.password.is_empty()
            || request.password.len() > 1024
        {
            self.repository.record_invalid_login(request.actors).await?;
            return Ok(HttpLoginOutcome::Unauthorized);
        }
        self.repository.login(request).await
    }
}
