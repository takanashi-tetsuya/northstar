//! REST login application port. Transport builds the canonical request identity;
//! persistence owns the guard, credential verification, and session transaction.
use anyhow::Result;
use northstar_abuse_policy::{GuardError, PowIntent, PowProof};
use northstar_operations_core::api_mutations::{
    IdempotencyRequest, IdempotentResponse, StoredApiResponse,
};

/// Narrow instrumentation capability for verifier-integrity events that must
/// be counted at detection, even if a later transaction cannot commit.
pub trait LoginFailureMetrics: Send + Sync {
    fn record_authentication_backend_failure(&self);
}

impl LoginFailureMetrics for northstar_telemetry::metrics::Metrics {
    fn record_authentication_backend_failure(&self) {
        self.authentication_backend_failures_total
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
}

#[derive(Clone)]
pub struct HttpLoginPolicy {
    pub domain: String,
    pub scram_iterations: u32,
    pub scram_sha1_enabled: bool,
    pub session_ttl_hours: i64,
}

pub struct HttpLoginRequest<'a> {
    pub idempotency: IdempotencyRequest<'a>,
    pub username: &'a str,
    pub password: &'a str,
    pub subject: &'a str,
    pub actors: &'a [String],
    pub proof: Option<&'a PowProof>,
    pub intent: &'a PowIntent,
}

pub enum HttpLoginOutcome {
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

pub trait HttpLoginRepository: Send + Sync {
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
pub struct HttpLoginService<R> {
    repository: R,
}

impl<R: HttpLoginRepository> HttpLoginService<R> {
    pub fn new(repository: R) -> Self {
        Self { repository }
    }

    pub async fn login(&self, request: HttpLoginRequest<'_>) -> Result<HttpLoginOutcome> {
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
