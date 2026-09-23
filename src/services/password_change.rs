//! Complete REST password-change command and transport-neutral outcomes.

use crate::abuse::{PowIntent, PowProof};
use crate::services::api_mutations::{IdempotencyRequest, IdempotentResponse, StoredApiResponse};
use anyhow::Result;
use std::net::IpAddr;
use uuid::Uuid;

pub(crate) struct PasswordChangeCommand<'a> {
    pub(crate) idempotency: IdempotencyRequest<'a>,
    pub(crate) presented_session: &'a str,
    pub(crate) current_password: &'a str,
    pub(crate) new_password: &'a str,
    pub(crate) proof: Option<&'a PowProof>,
    pub(crate) intent: &'a PowIntent,
    pub(crate) peer_ip: IpAddr,
}

#[derive(Clone, Copy)]
pub(crate) struct PasswordChangePolicy {
    pub(crate) scram_iterations: u32,
    pub(crate) scram_sha1_enabled: bool,
}

pub(crate) struct DisconnectedAccount {
    pub(crate) user_id: Uuid,
    pub(crate) username: String,
}

pub(crate) enum PasswordChangeResult {
    Replay(IdempotentResponse),
    Fresh(StoredApiResponse),
    RateLimited(StoredApiResponse),
    Changed(StoredApiResponse, DisconnectedAccount),
    Unauthorized,
    IdempotencyConflict,
    ReplayInvalidated,
    Busy(u64),
    CapacityLimited(u64),
    InProgress(u64),
    LeaseLost,
    WorkerOverloaded,
    VerifierUnavailable,
    PublicationUnavailable,
}

pub(crate) trait PasswordChangeRepository: Send + Sync {
    fn execute(
        &self,
        command: PasswordChangeCommand<'_>,
        policy: PasswordChangePolicy,
        invalid_input: bool,
    ) -> impl std::future::Future<Output = Result<PasswordChangeResult>> + Send;
}

#[derive(Clone)]
pub(crate) struct PasswordChangeService<R> {
    repository: R,
    policy: PasswordChangePolicy,
}

impl<R: PasswordChangeRepository> PasswordChangeService<R> {
    pub(crate) fn new(repository: R, scram_iterations: u32, scram_sha1_enabled: bool) -> Self {
        Self {
            repository,
            policy: PasswordChangePolicy {
                scram_iterations,
                scram_sha1_enabled,
            },
        }
    }

    pub(crate) async fn execute(
        &self,
        command: PasswordChangeCommand<'_>,
    ) -> Result<PasswordChangeResult> {
        let invalid_input = command.current_password.is_empty()
            || command.current_password.len() > 1024
            || crate::auth::validate_password(command.new_password).is_err();
        self.repository
            .execute(command, self.policy, invalid_input)
            .await
    }
}
