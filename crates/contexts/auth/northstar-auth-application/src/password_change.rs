//! Complete REST password-change command and transport-neutral outcomes.

use anyhow::Result;
use northstar_abuse_policy::{PowIntent, PowProof};
use northstar_operations_core::api_mutations::{
    IdempotencyRequest, IdempotentResponse, StoredApiResponse,
};
use std::net::IpAddr;
use uuid::Uuid;

pub struct PasswordChangeCommand<'a> {
    pub idempotency: IdempotencyRequest<'a>,
    pub presented_session: &'a str,
    pub current_password: &'a str,
    pub new_password: &'a str,
    pub proof: Option<&'a PowProof>,
    pub intent: &'a PowIntent,
    pub peer_ip: IpAddr,
}

#[derive(Clone, Copy)]
pub struct PasswordChangePolicy {
    pub scram_iterations: u32,
    pub scram_sha1_enabled: bool,
}

pub struct DisconnectedAccount {
    pub user_id: Uuid,
    pub username: String,
}

pub enum PasswordChangeResult {
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

pub trait PasswordChangeRepository: Send + Sync {
    fn execute(
        &self,
        command: PasswordChangeCommand<'_>,
        policy: PasswordChangePolicy,
        invalid_input: bool,
    ) -> impl std::future::Future<Output = Result<PasswordChangeResult>> + Send;
}

#[derive(Clone)]
pub struct PasswordChangeService<R> {
    repository: R,
    policy: PasswordChangePolicy,
}

impl<R: PasswordChangeRepository> PasswordChangeService<R> {
    pub fn new(repository: R, scram_iterations: u32, scram_sha1_enabled: bool) -> Self {
        Self {
            repository,
            policy: PasswordChangePolicy {
                scram_iterations,
                scram_sha1_enabled,
            },
        }
    }

    pub async fn execute(
        &self,
        command: PasswordChangeCommand<'_>,
    ) -> Result<PasswordChangeResult> {
        let invalid_input = command.current_password.is_empty()
            || command.current_password.len() > 1024
            || northstar_auth_core::validate_password(command.new_password).is_err();
        self.repository
            .execute(command, self.policy, invalid_input)
            .await
    }
}
