//! Account lifecycle application service.
//!
//! Applies registration policy and reserves password-work capacity before
//! requesting persistence. Each repository mutation owns its complete PoW,
//! invitation, credential or deletion transaction.

use crate::abuse::{GuardError, PowIntent, PowProof, WorkRequirement};
use anyhow::Result;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use uuid::Uuid;

#[derive(Clone, Copy)]
pub(crate) struct AccountPolicy {
    pub(crate) invitation_required: bool,
    pub(crate) registration_rate_per_hour: u32,
    pub(crate) scram_iterations: u32,
    pub(crate) scram_sha1_enabled: bool,
}

#[derive(Debug)]
pub(crate) enum RegistrationOutcome {
    Created(RegistrationAccount),
    AbuseDenied(WorkRequirement),
    InvalidUsername,
    InvitationRejected,
    UsernameTaken,
    RateLimited,
    CapacityExhausted,
    PasswordWorkOverloaded,
    Closed,
}

#[derive(Debug)]
pub(crate) struct RegistrationAccount {
    pub(crate) username: String,
}

#[derive(Debug)]
pub(crate) enum PasswordChangeOutcome {
    Changed,
    AbuseDenied(WorkRequirement),
    PasswordWorkOverloaded,
}

#[derive(Debug)]
pub(crate) enum DeletionQuiesceOutcome {
    Quiesced,
    Missing,
    AbuseDenied(WorkRequirement),
}

pub(crate) type RemovedRosterItem = (String, Option<String>, String, Option<String>);

#[derive(Debug)]
pub(crate) struct RemovedAccount {
    pub(crate) roster: Vec<RemovedRosterItem>,
    pub(crate) reverse_roster_changes: Vec<(Uuid, String, northstar_roster_core::RosterChange)>,
}

#[derive(Clone, Debug)]
pub struct DeletionRecoveryJob {
    pub user_id: Uuid,
    pub username: String,
    claim_token: Uuid,
    attempts: i32,
}
impl DeletionRecoveryJob {
    pub(crate) fn from_lease(
        user_id: Uuid,
        username: String,
        claim_token: Uuid,
        attempts: i32,
    ) -> Self {
        Self {
            user_id,
            username,
            claim_token,
            attempts,
        }
    }
    pub(crate) fn claim_token(&self) -> Uuid {
        self.claim_token
    }
    pub(crate) fn attempts(&self) -> i32 {
        self.attempts
    }
}

/// Opaque ownership fence for the HTTP registration guard stage. The
/// application service does not receive a SQLx transaction or DB lease type.
#[derive(Clone, Copy)]
pub(crate) struct RegistrationGuardLease {
    pub(crate) record_id: Uuid,
    pub(crate) lease_token: Uuid,
}

pub(crate) struct RegistrationGuardRequest<'a> {
    pub(crate) lease: RegistrationGuardLease,
    pub(crate) lease_seconds: i64,
    pub(crate) subject: &'a str,
    pub(crate) actors: &'a [String],
    pub(crate) proof: Option<&'a PowProof>,
    pub(crate) intent: &'a PowIntent,
}

pub(crate) enum RegistrationGuardOutcome {
    Verified,
    Denied(GuardError),
    LeaseLost,
}

/// The live public-registration setting shared with runtime administration.
/// Repository admission reads it after acquiring the idempotency lease; the
/// final transaction reads it again after password derivation.
#[derive(Clone)]
pub(crate) struct HttpRegistrationAvailability {
    closed: Arc<AtomicBool>,
    dependency_locked: bool,
    invitation_only: bool,
}

impl HttpRegistrationAvailability {
    pub(crate) fn new(
        closed: Arc<AtomicBool>,
        dependency_locked: bool,
        invitation_only: bool,
    ) -> Self {
        Self {
            closed,
            dependency_locked,
            invitation_only,
        }
    }

    pub(crate) fn is_closed(&self) -> bool {
        self.dependency_locked || self.closed.load(Ordering::Acquire)
    }

    pub(crate) fn requires_invitation(&self) -> bool {
        !self.is_closed() && self.invitation_only
    }
}

/// All HTTP registration work that may commit belongs to one repository
/// operation. The request identity is prepared by the transport from the
/// original body bytes, before the password is removed from that body.
pub(crate) struct HttpRegistrationRequest<'a> {
    pub(crate) idempotency: crate::services::api_mutations::IdempotencyRequest<'a>,
    pub(crate) username: &'a str,
    pub(crate) password: &'a str,
    pub(crate) invitation_token: Option<&'a str>,
    pub(crate) proof: Option<&'a PowProof>,
    pub(crate) intent: &'a PowIntent,
    pub(crate) subject: &'a str,
    pub(crate) actors: &'a [String],
    pub(crate) availability: HttpRegistrationAvailability,
}

pub(crate) enum HttpRegistrationOutcome {
    Created(Vec<u8>),
    Rejected(Vec<u8>),
    Replay(crate::services::api_mutations::IdempotentResponse),
    AbuseDenied(GuardError),
    Closed,
    RateLimited,
    CapacityExhausted,
    PasswordWorkOverloaded,
    InvalidUsername,
    InvitationRejected,
    UsernameTaken,
    IdempotencyConflict,
    ReplayInvalidated,
    Busy(u64),
    CapacityLimited(u64),
    InProgress(u64),
    LeaseLost,
}

pub(crate) struct RegistrationRequest<'a> {
    pub(crate) username: &'a str,
    pub(crate) password: &'a str,
    pub(crate) invitation_token: Option<&'a str>,
    pub(crate) proof: Option<&'a PowProof>,
    pub(crate) intent: &'a PowIntent,
    pub(crate) subject: &'a str,
    pub(crate) actors: &'a [String],
}

pub(crate) struct PasswordChangeRequest<'a> {
    pub(crate) subject: &'a str,
    pub(crate) actors: &'a [String],
    pub(crate) proof: Option<&'a PowProof>,
    pub(crate) intent: &'a PowIntent,
    pub(crate) user_id: Uuid,
    pub(crate) expected_auth_generation: i64,
    pub(crate) password: &'a str,
}

pub(crate) struct DeletionQuiesceRequest<'a> {
    pub(crate) subject: &'a str,
    pub(crate) actors: &'a [String],
    pub(crate) proof: Option<&'a PowProof>,
    pub(crate) intent: &'a PowIntent,
    pub(crate) user_id: Uuid,
    pub(crate) expected_auth_generation: i64,
}

pub(crate) trait AccountRepository: Send + Sync {
    fn register_http(
        &self,
        request: HttpRegistrationRequest<'_>,
        policy: AccountPolicy,
    ) -> impl std::future::Future<Output = Result<HttpRegistrationOutcome>> + Send;
    fn verify_registration_guard(
        &self,
        request: RegistrationGuardRequest<'_>,
    ) -> impl std::future::Future<Output = Result<RegistrationGuardOutcome>> + Send;
    fn register(
        &self,
        request: RegistrationRequest<'_>,
        policy: AccountPolicy,
        password_work: crate::password_work::PasswordWorkReservation,
    ) -> impl std::future::Future<Output = Result<RegistrationOutcome>> + Send;
    fn change_password(
        &self,
        request: PasswordChangeRequest<'_>,
        policy: AccountPolicy,
    ) -> impl std::future::Future<Output = Result<PasswordChangeOutcome>> + Send;
    fn quiesce_for_deletion(
        &self,
        request: DeletionQuiesceRequest<'_>,
    ) -> impl std::future::Future<Output = Result<DeletionQuiesceOutcome>> + Send;
    fn delete_quiesced(
        &self,
        user_id: Uuid,
    ) -> impl std::future::Future<Output = Result<Option<RemovedAccount>>> + Send;
    fn claim_deletion_recovery(
        &self,
        limit: i64,
        lease_seconds: i64,
    ) -> impl std::future::Future<Output = Result<Vec<DeletionRecoveryJob>>> + Send;
    fn release_deletion_recovery(
        &self,
        job: &DeletionRecoveryJob,
        error_code: &str,
    ) -> impl std::future::Future<Output = Result<bool>> + Send;
}

#[derive(Clone)]
pub(crate) struct AccountService<R> {
    repository: R,
    policy: AccountPolicy,
}
impl<R: AccountRepository> AccountService<R> {
    pub(crate) async fn register_http(
        &self,
        request: HttpRegistrationRequest<'_>,
    ) -> Result<HttpRegistrationOutcome> {
        self.repository.register_http(request, self.policy).await
    }
    pub(crate) fn new(
        repository: R,
        invitation_required: bool,
        registration_rate_per_hour: u32,
        scram_iterations: u32,
        scram_sha1_enabled: bool,
    ) -> Self {
        Self {
            repository,
            policy: AccountPolicy {
                invitation_required,
                registration_rate_per_hour,
                scram_iterations,
                scram_sha1_enabled,
            },
        }
    }
    pub(crate) async fn register(
        &self,
        request: RegistrationRequest<'_>,
    ) -> Result<RegistrationOutcome> {
        // Reserve bounded CPU capacity before borrowing a database connection.
        // The expensive work runs only after the body-bound v2 guard succeeds,
        // but proof consumption, actor advancement, invitation consumption,
        // credential creation and the account row remain one transaction. A
        // crash therefore rolls the proof back instead of burning it.
        let password_work = match crate::password_work::reserve().await {
            Ok(password_work) => password_work,
            Err(error) if error.is_overloaded() => {
                return Ok(RegistrationOutcome::PasswordWorkOverloaded)
            }
            Err(error) => return Err(anyhow::Error::new(error)),
        };

        self.repository
            .register(request, self.policy, password_work)
            .await
    }

    pub(crate) async fn change_password(
        &self,
        request: PasswordChangeRequest<'_>,
    ) -> Result<PasswordChangeOutcome> {
        self.repository.change_password(request, self.policy).await
    }

    pub(crate) async fn quiesce_for_deletion(
        &self,
        request: DeletionQuiesceRequest<'_>,
    ) -> Result<DeletionQuiesceOutcome> {
        self.repository.quiesce_for_deletion(request).await
    }

    pub(crate) async fn delete_quiesced(&self, user_id: Uuid) -> Result<Option<RemovedAccount>> {
        self.repository.delete_quiesced(user_id).await
    }

    pub(crate) async fn claim_deletion_recovery(
        &self,
        limit: i64,
        lease_seconds: i64,
    ) -> Result<Vec<DeletionRecoveryJob>> {
        self.repository
            .claim_deletion_recovery(limit, lease_seconds)
            .await
    }

    pub(crate) async fn release_deletion_recovery(
        &self,
        job: &DeletionRecoveryJob,
        error_code: &str,
    ) -> Result<bool> {
        self.repository
            .release_deletion_recovery(job, error_code)
            .await
    }
}
