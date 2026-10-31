//! Account lifecycle application service.
//!
//! Applies registration policy and reserves password-work capacity before
//! requesting persistence. Each repository mutation owns its complete PoW,
//! invitation, credential or deletion transaction.

use anyhow::Result;
pub use northstar_abuse_policy::PowProof;
use northstar_abuse_policy::{GuardError, PowIntent, WorkRequirement};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use uuid::Uuid;

#[derive(Clone, Copy)]
pub struct AccountPolicy {
    pub invitation_required: bool,
    pub registration_rate_per_hour: u32,
    pub scram_iterations: u32,
    pub scram_sha1_enabled: bool,
}

#[derive(Debug)]
pub enum RegistrationOutcome {
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
pub struct RegistrationAccount {
    pub username: String,
}

#[derive(Debug)]
pub enum PasswordChangeOutcome {
    Changed,
    AbuseDenied(WorkRequirement),
    PasswordWorkOverloaded,
}

#[derive(Debug)]
pub enum DeletionQuiesceOutcome {
    Quiesced,
    Missing,
    AbuseDenied(WorkRequirement),
}

pub type RemovedRosterItem = (String, Option<String>, String, Option<String>);

#[derive(Debug)]
pub struct RemovedAccount {
    pub roster: Vec<RemovedRosterItem>,
    pub reverse_roster_changes: Vec<(Uuid, String, northstar_roster_core::RosterChange)>,
}

#[derive(Clone, Debug)]
pub struct DeletionRecoveryJob {
    pub user_id: Uuid,
    pub username: String,
    claim_token: Uuid,
    attempts: i32,
}
impl DeletionRecoveryJob {
    pub fn from_lease(user_id: Uuid, username: String, claim_token: Uuid, attempts: i32) -> Self {
        Self {
            user_id,
            username,
            claim_token,
            attempts,
        }
    }
    pub fn claim_token(&self) -> Uuid {
        self.claim_token
    }
    pub fn attempts(&self) -> i32 {
        self.attempts
    }
}

/// Opaque ownership fence for the HTTP registration guard stage. The
/// application service does not receive a SQLx transaction or DB lease type.
#[derive(Clone, Copy)]
pub struct RegistrationGuardLease {
    pub record_id: Uuid,
    pub lease_token: Uuid,
}

pub struct RegistrationGuardRequest<'a> {
    pub lease: RegistrationGuardLease,
    pub lease_seconds: i64,
    pub subject: &'a str,
    pub actors: &'a [String],
    pub proof: Option<&'a PowProof>,
    pub intent: &'a PowIntent,
}

pub enum RegistrationGuardOutcome {
    Verified,
    Denied(GuardError),
    LeaseLost,
}

/// The live public-registration setting shared with runtime administration.
/// Repository admission reads it after acquiring the idempotency lease; the
/// final transaction reads it again after password derivation.
#[derive(Clone)]
pub struct HttpRegistrationAvailability {
    closed: Arc<AtomicBool>,
    dependency_locked: bool,
    invitation_only: bool,
}

impl HttpRegistrationAvailability {
    pub fn new(closed: Arc<AtomicBool>, dependency_locked: bool, invitation_only: bool) -> Self {
        Self {
            closed,
            dependency_locked,
            invitation_only,
        }
    }

    pub fn is_closed(&self) -> bool {
        self.dependency_locked || self.closed.load(Ordering::Acquire)
    }

    pub fn requires_invitation(&self) -> bool {
        !self.is_closed() && self.invitation_only
    }
}

/// All HTTP registration work that may commit belongs to one repository
/// operation. The request identity is prepared by the transport from the
/// original body bytes, before the password is removed from that body.
pub struct HttpRegistrationRequest<'a> {
    pub idempotency: northstar_operations_core::api_mutations::IdempotencyRequest<'a>,
    pub username: &'a str,
    pub password: &'a str,
    pub invitation_token: Option<&'a str>,
    pub proof: Option<&'a PowProof>,
    pub intent: &'a PowIntent,
    pub subject: &'a str,
    pub actors: &'a [String],
    pub availability: HttpRegistrationAvailability,
}

pub enum HttpRegistrationOutcome {
    Created(Vec<u8>),
    Rejected(Vec<u8>),
    Replay(northstar_operations_core::api_mutations::IdempotentResponse),
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

pub struct RegistrationRequest<'a> {
    pub username: &'a str,
    pub password: &'a str,
    pub invitation_token: Option<&'a str>,
    pub proof: Option<&'a PowProof>,
    pub intent: &'a PowIntent,
    pub subject: &'a str,
    pub actors: &'a [String],
}

pub struct PasswordChangeRequest<'a> {
    pub subject: &'a str,
    pub actors: &'a [String],
    pub proof: Option<&'a PowProof>,
    pub intent: &'a PowIntent,
    pub user_id: Uuid,
    pub expected_auth_generation: i64,
    pub password: &'a str,
}

pub struct DeletionQuiesceRequest<'a> {
    pub subject: &'a str,
    pub actors: &'a [String],
    pub proof: Option<&'a PowProof>,
    pub intent: &'a PowIntent,
    pub user_id: Uuid,
    pub expected_auth_generation: i64,
}

pub trait AccountRepository: Send + Sync {
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
        password_work: northstar_security::password_work::PasswordWorkReservation,
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
pub struct AccountService<R> {
    repository: R,
    policy: AccountPolicy,
}
impl<R: AccountRepository> AccountService<R> {
    pub async fn register_http(
        &self,
        request: HttpRegistrationRequest<'_>,
    ) -> Result<HttpRegistrationOutcome> {
        self.repository.register_http(request, self.policy).await
    }
    pub fn new(
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
    pub async fn register(&self, request: RegistrationRequest<'_>) -> Result<RegistrationOutcome> {
        // Reserve bounded CPU capacity before borrowing a database connection.
        // The expensive work runs only after the body-bound v2 guard succeeds,
        // but proof consumption, actor advancement, invitation consumption,
        // credential creation and the account row remain one transaction. A
        // crash therefore rolls the proof back instead of burning it.
        let password_work = match northstar_security::password_work::reserve().await {
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

    pub async fn change_password(
        &self,
        request: PasswordChangeRequest<'_>,
    ) -> Result<PasswordChangeOutcome> {
        self.repository.change_password(request, self.policy).await
    }

    pub async fn quiesce_for_deletion(
        &self,
        request: DeletionQuiesceRequest<'_>,
    ) -> Result<DeletionQuiesceOutcome> {
        self.repository.quiesce_for_deletion(request).await
    }

    pub async fn delete_quiesced(&self, user_id: Uuid) -> Result<Option<RemovedAccount>> {
        self.repository.delete_quiesced(user_id).await
    }

    pub async fn claim_deletion_recovery(
        &self,
        limit: i64,
        lease_seconds: i64,
    ) -> Result<Vec<DeletionRecoveryJob>> {
        self.repository
            .claim_deletion_recovery(limit, lease_seconds)
            .await
    }

    pub async fn release_deletion_recovery(
        &self,
        job: &DeletionRecoveryJob,
        error_code: &str,
    ) -> Result<bool> {
        self.repository
            .release_deletion_recovery(job, error_code)
            .await
    }
}
