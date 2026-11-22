//! Credential transaction observations and receipt transfer.

use super::credential_invocation::CredentialInvocation;
use super::{CommitError, HandlerReturn};
use anyhow::{ensure, Result};
use northstar_auth_core::credential::{
    BindingPublication, CredentialCommitReceipt, FastCommitPlan, StagedLoginEpoch,
};
use std::sync::{Arc, Mutex};
use uuid::Uuid;

#[derive(Clone, Eq, PartialEq)]
pub(super) struct ReceiptProjection {
    pub(super) stage: Option<StagedLoginEpoch>,
    pub(super) binding: Option<BindingPublication>,
}
impl ReceiptProjection {
    pub(super) fn of(receipt: &CredentialCommitReceipt) -> Self {
        Self {
            stage: receipt.staged_login_epoch(),
            binding: receipt.binding_publication().cloned(),
        }
    }
}

// Preserve the original repository error identity at the SQL adapter boundary.
// The internal observation rejection has no fabricated repository error.
pub fn credential_error<E: Into<anyhow::Error>>(error: CommitError<E>) -> anyhow::Error {
    match error {
        CommitError::Observation(error) => error,
        CommitError::Repository(error) => error.into(),
    }
}

// Credential transaction observation is deliberately separate from the
// transport-gated publication Invocation below. A read handle cannot begin SQL.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CredentialKind {
    UnboundFast,
    Binding,
    Resume,
}
impl CredentialKind {
    pub fn index(self) -> usize {
        match self {
            Self::UnboundFast => 0,
            Self::Binding => 1,
            Self::Resume => 2,
        }
    }
}
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum CredentialCall {
    #[default]
    NotEntered,
    Entered,
    Ok,
    Err,
}
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum Eligibility {
    #[default]
    NotEntered,
    Entered,
    Returned(Option<bool>),
    Err,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CredentialRollbackSite {
    GenerationRefused,
    FastExpired,
    BindingReservationLost,
    BindingStageMissing,
    BindingFastExpired,
    ResumeStageMissing,
    ResumeClaimLost,
    ResumeFastExpired,
    ResumePrivacyMissing,
}
impl CredentialRollbackSite {
    pub(super) fn permitted(self, snapshot: &CredentialSnapshot) -> bool {
        let absent = |operation: CredentialPreparation| {
            snapshot.preparation[operation.index()] == PreparationResult::Absent
        };
        match self {
            Self::GenerationRefused => {
                matches!(
                    snapshot.eligibility,
                    Eligibility::Returned(None | Some(false))
                ) && !snapshot.transaction_returned
            }
            Self::FastExpired => {
                snapshot.kind == CredentialKind::UnboundFast && absent(CredentialPreparation::Fast)
            }
            Self::BindingReservationLost => {
                snapshot.kind == CredentialKind::Binding && absent(CredentialPreparation::Binding)
            }
            Self::BindingStageMissing => {
                snapshot.kind == CredentialKind::Binding && absent(CredentialPreparation::Stage)
            }
            Self::BindingFastExpired => {
                snapshot.kind == CredentialKind::Binding && absent(CredentialPreparation::Fast)
            }
            Self::ResumeStageMissing => {
                snapshot.kind == CredentialKind::Resume && absent(CredentialPreparation::Stage)
            }
            Self::ResumeClaimLost => {
                snapshot.kind == CredentialKind::Resume && absent(CredentialPreparation::Activation)
            }
            Self::ResumeFastExpired => {
                snapshot.kind == CredentialKind::Resume && absent(CredentialPreparation::Fast)
            }
            Self::ResumePrivacyMissing => {
                snapshot.kind == CredentialKind::Resume && absent(CredentialPreparation::Privacy)
            }
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CredentialPreparation {
    Binding,
    Stage,
    Fast,
    Activation,
    Privacy,
}
impl CredentialPreparation {
    pub(super) fn index(self) -> usize {
        self as usize
    }
}
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum PreparationResult {
    #[default]
    NotEntered,
    Entered,
    Present,
    Absent,
    Err,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CredentialReturned {
    Authenticated,
    UnknownCredentials,
    Disabled,
    StaleGeneration,
    ExpiredCredentials,
    ReplayedCredentials,
    IntegrityFailure,
    BackendFailure,
    BindingCommitted,
    BindingCredentialsExpired,
    BindingReservationLost,
    ResumeCommitted,
    ResumeCredentialsExpired,
    ResumeClaimLost,
    ResumePrivacySelectionMissing,
    Error,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CredentialTerminal {
    Returned,
    Cancelled,
    Panicked,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CredentialSnapshot {
    pub attempt: Uuid,
    pub frame: Uuid,
    pub connection: Uuid,
    pub ordinal: u8,
    pub kind: CredentialKind,
    pub service_started: bool,
    pub repository_started: bool,
    pub begin: CredentialCall,
    pub eligibility: Eligibility,
    pub transaction_returned: bool,
    pub preparation: [PreparationResult; 5],
    pub stage_id: Option<Uuid>,
    pub rollback: Option<(CredentialRollbackSite, CredentialCall)>,
    pub commit: CredentialCall,
    pub receipt_constructed: bool,
    pub returned: Option<CredentialReturned>,
    pub return_matches: bool,
    pub transferred: bool,
    pub handler: Option<HandlerReturn>,
    pub call_terminal: Option<CredentialTerminal>,
    pub integrity_failure: bool,
}
// These test-only joins describe the actual receipt instances at each cut.
// They contain no request projection and confer no credential authority.
#[cfg(any(test, feature = "test-support"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CredentialAttemptJoin {
    pub attempt: Uuid,
    pub frame: Uuid,
    pub connection: Uuid,
    pub ordinal: u8,
    pub kind: CredentialKind,
}
#[cfg(any(test, feature = "test-support"))]
impl CredentialAttemptJoin {
    fn of(snapshot: &CredentialSnapshot) -> Self {
        Self {
            attempt: snapshot.attempt,
            frame: snapshot.frame,
            connection: snapshot.connection,
            ordinal: snapshot.ordinal,
            kind: snapshot.kind,
        }
    }
}
#[cfg(any(test, feature = "test-support"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CredentialJoins {
    pub owner: CredentialAttemptJoin,
    pub constructed_receipt: Option<Uuid>,
    pub returned_receipt: Option<Uuid>,
    pub transferred_receipt: Option<Uuid>,
}

// All request values are private, non-bearer authority inputs. They are never
// formatted in diagnostics. In particular FAST issue-device and login-device
// remain different fields, and resume keeps the original claim and limits.
#[derive(Clone, Eq, PartialEq)]
pub(super) struct CredentialRequest {
    pub(super) user: Uuid,
    pub(super) generation: i64,
    pub(super) connection: Uuid,
    pub(super) device: Option<Uuid>,
    pub(super) fast: Option<FastCommitPlan>,
    pub(super) binding: Option<BindingPublication>,
    pub(super) resume: Option<ResumeRequest>,
}
#[derive(Clone, Eq, PartialEq)]
pub(super) struct ResumeRequest {
    session: Uuid,
    claim: Uuid,
    client_h: u32,
    acknowledged_count: usize,
    peer_ip: std::net::IpAddr,
    privacy: Option<String>,
    ttl: u64,
    lease: u64,
    max_stanzas: usize,
    max_bytes: usize,
}
impl CredentialRequest {
    pub(super) fn fast(
        user: Uuid,
        generation: i64,
        plan: &FastCommitPlan,
        device: Option<Uuid>,
        connection: Uuid,
    ) -> Self {
        Self {
            user,
            generation,
            connection,
            device,
            fast: Some(plan.clone()),
            binding: None,
            resume: None,
        }
    }
    #[allow(clippy::too_many_arguments)]
    pub(super) fn binding(
        connection: Uuid,
        user: Uuid,
        generation: i64,
        key: &str,
        lease: u64,
        device: Option<Uuid>,
        fast: Option<&FastCommitPlan>,
    ) -> Self {
        Self {
            user,
            generation,
            connection,
            device,
            fast: fast.cloned(),
            binding: Some(BindingPublication {
                connection_id: connection,
                user_id: user,
                full_jid: key.to_owned(),
                lease_seconds: lease,
            }),
            resume: None,
        }
    }
    pub(super) fn resume(request: &crate::finalization::SmResumeFinalizationRequest<'_>) -> Self {
        Self {
            user: request.user_id,
            generation: request.expected_auth_generation,
            connection: request.connection_id,
            device: request.user_agent_id,
            fast: request.fast_plan.cloned(),
            binding: None,
            resume: Some(ResumeRequest {
                session: request.session_id,
                claim: request.claim_token,
                client_h: request.client_h,
                acknowledged_count: request.acknowledged_count,
                peer_ip: request.peer_ip,
                privacy: request.active_privacy_list.map(str::to_owned),
                ttl: request.ttl_seconds,
                lease: request.live_lease_seconds,
                max_stanzas: request.max_stanzas,
                max_bytes: request.max_bytes,
            }),
        }
    }
}
pub(super) struct CredentialWitness {
    pub(super) attempt: Uuid,
    pub(super) request: CredentialRequest,
    pub(super) receipt: ReceiptProjection,
}
pub(super) struct CredentialState {
    pub(super) request: Option<CredentialRequest>,
    pub(super) snapshot: CredentialSnapshot,
    pub(super) stage: Option<StagedLoginEpoch>,
    pub(super) witness: Option<CredentialWitness>,
    pub(super) prospective: Option<CredentialWitness>,
    pub(super) constructed: Option<(Uuid, ReceiptProjection)>,
    pub(super) returned: Option<(Uuid, ReceiptProjection)>,
    #[cfg(any(test, feature = "test-support"))]
    transferred_receipt: Option<Uuid>,
    pub(super) integrity: bool,
}
#[derive(Clone)]
pub struct CredentialObservation(pub(super) Arc<Mutex<CredentialState>>);
impl std::fmt::Debug for CredentialObservation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CredentialObservation { request and receipt: [redacted] }")
    }
}
impl CredentialObservation {
    #[cfg(any(test, feature = "test-support"))]
    pub fn joins(&self) -> CredentialJoins {
        let state = self.0.lock().unwrap();
        CredentialJoins {
            owner: CredentialAttemptJoin::of(&state.snapshot),
            constructed_receipt: state.constructed.as_ref().map(|(id, _)| *id),
            returned_receipt: state.returned.as_ref().map(|(id, _)| *id),
            transferred_receipt: state.transferred_receipt,
        }
    }
    pub fn snapshot(&self) -> CredentialSnapshot {
        let state = self.0.lock().unwrap();
        let mut snapshot = state.snapshot.clone();
        snapshot.integrity_failure = !state.integrity;
        snapshot
    }
    pub fn handler_returned(&self, returned: HandlerReturn) {
        self.0
            .lock()
            .unwrap()
            .snapshot
            .handler
            .get_or_insert(returned);
    }
}
// Non-Clone: only the invocation owner can lend the recorder or transfer the
// returned receipt. Retained frame/publication clones are read observations.
pub struct PreparedCredential {
    pub(super) observation: CredentialObservation,
}
impl PreparedCredential {
    pub fn new(frame: Uuid, connection: Uuid, ordinal: u8, kind: CredentialKind) -> Self {
        Self {
            observation: CredentialObservation(Arc::new(Mutex::new(CredentialState {
                request: None,
                stage: None,
                witness: None,
                prospective: None,
                constructed: None,
                returned: None,
                #[cfg(any(test, feature = "test-support"))]
                transferred_receipt: None,
                integrity: true,
                snapshot: CredentialSnapshot {
                    attempt: Uuid::new_v4(),
                    frame,
                    connection,
                    ordinal,
                    kind,
                    service_started: false,
                    repository_started: false,
                    begin: CredentialCall::NotEntered,
                    eligibility: Eligibility::NotEntered,
                    transaction_returned: false,
                    preparation: [PreparationResult::NotEntered; 5],
                    stage_id: None,
                    rollback: None,
                    commit: CredentialCall::NotEntered,
                    receipt_constructed: false,
                    returned: None,
                    return_matches: false,
                    transferred: false,
                    handler: None,
                    call_terminal: None,
                    integrity_failure: false,
                },
            }))),
        }
    }
    pub fn observation(&self) -> CredentialObservation {
        self.observation.clone()
    }
    fn bind(
        &self,
        kind: CredentialKind,
        request: CredentialRequest,
    ) -> Result<CredentialInvocation<'_>> {
        let mut state = self.observation.0.lock().unwrap();
        ensure!(
            state.snapshot.kind == kind
                && state.snapshot.connection == request.connection
                && !state.snapshot.service_started
                && state.snapshot.handler.is_none(),
            "credential invocation mismatch"
        );
        state.request = Some(request);
        state.snapshot.service_started = true;
        Ok(CredentialInvocation { prepared: self })
    }
    pub fn fast(
        &self,
        user: Uuid,
        generation: i64,
        plan: &FastCommitPlan,
        device: Option<Uuid>,
        connection: Uuid,
    ) -> Result<CredentialInvocation<'_>> {
        self.bind(
            CredentialKind::UnboundFast,
            CredentialRequest::fast(user, generation, plan, device, connection),
        )
    }
    #[allow(clippy::too_many_arguments)]
    pub fn binding(
        &self,
        connection: Uuid,
        user: Uuid,
        generation: i64,
        key: &str,
        lease: u64,
        device: Option<Uuid>,
        fast: Option<&FastCommitPlan>,
    ) -> Result<CredentialInvocation<'_>> {
        self.bind(
            CredentialKind::Binding,
            CredentialRequest::binding(connection, user, generation, key, lease, device, fast),
        )
    }
    pub fn resume(
        &self,
        request: &crate::finalization::SmResumeFinalizationRequest<'_>,
    ) -> Result<CredentialInvocation<'_>> {
        self.bind(CredentialKind::Resume, CredentialRequest::resume(request))
    }
    pub fn transfer(
        &self,
        receipt: &CredentialCommitReceipt,
        frame: Uuid,
        connection: Uuid,
    ) -> Result<CredentialObservation> {
        let mut state = self.observation.0.lock().unwrap();
        let actual = (
            receipt.publication_identity(),
            ReceiptProjection::of(receipt),
        );
        ensure!(
            state.snapshot.frame == frame
                && state.snapshot.connection == connection
                && state.snapshot.handler.is_none()
                && !state.snapshot.transferred
                && state.snapshot.return_matches
                && state.integrity
                && state.constructed.as_ref() == Some(&actual)
                && state.returned.as_ref() == Some(&actual)
                && state
                    .witness
                    .as_ref()
                    .is_some_and(|witness| witness.attempt == state.snapshot.attempt
                        && Some(&witness.request) == state.request.as_ref()
                        && witness.receipt == actual.1),
            "credential receipt has no matching same-attempt COMMIT witness"
        );
        state.snapshot.transferred = true;
        #[cfg(any(test, feature = "test-support"))]
        {
            state.transferred_receipt = Some(receipt.publication_identity());
        }
        Ok(self.observation.clone())
    }
}
