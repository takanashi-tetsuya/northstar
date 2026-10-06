//! Auth publication facts beginning at an actual returned credential receipt.
//! These observations neither recreate that receipt nor authorize SQL or I/O.
use super::{
    AuthenticationResult, BindingPublication, CredentialCommitReceipt, FastCommitPlan,
    StagedLoginEpoch,
};
use anyhow::{ensure, Result};
use std::{
    future::Future,
    sync::{Arc, Mutex},
};
use uuid::Uuid;

#[derive(Clone, Eq, PartialEq)]
struct ReceiptProjection {
    stage: Option<StagedLoginEpoch>,
    binding: Option<BindingPublication>,
}
impl ReceiptProjection {
    fn of(receipt: &CredentialCommitReceipt) -> Self {
        Self {
            stage: receipt.staged_login_epoch(),
            binding: receipt.binding_publication().cloned(),
        }
    }
}

// Preserve the original repository error identity at the SQL adapter boundary.
// The internal observation rejection has no fabricated repository error.
pub(crate) fn credential_error<E: Into<anyhow::Error>>(error: CommitError<E>) -> anyhow::Error {
    match error {
        CommitError::Observation(error) => error,
        CommitError::Repository(error) => error.into(),
    }
}

// Credential transaction observation is deliberately separate from the
// transport-gated publication Invocation below. A read handle cannot begin SQL.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CredentialKind {
    UnboundFast,
    Binding,
    Resume,
}
impl CredentialKind {
    pub(crate) fn index(self) -> usize {
        match self {
            Self::UnboundFast => 0,
            Self::Binding => 1,
            Self::Resume => 2,
        }
    }
}
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) enum CredentialCall {
    #[default]
    NotEntered,
    Entered,
    Ok,
    Err,
}
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) enum Eligibility {
    #[default]
    NotEntered,
    Entered,
    Returned(Option<bool>),
    Err,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CredentialRollbackSite {
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
    fn permitted(self, snapshot: &CredentialSnapshot) -> bool {
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
pub(crate) enum CredentialPreparation {
    Binding,
    Stage,
    Fast,
    Activation,
    Privacy,
}
impl CredentialPreparation {
    fn index(self) -> usize {
        self as usize
    }
}
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) enum PreparationResult {
    #[default]
    NotEntered,
    Entered,
    Present,
    Absent,
    Err,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CredentialReturned {
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
pub(crate) enum CredentialTerminal {
    Returned,
    Cancelled,
    Panicked,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CredentialSnapshot {
    pub(crate) attempt: Uuid,
    pub(crate) frame: Uuid,
    pub(crate) connection: Uuid,
    pub(crate) ordinal: u8,
    pub(crate) kind: CredentialKind,
    pub(crate) service_started: bool,
    pub(crate) repository_started: bool,
    pub(crate) begin: CredentialCall,
    pub(crate) eligibility: Eligibility,
    pub(crate) transaction_returned: bool,
    pub(crate) preparation: [PreparationResult; 5],
    pub(crate) stage_id: Option<Uuid>,
    pub(crate) rollback: Option<(CredentialRollbackSite, CredentialCall)>,
    pub(crate) commit: CredentialCall,
    pub(crate) receipt_constructed: bool,
    pub(crate) returned: Option<CredentialReturned>,
    pub(crate) return_matches: bool,
    pub(crate) transferred: bool,
    pub(crate) handler: Option<HandlerReturn>,
    pub(crate) call_terminal: Option<CredentialTerminal>,
    pub(crate) integrity_failure: bool,
}
// All request values are private, non-bearer authority inputs. They are never
// formatted in diagnostics. In particular FAST issue-device and login-device
// remain different fields, and resume keeps the original claim and limits.
#[derive(Clone, Eq, PartialEq)]
struct CredentialRequest {
    user: Uuid,
    generation: i64,
    connection: Uuid,
    device: Option<Uuid>,
    fast: Option<FastCommitPlan>,
    binding: Option<BindingPublication>,
    resume: Option<ResumeRequest>,
}
#[derive(Clone, Eq, PartialEq)]
struct ResumeRequest {
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
    fn fast(
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
    fn binding(
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
    fn resume(request: &crate::services::sm::SmResumeFinalizationRequest<'_>) -> Self {
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
struct CredentialWitness {
    attempt: Uuid,
    request: CredentialRequest,
    receipt: ReceiptProjection,
}
struct CredentialState {
    request: Option<CredentialRequest>,
    snapshot: CredentialSnapshot,
    stage: Option<StagedLoginEpoch>,
    witness: Option<CredentialWitness>,
    prospective: Option<CredentialWitness>,
    constructed: Option<(Uuid, ReceiptProjection)>,
    returned: Option<(Uuid, ReceiptProjection)>,
    integrity: bool,
}
#[derive(Clone)]
pub(crate) struct CredentialObservation(Arc<Mutex<CredentialState>>);
impl std::fmt::Debug for CredentialObservation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CredentialObservation { request and receipt: [redacted] }")
    }
}
impl CredentialObservation {
    pub(crate) fn snapshot(&self) -> CredentialSnapshot {
        let state = self.0.lock().unwrap();
        let mut snapshot = state.snapshot.clone();
        snapshot.integrity_failure = !state.integrity;
        snapshot
    }
    pub(crate) fn handler_returned(&self, returned: HandlerReturn) {
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
pub(crate) struct PreparedCredential {
    observation: CredentialObservation,
}
impl PreparedCredential {
    pub(crate) fn new(frame: Uuid, connection: Uuid, ordinal: u8, kind: CredentialKind) -> Self {
        Self {
            observation: CredentialObservation(Arc::new(Mutex::new(CredentialState {
                request: None,
                stage: None,
                witness: None,
                prospective: None,
                constructed: None,
                returned: None,
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
    pub(crate) fn observation(&self) -> CredentialObservation {
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
    pub(crate) fn fast(
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
    pub(crate) fn binding(
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
    pub(crate) fn resume(
        &self,
        request: &crate::services::sm::SmResumeFinalizationRequest<'_>,
    ) -> Result<CredentialInvocation<'_>> {
        self.bind(CredentialKind::Resume, CredentialRequest::resume(request))
    }
    pub(crate) fn transfer(
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
        Ok(self.observation.clone())
    }
}
pub(crate) struct CredentialInvocation<'a> {
    prepared: &'a PreparedCredential,
}
impl Drop for CredentialInvocation<'_> {
    fn drop(&mut self) {
        let mut state = self.prepared.observation.0.lock().unwrap();
        let terminal = if state.snapshot.returned.is_some() {
            CredentialTerminal::Returned
        } else if std::thread::panicking() {
            CredentialTerminal::Panicked
        } else {
            CredentialTerminal::Cancelled
        };
        state.snapshot.call_terminal.get_or_insert(terminal);
    }
}
impl CredentialInvocation<'_> {
    fn update(&self, update: impl FnOnce(&mut CredentialState)) {
        let mut state = self.prepared.observation.0.lock().unwrap();
        if state.snapshot.handler.is_some() || state.snapshot.returned.is_some() {
            state.integrity = false;
            return;
        }
        update(&mut state);
    }
    fn preparation_update(&self, update: impl FnOnce(&mut CredentialState)) {
        self.update(|state| {
            if !state.snapshot.transaction_returned
                || state.snapshot.commit != CredentialCall::NotEntered
                || state.snapshot.rollback.is_some()
            {
                state.integrity = false;
                return;
            }
            update(state);
        });
    }
    fn start(
        &self,
        allowed: impl FnOnce(&CredentialSnapshot) -> bool,
        enter: impl FnOnce(&mut CredentialSnapshot),
    ) -> Result<()> {
        let mut state = self.prepared.observation.0.lock().unwrap();
        if state.snapshot.handler.is_some()
            || state.snapshot.returned.is_some()
            || !state.integrity
            || !state.snapshot.repository_started
            || !allowed(&state.snapshot)
        {
            state.integrity = false;
            anyhow::bail!("credential operation is duplicate, late or out of order");
        }
        enter(&mut state.snapshot);
        Ok(())
    }
    fn enter_repository(&self, request: CredentialRequest) -> Result<()> {
        let mut state = self.prepared.observation.0.lock().unwrap();
        ensure!(
            state.request.as_ref() == Some(&request)
                && !state.snapshot.repository_started
                && state.snapshot.returned.is_none()
                && state.snapshot.handler.is_none(),
            "credential repository invocation mismatch"
        );
        state.snapshot.repository_started = true;
        Ok(())
    }
    pub(crate) fn enter_fast(
        &self,
        user: Uuid,
        generation: i64,
        plan: &FastCommitPlan,
        device: Option<Uuid>,
        connection: Uuid,
    ) -> Result<()> {
        self.enter_repository(CredentialRequest::fast(
            user, generation, plan, device, connection,
        ))
    }
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn enter_binding(
        &self,
        connection: Uuid,
        user: Uuid,
        generation: i64,
        key: &str,
        lease: u64,
        device: Option<Uuid>,
        fast: Option<&FastCommitPlan>,
    ) -> Result<()> {
        self.enter_repository(CredentialRequest::binding(
            connection, user, generation, key, lease, device, fast,
        ))
    }
    pub(crate) fn enter_resume(
        &self,
        request: &crate::services::sm::SmResumeFinalizationRequest<'_>,
    ) -> Result<()> {
        self.enter_repository(CredentialRequest::resume(request))
    }
    pub(crate) async fn begin<F, T, E>(
        observation: Option<&Self>,
        future: F,
    ) -> std::result::Result<T, CommitError<E>>
    where
        F: Future<Output = std::result::Result<T, E>>,
    {
        if let Some(observation) = observation {
            observation
                .start(
                    |snapshot| snapshot.begin == CredentialCall::NotEntered,
                    |snapshot| snapshot.begin = CredentialCall::Entered,
                )
                .map_err(CommitError::Observation)?;
        }
        let result = future.await.map_err(CommitError::Repository);
        if let Some(observation) = observation {
            observation.update(|state| {
                state.snapshot.begin = if result.is_ok() {
                    CredentialCall::Ok
                } else {
                    CredentialCall::Err
                }
            });
        }
        result
    }
    pub(crate) async fn eligibility<F, E>(
        observation: Option<&Self>,
        future: F,
    ) -> std::result::Result<Option<bool>, CommitError<E>>
    where
        F: Future<Output = std::result::Result<Option<bool>, E>>,
    {
        if let Some(observation) = observation {
            observation
                .start(
                    |snapshot| {
                        snapshot.begin == CredentialCall::Ok
                            && snapshot.eligibility == Eligibility::NotEntered
                    },
                    |snapshot| snapshot.eligibility = Eligibility::Entered,
                )
                .map_err(CommitError::Observation)?;
        }
        let result = future.await.map_err(CommitError::Repository);
        if let Some(observation) = observation {
            observation.update(|state| {
                state.snapshot.eligibility = match &result {
                    Ok(value) => Eligibility::Returned(*value),
                    Err(_) => Eligibility::Err,
                }
            });
        }
        result
    }
    pub(crate) fn transaction_returned(&self) {
        self.update(|state| state.snapshot.transaction_returned = true);
    }
    pub(crate) fn preparation_entered(&self, operation: CredentialPreparation) {
        self.preparation_update(|state| {
            let slot = &mut state.snapshot.preparation[operation.index()];
            if *slot != PreparationResult::NotEntered {
                state.integrity = false;
                return;
            }
            *slot = PreparationResult::Entered;
        });
    }
    pub(crate) fn preparation_returned(
        &self,
        operation: CredentialPreparation,
        result: PreparationResult,
    ) {
        self.preparation_update(|state| {
            let slot = &mut state.snapshot.preparation[operation.index()];
            if *slot != PreparationResult::Entered {
                state.integrity = false;
                return;
            }
            *slot = result;
        });
    }
    pub(crate) fn stage_id(&self, operation_id: Uuid) {
        self.preparation_update(|state| {
            if state.snapshot.stage_id.is_some()
                || state.snapshot.preparation[CredentialPreparation::Stage.index()]
                    != PreparationResult::Entered
            {
                state.integrity = false;
                return;
            }
            state.snapshot.stage_id = Some(operation_id);
        });
    }
    pub(crate) fn stage_returned(&self, result: &Result<Option<StagedLoginEpoch>>) {
        self.preparation_update(|state| {
            let slot = &mut state.snapshot.preparation[CredentialPreparation::Stage.index()];
            if *slot != PreparationResult::Entered {
                state.integrity = false;
                return;
            }
            *slot = match result {
                Ok(Some(_)) => PreparationResult::Present,
                Ok(None) => PreparationResult::Absent,
                Err(_) => PreparationResult::Err,
            };
            if let Ok(stage) = result {
                state.stage = *stage;
            }
        });
    }
    pub(crate) async fn rollback<F, E>(
        observation: Option<&Self>,
        site: CredentialRollbackSite,
        future: F,
    ) -> std::result::Result<(), CommitError<E>>
    where
        F: Future<Output = std::result::Result<(), E>>,
    {
        if let Some(observation) = observation {
            observation
                .start(
                    |snapshot| {
                        snapshot.begin == CredentialCall::Ok
                            && snapshot.rollback.is_none()
                            && snapshot.commit == CredentialCall::NotEntered
                            && site.permitted(snapshot)
                    },
                    |snapshot| snapshot.rollback = Some((site, CredentialCall::Entered)),
                )
                .map_err(CommitError::Observation)?;
        }
        let result = future.await.map_err(CommitError::Repository);
        if let Some(observation) = observation {
            observation.update(|state| {
                state.snapshot.rollback = Some((
                    site,
                    if result.is_ok() {
                        CredentialCall::Ok
                    } else {
                        CredentialCall::Err
                    },
                ))
            });
        }
        result
    }
    fn prepared_projection(state: &CredentialState) -> Option<ReceiptProjection> {
        let request = state.request.as_ref()?;
        let snapshot = &state.snapshot;
        if !state.integrity
            || !snapshot.repository_started
            || snapshot.begin != CredentialCall::Ok
            || snapshot.eligibility != Eligibility::Returned(Some(true))
            || !snapshot.transaction_returned
            || snapshot.rollback.is_some()
        {
            return None;
        }
        let stage_result = snapshot.preparation[CredentialPreparation::Stage.index()];
        match (request.device, state.stage) {
            (None, None)
                if snapshot.stage_id.is_none() && stage_result == PreparationResult::Absent => {}
            (Some(device), Some(stage))
                if stage_result == PreparationResult::Present
                    && Some(stage.operation_id) == snapshot.stage_id
                    && stage.connection_id == request.connection
                    && stage.user_id == request.user
                    && stage.auth_generation == request.generation
                    && stage.device_id == device => {}
            // FAST's existing API permits a missing stage. Binding/resume do not.
            (Some(_), None)
                if snapshot.kind == CredentialKind::UnboundFast
                    && snapshot.stage_id.is_some()
                    && stage_result == PreparationResult::Absent => {}
            _ => return None,
        }
        if request.fast.is_some()
            && snapshot.preparation[CredentialPreparation::Fast.index()]
                != PreparationResult::Present
        {
            return None;
        }
        if request.binding.is_some()
            && snapshot.preparation[CredentialPreparation::Binding.index()]
                != PreparationResult::Present
        {
            return None;
        }
        if request.resume.is_some()
            && (snapshot.preparation[CredentialPreparation::Activation.index()]
                != PreparationResult::Present
                || snapshot.preparation[CredentialPreparation::Privacy.index()]
                    != PreparationResult::Present)
        {
            return None;
        }
        Some(ReceiptProjection {
            stage: state.stage,
            binding: request.binding.clone(),
        })
    }
    pub(crate) async fn commit<F, E>(
        observation: Option<&Self>,
        future: F,
    ) -> std::result::Result<(), CommitError<E>>
    where
        F: Future<Output = std::result::Result<(), E>>,
    {
        if let Some(observation) = observation {
            let mut state = observation.prepared.observation.0.lock().unwrap();
            if !state.integrity
                || state.snapshot.handler.is_some()
                || state.snapshot.returned.is_some()
                || !state.snapshot.repository_started
                || !state.snapshot.transaction_returned
                || state.snapshot.commit != CredentialCall::NotEntered
                || state.snapshot.rollback.is_some()
            {
                state.integrity = false;
                return Err(CommitError::Observation(anyhow::anyhow!(
                    "credential COMMIT is duplicate, late or out of order"
                )));
            }
            let Some(receipt) = Self::prepared_projection(&state) else {
                state.integrity = false;
                return Err(CommitError::Observation(anyhow::anyhow!(
                    "credential COMMIT has incomplete preparation"
                )));
            };
            state.prospective = Some(CredentialWitness {
                attempt: state.snapshot.attempt,
                request: state.request.as_ref().expect("validated request").clone(),
                receipt,
            });
            state.snapshot.commit = CredentialCall::Entered;
        }
        let result = future.await.map_err(CommitError::Repository);
        if let Some(observation) = observation {
            observation.update(|state| {
                state.snapshot.commit = if result.is_ok() {
                    CredentialCall::Ok
                } else {
                    CredentialCall::Err
                };
                if result.is_ok() {
                    state.witness = state.prospective.take();
                }
            });
        }
        result
    }
    pub(crate) fn constructed(&self, receipt: &CredentialCommitReceipt) {
        self.update(|state| {
            if state.constructed.is_some() {
                state.integrity = false;
                return;
            }
            if state.snapshot.commit != CredentialCall::Ok {
                state.integrity = false;
            }
            state.constructed = Some((
                receipt.publication_identity(),
                ReceiptProjection::of(receipt),
            ));
            state.snapshot.receipt_constructed = true;
        });
    }
    fn returned(&self, returned: CredentialReturned, receipt: Option<&CredentialCommitReceipt>) {
        self.update(|state| {
            if state.snapshot.returned.is_some() {
                return;
            }
            let actual = receipt.map(|receipt| {
                (
                    receipt.publication_identity(),
                    ReceiptProjection::of(receipt),
                )
            });
            state.snapshot.return_matches = actual.as_ref().is_none_or(|actual| {
                state.integrity
                    && matches!(
                        (state.snapshot.kind, returned),
                        (
                            CredentialKind::UnboundFast,
                            CredentialReturned::Authenticated
                        ) | (
                            CredentialKind::Binding,
                            CredentialReturned::BindingCommitted
                        ) | (CredentialKind::Resume, CredentialReturned::ResumeCommitted)
                    )
                    && state.constructed.as_ref() == Some(actual)
                    && state.witness.as_ref().is_some_and(|witness| {
                        witness.attempt == state.snapshot.attempt
                            && Some(&witness.request) == state.request.as_ref()
                            && witness.receipt == actual.1
                    })
            });
            state.returned = actual;
            state.snapshot.returned = Some(returned);
        });
    }
    pub(crate) fn fast_returned(&self, result: &AuthenticationResult<CredentialCommitReceipt>) {
        let (returned, receipt) = match result {
            AuthenticationResult::Authenticated(receipt) => {
                (CredentialReturned::Authenticated, Some(receipt))
            }
            AuthenticationResult::UnknownCredentials => {
                (CredentialReturned::UnknownCredentials, None)
            }
            AuthenticationResult::Disabled => (CredentialReturned::Disabled, None),
            AuthenticationResult::StaleGeneration => (CredentialReturned::StaleGeneration, None),
            AuthenticationResult::ExpiredCredentials => {
                (CredentialReturned::ExpiredCredentials, None)
            }
            AuthenticationResult::ReplayedCredentials => {
                (CredentialReturned::ReplayedCredentials, None)
            }
            AuthenticationResult::IntegrityFailure => (CredentialReturned::IntegrityFailure, None),
            AuthenticationResult::BackendFailure(_) => (CredentialReturned::BackendFailure, None),
        };
        self.returned(returned, receipt);
    }
    pub(crate) fn binding_returned(
        &self,
        result: &Result<crate::services::sm::BindingFinalizationOutcome>,
    ) {
        use crate::services::sm::BindingFinalizationOutcome as Outcome;
        let (returned, receipt) = match result {
            Ok(Outcome::Committed { receipt }) => {
                (CredentialReturned::BindingCommitted, Some(receipt))
            }
            Ok(Outcome::CredentialsExpired) => {
                (CredentialReturned::BindingCredentialsExpired, None)
            }
            Ok(Outcome::ReservationLost) => (CredentialReturned::BindingReservationLost, None),
            Err(_) => (CredentialReturned::Error, None),
        };
        self.returned(returned, receipt);
    }
    pub(crate) fn resume_returned(
        &self,
        result: &Result<crate::services::sm::SmResumeFinalizationOutcome>,
    ) {
        use crate::services::sm::SmResumeFinalizationOutcome as Outcome;
        let (returned, receipt) = match result {
            Ok(Outcome::Committed(commit)) => {
                (CredentialReturned::ResumeCommitted, Some(&commit.receipt))
            }
            Ok(Outcome::CredentialsExpired) => (CredentialReturned::ResumeCredentialsExpired, None),
            Ok(Outcome::ClaimLost) => (CredentialReturned::ResumeClaimLost, None),
            Ok(Outcome::PrivacySelectionMissing) => {
                (CredentialReturned::ResumePrivacySelectionMissing, None)
            }
            Err(_) => (CredentialReturned::Error, None),
        };
        self.returned(returned, receipt);
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum HandlerReturn {
    Completed,
    Failed,
    TimedOut,
    Cancelled,
    Panicked,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Transport {
    NotStarted,
    Recording,
    WriteEntered,
    Written,
    BoshExposureEntered { rid: u64 },
    BoshAccepted { rid: u64 },
    BoshRefused { rid: u64 },
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Knowledge {
    NotStarted,
    NotRequired,
    BeforeCommit,
    CommitCallEntered,
    ReceiptKnown(Option<i64>),
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Rollback {
    NotRequested,
    CallEntered,
    Returned,
    Failed,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Returned {
    Authenticated(Option<i64>),
    UnknownCredentials,
    Disabled,
    StaleGeneration,
    ExpiredCredentials,
    ReplayedCredentials,
    IntegrityFailure,
    BackendFailure,
}
impl Returned {
    fn of(value: &AuthenticationResult<Option<i64>>) -> Self {
        match value {
            AuthenticationResult::Authenticated(epoch) => Self::Authenticated(*epoch),
            AuthenticationResult::UnknownCredentials => Self::UnknownCredentials,
            AuthenticationResult::Disabled => Self::Disabled,
            AuthenticationResult::StaleGeneration => Self::StaleGeneration,
            AuthenticationResult::ExpiredCredentials => Self::ExpiredCredentials,
            AuthenticationResult::ReplayedCredentials => Self::ReplayedCredentials,
            AuthenticationResult::IntegrityFailure => Self::IntegrityFailure,
            AuthenticationResult::BackendFailure(_) => Self::BackendFailure,
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Terminal {
    Completed,
    DeferredNotification,
    Failed,
    Cancelled,
    Panicked,
    Abandoned,
    ExposedNotAttempted,
}
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct Effects {
    pub(crate) unbound: bool,
    pub(crate) epoch_applied: bool,
    pub(crate) route_mapping: Option<bool>,
    pub(crate) route_activation: Option<bool>,
    pub(crate) caps_entered: bool,
    pub(crate) caps_returned: bool,
    pub(crate) notification_entered: bool,
    pub(crate) notification_returned: Option<bool>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Snapshot {
    pub(crate) control: Uuid,
    pub(crate) frame: Option<Uuid>,
    pub(crate) handler: Option<HandlerReturn>,
    pub(crate) sealed: bool,
    pub(crate) transport: Transport,
    pub(crate) publication: Knowledge,
    pub(crate) service_started: bool,
    pub(crate) repository_started: bool,
    pub(crate) rollback: Rollback,
    pub(crate) returned: Option<Returned>,
    pub(crate) return_matches: bool,
    pub(crate) effects: Effects,
    pub(crate) terminal: Option<Terminal>,
}
struct State {
    receipt_id: Uuid,
    receipt: ReceiptProjection,
    bound_effects: bool,
    notification_expected: bool,
    credential: Option<CredentialObservation>,
    snapshot: Snapshot,
}
#[derive(Clone)]
pub(crate) struct Observation(Arc<Mutex<State>>);
impl std::fmt::Debug for Observation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AuthPublicationObservation { receipt and identity: [redacted] }")
    }
}
impl Observation {
    pub(crate) fn returned_receipt(receipt: &CredentialCommitReceipt, frame: Option<Uuid>) -> Self {
        Self(Arc::new(Mutex::new(State {
            receipt_id: receipt.publication_identity(),
            bound_effects: false,
            notification_expected: false,
            credential: None,
            receipt: ReceiptProjection::of(receipt),
            snapshot: Snapshot {
                control: Uuid::new_v4(),
                frame,
                handler: None,
                sealed: false,
                transport: Transport::NotStarted,
                publication: Knowledge::NotStarted,
                service_started: false,
                repository_started: false,
                rollback: Rollback::NotRequested,
                returned: None,
                return_matches: false,
                effects: Effects::default(),
                terminal: None,
            },
        })))
    }
    pub(crate) fn observed_receipt(
        receipt: &CredentialCommitReceipt,
        frame: Uuid,
        credential: CredentialObservation,
    ) -> Self {
        let observation = Self::returned_receipt(receipt, Some(frame));
        observation.0.lock().unwrap().credential = Some(credential);
        observation
    }
    #[cfg(test)]
    pub(crate) fn credential(&self) -> Option<CredentialObservation> {
        self.0.lock().unwrap().credential.clone()
    }
    pub(crate) fn snapshot(&self) -> Snapshot {
        self.0.lock().unwrap().snapshot.clone()
    }
    pub(crate) fn handler_returned(&self, returned: HandlerReturn) {
        let mut state = self.0.lock().unwrap();
        state.snapshot.handler.get_or_insert(returned);
        if !state.snapshot.sealed && state.snapshot.terminal.is_none() {
            state.snapshot.terminal = Some(Terminal::Abandoned);
        }
    }
    pub(crate) fn sealed(&self, bound: bool, notification: bool) -> Result<()> {
        let mut state = self.0.lock().unwrap();
        ensure!(
            !state.snapshot.sealed && state.snapshot.terminal.is_none(),
            "auth receipt is no longer sealable"
        );
        state.snapshot.sealed = true;
        state.bound_effects = bound;
        state.notification_expected = notification;
        Ok(())
    }
    pub(crate) fn transport(&self, transport: Transport) -> Result<()> {
        let mut state = self.0.lock().unwrap();
        ensure!(
            state.snapshot.terminal.is_none(),
            "auth transport owner retired"
        );
        let allowed = matches!(
            (state.snapshot.transport, transport),
            (Transport::NotStarted, Transport::Recording)
                | (Transport::Recording, Transport::WriteEntered)
                | (Transport::WriteEntered, Transport::Written)
                | (
                    Transport::NotStarted | Transport::Recording,
                    Transport::BoshExposureEntered { .. }
                )
        ) || matches!((state.snapshot.transport, transport),
                (Transport::BoshExposureEntered { rid: previous }, Transport::BoshAccepted { rid } | Transport::BoshRefused { rid }) if previous == rid);
        ensure!(
            allowed,
            "auth transport observation is late or out of order"
        );
        state.snapshot.transport = transport;
        Ok(())
    }
    pub(crate) fn effects(&self, update: impl FnOnce(&mut Effects)) {
        update(&mut self.0.lock().unwrap().snapshot.effects);
    }
    pub(crate) fn retire(&self, terminal: Terminal) {
        let mut state = self.0.lock().unwrap();
        state.snapshot.terminal.get_or_insert(terminal);
    }
    pub(crate) fn successful_completion(&self, deferred: bool) -> bool {
        let state = self.0.lock().unwrap();
        let snapshot = &state.snapshot;
        let Some(Returned::Authenticated(epoch)) = snapshot.returned else {
            return false;
        };
        if !snapshot.return_matches {
            return false;
        }
        let effects = snapshot.effects;
        if state.bound_effects {
            if effects.unbound
                || !effects.epoch_applied
                || effects.route_mapping != Some(true)
                || effects.route_activation != Some(true)
                || !effects.caps_entered
                || !effects.caps_returned
            {
                return false;
            }
        } else if !effects.unbound
            || effects.epoch_applied
            || effects.route_mapping.is_some()
            || effects.route_activation.is_some()
            || effects.caps_entered
            || effects.caps_returned
        {
            return false;
        }
        if state.notification_expected && epoch.is_some() {
            effects.notification_entered && effects.notification_returned == Some(!deferred)
        } else {
            !deferred && !effects.notification_entered && effects.notification_returned.is_none()
        }
    }
    pub(crate) fn completed(&self) -> bool {
        match self.snapshot().terminal {
            Some(Terminal::Completed) => self.successful_completion(false),
            Some(Terminal::DeferredNotification) => self.successful_completion(true),
            _ => false,
        }
    }
    pub(crate) fn authenticated_return(&self, epoch: Option<i64>) -> bool {
        let snapshot = self.snapshot();
        snapshot.return_matches && snapshot.returned == Some(Returned::Authenticated(epoch))
    }
    pub(crate) fn abandon(&self) {
        let terminal = if matches!(
            self.snapshot().transport,
            Transport::Written | Transport::BoshAccepted { .. }
        ) {
            Terminal::ExposedNotAttempted
        } else {
            Terminal::Abandoned
        };
        self.retire(terminal);
    }
    pub(crate) fn begin<'a>(
        &'a self,
        receipt: &'a CredentialCommitReceipt,
    ) -> Result<Invocation<'a>> {
        let mut state = self.0.lock().unwrap();
        ensure!(
            state.receipt_id == receipt.publication_identity()
                && state.receipt == ReceiptProjection::of(receipt),
            "auth publication receipt mismatch"
        );
        ensure!(
            state.snapshot.terminal.is_none()
                && state.snapshot.publication == Knowledge::NotStarted,
            "auth publication is no longer pending"
        );
        ensure!(
            matches!(
                state.snapshot.transport,
                Transport::Written | Transport::BoshAccepted { .. }
            ),
            "auth publication requires successful control transport"
        );
        state.snapshot.publication = Knowledge::BeforeCommit;
        Ok(Invocation {
            observation: self,
            receipt,
        })
    }
}

/// The actual owned receipt is lent only to its exact publication invocation.
/// Repository COMMIT observations and the returned application value are separate.
pub(crate) struct Invocation<'a> {
    observation: &'a Observation,
    receipt: &'a CredentialCommitReceipt,
}
impl Invocation<'_> {
    pub(crate) fn receipt(&self) -> &CredentialCommitReceipt {
        self.receipt
    }
    fn validate(&self, state: &State) -> Result<()> {
        ensure!(
            state.receipt_id == self.receipt.publication_identity()
                && state.receipt == ReceiptProjection::of(self.receipt)
                && state.snapshot.terminal.is_none()
                && state.snapshot.publication == Knowledge::BeforeCommit
                && state.snapshot.returned.is_none(),
            "auth publication invocation is not current"
        );
        Ok(())
    }
    pub(crate) fn enter_service(&self) -> Result<()> {
        let mut state = self.observation.0.lock().unwrap();
        self.validate(&state)?;
        ensure!(
            !state.snapshot.service_started,
            "auth publication service already started"
        );
        state.snapshot.service_started = true;
        Ok(())
    }
    pub(crate) fn enter_repository(&self) -> Result<()> {
        let mut state = self.observation.0.lock().unwrap();
        self.validate(&state)?;
        ensure!(
            state.snapshot.service_started && !state.snapshot.repository_started,
            "auth publication repository is not pending"
        );
        state.snapshot.repository_started = true;
        Ok(())
    }
    pub(crate) fn not_required(&self) -> Result<()> {
        let mut state = self.observation.0.lock().unwrap();
        self.validate(&state)?;
        ensure!(
            state.snapshot.service_started && !state.snapshot.repository_started,
            "no-SQL auth publication must remain in service"
        );
        ensure!(
            self.receipt.staged_login_epoch().is_none()
                && self.receipt.binding_publication().is_none(),
            "auth publication SQL is required"
        );
        state.snapshot.publication = Knowledge::NotRequired;
        Ok(())
    }
    pub(crate) async fn commit<F, E>(
        &self,
        future: F,
        epoch: Option<i64>,
    ) -> Result<(), CommitError<E>>
    where
        F: Future<Output = Result<(), E>>,
    {
        {
            let mut state = self.observation.0.lock().unwrap();
            self.validate(&state).map_err(CommitError::Observation)?;
            if !state.snapshot.repository_started
                || state.snapshot.rollback != Rollback::NotRequested
            {
                return Err(CommitError::Observation(anyhow::anyhow!(
                    "auth publication COMMIT is not pending"
                )));
            }
            state.snapshot.publication = Knowledge::CommitCallEntered;
        }
        future.await.map_err(CommitError::Repository)?;
        self.observation.0.lock().unwrap().snapshot.publication = Knowledge::ReceiptKnown(epoch);
        Ok(())
    }
    pub(crate) async fn rollback<F, E>(&self, future: F) -> Result<(), CommitError<E>>
    where
        F: Future<Output = Result<(), E>>,
    {
        {
            let mut state = self.observation.0.lock().unwrap();
            self.validate(&state).map_err(CommitError::Observation)?;
            if !state.snapshot.repository_started
                || state.snapshot.rollback != Rollback::NotRequested
            {
                return Err(CommitError::Observation(anyhow::anyhow!(
                    "auth publication rollback is not pending"
                )));
            }
            state.snapshot.rollback = Rollback::CallEntered;
        }
        let result = future.await.map_err(CommitError::Repository);
        self.observation.0.lock().unwrap().snapshot.rollback = if result.is_ok() {
            Rollback::Returned
        } else {
            Rollback::Failed
        };
        result
    }
    pub(crate) fn returned(&self, returned: &AuthenticationResult<Option<i64>>) -> bool {
        let mut state = self.observation.0.lock().unwrap();
        if state.snapshot.returned.is_some() {
            return false;
        }
        let returned = Returned::of(returned);
        let matches = match returned {
            Returned::Authenticated(epoch) => {
                matches!(
                    state.snapshot.publication,
                    Knowledge::NotRequired if epoch.is_none()
                ) || state.snapshot.publication == Knowledge::ReceiptKnown(epoch)
            }
            _ => true,
        };
        state.snapshot.returned = Some(returned);
        state.snapshot.return_matches = matches;
        matches
    }
}
#[derive(Debug)]
pub(crate) enum CommitError<E> {
    Observation(anyhow::Error),
    Repository(E),
}
impl<E: std::fmt::Display> std::fmt::Display for CommitError<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Observation(error) => write!(f, "{error}"),
            Self::Repository(error) => write!(f, "{error}"),
        }
    }
}
impl<E: std::error::Error + 'static> std::error::Error for CommitError<E> {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        cell::Cell,
        pin::Pin,
        task::{Context, Poll, Waker},
    };

    fn receipt() -> CredentialCommitReceipt {
        CredentialCommitReceipt::new(
            None,
            Some(StagedLoginEpoch {
                operation_id: Uuid::from_u128(1),
                connection_id: Uuid::from_u128(2),
                user_id: Uuid::from_u128(3),
                device_id: Uuid::from_u128(4),
                auth_generation: 5,
                epoch: 999, // A receipt hint, deliberately not the adapter's stored epoch.
            }),
            None,
        )
    }
    fn written(receipt: &CredentialCommitReceipt, bound: bool) -> Observation {
        let observation = Observation::returned_receipt(receipt, Some(Uuid::from_u128(6)));
        observation.sealed(bound, false).unwrap();
        observation.transport(Transport::Recording).unwrap();
        observation.transport(Transport::WriteEntered).unwrap();
        observation.transport(Transport::Written).unwrap();
        observation
    }
    fn poll_once<F: Future>(future: Pin<&mut F>) -> Poll<F::Output> {
        future.poll(&mut Context::from_waker(Waker::noop()))
    }

    async fn prepare_empty_fast(invocation: &CredentialInvocation<'_>) {
        prepare_empty_fast_result(invocation, true).await;
    }
    async fn prepare_empty_fast_result(invocation: &CredentialInvocation<'_>, prepared_fast: bool) {
        invocation
            .enter_fast(
                Uuid::from_u128(2),
                7,
                &FastCommitPlan::default(),
                None,
                Uuid::from_u128(3),
            )
            .unwrap();
        CredentialInvocation::begin(Some(invocation), std::future::ready(Ok::<(), ()>(())))
            .await
            .unwrap();
        CredentialInvocation::eligibility(
            Some(invocation),
            std::future::ready(Ok::<_, ()>(Some(true))),
        )
        .await
        .unwrap();
        invocation.transaction_returned();
        invocation.preparation_entered(CredentialPreparation::Stage);
        invocation.stage_returned(&Ok(None));
        invocation.preparation_entered(CredentialPreparation::Fast);
        invocation.preparation_returned(
            CredentialPreparation::Fast,
            if prepared_fast {
                PreparationResult::Present
            } else {
                PreparationResult::Absent
            },
        );
    }
    #[tokio::test]
    async fn credential_acknowledgement_and_receipt_instance_are_independent_authority() {
        for acknowledgement in [false, true] {
            let prepared = PreparedCredential::new(
                Uuid::from_u128(1),
                Uuid::from_u128(3),
                0,
                CredentialKind::UnboundFast,
            );
            let invocation = prepared
                .fast(
                    Uuid::from_u128(2),
                    7,
                    &FastCommitPlan::default(),
                    None,
                    Uuid::from_u128(3),
                )
                .unwrap();
            prepare_empty_fast(&invocation).await;
            if acknowledgement {
                CredentialInvocation::commit(
                    Some(&invocation),
                    std::future::ready(Ok::<(), ()>(())),
                )
                .await
                .unwrap();
            }
            let receipt = CredentialCommitReceipt::new(None, None, None);
            let equal_fields = CredentialCommitReceipt::new(None, None, None);
            invocation.constructed(&receipt);
            invocation.fast_returned(&AuthenticationResult::Authenticated(receipt));
            let snapshot = prepared.observation().snapshot();
            assert_eq!(snapshot.returned, Some(CredentialReturned::Authenticated));
            assert_eq!(snapshot.return_matches, acknowledgement);
            assert!(prepared
                .transfer(&equal_fields, Uuid::from_u128(1), Uuid::from_u128(3))
                .is_err());
            assert!(!prepared.observation().snapshot().transferred);
        }
    }
    #[tokio::test]
    async fn credential_matching_receipt_transfers_only_its_original_attempt() {
        let prepared = PreparedCredential::new(
            Uuid::from_u128(1),
            Uuid::from_u128(3),
            0,
            CredentialKind::UnboundFast,
        );
        let wrong = PreparedCredential::new(
            Uuid::from_u128(1),
            Uuid::from_u128(3),
            1,
            CredentialKind::UnboundFast,
        );
        let invocation = prepared
            .fast(
                Uuid::from_u128(2),
                7,
                &FastCommitPlan::default(),
                None,
                Uuid::from_u128(3),
            )
            .unwrap();
        prepare_empty_fast(&invocation).await;
        CredentialInvocation::commit(Some(&invocation), std::future::ready(Ok::<(), ()>(())))
            .await
            .unwrap();
        let receipt = CredentialCommitReceipt::new(None, None, None);
        invocation.constructed(&receipt);
        let result = AuthenticationResult::Authenticated(receipt);
        invocation.fast_returned(&result);
        let AuthenticationResult::Authenticated(receipt) = result else {
            unreachable!()
        };
        assert!(wrong
            .transfer(&receipt, Uuid::from_u128(1), Uuid::from_u128(3))
            .is_err());
        assert!(prepared
            .transfer(&receipt, Uuid::from_u128(4), Uuid::from_u128(3))
            .is_err());
        let retained = prepared
            .transfer(&receipt, Uuid::from_u128(1), Uuid::from_u128(3))
            .unwrap();
        assert!(retained.snapshot().transferred);
        assert!(prepared
            .transfer(&receipt, Uuid::from_u128(1), Uuid::from_u128(3))
            .is_err());
    }

    #[test]
    fn credential_generation_helper_retains_exact_query_and_rollback_results() {
        for value in [None, Some(false), Some(true)] {
            for rollback in [
                CredentialCall::Ok,
                CredentialCall::Err,
                CredentialCall::Entered,
            ] {
                let prepared = PreparedCredential::new(
                    Uuid::from_u128(1),
                    Uuid::from_u128(3),
                    0,
                    CredentialKind::UnboundFast,
                );
                let invocation = prepared
                    .fast(
                        Uuid::from_u128(2),
                        7,
                        &FastCommitPlan::default(),
                        None,
                        Uuid::from_u128(3),
                    )
                    .unwrap();
                invocation
                    .enter_fast(
                        Uuid::from_u128(2),
                        7,
                        &FastCommitPlan::default(),
                        None,
                        Uuid::from_u128(3),
                    )
                    .unwrap();
                let mut work = Box::pin(async {
                    CredentialInvocation::begin(
                        Some(&invocation),
                        std::future::ready(Ok::<(), ()>(())),
                    )
                    .await
                    .unwrap();
                    let eligible = CredentialInvocation::eligibility(
                        Some(&invocation),
                        std::future::ready(Ok::<_, ()>(value)),
                    )
                    .await
                    .unwrap();
                    if eligible != Some(true) {
                        let _ = CredentialInvocation::rollback(
                            Some(&invocation),
                            CredentialRollbackSite::GenerationRefused,
                            async {
                                if rollback == CredentialCall::Entered {
                                    std::future::pending::<()>().await;
                                }
                                if rollback == CredentialCall::Err {
                                    Err(())
                                } else {
                                    Ok(())
                                }
                            },
                        )
                        .await;
                    } else {
                        invocation.transaction_returned();
                    }
                });
                assert_eq!(
                    poll_once(work.as_mut()).is_pending(),
                    value != Some(true) && rollback == CredentialCall::Entered
                );
                drop(work);
                drop(invocation);
                let snapshot = prepared.observation().snapshot();
                assert_eq!(snapshot.eligibility, Eligibility::Returned(value));
                assert_eq!(snapshot.transaction_returned, value == Some(true));
                assert_eq!(
                    snapshot.rollback,
                    if value == Some(true) {
                        None
                    } else {
                        Some((CredentialRollbackSite::GenerationRefused, rollback))
                    }
                );
                assert_eq!(snapshot.commit, CredentialCall::NotEntered);
                assert!(!snapshot.receipt_constructed);
            }
        }
    }

    #[test]
    fn credential_begin_and_query_error_or_pending_do_not_invent_rollback() {
        for query in [false, true] {
            for pending in [false, true] {
                let prepared = PreparedCredential::new(
                    Uuid::from_u128(1),
                    Uuid::from_u128(3),
                    0,
                    CredentialKind::UnboundFast,
                );
                let invocation = prepared
                    .fast(
                        Uuid::from_u128(2),
                        7,
                        &FastCommitPlan::default(),
                        None,
                        Uuid::from_u128(3),
                    )
                    .unwrap();
                invocation
                    .enter_fast(
                        Uuid::from_u128(2),
                        7,
                        &FastCommitPlan::default(),
                        None,
                        Uuid::from_u128(3),
                    )
                    .unwrap();
                let mut work = Box::pin(async {
                    let begin = CredentialInvocation::begin(Some(&invocation), async {
                        if !query && pending {
                            std::future::pending::<()>().await;
                        }
                        if query {
                            Ok(())
                        } else {
                            Err(())
                        }
                    })
                    .await;
                    if query {
                        begin.unwrap();
                        let _ = CredentialInvocation::eligibility(Some(&invocation), async {
                            if pending {
                                std::future::pending::<()>().await;
                            }
                            Err::<Option<bool>, ()>(())
                        })
                        .await;
                    }
                });
                assert_eq!(poll_once(work.as_mut()).is_pending(), pending);
                drop(work);
                drop(invocation);
                let snapshot = prepared.observation().snapshot();
                assert_eq!(
                    snapshot.begin,
                    if query {
                        CredentialCall::Ok
                    } else if pending {
                        CredentialCall::Entered
                    } else {
                        CredentialCall::Err
                    }
                );
                assert_eq!(
                    snapshot.eligibility,
                    if !query {
                        Eligibility::NotEntered
                    } else if pending {
                        Eligibility::Entered
                    } else {
                        Eligibility::Err
                    }
                );
                assert_eq!(snapshot.commit, CredentialCall::NotEntered);
                assert_eq!(snapshot.rollback, None);
            }
        }
    }

    #[tokio::test]
    async fn credential_duplicate_and_late_operations_never_poll_or_replace_first_facts() {
        for duplicate in [0, 1, 2, 3] {
            let prepared = PreparedCredential::new(
                Uuid::from_u128(1),
                Uuid::from_u128(3),
                0,
                CredentialKind::UnboundFast,
            );
            let invocation = prepared
                .fast(
                    Uuid::from_u128(2),
                    7,
                    &FastCommitPlan::default(),
                    None,
                    Uuid::from_u128(3),
                )
                .unwrap();
            prepare_empty_fast_result(&invocation, duplicate != 2).await;
            if duplicate == 2 {
                CredentialInvocation::rollback(
                    Some(&invocation),
                    CredentialRollbackSite::FastExpired,
                    std::future::ready(Ok::<(), ()>(())),
                )
                .await
                .unwrap();
            }
            if duplicate == 3 {
                CredentialInvocation::commit(
                    Some(&invocation),
                    std::future::ready(Ok::<(), ()>(())),
                )
                .await
                .unwrap();
            }
            let before = prepared.observation().snapshot();
            let calls = Cell::new(0);
            let rejected = match duplicate {
                0 => CredentialInvocation::begin(Some(&invocation), async {
                    calls.set(1);
                    Ok::<(), ()>(())
                })
                .await
                .is_err(),
                1 => CredentialInvocation::eligibility(Some(&invocation), async {
                    calls.set(1);
                    Ok::<_, ()>(Some(false))
                })
                .await
                .is_err(),
                2 => CredentialInvocation::rollback(
                    Some(&invocation),
                    CredentialRollbackSite::GenerationRefused,
                    async {
                        calls.set(1);
                        Ok::<(), ()>(())
                    },
                )
                .await
                .is_err(),
                _ => CredentialInvocation::commit(Some(&invocation), async {
                    calls.set(1);
                    Ok::<(), ()>(())
                })
                .await
                .is_err(),
            };
            assert!(rejected);
            assert_eq!(calls.get(), 0);
            let after = prepared.observation().snapshot();
            assert_eq!(
                (after.begin, after.eligibility, after.rollback, after.commit),
                (
                    before.begin,
                    before.eligibility,
                    before.rollback,
                    before.commit
                )
            );
            assert!(after.integrity_failure);
        }
        let prepared = PreparedCredential::new(
            Uuid::from_u128(1),
            Uuid::from_u128(3),
            0,
            CredentialKind::UnboundFast,
        );
        let invocation = prepared
            .fast(
                Uuid::from_u128(2),
                7,
                &FastCommitPlan::default(),
                None,
                Uuid::from_u128(3),
            )
            .unwrap();
        prepare_empty_fast(&invocation).await;
        CredentialInvocation::commit(Some(&invocation), std::future::ready(Ok::<(), ()>(())))
            .await
            .unwrap();
        let receipt = CredentialCommitReceipt::new(None, None, None);
        invocation.constructed(&receipt);
        let original_id = prepared
            .observation
            .0
            .lock()
            .unwrap()
            .constructed
            .as_ref()
            .unwrap()
            .0;
        invocation.constructed(&CredentialCommitReceipt::new(None, None, None));
        assert_eq!(
            prepared
                .observation
                .0
                .lock()
                .unwrap()
                .constructed
                .as_ref()
                .unwrap()
                .0,
            original_id
        );
        invocation.fast_returned(&AuthenticationResult::Authenticated(receipt));
        invocation.fast_returned(&AuthenticationResult::ExpiredCredentials);
        assert_eq!(
            prepared.observation().snapshot().returned,
            Some(CredentialReturned::Authenticated)
        );
        prepared
            .observation()
            .handler_returned(HandlerReturn::Completed);
        let calls = Cell::new(0);
        assert!(CredentialInvocation::commit(Some(&invocation), async {
            calls.set(1);
            Ok::<(), ()>(())
        })
        .await
        .is_err());
        assert_eq!(calls.get(), 0);
        assert_eq!(prepared.observation().snapshot().commit, CredentialCall::Ok);
    }

    #[tokio::test]
    async fn credential_commit_entry_freezes_preparation_and_stage_identity() {
        let prepared = PreparedCredential::new(
            Uuid::from_u128(1),
            Uuid::from_u128(3),
            0,
            CredentialKind::UnboundFast,
        );
        let invocation = prepared
            .fast(
                Uuid::from_u128(2),
                7,
                &FastCommitPlan::default(),
                None,
                Uuid::from_u128(3),
            )
            .unwrap();
        prepare_empty_fast(&invocation).await;
        let mut commit = Box::pin(CredentialInvocation::commit(
            Some(&invocation),
            std::future::pending::<std::result::Result<(), ()>>(),
        ));
        assert!(poll_once(commit.as_mut()).is_pending());
        invocation.stage_id(Uuid::from_u128(88));
        invocation.stage_returned(&Ok(Some(StagedLoginEpoch {
            operation_id: Uuid::from_u128(88),
            connection_id: Uuid::from_u128(3),
            user_id: Uuid::from_u128(2),
            device_id: Uuid::from_u128(4),
            auth_generation: 7,
            epoch: 9,
        })));
        let state = prepared.observation.0.lock().unwrap();
        assert!(state.prospective.as_ref().unwrap().receipt.stage.is_none());
        assert!(state.snapshot.stage_id.is_none());
        assert!(state.stage.is_none());
        assert!(!state.integrity);
        drop(state);
        drop(commit);
        assert_eq!(
            prepared.observation().snapshot().commit,
            CredentialCall::Entered
        );
    }

    #[tokio::test]
    async fn credential_stage_error_keeps_original_sql_operation_and_device_roles() {
        let plan = FastCommitPlan {
            issue: Some(super::super::FastTokenIssue {
                device_id: Uuid::from_u128(9),
                mechanism: "HT-SHA-256-NONE".to_owned(),
                ttl_days: 7,
                strong_reauth_max_days: 30,
                inherited_chain: None,
            }),
            ..FastCommitPlan::default()
        };
        let prepared = PreparedCredential::new(
            Uuid::from_u128(1),
            Uuid::from_u128(3),
            0,
            CredentialKind::UnboundFast,
        );
        let invocation = prepared
            .fast(
                Uuid::from_u128(2),
                7,
                &plan,
                Some(Uuid::from_u128(4)),
                Uuid::from_u128(3),
            )
            .unwrap();
        invocation
            .enter_fast(
                Uuid::from_u128(2),
                7,
                &plan,
                Some(Uuid::from_u128(4)),
                Uuid::from_u128(3),
            )
            .unwrap();
        CredentialInvocation::begin(Some(&invocation), std::future::ready(Ok::<(), ()>(())))
            .await
            .unwrap();
        CredentialInvocation::eligibility(
            Some(&invocation),
            std::future::ready(Ok::<_, ()>(Some(true))),
        )
        .await
        .unwrap();
        invocation.transaction_returned();
        invocation.preparation_entered(CredentialPreparation::Stage);
        invocation.stage_id(Uuid::from_u128(5));
        assert_eq!(
            prepared.observation().snapshot().stage_id,
            Some(Uuid::from_u128(5))
        );
        invocation.stage_id(Uuid::from_u128(6));
        invocation.stage_returned(&Err(anyhow::anyhow!("synthetic SQL stage error")));
        let state = prepared.observation.0.lock().unwrap();
        assert_eq!(state.snapshot.stage_id, Some(Uuid::from_u128(5)));
        assert_eq!(
            state.request.as_ref().unwrap().device,
            Some(Uuid::from_u128(4))
        );
        assert_eq!(
            state
                .request
                .as_ref()
                .unwrap()
                .fast
                .as_ref()
                .unwrap()
                .issue
                .as_ref()
                .unwrap()
                .device_id,
            Uuid::from_u128(9)
        );
        assert_eq!(state.snapshot.commit, CredentialCall::NotEntered);
        assert!(state.stage.is_none());
    }

    #[test]
    fn credential_refusal_sites_preserve_rollback_propagation_and_never_authorize_commit() {
        use crate::services::sm::{
            BindingFinalizationOutcome, SmResumeFinalizationOutcome, SmResumeFinalizationRequest,
        };
        let sites = [
            (
                CredentialKind::UnboundFast,
                CredentialRollbackSite::GenerationRefused,
                CredentialPreparation::Stage,
            ),
            (
                CredentialKind::UnboundFast,
                CredentialRollbackSite::FastExpired,
                CredentialPreparation::Fast,
            ),
            (
                CredentialKind::Binding,
                CredentialRollbackSite::BindingReservationLost,
                CredentialPreparation::Binding,
            ),
            (
                CredentialKind::Binding,
                CredentialRollbackSite::BindingStageMissing,
                CredentialPreparation::Stage,
            ),
            (
                CredentialKind::Binding,
                CredentialRollbackSite::BindingFastExpired,
                CredentialPreparation::Fast,
            ),
            (
                CredentialKind::Resume,
                CredentialRollbackSite::ResumeStageMissing,
                CredentialPreparation::Stage,
            ),
            (
                CredentialKind::Resume,
                CredentialRollbackSite::ResumeClaimLost,
                CredentialPreparation::Activation,
            ),
            (
                CredentialKind::Resume,
                CredentialRollbackSite::ResumeFastExpired,
                CredentialPreparation::Fast,
            ),
            (
                CredentialKind::Resume,
                CredentialRollbackSite::ResumePrivacyMissing,
                CredentialPreparation::Privacy,
            ),
        ];
        for (kind, site, operation) in sites {
            for outcome in [
                CredentialCall::Ok,
                CredentialCall::Err,
                CredentialCall::Entered,
            ] {
                let prepared =
                    PreparedCredential::new(Uuid::from_u128(1), Uuid::from_u128(3), 0, kind);
                let plan = FastCommitPlan::default();
                let request = SmResumeFinalizationRequest {
                    session_id: Uuid::from_u128(6),
                    claim_token: Uuid::from_u128(8),
                    connection_id: Uuid::from_u128(3),
                    user_id: Uuid::from_u128(2),
                    expected_auth_generation: 7,
                    client_h: 1,
                    acknowledged_count: 0,
                    peer_ip: "192.0.2.1".parse().unwrap(),
                    user_agent_id: Some(Uuid::from_u128(4)),
                    active_privacy_list: None,
                    ttl_seconds: 90,
                    live_lease_seconds: 43,
                    max_stanzas: 17,
                    max_bytes: 801,
                    fast_plan: Some(&plan),
                };
                let invocation = match kind {
                    CredentialKind::UnboundFast => {
                        prepared.fast(Uuid::from_u128(2), 7, &plan, None, Uuid::from_u128(3))
                    }
                    CredentialKind::Binding => prepared.binding(
                        Uuid::from_u128(3),
                        Uuid::from_u128(2),
                        7,
                        "private@example.test/resource",
                        43,
                        Some(Uuid::from_u128(4)),
                        Some(&plan),
                    ),
                    CredentialKind::Resume => prepared.resume(&request),
                }
                .unwrap();
                match kind {
                    CredentialKind::UnboundFast => invocation.enter_fast(
                        Uuid::from_u128(2),
                        7,
                        &plan,
                        None,
                        Uuid::from_u128(3),
                    ),
                    CredentialKind::Binding => invocation.enter_binding(
                        Uuid::from_u128(3),
                        Uuid::from_u128(2),
                        7,
                        "private@example.test/resource",
                        43,
                        Some(Uuid::from_u128(4)),
                        Some(&plan),
                    ),
                    CredentialKind::Resume => invocation.enter_resume(&request),
                }
                .unwrap();
                let mut work = Box::pin(async {
                    CredentialInvocation::begin(
                        Some(&invocation),
                        std::future::ready(Ok::<(), ()>(())),
                    )
                    .await
                    .unwrap();
                    CredentialInvocation::eligibility(
                        Some(&invocation),
                        std::future::ready(Ok::<_, ()>(
                            if site == CredentialRollbackSite::GenerationRefused {
                                Some(false)
                            } else {
                                Some(true)
                            },
                        )),
                    )
                    .await
                    .unwrap();
                    if site != CredentialRollbackSite::GenerationRefused {
                        invocation.transaction_returned();
                        invocation.preparation_entered(operation);
                        invocation.preparation_returned(operation, PreparationResult::Absent);
                    }
                    let rollback = CredentialInvocation::rollback(Some(&invocation), site, async {
                        if outcome == CredentialCall::Entered {
                            std::future::pending::<()>().await;
                        }
                        if outcome == CredentialCall::Err {
                            Err(std::io::Error::other("synthetic rollback error"))
                        } else {
                            Ok(())
                        }
                    })
                    .await
                    .map_err(credential_error);
                    match kind {
                        CredentialKind::UnboundFast => {
                            let result = match rollback {
                                Err(error) if site != CredentialRollbackSite::FastExpired => {
                                    AuthenticationResult::BackendFailure(error)
                                }
                                _ => AuthenticationResult::ExpiredCredentials,
                            };
                            invocation.fast_returned(&result);
                        }
                        CredentialKind::Binding => {
                            invocation.binding_returned(&rollback.map(|()| {
                                if site == CredentialRollbackSite::BindingReservationLost {
                                    BindingFinalizationOutcome::ReservationLost
                                } else {
                                    BindingFinalizationOutcome::CredentialsExpired
                                }
                            }))
                        }
                        CredentialKind::Resume => {
                            invocation.resume_returned(&rollback.map(|()| match site {
                                CredentialRollbackSite::ResumeClaimLost => {
                                    SmResumeFinalizationOutcome::ClaimLost
                                }
                                CredentialRollbackSite::ResumePrivacyMissing => {
                                    SmResumeFinalizationOutcome::PrivacySelectionMissing
                                }
                                _ => SmResumeFinalizationOutcome::CredentialsExpired,
                            }))
                        }
                    }
                });
                assert_eq!(
                    poll_once(work.as_mut()).is_pending(),
                    outcome == CredentialCall::Entered
                );
                drop(work);
                let snapshot = prepared.observation().snapshot();
                assert_eq!(snapshot.rollback, Some((site, outcome)));
                assert_eq!(snapshot.commit, CredentialCall::NotEntered);
                assert!(!snapshot.receipt_constructed);
                if outcome == CredentialCall::Entered {
                    assert_eq!(snapshot.returned, None);
                }
                if outcome == CredentialCall::Ok {
                    let returned = match site {
                        CredentialRollbackSite::GenerationRefused
                        | CredentialRollbackSite::FastExpired => {
                            CredentialReturned::ExpiredCredentials
                        }
                        CredentialRollbackSite::BindingReservationLost => {
                            CredentialReturned::BindingReservationLost
                        }
                        CredentialRollbackSite::BindingStageMissing
                        | CredentialRollbackSite::BindingFastExpired => {
                            CredentialReturned::BindingCredentialsExpired
                        }
                        CredentialRollbackSite::ResumeClaimLost => {
                            CredentialReturned::ResumeClaimLost
                        }
                        CredentialRollbackSite::ResumePrivacyMissing => {
                            CredentialReturned::ResumePrivacySelectionMissing
                        }
                        CredentialRollbackSite::ResumeStageMissing
                        | CredentialRollbackSite::ResumeFastExpired => {
                            CredentialReturned::ResumeCredentialsExpired
                        }
                    };
                    assert_eq!(snapshot.returned, Some(returned));
                }
                if outcome == CredentialCall::Err {
                    assert_eq!(
                        snapshot.returned,
                        Some(if site == CredentialRollbackSite::FastExpired {
                            CredentialReturned::ExpiredCredentials
                        } else if kind == CredentialKind::UnboundFast {
                            CredentialReturned::BackendFailure
                        } else {
                            CredentialReturned::Error
                        })
                    );
                }
                let calls = Cell::new(0);
                let mut commit = Box::pin(CredentialInvocation::commit(Some(&invocation), async {
                    calls.set(1);
                    Ok::<(), ()>(())
                }));
                assert!(matches!(
                    poll_once(commit.as_mut()),
                    Poll::Ready(Err(CommitError::Observation(_)))
                ));
                assert_eq!(calls.get(), 0);
            }
        }
    }
    #[tokio::test]
    async fn credential_incomplete_preparation_rejects_commit_without_polling_and_keeps_error_identity(
    ) {
        let prepared = PreparedCredential::new(
            Uuid::from_u128(1),
            Uuid::from_u128(3),
            0,
            CredentialKind::UnboundFast,
        );
        let invocation = prepared
            .fast(
                Uuid::from_u128(2),
                7,
                &FastCommitPlan::default(),
                None,
                Uuid::from_u128(3),
            )
            .unwrap();
        invocation
            .enter_fast(
                Uuid::from_u128(2),
                7,
                &FastCommitPlan::default(),
                None,
                Uuid::from_u128(3),
            )
            .unwrap();
        CredentialInvocation::begin(Some(&invocation), std::future::ready(Ok::<(), ()>(())))
            .await
            .unwrap();
        CredentialInvocation::eligibility(
            Some(&invocation),
            std::future::ready(Ok::<_, ()>(Some(true))),
        )
        .await
        .unwrap();
        invocation.transaction_returned();
        let calls = Cell::new(0);
        assert!(matches!(
            CredentialInvocation::commit(Some(&invocation), async {
                calls.set(1);
                Ok::<(), ()>(())
            })
            .await,
            Err(CommitError::Observation(_))
        ));
        assert_eq!(calls.get(), 0);
        assert_eq!(
            prepared.observation().snapshot().commit,
            CredentialCall::NotEntered
        );
        let result = CredentialInvocation::begin(
            None,
            std::future::ready(Err::<(), _>(std::io::Error::from(
                std::io::ErrorKind::ConnectionReset,
            ))),
        )
        .await;
        let error = credential_error(result.unwrap_err());
        assert_eq!(
            error.downcast_ref::<std::io::Error>().unwrap().kind(),
            std::io::ErrorKind::ConnectionReset
        );
    }

    #[test]
    fn equal_empty_receipts_are_not_the_same_publication_authority() {
        let first = CredentialCommitReceipt::new(None, None, None);
        let second = CredentialCommitReceipt::new(None, None, None);
        let observation = written(&first, false);
        assert!(observation.begin(&second).is_err());
        assert_eq!(observation.snapshot().publication, Knowledge::NotStarted);
        let invocation = observation.begin(&first).unwrap();
        invocation.enter_service().unwrap();
        invocation.not_required().unwrap();
        assert!(invocation.returned(&AuthenticationResult::Authenticated(None)));
        assert_eq!(observation.snapshot().publication, Knowledge::NotRequired);
        assert!(!observation.snapshot().repository_started);
    }

    #[test]
    fn service_and_repository_borrowed_invocations_start_exactly_once() {
        let receipt = receipt();
        let observation = written(&receipt, true);
        let invocation = observation.begin(&receipt).unwrap();
        assert!(invocation.enter_repository().is_err());
        invocation.enter_service().unwrap();
        assert!(invocation.enter_service().is_err());
        invocation.enter_repository().unwrap();
        assert!(invocation.enter_repository().is_err());
        assert!(observation.begin(&receipt).is_err());
        assert_eq!(observation.snapshot().publication, Knowledge::BeforeCommit);
        assert!(observation.snapshot().returned.is_none());
    }

    #[test]
    fn publication_commit_pending_error_and_duplicate_keep_exact_knowledge() {
        for pending in [false, true] {
            let receipt = receipt();
            let observation = written(&receipt, true);
            let invocation = observation.begin(&receipt).unwrap();
            invocation.enter_service().unwrap();
            invocation.enter_repository().unwrap();
            let mut commit = Box::pin(invocation.commit(
                async {
                    if pending {
                        std::future::pending::<()>().await;
                    }
                    Err::<(), _>(std::io::Error::other("reply lost"))
                },
                Some(7),
            ));
            let polled = poll_once(commit.as_mut());
            assert_eq!(polled.is_pending(), pending);
            if !pending {
                assert!(matches!(
                    polled,
                    Poll::Ready(Err(CommitError::Repository(_)))
                ));
            }
            drop(commit);
            assert_eq!(
                observation.snapshot().publication,
                Knowledge::CommitCallEntered
            );
            let calls = Cell::new(0);
            let mut duplicate = Box::pin(invocation.commit(
                async {
                    calls.set(calls.get() + 1);
                    Ok::<(), std::io::Error>(())
                },
                Some(7),
            ));
            assert!(matches!(
                poll_once(duplicate.as_mut()),
                Poll::Ready(Err(CommitError::Observation(_)))
            ));
            assert_eq!(calls.get(), 0);
        }
    }

    #[tokio::test]
    async fn publication_receipt_and_return_use_stored_epoch_not_hint() {
        let receipt = receipt();
        let observation = written(&receipt, true);
        let invocation = observation.begin(&receipt).unwrap();
        invocation.enter_service().unwrap();
        invocation.enter_repository().unwrap();
        invocation
            .commit(std::future::ready(Ok::<(), std::io::Error>(())), Some(7))
            .await
            .unwrap();
        assert_eq!(receipt.staged_login_epoch().unwrap().epoch, 999);
        assert_eq!(
            observation.snapshot().publication,
            Knowledge::ReceiptKnown(Some(7))
        );
        assert!(!invocation.returned(&AuthenticationResult::Authenticated(Some(999))));
        assert_eq!(
            observation.snapshot().returned,
            Some(Returned::Authenticated(Some(999)))
        );
        assert!(!observation.authenticated_return(Some(7)));
        assert!(!invocation.returned(&AuthenticationResult::Authenticated(Some(7))));
    }

    #[tokio::test]
    async fn successful_return_alone_cannot_authorize_downstream_effects() {
        let receipt = receipt();
        let observation = written(&receipt, true);
        let invocation = observation.begin(&receipt).unwrap();
        invocation.enter_service().unwrap();
        invocation.enter_repository().unwrap();
        assert!(!invocation.returned(&AuthenticationResult::Authenticated(Some(7))));
        assert!(!observation.authenticated_return(Some(7)));
        assert!(!observation.successful_completion(false));
        assert_eq!(observation.snapshot().publication, Knowledge::BeforeCommit);
    }

    #[tokio::test]
    async fn rollback_failure_and_cancel_do_not_claim_a_rollback_receipt() {
        for pending in [false, true] {
            let receipt = receipt();
            let observation = written(&receipt, true);
            let invocation = observation.begin(&receipt).unwrap();
            invocation.enter_service().unwrap();
            invocation.enter_repository().unwrap();
            let mut rollback = Box::pin(invocation.rollback(async {
                if pending {
                    std::future::pending::<()>().await;
                }
                Err::<(), _>(std::io::Error::other("rollback reply lost"))
            }));
            assert_eq!(poll_once(rollback.as_mut()).is_pending(), pending);
            drop(rollback);
            assert_eq!(
                observation.snapshot().rollback,
                if pending {
                    Rollback::CallEntered
                } else {
                    Rollback::Failed
                }
            );
            assert_eq!(observation.snapshot().publication, Knowledge::BeforeCommit);
            assert!(invocation.returned(&AuthenticationResult::ExpiredCredentials));
            assert!(!observation.successful_completion(false));
        }
    }

    #[tokio::test]
    async fn positive_completion_requires_publication_and_captured_effect_results() {
        let receipt = receipt();
        let observation = written(&receipt, true);
        let invocation = observation.begin(&receipt).unwrap();
        invocation.enter_service().unwrap();
        invocation.enter_repository().unwrap();
        invocation
            .commit(std::future::ready(Ok::<(), std::io::Error>(())), Some(7))
            .await
            .unwrap();
        assert!(invocation.returned(&AuthenticationResult::Authenticated(Some(7))));
        assert!(!observation.successful_completion(false));
        observation.effects(|effects| {
            effects.epoch_applied = true;
            effects.route_mapping = Some(true);
            effects.route_activation = Some(true);
            effects.caps_entered = true;
        });
        assert!(!observation.successful_completion(false));
        observation.effects(|effects| effects.caps_returned = true);
        assert!(observation.successful_completion(false));
        assert!(!observation.successful_completion(true));
    }

    #[test]
    fn late_transport_observations_cannot_erase_success() {
        let receipt = receipt();
        let native = written(&receipt, true);
        let prior = native.snapshot();
        assert!(native.transport(Transport::WriteEntered).is_err());
        assert!(native.transport(Transport::BoshRefused { rid: 9 }).is_err());
        assert_eq!(native.snapshot(), prior);
        let bosh = Observation::returned_receipt(&receipt, None);
        bosh.sealed(true, false).unwrap();
        bosh.transport(Transport::BoshExposureEntered { rid: 10 })
            .unwrap();
        assert!(bosh.transport(Transport::BoshAccepted { rid: 11 }).is_err());
        bosh.transport(Transport::BoshAccepted { rid: 10 }).unwrap();
        let prior = bosh.snapshot();
        assert!(bosh.transport(Transport::BoshRefused { rid: 10 }).is_err());
        assert_eq!(bosh.snapshot(), prior);
    }
}
