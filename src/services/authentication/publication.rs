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
// These test-only joins describe the actual receipt instances at each cut.
// They contain no request projection and confer no credential authority.
#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CredentialAttemptJoin {
    pub(crate) attempt: Uuid,
    pub(crate) frame: Uuid,
    pub(crate) connection: Uuid,
    pub(crate) ordinal: u8,
    pub(crate) kind: CredentialKind,
}
#[cfg(test)]
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
#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CredentialJoins {
    pub(crate) owner: CredentialAttemptJoin,
    pub(crate) constructed_receipt: Option<Uuid>,
    pub(crate) returned_receipt: Option<Uuid>,
    pub(crate) transferred_receipt: Option<Uuid>,
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
    #[cfg(test)]
    transferred_receipt: Option<Uuid>,
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
    #[cfg(test)]
    pub(crate) fn joins(&self) -> CredentialJoins {
        let state = self.0.lock().unwrap();
        CredentialJoins {
            owner: CredentialAttemptJoin::of(&state.snapshot),
            constructed_receipt: state.constructed.as_ref().map(|(id, _)| *id),
            returned_receipt: state.returned.as_ref().map(|(id, _)| *id),
            transferred_receipt: state.transferred_receipt,
        }
    }
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
                #[cfg(test)]
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
        #[cfg(test)]
        {
            state.transferred_receipt = Some(receipt.publication_identity());
        }
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
#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PublicationJoins {
    pub(crate) control: Uuid,
    pub(crate) frame: Option<Uuid>,
    pub(crate) receipt: Uuid,
    pub(crate) credential: Option<CredentialAttemptJoin>,
    pub(crate) begun_receipt: Option<Uuid>,
    pub(crate) bound_effects: bool,
    pub(crate) notification_expected: bool,
}
struct State {
    receipt_id: Uuid,
    #[cfg(test)]
    begun_receipt: Option<Uuid>,
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
            #[cfg(test)]
            begun_receipt: None,
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
    #[cfg(test)]
    pub(crate) fn joins(&self) -> PublicationJoins {
        let state = self.0.lock().unwrap();
        PublicationJoins {
            control: state.snapshot.control,
            frame: state.snapshot.frame,
            receipt: state.receipt_id,
            credential: state
                .credential
                .as_ref()
                .map(|credential| credential.joins().owner),
            begun_receipt: state.begun_receipt,
            bound_effects: state.bound_effects,
            notification_expected: state.notification_expected,
        }
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
        #[cfg(test)]
        {
            state.begun_receipt = Some(receipt.publication_identity());
        }
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
mod tests;
