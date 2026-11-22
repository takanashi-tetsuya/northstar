//! Credential invocation observations across repository calls and return.

use super::credential::{
    CredentialCall, CredentialKind, CredentialPreparation, CredentialRequest, CredentialReturned,
    CredentialRollbackSite, CredentialSnapshot, CredentialState, CredentialTerminal,
    CredentialWitness, Eligibility, PreparationResult, PreparedCredential, ReceiptProjection,
};
use super::CommitError;
use anyhow::{ensure, Result};
use northstar_auth_core::credential::{
    AuthenticationResult, CredentialCommitReceipt, FastCommitPlan, StagedLoginEpoch,
};
use std::future::Future;
use uuid::Uuid;

pub struct CredentialInvocation<'a> {
    pub(super) prepared: &'a PreparedCredential,
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
    pub fn enter_fast(
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
    pub fn enter_binding(
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
    pub fn enter_resume(
        &self,
        request: &crate::finalization::SmResumeFinalizationRequest<'_>,
    ) -> Result<()> {
        self.enter_repository(CredentialRequest::resume(request))
    }
    pub async fn begin<F, T, E>(
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
    pub async fn eligibility<F, E>(
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
    pub fn transaction_returned(&self) {
        self.update(|state| state.snapshot.transaction_returned = true);
    }
    pub fn preparation_entered(&self, operation: CredentialPreparation) {
        self.preparation_update(|state| {
            let slot = &mut state.snapshot.preparation[operation.index()];
            if *slot != PreparationResult::NotEntered {
                state.integrity = false;
                return;
            }
            *slot = PreparationResult::Entered;
        });
    }
    pub fn preparation_returned(
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
    pub fn stage_id(&self, operation_id: Uuid) {
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
    pub fn stage_returned(&self, result: &Result<Option<StagedLoginEpoch>>) {
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
    pub async fn rollback<F, E>(
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
    pub async fn commit<F, E>(
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
    pub fn constructed(&self, receipt: &CredentialCommitReceipt) {
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
    pub fn fast_returned(&self, result: &AuthenticationResult<CredentialCommitReceipt>) {
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
    pub fn binding_returned(
        &self,
        result: &Result<crate::finalization::BindingFinalizationOutcome>,
    ) {
        use crate::finalization::BindingFinalizationOutcome as Outcome;
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
    pub fn resume_returned(
        &self,
        result: &Result<crate::finalization::SmResumeFinalizationOutcome>,
    ) {
        use crate::finalization::SmResumeFinalizationOutcome as Outcome;
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
