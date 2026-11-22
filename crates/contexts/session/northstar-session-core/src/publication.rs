//! Auth publication facts beginning at an actual returned credential receipt.
//! These observations neither recreate that receipt nor authorize SQL or I/O.
use anyhow::{ensure, Result};
use northstar_auth_core::credential::{AuthenticationResult, CredentialCommitReceipt};
#[cfg(test)]
use northstar_auth_core::credential::{FastCommitPlan, StagedLoginEpoch};
use std::{
    future::Future,
    sync::{Arc, Mutex},
};
use uuid::Uuid;

mod credential;
mod credential_invocation;

use credential::ReceiptProjection;
pub use credential::{
    credential_error, CredentialCall, CredentialKind, CredentialObservation, CredentialPreparation,
    CredentialReturned, CredentialRollbackSite, CredentialSnapshot, CredentialTerminal,
    Eligibility, PreparationResult, PreparedCredential,
};
#[cfg(any(test, feature = "test-support"))]
pub use credential::{CredentialAttemptJoin, CredentialJoins};
pub use credential_invocation::CredentialInvocation;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HandlerReturn {
    Completed,
    Failed,
    TimedOut,
    Cancelled,
    Panicked,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Transport {
    NotStarted,
    Recording,
    WriteEntered,
    Written,
    BoshExposureEntered { rid: u64 },
    BoshAccepted { rid: u64 },
    BoshRefused { rid: u64 },
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Knowledge {
    NotStarted,
    NotRequired,
    BeforeCommit,
    CommitCallEntered,
    ReceiptKnown(Option<i64>),
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Rollback {
    NotRequested,
    CallEntered,
    Returned,
    Failed,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Returned {
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
pub enum Terminal {
    Completed,
    DeferredNotification,
    Failed,
    Cancelled,
    Panicked,
    Abandoned,
    ExposedNotAttempted,
}
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Effects {
    pub unbound: bool,
    pub epoch_applied: bool,
    pub route_mapping: Option<bool>,
    pub route_activation: Option<bool>,
    pub caps_entered: bool,
    pub caps_returned: bool,
    pub notification_entered: bool,
    pub notification_returned: Option<bool>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Snapshot {
    pub control: Uuid,
    pub frame: Option<Uuid>,
    pub handler: Option<HandlerReturn>,
    pub sealed: bool,
    pub transport: Transport,
    pub publication: Knowledge,
    pub service_started: bool,
    pub repository_started: bool,
    pub rollback: Rollback,
    pub returned: Option<Returned>,
    pub return_matches: bool,
    pub effects: Effects,
    pub terminal: Option<Terminal>,
}
#[cfg(any(test, feature = "test-support"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublicationJoins {
    pub control: Uuid,
    pub frame: Option<Uuid>,
    pub receipt: Uuid,
    pub credential: Option<CredentialAttemptJoin>,
    pub begun_receipt: Option<Uuid>,
    pub bound_effects: bool,
    pub notification_expected: bool,
}
struct State {
    receipt_id: Uuid,
    #[cfg(any(test, feature = "test-support"))]
    begun_receipt: Option<Uuid>,
    receipt: ReceiptProjection,
    bound_effects: bool,
    notification_expected: bool,
    credential: Option<CredentialObservation>,
    snapshot: Snapshot,
}
#[derive(Clone)]
pub struct Observation(Arc<Mutex<State>>);
impl std::fmt::Debug for Observation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AuthPublicationObservation { receipt and identity: [redacted] }")
    }
}
impl Observation {
    pub fn returned_receipt(receipt: &CredentialCommitReceipt, frame: Option<Uuid>) -> Self {
        Self(Arc::new(Mutex::new(State {
            receipt_id: receipt.publication_identity(),
            #[cfg(any(test, feature = "test-support"))]
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
    pub fn observed_receipt(
        receipt: &CredentialCommitReceipt,
        frame: Uuid,
        credential: CredentialObservation,
    ) -> Self {
        let observation = Self::returned_receipt(receipt, Some(frame));
        observation.0.lock().unwrap().credential = Some(credential);
        observation
    }
    #[cfg(any(test, feature = "test-support"))]
    pub fn credential(&self) -> Option<CredentialObservation> {
        self.0.lock().unwrap().credential.clone()
    }
    #[cfg(any(test, feature = "test-support"))]
    pub fn joins(&self) -> PublicationJoins {
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
    pub fn snapshot(&self) -> Snapshot {
        self.0.lock().unwrap().snapshot.clone()
    }
    pub fn handler_returned(&self, returned: HandlerReturn) {
        let mut state = self.0.lock().unwrap();
        state.snapshot.handler.get_or_insert(returned);
        if !state.snapshot.sealed && state.snapshot.terminal.is_none() {
            state.snapshot.terminal = Some(Terminal::Abandoned);
        }
    }
    pub fn sealed(&self, bound: bool, notification: bool) -> Result<()> {
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
    pub fn transport(&self, transport: Transport) -> Result<()> {
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
    pub fn effects(&self, update: impl FnOnce(&mut Effects)) {
        update(&mut self.0.lock().unwrap().snapshot.effects);
    }
    pub fn retire(&self, terminal: Terminal) {
        let mut state = self.0.lock().unwrap();
        state.snapshot.terminal.get_or_insert(terminal);
    }
    pub fn successful_completion(&self, deferred: bool) -> bool {
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
    pub fn completed(&self) -> bool {
        match self.snapshot().terminal {
            Some(Terminal::Completed) => self.successful_completion(false),
            Some(Terminal::DeferredNotification) => self.successful_completion(true),
            _ => false,
        }
    }
    pub fn authenticated_return(&self, epoch: Option<i64>) -> bool {
        let snapshot = self.snapshot();
        snapshot.return_matches && snapshot.returned == Some(Returned::Authenticated(epoch))
    }
    pub fn abandon(&self) {
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
    pub fn begin<'a>(&'a self, receipt: &'a CredentialCommitReceipt) -> Result<Invocation<'a>> {
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
        #[cfg(any(test, feature = "test-support"))]
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
pub struct Invocation<'a> {
    observation: &'a Observation,
    receipt: &'a CredentialCommitReceipt,
}
impl Invocation<'_> {
    pub fn receipt(&self) -> &CredentialCommitReceipt {
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
    pub fn enter_service(&self) -> Result<()> {
        let mut state = self.observation.0.lock().unwrap();
        self.validate(&state)?;
        ensure!(
            !state.snapshot.service_started,
            "auth publication service already started"
        );
        state.snapshot.service_started = true;
        Ok(())
    }
    pub fn enter_repository(&self) -> Result<()> {
        let mut state = self.observation.0.lock().unwrap();
        self.validate(&state)?;
        ensure!(
            state.snapshot.service_started && !state.snapshot.repository_started,
            "auth publication repository is not pending"
        );
        state.snapshot.repository_started = true;
        Ok(())
    }
    pub fn not_required(&self) -> Result<()> {
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
    pub async fn commit<F, E>(&self, future: F, epoch: Option<i64>) -> Result<(), CommitError<E>>
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
    pub async fn rollback<F, E>(&self, future: F) -> Result<(), CommitError<E>>
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
    pub fn returned(&self, returned: &AuthenticationResult<Option<i64>>) -> bool {
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
pub enum CommitError<E> {
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
