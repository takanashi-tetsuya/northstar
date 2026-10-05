//! Auth publication facts beginning at an actual returned credential receipt.
//! These observations neither recreate that receipt nor authorize SQL or I/O.
use super::{AuthenticationResult, BindingPublication, CredentialCommitReceipt, StagedLoginEpoch};
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
