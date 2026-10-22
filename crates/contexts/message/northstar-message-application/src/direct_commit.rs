//! Exact direct-transaction knowledge, separate from admission and returned mode.
use crate::{validate_authority, InvalidMessageCommand, MessageApplication};
use northstar_abuse_policy::admission_execution::Correlation;
use northstar_message_core::{
    DirectPersonalMessageAdmission, DirectPostCommitMode, DirectSpoolEligibility, MessageCommit,
    MessagePostCommit, PersonalMessageDestination, ValidatedPersonalMessage,
};
use std::future::Future;
use uuid::Uuid;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DirectCommandFacts {
    pub actor_id: Uuid,
    pub recipient_id: Uuid,
    pub delivery_id: Uuid,
    pub archive_ids: Vec<Uuid>,
    pub eligibility: DirectSpoolEligibility,
}

impl DirectCommandFacts {
    pub fn for_local(
        command: &ValidatedPersonalMessage<'_>,
        eligibility: DirectSpoolEligibility,
    ) -> Result<Self, Rejected> {
        let Some(actor_id) = command.local_actor_id else {
            return Err(Rejected::Command);
        };
        let PersonalMessageDestination::Local(destination) = command.destination else {
            return Err(Rejected::Command);
        };
        // This is the existing personal transaction's projection bound. The
        // private normal-local preparation supplies at most sender + recipient.
        if command.archives.len() > 2 {
            return Err(Rejected::Command);
        }
        Ok(Self {
            actor_id,
            recipient_id: destination.recipient_id,
            delivery_id: destination.delivery_id,
            archive_ids: command.archives.iter().map(|archive| archive.id).collect(),
            eligibility,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DirectEffect {
    correlation: Correlation,
    command: DirectCommandFacts,
}

impl DirectEffect {
    pub fn correlation(&self) -> Correlation {
        self.correlation
    }
    pub fn command(&self) -> &DirectCommandFacts {
        &self.command
    }
}

/// Replay IDs are the actual previously stored archive projections returned
/// by the repository, never the fresh IDs in this request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TransactionOutcome {
    Stored {
        recipient_id: Uuid,
        delivery_id: Uuid,
        archive_ids: Vec<Uuid>,
        live_claim_id: Option<Uuid>,
    },
    Replay {
        archive_ids: Vec<Uuid>,
    },
    AccountUnavailable,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedCommit {
    pub correlation: Correlation,
    pub outcome: TransactionOutcome,
    pub admitted_mode: DirectPostCommitMode,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Receipt {
    pub prepared: PreparedCommit,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Knowledge {
    NoCommitRequested,
    CommitCallEntered(PreparedCommit),
    ReceiptKnown(Receipt),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Rejected {
    Command,
    Correlation,
    NotStarted,
    AlreadyStarted,
    AlreadyCompleted,
    Knowledge,
    Result,
}
impl std::fmt::Display for Rejected {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "direct commit rejected: {self:?}")
    }
}
impl std::error::Error for Rejected {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExecutionOutcome {
    Completed(DirectPersonalMessageAdmission),
    PreCommitFailure,
    Unknown,
    ReceiptPreserved(Receipt),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Snapshot {
    pub effect: DirectEffect,
    pub started: bool,
    pub knowledge: Knowledge,
    pub outcome: Option<ExecutionOutcome>,
}

pub(crate) struct Execution {
    state: Snapshot,
}

impl Execution {
    pub(crate) fn new(correlation: Correlation, command: DirectCommandFacts) -> Self {
        Self {
            state: Snapshot {
                effect: DirectEffect {
                    correlation,
                    command,
                },
                started: false,
                knowledge: Knowledge::NoCommitRequested,
                outcome: None,
            },
        }
    }
    pub(crate) fn effect(&self) -> &DirectEffect {
        &self.state.effect
    }
    pub(crate) fn snapshot(&self) -> Snapshot {
        self.state.clone()
    }
    pub(crate) fn state(&self) -> &Snapshot {
        &self.state
    }
    fn validate(&self, effect: &DirectEffect) -> Result<(), Rejected> {
        if self.state.effect != *effect {
            return Err(Rejected::Correlation);
        }
        if self.state.outcome.is_some() {
            return Err(Rejected::AlreadyCompleted);
        }
        Ok(())
    }
    pub(crate) fn start(&mut self, effect: &DirectEffect) -> Result<(), Rejected> {
        self.validate(effect)?;
        if self.state.started {
            return Err(Rejected::AlreadyStarted);
        }
        self.state.started = true;
        Ok(())
    }
    pub(crate) fn enter_commit(
        &mut self,
        effect: &DirectEffect,
        prepared: PreparedCommit,
    ) -> Result<(), Rejected> {
        self.validate(effect)?;
        if !self.state.started {
            return Err(Rejected::NotStarted);
        }
        if prepared.correlation != effect.correlation {
            return Err(Rejected::Correlation);
        }
        if self.state.knowledge != Knowledge::NoCommitRequested {
            return Err(Rejected::Knowledge);
        }
        if prepared.admitted_mode == DirectPostCommitMode::Rejected {
            return Err(Rejected::Knowledge);
        }
        if prepared.admitted_mode == DirectPostCommitMode::SpoolOnly
            && effect.command.eligibility == DirectSpoolEligibility::LiveOnly
        {
            return Err(Rejected::Knowledge);
        }
        match &prepared.outcome {
            TransactionOutcome::Stored {
                recipient_id,
                delivery_id,
                archive_ids,
                live_claim_id,
            } => {
                if *recipient_id != effect.command.recipient_id
                    || *delivery_id != effect.command.delivery_id
                    || *archive_ids != effect.command.archive_ids
                    || live_claim_id.is_some_and(|claim| claim != *delivery_id)
                    || (prepared.admitted_mode != DirectPostCommitMode::Live
                        && live_claim_id.is_some())
                {
                    return Err(Rejected::Knowledge);
                }
            }
            TransactionOutcome::Replay { .. } | TransactionOutcome::AccountUnavailable => {}
        }
        self.state.knowledge = Knowledge::CommitCallEntered(prepared);
        Ok(())
    }
    pub(crate) fn received(
        &mut self,
        effect: &DirectEffect,
        prepared: PreparedCommit,
    ) -> Result<(), Rejected> {
        self.validate(effect)?;
        if !matches!(&self.state.knowledge, Knowledge::CommitCallEntered(expected) if expected == &prepared)
        {
            return Err(Rejected::Knowledge);
        }
        self.state.knowledge = Knowledge::ReceiptKnown(Receipt { prepared });
        Ok(())
    }
    pub(crate) fn complete(
        &mut self,
        effect: &DirectEffect,
        result: Option<DirectPersonalMessageAdmission>,
    ) -> Result<ExecutionOutcome, Rejected> {
        self.validate(effect)?;
        if !self.state.started {
            return Err(Rejected::NotStarted);
        }
        let outcome = if let Some(result) = result {
            let Knowledge::ReceiptKnown(receipt) = &self.state.knowledge else {
                return Err(Rejected::Knowledge);
            };
            let expected = match &receipt.prepared.outcome {
                TransactionOutcome::Stored {
                    recipient_id,
                    delivery_id,
                    archive_ids,
                    live_claim_id,
                } => (
                    MessageCommit::Stored {
                        archive_written: !archive_ids.is_empty(),
                        post_commit: MessagePostCommit::RouteLocalDelivery {
                            recipient_id: *recipient_id,
                            delivery_id: *delivery_id,
                        },
                    },
                    *live_claim_id,
                ),
                TransactionOutcome::Replay { .. } => (MessageCommit::Replay, None),
                TransactionOutcome::AccountUnavailable => (MessageCommit::AccountUnavailable, None),
            };
            if result.commit != expected.0
                || result.live_claim_id != expected.1
                || result.mode == DirectPostCommitMode::Rejected
                || (receipt.prepared.admitted_mode == DirectPostCommitMode::SpoolOnly
                    && result.mode != DirectPostCommitMode::SpoolOnly)
            {
                return Err(Rejected::Result);
            }
            ExecutionOutcome::Completed(result)
        } else {
            match self.state.knowledge {
                Knowledge::NoCommitRequested => ExecutionOutcome::PreCommitFailure,
                Knowledge::CommitCallEntered(_) => ExecutionOutcome::Unknown,
                Knowledge::ReceiptKnown(ref receipt) => {
                    ExecutionOutcome::ReceiptPreserved(receipt.clone())
                }
            }
        };
        self.state.outcome = Some(outcome.clone());
        Ok(outcome)
    }
}

/// The private runtime implementation owns the prepared command and outer
/// operation. Start validates the exact command before repository I/O.
pub trait DirectCommitObserver: Send + Sync {
    fn start(
        &self,
        command: &ValidatedPersonalMessage<'_>,
        eligibility: DirectSpoolEligibility,
    ) -> Result<(), Rejected>;
    fn prepare(
        &self,
        outcome: TransactionOutcome,
        admitted_mode: DirectPostCommitMode,
    ) -> Result<PreparedCommit, Rejected>;
    fn received(&self, prepared: PreparedCommit) -> Result<(), Rejected>;
    fn complete(
        &self,
        result: Option<DirectPersonalMessageAdmission>,
    ) -> Result<ExecutionOutcome, Rejected>;
}

pub trait DirectCommitRepository {
    type Error;
    fn commit_direct<'a>(
        &'a self,
        command: &'a ValidatedPersonalMessage<'a>,
        eligibility: DirectSpoolEligibility,
        observer: Option<&'a dyn DirectCommitObserver>,
    ) -> impl Future<Output = Result<DirectPersonalMessageAdmission, Self::Error>> + Send + 'a;
}

#[derive(Debug)]
pub enum CommitError<E> {
    Invalid(InvalidMessageCommand),
    Observation {
        error: Rejected,
        outcome: Option<ExecutionOutcome>,
    },
    Repository {
        error: E,
        outcome: Option<ExecutionOutcome>,
    },
}

impl<R: DirectCommitRepository> MessageApplication<R> {
    pub async fn commit_direct(
        &self,
        command: &ValidatedPersonalMessage<'_>,
        eligibility: DirectSpoolEligibility,
        observer: Option<&dyn DirectCommitObserver>,
    ) -> Result<DirectPersonalMessageAdmission, CommitError<R::Error>> {
        validate_authority(command).map_err(CommitError::Invalid)?;
        if let Some(observer) = observer {
            observer
                .start(command, eligibility)
                .map_err(|error| CommitError::Observation {
                    error,
                    outcome: None,
                })?;
        }
        let result = self
            .repository
            .commit_direct(command, eligibility, observer)
            .await;
        let outcome = if let Some(observer) = observer {
            match observer.complete(result.as_ref().ok().copied()) {
                Ok(outcome) => Some(outcome),
                Err(error) => {
                    return Err(CommitError::Observation {
                        error,
                        outcome: observer.complete(None).ok(),
                    })
                }
            }
        } else {
            None
        };
        result.map_err(|error| CommitError::Repository { error, outcome })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PersonalMessageCommitRepository;
    use northstar_message_core::{IdentityAuthority, LocalDelivery, MessageIdentity};
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Mutex,
    };

    fn command() -> ValidatedPersonalMessage<'static> {
        ValidatedPersonalMessage {
            local_actor_id: Some(Uuid::from_u128(1)),
            identity: None,
            archives: &[],
            destination: PersonalMessageDestination::Local(LocalDelivery {
                delivery_id: Uuid::from_u128(2),
                recipient_id: Uuid::from_u128(3),
                recipient_bare_jid: "bob@example.test",
                sender_jid: "alice@example.test/device",
                stanza: "stored-private-payload",
                encrypted: false,
                mam_backed: false,
            }),
        }
    }
    struct Observer(Mutex<Execution>);
    impl Observer {
        fn new() -> Self {
            Self(Mutex::new(Execution::new(
                Correlation {
                    operation: Uuid::from_u128(4),
                    effect: 3,
                    generation: 0,
                    attempt: 1,
                },
                DirectCommandFacts::for_local(&command(), DirectSpoolEligibility::Eligible)
                    .unwrap(),
            )))
        }
        fn snapshot(&self) -> Snapshot {
            self.0.lock().unwrap().snapshot()
        }
    }
    impl DirectCommitObserver for Observer {
        fn start(
            &self,
            actual: &ValidatedPersonalMessage<'_>,
            eligibility: DirectSpoolEligibility,
        ) -> Result<(), Rejected> {
            if *actual != command() || eligibility != DirectSpoolEligibility::Eligible {
                return Err(Rejected::Command);
            }
            let mut execution = self.0.lock().unwrap();
            let effect = execution.effect().clone();
            execution.start(&effect)
        }
        fn prepare(
            &self,
            outcome: TransactionOutcome,
            admitted_mode: DirectPostCommitMode,
        ) -> Result<PreparedCommit, Rejected> {
            let mut execution = self.0.lock().unwrap();
            let effect = execution.effect().clone();
            let prepared = PreparedCommit {
                correlation: effect.correlation(),
                outcome,
                admitted_mode,
            };
            execution.enter_commit(&effect, prepared.clone())?;
            Ok(prepared)
        }
        fn received(&self, prepared: PreparedCommit) -> Result<(), Rejected> {
            let mut execution = self.0.lock().unwrap();
            let effect = execution.effect().clone();
            execution.received(&effect, prepared)
        }
        fn complete(
            &self,
            result: Option<DirectPersonalMessageAdmission>,
        ) -> Result<ExecutionOutcome, Rejected> {
            let mut execution = self.0.lock().unwrap();
            let effect = execution.effect().clone();
            execution.complete(&effect, result)
        }
    }
    #[derive(Clone, Copy)]
    enum Cut {
        BeforeCommit,
        DuringCommit,
        AfterReceipt,
        Return,
    }
    struct Repository {
        fact: TransactionOutcome,
        admitted: DirectPostCommitMode,
        returned: DirectPersonalMessageAdmission,
        cut: Cut,
        calls: AtomicUsize,
    }
    impl PersonalMessageCommitRepository for Repository {
        type Error = &'static str;
        async fn commit<'a>(
            &'a self,
            _: &'a ValidatedPersonalMessage<'a>,
        ) -> Result<MessageCommit, Self::Error> {
            panic!("mode-aware consumer must use its actual port")
        }
    }
    impl DirectCommitRepository for Repository {
        type Error = &'static str;
        async fn commit_direct<'a>(
            &'a self,
            _: &'a ValidatedPersonalMessage<'a>,
            _: DirectSpoolEligibility,
            observer: Option<&'a dyn DirectCommitObserver>,
        ) -> Result<DirectPersonalMessageAdmission, Self::Error> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            if matches!(self.cut, Cut::BeforeCommit) {
                return Err("before");
            }
            if let Some(observer) = observer {
                let prepared = observer.prepare(self.fact.clone(), self.admitted).unwrap();
                if matches!(self.cut, Cut::DuringCommit) {
                    return Err("during");
                }
                observer.received(prepared).unwrap();
                if matches!(self.cut, Cut::AfterReceipt) {
                    return Err("after");
                }
            }
            Ok(self.returned)
        }
    }
    fn stored(
        claim: Option<Uuid>,
        admitted: DirectPostCommitMode,
        returned: DirectPostCommitMode,
        cut: Cut,
    ) -> Repository {
        Repository {
            fact: TransactionOutcome::Stored {
                recipient_id: Uuid::from_u128(3),
                delivery_id: Uuid::from_u128(2),
                archive_ids: vec![],
                live_claim_id: claim,
            },
            admitted,
            returned: DirectPersonalMessageAdmission {
                commit: MessageCommit::Stored {
                    archive_written: false,
                    post_commit: MessagePostCommit::RouteLocalDelivery {
                        recipient_id: Uuid::from_u128(3),
                        delivery_id: Uuid::from_u128(2),
                    },
                },
                mode: returned,
                live_claim_id: claim,
            },
            cut,
            calls: AtomicUsize::new(0),
        }
    }

    #[tokio::test]
    async fn actual_mode_port_accepts_standalone_cluster_and_degraded_return_only_with_receipt() {
        for (claim, admitted, returned) in [
            (None, DirectPostCommitMode::Live, DirectPostCommitMode::Live),
            (
                Some(Uuid::from_u128(2)),
                DirectPostCommitMode::Live,
                DirectPostCommitMode::Live,
            ),
            (
                Some(Uuid::from_u128(2)),
                DirectPostCommitMode::Live,
                DirectPostCommitMode::SpoolOnly,
            ),
            (
                None,
                DirectPostCommitMode::SpoolOnly,
                DirectPostCommitMode::SpoolOnly,
            ),
        ] {
            let application =
                MessageApplication::new(stored(claim, admitted, returned, Cut::Return));
            let observer = Observer::new();
            let result = application
                .commit_direct(
                    &command(),
                    DirectSpoolEligibility::Eligible,
                    Some(&observer),
                )
                .await
                .unwrap();
            assert_eq!(result.mode, returned);
            assert!(matches!(
                observer.snapshot().knowledge,
                Knowledge::ReceiptKnown(_)
            ));
            assert_eq!(application.repository.calls.load(Ordering::Relaxed), 1);
        }
    }

    #[tokio::test]
    async fn commit_error_cuts_keep_independent_unknown_and_positive_receipt_facts() {
        for cut in [Cut::BeforeCommit, Cut::DuringCommit, Cut::AfterReceipt] {
            let application = MessageApplication::new(stored(
                None,
                DirectPostCommitMode::Live,
                DirectPostCommitMode::Live,
                cut,
            ));
            let observer = Observer::new();
            let error = application
                .commit_direct(
                    &command(),
                    DirectSpoolEligibility::Eligible,
                    Some(&observer),
                )
                .await
                .unwrap_err();
            let CommitError::Repository {
                outcome: Some(outcome),
                ..
            } = error
            else {
                panic!("repository classification")
            };
            assert!(matches!(
                (cut, outcome),
                (Cut::BeforeCommit, ExecutionOutcome::PreCommitFailure)
                    | (Cut::DuringCommit, ExecutionOutcome::Unknown)
                    | (Cut::AfterReceipt, ExecutionOutcome::ReceiptPreserved(_))
            ));
        }
    }

    #[tokio::test]
    async fn replay_and_unavailable_receipts_never_claim_fresh_requested_rows() {
        for (fact, commit) in [
            (
                TransactionOutcome::Replay {
                    archive_ids: vec![Uuid::from_u128(77)],
                },
                MessageCommit::Replay,
            ),
            (
                TransactionOutcome::AccountUnavailable,
                MessageCommit::AccountUnavailable,
            ),
        ] {
            for cut in [Cut::Return, Cut::AfterReceipt] {
                let mut repository = stored(
                    None,
                    DirectPostCommitMode::Live,
                    DirectPostCommitMode::Live,
                    cut,
                );
                repository.fact = fact.clone();
                repository.returned.commit = commit;
                let application = MessageApplication::new(repository);
                let observer = Observer::new();
                let returned = application
                    .commit_direct(
                        &command(),
                        DirectSpoolEligibility::Eligible,
                        Some(&observer),
                    )
                    .await;
                if matches!(cut, Cut::Return) {
                    assert_eq!(returned.unwrap().commit, commit);
                } else {
                    assert!(matches!(
                        returned,
                        Err(CommitError::Repository {
                            outcome: Some(ExecutionOutcome::ReceiptPreserved(_)),
                            ..
                        })
                    ));
                }
                let Knowledge::ReceiptKnown(receipt) = observer.snapshot().knowledge else {
                    panic!("receipt")
                };
                assert_eq!(receipt.prepared.outcome, fact);
            }
        }
    }

    #[tokio::test]
    async fn mismatched_success_preserves_actual_receipt_and_cannot_become_a_route_result() {
        let mut repository = stored(
            None,
            DirectPostCommitMode::Live,
            DirectPostCommitMode::Live,
            Cut::Return,
        );
        repository.returned.commit = MessageCommit::Replay;
        let application = MessageApplication::new(repository);
        let observer = Observer::new();
        assert!(matches!(
            application
                .commit_direct(
                    &command(),
                    DirectSpoolEligibility::Eligible,
                    Some(&observer)
                )
                .await,
            Err(CommitError::Observation {
                error: Rejected::Result,
                outcome: Some(ExecutionOutcome::ReceiptPreserved(_))
            })
        ));
        assert!(matches!(
            observer.snapshot().knowledge,
            Knowledge::ReceiptKnown(_)
        ));
    }

    #[tokio::test]
    async fn authenticated_remote_convenience_uses_mode_port_without_local_witness() {
        let mut remote = command();
        remote.local_actor_id = None;
        remote.identity = Some(MessageIdentity {
            authority: IdentityAuthority::AuthenticatedRemoteStanza,
            actor_scope_raw: "sender@remote.test",
            actor_scope: "sender@remote.test",
            target_scope: "bob@example.test",
            value: "remote-origin",
            payload: "remote-payload",
        });
        let application = MessageApplication::new(stored(
            None,
            DirectPostCommitMode::Live,
            DirectPostCommitMode::Live,
            Cut::Return,
        ));
        application
            .commit_direct(&remote, DirectSpoolEligibility::Eligible, None)
            .await
            .unwrap();
        assert_eq!(application.repository.calls.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn wrong_effect_and_receipt_are_inert_and_finished_effect_cannot_mutate() {
        let observer = Observer::new();
        observer
            .start(&command(), DirectSpoolEligibility::Eligible)
            .unwrap();
        let prepared = observer
            .prepare(
                TransactionOutcome::AccountUnavailable,
                DirectPostCommitMode::Live,
            )
            .unwrap();
        let before = observer.snapshot();
        let mut wrong = prepared.clone();
        wrong.correlation.generation += 1;
        assert_eq!(observer.received(wrong), Err(Rejected::Knowledge));
        assert_eq!(observer.snapshot(), before);
        observer.received(prepared.clone()).unwrap();
        observer.complete(None).unwrap();
        let finished = observer.snapshot();
        assert_eq!(observer.received(prepared), Err(Rejected::AlreadyCompleted));
        assert_eq!(observer.snapshot(), finished);
    }

    #[test]
    fn live_only_cannot_commit_spooled_but_may_degrade_after_a_live_commit() {
        let mut execution = Execution::new(
            Correlation {
                operation: Uuid::from_u128(90),
                effect: 3,
                generation: 0,
                attempt: 1,
            },
            DirectCommandFacts::for_local(&command(), DirectSpoolEligibility::LiveOnly).unwrap(),
        );
        let effect = execution.effect().clone();
        execution.start(&effect).unwrap();
        let repository = stored(
            None,
            DirectPostCommitMode::Live,
            DirectPostCommitMode::SpoolOnly,
            Cut::Return,
        );
        let mut prepared = PreparedCommit {
            correlation: effect.correlation(),
            outcome: repository.fact,
            admitted_mode: DirectPostCommitMode::SpoolOnly,
        };
        let before = execution.snapshot();
        assert_eq!(
            execution.enter_commit(&effect, prepared.clone()),
            Err(Rejected::Knowledge)
        );
        assert_eq!(execution.snapshot(), before);
        prepared.admitted_mode = DirectPostCommitMode::Live;
        execution.enter_commit(&effect, prepared.clone()).unwrap();
        execution.received(&effect, prepared).unwrap();
        assert_eq!(
            execution
                .complete(&effect, Some(repository.returned))
                .unwrap(),
            ExecutionOutcome::Completed(repository.returned)
        );
    }
}
