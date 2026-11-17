//! Rated admission drives the same coordinator as controlled cases.
//! Reservation, independent finalization and guard-only transactions stay distinct.
pub mod witness;

use anyhow::Result;
use northstar_abuse_policy::admission_execution::{
    BeginRequest, BeginResult, Command, Completion, Coordinator, Correlation, Effect, EffectResult,
    ExecutionOutcome, FailureKind, GuardDecision, Knowledge, ReconcileResult, TransactionScope,
};
use northstar_abuse_policy::admission_transaction::{AdmissionFence, FinalizeDecision};
use northstar_abuse_policy::message_admission::{
    acceptance_fence, MessageAdmissionAcceptance, MessageAdmissionLease, MessageAdmissionStart,
};
use northstar_abuse_policy::MessageAdmissionRequest;
use uuid::Uuid;
use witness::{AdmissionWitness, RetainedAdmission};

pub trait MessageAdmissionRepository: Send + Sync {
    fn begin(
        &self,
        request: &MessageAdmissionRequest<'_>,
        witness: &AdmissionWitness,
    ) -> impl std::future::Future<Output = Result<MessageAdmissionStart>> + Send;
    fn accept(
        &self,
        acceptance: &MessageAdmissionAcceptance<'_>,
        witness: &AdmissionWitness,
    ) -> impl std::future::Future<Output = Result<FinalizeDecision>> + Send;
    fn reconcile(
        &self,
        effect: &Effect,
    ) -> impl std::future::Future<Output = Result<ReconcileResult>> + Send;
}

pub fn begin_command(request: &MessageAdmissionRequest<'_>) -> Result<Command> {
    northstar_abuse_policy::message_admission::validate_message_admission_request(request)?;
    Ok(Command::Begin(BeginRequest::from(*request)))
}
pub fn operation(command: Command) -> (Coordinator, AdmissionWitness) {
    let coordinator = Coordinator::new(
        Correlation {
            operation: Uuid::new_v4(),
            effect: 1,
            generation: 0,
            attempt: 1,
        },
        command,
    );
    let witness = AdmissionWitness::new(coordinator.pending().expect("new operation").clone());
    (coordinator, witness)
}

#[derive(Clone)]
pub struct MessageAdmissionService<R> {
    repository: R,
}

/// Redacted classification: no SQL/row/payload text in emitted errors.
#[derive(Debug, thiserror::Error)]
#[error("admission execution failed: {outcome:?}")]
struct AdmissionExecutionError {
    outcome: ExecutionOutcome,
}

fn failure(error: &anyhow::Error) -> FailureKind {
    if northstar_abuse_policy::message_admission::is_abuse_state_busy(error) {
        FailureKind::ActorBusy
    } else {
        FailureKind::Backend
    }
}
fn error_for(outcome: ExecutionOutcome) -> anyhow::Error {
    if matches!(
        outcome,
        ExecutionOutcome::PreCommitFailure(FailureKind::ActorBusy)
    ) {
        return northstar_abuse_policy::message_admission::AbuseStateBusy.into();
    }
    AdmissionExecutionError { outcome }.into()
}

fn begin_result(result: &MessageAdmissionStart, knowledge: &Knowledge) -> BeginResult {
    match result {
        MessageAdmissionStart::Proceed {
            lease: Some(lease), ..
        } => BeginResult::Reserved(acceptance_fence(&lease.acceptance())),
        MessageAdmissionStart::Proceed { lease: None, .. } => {
            BeginResult::GuardOnly(GuardDecision::Allowed)
        }
        MessageAdmissionStart::ReplayAccepted => BeginResult::ReplayAccepted,
        MessageAdmissionStart::InProgress { .. } => BeginResult::InProgress,
        MessageAdmissionStart::Denied(_) => {
            if matches!(knowledge, Knowledge::NoCommitRequested)
                || matches!(knowledge, Knowledge::ReceiptKnown(r) if r.scope == TransactionScope::GuardOnlyVerification)
            {
                BeginResult::GuardOnly(GuardDecision::Denied)
            } else {
                BeginResult::Denied
            }
        }
        MessageAdmissionStart::Conflict => BeginResult::Conflict,
        MessageAdmissionStart::CapacityLimited => BeginResult::CapacityLimited,
    }
}

impl<R: MessageAdmissionRepository> MessageAdmissionService<R> {
    pub fn new(repository: R) -> Self {
        Self { repository }
    }

    /// Production frame callers create `retained` synchronously outside this
    /// future. Dropping this await cannot discard its witness or exact command.
    pub async fn begin_message_admission_retained(
        &self,
        request: &MessageAdmissionRequest<'_>,
        retained: &RetainedAdmission,
    ) -> Result<MessageAdmissionStart> {
        retained.start(&begin_command(request)?)?;
        let witness = retained.witness();
        let result = self.repository.begin(request, &witness).await;
        let knowledge = witness.snapshot().knowledge().clone();
        let completion = match &result {
            Ok(value) => EffectResult::Begin(begin_result(value, &knowledge)),
            Err(error) => EffectResult::Failed(failure(error)),
        };
        let outcome = retained.complete(completion)?;
        match outcome {
            ExecutionOutcome::Completed {
                result: EffectResult::Begin(_),
                ..
            } => {
                // Only an accepted Stage2 completion issues authority. Guard
                // success remains distinct from a durable reservation receipt.
                use crate::direct_lifecycle::AdmissionGrant;
                match (&result, retained.admission_grant()) {
                    (
                        Ok(MessageAdmissionStart::Proceed { lease: Some(_), .. }),
                        Some(AdmissionGrant::Reserved(_)),
                    )
                    | (
                        Ok(MessageAdmissionStart::Proceed { lease: None, .. }),
                        Some(AdmissionGrant::GuardOnly(_)),
                    ) => {}
                    (Ok(MessageAdmissionStart::Proceed { .. }), _) => {
                        anyhow::bail!("completed admission lacked its matching grant");
                    }
                    _ => {}
                }
                result
            }
            other => Err(error_for(other)),
        }
    }

    pub async fn accept_message_admission_retained(
        &self,
        lease: &MessageAdmissionLease,
        retained: &RetainedAdmission,
    ) -> Result<()> {
        let acceptance = lease.acceptance();
        retained.start(&Command::Finalize(acceptance_fence(&acceptance)))?;
        let witness = retained.witness();
        let result = self.repository.accept(&acceptance, &witness).await;
        let completion = match &result {
            Ok(decision) => EffectResult::Finalize(*decision),
            Err(error) => EffectResult::Failed(failure(error)),
        };
        match retained.complete(completion)? {
            ExecutionOutcome::Completed {
                result:
                    EffectResult::Finalize(
                        FinalizeDecision::AcceptPending | FinalizeDecision::AlreadyAccepted,
                    ),
                ..
            } => Ok(()),
            other => Err(error_for(other)),
        }
    }

    pub async fn begin_message_admission(
        &self,
        request: &MessageAdmissionRequest<'_>,
    ) -> Result<MessageAdmissionStart> {
        let (mut coordinator, witness) = operation(begin_command(request)?);
        let effect = coordinator.pending().expect("new begin").clone();
        let result = self.repository.begin(request, &witness).await;
        let observed = witness.snapshot();
        coordinator.observe_witness(&observed)?;
        let knowledge = observed.knowledge().clone();
        let completion_result = match &result {
            Ok(value) => EffectResult::Begin(begin_result(value, &knowledge)),
            Err(error) => EffectResult::Failed(failure(error)),
        };
        let outcome = coordinator
            .complete(Completion {
                effect,
                result: completion_result,
                knowledge,
            })?
            .clone();
        match outcome {
            ExecutionOutcome::Completed {
                result: EffectResult::Begin(_),
                ..
            } => result,
            other => Err(error_for(other)),
        }
    }

    pub async fn accept_message_admission(&self, lease: &MessageAdmissionLease) -> Result<()> {
        let acceptance = lease.acceptance();
        let (mut coordinator, witness) =
            operation(Command::Finalize(acceptance_fence(&acceptance)));
        let effect = coordinator.pending().expect("new finalize").clone();
        let result = self.repository.accept(&acceptance, &witness).await;
        let observed = witness.snapshot();
        coordinator.observe_witness(&observed)?;
        let completion_result = match &result {
            Ok(decision) => EffectResult::Finalize(*decision),
            Err(error) => EffectResult::Failed(failure(error)),
        };
        let outcome = coordinator
            .complete(Completion {
                effect,
                result: completion_result,
                knowledge: observed.knowledge().clone(),
            })?
            .clone();
        match outcome {
            ExecutionOutcome::Completed {
                result:
                    EffectResult::Finalize(
                        FinalizeDecision::AcceptPending | FinalizeDecision::AlreadyAccepted,
                    ),
                ..
            } => Ok(()),
            other => Err(error_for(other)),
        }
    }

    /// Read-only observation, not permission to repeat Begin or route. Stage3 owns scheduling.
    #[allow(dead_code)]
    pub async fn reconcile_message_admission(
        &self,
        unresolved: Correlation,
        fence: AdmissionFence,
    ) -> Result<ReconcileResult> {
        let (mut coordinator, witness) = operation(Command::Reconcile {
            unresolved,
            fence: fence.clone(),
        });
        let effect = coordinator.pending().expect("new reconcile").clone();
        let result = self.repository.reconcile(&effect).await;
        let observed = witness.snapshot();
        coordinator.observe_witness(&observed)?;
        let completion_result = match &result {
            Ok(observation) => EffectResult::Reconcile(observation.clone()),
            Err(error) => EffectResult::Failed(failure(error)),
        };
        let outcome = coordinator
            .complete(Completion {
                effect,
                result: completion_result,
                knowledge: observed.knowledge().clone(),
            })?
            .clone();
        match outcome {
            ExecutionOutcome::Completed {
                result: EffectResult::Reconcile(observation),
                ..
            } => Ok(observation),
            other => Err(error_for(other)),
        }
    }
}

/// Shared finalization body. The lazy owner lookup is intentionally skipped
/// when no lease exists; preparing the retained handle precedes taking it.
pub async fn finalize_message_admission_with<A, O, F, E>(
    service: &MessageAdmissionService<A>,
    lease: &mut Option<MessageAdmissionLease>,
    route_label: &'static str,
    operation: O,
    enter_followup: F,
    post_accept_failed: E,
) where
    A: MessageAdmissionRepository,
    O: FnOnce() -> Option<witness::DirectOperationHandle>,
    F: FnOnce(),
    E: FnOnce(),
{
    let Some(retained_lease) = lease.as_ref() else {
        return;
    };
    let retained = operation().map(|operation| operation.finalize(retained_lease));
    let lease = lease.take().expect("lease checked above");
    enter_followup();
    let result = match retained {
        Some(Ok(retained)) => {
            service
                .accept_message_admission_retained(&lease, &retained)
                .await
        }
        Some(Err(error)) => Err(error),
        None => service.accept_message_admission(&lease).await,
    };
    if let Err(error) = result {
        // Acceptance cannot be turned into a retriable stanza rejection by
        // failure to finish its independent PoW reservation transaction.
        post_accept_failed();
        tracing::warn!(target: "northstar_server::xmpp::protocol::messaging",
            ?error, route = route_label,
            "accepted message PoW admission could not be finalized");
    }
}

#[cfg(any(test, feature = "test-support"))]
pub mod continuation_fixture {
    use super::*;
    use northstar_abuse_policy::admission_execution::{
        AdmissionCommitObserver, BeginCommitPurpose, CommitFact, FinalizeSuccess,
    };
    use northstar_abuse_policy::{MessageDedupeIdentity, WorkRequirement};
    use std::sync::{Arc, Mutex};

    pub type Events = Arc<Mutex<Vec<&'static str>>>;
    #[derive(Clone, Copy, Eq, PartialEq)]
    pub enum Admission {
        Reserved,
        GuardOnly,
        NotRated,
    }
    #[derive(Clone, Copy, Default, Eq, PartialEq)]
    pub enum FinalizeCut {
        #[default]
        Success,
        PreCommitError,
        CommitError,
        AfterReceiptError,
        PendingBeforeCommit,
        PendingCommit,
    }
    pub struct Repository {
        pub admission: Admission,
        pub cut: FinalizeCut,
        pub events: Events,
    }
    pub fn lease(token: u128) -> MessageAdmissionLease {
        MessageAdmissionLease::new(
            vec![1; 32],
            vec![2; 32],
            Uuid::from_u128(token),
            MessageDedupeIdentity {
                identity_digest: vec![4; 32],
                candidates: vec![],
            },
        )
    }
    pub fn request() -> MessageAdmissionRequest<'static> {
        MessageAdmissionRequest {
            actor_id: Uuid::from_u128(1),
            account_bare: "alice@example.test",
            normalized_target: "bob@example.test",
            origin_id: Some("origin"),
            normalized_payload: "private-admission-stanza",
            pow_intent_payload: "private-admission-stanza",
            subject: "message",
            actors: &[],
            proof: None,
        }
    }
    impl MessageAdmissionRepository for Repository {
        async fn begin(
            &self,
            _: &MessageAdmissionRequest<'_>,
            witness: &AdmissionWitness,
        ) -> Result<MessageAdmissionStart> {
            self.events.lock().unwrap().push("begin");
            let lease = match self.admission {
                Admission::Reserved => {
                    let lease = lease(3);
                    let prepared = witness.prepare(
                        TransactionScope::RatedBegin(BeginCommitPurpose::NewReservation),
                        CommitFact::Reserved(acceptance_fence(&lease.acceptance())),
                    )?;
                    witness.received(prepared);
                    Some(lease)
                }
                Admission::GuardOnly => {
                    let prepared = witness.prepare(
                        TransactionScope::GuardOnlyVerification,
                        CommitFact::GuardOnly(GuardDecision::Allowed),
                    )?;
                    witness.received(prepared);
                    None
                }
                Admission::NotRated => panic!("un-rated fixture called admission repository"),
            };
            Ok(MessageAdmissionStart::Proceed {
                lease,
                requirement: WorkRequirement {
                    action: "message".into(),
                    step: 0,
                    work_factor: 1,
                    max_work_factor: 1,
                    hard_wait_seconds: 0,
                    retry_after_seconds: 0,
                    cooldown_seconds: 0,
                    approximate_max_device_seconds: 0,
                    notice: String::new(),
                },
            })
        }
        async fn accept(
            &self,
            acceptance: &MessageAdmissionAcceptance<'_>,
            witness: &AdmissionWitness,
        ) -> Result<FinalizeDecision> {
            self.events.lock().unwrap().push("accept");
            assert_eq!(
                acceptance_fence(acceptance),
                acceptance_fence(&lease(3).acceptance())
            );
            if self.cut == FinalizeCut::PendingBeforeCommit {
                std::future::pending::<()>().await;
            }
            if self.cut == FinalizeCut::PreCommitError {
                anyhow::bail!("controlled pre-COMMIT finalization error");
            }
            // Controlled repository facts through the real retained service.
            // This fixture does not execute the SQL Transaction wrapper.
            let prepared = witness.prepare(
                TransactionScope::AdmissionFinalize,
                CommitFact::Finalized {
                    fence: acceptance_fence(acceptance),
                    result: FinalizeSuccess::PendingAccepted,
                },
            )?;
            self.events.lock().unwrap().push("finalize_commit");
            if self.cut == FinalizeCut::PendingCommit {
                std::future::pending::<()>().await;
            }
            if self.cut == FinalizeCut::CommitError {
                anyhow::bail!("controlled finalization COMMIT loss");
            }
            witness.received(prepared);
            self.events.lock().unwrap().push("finalize_receipt");
            if self.cut == FinalizeCut::AfterReceiptError {
                anyhow::bail!("controlled finalization post-receipt error");
            }
            Ok(FinalizeDecision::AcceptPending)
        }
        async fn reconcile(&self, _: &Effect) -> Result<ReconcileResult> {
            panic!("continuation attempted reconciliation")
        }
    }
}

#[cfg(test)]
mod tests;
