//! Rated admission drives the same coordinator as controlled cases.
//! Reservation, independent finalization and guard-only transactions stay distinct.
pub(crate) mod witness;

use crate::abuse::{
    MessageAdmissionAcceptance, MessageAdmissionLease, MessageAdmissionRequest,
    MessageAdmissionStart,
};
use anyhow::Result;
use northstar_abuse_policy::admission_execution::{
    BeginRequest, BeginResult, Command, Completion, Coordinator, Correlation, EffectResult,
    ExecutionOutcome, FailureKind, GuardDecision, Knowledge, TransactionScope,
};
use northstar_abuse_policy::admission_transaction::{
    AdmissionFence, FinalizeDecision, ReconcileObservation,
};
use uuid::Uuid;
use witness::AdmissionWitness;

pub(crate) trait MessageAdmissionRepository: Send + Sync {
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
        fence: &AdmissionFence,
    ) -> impl std::future::Future<Output = Result<ReconcileObservation>> + Send;
}

pub(crate) fn begin_command(request: &MessageAdmissionRequest<'_>) -> Result<Command> {
    crate::abuse::validate_message_admission_request(request)?;
    Ok(Command::Begin(BeginRequest::from(
        northstar_abuse_policy::MessageAdmissionRequest {
            actor_id: request.actor_id,
            account_bare: request.account_bare,
            normalized_target: request.normalized_target,
            origin_id: request.origin_id,
            normalized_payload: request.normalized_payload,
            pow_intent_payload: request.pow_intent_payload,
            subject: request.subject,
            actors: request.actors,
            proof: request.proof,
        },
    )))
}
pub(crate) fn acceptance_fence(acceptance: &MessageAdmissionAcceptance<'_>) -> AdmissionFence {
    AdmissionFence {
        admission_key: acceptance.admission_key().to_vec(),
        payload_mac: acceptance.payload_mac().to_vec(),
        lease_token: acceptance.lease_token(),
    }
}
pub(crate) fn operation(command: Command) -> (Coordinator, AdmissionWitness) {
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
pub(crate) struct MessageAdmissionService<R> {
    repository: R,
}

/// Redacted classification: no SQL/row/payload text in emitted errors.
#[derive(Debug, thiserror::Error)]
#[error("admission execution failed: {outcome:?}")]
struct AdmissionExecutionError {
    outcome: ExecutionOutcome,
}

fn failure(error: &anyhow::Error) -> FailureKind {
    if crate::abuse::is_abuse_state_busy(error) {
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
        return crate::abuse::AbuseStateBusy.into();
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
    pub(crate) fn new(repository: R) -> Self {
        Self { repository }
    }

    pub(crate) async fn begin_message_admission(
        &self,
        request: &MessageAdmissionRequest<'_>,
    ) -> Result<MessageAdmissionStart> {
        let (mut coordinator, witness) = operation(begin_command(request)?);
        let effect = coordinator.pending().expect("new begin").clone();
        let result = self.repository.begin(request, &witness).await;
        let knowledge = witness.knowledge();
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

    pub(crate) async fn accept_message_admission(
        &self,
        lease: &MessageAdmissionLease,
    ) -> Result<()> {
        let acceptance = lease.acceptance();
        let (mut coordinator, witness) =
            operation(Command::Finalize(acceptance_fence(&acceptance)));
        let effect = coordinator.pending().expect("new finalize").clone();
        let result = self.repository.accept(&acceptance, &witness).await;
        let completion_result = match &result {
            Ok(decision) => EffectResult::Finalize(*decision),
            Err(error) => EffectResult::Failed(failure(error)),
        };
        let outcome = coordinator
            .complete(Completion {
                effect,
                result: completion_result,
                knowledge: witness.knowledge(),
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
    pub(crate) async fn reconcile_message_admission(
        &self,
        unresolved: Correlation,
        fence: AdmissionFence,
    ) -> Result<ReconcileObservation> {
        let (mut coordinator, _) = operation(Command::Reconcile {
            unresolved,
            fence: fence.clone(),
        });
        let effect = coordinator.pending().expect("new reconcile").clone();
        let result = self.repository.reconcile(&fence).await;
        let completion_result = match &result {
            Ok(observation) => EffectResult::Reconcile(*observation),
            Err(error) => EffectResult::Failed(failure(error)),
        };
        let outcome = coordinator
            .complete(Completion {
                effect,
                result: completion_result,
                knowledge: Knowledge::NoCommitRequested,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::abuse::{MessageDedupeIdentity, WorkRequirement};
    use northstar_abuse_policy::admission_execution::{
        BeginCommitPurpose, CommitFact, FinalizeSuccess,
    };

    #[derive(Clone, Copy)]
    enum Mode {
        Memory,
        GuardReceipt,
        ReservedReceipt,
        MissingReceipt,
        CommitUnknown,
        Busy,
        Conflict,
    }
    struct Repository(Mode);
    fn requirement() -> WorkRequirement {
        WorkRequirement {
            action: "message".into(),
            step: 0,
            work_factor: 1,
            max_work_factor: 1,
            hard_wait_seconds: 0,
            retry_after_seconds: 0,
            cooldown_seconds: 0,
            approximate_max_device_seconds: 0,
            notice: String::new(),
        }
    }
    fn lease() -> MessageAdmissionLease {
        MessageAdmissionLease::new(
            vec![1; 32],
            vec![2; 32],
            Uuid::from_u128(3),
            MessageDedupeIdentity {
                identity_digest: vec![4; 32],
                candidates: vec![],
            },
        )
    }
    impl MessageAdmissionRepository for Repository {
        async fn begin(
            &self,
            _: &MessageAdmissionRequest<'_>,
            witness: &AdmissionWitness,
        ) -> Result<MessageAdmissionStart> {
            match self.0 {
                Mode::Memory => Ok(MessageAdmissionStart::Proceed {
                    lease: None,
                    requirement: requirement(),
                }),
                Mode::GuardReceipt => {
                    let receipt = witness.prepare(
                        TransactionScope::GuardOnlyVerification,
                        CommitFact::GuardOnly(GuardDecision::Allowed),
                    )?;
                    witness.received(receipt);
                    Ok(MessageAdmissionStart::Proceed {
                        lease: None,
                        requirement: requirement(),
                    })
                }
                Mode::ReservedReceipt | Mode::MissingReceipt => {
                    let lease = lease();
                    if matches!(self.0, Mode::ReservedReceipt) {
                        let receipt = witness.prepare(
                            TransactionScope::RatedBegin(BeginCommitPurpose::NewReservation),
                            CommitFact::Reserved(acceptance_fence(&lease.acceptance())),
                        )?;
                        witness.received(receipt);
                    }
                    Ok(MessageAdmissionStart::Proceed {
                        lease: Some(lease),
                        requirement: requirement(),
                    })
                }
                Mode::CommitUnknown => {
                    let _ = witness.prepare(
                        TransactionScope::RatedBegin(BeginCommitPurpose::NewReservation),
                        CommitFact::Reserved(acceptance_fence(&lease().acceptance())),
                    )?;
                    anyhow::bail!("backend error with forbidden-private-row-text")
                }
                Mode::Busy => Err(crate::abuse::AbuseStateBusy.into()),
                Mode::Conflict => Ok(MessageAdmissionStart::Conflict),
            }
        }
        async fn accept(
            &self,
            acceptance: &MessageAdmissionAcceptance<'_>,
            witness: &AdmissionWitness,
        ) -> Result<FinalizeDecision> {
            let receipt = witness.prepare(
                TransactionScope::AdmissionFinalize,
                CommitFact::Finalized {
                    fence: acceptance_fence(acceptance),
                    result: FinalizeSuccess::AlreadyAccepted,
                },
            )?;
            witness.received(receipt);
            Ok(FinalizeDecision::AlreadyAccepted)
        }
        async fn reconcile(&self, _: &AdmissionFence) -> Result<ReconcileObservation> {
            Ok(ReconcileObservation::Missing)
        }
    }
    fn request() -> MessageAdmissionRequest<'static> {
        MessageAdmissionRequest {
            actor_id: Uuid::from_u128(5),
            account_bare: "alice@example.test",
            normalized_target: "bob@example.test/device",
            origin_id: Some("origin"),
            normalized_payload: "<message/>",
            pow_intent_payload: "<message/>",
            subject: "message",
            actors: &[],
            proof: None,
        }
    }
    #[tokio::test]
    async fn admission_service_consumes_shared_outcome_and_requires_reservation_receipt() {
        for mode in [Mode::Memory, Mode::GuardReceipt, Mode::ReservedReceipt] {
            assert!(matches!(
                MessageAdmissionService::new(Repository(mode))
                    .begin_message_admission(&request())
                    .await
                    .unwrap(),
                MessageAdmissionStart::Proceed { .. }
            ));
        }
        assert!(
            MessageAdmissionService::new(Repository(Mode::MissingReceipt))
                .begin_message_admission(&request())
                .await
                .is_err()
        );
        assert!(matches!(
            MessageAdmissionService::new(Repository(Mode::Conflict))
                .begin_message_admission(&request())
                .await
                .unwrap(),
            MessageAdmissionStart::Conflict
        ));
    }
    #[tokio::test]
    async fn admission_service_preserves_busy_and_redacts_unknown_backend_error() {
        let busy = MessageAdmissionService::new(Repository(Mode::Busy))
            .begin_message_admission(&request())
            .await
            .unwrap_err();
        assert!(crate::abuse::is_abuse_state_busy(&busy));
        let unknown = MessageAdmissionService::new(Repository(Mode::CommitUnknown))
            .begin_message_admission(&request())
            .await
            .unwrap_err();
        assert!(unknown.to_string().contains("Unknown"));
        assert!(!format!("{unknown:?}").contains("forbidden-private"));
        assert!(MessageAdmissionService::new(Repository(Mode::Memory))
            .accept_message_admission(&lease())
            .await
            .is_ok());
    }
    #[test]
    fn admission_request_limits_are_checked_before_ownership_conversion() {
        let payload = "x".repeat(1_048_577);
        let request = MessageAdmissionRequest {
            normalized_payload: &payload,
            ..request()
        };
        assert!(begin_command(&request).is_err());
    }
}
