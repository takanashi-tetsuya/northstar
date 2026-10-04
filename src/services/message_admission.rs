//! Rated admission drives the same coordinator as controlled cases.
//! Reservation, independent finalization and guard-only transactions stay distinct.
pub(crate) mod witness;

use crate::abuse::{
    MessageAdmissionAcceptance, MessageAdmissionLease, MessageAdmissionRequest,
    MessageAdmissionStart,
};
use anyhow::Result;
use northstar_abuse_policy::admission_execution::{
    BeginRequest, BeginResult, Command, Completion, Coordinator, Correlation, Effect, EffectResult,
    ExecutionOutcome, FailureKind, GuardDecision, Knowledge, ReconcileResult, TransactionScope,
};
use northstar_abuse_policy::admission_transaction::{AdmissionFence, FinalizeDecision};
use uuid::Uuid;
use witness::{AdmissionWitness, RetainedAdmission};

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
        effect: &Effect,
    ) -> impl std::future::Future<Output = Result<ReconcileResult>> + Send;
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

    /// Production frame callers create `retained` synchronously outside this
    /// future. Dropping this await cannot discard its witness or exact command.
    pub(crate) async fn begin_message_admission_retained(
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
                use northstar_message_application::direct_lifecycle::AdmissionGrant;
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

    pub(crate) async fn accept_message_admission_retained(
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

    pub(crate) async fn begin_message_admission(
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

    pub(crate) async fn accept_message_admission(
        &self,
        lease: &MessageAdmissionLease,
    ) -> Result<()> {
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
    pub(crate) async fn reconcile_message_admission(
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
pub(crate) async fn finalize_message_admission_with<A, O, F, E>(
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
        tracing::warn!(target: "rust_xmpp_server::xmpp::protocol::messaging",
            ?error, route = route_label,
            "accepted message PoW admission could not be finalized");
    }
}

#[cfg(test)]
pub(crate) mod continuation_fixture {
    use super::*;
    use crate::abuse::{MessageDedupeIdentity, WorkRequirement};
    use northstar_abuse_policy::admission_execution::{
        BeginCommitPurpose, CommitFact, FinalizeSuccess,
    };
    use std::sync::{Arc, Mutex};

    pub(crate) type Events = Arc<Mutex<Vec<&'static str>>>;
    #[derive(Clone, Copy, Eq, PartialEq)]
    pub(crate) enum Admission {
        Reserved,
        GuardOnly,
        NotRated,
    }
    #[derive(Clone, Copy, Default, Eq, PartialEq)]
    pub(crate) enum FinalizeCut {
        #[default]
        Success,
        PreCommitError,
        CommitError,
        AfterReceiptError,
        PendingBeforeCommit,
        PendingCommit,
    }
    pub(crate) struct Repository {
        pub(crate) admission: Admission,
        pub(crate) cut: FinalizeCut,
        pub(crate) events: Events,
    }
    pub(crate) fn lease(token: u128) -> MessageAdmissionLease {
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
    pub(crate) fn request() -> MessageAdmissionRequest<'static> {
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
                    let prepared = witness.prepare(
                        TransactionScope::GuardOnlyVerification,
                        CommitFact::GuardOnly(GuardDecision::Allowed),
                    )?;
                    witness.received(prepared);
                    Ok(MessageAdmissionStart::Proceed {
                        lease: None,
                        requirement: requirement(),
                    })
                }
                Mode::ReservedReceipt | Mode::MissingReceipt => {
                    let lease = lease();
                    if matches!(self.0, Mode::ReservedReceipt) {
                        let prepared = witness.prepare(
                            TransactionScope::RatedBegin(BeginCommitPurpose::NewReservation),
                            CommitFact::Reserved(acceptance_fence(&lease.acceptance())),
                        )?;
                        witness.received(prepared);
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
            let prepared = witness.prepare(
                TransactionScope::AdmissionFinalize,
                CommitFact::Finalized {
                    fence: acceptance_fence(acceptance),
                    result: FinalizeSuccess::AlreadyAccepted,
                },
            )?;
            witness.received(prepared);
            Ok(FinalizeDecision::AlreadyAccepted)
        }
        async fn reconcile(&self, effect: &Effect) -> Result<ReconcileResult> {
            use northstar_abuse_policy::admission_transaction::{
                ReconcileObservation, TimedReconcileObservation,
            };
            Ok(ReconcileResult {
                effect: Box::new(effect.clone()),
                observation: TimedReconcileObservation {
                    observed_at: chrono::DateTime::from_timestamp_micros(123_456).unwrap(),
                    observation: ReconcileObservation::Missing,
                },
            })
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
        let error = unknown.downcast_ref::<AdmissionExecutionError>().unwrap();
        assert!(matches!(
            &error.outcome,
            ExecutionOutcome::Unknown { prepared, .. }
                if prepared.fact == CommitFact::Reserved(acceptance_fence(&lease().acceptance()))
        ));
        assert!(MessageAdmissionService::new(Repository(Mode::Memory))
            .accept_message_admission(&lease())
            .await
            .is_ok());
    }
    #[tokio::test]
    async fn reconciliation_service_returns_the_repository_sample_and_request() {
        let unresolved = Correlation {
            operation: Uuid::from_u128(10),
            effect: 9,
            generation: 8,
            attempt: 7,
        };
        let fence = acceptance_fence(&lease().acceptance());
        let result = MessageAdmissionService::new(Repository(Mode::Memory))
            .reconcile_message_admission(unresolved, fence.clone())
            .await
            .unwrap();
        assert_eq!(result.observation.observed_at.timestamp_micros(), 123_456);
        assert_eq!(
            result.observation.observation,
            northstar_abuse_policy::admission_transaction::ReconcileObservation::Missing
        );
        assert_eq!(
            result.effect.command,
            Command::Reconcile { unresolved, fence }
        );
        assert_eq!(result.effect.correlation.effect, 1);
        assert_eq!(result.effect.correlation.generation, 0);
        assert_eq!(result.effect.correlation.attempt, 1);
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

    #[tokio::test]
    async fn retained_service_preserves_stage2_results_and_exact_finalization_grant() {
        use witness::DirectOperationHandle;
        for mode in [
            Mode::Memory,
            Mode::GuardReceipt,
            Mode::ReservedReceipt,
            Mode::MissingReceipt,
            Mode::Busy,
            Mode::Conflict,
            Mode::CommitUnknown,
        ] {
            let service = MessageAdmissionService::new(Repository(mode));
            let request = request();
            let owner = DirectOperationHandle::new(Uuid::new_v4());
            let retained = owner.begin(&request).unwrap();
            let actual = service
                .begin_message_admission_retained(&request, &retained)
                .await;
            let ordinary = service.begin_message_admission(&request).await;
            match (&actual, &ordinary) {
                (
                    Ok(MessageAdmissionStart::Proceed { lease: actual, .. }),
                    Ok(MessageAdmissionStart::Proceed {
                        lease: ordinary, ..
                    }),
                ) => {
                    assert_eq!(actual.is_some(), ordinary.is_some());
                    assert_eq!(
                        owner
                            .snapshot()
                            .reservation
                            .unwrap()
                            .has_durable_reservation_receipt(),
                        actual.is_some()
                    );
                }
                (Ok(MessageAdmissionStart::Conflict), Ok(MessageAdmissionStart::Conflict)) => {}
                (Err(actual), Err(ordinary)) => {
                    assert_eq!(
                        crate::abuse::is_abuse_state_busy(actual),
                        crate::abuse::is_abuse_state_busy(ordinary)
                    );
                    if let (Some(actual), Some(ordinary)) = (
                        actual.downcast_ref::<AdmissionExecutionError>(),
                        ordinary.downcast_ref::<AdmissionExecutionError>(),
                    ) {
                        // Correlation now uses the originating frame ID; the
                        // Stage2 outcome class and authority facts stay intact.
                        assert_eq!(
                            std::mem::discriminant(&actual.outcome),
                            std::mem::discriminant(&ordinary.outcome)
                        );
                    } else {
                        assert_eq!(actual.to_string(), ordinary.to_string());
                    }
                }
                other => panic!("retained/convenience disagreement: {other:?}"),
            }
            if let Ok(MessageAdmissionStart::Proceed {
                lease: Some(lease), ..
            }) = actual
            {
                let reservation = owner.snapshot().reservation;
                let finalization = owner.finalize(&lease).unwrap();
                service
                    .accept_message_admission_retained(&lease, &finalization)
                    .await
                    .unwrap();
                assert_eq!(owner.snapshot().reservation, reservation);
                assert!(matches!(
                    owner.snapshot().finalization.unwrap().witness.knowledge(),
                    Knowledge::ReceiptKnown(_)
                ));
                assert!(owner.finalize(&lease).is_err());
            }
        }
    }

    #[tokio::test]
    async fn retained_service_rejects_changed_input_and_duplicate_effect_before_repository_io() {
        struct MustNotRun;
        impl MessageAdmissionRepository for MustNotRun {
            async fn begin(
                &self,
                _: &MessageAdmissionRequest<'_>,
                _: &AdmissionWitness,
            ) -> Result<MessageAdmissionStart> {
                panic!("mismatched request reached repository")
            }
            async fn accept(
                &self,
                _: &MessageAdmissionAcceptance<'_>,
                _: &AdmissionWitness,
            ) -> Result<FinalizeDecision> {
                panic!("unexpected accept")
            }
            async fn reconcile(&self, _: &Effect) -> Result<ReconcileResult> {
                panic!("unexpected read")
            }
        }
        let owner = witness::DirectOperationHandle::new(Uuid::new_v4());
        let original = request();
        let retained = owner.begin(&original).unwrap();
        let before = owner.snapshot();
        let changed = MessageAdmissionRequest {
            normalized_target: "other@example.test",
            ..original
        };
        assert!(MessageAdmissionService::new(MustNotRun)
            .begin_message_admission_retained(&changed, &retained)
            .await
            .is_err());
        assert_eq!(owner.snapshot(), before);
        MessageAdmissionService::new(Repository(Mode::Memory))
            .begin_message_admission_retained(&request(), &retained)
            .await
            .unwrap();
        assert!(MessageAdmissionService::new(MustNotRun)
            .begin_message_admission_retained(&request(), &retained)
            .await
            .is_err());
    }

    #[derive(Clone, Copy)]
    enum CancelCut {
        BeforeCommit,
        DuringCommit,
        AfterReceipt,
    }

    struct CancellableRepository(CancelCut);

    impl CancellableRepository {
        async fn stop(
            &self,
            witness: &AdmissionWitness,
            scope: TransactionScope,
            fact: CommitFact,
        ) {
            if !matches!(self.0, CancelCut::BeforeCommit) {
                let prepared = witness.prepare(scope, fact).unwrap();
                if matches!(self.0, CancelCut::AfterReceipt) {
                    witness.received(prepared);
                }
            }
            std::future::pending::<()>().await;
        }
    }

    impl MessageAdmissionRepository for CancellableRepository {
        async fn begin(
            &self,
            _: &MessageAdmissionRequest<'_>,
            witness: &AdmissionWitness,
        ) -> Result<MessageAdmissionStart> {
            self.stop(
                witness,
                TransactionScope::RatedBegin(BeginCommitPurpose::NewReservation),
                CommitFact::Reserved(acceptance_fence(&lease().acceptance())),
            )
            .await;
            unreachable!()
        }
        async fn accept(
            &self,
            acceptance: &MessageAdmissionAcceptance<'_>,
            witness: &AdmissionWitness,
        ) -> Result<FinalizeDecision> {
            self.stop(
                witness,
                TransactionScope::AdmissionFinalize,
                CommitFact::Finalized {
                    fence: acceptance_fence(acceptance),
                    result: FinalizeSuccess::PendingAccepted,
                },
            )
            .await;
            unreachable!()
        }
        async fn reconcile(&self, _: &Effect) -> Result<ReconcileResult> {
            panic!("cancellation does not schedule reconciliation")
        }
    }

    fn assert_cancel_cut(knowledge: &Knowledge, cut: CancelCut) {
        assert!(matches!(
            (knowledge, cut),
            (Knowledge::NoCommitRequested, CancelCut::BeforeCommit)
                | (Knowledge::CommitCallEntered(_), CancelCut::DuringCommit)
                | (Knowledge::ReceiptKnown(_), CancelCut::AfterReceipt)
        ));
    }

    #[tokio::test]
    async fn retained_begin_survives_unpolled_and_each_commit_cut_without_inventing_grant() {
        for cut in [
            CancelCut::BeforeCommit,
            CancelCut::DuringCommit,
            CancelCut::AfterReceipt,
        ] {
            let owner = witness::DirectOperationHandle::new(Uuid::new_v4());
            let request = request();
            let retained = owner.begin(&request).unwrap();
            let service = MessageAdmissionService::new(CancellableRepository(cut));
            drop(service.begin_message_admission_retained(&request, &retained));
            assert!(!owner.snapshot().reservation.unwrap().effect_started);
            let mut future =
                Box::pin(service.begin_message_admission_retained(&request, &retained));
            assert!(futures::poll!(&mut future).is_pending());
            drop(future);
            let snapshot = owner.snapshot().reservation.unwrap();
            assert_cancel_cut(snapshot.witness.knowledge(), cut);
            assert!(matches!(
                snapshot.state,
                northstar_abuse_policy::admission_execution::ExecutionState::Waiting(_)
            ));
            assert!(retained.admission_grant().is_none());
        }
    }

    #[tokio::test]
    async fn retained_finalize_cancellation_keeps_begin_receipt_and_exact_fence() {
        for cut in [
            CancelCut::BeforeCommit,
            CancelCut::DuringCommit,
            CancelCut::AfterReceipt,
        ] {
            let owner = witness::DirectOperationHandle::new(Uuid::new_v4());
            let request = request();
            let begin = owner.begin(&request).unwrap();
            let MessageAdmissionStart::Proceed {
                lease: Some(lease), ..
            } = MessageAdmissionService::new(Repository(Mode::ReservedReceipt))
                .begin_message_admission_retained(&request, &begin)
                .await
                .unwrap()
            else {
                panic!("reserved lease")
            };
            let reservation = owner.snapshot().reservation;
            let retained = owner.finalize(&lease).unwrap();
            let service = MessageAdmissionService::new(CancellableRepository(cut));
            let mut future = Box::pin(service.accept_message_admission_retained(&lease, &retained));
            assert!(futures::poll!(&mut future).is_pending());
            drop(future);
            drop(lease);
            let snapshot = owner.snapshot();
            assert_eq!(snapshot.reservation, reservation);
            let finalization = snapshot.finalization.unwrap();
            assert_cancel_cut(finalization.witness.knowledge(), cut);
            assert_eq!(
                finalization.witness.effect().command,
                Command::Finalize(acceptance_fence(&self::lease().acceptance()))
            );
        }
    }
}
