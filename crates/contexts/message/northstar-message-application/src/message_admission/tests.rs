//! Unit tests of the message admission service: retained begin, finalization and witness drivers.

use super::*;
use northstar_abuse_policy::admission_execution::{
    AdmissionCommitObserver, BeginCommitPurpose, CommitFact, FinalizeSuccess,
};
use northstar_abuse_policy::{MessageDedupeIdentity, WorkRequirement};

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
            Mode::Busy => Err(northstar_abuse_policy::message_admission::AbuseStateBusy.into()),
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
                observed_at: northstar_time::DateTime::from_timestamp_micros(123_456).unwrap(),
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
    assert!(northstar_abuse_policy::message_admission::is_abuse_state_busy(&busy));
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
                    northstar_abuse_policy::message_admission::is_abuse_state_busy(actual),
                    northstar_abuse_policy::message_admission::is_abuse_state_busy(ordinary)
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
    async fn stop(&self, witness: &AdmissionWitness, scope: TransactionScope, fact: CommitFact) {
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
        let mut future = Box::pin(service.begin_message_admission_retained(&request, &retained));
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

#[tokio::test]
async fn admission_drivers_reject_results_inconsistent_with_the_observed_witness() {
    use northstar_abuse_policy::admission_execution::CompletionRejected;

    struct InconsistentRepository;
    impl MessageAdmissionRepository for InconsistentRepository {
        async fn begin(
            &self,
            _: &MessageAdmissionRequest<'_>,
            witness: &AdmissionWitness,
        ) -> Result<MessageAdmissionStart> {
            let prepared = witness.prepare(
                TransactionScope::RatedBegin(BeginCommitPurpose::NewReservation),
                CommitFact::Reserved(acceptance_fence(&lease().acceptance())),
            )?;
            witness.received(prepared);
            let foreign = continuation_fixture::lease(99);
            Ok(MessageAdmissionStart::Proceed {
                lease: Some(foreign),
                requirement: requirement(),
            })
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
                    result: FinalizeSuccess::PendingAccepted,
                },
            )?;
            witness.received(prepared);
            Ok(FinalizeDecision::AlreadyAccepted)
        }
        async fn reconcile(&self, effect: &Effect) -> Result<ReconcileResult> {
            let mut result = Repository(Mode::Memory).reconcile(effect).await?;
            result.effect.correlation.attempt += 1;
            Ok(result)
        }
    }

    let service = MessageAdmissionService::new(InconsistentRepository);
    let fence = acceptance_fence(&lease().acceptance());
    let unresolved = Correlation {
        operation: Uuid::from_u128(51),
        effect: 1,
        generation: 0,
        attempt: 1,
    };
    let control = MessageAdmissionService::new(Repository(Mode::ReservedReceipt));
    assert!(matches!(
        control.begin_message_admission(&request()).await.unwrap(),
        MessageAdmissionStart::Proceed { lease: Some(_), .. }
    ));
    control.accept_message_admission(&lease()).await.unwrap();
    control
        .reconcile_message_admission(unresolved, fence.clone())
        .await
        .unwrap();
    let results = [
        (
            "begin rejects a different returned reservation",
            service
                .begin_message_admission(&request())
                .await
                .map(|_| ()),
            CompletionRejected::Knowledge,
        ),
        (
            "finalize rejects a different returned decision",
            service.accept_message_admission(&lease()).await,
            CompletionRejected::Knowledge,
        ),
        (
            "reconcile rejects a different sampled attempt",
            service
                .reconcile_message_admission(unresolved, fence)
                .await
                .map(|_| ()),
            CompletionRejected::Correlation,
        ),
    ];
    for (label, result, expected) in results {
        let Err(error) = result else {
            panic!("{label}: inconsistent repository result escaped the coordinator");
        };
        assert_eq!(
            error.downcast_ref::<CompletionRejected>(),
            Some(&expected),
            "{label}: {error}"
        );
    }
}

#[tokio::test]
async fn retained_begin_checks_every_input_and_claims_one_repository_invocation() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct WaitingRepository(AtomicUsize);
    impl MessageAdmissionRepository for WaitingRepository {
        async fn begin(
            &self,
            request: &MessageAdmissionRequest<'_>,
            witness: &AdmissionWitness,
        ) -> Result<MessageAdmissionStart> {
            assert_eq!(
                begin_command(request).unwrap(),
                witness.snapshot().effect().command
            );
            self.0.fetch_add(1, Ordering::SeqCst);
            std::future::pending().await
        }
        async fn accept(
            &self,
            _: &MessageAdmissionAcceptance<'_>,
            _: &AdmissionWitness,
        ) -> Result<FinalizeDecision> {
            panic!("begin invoked finalization");
        }
        async fn reconcile(&self, _: &Effect) -> Result<ReconcileResult> {
            panic!("begin invoked reconciliation");
        }
    }

    let proof = northstar_abuse_policy::PowProof {
        challenge_id: Uuid::from_u128(52),
        nonce: "nonce".into(),
    };
    let actors = ["actor".to_owned()];
    let original = request();
    let service = MessageAdmissionService::new(WaitingRepository(AtomicUsize::new(0)));
    let owner = witness::DirectOperationHandle::new(Uuid::from_u128(53));
    let retained = owner.begin(&original).unwrap();
    let before = owner.snapshot();
    for (label, changed) in [
        (
            "actor",
            MessageAdmissionRequest {
                actor_id: Uuid::from_u128(54),
                ..original
            },
        ),
        (
            "account",
            MessageAdmissionRequest {
                account_bare: "other@example.test",
                ..original
            },
        ),
        (
            "target",
            MessageAdmissionRequest {
                normalized_target: "other@example.test",
                ..original
            },
        ),
        (
            "origin",
            MessageAdmissionRequest {
                origin_id: None,
                ..original
            },
        ),
        (
            "payload",
            MessageAdmissionRequest {
                normalized_payload: "changed",
                ..original
            },
        ),
        (
            "proof intent",
            MessageAdmissionRequest {
                pow_intent_payload: "changed",
                ..original
            },
        ),
        (
            "subject",
            MessageAdmissionRequest {
                subject: "other",
                ..original
            },
        ),
        (
            "actors",
            MessageAdmissionRequest {
                actors: &actors,
                ..original
            },
        ),
        (
            "proof",
            MessageAdmissionRequest {
                proof: Some(&proof),
                ..original
            },
        ),
    ] {
        let mut future = Box::pin(service.begin_message_admission_retained(&changed, &retained));
        let std::task::Poll::Ready(result) = futures::poll!(&mut future) else {
            panic!("{label}: changed input reached the waiting repository");
        };
        assert!(result.is_err(), "{label}: changed input was accepted");
        assert_eq!(
            owner.snapshot(),
            before,
            "{label}: rejected input mutated owner"
        );
        assert_eq!(service.repository.0.load(Ordering::SeqCst), 0, "{label}");
    }
    let mut first = Box::pin(service.begin_message_admission_retained(&original, &retained));
    assert!(futures::poll!(&mut first).is_pending());
    let waiting = owner.snapshot();
    assert!(waiting.reservation.as_ref().unwrap().effect_started);
    let cloned = retained.clone();
    let mut duplicate = Box::pin(service.begin_message_admission_retained(&original, &cloned));
    let std::task::Poll::Ready(Err(error)) = futures::poll!(&mut duplicate) else {
        panic!("cloned handle invoked the waiting repository twice");
    };
    assert_eq!(
        error.downcast_ref::<crate::direct_lifecycle::Rejected>(),
        Some(&crate::direct_lifecycle::Rejected::AlreadyStarted)
    );
    let changed = MessageAdmissionRequest {
        normalized_target: "other@example.test",
        ..original
    };
    let mut changed_duplicate =
        Box::pin(service.begin_message_admission_retained(&changed, &cloned));
    let std::task::Poll::Ready(Err(error)) = futures::poll!(&mut changed_duplicate) else {
        panic!("changed duplicate bypassed request validation");
    };
    assert_eq!(
        error.downcast_ref::<crate::direct_lifecycle::Rejected>(),
        Some(&crate::direct_lifecycle::Rejected::Request)
    );
    assert_eq!(service.repository.0.load(Ordering::SeqCst), 1);
    assert_eq!(owner.snapshot(), waiting);
    drop(first);
    assert_eq!(owner.snapshot(), waiting);
    assert!(retained.admission_grant().is_none());
}

#[test]
fn admission_grants_follow_completion_and_finished_witnesses_cannot_change() {
    use crate::direct_lifecycle::{AdmissionGrant, DirectLifecycle, Rejected};
    use northstar_abuse_policy::admission_execution::{CompletionRejected, Receipt};

    let fence = acceptance_fence(&lease().acceptance());
    for (label, scope, fact, result, expected_grant) in [
        (
            "reservation receipt",
            TransactionScope::RatedBegin(BeginCommitPurpose::NewReservation),
            CommitFact::Reserved(fence.clone()),
            EffectResult::Begin(BeginResult::Reserved(fence.clone())),
            "reserved",
        ),
        (
            "allowed guard receipt",
            TransactionScope::GuardOnlyVerification,
            CommitFact::GuardOnly(GuardDecision::Allowed),
            EffectResult::Begin(BeginResult::GuardOnly(GuardDecision::Allowed)),
            "guard",
        ),
        (
            "denied guard receipt",
            TransactionScope::GuardOnlyVerification,
            CommitFact::GuardOnly(GuardDecision::Denied),
            EffectResult::Begin(BeginResult::GuardOnly(GuardDecision::Denied)),
            "none",
        ),
        (
            "reservation receipt with failed completion",
            TransactionScope::RatedBegin(BeginCommitPurpose::NewReservation),
            CommitFact::Reserved(fence.clone()),
            EffectResult::Failed(FailureKind::Backend),
            "none",
        ),
    ] {
        let mut owner = DirectLifecycle::new(Uuid::from_u128(55), 7, 2);
        let command = begin_command(&request()).unwrap();
        let Command::Begin(input) = command.clone() else {
            unreachable!()
        };
        let handle = owner.begin(input).unwrap();
        assert!(owner.admission_grant().is_none(), "{label}: issued grant");
        owner.start_effect(&handle, &command).unwrap();
        let prepared = northstar_abuse_policy::admission_execution::PreparedCommit {
            correlation: owner.witness(&handle).unwrap().effect().correlation,
            scope,
            fact,
        };
        owner.enter_commit(&handle, prepared.clone()).unwrap();
        assert!(
            owner.admission_grant().is_none(),
            "{label}: prospective grant"
        );
        let receipt = Receipt {
            correlation: prepared.correlation,
            scope: prepared.scope,
            fact: prepared.fact.clone(),
        };
        owner.record_receipt(&handle, receipt.clone()).unwrap();
        assert!(
            owner.admission_grant().is_none(),
            "{label}: uncompleted grant"
        );
        let before = owner.snapshot();
        assert!(owner
            .complete(&handle, EffectResult::Finalize(FinalizeDecision::Missing))
            .is_err());
        assert_eq!(
            owner.snapshot(),
            before,
            "{label}: rejected completion mutated owner"
        );
        let outcome = owner.complete(&handle, result.clone()).unwrap();
        assert_eq!(
            outcome,
            match result {
                EffectResult::Failed(cause) => ExecutionOutcome::ReceiptPreserved {
                    receipt: receipt.clone(),
                    cause,
                },
                result => ExecutionOutcome::Completed {
                    result,
                    knowledge: Knowledge::ReceiptKnown(receipt.clone()),
                },
            },
            "{label}"
        );
        match (expected_grant, owner.admission_grant()) {
            ("reserved", Some(AdmissionGrant::Reserved(grant))) => {
                assert_eq!(grant.fence(), &fence)
            }
            ("guard", Some(AdmissionGrant::GuardOnly(_))) | ("none", None) => {}
            other => panic!("{label}: wrong grant {other:?}"),
        }
        let finished = owner.snapshot();
        let completed = Rejected::Completion(CompletionRejected::AlreadyCompleted);
        assert_eq!(
            owner.enter_commit(&handle, prepared),
            Err(completed),
            "{label}: late prepare"
        );
        assert_eq!(
            owner.record_receipt(&handle, receipt),
            Err(completed),
            "{label}: late receipt"
        );
        assert_eq!(
            owner.start_effect(&handle, &command),
            Err(completed),
            "{label}: late invocation"
        );
        assert_eq!(
            owner.snapshot(),
            finished,
            "{label}: finished witness changed"
        );
    }
}

#[tokio::test]
async fn retained_finalization_rejects_changed_fences_before_repository_io() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct Acceptor(AtomicUsize);
    impl MessageAdmissionRepository for Acceptor {
        async fn begin(
            &self,
            _: &MessageAdmissionRequest<'_>,
            _: &AdmissionWitness,
        ) -> Result<MessageAdmissionStart> {
            panic!("finalization restarted admission");
        }
        async fn accept(
            &self,
            acceptance: &MessageAdmissionAcceptance<'_>,
            witness: &AdmissionWitness,
        ) -> Result<FinalizeDecision> {
            self.0.fetch_add(1, Ordering::SeqCst);
            assert_eq!(
                acceptance_fence(acceptance),
                acceptance_fence(&lease().acceptance())
            );
            Repository(Mode::Memory).accept(acceptance, witness).await
        }
        async fn reconcile(&self, _: &Effect) -> Result<ReconcileResult> {
            panic!("finalization scheduled reconciliation");
        }
    }

    let owner = witness::DirectOperationHandle::new(Uuid::from_u128(56));
    let original = request();
    let begin = owner.begin(&original).unwrap();
    let MessageAdmissionStart::Proceed {
        lease: Some(issued),
        ..
    } = MessageAdmissionService::new(Repository(Mode::ReservedReceipt))
        .begin_message_admission_retained(&original, &begin)
        .await
        .unwrap()
    else {
        panic!("fixture did not issue reservation");
    };
    let retained = owner.finalize(&issued).unwrap();
    let before = owner.snapshot();
    let service = MessageAdmissionService::new(Acceptor(AtomicUsize::new(0)));
    for (label, key, mac, token) in [
        ("admission key", 9, 2, 3),
        ("payload MAC", 1, 9, 3),
        ("lease token", 1, 2, 99),
    ] {
        let changed = MessageAdmissionLease::new(
            vec![key; 32],
            vec![mac; 32],
            Uuid::from_u128(token),
            MessageDedupeIdentity {
                identity_digest: vec![4; 32],
                candidates: vec![],
            },
        );
        assert!(
            service
                .accept_message_admission_retained(&changed, &retained)
                .await
                .is_err(),
            "{label}"
        );
        assert_eq!(
            owner.snapshot(),
            before,
            "{label}: changed fence consumed effect"
        );
        assert_eq!(
            service.repository.0.load(Ordering::SeqCst),
            0,
            "{label}: changed fence reached repository"
        );
    }
    service
        .accept_message_admission_retained(&issued, &retained)
        .await
        .unwrap();
    let finished = owner.snapshot();
    assert_eq!(finished.reservation, before.reservation);
    let finalization = finished.finalization.as_ref().unwrap();
    assert!(finalization.effect_started);
    assert_eq!(
        finalization.state,
        northstar_abuse_policy::admission_execution::ExecutionState::Finished(
            ExecutionOutcome::Completed {
                result: EffectResult::Finalize(FinalizeDecision::AlreadyAccepted),
                knowledge: Knowledge::ReceiptKnown(
                    northstar_abuse_policy::admission_execution::Receipt {
                        correlation: finalization.witness.effect().correlation,
                        scope: TransactionScope::AdmissionFinalize,
                        fact: CommitFact::Finalized {
                            fence: acceptance_fence(&issued.acceptance()),
                            result: FinalizeSuccess::AlreadyAccepted,
                        },
                    }
                ),
            }
        )
    );
    let Err(error) = service
        .accept_message_admission_retained(&issued, &retained.clone())
        .await
    else {
        panic!("finished finalization invoked the repository twice");
    };
    assert_eq!(
        error.downcast_ref::<crate::direct_lifecycle::Rejected>(),
        Some(&crate::direct_lifecycle::Rejected::Completion(
            northstar_abuse_policy::admission_execution::CompletionRejected::AlreadyCompleted,
        ))
    );
    assert_eq!(owner.snapshot(), finished);
    assert_eq!(service.repository.0.load(Ordering::SeqCst), 1);
}
