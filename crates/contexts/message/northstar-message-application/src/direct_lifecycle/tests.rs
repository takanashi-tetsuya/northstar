use super::*;
use northstar_abuse_policy::admission_execution::{
    BeginCommitPurpose, FailureKind, FinalizeSuccess, TransactionScope,
};
use northstar_abuse_policy::PowProof;

fn request() -> BeginRequest {
    BeginRequest {
        actor_id: Uuid::from_u128(1),
        account_bare: "private-sender@example.test".into(),
        normalized_target: "private-target@example.test/resource".into(),
        origin_id: Some("private-origin".into()),
        normalized_payload: "private-normalized-payload".into(),
        pow_intent_payload: "private-pow-intent".into(),
        subject: "private-subject".into(),
        actors: vec!["private-actor".into()],
        proof: Some(PowProof {
            challenge_id: Uuid::from_u128(2),
            nonce: "private-nonce".into(),
        }),
    }
}

fn fence() -> AdmissionFence {
    AdmissionFence {
        admission_key: vec![3; 32],
        payload_mac: vec![4; 32],
        lease_token: Uuid::from_u128(5),
    }
}

fn begin(id: u128) -> (DirectLifecycle, AdmissionEffectHandle) {
    let mut lifecycle = DirectLifecycle::new(Uuid::from_u128(id), 7, 1);
    let handle = lifecycle.begin(request()).unwrap();
    lifecycle
        .start_effect(&handle, &Command::Begin(request()))
        .unwrap();
    (lifecycle, handle)
}

fn prospective(handle: &AdmissionEffectHandle) -> PreparedCommit {
    PreparedCommit {
        correlation: handle.effect().correlation,
        scope: TransactionScope::RatedBegin(BeginCommitPurpose::NewReservation),
        fact: CommitFact::Reserved(fence()),
    }
}

fn received(
    lifecycle: &mut DirectLifecycle,
    handle: &AdmissionEffectHandle,
    prepared: PreparedCommit,
) {
    lifecycle.enter_commit(handle, prepared.clone()).unwrap();
    lifecycle
        .record_receipt(
            handle,
            Receipt {
                correlation: prepared.correlation,
                scope: prepared.scope,
                fact: prepared.fact,
            },
        )
        .unwrap();
}

fn reserved(id: u128) -> (DirectLifecycle, ReservationGrant) {
    let (mut lifecycle, handle) = begin(id);
    received(&mut lifecycle, &handle, prospective(&handle));
    lifecycle
        .complete(&handle, EffectResult::Begin(BeginResult::Reserved(fence())))
        .unwrap();
    let Some(AdmissionGrant::Reserved(grant)) = lifecycle.admission_grant() else {
        panic!("reservation grant")
    };
    (lifecycle, grant)
}

#[test]
fn effect_and_positive_witness_are_not_completed_admission_authority() {
    let (mut lifecycle, handle) = begin(10);
    assert_eq!(lifecycle.admission_grant(), None);
    lifecycle
        .enter_commit(&handle, prospective(&handle))
        .unwrap();
    assert_eq!(lifecycle.admission_grant(), None);
    let prepared = prospective(&handle);
    lifecycle
        .record_receipt(
            &handle,
            Receipt {
                correlation: prepared.correlation,
                scope: prepared.scope,
                fact: prepared.fact,
            },
        )
        .unwrap();
    assert_eq!(lifecycle.admission_grant(), None);
    let before = lifecycle.snapshot();
    assert!(lifecycle
        .complete(&handle, EffectResult::Begin(BeginResult::ReplayAccepted))
        .is_err());
    assert_eq!(lifecycle.snapshot(), before);
    lifecycle
        .complete(&handle, EffectResult::Begin(BeginResult::Reserved(fence())))
        .unwrap();
    assert!(matches!(
        lifecycle.admission_grant(),
        Some(AdmissionGrant::Reserved(_))
    ));
    assert!(lifecycle
        .snapshot()
        .reservation
        .unwrap()
        .has_durable_reservation_receipt());
}

#[test]
fn memory_and_guard_receipts_never_become_reservation_grants() {
    let (_, other_grant) = reserved(11);
    for durable_guard in [false, true] {
        let (mut lifecycle, handle) = begin(12);
        if durable_guard {
            received(
                &mut lifecycle,
                &handle,
                PreparedCommit {
                    correlation: handle.effect().correlation,
                    scope: TransactionScope::GuardOnlyVerification,
                    fact: CommitFact::GuardOnly(GuardDecision::Allowed),
                },
            );
        }
        lifecycle
            .complete(
                &handle,
                EffectResult::Begin(BeginResult::GuardOnly(GuardDecision::Allowed)),
            )
            .unwrap();
        assert!(matches!(
            lifecycle.admission_grant(),
            Some(AdmissionGrant::GuardOnly(_))
        ));
        assert!(!lifecycle
            .snapshot()
            .reservation
            .unwrap()
            .has_durable_reservation_receipt());
        assert_eq!(
            lifecycle.finalize(&other_grant),
            Err(Rejected::ReservationRequired)
        );
    }
}

#[test]
fn completed_memory_guard_rejects_later_commit_entry_without_changing_facts() {
    let (mut lifecycle, handle) = begin(22);
    lifecycle
        .complete(
            &handle,
            EffectResult::Begin(BeginResult::GuardOnly(GuardDecision::Allowed)),
        )
        .unwrap();
    let before = lifecycle.snapshot();
    assert_eq!(
        lifecycle.enter_commit(
            &handle,
            PreparedCommit {
                correlation: handle.effect().correlation,
                scope: TransactionScope::GuardOnlyVerification,
                fact: CommitFact::GuardOnly(GuardDecision::Allowed),
            }
        ),
        Err(Rejected::Completion(CompletionRejected::AlreadyCompleted))
    );
    assert_eq!(lifecycle.snapshot(), before);
    assert!(matches!(
        lifecycle.admission_grant(),
        Some(AdmissionGrant::GuardOnly(_))
    ));
    assert!(!before
        .reservation
        .unwrap()
        .has_durable_reservation_receipt());
}

#[test]
fn completed_unknown_rejects_late_receipt_but_waiting_receipt_survives_failure() {
    for finish_before_receipt in [true, false] {
        let (mut lifecycle, handle) = begin(23);
        let prepared = prospective(&handle);
        lifecycle.enter_commit(&handle, prepared.clone()).unwrap();
        let receipt = Receipt {
            correlation: prepared.correlation,
            scope: prepared.scope,
            fact: prepared.fact,
        };
        if finish_before_receipt {
            let outcome = lifecycle
                .complete(&handle, EffectResult::Failed(FailureKind::Backend))
                .unwrap();
            assert!(matches!(outcome, ExecutionOutcome::Unknown { .. }));
            let before = lifecycle.snapshot();
            assert_eq!(
                lifecycle.record_receipt(&handle, receipt),
                Err(Rejected::Completion(CompletionRejected::AlreadyCompleted))
            );
            assert_eq!(lifecycle.snapshot(), before);
        } else {
            lifecycle.record_receipt(&handle, receipt.clone()).unwrap();
            assert_eq!(
                lifecycle
                    .complete(&handle, EffectResult::Failed(FailureKind::Cancelled))
                    .unwrap(),
                ExecutionOutcome::ReceiptPreserved {
                    receipt,
                    cause: FailureKind::Cancelled
                }
            );
            assert!(lifecycle
                .snapshot()
                .reservation
                .unwrap()
                .has_durable_reservation_receipt());
        }
        assert!(lifecycle.admission_grant().is_none());
    }
}

#[test]
fn all_original_authority_fields_are_bound_before_effect_start() {
    for field in 0..10 {
        let mut lifecycle = DirectLifecycle::new(Uuid::from_u128(13), 2, 3);
        let handle = lifecycle.begin(request()).unwrap();
        let before = lifecycle.snapshot();
        let mut changed = request();
        match field {
            0 => changed.actor_id = Uuid::from_u128(999),
            1 => changed.account_bare.push('x'),
            2 => changed.normalized_target.push('x'),
            3 => changed.origin_id = None,
            4 => changed.normalized_payload.push('x'),
            5 => changed.pow_intent_payload.push('x'),
            6 => changed.subject.push('x'),
            7 => changed.actors.push("other".into()),
            8 => changed.proof.as_mut().unwrap().challenge_id = Uuid::from_u128(999),
            9 => changed.proof.as_mut().unwrap().nonce.push('x'),
            _ => unreachable!(),
        }
        assert_eq!(
            lifecycle.start_effect(&handle, &Command::Begin(changed)),
            Err(Rejected::Request)
        );
        assert_eq!(lifecycle.snapshot(), before);
        lifecycle
            .start_effect(&handle, &Command::Begin(request()))
            .unwrap();
        assert_eq!(
            lifecycle.start_effect(&handle, &Command::Begin(request())),
            Err(Rejected::AlreadyStarted)
        );
    }
}

#[test]
fn foreign_effect_generation_attempt_and_changed_source_cannot_mutate_owner() {
    let (mut lifecycle, handle) = begin(14);
    let before = lifecycle.snapshot();
    for field in 0..5 {
        let mut changed = handle.clone();
        match field {
            0 => changed.effect.correlation.operation = Uuid::from_u128(999),
            1 => changed.effect.correlation.effect += 1,
            2 => changed.effect.correlation.generation += 1,
            3 => changed.effect.correlation.attempt += 1,
            4 => changed.effect.command = Command::Finalize(fence()),
            _ => unreachable!(),
        }
        assert_eq!(
            lifecycle.enter_commit(&changed, prospective(&changed)),
            Err(Rejected::Grant)
        );
        assert_eq!(lifecycle.snapshot(), before);
    }
    assert_eq!(lifecycle.begin(request()), Err(Rejected::AlreadyStarted));
}

#[test]
fn exact_completed_reservation_can_finalize_only_once() {
    let (mut lifecycle, grant) = reserved(15);
    let (_, foreign) = reserved(16);
    assert_eq!(lifecycle.finalize(&foreign), Err(Rejected::Fence));
    let handle = lifecycle.finalize(&grant).unwrap();
    assert_ne!(handle.effect().correlation, grant.correlation);
    assert_eq!(lifecycle.finalize(&grant), Err(Rejected::AlreadyStarted));
    let mut changed = fence();
    changed.lease_token = Uuid::from_u128(999);
    assert_eq!(
        lifecycle.start_effect(&handle, &Command::Finalize(changed)),
        Err(Rejected::Request)
    );
    lifecycle
        .start_effect(&handle, &Command::Finalize(fence()))
        .unwrap();
}

#[test]
fn finalization_unknown_retains_separate_positive_reservation_receipt() {
    let (mut lifecycle, grant) = reserved(17);
    let reservation = lifecycle.snapshot().reservation;
    let handle = lifecycle.finalize(&grant).unwrap();
    lifecycle
        .start_effect(&handle, &Command::Finalize(fence()))
        .unwrap();
    lifecycle
        .enter_commit(
            &handle,
            PreparedCommit {
                correlation: handle.effect().correlation,
                scope: TransactionScope::AdmissionFinalize,
                fact: CommitFact::Finalized {
                    fence: fence(),
                    result: FinalizeSuccess::PendingAccepted,
                },
            },
        )
        .unwrap();
    assert!(matches!(
        lifecycle
            .complete(&handle, EffectResult::Failed(FailureKind::Cancelled))
            .unwrap(),
        ExecutionOutcome::Unknown { .. }
    ));
    let terminal = lifecycle.retire(TerminalReason::Cancelled);
    assert_eq!(
        terminal.classification(),
        TerminalClassification::TerminalUnresolved
    );
    assert_eq!(lifecycle.snapshot().reservation, reservation);
    assert_eq!(
        lifecycle.start_effect(&handle, &Command::Finalize(fence())),
        Err(Rejected::Retired)
    );
    assert_eq!(lifecycle.retire(TerminalReason::Completed), terminal);
}

#[test]
fn two_unknown_operations_cannot_be_cleared_by_a_later_success() {
    let (mut first, first_handle) = begin(18);
    first
        .enter_commit(&first_handle, prospective(&first_handle))
        .unwrap();
    first.retire(TerminalReason::Cancelled);
    let old = first.snapshot();
    let (mut second, second_handle) = begin(19);
    second
        .enter_commit(&second_handle, prospective(&second_handle))
        .unwrap();
    second.retire(TerminalReason::TimedOut);
    let second_old = second.snapshot();
    let (mut later, _) = reserved(20);
    later.retire(TerminalReason::Completed);
    assert_eq!(first.snapshot(), old);
    assert_eq!(second.snapshot(), second_old);
    assert_eq!(
        old.classification(),
        TerminalClassification::TerminalUnresolved
    );
    assert_eq!(
        second_old.classification(),
        TerminalClassification::TerminalUnresolved
    );
    assert_eq!(
        first.complete(
            &first_handle,
            EffectResult::Begin(BeginResult::Reserved(fence()))
        ),
        Err(Rejected::Retired)
    );
}

#[test]
fn debug_projection_redacts_all_retained_request_material() {
    let (mut lifecycle, handle) = begin(21);
    lifecycle
        .enter_commit(&handle, prospective(&handle))
        .unwrap();
    let summary = lifecycle.retire(TerminalReason::Cancelled);
    assert_eq!(summary.reservation.unwrap().phase, EffectPhase::Waiting);
    assert_eq!(
        summary.classification(),
        lifecycle.snapshot().classification()
    );
    let rendered = format!("{summary:?} {:?}", lifecycle.snapshot());
    for private in [
        "private-sender",
        "private-target",
        "private-origin",
        "private-normalized",
        "private-pow",
        "private-subject",
        "private-actor",
        "private-nonce",
    ] {
        assert!(
            !rendered.contains(private),
            "retained request leaked through Debug"
        );
    }
}

#[test]
fn direct_receipt_kind_and_unreturned_mode_stay_separate_from_admission_finalization() {
    use northstar_message_core::{DirectPostCommitMode, DirectSpoolEligibility};
    for kind in 0..3 {
        let (mut lifecycle, grant) = reserved(100 + kind);
        let original = request();
        let begin_snapshot = lifecycle.snapshot().reservation;
        let effect = lifecycle
            .prepare_direct(
                PreparationAdmission::Rated(OriginalAdmission {
                    actor_id: original.actor_id,
                    account_bare: &original.account_bare,
                    normalized_target: &original.normalized_target,
                    origin_id: original.origin_id.as_deref(),
                    normalized_payload: &original.normalized_payload,
                }),
                direct_commit::DirectCommandFacts {
                    actor_id: original.actor_id,
                    recipient_id: Uuid::from_u128(30),
                    delivery_id: Uuid::from_u128(31),
                    archive_ids: vec![],
                    eligibility: DirectSpoolEligibility::Eligible,
                },
            )
            .unwrap();
        lifecycle.start_direct(&effect).unwrap();
        assert!(lifecycle.finalize(&grant).is_err());
        let outcome = match kind {
            0 => direct_commit::TransactionOutcome::Stored {
                recipient_id: Uuid::from_u128(30),
                delivery_id: Uuid::from_u128(31),
                archive_ids: vec![],
                live_claim_id: None,
            },
            1 => direct_commit::TransactionOutcome::Replay {
                archive_ids: vec![Uuid::from_u128(99)],
            },
            _ => direct_commit::TransactionOutcome::AccountUnavailable,
        };
        let prepared = direct_commit::PreparedCommit {
            correlation: effect.correlation(),
            outcome,
            admitted_mode: DirectPostCommitMode::Live,
        };
        lifecycle
            .enter_direct_commit(&effect, prepared.clone())
            .unwrap();
        lifecycle.receive_direct_commit(&effect, prepared).unwrap();
        lifecycle.complete_direct(&effect, None).unwrap();
        let finalized = lifecycle.finalize(&grant);
        assert_eq!(finalized.is_ok(), kind != 2);
        assert_eq!(lifecycle.snapshot().reservation, begin_snapshot);
        let summary = lifecycle.retire(TerminalReason::Cancelled).direct.unwrap();
        assert_eq!(
            summary.confirmed_outcome,
            Some(match kind {
                0 => DirectOutcomeClass::Stored,
                1 => DirectOutcomeClass::Replay,
                _ => DirectOutcomeClass::AccountUnavailable,
            })
        );
        assert_eq!(
            summary.receipt_admitted_mode,
            Some(DirectPostCommitMode::Live)
        );
        assert_eq!(summary.returned_mode, None);
    }
}

#[test]
fn direct_promotion_after_finalization_and_begin_after_unrated_promotion_are_inert() {
    use northstar_message_core::DirectSpoolEligibility;
    let facts = direct_commit::DirectCommandFacts {
        actor_id: request().actor_id,
        recipient_id: Uuid::from_u128(30),
        delivery_id: Uuid::from_u128(31),
        archive_ids: vec![],
        eligibility: DirectSpoolEligibility::Eligible,
    };
    let (mut rated, grant) = reserved(201);
    rated.finalize(&grant).unwrap();
    let original = request();
    let before = rated.snapshot();
    assert_eq!(
        rated.prepare_direct(
            PreparationAdmission::Rated(OriginalAdmission {
                actor_id: original.actor_id,
                account_bare: &original.account_bare,
                normalized_target: &original.normalized_target,
                origin_id: original.origin_id.as_deref(),
                normalized_payload: &original.normalized_payload,
            }),
            facts.clone()
        ),
        Err(Rejected::AlreadyStarted)
    );
    assert_eq!(rated.snapshot(), before);
    let mut unrated = DirectLifecycle::new(Uuid::from_u128(202), 0, 1);
    unrated
        .prepare_direct(PreparationAdmission::NoAdmissionRequired, facts)
        .unwrap();
    let before = unrated.snapshot();
    assert_eq!(unrated.begin(request()), Err(Rejected::AlreadyStarted));
    assert_eq!(unrated.snapshot(), before);
    assert!(before.reservation.is_none());
}

fn retained_direct(
    lifecycle: &mut DirectLifecycle,
    rated: bool,
    kind: u8,
    returned_mode: Option<northstar_message_core::DirectPostCommitMode>,
) {
    use northstar_message_core::{
        DirectPostCommitMode, DirectSpoolEligibility, MessageCommit, MessagePostCommit,
    };
    let original = request();
    let admission = if rated {
        PreparationAdmission::Rated(OriginalAdmission {
            actor_id: original.actor_id,
            account_bare: &original.account_bare,
            normalized_target: &original.normalized_target,
            origin_id: original.origin_id.as_deref(),
            normalized_payload: &original.normalized_payload,
        })
    } else {
        PreparationAdmission::NoAdmissionRequired
    };
    let effect = lifecycle
        .prepare_direct(
            admission,
            direct_commit::DirectCommandFacts {
                actor_id: original.actor_id,
                recipient_id: Uuid::from_u128(30),
                delivery_id: Uuid::from_u128(31),
                archive_ids: vec![],
                eligibility: DirectSpoolEligibility::Eligible,
            },
        )
        .unwrap();
    lifecycle.start_direct(&effect).unwrap();
    let fact = match kind {
        0 => direct_commit::TransactionOutcome::Stored {
            recipient_id: Uuid::from_u128(30),
            delivery_id: Uuid::from_u128(31),
            archive_ids: vec![],
            live_claim_id: Some(Uuid::from_u128(31)),
        },
        1 => direct_commit::TransactionOutcome::Replay {
            archive_ids: vec![],
        },
        _ => direct_commit::TransactionOutcome::AccountUnavailable,
    };
    let prepared = direct_commit::PreparedCommit {
        correlation: effect.correlation(),
        outcome: fact,
        admitted_mode: DirectPostCommitMode::Live,
    };
    lifecycle
        .enter_direct_commit(&effect, prepared.clone())
        .unwrap();
    lifecycle.receive_direct_commit(&effect, prepared).unwrap();
    lifecycle
        .complete_direct(
            &effect,
            returned_mode.map(|mode| DirectPersonalMessageAdmission {
                commit: match kind {
                    0 => MessageCommit::Stored {
                        archive_written: false,
                        post_commit: MessagePostCommit::RouteLocalDelivery {
                            recipient_id: Uuid::from_u128(30),
                            delivery_id: Uuid::from_u128(31),
                        },
                    },
                    1 => MessageCommit::Replay,
                    _ => MessageCommit::AccountUnavailable,
                },
                mode,
                live_claim_id: (kind == 0).then_some(Uuid::from_u128(31)),
            }),
        )
        .unwrap();
}

#[test]
fn handoff_requires_actual_finalization_completion_but_unknown_attempt_is_sufficient() {
    use northstar_message_core::DirectPostCommitMode;
    let (mut lifecycle, grant) = reserved(301);
    retained_direct(&mut lifecycle, true, 0, Some(DirectPostCommitMode::Live));
    let direct_before = lifecycle.snapshot().direct;
    let before = lifecycle.snapshot();
    assert!(lifecycle.begin_handoff().is_err());
    assert_eq!(lifecycle.snapshot(), before);
    let finalize = lifecycle.finalize(&grant).unwrap();
    let before = lifecycle.snapshot();
    assert!(lifecycle.begin_handoff().is_err());
    assert_eq!(lifecycle.snapshot(), before);
    lifecycle
        .start_effect(&finalize, &Command::Finalize(fence()))
        .unwrap();
    lifecycle
        .enter_commit(
            &finalize,
            PreparedCommit {
                correlation: finalize.effect().correlation,
                scope: TransactionScope::AdmissionFinalize,
                fact: CommitFact::Finalized {
                    fence: fence(),
                    result: FinalizeSuccess::PendingAccepted,
                },
            },
        )
        .unwrap();
    lifecycle
        .complete(&finalize, EffectResult::Failed(FailureKind::Cancelled))
        .unwrap();
    let direct_handoff::Next::CheckHealth(health) = lifecycle.begin_handoff().unwrap() else {
        panic!("known live mode requires existing health read")
    };
    let direct_handoff::Next::Route(grant) = lifecycle
        .observe_handoff_health(health, DirectPostCommitMode::Live)
        .unwrap()
    else {
        unreachable!()
    };
    let source = grant.source();
    lifecycle.consume_route(grant, source).unwrap();
    assert_eq!(lifecycle.snapshot().direct, direct_before);
    assert!(matches!(
        lifecycle.snapshot().finalization.unwrap().state,
        ExecutionState::Finished(ExecutionOutcome::Unknown { .. })
    ));
}

#[test]
fn handoff_never_promotes_replay_unavailable_or_an_old_retired_owner() {
    use northstar_message_core::DirectPostCommitMode;
    for kind in [1, 2] {
        let mut lifecycle = DirectLifecycle::new(Uuid::from_u128(310 + u128::from(kind)), 0, 1);
        retained_direct(
            &mut lifecycle,
            false,
            kind,
            Some(DirectPostCommitMode::Live),
        );
        let before = lifecycle.snapshot();
        assert!(lifecycle.begin_handoff().is_err());
        assert_eq!(lifecycle.snapshot(), before);
    }
    let mut lifecycle = DirectLifecycle::new(Uuid::from_u128(320), 0, 1);
    retained_direct(&mut lifecycle, false, 0, Some(DirectPostCommitMode::Live));
    let direct_handoff::Next::CheckHealth(health) = lifecycle.begin_handoff().unwrap() else {
        unreachable!()
    };
    let direct_handoff::Next::Route(grant) = lifecycle
        .observe_handoff_health(health, DirectPostCommitMode::Live)
        .unwrap()
    else {
        unreachable!()
    };
    let source = grant.source();
    let before = lifecycle.snapshot();
    assert!(lifecycle.begin_handoff().is_err());
    assert_eq!(lifecycle.snapshot(), before);
    lifecycle.retire(TerminalReason::Cancelled);
    let retired = lifecycle.snapshot();
    assert!(lifecycle.consume_route(grant, source).is_err());
    assert_eq!(lifecycle.snapshot(), retired);
}

#[test]
fn spool_and_preserved_stored_receipts_issue_only_single_use_recovery() {
    use northstar_message_core::DirectPostCommitMode;
    for returned in [None, Some(DirectPostCommitMode::SpoolOnly)] {
        let mut lifecycle = DirectLifecycle::new(Uuid::from_u128(330), 0, 1);
        retained_direct(&mut lifecycle, false, 0, returned);
        let direct_handoff::Next::Recover(grant) = lifecycle.begin_handoff().unwrap() else {
            panic!("no live authority")
        };
        let handle = lifecycle.consume_recovery(grant).unwrap();
        let before = lifecycle.snapshot();
        assert!(lifecycle.begin_handoff().is_err());
        assert!(handle.local_permit(handle.snapshot().source).is_err());
        assert_eq!(lifecycle.snapshot(), before);
        assert!(lifecycle.snapshot().reservation.is_none());
        assert!(lifecycle.snapshot().finalization.is_none());
    }
}
