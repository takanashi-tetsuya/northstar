use super::*;
use northstar_message_core::{DirectPersonalMessageAdmission, MessageCommit, MessagePostCommit};

// Only retained coordinators and fake route callbacks. No original runner,
// application, saved Case, writer, database or ignored entry is invoked.
async fn owner(mode: DirectPostCommitMode, finish: bool) -> DirectOperationHandle {
    let owner = DirectOperationHandle::new(Uuid::from_u128(101));
    let request = MessageAdmissionRequest {
        actor_id: Uuid::from_u128(1),
        account_bare: "alice@example.test",
        normalized_target: "bob@example.test",
        origin_id: Some("o"),
        normalized_payload: "<message/>",
        pow_intent_payload: "<message/>",
        subject: "message",
        actors: &[],
        proof: None,
    };
    let lease = northstar_abuse_application::guard::MessageAdmissionLease::new(
        vec![1; 32],
        vec![2; 32],
        Uuid::from_u128(6),
        northstar_abuse_policy::MessageDedupeIdentity {
            identity_digest: vec![3; 32],
            candidates: vec![],
        },
    );
    let fence = northstar_abuse_application::guard::acceptance_fence(&lease.acceptance());
    let begin = owner.begin(&request).unwrap();
    begin
        .start(&message_admission::begin_command(&request).unwrap())
        .unwrap();
    witness::saved_case_commit_observed(
        async { Ok(()) },
        &begin.witness(),
        admission::TransactionScope::RatedBegin(admission::BeginCommitPurpose::NewReservation),
        admission::CommitFact::Reserved(fence.clone()),
    )
    .await
    .unwrap();
    begin
        .complete(admission::EffectResult::Begin(
            admission::BeginResult::Reserved(fence.clone()),
        ))
        .unwrap();
    let effect = owner
        .prepare_direct(
            direct_lifecycle::PreparationAdmission::Rated(direct_lifecycle::OriginalAdmission {
                actor_id: request.actor_id,
                account_bare: request.account_bare,
                normalized_target: request.normalized_target,
                origin_id: request.origin_id,
                normalized_payload: request.normalized_payload,
            }),
            direct_commit::DirectCommandFacts {
                actor_id: request.actor_id,
                recipient_id: Uuid::from_u128(2),
                delivery_id: Uuid::from_u128(3),
                archive_ids: vec![],
                eligibility: DirectSpoolEligibility::Eligible,
            },
        )
        .unwrap();
    owner.start_direct(&effect).unwrap();
    let committed = direct_commit::PreparedCommit {
        correlation: effect.correlation(),
        outcome: direct_commit::TransactionOutcome::Stored {
            recipient_id: Uuid::from_u128(2),
            delivery_id: Uuid::from_u128(3),
            archive_ids: vec![],
            live_claim_id: Some(Uuid::from_u128(3)),
        },
        admitted_mode: DirectPostCommitMode::Live,
    };
    owner
        .prepare_direct_commit(&effect, committed.clone())
        .unwrap();
    owner.receive_direct_commit(&effect, committed).unwrap();
    owner
        .complete_direct(
            &effect,
            Some(DirectPersonalMessageAdmission {
                commit: MessageCommit::Stored {
                    archive_written: false,
                    post_commit: MessagePostCommit::RouteLocalDelivery {
                        recipient_id: Uuid::from_u128(2),
                        delivery_id: Uuid::from_u128(3),
                    },
                },
                mode,
                live_claim_id: Some(Uuid::from_u128(3)),
            }),
        )
        .unwrap();
    let finalization = owner.finalize(&lease).unwrap();
    finalization
        .start(&admission::Command::Finalize(fence.clone()))
        .unwrap();
    witness::saved_case_commit_observed(
        async { Ok(()) },
        &finalization.witness(),
        admission::TransactionScope::AdmissionFinalize,
        admission::CommitFact::Finalized {
            fence,
            result: admission::FinalizeSuccess::PendingAccepted,
        },
    )
    .await
    .unwrap();
    if finish {
        finalization
            .complete(admission::EffectResult::Finalize(
                FinalizeDecision::AcceptPending,
            ))
            .unwrap();
    }
    owner
}

fn plan(rearm: wire::Rearm) -> wire::Route {
    wire::Route {
        frame_id: wire::Id(Uuid::from_u128(101)),
        initial_queue: wire::Queue::Empty,
        prefill: wire::Nullable::Null(()),
        targets: vec![],
        health_modes: vec![wire::Mode::Live; 3],
        remote_primary_returns: vec![],
        rearm,
    }
}

fn port<'a>(owner: &DirectOperationHandle, plan: &'a wire::Route) -> RoutePort<'a> {
    RoutePort {
        plan,
        clustered: false,
        log: Arc::new(FrameLog {
            owner: owner.clone(),
            sequence: Arc::new(Mutex::new(wire::Sequence::default())),
            prefixes: Mutex::new(vec![]),
            route: Mutex::new(wire::RouteEvidence::default()),
            routing: AtomicBool::new(false),
            direct_pending: AtomicBool::new(false),
            rearm_pending: AtomicBool::new(false),
        }),
        health: Mutex::new(plan.health_modes.iter().copied().collect()),
        remote: Mutex::new(VecDeque::new()),
    }
}

#[tokio::test]
async fn post_finalize_health_captures_return_and_skips_router_reads() {
    let owner = owner(DirectPostCommitMode::Live, true).await;
    let direct_handoff::Next::CheckHealth(permit) = owner.begin_handoff().unwrap() else {
        panic!("expected health permit");
    };
    let plan = plan(wire::Rearm::Return);
    let port = port(&owner, &plan);
    let mode = port.direct_route_mode();
    owner.observe_handoff_health(permit, mode).unwrap();
    port.log.routing.store(true, Ordering::SeqCst);
    port.direct_route_mode();
    port.direct_route_mode();
    let prefixes = port.log.prefixes.lock().unwrap();
    let route = port.log.route.lock().unwrap();
    assert_eq!(prefixes.len(), 1);
    assert_eq!(route.health_reads.len(), 3);
    assert_eq!(prefixes[0].seq + 1, route.health_reads[0].seq);
    assert!(matches!(
        prefixes[0]
            .state
            .finalize
            .as_ref()
            .unwrap()
            .returned
            .as_ref(),
        Some(wire::AdmissionReturned::AcceptPending)
    ));
    assert_eq!(
        prefixes[0].state.handoff.as_ref().unwrap().route_end,
        "NotStarted"
    );
}

#[tokio::test]
async fn initial_rearm_captures_permit_before_sole_call() {
    for pending in [false, true] {
        let owner = owner(DirectPostCommitMode::SpoolOnly, true).await;
        let direct_handoff::Next::Recover(grant) = owner.begin_handoff().unwrap() else {
            panic!("expected recovery permit");
        };
        let source = grant.source();
        let handoff = owner.consume_recovery(grant).unwrap();
        let permit = handoff.rearm_permit(source).unwrap().unwrap();
        let plan = plan(if pending {
            wire::Rearm::Pending
        } else {
            wire::Rearm::Return
        });
        let port = port(&owner, &plan);
        let mut call = Box::pin(port.rearm_direct_route(source));
        assert_eq!(futures::poll!(&mut call).is_pending(), pending);
        drop(call);
        if !pending {
            permit.returned();
        }
        let prefixes = port.log.prefixes.lock().unwrap();
        let route = port.log.route.lock().unwrap();
        assert!(route.health_reads.is_empty());
        assert_eq!(prefixes.len(), 2);
        assert_eq!(route.rearm_calls.len(), 1);
        assert_eq!(prefixes[0].seq + 1, route.rearm_calls[0].seq);
        assert_eq!(route.rearm_calls[0].seq + 1, prefixes[1].seq);
        assert!(route.rearm_calls[0].source.actual() == TransportOwnershipSource::C2s(source));
        assert_eq!(route.rearm_calls[0].returned, !pending);
        assert!(matches!(
            prefixes[0]
                .state
                .finalize
                .as_ref()
                .unwrap()
                .returned
                .as_ref(),
            Some(wire::AdmissionReturned::AcceptPending)
        ));
        assert_eq!(
            prefixes[0].state.handoff.as_ref().unwrap().rearm,
            "CallEntered"
        );
        assert_eq!(
            prefixes[1].state.handoff.as_ref().unwrap().rearm,
            "CallEntered"
        );
    }
}

#[tokio::test]
async fn unresolved_finalization_snapshot_stays_unreturned() {
    let owner = owner(DirectPostCommitMode::Live, false).await;
    let plan = plan(wire::Rearm::Return);
    let port = port(&owner, &plan);
    port.direct_route_mode();
    let prefixes = port.log.prefixes.lock().unwrap();
    assert_eq!(prefixes.len(), 1);
    assert!(prefixes[0]
        .state
        .finalize
        .as_ref()
        .unwrap()
        .returned
        .is_none());
}

#[tokio::test]
async fn routed_rearm_keeps_existing_post_call_snapshot() {
    let owner = owner(DirectPostCommitMode::Live, true).await;
    let direct_handoff::Next::CheckHealth(health) = owner.begin_handoff().unwrap() else {
        panic!("expected health permit");
    };
    let direct_handoff::Next::Route(grant) = owner
        .observe_handoff_health(health, DirectPostCommitMode::Live)
        .unwrap()
    else {
        panic!("expected route permit");
    };
    let source = grant.source();
    let handoff = owner.consume_route(grant, source).unwrap();
    let permit = handoff.rearm_permit(source).unwrap().unwrap();
    let plan = plan(wire::Rearm::Return);
    let port = port(&owner, &plan);
    port.log.routing.store(true, Ordering::SeqCst);
    port.rearm_direct_route(source).await;
    permit.returned();
    let prefixes = port.log.prefixes.lock().unwrap();
    let route = port.log.route.lock().unwrap();
    assert_eq!(prefixes.len(), 1);
    assert_eq!(route.rearm_calls[0].seq + 1, prefixes[0].seq);
}
