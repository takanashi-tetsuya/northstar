use super::*;
use crate::{
    bosh_ownership::{OperationKind, Terminal},
    DurableDelivery,
};
use std::{
    pin::Pin,
    sync::atomic::{AtomicBool, Ordering},
    task::{Context, Poll, Waker},
};

fn operation() -> Operation {
    Operation::new(Scope {
        session_id: Uuid::from_u128(71),
        ttl_seconds: 600,
        kind: OperationKind::Request,
    })
}
fn c2s(id: u128) -> Source {
    Source::C2s(DurableDelivery {
        recipient_id: Uuid::from_u128(72),
        message_id: Uuid::from_u128(id),
        claim_id: Some(Uuid::from_u128(73)),
    })
}
fn mix() -> Source {
    Source::Mix(MixDelivery {
        delivery_id: Uuid::from_u128(81),
        lease_token: Uuid::from_u128(82),
    })
}
fn ownership() -> BoshResponseOwnership {
    BoshResponseOwnership {
        c2s_message_ids: vec![Uuid::from_u128(74)],
        mix_delivery_ids: vec![Uuid::from_u128(81)],
    }
}
fn bind(operation: &Operation) -> BindRequest {
    operation
        .begin_response(
            10,
            ResponseKind::Payload,
            vec![Some(c2s(74)), None, Some(mix())],
        )
        .unwrap()
        .attempt(
            vec![c2s(74), mix()],
            [Some(c2s(74)), None, Some(mix())].into_iter(),
        )
        .unwrap()
}
fn poll_once<F: Future>(future: Pin<&mut F>) -> Poll<F::Output> {
    future.poll(&mut Context::from_waker(Waker::noop()))
}
fn ack(operation: &Operation) -> AckRequest {
    let renew = operation.begin_renew(None).unwrap();
    renew.enter_commit().unwrap().received();
    renew.returned().unwrap().begin_ack(10).unwrap()
}
fn deleted() -> Vec<DeletedSource> {
    vec![
        DeletedSource::C2s {
            recipient_id: Uuid::from_u128(72),
            message_id: Uuid::from_u128(74),
        },
        DeletedSource::Mix(mix().mix().unwrap()),
    ]
}

#[test]
fn whole_ordered_cut_and_private_request_binding_reject_changes_inertly() {
    let operation = operation();
    let build = operation
        .begin_response(
            10,
            ResponseKind::Payload,
            vec![Some(c2s(74)), None, Some(mix())],
        )
        .unwrap();
    let before = operation.snapshot();
    let changed_claim = Source::C2s(DurableDelivery {
        claim_id: Some(Uuid::from_u128(99)),
        ..c2s(74).c2s().unwrap()
    });
    let changed_mix = Source::Mix(MixDelivery {
        lease_token: Uuid::from_u128(99),
        ..mix().mix().unwrap()
    });
    for slots in [
        vec![None, Some(c2s(74)), Some(mix())],
        vec![Some(c2s(74)), Some(mix())],
        vec![Some(c2s(75)), None, Some(mix())],
        vec![Some(changed_claim), None, Some(mix())],
        vec![Some(c2s(74)), None, Some(changed_mix)],
    ] {
        let sources = slots.iter().copied().flatten().collect();
        assert!(matches!(
            build.attempt(sources, slots.into_iter()),
            Err(Rejected::Source)
        ));
        assert_eq!(operation.snapshot(), before);
    }
    let request = build
        .attempt(
            vec![c2s(74), mix()],
            [Some(c2s(74)), None, Some(mix())].into_iter(),
        )
        .unwrap();
    request.validate_for_io().unwrap();
    let before = operation.snapshot();
    for change in 0..4 {
        let mut changed = BindRequest {
            operation: operation.clone(),
            response: request.response,
            attempt: request.attempt,
            scope: request.scope,
            rid: request.rid,
            sources: request.sources.clone(),
        };
        match change {
            0 => changed.scope.session_id = Uuid::nil(),
            1 => changed.scope.ttl_seconds += 1,
            2 => changed.rid += 1,
            _ => changed.sources = Arc::new(request.sources.as_ref().clone()),
        }
        assert_eq!(changed.validate_for_io(), Err(Rejected::Source));
        assert_eq!(operation.snapshot(), before);
    }
}

#[test]
fn bind_commit_membership_is_exact_and_source_less_response_needs_no_commit() {
    let operation = operation();
    let request = bind(&operation);
    let before = operation.snapshot();
    for changed in [
        BoshResponseOwnership::default(),
        BoshResponseOwnership {
            c2s_message_ids: vec![Uuid::from_u128(75)],
            ..ownership()
        },
        BoshResponseOwnership {
            mix_delivery_ids: vec![Uuid::from_u128(81), Uuid::from_u128(81)],
            ..ownership()
        },
    ] {
        assert!(matches!(
            request.enter_commit(changed),
            Err(Rejected::Receipt)
        ));
        assert_eq!(operation.snapshot(), before);
    }
    let plain = operation
        .begin_response(11, ResponseKind::Payload, vec![None])
        .unwrap()
        .attempt(vec![], [None].into_iter())
        .unwrap();
    assert_eq!(plain.validate_for_io(), Err(Rejected::State));
    let exposed = plain
        .returned(BoshResponseOwnership::default())
        .unwrap()
        .begin_exposure()
        .unwrap();
    exposed.sending();
    exposed.sent(false);
    exposed.begin_bookkeeping().unwrap().updated();
    let snapshot = operation.snapshot();
    assert_eq!(
        snapshot.responses[1].attempts[0].knowledge,
        BindKnowledge::NotRequired
    );
    assert_eq!(snapshot.responses[1].refused_responders, 1);
    assert!(snapshot.responses[1].bookkeeping);
}

#[test]
fn bind_commit_poll_loss_and_receipt_have_independent_knowledge() {
    for cut in 0..3 {
        let operation = operation();
        let request = bind(&operation);
        let mut future = Box::pin(bind_commit_observed(
            async {
                if cut == 0 {
                    std::future::pending::<()>().await;
                }
                if cut == 1 {
                    Err(std::io::Error::other("lost COMMIT reply"))
                } else {
                    Ok(())
                }
            },
            &request,
            ownership(),
        ));
        let result = poll_once(future.as_mut());
        assert_eq!(result.is_pending(), cut == 0);
        drop(future);
        let summary = operation.retire(Terminal::Cancelled);
        assert_eq!(summary.responses.bind_unknown, usize::from(cut != 2));
        assert_eq!(summary.responses.bind_receipts, usize::from(cut == 2));
        assert_eq!(summary.responses.accepted_responders, 0);
        assert_eq!(request.validate_for_io(), Err(Rejected::Retired));
    }
}

#[test]
fn returned_membership_and_late_receipt_never_substitute_for_each_other() {
    for committed in [false, true] {
        let operation = operation();
        let request = bind(&operation);
        if committed {
            request.enter_commit(ownership()).unwrap().received();
        }
        let wrong = BoshResponseOwnership {
            c2s_message_ids: vec![Uuid::from_u128(75)],
            ..ownership()
        };
        assert!(matches!(
            request.returned(wrong.clone()),
            Err(Rejected::Receipt)
        ));
        let snapshot = operation.snapshot();
        assert_eq!(
            snapshot.responses[0].attempts[0].returned.as_deref(),
            Some(&wrong)
        );
        assert!(!snapshot.responses[0].attempts[0].return_matches);
        assert_eq!(
            snapshot.summary().responses.bind_receipts,
            usize::from(committed)
        );
    }
    let first = operation();
    let other = operation();
    let request = bind(&first);
    let other_request = bind(&other);
    other_request.enter_commit(ownership()).unwrap().received();
    let permit = request.enter_commit(ownership()).unwrap();
    assert!(matches!(
        request.returned(ownership()),
        Err(Rejected::Receipt)
    ));
    first.retire(Terminal::Cancelled);
    permit.received();
    let snapshot = first.snapshot();
    assert!(matches!(
        snapshot.responses[0].attempts[0].knowledge,
        BindKnowledge::ReceiptKnown(_)
    ));
    assert!(!snapshot.responses[0].attempts[0].return_matches);
    assert!(!snapshot.responses[0].exposure_entered);
}

#[test]
fn restoration_matches_all_message_ids_in_reverse_order_and_releases_sources() {
    let operation = operation();
    let changed_claim = Source::C2s(DurableDelivery {
        recipient_id: Uuid::from_u128(99),
        claim_id: Some(Uuid::from_u128(98)),
        ..c2s(74).c2s().unwrap()
    });
    let slots = vec![Some(c2s(74)), None, Some(changed_claim), Some(mix())];
    let build = operation
        .begin_response(10, ResponseKind::Payload, slots.clone())
        .unwrap();
    let request = build
        .attempt(slots.iter().copied().flatten().collect(), slots.into_iter())
        .unwrap();
    let weak = Arc::downgrade(&request.sources);
    let restoration = request.supersession(Uuid::from_u128(74)).unwrap();
    assert_eq!(restoration.selected_indices(), [0, 1, 2, 3]);
    restoration.restored(vec![2, 0]).unwrap();
    assert!(weak.upgrade().is_none());
    let snapshot = operation.snapshot();
    assert_eq!(snapshot.responses[0].removed, [true, false, true, false]);
    assert!(snapshot.responses[0].attempts[0].sources.is_none());
    let survivor = build
        .attempt(vec![mix()], [None, Some(mix())].into_iter())
        .unwrap();
    survivor
        .enter_commit(BoshResponseOwnership {
            c2s_message_ids: vec![],
            mix_delivery_ids: vec![Uuid::from_u128(81)],
        })
        .unwrap()
        .received();
    assert_eq!(operation.summary().responses.restored_indices, 2);
}

#[test]
fn restoration_is_precommit_only_and_mismatched_removal_does_not_allow_rebuild() {
    for receipt in [false, true] {
        let operation = operation();
        let request = bind(&operation);
        let permit = request.enter_commit(ownership()).unwrap();
        if receipt {
            permit.received();
        } else {
            drop(permit);
        }
        let before = operation.snapshot();
        assert!(matches!(
            request.supersession(Uuid::from_u128(74)),
            Err(Rejected::State)
        ));
        assert_eq!(operation.snapshot(), before);
    }
    let operation = operation();
    let build = operation
        .begin_response(10, ResponseKind::Payload, vec![Some(c2s(74)), None])
        .unwrap();
    let request = build
        .attempt(vec![c2s(74)], [Some(c2s(74)), None].into_iter())
        .unwrap();
    assert!(matches!(
        request
            .supersession(Uuid::from_u128(74))
            .unwrap()
            .restored(vec![1]),
        Err(Rejected::Source)
    ));
    let snapshot = operation.snapshot();
    assert_eq!(snapshot.responses[0].attempts[0].removed_indices, [1]);
    assert!(!snapshot.responses[0].attempts[0].restore_matches);
    assert_eq!(snapshot.responses[0].removed, [false, false]);
    assert!(matches!(
        build.attempt(vec![], [None].into_iter()),
        Err(Rejected::State)
    ));
}

#[test]
fn renewal_preserves_expected_value_and_separates_replay_from_fresh_ack() {
    let operation = operation();
    let duplicate = Arc::new(BoshResponseOwnership {
        c2s_message_ids: vec![Uuid::from_u128(74); 2],
        mix_delivery_ids: vec![],
    });
    let cached = operation
        .begin_renew(Some((10, duplicate.clone())))
        .unwrap();
    assert_eq!(cached.expected(), Some((10, duplicate.as_ref())));
    // Renewal SQL already treats expected membership as sets. This request
    // deliberately does not add a duplicate rejection policy.
    cached.enter_commit().unwrap().received();
    assert!(matches!(
        cached.returned().unwrap().begin_ack(10),
        Err(Rejected::State)
    ));
    let no_receipt = operation.begin_renew(None).unwrap();
    assert!(matches!(no_receipt.returned(), Err(Rejected::Receipt)));
    assert!(operation.snapshot().acknowledgements.is_empty());
    let fresh = operation.begin_renew(None).unwrap();
    fresh.enter_commit().unwrap().received();
    assert!(matches!(
        fresh.returned().unwrap().begin_replay(),
        Err(Rejected::State)
    ));
    let request = ack(&operation);
    assert_eq!(request.session_id(), Uuid::from_u128(71));
    assert_eq!(request.rid(), 10);
}

#[test]
fn ack_duplicate_identities_reject_before_commit_poll_without_reordering() {
    let operation = operation();
    let request = ack(&operation);
    let before = operation.snapshot();
    let same_c2s = vec![
        deleted()[0],
        DeletedSource::C2s {
            recipient_id: Uuid::from_u128(99),
            message_id: Uuid::from_u128(74),
        },
    ];
    let same_mix = vec![
        deleted()[1],
        DeletedSource::Mix(MixDelivery {
            lease_token: Uuid::from_u128(99),
            ..mix().mix().unwrap()
        }),
    ];
    for repeated in [same_c2s, same_mix] {
        let polled = AtomicBool::new(false);
        let mut future = Box::pin(ack_commit_observed(
            async {
                polled.store(true, Ordering::SeqCst);
                Ok::<_, std::io::Error>(())
            },
            &request,
            repeated,
        ));
        assert!(matches!(
            poll_once(future.as_mut()),
            Poll::Ready(Err(CompletionError::Binding(Rejected::Source)))
        ));
        drop(future);
        assert!(!polled.load(Ordering::SeqCst));
        assert_eq!(operation.snapshot(), before);
    }
    // Equal UUIDs across different tables are independent identities.
    let distinct = vec![
        DeletedSource::Mix(MixDelivery {
            delivery_id: Uuid::from_u128(74),
            ..mix().mix().unwrap()
        }),
        deleted()[0],
    ];
    request.enter_commit(distinct.clone()).unwrap().received();
    assert_eq!(
        operation.snapshot().acknowledgements[0].deleted.as_deref(),
        Some(&distinct)
    );
}

#[test]
fn ack_empty_commit_loss_and_positive_receipt_remain_distinct() {
    for empty in [false, true] {
        for cut in 0..3 {
            let operation = operation();
            let request = ack(&operation);
            let facts = if empty { vec![] } else { deleted() };
            let mut future = Box::pin(ack_commit_observed(
                async {
                    if cut == 0 {
                        std::future::pending::<()>().await;
                    }
                    if cut == 1 {
                        Err(std::io::Error::other("COMMIT response lost"))
                    } else {
                        Ok(())
                    }
                },
                &request,
                facts.clone(),
            ));
            assert_eq!(poll_once(future.as_mut()).is_pending(), cut == 0);
            drop(future);
            assert_eq!(
                operation.snapshot().acknowledgements[0].deleted.as_deref(),
                Some(&facts)
            );
            assert_eq!(
                operation.summary().responses.deleted,
                if cut == 2 { facts.len() } else { 0 }
            );
            if cut == 2 {
                let accepted = request.returned().unwrap();
                accepted.evicted();
                accepted.sending_receipt();
                accepted.receipt_sent(false);
            } else {
                assert!(matches!(request.returned(), Err(Rejected::Receipt)));
            }
            assert_eq!(
                operation.summary().responses.evictions,
                usize::from(cut == 2)
            );
        }
    }
}

#[test]
fn retirement_blocks_durable_starts_but_late_control_facts_cannot_change_terminal() {
    let operation = operation();
    let request = bind(&operation);
    request.enter_commit(ownership()).unwrap().received();
    let bound = request.returned(ownership()).unwrap();
    let terminal = operation.returned(false);
    assert!(matches!(bound.begin_exposure(), Err(Rejected::Retired)));
    assert!(matches!(
        operation.begin_renew(None),
        Err(Rejected::Retired)
    ));
    assert!(matches!(
        operation.begin_response(11, ResponseKind::Payload, vec![]),
        Err(Rejected::Retired)
    ));
    // These are observations of fixed synchronous controls, not authority
    // to expose payloads or begin a new durable effect after retirement.
    let empty = operation.observe_empty_control(11);
    empty.sending();
    empty.sent(false);
    empty.updated();
    let terminal_control = operation.observe_terminal_control(12);
    terminal_control.sending();
    terminal_control.sent(true);
    let after = operation.summary();
    assert_eq!(after.terminal, terminal.terminal);
    assert_eq!(after.keep_running, Some(false));
    assert_eq!(after.responses.accepted_responders, 0);
    assert_eq!(after.responses.control_accepted, 1);
}

#[test]
fn response_commits_bind_before_poll_and_keep_exact_receipts_on_success_only() {
    for kind in ["bind", "renew", "ack"] {
        for (cut, result) in [
            ("cancelled", None),
            ("reply_lost", Some(Err("response commit reply lost"))),
            ("committed", Some(Ok(()))),
            ("retired", None),
        ] {
            let operation = operation();
            let control = crate::test_support::CommitControl::default();
            let commit = control.future(|| {
                assert_ne!(cut, "retired", "{kind} must reject before polling");
                let snapshot = operation.snapshot();
                match kind {
                    "bind" => assert_eq!(
                        snapshot.responses[0].attempts[0].knowledge,
                        BindKnowledge::CommitCallEntered(Arc::new(ownership())),
                        "{kind}/{cut}"
                    ),
                    "renew" => assert_eq!(
                        snapshot.renewals[0].knowledge,
                        Knowledge::CommitCallEntered,
                        "{kind}/{cut}"
                    ),
                    "ack" => {
                        assert_eq!(
                            snapshot.acknowledgements[0].knowledge,
                            Knowledge::CommitCallEntered,
                            "{kind}/{cut}"
                        );
                        assert_eq!(
                            snapshot.acknowledgements[0].deleted.as_deref(),
                            Some(&deleted()),
                            "{kind}/{cut}"
                        );
                    }
                    _ => unreachable!(),
                }
            });
            let mut future = Box::pin(async {
                match kind {
                    "bind" => {
                        let request = bind(&operation);
                        if cut == "retired" {
                            operation.retire(Terminal::Cancelled);
                        }
                        bind_commit_observed(commit, &request, ownership()).await
                    }
                    "renew" => {
                        let request = operation.begin_renew(None).unwrap();
                        if cut == "retired" {
                            operation.retire(Terminal::Cancelled);
                        }
                        renew_commit_observed(commit, &request).await
                    }
                    "ack" => {
                        let request = ack(&operation);
                        if cut == "retired" {
                            operation.retire(Terminal::Cancelled);
                        }
                        ack_commit_observed(commit, &request, deleted()).await
                    }
                    _ => unreachable!(),
                }
            });
            let first = poll_once(future.as_mut());
            if cut == "retired" {
                assert!(
                    matches!(
                        first,
                        Poll::Ready(Err(CompletionError::Binding(Rejected::Retired)))
                    ),
                    "{kind}/{cut}"
                );
            } else {
                assert!(first.is_pending(), "{kind}/{cut}");
                if let Some(result) = result {
                    control.result.set(Some(result));
                    match (poll_once(future.as_mut()), result) {
                        (Poll::Ready(Ok(())), Ok(())) => {}
                        (Poll::Ready(Err(CompletionError::Repository(error))), Err(expected)) => {
                            assert_eq!(error, expected, "{kind}/{cut}");
                        }
                        _ => panic!("unexpected response result: {kind}/{cut}"),
                    }
                }
            }
            drop(future);
            assert_eq!(
                *control.events.borrow(),
                if cut == "retired" {
                    vec!["drop"]
                } else if result.is_some() {
                    vec!["poll", "poll", "drop"]
                } else {
                    vec!["poll", "drop"]
                },
                "{kind}/{cut}"
            );
            let snapshot = operation.snapshot();
            let expected = if cut == "retired" {
                Knowledge::NoCommitRequested
            } else if result == Some(Ok(())) {
                Knowledge::ReceiptKnown
            } else {
                Knowledge::CommitCallEntered
            };
            match kind {
                "bind" => {
                    let expected = match expected {
                        Knowledge::NoCommitRequested => BindKnowledge::NoCommitRequested,
                        Knowledge::CommitCallEntered => {
                            BindKnowledge::CommitCallEntered(Arc::new(ownership()))
                        }
                        Knowledge::ReceiptKnown => {
                            BindKnowledge::ReceiptKnown(Arc::new(ownership()))
                        }
                    };
                    let attempt = &snapshot.responses[0].attempts[0];
                    assert_eq!(attempt.knowledge, expected, "{kind}/{cut}");
                    assert_eq!(attempt.returned, None, "{kind}/{cut}");
                }
                "renew" => {
                    assert_eq!(snapshot.renewals[0].knowledge, expected, "{kind}/{cut}");
                    assert!(!snapshot.renewals[0].returned, "{kind}/{cut}");
                }
                "ack" => {
                    assert_eq!(
                        snapshot.acknowledgements[0].knowledge, expected,
                        "{kind}/{cut}"
                    );
                    assert!(!snapshot.acknowledgements[0].returned, "{kind}/{cut}");
                }
                _ => unreachable!(),
            }
            assert!(
                !snapshot
                    .responses
                    .iter()
                    .any(|response| response.exposure_entered),
                "{kind}/{cut}"
            );
        }
    }
}

#[test]
fn exposure_requires_its_matching_returned_bind_and_rejects_reuse() {
    for (label, committed, returned, restored) in [
        ("receipt_without_return", true, false, false),
        ("return_without_receipt", false, true, false),
        ("restored_selection", true, true, true),
        ("matched_selection", true, true, false),
    ] {
        let operation = operation();
        let request = bind(&operation);
        if committed {
            request.enter_commit(ownership()).unwrap().received();
        }
        // Deliberately corrupt a private continuation to exercise the
        // exposure guard even when a caller could not obtain it normally.
        if returned {
            let result = request.returned(ownership());
            if !committed {
                assert!(matches!(result, Err(Rejected::Receipt)), "{label}");
                assert!(
                    !operation.snapshot().responses[0].exposure_entered,
                    "{label}"
                );
                continue;
            }
            let bound = result.unwrap();
            if restored {
                operation.0.lock().unwrap().responses[0].attempts[0].restored = true;
            }
            let duplicate = BoundResponse {
                request: BindRequest {
                    operation: bound.request.operation.clone(),
                    response: bound.request.response,
                    attempt: bound.request.attempt,
                    scope: bound.request.scope,
                    rid: bound.request.rid,
                    sources: bound.request.sources.clone(),
                },
                ownership: bound.ownership.clone(),
            };
            if restored {
                assert!(
                    matches!(bound.begin_exposure(), Err(Rejected::Receipt)),
                    "{label}"
                );
            } else {
                bound.begin_exposure().unwrap();
                assert!(
                    matches!(duplicate.begin_exposure(), Err(Rejected::State)),
                    "{label}"
                );
            }
        } else {
            let bound = BoundResponse {
                request,
                ownership: Arc::new(ownership()),
            };
            assert!(
                matches!(bound.begin_exposure(), Err(Rejected::Receipt)),
                "{label}"
            );
        }
        assert_eq!(
            operation.snapshot().responses[0].exposure_entered,
            !restored && returned,
            "{label}"
        );
    }
}

#[test]
fn response_request_snapshot_and_summary_debug_redact_retained_tokens() {
    let operation = operation();
    let request = bind(&operation);
    request.enter_commit(ownership()).unwrap().received();
    let renew = operation
        .begin_renew(Some((10, Arc::new(ownership()))))
        .unwrap();
    let request_ack = ack(&operation);
    request_ack.enter_commit(deleted()).unwrap().received();
    let snapshot = operation.snapshot();
    assert_eq!(
        snapshot.responses[0].lineage[0]
            .unwrap()
            .c2s()
            .unwrap()
            .claim_id,
        Some(Uuid::from_u128(73))
    );
    assert_eq!(
        snapshot.responses[0].lineage[2]
            .unwrap()
            .mix()
            .unwrap()
            .lease_token,
        Uuid::from_u128(82)
    );
    let debug = format!(
        "{operation:?} {request:?} {renew:?} {request_ack:?} {snapshot:?} {:?} {:?} {:?}",
        snapshot.responses,
        snapshot.acknowledgements,
        operation.summary()
    );
    for secret in [71, 72, 73, 74, 81, 82] {
        assert!(!debug.contains(&Uuid::from_u128(secret).to_string()));
    }
}
