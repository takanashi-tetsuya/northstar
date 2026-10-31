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

async fn prepare_empty_fast(invocation: &CredentialInvocation<'_>) {
    prepare_empty_fast_result(invocation, true).await;
}
async fn prepare_empty_fast_result(invocation: &CredentialInvocation<'_>, prepared_fast: bool) {
    invocation
        .enter_fast(
            Uuid::from_u128(2),
            7,
            &FastCommitPlan::default(),
            None,
            Uuid::from_u128(3),
        )
        .unwrap();
    CredentialInvocation::begin(Some(invocation), std::future::ready(Ok::<(), ()>(())))
        .await
        .unwrap();
    CredentialInvocation::eligibility(
        Some(invocation),
        std::future::ready(Ok::<_, ()>(Some(true))),
    )
    .await
    .unwrap();
    invocation.transaction_returned();
    invocation.preparation_entered(CredentialPreparation::Stage);
    invocation.stage_returned(&Ok(None));
    invocation.preparation_entered(CredentialPreparation::Fast);
    invocation.preparation_returned(
        CredentialPreparation::Fast,
        if prepared_fast {
            PreparationResult::Present
        } else {
            PreparationResult::Absent
        },
    );
}
#[tokio::test]
async fn credential_joins_preserve_actual_construction_return_and_transfer_cuts() {
    let prepared = PreparedCredential::new(
        Uuid::from_u128(1),
        Uuid::from_u128(3),
        0,
        CredentialKind::UnboundFast,
    );
    let observation = prepared.observation();
    let before = observation.snapshot();
    let introduced = observation.joins();
    assert_eq!(introduced.owner.attempt, before.attempt);
    assert_eq!(introduced.owner.frame, Uuid::from_u128(1));
    assert_eq!(introduced.owner.connection, Uuid::from_u128(3));
    assert_eq!(introduced.owner.ordinal, 0);
    assert_eq!(introduced.owner.kind, CredentialKind::UnboundFast);
    assert_eq!(introduced.constructed_receipt, None);
    assert_eq!(introduced.returned_receipt, None);
    assert_eq!(introduced.transferred_receipt, None);
    assert_eq!(observation.snapshot(), before);

    let invocation = prepared
        .fast(
            Uuid::from_u128(2),
            7,
            &FastCommitPlan::default(),
            None,
            Uuid::from_u128(3),
        )
        .unwrap();
    prepare_empty_fast(&invocation).await;
    CredentialInvocation::commit(Some(&invocation), std::future::ready(Ok::<(), ()>(())))
        .await
        .unwrap();
    assert_eq!(observation.joins(), introduced);
    let receipt = CredentialCommitReceipt::new(None, None, None);
    let id = receipt.publication_identity();
    invocation.constructed(&receipt);
    let constructed = observation.joins();
    assert_eq!(constructed.owner, introduced.owner);
    assert_eq!(constructed.constructed_receipt, Some(id));
    assert_eq!(constructed.returned_receipt, None);
    assert_eq!(constructed.transferred_receipt, None);
    let result = AuthenticationResult::Authenticated(receipt);
    invocation.fast_returned(&result);
    drop(invocation);
    let AuthenticationResult::Authenticated(receipt) = result else {
        unreachable!()
    };
    let returned = observation.joins();
    assert_eq!(returned.constructed_receipt, Some(id));
    assert_eq!(returned.returned_receipt, Some(id));
    assert_eq!(returned.transferred_receipt, None);
    let before = observation.snapshot();
    assert_eq!(observation.joins(), returned);
    assert_eq!(observation.snapshot(), before);

    prepared
        .transfer(&receipt, Uuid::from_u128(1), Uuid::from_u128(3))
        .unwrap();
    let transferred = observation.joins();
    assert_eq!(transferred.owner, introduced.owner);
    assert_eq!(transferred.transferred_receipt, Some(id));
    assert!(prepared
        .transfer(&receipt, Uuid::from_u128(1), Uuid::from_u128(3))
        .is_err());
    assert_eq!(observation.joins(), transferred);
}

#[tokio::test]
async fn credential_joins_expose_swapped_raw_returns_after_anchored_construction() {
    let prepared = [
        PreparedCredential::new(
            Uuid::from_u128(1),
            Uuid::from_u128(3),
            0,
            CredentialKind::UnboundFast,
        ),
        PreparedCredential::new(
            Uuid::from_u128(1),
            Uuid::from_u128(3),
            1,
            CredentialKind::UnboundFast,
        ),
    ];
    let invocations = prepared.each_ref().map(|prepared| {
        prepared
            .fast(
                Uuid::from_u128(2),
                7,
                &FastCommitPlan::default(),
                None,
                Uuid::from_u128(3),
            )
            .unwrap()
    });
    for invocation in &invocations {
        prepare_empty_fast(invocation).await;
        CredentialInvocation::commit(Some(invocation), std::future::ready(Ok::<(), ()>(())))
            .await
            .unwrap();
    }
    let first = CredentialCommitReceipt::new(None, None, None);
    let second = CredentialCommitReceipt::new(None, None, None);
    invocations[0].constructed(&first);
    invocations[1].constructed(&second);
    let introduced = prepared
        .each_ref()
        .map(|prepared| prepared.observation().joins());
    assert_ne!(introduced[0].owner.attempt, introduced[1].owner.attempt);
    assert_ne!(
        introduced[0].constructed_receipt,
        introduced[1].constructed_receipt,
    );
    assert_eq!(introduced[0].owner.ordinal, 0);
    assert_eq!(introduced[1].owner.ordinal, 1);

    // Both receipts are real and previously introduced. Reassign only the
    // returned association, leaving each original attempt and witness intact.
    let results = [
        AuthenticationResult::Authenticated(second),
        AuthenticationResult::Authenticated(first),
    ];
    for (invocation, result) in invocations.iter().zip(&results) {
        invocation.fast_returned(result);
    }
    drop(invocations);
    for (index, (prepared, result)) in prepared.iter().zip(&results).enumerate() {
        let AuthenticationResult::Authenticated(receipt) = result else {
            unreachable!()
        };
        let observation = prepared.observation();
        let actual = observation.joins();
        assert_eq!(actual.owner, introduced[index].owner);
        assert_eq!(
            actual.constructed_receipt,
            introduced[index].constructed_receipt,
        );
        assert_eq!(
            actual.returned_receipt,
            introduced[1 - index].constructed_receipt,
        );
        assert_eq!(
            actual.returned_receipt,
            Some(receipt.publication_identity())
        );
        assert!(!observation.snapshot().return_matches);
        assert!(prepared
            .transfer(receipt, Uuid::from_u128(1), Uuid::from_u128(3))
            .is_err());
        assert_eq!(observation.joins(), actual);
        assert_eq!(actual.transferred_receipt, None);
    }
}

#[test]
fn publication_joins_project_actual_sealed_effect_intent_without_fixture_inference() {
    for (bound, notification) in [(false, false), (true, false), (true, true)] {
        let receipt = CredentialCommitReceipt::new(None, None, None);
        let observation = Observation::returned_receipt(&receipt, None);
        let initial = observation.joins();
        assert!(!initial.bound_effects);
        assert!(!initial.notification_expected);
        observation.sealed(bound, notification).unwrap();
        let sealed = observation.joins();
        assert_eq!(sealed.bound_effects, bound);
        assert_eq!(sealed.notification_expected, notification);
        assert_eq!(sealed.receipt, initial.receipt);
        assert_eq!(sealed.control, initial.control);
        assert_eq!(sealed.credential, None);
        assert_eq!(sealed.begun_receipt, None);
        let snapshot = observation.snapshot();
        assert_eq!(snapshot.effects, Effects::default());
        assert_eq!(observation.joins(), sealed);
        assert_eq!(observation.snapshot(), snapshot);
        assert!(observation.sealed(!bound, !notification).is_err());
        assert_eq!(observation.joins(), sealed);
    }
}

#[tokio::test]
async fn credential_transfer_remains_distinct_from_publication_begin_after_bosh_exposure() {
    let frame = Uuid::from_u128(1);
    let connection = Uuid::from_u128(3);
    let prepared = PreparedCredential::new(frame, connection, 0, CredentialKind::UnboundFast);
    let invocation = prepared
        .fast(
            Uuid::from_u128(2),
            7,
            &FastCommitPlan::default(),
            None,
            connection,
        )
        .unwrap();
    prepare_empty_fast(&invocation).await;
    CredentialInvocation::commit(Some(&invocation), std::future::ready(Ok::<(), ()>(())))
        .await
        .unwrap();
    let receipt = CredentialCommitReceipt::new(None, None, None);
    invocation.constructed(&receipt);
    let result = AuthenticationResult::Authenticated(receipt);
    invocation.fast_returned(&result);
    drop(invocation);
    let AuthenticationResult::Authenticated(receipt) = result else {
        unreachable!()
    };
    let credential = prepared.transfer(&receipt, frame, connection).unwrap();
    let transferred = credential.joins();
    let id = receipt.publication_identity();
    assert_eq!(transferred.constructed_receipt, Some(id));
    assert_eq!(transferred.returned_receipt, Some(id));
    assert_eq!(transferred.transferred_receipt, Some(id));
    let publication = Observation::observed_receipt(&receipt, frame, credential.clone());
    publication.sealed(false, false).unwrap();
    publication
        .transport(Transport::BoshExposureEntered { rid: 48 })
        .unwrap();
    publication
        .transport(Transport::BoshAccepted { rid: 48 })
        .unwrap();
    let joins = publication.joins();
    assert_eq!(joins.credential, Some(transferred.owner));
    assert_eq!(joins.receipt, id);
    assert_eq!(joins.begun_receipt, None);
    assert_eq!(publication.snapshot().publication, Knowledge::NotStarted);
    assert_eq!(credential.joins(), transferred);
    // This checks only the existing observation cuts. It constructs no
    // holder or response and claims no selected-owner transfer or cache.
}

#[test]
fn publication_joins_keep_return_only_origin_and_actual_begin_distinct() {
    let receipt = receipt();
    let observation = written(&receipt, true);
    let before = observation.snapshot();
    let joins = observation.joins();
    assert_eq!(joins.control, before.control);
    assert_eq!(joins.frame, Some(Uuid::from_u128(6)));
    assert_eq!(joins.receipt, receipt.publication_identity());
    assert_eq!(joins.credential, None);
    assert_eq!(joins.begun_receipt, None);
    assert_eq!(observation.snapshot(), before);
    let replacement = CredentialCommitReceipt::new(None, receipt.staged_login_epoch(), None);
    assert!(observation.begin(&replacement).is_err());
    assert_eq!(observation.joins(), joins);
    assert_eq!(observation.snapshot(), before);
    let invocation = observation.begin(&receipt).unwrap();
    let begun = observation.joins();
    assert_eq!(begun.receipt, joins.receipt);
    assert_eq!(
        begun.begun_receipt,
        Some(invocation.receipt().publication_identity()),
    );
    assert_eq!(begun.credential, None);
    assert!(!observation.snapshot().service_started);
    assert!(observation.begin(&replacement).is_err());
    assert_eq!(observation.joins(), begun);
}

#[tokio::test]
async fn credential_acknowledgement_and_receipt_instance_are_independent_authority() {
    for acknowledgement in [false, true] {
        let prepared = PreparedCredential::new(
            Uuid::from_u128(1),
            Uuid::from_u128(3),
            0,
            CredentialKind::UnboundFast,
        );
        let invocation = prepared
            .fast(
                Uuid::from_u128(2),
                7,
                &FastCommitPlan::default(),
                None,
                Uuid::from_u128(3),
            )
            .unwrap();
        prepare_empty_fast(&invocation).await;
        if acknowledgement {
            CredentialInvocation::commit(Some(&invocation), std::future::ready(Ok::<(), ()>(())))
                .await
                .unwrap();
        }
        let receipt = CredentialCommitReceipt::new(None, None, None);
        let equal_fields = CredentialCommitReceipt::new(None, None, None);
        invocation.constructed(&receipt);
        invocation.fast_returned(&AuthenticationResult::Authenticated(receipt));
        let snapshot = prepared.observation().snapshot();
        assert_eq!(snapshot.returned, Some(CredentialReturned::Authenticated));
        assert_eq!(snapshot.return_matches, acknowledgement);
        assert!(prepared
            .transfer(&equal_fields, Uuid::from_u128(1), Uuid::from_u128(3))
            .is_err());
        assert!(!prepared.observation().snapshot().transferred);
    }
}
#[tokio::test]
async fn credential_matching_receipt_transfers_only_its_original_attempt() {
    let prepared = PreparedCredential::new(
        Uuid::from_u128(1),
        Uuid::from_u128(3),
        0,
        CredentialKind::UnboundFast,
    );
    let wrong = PreparedCredential::new(
        Uuid::from_u128(1),
        Uuid::from_u128(3),
        1,
        CredentialKind::UnboundFast,
    );
    let invocation = prepared
        .fast(
            Uuid::from_u128(2),
            7,
            &FastCommitPlan::default(),
            None,
            Uuid::from_u128(3),
        )
        .unwrap();
    prepare_empty_fast(&invocation).await;
    CredentialInvocation::commit(Some(&invocation), std::future::ready(Ok::<(), ()>(())))
        .await
        .unwrap();
    let receipt = CredentialCommitReceipt::new(None, None, None);
    invocation.constructed(&receipt);
    let result = AuthenticationResult::Authenticated(receipt);
    invocation.fast_returned(&result);
    let AuthenticationResult::Authenticated(receipt) = result else {
        unreachable!()
    };
    assert!(wrong
        .transfer(&receipt, Uuid::from_u128(1), Uuid::from_u128(3))
        .is_err());
    assert!(prepared
        .transfer(&receipt, Uuid::from_u128(4), Uuid::from_u128(3))
        .is_err());
    let retained = prepared
        .transfer(&receipt, Uuid::from_u128(1), Uuid::from_u128(3))
        .unwrap();
    assert!(retained.snapshot().transferred);
    assert!(prepared
        .transfer(&receipt, Uuid::from_u128(1), Uuid::from_u128(3))
        .is_err());
}

#[test]
fn credential_generation_helper_retains_exact_query_and_rollback_results() {
    for value in [None, Some(false), Some(true)] {
        for rollback in [
            CredentialCall::Ok,
            CredentialCall::Err,
            CredentialCall::Entered,
        ] {
            let prepared = PreparedCredential::new(
                Uuid::from_u128(1),
                Uuid::from_u128(3),
                0,
                CredentialKind::UnboundFast,
            );
            let invocation = prepared
                .fast(
                    Uuid::from_u128(2),
                    7,
                    &FastCommitPlan::default(),
                    None,
                    Uuid::from_u128(3),
                )
                .unwrap();
            invocation
                .enter_fast(
                    Uuid::from_u128(2),
                    7,
                    &FastCommitPlan::default(),
                    None,
                    Uuid::from_u128(3),
                )
                .unwrap();
            let mut work = Box::pin(async {
                CredentialInvocation::begin(
                    Some(&invocation),
                    std::future::ready(Ok::<(), ()>(())),
                )
                .await
                .unwrap();
                let eligible = CredentialInvocation::eligibility(
                    Some(&invocation),
                    std::future::ready(Ok::<_, ()>(value)),
                )
                .await
                .unwrap();
                if eligible != Some(true) {
                    let _ = CredentialInvocation::rollback(
                        Some(&invocation),
                        CredentialRollbackSite::GenerationRefused,
                        async {
                            if rollback == CredentialCall::Entered {
                                std::future::pending::<()>().await;
                            }
                            if rollback == CredentialCall::Err {
                                Err(())
                            } else {
                                Ok(())
                            }
                        },
                    )
                    .await;
                } else {
                    invocation.transaction_returned();
                }
            });
            assert_eq!(
                poll_once(work.as_mut()).is_pending(),
                value != Some(true) && rollback == CredentialCall::Entered
            );
            drop(work);
            drop(invocation);
            let snapshot = prepared.observation().snapshot();
            assert_eq!(snapshot.eligibility, Eligibility::Returned(value));
            assert_eq!(snapshot.transaction_returned, value == Some(true));
            assert_eq!(
                snapshot.rollback,
                if value == Some(true) {
                    None
                } else {
                    Some((CredentialRollbackSite::GenerationRefused, rollback))
                }
            );
            assert_eq!(snapshot.commit, CredentialCall::NotEntered);
            assert!(!snapshot.receipt_constructed);
        }
    }
}

#[test]
fn credential_begin_and_query_error_or_pending_do_not_invent_rollback() {
    for query in [false, true] {
        for pending in [false, true] {
            let prepared = PreparedCredential::new(
                Uuid::from_u128(1),
                Uuid::from_u128(3),
                0,
                CredentialKind::UnboundFast,
            );
            let invocation = prepared
                .fast(
                    Uuid::from_u128(2),
                    7,
                    &FastCommitPlan::default(),
                    None,
                    Uuid::from_u128(3),
                )
                .unwrap();
            invocation
                .enter_fast(
                    Uuid::from_u128(2),
                    7,
                    &FastCommitPlan::default(),
                    None,
                    Uuid::from_u128(3),
                )
                .unwrap();
            let mut work = Box::pin(async {
                let begin = CredentialInvocation::begin(Some(&invocation), async {
                    if !query && pending {
                        std::future::pending::<()>().await;
                    }
                    if query {
                        Ok(())
                    } else {
                        Err(())
                    }
                })
                .await;
                if query {
                    begin.unwrap();
                    let _ = CredentialInvocation::eligibility(Some(&invocation), async {
                        if pending {
                            std::future::pending::<()>().await;
                        }
                        Err::<Option<bool>, ()>(())
                    })
                    .await;
                }
            });
            assert_eq!(poll_once(work.as_mut()).is_pending(), pending);
            drop(work);
            drop(invocation);
            let snapshot = prepared.observation().snapshot();
            assert_eq!(
                snapshot.begin,
                if query {
                    CredentialCall::Ok
                } else if pending {
                    CredentialCall::Entered
                } else {
                    CredentialCall::Err
                }
            );
            assert_eq!(
                snapshot.eligibility,
                if !query {
                    Eligibility::NotEntered
                } else if pending {
                    Eligibility::Entered
                } else {
                    Eligibility::Err
                }
            );
            assert_eq!(snapshot.commit, CredentialCall::NotEntered);
            assert_eq!(snapshot.rollback, None);
        }
    }
}

#[tokio::test]
async fn credential_duplicate_and_late_operations_never_poll_or_replace_first_facts() {
    for duplicate in [0, 1, 2, 3] {
        let prepared = PreparedCredential::new(
            Uuid::from_u128(1),
            Uuid::from_u128(3),
            0,
            CredentialKind::UnboundFast,
        );
        let invocation = prepared
            .fast(
                Uuid::from_u128(2),
                7,
                &FastCommitPlan::default(),
                None,
                Uuid::from_u128(3),
            )
            .unwrap();
        prepare_empty_fast_result(&invocation, duplicate != 2).await;
        if duplicate == 2 {
            CredentialInvocation::rollback(
                Some(&invocation),
                CredentialRollbackSite::FastExpired,
                std::future::ready(Ok::<(), ()>(())),
            )
            .await
            .unwrap();
        }
        if duplicate == 3 {
            CredentialInvocation::commit(Some(&invocation), std::future::ready(Ok::<(), ()>(())))
                .await
                .unwrap();
        }
        let before = prepared.observation().snapshot();
        let calls = Cell::new(0);
        let rejected = match duplicate {
            0 => CredentialInvocation::begin(Some(&invocation), async {
                calls.set(1);
                Ok::<(), ()>(())
            })
            .await
            .is_err(),
            1 => CredentialInvocation::eligibility(Some(&invocation), async {
                calls.set(1);
                Ok::<_, ()>(Some(false))
            })
            .await
            .is_err(),
            2 => CredentialInvocation::rollback(
                Some(&invocation),
                CredentialRollbackSite::GenerationRefused,
                async {
                    calls.set(1);
                    Ok::<(), ()>(())
                },
            )
            .await
            .is_err(),
            _ => CredentialInvocation::commit(Some(&invocation), async {
                calls.set(1);
                Ok::<(), ()>(())
            })
            .await
            .is_err(),
        };
        assert!(rejected);
        assert_eq!(calls.get(), 0);
        let after = prepared.observation().snapshot();
        assert_eq!(
            (after.begin, after.eligibility, after.rollback, after.commit),
            (
                before.begin,
                before.eligibility,
                before.rollback,
                before.commit
            )
        );
        assert!(after.integrity_failure);
    }
    let prepared = PreparedCredential::new(
        Uuid::from_u128(1),
        Uuid::from_u128(3),
        0,
        CredentialKind::UnboundFast,
    );
    let invocation = prepared
        .fast(
            Uuid::from_u128(2),
            7,
            &FastCommitPlan::default(),
            None,
            Uuid::from_u128(3),
        )
        .unwrap();
    prepare_empty_fast(&invocation).await;
    CredentialInvocation::commit(Some(&invocation), std::future::ready(Ok::<(), ()>(())))
        .await
        .unwrap();
    let receipt = CredentialCommitReceipt::new(None, None, None);
    invocation.constructed(&receipt);
    let original_id = prepared
        .observation
        .0
        .lock()
        .unwrap()
        .constructed
        .as_ref()
        .unwrap()
        .0;
    invocation.constructed(&CredentialCommitReceipt::new(None, None, None));
    assert_eq!(
        prepared
            .observation
            .0
            .lock()
            .unwrap()
            .constructed
            .as_ref()
            .unwrap()
            .0,
        original_id
    );
    invocation.fast_returned(&AuthenticationResult::Authenticated(receipt));
    invocation.fast_returned(&AuthenticationResult::ExpiredCredentials);
    assert_eq!(
        prepared.observation().snapshot().returned,
        Some(CredentialReturned::Authenticated)
    );
    prepared
        .observation()
        .handler_returned(HandlerReturn::Completed);
    let calls = Cell::new(0);
    assert!(CredentialInvocation::commit(Some(&invocation), async {
        calls.set(1);
        Ok::<(), ()>(())
    })
    .await
    .is_err());
    assert_eq!(calls.get(), 0);
    assert_eq!(prepared.observation().snapshot().commit, CredentialCall::Ok);
}

#[tokio::test]
async fn credential_commit_entry_freezes_preparation_and_stage_identity() {
    let prepared = PreparedCredential::new(
        Uuid::from_u128(1),
        Uuid::from_u128(3),
        0,
        CredentialKind::UnboundFast,
    );
    let invocation = prepared
        .fast(
            Uuid::from_u128(2),
            7,
            &FastCommitPlan::default(),
            None,
            Uuid::from_u128(3),
        )
        .unwrap();
    prepare_empty_fast(&invocation).await;
    let mut commit = Box::pin(CredentialInvocation::commit(
        Some(&invocation),
        std::future::pending::<std::result::Result<(), ()>>(),
    ));
    assert!(poll_once(commit.as_mut()).is_pending());
    invocation.stage_id(Uuid::from_u128(88));
    invocation.stage_returned(&Ok(Some(StagedLoginEpoch {
        operation_id: Uuid::from_u128(88),
        connection_id: Uuid::from_u128(3),
        user_id: Uuid::from_u128(2),
        device_id: Uuid::from_u128(4),
        auth_generation: 7,
        epoch: 9,
    })));
    let state = prepared.observation.0.lock().unwrap();
    assert!(state.prospective.as_ref().unwrap().receipt.stage.is_none());
    assert!(state.snapshot.stage_id.is_none());
    assert!(state.stage.is_none());
    assert!(!state.integrity);
    drop(state);
    drop(commit);
    assert_eq!(
        prepared.observation().snapshot().commit,
        CredentialCall::Entered
    );
}

#[tokio::test]
async fn credential_stage_error_keeps_original_sql_operation_and_device_roles() {
    let plan = FastCommitPlan {
        issue: Some(super::super::FastTokenIssue {
            device_id: Uuid::from_u128(9),
            mechanism: "HT-SHA-256-NONE".to_owned(),
            ttl_days: 7,
            strong_reauth_max_days: 30,
            inherited_chain: None,
        }),
        ..FastCommitPlan::default()
    };
    let prepared = PreparedCredential::new(
        Uuid::from_u128(1),
        Uuid::from_u128(3),
        0,
        CredentialKind::UnboundFast,
    );
    let invocation = prepared
        .fast(
            Uuid::from_u128(2),
            7,
            &plan,
            Some(Uuid::from_u128(4)),
            Uuid::from_u128(3),
        )
        .unwrap();
    invocation
        .enter_fast(
            Uuid::from_u128(2),
            7,
            &plan,
            Some(Uuid::from_u128(4)),
            Uuid::from_u128(3),
        )
        .unwrap();
    CredentialInvocation::begin(Some(&invocation), std::future::ready(Ok::<(), ()>(())))
        .await
        .unwrap();
    CredentialInvocation::eligibility(
        Some(&invocation),
        std::future::ready(Ok::<_, ()>(Some(true))),
    )
    .await
    .unwrap();
    invocation.transaction_returned();
    invocation.preparation_entered(CredentialPreparation::Stage);
    invocation.stage_id(Uuid::from_u128(5));
    assert_eq!(
        prepared.observation().snapshot().stage_id,
        Some(Uuid::from_u128(5))
    );
    invocation.stage_id(Uuid::from_u128(6));
    invocation.stage_returned(&Err(anyhow::anyhow!("synthetic SQL stage error")));
    let state = prepared.observation.0.lock().unwrap();
    assert_eq!(state.snapshot.stage_id, Some(Uuid::from_u128(5)));
    assert_eq!(
        state.request.as_ref().unwrap().device,
        Some(Uuid::from_u128(4))
    );
    assert_eq!(
        state
            .request
            .as_ref()
            .unwrap()
            .fast
            .as_ref()
            .unwrap()
            .issue
            .as_ref()
            .unwrap()
            .device_id,
        Uuid::from_u128(9)
    );
    assert_eq!(state.snapshot.commit, CredentialCall::NotEntered);
    assert!(state.stage.is_none());
}

#[test]
fn credential_refusal_sites_preserve_rollback_propagation_and_never_authorize_commit() {
    use northstar_session_core::finalization::{
        BindingFinalizationOutcome, SmResumeFinalizationOutcome, SmResumeFinalizationRequest,
    };
    let sites = [
        (
            CredentialKind::UnboundFast,
            CredentialRollbackSite::GenerationRefused,
            CredentialPreparation::Stage,
        ),
        (
            CredentialKind::UnboundFast,
            CredentialRollbackSite::FastExpired,
            CredentialPreparation::Fast,
        ),
        (
            CredentialKind::Binding,
            CredentialRollbackSite::BindingReservationLost,
            CredentialPreparation::Binding,
        ),
        (
            CredentialKind::Binding,
            CredentialRollbackSite::BindingStageMissing,
            CredentialPreparation::Stage,
        ),
        (
            CredentialKind::Binding,
            CredentialRollbackSite::BindingFastExpired,
            CredentialPreparation::Fast,
        ),
        (
            CredentialKind::Resume,
            CredentialRollbackSite::ResumeStageMissing,
            CredentialPreparation::Stage,
        ),
        (
            CredentialKind::Resume,
            CredentialRollbackSite::ResumeClaimLost,
            CredentialPreparation::Activation,
        ),
        (
            CredentialKind::Resume,
            CredentialRollbackSite::ResumeFastExpired,
            CredentialPreparation::Fast,
        ),
        (
            CredentialKind::Resume,
            CredentialRollbackSite::ResumePrivacyMissing,
            CredentialPreparation::Privacy,
        ),
    ];
    for (kind, site, operation) in sites {
        for outcome in [
            CredentialCall::Ok,
            CredentialCall::Err,
            CredentialCall::Entered,
        ] {
            let prepared = PreparedCredential::new(Uuid::from_u128(1), Uuid::from_u128(3), 0, kind);
            let plan = FastCommitPlan::default();
            let request = SmResumeFinalizationRequest {
                session_id: Uuid::from_u128(6),
                claim_token: Uuid::from_u128(8),
                connection_id: Uuid::from_u128(3),
                user_id: Uuid::from_u128(2),
                expected_auth_generation: 7,
                client_h: 1,
                acknowledged_count: 0,
                peer_ip: "192.0.2.1".parse().unwrap(),
                user_agent_id: Some(Uuid::from_u128(4)),
                active_privacy_list: None,
                ttl_seconds: 90,
                live_lease_seconds: 43,
                max_stanzas: 17,
                max_bytes: 801,
                fast_plan: Some(&plan),
            };
            let invocation = match kind {
                CredentialKind::UnboundFast => {
                    prepared.fast(Uuid::from_u128(2), 7, &plan, None, Uuid::from_u128(3))
                }
                CredentialKind::Binding => prepared.binding(
                    Uuid::from_u128(3),
                    Uuid::from_u128(2),
                    7,
                    "private@example.test/resource",
                    43,
                    Some(Uuid::from_u128(4)),
                    Some(&plan),
                ),
                CredentialKind::Resume => prepared.resume(&request),
            }
            .unwrap();
            match kind {
                CredentialKind::UnboundFast => {
                    invocation.enter_fast(Uuid::from_u128(2), 7, &plan, None, Uuid::from_u128(3))
                }
                CredentialKind::Binding => invocation.enter_binding(
                    Uuid::from_u128(3),
                    Uuid::from_u128(2),
                    7,
                    "private@example.test/resource",
                    43,
                    Some(Uuid::from_u128(4)),
                    Some(&plan),
                ),
                CredentialKind::Resume => invocation.enter_resume(&request),
            }
            .unwrap();
            let mut work = Box::pin(async {
                CredentialInvocation::begin(
                    Some(&invocation),
                    std::future::ready(Ok::<(), ()>(())),
                )
                .await
                .unwrap();
                CredentialInvocation::eligibility(
                    Some(&invocation),
                    std::future::ready(Ok::<_, ()>(
                        if site == CredentialRollbackSite::GenerationRefused {
                            Some(false)
                        } else {
                            Some(true)
                        },
                    )),
                )
                .await
                .unwrap();
                if site != CredentialRollbackSite::GenerationRefused {
                    invocation.transaction_returned();
                    invocation.preparation_entered(operation);
                    invocation.preparation_returned(operation, PreparationResult::Absent);
                }
                let rollback = CredentialInvocation::rollback(Some(&invocation), site, async {
                    if outcome == CredentialCall::Entered {
                        std::future::pending::<()>().await;
                    }
                    if outcome == CredentialCall::Err {
                        Err(std::io::Error::other("synthetic rollback error"))
                    } else {
                        Ok(())
                    }
                })
                .await
                .map_err(credential_error);
                match kind {
                    CredentialKind::UnboundFast => {
                        let result = match rollback {
                            Err(error) if site != CredentialRollbackSite::FastExpired => {
                                AuthenticationResult::BackendFailure(error)
                            }
                            _ => AuthenticationResult::ExpiredCredentials,
                        };
                        invocation.fast_returned(&result);
                    }
                    CredentialKind::Binding => invocation.binding_returned(&rollback.map(|()| {
                        if site == CredentialRollbackSite::BindingReservationLost {
                            BindingFinalizationOutcome::ReservationLost
                        } else {
                            BindingFinalizationOutcome::CredentialsExpired
                        }
                    })),
                    CredentialKind::Resume => {
                        invocation.resume_returned(&rollback.map(|()| match site {
                            CredentialRollbackSite::ResumeClaimLost => {
                                SmResumeFinalizationOutcome::ClaimLost
                            }
                            CredentialRollbackSite::ResumePrivacyMissing => {
                                SmResumeFinalizationOutcome::PrivacySelectionMissing
                            }
                            _ => SmResumeFinalizationOutcome::CredentialsExpired,
                        }))
                    }
                }
            });
            assert_eq!(
                poll_once(work.as_mut()).is_pending(),
                outcome == CredentialCall::Entered
            );
            drop(work);
            let snapshot = prepared.observation().snapshot();
            assert_eq!(snapshot.rollback, Some((site, outcome)));
            assert_eq!(snapshot.commit, CredentialCall::NotEntered);
            assert!(!snapshot.receipt_constructed);
            if outcome == CredentialCall::Entered {
                assert_eq!(snapshot.returned, None);
            }
            if outcome == CredentialCall::Ok {
                let returned = match site {
                    CredentialRollbackSite::GenerationRefused
                    | CredentialRollbackSite::FastExpired => CredentialReturned::ExpiredCredentials,
                    CredentialRollbackSite::BindingReservationLost => {
                        CredentialReturned::BindingReservationLost
                    }
                    CredentialRollbackSite::BindingStageMissing
                    | CredentialRollbackSite::BindingFastExpired => {
                        CredentialReturned::BindingCredentialsExpired
                    }
                    CredentialRollbackSite::ResumeClaimLost => CredentialReturned::ResumeClaimLost,
                    CredentialRollbackSite::ResumePrivacyMissing => {
                        CredentialReturned::ResumePrivacySelectionMissing
                    }
                    CredentialRollbackSite::ResumeStageMissing
                    | CredentialRollbackSite::ResumeFastExpired => {
                        CredentialReturned::ResumeCredentialsExpired
                    }
                };
                assert_eq!(snapshot.returned, Some(returned));
            }
            if outcome == CredentialCall::Err {
                assert_eq!(
                    snapshot.returned,
                    Some(if site == CredentialRollbackSite::FastExpired {
                        CredentialReturned::ExpiredCredentials
                    } else if kind == CredentialKind::UnboundFast {
                        CredentialReturned::BackendFailure
                    } else {
                        CredentialReturned::Error
                    })
                );
            }
            let calls = Cell::new(0);
            let mut commit = Box::pin(CredentialInvocation::commit(Some(&invocation), async {
                calls.set(1);
                Ok::<(), ()>(())
            }));
            assert!(matches!(
                poll_once(commit.as_mut()),
                Poll::Ready(Err(CommitError::Observation(_)))
            ));
            assert_eq!(calls.get(), 0);
        }
    }
}
#[tokio::test]
async fn credential_incomplete_preparation_rejects_commit_without_polling_and_keeps_error_identity()
{
    let prepared = PreparedCredential::new(
        Uuid::from_u128(1),
        Uuid::from_u128(3),
        0,
        CredentialKind::UnboundFast,
    );
    let invocation = prepared
        .fast(
            Uuid::from_u128(2),
            7,
            &FastCommitPlan::default(),
            None,
            Uuid::from_u128(3),
        )
        .unwrap();
    invocation
        .enter_fast(
            Uuid::from_u128(2),
            7,
            &FastCommitPlan::default(),
            None,
            Uuid::from_u128(3),
        )
        .unwrap();
    CredentialInvocation::begin(Some(&invocation), std::future::ready(Ok::<(), ()>(())))
        .await
        .unwrap();
    CredentialInvocation::eligibility(
        Some(&invocation),
        std::future::ready(Ok::<_, ()>(Some(true))),
    )
    .await
    .unwrap();
    invocation.transaction_returned();
    let calls = Cell::new(0);
    assert!(matches!(
        CredentialInvocation::commit(Some(&invocation), async {
            calls.set(1);
            Ok::<(), ()>(())
        })
        .await,
        Err(CommitError::Observation(_))
    ));
    assert_eq!(calls.get(), 0);
    assert_eq!(
        prepared.observation().snapshot().commit,
        CredentialCall::NotEntered
    );
    let result = CredentialInvocation::begin(
        None,
        std::future::ready(Err::<(), _>(std::io::Error::from(
            std::io::ErrorKind::ConnectionReset,
        ))),
    )
    .await;
    let error = credential_error(result.unwrap_err());
    assert_eq!(
        error.downcast_ref::<std::io::Error>().unwrap().kind(),
        std::io::ErrorKind::ConnectionReset
    );
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
