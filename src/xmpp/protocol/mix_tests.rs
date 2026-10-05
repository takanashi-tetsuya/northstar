use super::*;
use crate::services::mix::MamRsmPage;

struct MixWorkerHolderProbe<T> {
    output: Option<T>,
    pending: bool,
    panic_poll: bool,
    panic_drop: bool,
    dropped: Option<Box<dyn FnOnce() + Send>>,
}
impl<T: Unpin> std::future::Future for MixWorkerHolderProbe<T> {
    type Output = Result<T>;
    fn poll(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        let this = self.get_mut();
        if this.panic_poll {
            std::panic::panic_any("MIX worker probe poll panic");
        }
        if this.pending {
            std::task::Poll::Pending
        } else {
            std::task::Poll::Ready(Ok(this.output.take().unwrap()))
        }
    }
}
impl<T> Drop for MixWorkerHolderProbe<T> {
    fn drop(&mut self) {
        if let Some(dropped) = self.dropped.take() {
            dropped();
        }
        if self.panic_drop {
            std::panic::panic_any("MIX worker probe drop panic");
        }
    }
}

#[tokio::test]
async fn mix_worker_claim_holder_retains_panics_and_destroys_child_before_retirement() {
    use crate::services::mix::outbox::{core, fixture};
    use futures::FutureExt;
    use std::sync::atomic::{AtomicBool, Ordering};
    for cut in 0..5 {
        let dropped = Arc::new(AtomicBool::new(false));
        let marker = dropped.clone();
        let (owner, runner) = fixture::claim_probe(|owner| {
            let owner = owner.clone();
            Box::pin(MixWorkerHolderProbe {
                output: Some(Vec::new()),
                pending: cut != 3,
                panic_poll: cut == 2,
                panic_drop: cut >= 3,
                dropped: Some(Box::new(move || {
                    assert_eq!(owner.snapshot().terminal, None);
                    marker.store(true, Ordering::Relaxed);
                })),
            })
        });
        let mut runner = Box::pin(runner);
        if matches!(cut, 2 | 3) {
            let payload = match std::panic::AssertUnwindSafe(&mut runner)
                .catch_unwind()
                .await
            {
                Err(payload) => payload,
                Ok(_) => panic!("expected holder probe panic"),
            };
            assert_eq!(
                payload.downcast_ref::<&str>(),
                Some(&if cut == 2 {
                    "MIX worker probe poll panic"
                } else {
                    "MIX worker probe drop panic"
                })
            );
            assert_eq!(
                owner.snapshot().terminal,
                None,
                "externally caught panic does not destroy the holder"
            );
        } else if cut != 0 {
            assert!(futures::poll!(&mut runner).is_pending());
        }
        if cut == 4 {
            let payload = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(runner)))
                .unwrap_err();
            assert_eq!(
                payload.downcast_ref::<&str>(),
                Some(&"MIX worker probe drop panic")
            );
        } else {
            drop(runner);
        }
        assert!(dropped.load(Ordering::Relaxed));
        assert_eq!(
            owner.snapshot().terminal,
            Some(if cut >= 2 {
                core::TerminalReason::Panicked
            } else {
                core::TerminalReason::Cancelled
            })
        );
        assert_eq!(
            owner.snapshot().knowledge,
            core::ClaimKnowledge::NoStatementEntered
        );
    }
}

#[tokio::test]
async fn mix_worker_attempt_holder_retains_panics_and_destroys_child_before_retirement() {
    use crate::services::mix::outbox::{core, fixture};
    use futures::FutureExt;
    use std::sync::atomic::{AtomicBool, Ordering};
    for cut in 0..5 {
        let dropped = Arc::new(AtomicBool::new(false));
        let marker = dropped.clone();
        let (owner, runner) = fixture::attempt_probe(|owner| {
            let owner = owner.clone();
            Box::pin(MixWorkerHolderProbe {
                output: Some(()),
                pending: cut != 3,
                panic_poll: cut == 2,
                panic_drop: cut >= 3,
                dropped: Some(Box::new(move || {
                    assert_eq!(owner.snapshot().terminal, None);
                    marker.store(true, Ordering::Relaxed);
                })),
            })
        });
        let mut runner = Box::pin(runner);
        if matches!(cut, 2 | 3) {
            let payload = match std::panic::AssertUnwindSafe(&mut runner)
                .catch_unwind()
                .await
            {
                Err(payload) => payload,
                Ok(_) => panic!("expected holder probe panic"),
            };
            assert_eq!(
                payload.downcast_ref::<&str>(),
                Some(&if cut == 2 {
                    "MIX worker probe poll panic"
                } else {
                    "MIX worker probe drop panic"
                })
            );
            assert_eq!(owner.snapshot().terminal, None);
        } else if cut != 0 {
            assert!(futures::poll!(&mut runner).is_pending());
        }
        if cut == 4 {
            let payload = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(runner)))
                .unwrap_err();
            assert_eq!(
                payload.downcast_ref::<&str>(),
                Some(&"MIX worker probe drop panic")
            );
        } else {
            drop(runner);
        }
        assert!(dropped.load(Ordering::Relaxed));
        assert_eq!(
            owner.snapshot().terminal,
            Some(if cut >= 2 {
                core::TerminalReason::Panicked
            } else {
                core::TerminalReason::Cancelled
            })
        );
        assert_eq!(owner.snapshot().route, core::RoutePhase::Unprepared);
        assert!(owner.snapshot().settlement.is_none());
    }
}

#[tokio::test]
async fn mix_worker_observed_local_waiter_records_all_typed_transfers_before_return() {
    use crate::services::mix::outbox::{core, fixture};
    for (completion, boundary) in [
        (
            crate::outbound::MixTransportCompletion::SocketFenced {
                connection_id: Uuid::from_u128(101),
            },
            core::TransferBoundary::SocketFenced(Uuid::from_u128(101)),
        ),
        (
            crate::outbound::MixTransportCompletion::SmPersisted {
                session_id: Uuid::from_u128(102),
            },
            core::TransferBoundary::SmPersisted(Uuid::from_u128(102)),
        ),
        (
            crate::outbound::MixTransportCompletion::BoshPersisted {
                session_id: Uuid::from_u128(103),
            },
            core::TransferBoundary::BoshPersisted(Uuid::from_u128(103)),
        ),
    ] {
        let (owner, route) = fixture::route(false);
        let request = route.local_request("bob@local.test/phone".into()).unwrap();
        let (output, mut consumer) = tokio::sync::mpsc::channel(1);
        let sender = crate::outbound::OutboundSender::new(output);
        let disconnect = tokio_util::sync::CancellationToken::new();
        let mut waiting = Box::pin(try_send_local_durable_mix_observed(
            &sender,
            &disconnect,
            &request,
        ));
        assert!(futures::poll!(&mut waiting).is_pending());
        let item = consumer
            .try_recv()
            .expect("one exact item was actually queued");
        assert_eq!(
            item.mix_delivery(),
            Some(crate::outbound::MixDelivery {
                delivery_id: Uuid::from_u128(91),
                lease_token: Uuid::from_u128(96)
            })
        );
        assert!(owner.snapshot().transfer.is_none());
        item.complete_mix_handoff(completion);
        assert_eq!(waiting.await.unwrap(), completion);
        assert_eq!(
            owner.snapshot().transfer,
            Some(core::TransferFact {
                target: "bob@local.test/phone".into(),
                boundary
            })
        );
        assert!(!disconnect.is_cancelled());
        assert!(matches!(
            try_send_local_durable_mix_observed(&sender, &disconnect, &request).await,
            Err(MixLocalTransportFailure::Observation(_))
        ));
        assert!(
            consumer.try_recv().is_err(),
            "a repeated request must not enqueue a second item"
        );
        owner.close_renewal_scope().unwrap();
        assert!(matches!(
            route.returned(core::RouteResult::Retry),
            Err(core::Rejected::Transferred)
        ));
        assert!(owner.snapshot().settlement.is_none());
    }
}

#[tokio::test]
async fn mix_worker_cancelled_local_wait_keeps_uncertainty_and_exact_disconnect() {
    use crate::services::mix::outbox::{core, fixture};
    let (owner, route) = fixture::route(false);
    let request = route.local_request("bob@local.test/phone".into()).unwrap();
    let (output, mut consumer) = tokio::sync::mpsc::channel(1);
    let sender = crate::outbound::OutboundSender::new(output);
    let disconnect = tokio_util::sync::CancellationToken::new();
    let mut waiting = Box::pin(try_send_local_durable_mix_observed(
        &sender,
        &disconnect,
        &request,
    ));
    assert!(futures::poll!(&mut waiting).is_pending());
    let item = consumer.try_recv().unwrap();
    drop(waiting);
    assert!(disconnect.is_cancelled());
    assert!(owner.snapshot().local[0].enqueued);
    assert_eq!(owner.snapshot().local[0].returned, None);
    assert!(owner.snapshot().transfer.is_none());
    drop(item);
    owner.close_renewal_scope().unwrap();
    assert!(matches!(
        route.returned(core::RouteResult::Retry),
        Err(core::Rejected::MissingReceipt)
    ));
    assert!(owner.snapshot().settlement.is_none());
}

#[test]
fn mix_worker_cluster_adapter_consumes_typed_handoff_but_never_a_delivered_boolean() {
    use crate::services::mix::outbox::{core, fixture};
    for (boundary, expected) in [
        (
            crate::cluster::ClusterMixHandoff::SocketFenced,
            core::TransferBoundary::ClusterSocketFenced,
        ),
        (
            crate::cluster::ClusterMixHandoff::SmPersisted,
            core::TransferBoundary::ClusterSmPersisted,
        ),
        (
            crate::cluster::ClusterMixHandoff::BoshPersisted,
            core::TransferBoundary::ClusterBoshPersisted,
        ),
    ] {
        let (owner, route) = fixture::route(false);
        let request = route.cluster_request("node-b".into()).unwrap();
        request.start().unwrap();
        let result = Ok(crate::cluster::NodeDeliveryReceipt {
            acknowledged: true,
            delivered: true,
            mix_handoff: Some(boundary),
            ..Default::default()
        });
        record_claimed_cluster_result(&request, &result).unwrap();
        assert_eq!(
            owner.snapshot().transfer,
            Some(core::TransferFact {
                target: "node-b".into(),
                boundary: expected
            })
        );
        owner.close_renewal_scope().unwrap();
        assert!(matches!(
            route.returned(core::RouteResult::Retry),
            Err(core::Rejected::Transferred)
        ));
        assert!(owner.snapshot().settlement.is_none());
    }
    for result in [
        Ok(crate::cluster::NodeDeliveryReceipt {
            acknowledged: true,
            delivered: true,
            ..Default::default()
        }),
        Ok(crate::cluster::NodeDeliveryReceipt {
            acknowledged: false,
            delivered: true,
            mix_handoff: Some(crate::cluster::ClusterMixHandoff::SmPersisted),
            ..Default::default()
        }),
        Err(anyhow::anyhow!("cluster receipt error")),
    ] {
        let (owner, route) = fixture::route(false);
        let request = route.cluster_request("node-b".into()).unwrap();
        request.start().unwrap();
        record_claimed_cluster_result(&request, &result).unwrap();
        assert!(owner.snapshot().transfer.is_none());
        assert_eq!(owner.snapshot().cluster[0].handoff, None);
        assert!(owner.snapshot().settlement.is_none());
    }
}

#[tokio::test]
async fn mix_worker_unpolled_and_stopped_claims_do_not_invent_an_empty_database_receipt() {
    use crate::services::mix::outbox::{self, core};
    use std::sync::atomic::{AtomicUsize, Ordering};
    for stopped in [false, true] {
        let turn = outbox::ClaimTurn::new(1, 8 * 1024 * 1024).unwrap();
        let owner = turn.observation();
        let calls = Arc::new(AtomicUsize::new(0));
        let effect_calls = calls.clone();
        let run = turn.run(move |request, _| async move {
            let stop = tokio_util::sync::CancellationToken::new();
            stop.cancel();
            drainable_mix_outbox_claim(
                &stop,
                &tokio_util::sync::CancellationToken::new(),
                async move {
                    effect_calls.fetch_add(1, Ordering::Relaxed);
                    request.start()?;
                    Ok::<Vec<outbox::OwnedAttempt>, anyhow::Error>(vec![])
                },
            )
            .await
        });
        if stopped {
            assert!(run.await.unwrap().is_empty());
        } else {
            drop(run);
        }
        assert_eq!(calls.load(Ordering::Relaxed), 0);
        assert!(!owner.snapshot().started);
        assert_eq!(
            owner.snapshot().knowledge,
            core::ClaimKnowledge::NoStatementEntered
        );
        assert_eq!(
            owner.snapshot().terminal,
            Some(if stopped {
                core::TerminalReason::Completed
            } else {
                core::TerminalReason::Cancelled
            })
        );
    }
    let owned = outbox::OwnedAttempt::new(outbox::fixture::attempt(false));
    let owner = owned.observation();
    drop(owned);
    assert_eq!(
        owner.snapshot().terminal,
        Some(core::TerminalReason::Cancelled)
    );
    assert_eq!(owner.snapshot().route, core::RoutePhase::Unprepared);
}

#[tokio::test]
async fn mix_worker_claim_statement_cuts_keep_receipts_without_issuing_attempts_after_error() {
    use crate::services::mix::outbox::{self, core, fixture};
    use std::sync::atomic::{AtomicUsize, Ordering};
    for cut in 0..4 {
        let turn = outbox::ClaimTurn::new(1, 8 * 1024 * 1024).unwrap();
        let owner = turn.observation();
        let calls = Arc::new(AtomicUsize::new(0));
        let child_calls = calls.clone();
        let mut run = Box::pin(turn.run(move |request, _| async move {
            request.start()?;
            if cut == 0 {
                std::future::pending::<()>().await;
            }
            let entered = request.enter_statement()?;
            child_calls.fetch_add(1, Ordering::Relaxed);
            if cut == 1 {
                std::future::pending::<()>().await;
            }
            request.received(entered, fixture::claimed_rows(false))?;
            if cut == 2 {
                std::future::pending::<()>().await;
            }
            request.failed()?;
            anyhow::bail!("claim receipt-before-return error")
        }));
        if cut == 3 {
            assert!(matches!(
                futures::poll!(&mut run),
                std::task::Poll::Ready(Err(_))
            ));
        } else {
            assert!(futures::poll!(&mut run).is_pending());
        }
        drop(run);
        assert_eq!(calls.load(Ordering::Relaxed), usize::from(cut != 0));
        match owner.snapshot().knowledge {
            core::ClaimKnowledge::NoStatementEntered => assert_eq!(cut, 0),
            core::ClaimKnowledge::AutocommitStatementEntered => assert_eq!(cut, 1),
            core::ClaimKnowledge::StatementReceipt(rows) => {
                assert!(cut >= 2);
                assert_eq!(rows.len(), 1);
                assert_eq!(rows[0].source.delivery_id, Uuid::from_u128(91));
                assert_eq!(rows[0].source.lease_token, Uuid::from_u128(96));
            }
            core::ClaimKnowledge::ReadEmpty => panic!("no empty shortcut was executed"),
        }
        assert_eq!(
            owner.snapshot().returned,
            (cut == 3).then_some(core::ClaimReturned::Error)
        );
    }
}

#[tokio::test]
async fn mix_worker_archive_commit_cuts_preserve_stored_and_replay_knowledge() {
    use crate::services::mix::outbox::{self, core, fixture};
    use std::sync::atomic::{AtomicUsize, Ordering};
    for result in [
        core::ArchiveResult::Stored(Uuid::from_u128(97)),
        core::ArchiveResult::Replay(Uuid::from_u128(98)),
    ] {
        for cut in 0..5 {
            let (owner, route) = fixture::route(true);
            let request = route
                .archive_request(
                    Uuid::from_u128(99),
                    Uuid::from_u128(97),
                    Some(Uuid::from_u128(95).to_string()),
                )
                .unwrap();
            let calls = AtomicUsize::new(0);
            let mut effect = Box::pin(async {
                request.start()?;
                if cut == 1 {
                    std::future::pending::<()>().await;
                }
                core::archive_commit_observed(
                    async {
                        calls.fetch_add(1, Ordering::Relaxed);
                        if cut == 2 {
                            std::future::pending::<()>().await;
                        }
                        Ok::<(), anyhow::Error>(())
                    },
                    &request,
                    result,
                )
                .await
                .map_err(outbox::commit_error)?;
                if cut == 3 {
                    std::future::pending::<()>().await;
                }
                request.failed()?;
                Err::<(), anyhow::Error>(anyhow::anyhow!("archive receipt-before-return error"))
            });
            if cut == 4 {
                assert!(matches!(
                    futures::poll!(&mut effect),
                    std::task::Poll::Ready(Err(_))
                ));
            } else if cut != 0 {
                assert!(futures::poll!(&mut effect).is_pending());
            }
            drop(effect);
            assert_eq!(calls.load(Ordering::Relaxed), usize::from(cut >= 2));
            assert_eq!(
                owner.snapshot().archive.knowledge,
                match cut {
                    0 | 1 => core::ArchiveKnowledge::NoCommitEntered,
                    2 => core::ArchiveKnowledge::CommitCallEntered(result),
                    _ => core::ArchiveKnowledge::ReceiptKnown(result),
                }
            );
            assert_eq!(
                owner.snapshot().archive.returned,
                (cut == 4).then_some(core::ArchiveReturned::Error)
            );
            assert!(route.local_request("bob@local.test/phone".into()).is_err());
        }
    }
}

#[tokio::test]
async fn mix_worker_settlement_commit_cuts_keep_no_match_not_moved_and_lease_lost_receipts() {
    use crate::services::mix::outbox::{self, core, fixture};
    use std::sync::atomic::{AtomicUsize, Ordering};
    for result in [
        core::SettlementResult::Ack(false),
        core::SettlementResult::DeadLetter(false),
        core::SettlementResult::Retry(core::RetryResult::LeaseLost),
    ] {
        for cut in 0..5 {
            let (owner, request) = fixture::settlement(result.kind());
            let calls = AtomicUsize::new(0);
            let mut effect = Box::pin(async {
                request.start()?;
                if cut == 1 {
                    std::future::pending::<()>().await;
                }
                core::settlement_commit_observed(
                    async {
                        calls.fetch_add(1, Ordering::Relaxed);
                        if cut == 2 {
                            std::future::pending::<()>().await;
                        }
                        Ok::<(), anyhow::Error>(())
                    },
                    &request,
                    result,
                )
                .await
                .map_err(outbox::commit_error)?;
                if cut == 3 {
                    std::future::pending::<()>().await;
                }
                request.failed()?;
                Err::<(), anyhow::Error>(anyhow::anyhow!("settlement receipt-before-return error"))
            });
            if cut == 4 {
                assert!(matches!(
                    futures::poll!(&mut effect),
                    std::task::Poll::Ready(Err(_))
                ));
            } else if cut != 0 {
                assert!(futures::poll!(&mut effect).is_pending());
            }
            drop(effect);
            assert_eq!(calls.load(Ordering::Relaxed), usize::from(cut >= 2));
            assert_eq!(
                owner.snapshot().settlement.as_ref().unwrap().knowledge,
                match cut {
                    0 | 1 => core::SettlementKnowledge::NotEntered,
                    2 => core::SettlementKnowledge::CommitCallEntered(result),
                    _ => core::SettlementKnowledge::ReceiptKnown(result),
                }
            );
            assert_eq!(
                owner.snapshot().settlement.as_ref().unwrap().returned,
                (cut == 4).then_some(core::SettlementReturned::Error)
            );
            assert!(matches!(
                owner.renewal_request(),
                Err(core::Rejected::Settlement)
            ));
        }
    }
}

#[tokio::test(start_paused = true)]
async fn mix_worker_existing_renewal_loop_drops_pending_child_before_scope_closure() {
    use crate::services::mix::outbox::{core, fixture};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    struct RenewalDrop {
        owner: core::Observation,
        dropped: Arc<AtomicBool>,
    }
    impl Drop for RenewalDrop {
        fn drop(&mut self) {
            assert!(!self.owner.snapshot().renewal_scope_closed);
            assert_eq!(self.owner.snapshot().terminal, None);
            self.dropped.store(true, Ordering::Relaxed);
        }
    }
    let (owner, route) = fixture::route(false);
    let gate = Arc::new(tokio::sync::Semaphore::new(1));
    let effect_gate = gate.clone();
    let renewal_gate = gate.clone();
    let renewal_owner = owner.clone();
    let dropped = Arc::new(AtomicBool::new(false));
    let renewal_dropped = dropped.clone();
    let renewals = Arc::new(AtomicUsize::new(0));
    let renewal_calls = renewals.clone();
    let (release_tx, release_rx) = tokio::sync::oneshot::channel();
    let mut run = Box::pin(run_claimed_mix_effect_with_lease(
        tokio_util::sync::CancellationToken::new(),
        tokio::time::Instant::now() + Duration::from_secs(1),
        Duration::from_millis(10),
        async move {
            let permit = effect_gate.acquire_owned().await.unwrap();
            release_rx.await.unwrap();
            drop(permit);
            Ok(())
        },
        move || -> BoxFuture<'static, Result<bool>> {
            let gate = renewal_gate.clone();
            let owner = renewal_owner.clone();
            let dropped = renewal_dropped.clone();
            let calls = renewal_calls.clone();
            Box::pin(async move {
                let request = owner.renewal_request()?;
                let _marker = RenewalDrop {
                    owner: owner.clone(),
                    dropped,
                };
                calls.fetch_add(1, Ordering::Relaxed);
                let _permit = gate.acquire_owned().await.unwrap();
                request.start()?;
                let entered = request.enter_statement()?;
                request.received(entered, true)?;
                Ok(request.returned(true)?)
            })
        },
    ));
    assert!(futures::poll!(&mut run).is_pending());
    assert_eq!(gate.available_permits(), 0);
    tokio::time::advance(Duration::from_millis(10)).await;
    assert!(futures::poll!(&mut run).is_pending());
    assert_eq!(renewals.load(Ordering::Relaxed), 1);
    release_tx.send(()).unwrap();
    assert!(matches!(
        futures::poll!(&mut run),
        std::task::Poll::Ready(Ok(Some(())))
    ));
    drop(run);
    assert!(dropped.load(Ordering::Relaxed));
    assert_eq!(gate.available_permits(), 1);
    assert!(owner.snapshot().renewal.pending);
    assert_eq!(owner.snapshot().renewal.returned, None);
    assert_eq!(
        owner.snapshot().renewal.knowledge,
        core::RenewalKnowledge::NotEntered
    );
    let closed = owner.close_renewal_scope().unwrap();
    assert!(route
        .returned(core::RouteResult::CompletedByWorker)
        .unwrap()
        .settlement(core::SettlementCommand::Ack, closed)
        .unwrap()
        .is_some());
}

#[tokio::test]
async fn mix_foreground_authenticated_replay_never_starts_membership_or_store_effects() {
    use crate::services::mix::foreground::{fixture, Observation};
    use northstar_room_application::mix::{read_observed, Knowledge, ReadReturned, Rejected, Wake};
    use std::sync::atomic::Ordering;
    for replay in [
        MixBusinessReplay::Replay(Uuid::from_u128(70)),
        MixBusinessReplay::Conflict,
    ] {
        let owner = Observation::new(fixture::prepared(true));
        let request = owner.replay_request().unwrap().unwrap();
        let calls = fixture::Calls::default();
        let result = read_observed(&request, "mix.local.test", async {
            calls.repository.fetch_add(1, Ordering::Relaxed);
            let raw = fixture::existing();
            request.observed_existing(raw.clone())?;
            request.authenticated(&raw, replay)?;
            Ok::<_, anyhow::Error>(replay)
        })
        .await
        .unwrap();
        // A replay/conflict cannot mint the immutable first-execution request.
        // The production source pin separately requires this return before
        // its mutable participant/preference calls.
        if let Ok(store) = owner.store_request(fixture::command(true)) {
            calls.membership.fetch_add(1, Ordering::Relaxed);
            fixture::admit(&store, fixture::Cut::Return, true, &calls)
                .await
                .unwrap();
        }
        assert_eq!(result, replay);
        assert_eq!(calls.repository.load(Ordering::Relaxed), 1);
        assert_eq!(calls.membership.load(Ordering::Relaxed), 0);
        assert_eq!(calls.commit.load(Ordering::Relaxed), 0);
        assert_eq!(calls.wake.load(Ordering::Relaxed), 0);
        assert_eq!(
            owner.snapshot().replay.returned,
            Some(ReadReturned::Outcome(replay))
        );
        assert_eq!(owner.snapshot().knowledge, Knowledge::NoCommitRequested);
        assert_eq!(owner.snapshot().wake, Wake::Unavailable);
        assert!(matches!(
            owner.store_request(fixture::command(true)),
            Err(Rejected::Read)
        ));
    }
}

#[tokio::test]
async fn mix_foreground_raw_existing_survives_cancelled_rollback_without_authenticated_replay() {
    use crate::services::mix::foreground::{fixture, Observation};
    use northstar_room_application::mix::{
        admit_observed, read_observed, Knowledge, Rejected, TerminalReason,
    };
    let owner = Observation::new(fixture::prepared(true));
    let read = owner.replay_request().unwrap().unwrap();
    read_observed(&read, "mix.local.test", async {
        read.observed_miss()?;
        Ok::<_, anyhow::Error>(MixBusinessReplay::Miss)
    })
    .await
    .unwrap();
    let request = owner.store_request(fixture::command(true)).unwrap();
    let raw = fixture::existing();
    let mut effect = Box::pin(admit_observed(&request, "mix.local.test", async {
        request.observed_existing(raw.clone())?;
        // Independent fake rollback completion gate, never resolved here.
        std::future::pending::<()>().await;
        request.authenticated(&raw, MixBusinessReplay::Replay(Uuid::from_u128(70)))?;
        Ok::<_, anyhow::Error>(crate::services::mix::StoreMixMessageAdmission {
            outcome: StoreEventOutcome::Replay(Uuid::from_u128(70)),
            recipients: vec![],
        })
    }));
    assert!(futures::poll!(&mut effect).is_pending());
    drop(effect);
    assert_eq!(owner.snapshot().existing.raw.as_deref(), Some(&raw));
    assert_eq!(owner.snapshot().existing.authenticated, None);
    assert_eq!(owner.snapshot().returned, None);
    assert_eq!(owner.snapshot().knowledge, Knowledge::NoCommitRequested);
    owner.retire(TerminalReason::Cancelled);
    let frozen = owner.snapshot();
    assert_eq!(
        request.authenticated(&raw, MixBusinessReplay::Replay(Uuid::from_u128(70))),
        Err(Rejected::Retired)
    );
    assert_eq!(owner.snapshot(), frozen);
}

#[tokio::test]
async fn mix_foreground_actual_projection_and_receipt_error_have_exclusive_wake_behavior() {
    use crate::services::mix::foreground::{fixture, Observation};
    use northstar_room_application::mix::{Knowledge, Returned, Wake};
    use std::sync::atomic::Ordering;
    for audience in [false, true] {
        let owner = Observation::new(fixture::prepared(false));
        let request = owner.store_request(fixture::command(false)).unwrap();
        let calls = fixture::Calls::default();
        let completion = fixture::admit(&request, fixture::Cut::Return, audience, &calls)
            .await
            .unwrap();
        let (returned, wake) = completion.into_wake(&owner).unwrap();
        assert_eq!(*returned, fixture::returned(audience));
        if let Some(wake) = wake {
            wake.invoke(|| {
                calls.wake.fetch_add(1, Ordering::Relaxed);
            })
            .unwrap();
        }
        assert_eq!(calls.repository.load(Ordering::Relaxed), 1);
        assert_eq!(calls.commit.load(Ordering::Relaxed), 1);
        assert_eq!(calls.wake.load(Ordering::Relaxed), usize::from(audience));
        let Knowledge::ReceiptKnown(fact) = owner.snapshot().knowledge else {
            panic!("missing fresh receipt");
        };
        assert_eq!(fact.authoritative_id, Uuid::from_u128(72));
        assert_eq!(fact.storage_id, Uuid::from_u128(74));
        if let Some(projection) = &fact.projection {
            assert_eq!(projection.recipients[0].delivery_id, Uuid::from_u128(75));
            assert_eq!(projection.recipients[0].sequence, 812);
            assert_eq!(projection.recipients[0].participant.jid, "bob@local.test");
        } else {
            assert!(!audience);
        }
        assert_eq!(
            owner.snapshot().returned,
            Some(Returned::AcceptedStored(Uuid::from_u128(72)))
        );
    }
    let owner = Observation::new(fixture::prepared(false));
    let request = owner.store_request(fixture::command(false)).unwrap();
    let calls = fixture::Calls::default();
    assert!(
        fixture::admit(&request, fixture::Cut::FailAfterReceipt, true, &calls)
            .await
            .is_err()
    );
    assert!(matches!(
        owner.snapshot().knowledge,
        Knowledge::ReceiptKnown(_)
    ));
    assert_eq!(owner.snapshot().returned, Some(Returned::Error));
    assert_eq!(owner.snapshot().wake, Wake::Unavailable);
    assert_eq!(calls.wake.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn mix_foreground_receiving_configuration_rejects_self_consistent_claim_before_effect() {
    use crate::services::mix::foreground::{fixture, Observation, PreparedIngress};
    use northstar_room_application::mix::{read_observed, EffectError, Rejected};
    use std::sync::atomic::Ordering;
    let input = fixture::prepared(true);
    let mut forged = input.ingress().clone();
    forged.channel_jid = "room@mix.attacker.test".into();
    assert!(forged.matches_receiving_domain("mix.attacker.test"));
    let owner = Observation::new(PreparedIngress::new(forged));
    let request = owner.replay_request().unwrap().unwrap();
    let calls = fixture::Calls::default();
    let result = read_observed(&request, "mix.local.test", async {
        calls.repository.fetch_add(1, Ordering::Relaxed);
        request.observed_miss()?;
        Ok::<_, anyhow::Error>(MixBusinessReplay::Miss)
    })
    .await;
    assert!(matches!(
        result,
        Err(EffectError::Observation(Rejected::Input))
    ));
    assert_eq!(calls.repository.load(Ordering::Relaxed), 0);
    assert!(!owner.snapshot().replay.started);
}

#[tokio::test]
async fn mix_foreground_constructed_unpolled_commit_does_not_enter_message_commit() {
    use crate::services::mix::foreground::{fixture, Observation};
    use northstar_room_application::mix::{admit_observed, commit_observed, Knowledge};
    use std::sync::atomic::Ordering;
    let owner = Observation::new(fixture::prepared(false));
    let request = owner.store_request(fixture::command(false)).unwrap();
    let calls = fixture::Calls::default();
    let mut effect = Box::pin(admit_observed(&request, "mix.local.test", async {
        calls.repository.fetch_add(1, Ordering::Relaxed);
        let commit = commit_observed(
            async {
                calls.commit.fetch_add(1, Ordering::Relaxed);
                Ok::<(), anyhow::Error>(())
            },
            &request,
            fixture::stored(true),
        );
        drop(commit);
        std::future::pending::<()>().await;
        Ok::<_, anyhow::Error>(fixture::returned(true))
    }));
    assert!(futures::poll!(&mut effect).is_pending());
    drop(effect);
    assert_eq!(calls.repository.load(Ordering::Relaxed), 1);
    assert_eq!(calls.commit.load(Ordering::Relaxed), 0);
    assert_eq!(owner.snapshot().knowledge, Knowledge::NoCommitRequested);
    assert_eq!(owner.snapshot().returned, None);
}

#[tokio::test]
async fn transferred_mix_source_never_constructs_old_worker_acknowledgement() {
    let completed = finish_mix_delivery_owner(
        ChannelStanzaDeliveryOutcome::TransferredToRecoverableTransport,
        || -> std::future::Ready<Result<bool>> {
            panic!("a transferred lease cannot reach old-worker settlement")
        },
    )
    .await
    .unwrap();
    assert!(completed);
}

#[tokio::test]
async fn worker_owned_mix_source_acknowledges_once_and_preserves_fence_failure() {
    for acknowledged in [true, false] {
        let calls = std::cell::Cell::new(0);
        let result = finish_mix_delivery_owner(
            ChannelStanzaDeliveryOutcome::CompletedByClaimingWorker,
            || {
                calls.set(calls.get() + 1);
                async { Ok(acknowledged) }
            },
        )
        .await
        .unwrap();
        assert_eq!(result, acknowledged);
        assert_eq!(calls.get(), 1);
    }
    let error = finish_mix_delivery_owner(
        ChannelStanzaDeliveryOutcome::CompletedByClaimingWorker,
        || async { anyhow::bail!("injected settlement backend failure") },
    )
    .await
    .unwrap_err();
    assert_eq!(error.to_string(), "injected settlement backend failure");
}

#[tokio::test(start_paused = true)]
async fn pending_mix_acknowledgement_obeys_existing_attempt_deadline() {
    let cancel = tokio_util::sync::CancellationToken::new();
    let deadline = tokio::time::Instant::now() + MIX_OUTBOX_ATTEMPT_DEADLINE;
    let calls = std::cell::Cell::new(0);
    let settlement = finish_mix_delivery_owner(
        ChannelStanzaDeliveryOutcome::CompletedByClaimingWorker,
        || {
            calls.set(calls.get() + 1);
            bounded_mix_outbox_turn(&cancel, deadline, std::future::pending::<Result<bool>>())
        },
    );
    tokio::pin!(settlement);
    assert!(futures::poll!(&mut settlement).is_pending());
    tokio::time::advance(MIX_OUTBOX_ATTEMPT_DEADLINE).await;
    let error = settlement.await.unwrap_err();
    assert!(mix_outbox_deadline_elapsed(&error));
    assert_eq!(calls.get(), 1);
}

#[tokio::test(start_paused = true)]
async fn pending_mix_acknowledgement_obeys_cancellation_without_retry() {
    let cancel = tokio_util::sync::CancellationToken::new();
    let calls = std::cell::Cell::new(0);
    let settlement = finish_mix_delivery_owner(
        ChannelStanzaDeliveryOutcome::CompletedByClaimingWorker,
        || {
            calls.set(calls.get() + 1);
            bounded_mix_outbox_turn(
                &cancel,
                tokio::time::Instant::now() + MIX_OUTBOX_ATTEMPT_DEADLINE,
                std::future::pending::<Result<bool>>(),
            )
        },
    );
    tokio::pin!(settlement);
    assert!(futures::poll!(&mut settlement).is_pending());
    cancel.cancel();
    let error = settlement.await.unwrap_err();
    assert!(mix_outbox_is_shutting_down(&error));
    assert_eq!(calls.get(), 1);
}

#[tokio::test]
async fn sm_and_bosh_mix_handoffs_preserve_typed_transport_owner() {
    for completion in [
        crate::outbound::MixTransportCompletion::SmPersisted {
            session_id: Uuid::from_u128(41),
        },
        crate::outbound::MixTransportCompletion::BoshPersisted {
            session_id: Uuid::from_u128(43),
        },
    ] {
        let source = crate::outbound::MixDelivery {
            delivery_id: Uuid::from_u128(47),
            lease_token: Uuid::from_u128(53),
        };
        let (output, mut consumer) = tokio::sync::mpsc::channel(1);
        let sender = crate::outbound::OutboundSender::new(output);
        let disconnect = tokio_util::sync::CancellationToken::new();
        let mut waiting = Box::pin(try_send_local_durable_mix(
            &sender,
            &disconnect,
            "owned".to_owned(),
            source,
        ));
        assert!(futures::poll!(&mut waiting).is_pending());
        let item = consumer.recv().await.unwrap();
        assert_eq!(item.mix_delivery(), Some(source));
        // Dequeue is insufficient. Only the transport's typed completion
        // resolves the same production waiter used by claimed MIX routing.
        assert!(futures::poll!(&mut waiting).is_pending());
        item.complete_mix_handoff(completion);
        assert_eq!(waiting.await.unwrap(), completion);
        assert!(!disconnect.is_cancelled());
    }
}

#[tokio::test]
async fn delivery_idle_scan_stays_bounded_and_retained_commits_bypass_backoff() {
    let broker = crate::services::mix::MixDeliveryWakeBroker::for_test();
    let mut wake = Some(broker.subscribe());
    let mut now = tokio::time::Instant::now();
    let mut schedule = MixClaimSchedule::starting_at(MixOutboxQueue::Delivery, now);
    assert_eq!(schedule.next_claim, now);
    for delay_ms in [250, 500, 1000, 1000, 1000] {
        schedule.record_claim(now, false);
        assert_eq!(schedule.next_claim - now, Duration::from_millis(delay_ms));
        now = schedule.next_claim;
    }
    // A commit races the worker's next wait. The retained generation must
    // win without waiting for the recovery timer or trusting the payload
    // as permission to deliver; the next step is a fresh database claim.
    now = tokio::time::Instant::now();
    schedule.record_claim(now, false);
    broker.publish_local_commit();
    tokio::select! {
        biased;
        open = wait_for_mix_delivery_wake(&mut wake) => {
            assert!(open);
            schedule.record_progress(now);
        }
        _ = tokio::time::sleep_until(schedule.next_claim) => {
            panic!("retained commit waited for the idle recovery timer")
        }
    }
    assert_eq!(schedule.next_claim, now);
    schedule.record_claim(now, false);
    assert_eq!(schedule.next_claim - now, MixClaimSchedule::BASE_DELAY);
}

#[test]
fn actual_delivery_work_restores_the_fast_claim_cadence() {
    let now = tokio::time::Instant::now();
    let mut schedule = MixClaimSchedule::starting_at(MixOutboxQueue::Delivery, now);
    for _ in 0..5 {
        schedule.record_claim(now, false);
    }
    schedule.record_claim(now, true);
    assert_eq!(schedule.next_claim - now, MixClaimSchedule::BASE_DELAY);
    schedule.record_progress(now);
    assert_eq!(schedule.next_claim, now);
    schedule.record_claim(now, false);
    assert_eq!(schedule.next_claim - now, MixClaimSchedule::BASE_DELAY);
}

#[test]
fn pam_without_a_commit_wake_keeps_its_original_scan_latency() {
    let now = tokio::time::Instant::now();
    let mut schedule = MixClaimSchedule::starting_at(MixOutboxQueue::PamResult, now);
    for _ in 0..100 {
        schedule.record_claim(now, false);
        assert_eq!(schedule.next_claim - now, Duration::from_millis(250));
    }
}

#[tokio::test]
async fn durable_local_mix_delivery_requires_transport_ownership_and_closes_failed_routes() {
    let source = crate::outbound::MixDelivery {
        delivery_id: Uuid::from_u128(1),
        lease_token: Uuid::from_u128(2),
    };

    // Entering the bounded queue is deliberately insufficient: an exact
    // C2S transport must establish its socket fence or persist a typed
    // hand-off. A direct writer cannot report an unfenced write.
    let (output, mut consumer) = tokio::sync::mpsc::channel(1);
    let sender = crate::outbound::OutboundSender::new(output);
    let disconnect = tokio_util::sync::CancellationToken::new();
    let waiter = {
        let sender = sender.clone();
        let disconnect = disconnect.clone();
        tokio::spawn(async move {
            try_send_local_durable_mix(&sender, &disconnect, "owned".to_owned(), source).await
        })
    };
    let item = consumer.recv().await.expect("durable MIX item was queued");
    assert_eq!(item.mix_delivery(), Some(source));
    let socket_fence = crate::outbound::MixTransportCompletion::SocketFenced {
        connection_id: Uuid::from_u128(3),
    };
    item.complete_mix_handoff(socket_fence);
    assert_eq!(
        waiter
            .await
            .expect("ownership waiter must not panic")
            .expect("socket fence must complete the durable hand-off"),
        socket_fence
    );
    assert!(!disconnect.is_cancelled());

    // A full bounded queue must close this transport before another
    // durable retry could overtake its unconfirmed predecessor.
    let (output, _consumer) = tokio::sync::mpsc::channel(1);
    let sender = crate::outbound::OutboundSender::new(output);
    let disconnect = tokio_util::sync::CancellationToken::new();
    sender
        .try_send("older".to_owned())
        .expect("test queue accepts predecessor");
    assert_eq!(
        try_send_local_durable_mix(&sender, &disconnect, "full".to_owned(), source).await,
        Err(MixLocalTransportFailure::QueueFull)
    );
    assert!(disconnect.is_cancelled());

    // A live session object with an already closed output cannot accept a
    // durable row either.
    let (output, consumer) = tokio::sync::mpsc::channel(1);
    drop(consumer);
    let sender = crate::outbound::OutboundSender::new(output);
    let disconnect = tokio_util::sync::CancellationToken::new();
    assert_eq!(
        try_send_local_durable_mix(&sender, &disconnect, "closed".to_owned(), source).await,
        Err(MixLocalTransportFailure::QueueClosed)
    );
    assert!(disconnect.is_cancelled());

    // If an output item disappears before it establishes ownership, the
    // one-shot hand-off closes and the exact transport is rejected.
    let (output, mut consumer) = tokio::sync::mpsc::channel(1);
    let sender = crate::outbound::OutboundSender::new(output);
    let disconnect = tokio_util::sync::CancellationToken::new();
    let waiter = {
        let sender = sender.clone();
        let disconnect = disconnect.clone();
        tokio::spawn(async move {
            try_send_local_durable_mix(&sender, &disconnect, "handoff-closed".to_owned(), source)
                .await
        })
    };
    drop(
        consumer
            .recv()
            .await
            .expect("receipt-close MIX item was queued"),
    );
    assert_eq!(
        waiter.await.expect("handoff waiter must not panic"),
        Err(MixLocalTransportFailure::HandoffClosed)
    );
    assert!(disconnect.is_cancelled());

    // Dropping a waiter after the item was dequeued also closes the exact
    // transport. This is what makes the outbox deadline/cancellation safe
    // without relying on a synthetic short receipt timeout.
    let (output, mut consumer) = tokio::sync::mpsc::channel(1);
    let sender = crate::outbound::OutboundSender::new(output);
    let disconnect = tokio_util::sync::CancellationToken::new();
    let waiter = {
        let sender = sender.clone();
        let disconnect = disconnect.clone();
        tokio::spawn(async move {
            try_send_local_durable_mix(&sender, &disconnect, "cancelled".to_owned(), source).await
        })
    };
    let late = consumer
        .recv()
        .await
        .expect("cancelled MIX item was queued");
    waiter.abort();
    let _ = waiter.await;
    assert!(disconnect.is_cancelled());
    drop(late);
}

#[test]
fn mix_maintenance_starts_after_the_first_foreground_claim_window() {
    let start = tokio::time::Instant::now();
    let schedule = MixMaintenanceSchedule::starting_at(start);
    // MX01: a committed delivery can be claimed before the first retention
    // page is due; the worker does not begin with maintenance.
    assert!(!schedule.due(start));
    assert!(schedule.next_deadline > start);
}

#[test]
fn mix_maintenance_runs_only_at_its_fixed_deadline() {
    let start = tokio::time::Instant::now();
    let schedule = MixMaintenanceSchedule::starting_at(start);
    // MX02: ordinary wakes do not make a future maintenance page due.
    assert!(!schedule.due(schedule.next_deadline - Duration::from_nanos(1)));
    assert!(schedule.due(schedule.next_deadline));
}

#[test]
fn mix_maintenance_deadline_is_not_reset_by_foreground_work() {
    let start = tokio::time::Instant::now();
    let schedule = MixMaintenanceSchedule::starting_at(start);
    let original_deadline = schedule.next_deadline;
    // MX03: a busy delivery wake may change next_claim, but it has no
    // authority to mutate this lifecycle-owned maintenance deadline.
    for _ in 0..1_000 {
        assert_eq!(schedule.next_deadline, original_deadline);
    }
    assert!(schedule.due(original_deadline));
}

#[test]
fn mix_maintenance_skips_missed_ticks_and_yields_between_pages() {
    let start = tokio::time::Instant::now();
    let mut schedule = MixMaintenanceSchedule::starting_at(start);
    let delayed_completion = schedule.next_deadline + Duration::from_secs(300);
    assert!(schedule.due(delayed_completion));
    schedule.record_completed_page(delayed_completion);
    // MX04/MX12: one delayed page creates one future deadline, not a
    // catch-up burst. A multi-page backlog therefore yields between pages.
    assert_eq!(
        schedule.next_deadline,
        delayed_completion + MIX_OUTBOX_MAINTENANCE_INTERVAL
    );
    assert!(!schedule.due(delayed_completion));
}

#[tokio::test]
async fn maintenance_wait_continues_polling_claimed_work_that_releases_it() {
    let (release_maintenance, maintenance_released) = tokio::sync::oneshot::channel();
    let mut in_flight = FuturesUnordered::<MixOutboxTask>::new();
    in_flight.push(Box::pin(async move {
        release_maintenance
            .send(())
            .expect("maintenance receiver must still be present");
        (MixOutboxQueue::Delivery, Ok(()))
    }));
    let mut maintenance: Option<MixOutboxMaintenanceTask> = Some(Box::pin(async move {
        maintenance_released
            .await
            .expect("claimed work must release maintenance");
        Ok(())
    }));
    let mut claim: Option<MixOutboxClaimTask> = None;

    // MX12: the maintenance future is pending until the claimed future
    // runs. If the worker awaited maintenance outside the shared poll,
    // this controlled dependency would never make progress.
    assert!(matches!(
        next_mix_outbox_progress(&mut in_flight, &mut claim, &mut maintenance).await,
        MixOutboxProgress::InFlight(MixOutboxQueue::Delivery, Ok(()))
    ));
    assert!(matches!(
        next_mix_outbox_progress(&mut in_flight, &mut claim, &mut maintenance).await,
        MixOutboxProgress::Maintenance(Ok(()))
    ));
    assert!(maintenance.is_none());
}

#[tokio::test]
async fn pending_claim_continues_polling_claimed_work_that_releases_it() {
    let (release_claim, claim_released) = tokio::sync::oneshot::channel();
    let mut in_flight = FuturesUnordered::<MixOutboxTask>::new();
    in_flight.push(Box::pin(async move {
        release_claim
            .send(())
            .expect("claim receiver must still be present");
        (MixOutboxQueue::Delivery, Ok(()))
    }));
    let mut claim: Option<MixOutboxClaimTask> = Some(Box::pin(async move {
        claim_released
            .await
            .expect("claimed work must release foreground claim");
        Ok(Vec::new())
    }));
    let mut maintenance: Option<MixOutboxMaintenanceTask> = None;

    // MX13: a database/pool wait while claiming more work must not park a
    // row already leased by this lane. The claimed row makes progress
    // first, releases the wait, and then the same shared poll completes
    // the foreground claim without changing cancellation or lease rules.
    assert!(matches!(
        next_mix_outbox_progress(&mut in_flight, &mut claim, &mut maintenance).await,
        MixOutboxProgress::InFlight(MixOutboxQueue::Delivery, Ok(()))
    ));
    assert!(matches!(
        next_mix_outbox_progress(&mut in_flight, &mut claim, &mut maintenance).await,
        MixOutboxProgress::Claim(Ok(claimed)) if claimed.is_empty()
    ));
    assert!(claim.is_none());
}

#[tokio::test]
async fn stopped_mix_lane_does_not_issue_another_claim() {
    let stop_claiming = tokio_util::sync::CancellationToken::new();
    let cancel = tokio_util::sync::CancellationToken::new();
    stop_claiming.cancel();
    let claimed = drainable_mix_outbox_claim::<Uuid>(&stop_claiming, &cancel, async {
        anyhow::bail!("shutdown must not poll a new database claim")
    })
    .await
    .expect("an unstarted claim has no lease to recover");
    assert!(claimed.is_empty());
}

#[tokio::test]
async fn graceful_stop_recovers_a_committed_mix_claim_response() {
    let stop_claiming = tokio_util::sync::CancellationToken::new();
    let cancel = tokio_util::sync::CancellationToken::new();
    let token = Uuid::new_v4();
    let (committed_tx, committed_rx) = tokio::sync::oneshot::channel();
    let (response_tx, response_rx) = tokio::sync::oneshot::channel();
    let task_stop = stop_claiming.clone();
    let task = tokio::spawn(async move {
        drainable_mix_outbox_claim(&task_stop, &cancel, async move {
            // The database has committed this exact token, but the
            // response has not reached the lane when shutdown starts.
            committed_tx.send(()).unwrap();
            response_rx.await.unwrap();
            Ok(vec![token])
        })
        .await
    });
    committed_rx.await.unwrap();
    stop_claiming.cancel();
    response_tx.send(()).unwrap();
    let claimed = tokio::time::timeout(Duration::from_secs(1), task)
        .await
        .expect("graceful stop must continue polling the bounded claim")
        .unwrap()
        .expect("a committed response must not be discarded by admission shutdown");
    assert_eq!(claimed, vec![token]);
}

#[tokio::test]
async fn hard_cancel_still_discards_an_unknown_mix_claim_response() {
    let stop_claiming = tokio_util::sync::CancellationToken::new();
    let cancel = tokio_util::sync::CancellationToken::new();
    let task_cancel = cancel.clone();
    let (committed_tx, committed_rx) = tokio::sync::oneshot::channel();
    let (response_tx, response_rx) = tokio::sync::oneshot::channel::<()>();
    let task = tokio::spawn(async move {
        drainable_mix_outbox_claim(&stop_claiming, &task_cancel, async move {
            committed_tx.send(()).unwrap();
            response_rx.await.unwrap();
            Ok(vec![Uuid::new_v4()])
        })
        .await
    });
    committed_rx.await.unwrap();
    cancel.cancel();
    let error = tokio::time::timeout(Duration::from_secs(1), task)
        .await
        .expect("hard cancellation must still bound an uncertain claim")
        .unwrap()
        .expect_err("an unknown committed token must remain for durable lease recovery");
    assert!(mix_outbox_is_shutting_down(&error));
    assert!(
        response_tx.send(()).is_err(),
        "pending response future was not dropped"
    );
}

#[tokio::test]
async fn graceful_empty_pam_lane_preserves_delivery_claim_and_effect_drain() {
    let stop_claiming = tokio_util::sync::CancellationToken::new();
    let cancel = tokio_util::sync::CancellationToken::new();
    let delivery_stop = stop_claiming.clone();
    let delivery_cancel = cancel.clone();
    let pam_stop = stop_claiming.clone();
    let (committed_tx, committed_rx) = tokio::sync::oneshot::channel();
    let (pam_stopped_tx, pam_stopped_rx) = tokio::sync::oneshot::channel();
    let (response_tx, response_rx) = tokio::sync::oneshot::channel();
    let token = Uuid::new_v4();
    let joined = tokio::spawn(async move {
        join_mix_outbox_lanes(
            stop_claiming,
            cancel,
            async move {
                let claimed =
                    drainable_mix_outbox_claim(&delivery_stop, &delivery_cancel, async move {
                        committed_tx.send(()).unwrap();
                        response_rx.await.unwrap();
                        Ok(vec![token])
                    })
                    .await?;
                assert_eq!(claimed, vec![token]);
                let deadline = tokio::time::Instant::now() + MIX_OUTBOX_ATTEMPT_DEADLINE;
                let outcome = run_claimed_mix_effect_with_lease(
                    delivery_cancel.clone(),
                    deadline,
                    MIX_OUTBOX_LEASE_RENEWAL_INTERVAL,
                    async { Ok(token) },
                    || Box::pin(async { panic!("immediate work needs no renewal") }),
                )
                .await?;
                assert_eq!(outcome, Some(token));
                // The final acknowledgement/defer database turn uses
                // the same exact token and original attempt deadline.
                let finalized =
                    bounded_mix_outbox_turn(&delivery_cancel, deadline, async { Ok(token) })
                        .await?;
                assert_eq!(finalized, token);
                Ok(())
            },
            async move {
                committed_rx.await.unwrap();
                pam_stop.cancel();
                pam_stopped_tx.send(()).unwrap();
                Ok(())
            },
        )
        .await
    });
    pam_stopped_rx.await.unwrap();
    response_tx.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(1), joined)
        .await
        .expect("an empty stopped PAM lane must not strand the delivery lane")
        .unwrap()
        .expect("normal shutdown must preserve the delivery lane's hard-cancel token");
}

#[test]
fn mix_outbox_lane_budgets_preserve_the_pam_window() {
    assert_eq!(mix_outbox_lane_budgets(1), (1, 1));
    assert_eq!(mix_outbox_lane_budgets(16), (16, 2));
}

#[test]
fn durable_mix_no_live_route_is_parked_with_or_without_an_archive_projection() {
    for archive_projection_present in [false, true] {
        assert_eq!(
            classify_durable_mix_route(
                archive_projection_present,
                false,
                DurableMixRouteAvailability::NoTarget,
                false,
            ),
            DurableMixRouteDisposition::Park,
            "a MAM projection is not a live delivery acknowledgement",
        );
    }
}

#[test]
fn durable_mix_unknown_or_unsupported_route_is_parked_without_an_age_cutoff() {
    // The classifier intentionally has no age input: a route that is
    // still unknown after a delayed caps discovery remains recoverable
    // until the database delivery expiry, not an arbitrary 30-second
    // capability timer.
    for availability in [
        DurableMixRouteAvailability::UnknownCapability,
        DurableMixRouteAvailability::Unsupported,
    ] {
        assert_eq!(
            classify_durable_mix_route(false, false, availability, false),
            DurableMixRouteDisposition::Park,
        );
    }
}

#[test]
fn durable_mix_route_preserves_accepted_and_real_failure_paths() {
    assert_eq!(
        classify_durable_mix_route(false, true, DurableMixRouteAvailability::Deliverable, false,),
        DurableMixRouteDisposition::Accepted,
    );
    assert_eq!(
        classify_durable_mix_route(
            false,
            false,
            DurableMixRouteAvailability::Deliverable,
            false,
        ),
        DurableMixRouteDisposition::RetryDeliverable,
    );
    assert_eq!(
        classify_durable_mix_route(false, false, DurableMixRouteAvailability::NoTarget, true,),
        DurableMixRouteDisposition::RetryCluster,
    );
}

#[tokio::test]
async fn pam_lane_starts_while_a_delivery_lane_waits_on_external_io() {
    let (delivery_started_tx, delivery_started_rx) = tokio::sync::oneshot::channel();
    let (release_delivery_tx, release_delivery_rx) = tokio::sync::oneshot::channel();
    let (pam_started_tx, pam_started_rx) = tokio::sync::oneshot::channel();
    let lane_cancel = tokio_util::sync::CancellationToken::new();
    let joined = tokio::spawn(async move {
        join_mix_outbox_lanes(
            tokio_util::sync::CancellationToken::new(),
            lane_cancel,
            async move {
                let _ = delivery_started_tx.send(());
                let _ = release_delivery_rx.await;
                Ok(())
            },
            async move {
                let _ = pam_started_tx.send(());
                Ok(())
            },
        )
        .await
    });

    delivery_started_rx.await.unwrap();
    // The delivery is deliberately held until after this assertion, so
    // the bounded wait only permits ordinary CI scheduler latency; it
    // cannot mask a return to serial delivery-then-PAM execution.
    tokio::time::timeout(Duration::from_secs(1), pam_started_rx)
        .await
        .expect("PAM lane must start before a slow delivery is released")
        .unwrap();
    release_delivery_tx.send(()).unwrap();
    assert!(joined.await.unwrap().is_ok());
}

#[tokio::test]
async fn failed_mix_outbox_lane_cancels_and_drains_its_peer() {
    let lane_cancel = tokio_util::sync::CancellationToken::new();
    let peer_cancel = lane_cancel.clone();
    let (peer_started_tx, peer_started_rx) = tokio::sync::oneshot::channel();
    let (peer_drained_tx, peer_drained_rx) = tokio::sync::oneshot::channel();
    let result = tokio::time::timeout(
        Duration::from_secs(1),
        join_mix_outbox_lanes(
            tokio_util::sync::CancellationToken::new(),
            lane_cancel,
            async move {
                peer_started_rx
                    .await
                    .expect("peer lane must begin before the failure");
                anyhow::bail!("injected MIX delivery lane failure")
            },
            async move {
                let _ = peer_started_tx.send(());
                peer_cancel.cancelled().await;
                let _ = peer_drained_tx.send(());
                Ok(())
            },
        ),
    )
    .await
    .expect("failed lane must not wait forever for its continuous peer");
    assert!(result.is_err());
    peer_drained_rx
        .await
        .expect("peer must observe cancellation before join returns");
}

#[test]
fn verified_mix_presence_requires_the_exact_live_resource_epoch() {
    let expected = Uuid::new_v4();
    assert!(mix_presence_epoch_is_current(
        expected, expected, 7, 7, true, true, true
    ));
    assert!(!mix_presence_epoch_is_current(
        Uuid::new_v4(),
        expected,
        7,
        7,
        true,
        true,
        true
    ));
    assert!(!mix_presence_epoch_is_current(
        expected, expected, 8, 7, true, true, true
    ));
    assert!(!mix_presence_epoch_is_current(
        expected, expected, 7, 7, false, true, true
    ));
    assert!(!mix_presence_epoch_is_current(
        expected, expected, 7, 7, true, false, true
    ));
    assert!(!mix_presence_epoch_is_current(
        expected, expected, 7, 7, true, true, false
    ));
}

#[test]
fn directed_mix_unavailable_suppresses_only_its_channel() {
    let suppressed = dashmap::DashSet::new();
    suppressed.insert("one@mix.example.test".to_owned());
    assert!(mix_presence_fallback_is_suppressed(
        &suppressed,
        "one@mix.example.test"
    ));
    assert!(!mix_presence_fallback_is_suppressed(
        &suppressed,
        "two@mix.example.test"
    ));
    suppressed.insert("*".to_owned());
    assert!(mix_presence_fallback_is_suppressed(
        &suppressed,
        "two@mix.example.test"
    ));
}

#[test]
fn broadcast_unavailable_never_depends_on_a_remaining_caps_mapping() {
    assert_eq!(
        mix_broadcast_presence_action("unavailable", MixSessionCapability::Unknown),
        MixBroadcastPresenceAction::Retract
    );
    assert_eq!(
        mix_broadcast_presence_action("unavailable", MixSessionCapability::Unsupported),
        MixBroadcastPresenceAction::Retract
    );
    assert_eq!(
        mix_broadcast_presence_action("available", MixSessionCapability::Unknown),
        MixBroadcastPresenceAction::Retract
    );
    assert_eq!(
        mix_broadcast_presence_action("available", MixSessionCapability::Supported),
        MixBroadcastPresenceAction::Publish
    );
}

#[tokio::test]
async fn cancellation_preempts_a_pending_mix_outbox_database_turn() {
    let cancel = tokio_util::sync::CancellationToken::new();
    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    let task_cancel = cancel.clone();
    let task = tokio::spawn(async move {
        cancellable_mix_outbox_turn(&task_cancel, async move {
            let _ = started_tx.send(());
            std::future::pending::<Result<()>>().await
        })
        .await
    });

    started_rx.await.unwrap();
    cancel.cancel();
    let error = tokio::time::timeout(Duration::from_secs(1), task)
        .await
        .expect("cancellation must preempt a pending semaphore or database turn")
        .expect("test task must not panic")
        .expect_err("pending turn must report cancellation");
    assert!(mix_outbox_is_shutting_down(&error));
}

#[tokio::test]
async fn claimed_mix_renewal_never_pauses_an_effect_holding_the_outbox_gate() {
    let gate = Arc::new(tokio::sync::Semaphore::new(1));
    let (effect_started_tx, effect_started_rx) = tokio::sync::oneshot::channel();
    let (renewal_started_tx, renewal_started_rx) = tokio::sync::oneshot::channel();
    let (release_effect_tx, release_effect_rx) = tokio::sync::oneshot::channel();
    let effect_gate = Arc::clone(&gate);
    let renewal_gate = Arc::clone(&gate);
    let mut renewal_started_tx = Some(renewal_started_tx);

    let task = tokio::spawn(async move {
        run_claimed_mix_effect_with_lease(
            tokio_util::sync::CancellationToken::new(),
            tokio::time::Instant::now() + Duration::from_secs(1),
            Duration::from_millis(10),
            async move {
                let permit = effect_gate
                    .acquire_owned()
                    .await
                    .expect("test gate remains open");
                let _ = effect_started_tx.send(());
                release_effect_rx
                    .await
                    .expect("test releases the effect after renewal starts");
                drop(permit);
                Ok(())
            },
            move || -> BoxFuture<'static, Result<bool>> {
                let gate = Arc::clone(&renewal_gate);
                let started = renewal_started_tx.take();
                Box::pin(async move {
                    if let Some(started) = started {
                        let _ = started.send(());
                    }
                    let _permit = gate.acquire_owned().await.expect("test gate remains open");
                    Ok(true)
                })
            },
        )
        .await
    });

    effect_started_rx
        .await
        .expect("effect must acquire the single permit");
    tokio::time::timeout(Duration::from_secs(1), renewal_started_rx)
        .await
        .expect("delayed renewal must be scheduled")
        .expect("renewal future must begin waiting for the same permit");
    release_effect_tx
        .send(())
        .expect("effect remains pending until released");

    let result = tokio::time::timeout(Duration::from_secs(1), task)
        .await
        .expect("effect must remain pollable while renewal waits")
        .expect("test task must not panic");
    assert!(matches!(result, Ok(Some(()))));
    assert_eq!(gate.available_permits(), 1);
}

#[tokio::test]
async fn claimed_mix_deadline_drops_a_pending_renewal_and_releases_the_gate() {
    let gate = Arc::new(tokio::sync::Semaphore::new(1));
    let (effect_started_tx, effect_started_rx) = tokio::sync::oneshot::channel();
    let (renewal_started_tx, renewal_started_rx) = tokio::sync::oneshot::channel();
    let effect_gate = Arc::clone(&gate);
    let renewal_gate = Arc::clone(&gate);
    let mut renewal_started_tx = Some(renewal_started_tx);

    let task = tokio::spawn(async move {
        run_claimed_mix_effect_with_lease(
            tokio_util::sync::CancellationToken::new(),
            tokio::time::Instant::now() + Duration::from_millis(80),
            Duration::from_millis(10),
            async move {
                let _permit = effect_gate
                    .acquire_owned()
                    .await
                    .expect("test gate remains open");
                let _ = effect_started_tx.send(());
                std::future::pending::<Result<()>>().await
            },
            move || -> BoxFuture<'static, Result<bool>> {
                let gate = Arc::clone(&renewal_gate);
                let started = renewal_started_tx.take();
                Box::pin(async move {
                    if let Some(started) = started {
                        let _ = started.send(());
                    }
                    let _permit = gate.acquire_owned().await.expect("test gate remains open");
                    Ok(true)
                })
            },
        )
        .await
    });

    effect_started_rx
        .await
        .expect("effect must acquire the single permit");
    tokio::time::timeout(Duration::from_secs(1), renewal_started_rx)
        .await
        .expect("renewal must be scheduled before the absolute deadline")
        .expect("renewal future must begin waiting for the same permit");

    let error = tokio::time::timeout(Duration::from_secs(1), task)
        .await
        .expect("absolute deadline must remain pollable during renewal")
        .expect("test task must not panic")
        .expect_err("pending effect must report its claimed deadline");
    assert!(mix_outbox_deadline_elapsed(&error));
    assert_eq!(gate.available_permits(), 1);
}

#[tokio::test]
async fn claimed_mix_cancellation_drops_a_pending_renewal_and_releases_the_gate() {
    let cancel = tokio_util::sync::CancellationToken::new();
    let gate = Arc::new(tokio::sync::Semaphore::new(1));
    let (effect_started_tx, effect_started_rx) = tokio::sync::oneshot::channel();
    let (renewal_started_tx, renewal_started_rx) = tokio::sync::oneshot::channel();
    let effect_gate = Arc::clone(&gate);
    let renewal_gate = Arc::clone(&gate);
    let task_cancel = cancel.clone();
    let mut renewal_started_tx = Some(renewal_started_tx);

    let task = tokio::spawn(async move {
        run_claimed_mix_effect_with_lease(
            task_cancel,
            tokio::time::Instant::now() + Duration::from_secs(1),
            Duration::from_millis(10),
            async move {
                let _permit = effect_gate
                    .acquire_owned()
                    .await
                    .expect("test gate remains open");
                let _ = effect_started_tx.send(());
                std::future::pending::<Result<()>>().await
            },
            move || -> BoxFuture<'static, Result<bool>> {
                let gate = Arc::clone(&renewal_gate);
                let started = renewal_started_tx.take();
                Box::pin(async move {
                    if let Some(started) = started {
                        let _ = started.send(());
                    }
                    let _permit = gate.acquire_owned().await.expect("test gate remains open");
                    Ok(true)
                })
            },
        )
        .await
    });

    effect_started_rx
        .await
        .expect("effect must acquire the single permit");
    tokio::time::timeout(Duration::from_secs(1), renewal_started_rx)
        .await
        .expect("renewal must be scheduled")
        .expect("renewal future must begin waiting for the same permit");
    cancel.cancel();

    let error = tokio::time::timeout(Duration::from_secs(1), task)
        .await
        .expect("cancellation must remain pollable during renewal")
        .expect("test task must not panic")
        .expect_err("pending effect must report cancellation");
    assert!(mix_outbox_is_shutting_down(&error));
    assert_eq!(gate.available_permits(), 1);
}

#[tokio::test]
async fn claimed_mix_final_database_turn_honors_the_shared_deadline() {
    let cancel = tokio_util::sync::CancellationToken::new();
    let error = bounded_mix_outbox_turn(
        &cancel,
        tokio::time::Instant::now() + Duration::from_millis(20),
        std::future::pending::<Result<()>>(),
    )
    .await
    .expect_err("pending finalization must not outlive the claimed deadline");
    assert!(mix_outbox_deadline_elapsed(&error));
}

#[test]
fn replay_commitments_are_stable_and_purpose_separated() {
    let target = Uuid::parse_str("00112233-4455-6677-8899-aabbccddeeff").unwrap();
    let first = mix_replay_semantics(
        "retraction",
        "alice@example.test",
        "room@mix.example.test",
        Some(target),
        "",
    );
    let retry = mix_replay_semantics(
        "retraction",
        "alice@example.test",
        "room@mix.example.test",
        Some(target),
        "",
    );
    let message = mix_replay_semantics(
        "message",
        "alice@example.test",
        "room@mix.example.test",
        Some(target),
        "",
    );
    assert_eq!(first, retry);
    assert_ne!(first, message);
}

#[test]
fn only_state_changing_federated_iqs_enter_result_replay() {
    let ping = parse_iq("<iq type='get' id='p'><ping xmlns='urn:xmpp:ping'/></iq>")
        .unwrap()
        .unwrap();
    let leave = parse_iq("<iq type='set' id='l'><leave xmlns='urn:xmpp:mix:core:1'/></iq>")
        .unwrap()
        .unwrap();
    assert!(!federated_mix_iq_is_mutation(&ping));
    assert!(federated_mix_iq_is_mutation(&leave));
}

fn relay_stage(seed: usize) -> MixIqRelayStage {
    MixIqRelayStage::Participant {
        requester_full_jid: format!("alice@example.test/{seed}"),
        original_id: format!("original-{seed}"),
        expected_from: "channel@mix.example.test".to_owned(),
        channel_jid: "channel@mix.example.test".to_owned(),
    }
}

#[test]
fn mix_iq_relay_admission_is_concurrently_hard_bounded() {
    let limit = 8;
    let workers = 64;
    let index = Arc::new(MixIqRelayIndex::with_limits(limit, Duration::from_secs(30)));
    let barrier = Arc::new(std::sync::Barrier::new(workers));
    let mut threads = Vec::new();
    for seed in 0..workers {
        let index = Arc::clone(&index);
        let barrier = Arc::clone(&barrier);
        threads.push(std::thread::spawn(move || {
            barrier.wait();
            index.admit(format!("relay-{seed}"), relay_stage(seed), Instant::now())
        }));
    }
    let admitted = threads
        .into_iter()
        .map(|thread| thread.join().expect("MIX relay worker panicked"))
        .filter(|admitted| *admitted)
        .count();
    assert_eq!(admitted, limit);
    assert_eq!(index.len(), limit);
}

#[test]
fn mix_iq_relay_expiry_has_one_exact_consumer() {
    let index = MixIqRelayIndex::with_limits(2, Duration::ZERO);
    assert!(index.admit("relay".to_owned(), relay_stage(1), Instant::now()));
    assert_eq!(index.take_expired(Instant::now()).len(), 1);
    assert!(index.take_expired(Instant::now()).is_empty());
    assert_eq!(index.len(), 0);
}

#[test]
fn mix_iq_relay_response_and_expiry_cannot_both_claim_one_id() {
    let index = Arc::new(MixIqRelayIndex::with_limits(2, Duration::ZERO));
    assert!(index.admit("relay".to_owned(), relay_stage(1), Instant::now()));
    let barrier = Arc::new(std::sync::Barrier::new(2));
    let response_index = Arc::clone(&index);
    let response_barrier = Arc::clone(&barrier);
    let response = std::thread::spawn(move || {
        response_barrier.wait();
        response_index.remove("relay").is_some()
    });
    barrier.wait();
    let expired = index.take_expired(Instant::now()).len();
    let responded = response.join().expect("MIX response worker panicked");
    assert_eq!(expired + usize::from(responded), 1);
    assert!(index.is_empty());
}

#[test]
fn parses_pam_join_without_default_subscriptions() {
    let request = parse_iq("<iq type='set' id='j1' from='a@example.test/r' to='a@example.test'><client-join xmlns='urn:xmpp:mix:pam:2' channel='c@mix.example.test'><join xmlns='urn:xmpp:mix:core:1'><nick>A</nick></join></client-join></iq>").unwrap().unwrap();
    let IqOperation::PamJoin { channel, join } = request.operation else {
        panic!("wrong operation")
    };
    assert_eq!(channel, "c@mix.example.test");
    assert!(join.nodes.is_empty());
    assert_eq!(join.nick.as_deref(), Some("A"));
}

#[test]
fn mix_anon_join_uses_exact_preferences_and_returns_every_supported_value() {
    let request = parse_iq("<iq type='set' id='anon'><join xmlns='urn:xmpp:mix:anon:0'><subscribe node='urn:xmpp:mix:nodes:messages'/><x xmlns='jabber:x:data' type='submit'><field var='FORM_TYPE'><value>urn:xmpp:mix:anon:0</value></field><field var='JID Visibility'><value>prefer not</value></field><field var='Presence'><value>not share</value></field></x></join></iq>").unwrap().unwrap();
    let IqOperation::Join(join) = request.operation else {
        panic!("MIX-ANON join was not parsed")
    };
    assert!(join.anonymous_profile);
    let preference = join.preference.unwrap();
    assert_eq!(preference.jid_visibility, "prefer not");
    assert_eq!(preference.private_messages, "allow");
    assert_eq!(preference.vcard, "block");
    assert!(!preference.share_presence);
    let participant = MixParticipant {
        participant_id: Uuid::nil(),
        jid: "alice@example.test".to_owned(),
        nick: Some("Alice".to_owned()),
    };
    let response = core_join_payload(&participant, &join.nodes, Some(&preference), true).unwrap();
    assert!(response.contains("xmlns='urn:xmpp:mix:anon:0'"));
    for value in ["prefer not", "allow", "block", "not share"] {
        assert!(response.contains(&format!("<value>{value}</value>")));
    }
}

#[test]
fn mix_private_messages_strip_forged_identity_and_never_accept_groupchat() {
    let (children, encrypted, kind) = private_message_children("<message type='chat'><body>secret</body><mix xmlns='urn:xmpp:mix:core:1'><jid>mallory@example.test</jid></mix><stanza-id xmlns='urn:xmpp:sid:0' id='forged'/></message>").unwrap();
    assert_eq!(kind, "chat");
    assert!(children.contains("secret"));
    assert!(!children.contains("mallory"));
    assert!(!children.contains("forged"));
    assert!(!encrypted);
    assert!(private_message_children(
        "<message type='groupchat'><body>not private</body></message>"
    )
    .is_err());
}

#[test]
fn mix_misc_retraction_is_canonical_bodyless_and_unambiguous() {
    let target = Uuid::new_v4();
    let valid_xml = format!(
        "<message type='groupchat'><retract xmlns='urn:xmpp:mix:misc:0' id='{target}'/></message>"
    );
    let valid = Document::parse(&valid_xml).unwrap();
    assert_eq!(
        mix_retraction_target(valid.root_element()).unwrap(),
        Some(target)
    );
    for invalid in [
        format!(
            "<message><body>x</body><retract xmlns='urn:xmpp:mix:misc:0' id='{target}'/></message>"
        ),
        format!(
            "<message><retract xmlns='urn:xmpp:mix:misc:0' id='{target}'/><retract xmlns='urn:xmpp:mix:misc:0' id='{target}'/></message>"
        ),
        "<message><retract xmlns='urn:xmpp:mix:misc:0' id='not-a-uuid'/></message>".to_owned(),
    ] {
        let invalid = Document::parse(&invalid).unwrap();
        assert!(mix_retraction_target(invalid.root_element()).is_err());
    }
}

#[test]
fn rejects_unknown_or_duplicate_form_fields() {
    assert!(parse_iq("<iq type='set' id='form1'><pubsub xmlns='http://jabber.org/protocol/pubsub'><publish node='urn:xmpp:mix:nodes:info'><item><x xmlns='jabber:x:data' type='submit'><field var='Name'><value>A</value></field><field var='Name'><value>B</value></field></x></item></publish></pubsub></iq>").is_err());
}

#[test]
fn strict_iq_shape_rejects_ambiguous_or_nested_payloads() {
    assert!(parse_iq("<iq type='set' id='two'><join xmlns='urn:xmpp:mix:core:1'/><leave xmlns='urn:xmpp:mix:core:1'/></iq>").is_err());
    assert!(parse_iq("<iq type='set' id='leave'><client-leave xmlns='urn:xmpp:mix:pam:2' channel='c@mix.example.test'/></iq>").is_err());
    assert!(parse_iq("<iq type='set' id='nick'><join xmlns='urn:xmpp:mix:core:1'><nick>A</nick><nick>B</nick></join></iq>").is_err());
    assert!(parse_iq("<iq type='get' id='max'><pubsub xmlns='http://jabber.org/protocol/pubsub'><items node='urn:xmpp:mix:nodes:participants' max_items='NaN'/></pubsub></iq>").is_err());
    assert!(parse_iq("<iq type='set' id='retract'><pubsub xmlns='http://jabber.org/protocol/pubsub'><retract node='urn:xmpp:mix:nodes:banned'><unexpected/><item id='a@example.test'/></retract></pubsub></iq>").is_err());
}

#[test]
fn mix_routing_does_not_intercept_general_pubsub_requests() {
    let general_pubsub = "<iq type='set' id='p1' to='pubsub.example.test'><pubsub xmlns='http://jabber.org/protocol/pubsub'><create node='managed'/><configure/></pubsub></iq>";
    assert!(!mix_iq_route_candidate(general_pubsub, "mix.example.test"));

    let mix_pubsub = "<iq type='get' id='m1' to='channel@mix.example.test'><pubsub xmlns='http://jabber.org/protocol/pubsub'><items node='urn:xmpp:mix:nodes:messages'/></pubsub></iq>";
    assert!(mix_iq_route_candidate(mix_pubsub, "mix.example.test"));

    let pam = "<iq type='set' id='j1' to='alice@example.test'><client-join xmlns='urn:xmpp:mix:pam:2' channel='channel@mix.remote.test'><join xmlns='urn:xmpp:mix:core:1'/></client-join></iq>";
    assert!(mix_iq_route_candidate(pam, "mix.example.test"));
}

#[test]
fn mix_mam_uses_the_standard_extended_query_model() {
    let request = parse_iq("<iq type='set' id='m1' to='room@mix.example.test'><query xmlns='urn:xmpp:mam:2' queryid='sync'><x xmlns='jabber:x:data' type='submit'><field var='FORM_TYPE' type='hidden'><value>urn:xmpp:mam:2</value></field><field var='with' type='jid-single'><value>alice@example.test</value></field><field var='start'><value>2026-01-01T00:00:00Z</value></field></x><set xmlns='http://jabber.org/protocol/rsm'><max>25</max><before/></set><flip-page xmlns='urn:xmpp:mam:2'/></query></iq>").unwrap().unwrap();
    let IqOperation::Mam(parsed) = request.operation else {
        panic!("MIX MAM query was not parsed");
    };
    assert_eq!(parsed.query.with_jid.as_deref(), Some("alice@example.test"));
    assert_eq!(parsed.query.max, 25);
    assert_eq!(
        MamArchiveQuery::from(parsed.query.clone()).page,
        MamRsmPage::Last
    );
    assert_eq!(parsed.query.start.unwrap().timestamp(), 1_767_225_600);
    assert_eq!(parsed.query_id.as_deref(), Some("sync"));
    assert!(parsed.flip_page);

    let malformed = parse_iq("<iq type='set' id='m2' to='room@mix.example.test'><query xmlns='urn:xmpp:mam:2'><set xmlns='http://jabber.org/protocol/rsm'><max>NaN</max></set></query></iq>").unwrap().unwrap();
    assert!(matches!(
        malformed.operation,
        IqOperation::MamError("bad-request")
    ));
}

#[test]
fn mix_mam_form_and_metadata_require_empty_get_payloads() {
    let form = parse_iq(
        "<iq type='get' id='f1' to='room@mix.example.test'><query xmlns='urn:xmpp:mam:2'/></iq>",
    )
    .unwrap()
    .unwrap();
    assert!(matches!(form.operation, IqOperation::MamForm));
    let metadata = parse_iq(
        "<iq type='get' id='f2' to='room@mix.example.test'><metadata xmlns='urn:xmpp:mam:2'/></iq>",
    )
    .unwrap()
    .unwrap();
    assert!(matches!(metadata.operation, IqOperation::MamMetadata));
    let invalid = parse_iq("<iq type='get' id='f3' to='room@mix.example.test'><query xmlns='urn:xmpp:mam:2'><unexpected/></query></iq>").unwrap().unwrap();
    assert!(matches!(
        invalid.operation,
        IqOperation::MamError("bad-request")
    ));
}

#[test]
fn pam_and_core_join_identifiers_follow_their_respective_xeps() {
    let participant = MixParticipant {
        participant_id: Uuid::parse_str("00112233-4455-6677-8899-aabbccddeeff").unwrap(),
        jid: "alice@example.test".to_owned(),
        nick: Some("Nick".to_owned()),
    };
    let nodes = vec![NODE_MESSAGES.to_owned()];
    let core = core_join_payload(&participant, &nodes, None, false).unwrap();
    assert!(core.contains("id='00112233-4455-6677-8899-aabbccddeeff'"));
    assert!(!core.contains(" jid="));
    let pam = pam_join_payload("room@mix.example.test", &participant, &nodes, None, false).unwrap();
    assert!(pam.contains("jid='00112233-4455-6677-8899-aabbccddeeff#room@mix.example.test'"));
    assert!(!pam.contains(" id="));
}

#[test]
fn remote_join_result_is_direct_channel_bound_and_unambiguous() {
    let result = parse_remote_join_result(
        "<iq type='result' id='j1'><join xmlns='urn:xmpp:mix:core:1' id='opaque'><subscribe node='urn:xmpp:mix:nodes:messages'/><nick>Nick</nick></join></iq>",
        "room@mix.remote.test",
    )
    .unwrap();
    assert_eq!(result.participant_id, "opaque");
    assert_eq!(result.participant_jid, "opaque#room@mix.remote.test");
    assert_eq!(result.nick.as_deref(), Some("Nick"));

    let documented_pam_form = parse_remote_join_result(
        "<iq type='result' id='j2'><join xmlns='urn:xmpp:mix:core:1' jid='opaque#room@mix.remote.test'/></iq>",
        "room@mix.remote.test",
    )
    .unwrap();
    assert_eq!(documented_pam_form.participant_id, "opaque");

    assert!(parse_remote_join_result(
        "<iq type='result' id='bad'><wrapper><join xmlns='urn:xmpp:mix:core:1' id='nested'/></wrapper></iq>",
        "room@mix.remote.test",
    )
    .is_err());
    assert!(parse_remote_join_result(
        "<iq type='result' id='bad'><join xmlns='urn:xmpp:mix:core:1' id='one' jid='one#room@mix.remote.test'/></iq>",
        "room@mix.remote.test",
    )
    .is_err());
    assert!(parse_remote_join_result(
        "<iq type='result' id='bad'><join xmlns='urn:xmpp:mix:core:1' jid='opaque#other@mix.remote.test'/></iq>",
        "room@mix.remote.test",
    )
    .is_err());
    assert_eq!(
        parse_remote_pam_success("<iq type='result' id='leave'/>", "room@mix.remote.test",)
            .unwrap(),
        None
    );
    assert_eq!(
        parse_remote_pam_success(
            "<iq type='result' id='leave'><leave xmlns='urn:xmpp:mix:core:1'/></iq>",
            "room@mix.remote.test",
        )
        .unwrap(),
        None
    );
    assert!(parse_remote_pam_success(
        "<iq type='result' id='bad-leave'><leave xmlns='urn:xmpp:mix:core:1' unexpected='true'/></iq>",
        "room@mix.remote.test",
    )
    .is_err());
    assert!(parse_remote_pam_success(
        "<iq type='result' id='bad-leave-text'><leave xmlns='urn:xmpp:mix:core:1'> <!-- split -->unexpected</leave></iq>",
        "room@mix.remote.test",
    )
    .is_err());
    assert!(parse_remote_pam_success(
        "<iq type='result' id='bad'><unexpected/></iq>",
        "room@mix.remote.test",
    )
    .is_err());
}

#[test]
fn remote_iq_error_relay_accepts_only_standard_safe_conditions() {
    let error = parse_remote_iq_error("<iq type='error' id='e1'><error type='auth'><forbidden xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/><text xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'>no</text></error></iq>").unwrap();
    assert_eq!(error.error_type, "auth");
    assert_eq!(error.condition, "forbidden");
    assert!(parse_remote_iq_error("<iq type='error' id='e2'><error type='cancel'><attacker-controlled xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></iq>").is_err());
    assert!(parse_remote_iq_error("<iq type='error' id='e3'><error type='evil'><forbidden xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></iq>").is_err());
}

#[test]
fn strips_client_asserted_mix_identity_but_preserves_modern_payloads() {
    let (children, encrypted) = message_children("<message type='groupchat' to='c@mix.example.test'><body>x</body><file-sharing xmlns='urn:xmpp:sfs:0'/><origin-id xmlns='urn:xmpp:sid:0' id='client'/><stanza-id xmlns='urn:xmpp:sid:0' id='forged' by='c@mix.example.test'/><mix xmlns='urn:xmpp:mix:core:1'><jid>mallory@example.test</jid></mix></message>").unwrap();
    assert!(children.contains("file-sharing"));
    assert!(children.contains("origin-id"));
    assert!(!children.contains("forged"));
    assert!(!children.contains("mallory"));
    assert!(!encrypted);
}

#[test]
fn reflected_mix_history_identity_is_channel_bound_and_canonical() {
    let id = Uuid::new_v4();
    let valid_xml = format!(
        "<message type='groupchat' from='room@mix.remote.test/participant' to='alice@example.test'><mix xmlns='urn:xmpp:mix:core:1'><nick>Alice</nick></mix><stanza-id xmlns='urn:xmpp:sid:0' by='room@mix.remote.test' id='{id}'/></message>"
    );
    let valid = Document::parse(&valid_xml).unwrap();
    assert_eq!(reflected_mix_stanza_id(valid.root_element()).unwrap(), id);

    for invalid in [
        format!("<message from='room@mix.remote.test/participant'><stanza-id xmlns='urn:xmpp:sid:0' by='other@mix.remote.test' id='{id}'/></message>"),
        format!("<message from='room@mix.remote.test/participant'><stanza-id xmlns='urn:xmpp:sid:0' by='room@mix.remote.test' id='{id}'/><stanza-id xmlns='urn:xmpp:sid:0' by='room@mix.remote.test' id='{id}'/></message>"),
        "<message from='room@mix.remote.test/participant'><stanza-id xmlns='urn:xmpp:sid:0' by='room@mix.remote.test' id='NOT-A-UUID'/></message>".to_owned(),
    ] {
        let invalid = Document::parse(&invalid).unwrap();
        assert!(reflected_mix_stanza_id(invalid.root_element()).is_err());
    }
}

#[test]
fn federated_actor_identity_helpers_preserve_their_bare_or_full_contract() {
    assert_eq!(
        authenticated_actor("alice@remote.test", "remote.test").unwrap(),
        AuthenticatedMixIqActor {
            bare: "alice@remote.test".to_owned(),
            reply_to: "alice@remote.test".to_owned(),
        }
    );
    assert_eq!(
        authenticated_actor("alice@remote.test/Phone", "remote.test").unwrap(),
        AuthenticatedMixIqActor {
            bare: "alice@remote.test".to_owned(),
            reply_to: "alice@remote.test/Phone".to_owned(),
        }
    );
    assert!(authenticated_actor("alice@evil.test", "remote.test").is_err());
    assert_eq!(
        authenticated_full_actor("alice@remote.test/Phone", "remote.test").unwrap(),
        "alice@remote.test/Phone"
    );
    assert!(authenticated_full_actor("alice@remote.test", "remote.test").is_err());
    assert!(authenticated_full_actor("alice@evil.test/Phone", "remote.test").is_err());
}

#[test]
fn federated_mix_disco_is_strict_and_advertises_mam_only_on_channels() {
    let request = parse_mix_disco_info(
        "<iq type='get' id='d1' from='alice@remote.test/Phone' to='room@mix.example.test'><query xmlns='http://jabber.org/protocol/disco#info'/></iq>",
    )
    .unwrap()
    .unwrap();
    assert_eq!(request.id, "d1");
    assert_eq!(request.node, None);
    assert_eq!(request.error, None);

    let malformed = parse_mix_disco_info(
        "<iq type='get' id='d2' from='remote.test' to='mix.example.test'><query xmlns='http://jabber.org/protocol/disco#info'><unexpected/></query></iq>",
    )
    .unwrap()
    .unwrap();
    assert_eq!(malformed.error, Some("bad-request"));

    let service = mix_service_disco_info_payload("Northstar", "").unwrap();
    assert!(!service.contains("urn:xmpp:mam:2"));
    let channel_without_mam =
        mix_channel_disco_info_payload("Room", false, false, false, "").unwrap();
    assert!(!channel_without_mam.contains("urn:xmpp:mam:2"));
    let channel = mix_channel_disco_info_payload("Room", false, false, true, "").unwrap();
    for feature in [
        "http://jabber.org/protocol/rsm",
        "urn:xmpp:mam:2",
        "urn:xmpp:mam:2#extended",
        "urn:xmpp:sid:0",
    ] {
        assert!(channel.contains(feature), "missing {feature}");
    }
}

#[test]
fn parses_empty_federated_iq_response_for_pam_correlation() {
    let request = parse_iq(
        "<iq type='result' id='server-correlation' from='c@mix.remote.test' to='a@example.test'/>",
    )
    .unwrap()
    .unwrap();
    assert_eq!(request.id, "server-correlation");
    assert!(matches!(request.operation, IqOperation::Response));
}

#[test]
fn mix_service_identity_is_bound_to_authenticated_s2s_domain() {
    assert!(authenticated_mix_service("remote.test", "remote.test"));
    assert!(!authenticated_mix_service("mix.remote.test", "remote.test"));
    assert!(authenticated_mix_service(
        "mix.remote.test",
        "mix.remote.test"
    ));
    assert!(!authenticated_mix_service("mix.evil.test", "remote.test"));
    assert!(!authenticated_mix_service("evil.test", "remote.test"));
}

#[test]
fn remote_stable_participant_ids_are_opaque_but_delimiter_safe() {
    assert!(crate::services::mix::valid_stable_participant_id(
        "not-a-uuid"
    ));
    assert!(crate::services::mix::valid_stable_participant_id("αβγ"));
    assert!(!crate::services::mix::valid_stable_participant_id(""));
    assert!(!crate::services::mix::valid_stable_participant_id(
        "id#channel"
    ));
    assert!(!crate::services::mix::valid_stable_participant_id(
        "id@example.test"
    ));
    assert!(!crate::services::mix::valid_stable_participant_id(
        "id/resource"
    ));
    assert_eq!(
        decode_participant_jid("opaque#room@mix.remote.test").unwrap(),
        ("opaque".to_owned(), "room@mix.remote.test".to_owned())
    );
    assert!(decode_participant_jid("UPPER#room@mix.remote.test").is_err());
}

#[test]
fn reflected_federated_payloads_require_one_strict_server_identity() {
    let message = Document::parse("<message type='groupchat'><body>x</body><mix xmlns='urn:xmpp:mix:core:1'><nick>Nick</nick></mix></message>").unwrap();
    assert!(validate_reflected_mix_identity(message.root_element()).is_ok());
    let missing = Document::parse("<message type='groupchat'><body>x</body></message>").unwrap();
    assert!(validate_reflected_mix_identity(missing.root_element()).is_err());

    let presence = Document::parse("<presence><mix xmlns='urn:xmpp:mix:presence:0'><jid>a@example.test/r</jid><nick>Nick</nick></mix></presence>").unwrap();
    assert!(validate_reflected_mix_presence_identity(presence.root_element()).is_ok());
    let duplicate = Document::parse("<presence><mix xmlns='urn:xmpp:mix:presence:0'/><mix xmlns='urn:xmpp:mix:presence:0'/></presence>").unwrap();
    assert!(validate_reflected_mix_presence_identity(duplicate.root_element()).is_err());
}

#[test]
fn federated_delivery_is_node_scoped_not_bound_to_the_receivers_own_id() {
    let membership = PamMembership {
        id: Uuid::new_v4(),
        user_id: Uuid::new_v4(),
        channel_jid: "room@mix.remote.test".to_owned(),
        participant_id: Some("receivers-stable-id".to_owned()),
        state: "joined".to_owned(),
        request_id: None,
        client_request_id: None,
        requester_full_jid: None,
        subscriptions: vec![NODE_PRESENCE.to_owned()],
    };
    assert!(pam_membership_receives(&membership, NODE_PRESENCE));
    assert!(!pam_membership_receives(&membership, NODE_MESSAGES));
}

#[test]
fn mix_presence_relay_accepts_only_read_only_vcards() {
    let temp = parse_relay_iq("<iq type='get' id='v1' from='alice@example.test/Phone' to='opaque#room@mix.remote.test/Target'><vCard xmlns='vcard-temp'/></iq>").unwrap().unwrap();
    assert_eq!(temp.request, Some(RelayPayload::VCardTemp));
    let v4 = parse_relay_iq("<iq type='get' id='v2' from='alice@example.test/Phone' to='opaque#room@mix.remote.test'><pubsub xmlns='http://jabber.org/protocol/pubsub'><items node='urn:xmpp:vcard4'><item id='current'/></items></pubsub></iq>").unwrap().unwrap();
    assert_eq!(
        v4.request,
        Some(RelayPayload::VCard4 {
            item_id: Some("current".to_owned())
        })
    );
    assert!(parse_relay_iq("<iq type='set' id='v3' from='alice@example.test/Phone' to='opaque#room@mix.remote.test'><vCard xmlns='vcard-temp'/></iq>").unwrap().is_none());
    assert!(parse_relay_iq("<iq type='get' id='v4' from='alice@example.test/Phone' to='opaque#room@mix.remote.test'><query xmlns='jabber:iq:version'/></iq>").unwrap().is_none());
    assert!(parse_relay_iq("<iq type='get' id='v5' from='alice@example.test/Phone' to='opaque#room@mix.remote.test'><pubsub xmlns='http://jabber.org/protocol/pubsub'><items node='urn:xmpp:vcard4'/><publish node='urn:xmpp:vcard4'/></pubsub></iq>").unwrap().is_none());
}

#[test]
fn encoded_presence_resource_is_precis_case_sensitive() {
    let upper = encoded_participant_full_jid(
        "room@mix.example.test",
        "00112233-4455-6677-8899-aabbccddeeff",
        "Phone",
    )
    .unwrap();
    let lower = encoded_participant_full_jid(
        "room@mix.example.test",
        "00112233-4455-6677-8899-aabbccddeeff",
        "phone",
    )
    .unwrap();
    assert_eq!(
        upper,
        "00112233-4455-6677-8899-aabbccddeeff#room@mix.example.test/Phone"
    );
    assert_ne!(upper, lower);
}
