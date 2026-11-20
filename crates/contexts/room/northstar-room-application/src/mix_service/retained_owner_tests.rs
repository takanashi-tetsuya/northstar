use super::{MixBusinessReplay, StoreEventOutcome};
use anyhow::Result;
use std::sync::Arc;
use uuid::Uuid;

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
    use crate::mix_service::outbox::{core, fixture};
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
    use crate::mix_service::outbox::{core, fixture};
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
async fn mix_worker_claim_statement_cuts_keep_receipts_without_issuing_attempts_after_error() {
    use crate::mix_service::outbox;
    use crate::mix_service::outbox::{core, fixture};
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
    use crate::mix_service::outbox;
    use crate::mix_service::outbox::{core, fixture};
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
    use crate::mix_service::outbox;
    use crate::mix_service::outbox::{core, fixture};
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

#[tokio::test]
async fn mix_foreground_authenticated_replay_never_starts_membership_or_store_effects() {
    use crate::mix::{read_observed, Knowledge, ReadReturned, Rejected, Wake};
    use crate::mix_service::foreground::{fixture, Observation};
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
        if let Ok(store) =
            owner.store_request(fixture::command(true), fixture::publisher_identity())
        {
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
            owner.store_request(fixture::command(true), fixture::publisher_identity()),
            Err(Rejected::Read)
        ));
    }
}

#[tokio::test]
async fn mix_foreground_raw_existing_survives_cancelled_rollback_without_authenticated_replay() {
    use crate::mix::{admit_observed, read_observed, Knowledge, Rejected, TerminalReason};
    use crate::mix_service::foreground::{fixture, Observation};
    let owner = Observation::new(fixture::prepared(true));
    let read = owner.replay_request().unwrap().unwrap();
    read_observed(&read, "mix.local.test", async {
        read.observed_miss()?;
        Ok::<_, anyhow::Error>(MixBusinessReplay::Miss)
    })
    .await
    .unwrap();
    let request = owner
        .store_request(fixture::command(true), fixture::publisher_identity())
        .unwrap();
    let raw = fixture::existing();
    let mut effect = Box::pin(admit_observed(&request, "mix.local.test", async {
        request.observed_existing(raw.clone())?;
        // Independent fake rollback completion gate, never resolved here.
        std::future::pending::<()>().await;
        request.authenticated(&raw, MixBusinessReplay::Replay(Uuid::from_u128(70)))?;
        Ok::<_, anyhow::Error>(crate::mix_service::StoreMixMessageAdmission {
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
    use crate::mix::{Knowledge, Returned, Wake};
    use crate::mix_service::foreground::{fixture, Observation};
    use std::sync::atomic::Ordering;
    for audience in [false, true] {
        let owner = Observation::new(fixture::prepared(false));
        let request = owner
            .store_request(fixture::command(false), fixture::publisher_identity())
            .unwrap();
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
    let request = owner
        .store_request(fixture::command(false), fixture::publisher_identity())
        .unwrap();
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
    use crate::mix::{read_observed, EffectError, Rejected};
    use crate::mix_service::foreground::{fixture, Observation, PreparedIngress};
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
    use crate::mix::{admit_observed, commit_observed, Knowledge};
    use crate::mix_service::foreground::{fixture, Observation};
    use std::sync::atomic::Ordering;
    let owner = Observation::new(fixture::prepared(false));
    let request = owner
        .store_request(fixture::command(false), fixture::publisher_identity())
        .unwrap();
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
