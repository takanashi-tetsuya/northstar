use super::*;
use crate::channel_delivery::{finish_mix_delivery_owner, send_claimed_cluster_mix};
use crate::claimed::*;
use northstar_delivery_core::node_delivery::{ClusterMixHandoff, NodeDeliveryReceipt};
use northstar_delivery_core::{MixDelivery, MixTransportCompletion};
use northstar_room_application::mix_service::outbox::fixture as owner_fixture;
use northstar_room_application::mix_service::MixService;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use tokio_util::sync::CancellationToken;

mod contracts;
pub(crate) mod fixture;
mod policy;

pub(crate) use contracts::reflection_host;
use contracts::*;
use fixture::Context;
use fixture::*;
use policy::*;

fn attempt_from_row(row: mix_worker::Row) -> mix_worker::Attempt {
    let claim = mix_worker::ClaimObservation::new(mix_worker::ClaimCommand {
        limit: 1,
        max_bytes: 8 * 1024 * 1024,
    });
    let request = claim.request().unwrap();
    request.start().unwrap();
    let entered = request.enter_statement().unwrap();
    let rows: mix_worker::Rows = vec![Arc::new(row)].into();
    request.received(entered, rows.clone()).unwrap();
    request.returned(rows).unwrap().pop().unwrap()
}

fn row(archive: bool) -> mix_worker::Row {
    owner_fixture::claimed_rows(archive)[0].as_ref().clone()
}

#[tokio::test(start_paused = true)]
async fn lanes_claim_and_process_only_their_queue() {
    for (label, budget, pam_budget) in [
        ("one_slot", 1, 1),
        ("two_slots", 2, 2),
        ("full_budget", 16, 2),
    ] {
        assert_eq!(
            mix_outbox_lane_budgets(budget),
            (budget, pam_budget),
            "{label}"
        );
        let context = Context::new(u32::try_from(budget).unwrap());
        context
            .state
            .rows
            .lock()
            .unwrap()
            .push_back(owner_fixture::claimed_rows(false));
        let pam = pam_result(0);
        context
            .state
            .pam
            .lock()
            .unwrap()
            .push_back(vec![pam.clone()]);
        let stop = CancellationToken::new();
        let cancel = CancellationToken::new();
        let delivery = claim_mix_outbox_work(
            context.clone(),
            stop.clone(),
            cancel.clone(),
            MixOutboxQueue::Delivery,
            budget,
        )
        .await
        .unwrap();
        let reply = claim_mix_outbox_work(
            context.clone(),
            stop,
            cancel.clone(),
            MixOutboxQueue::PamResult,
            pam_budget,
        )
        .await
        .unwrap();
        assert_eq!(delivery.len(), 1, "{label}");
        assert_eq!(reply.len(), 1, "{label}");
        assert!(
            matches!(&delivery[0], MixOutboxWork::Delivery(_)),
            "{label}"
        );
        assert!(matches!(&reply[0], MixOutboxWork::PamResult(_)), "{label}");
        assert_eq!(
            context.state.calls(),
            vec![
                Call::Claim(mix_worker::ClaimCommand {
                    limit: i64::try_from(budget).unwrap(),
                    max_bytes: 8 * 1024 * 1024
                }),
                Call::PamClaim(i64::try_from(pam_budget).unwrap()),
            ],
            "{label}"
        );
        for (work, expected) in delivery
            .into_iter()
            .map(|work| (work, MixOutboxQueue::Delivery))
            .chain(
                reply
                    .into_iter()
                    .map(|work| (work, MixOutboxQueue::PamResult)),
            )
        {
            let (queue, result) =
                process_mix_outbox_work(context.clone(), work, cancel.clone()).await;
            assert_eq!(queue, expected, "{label}");
            result.unwrap();
        }
        assert!(
            context
                .state
                .calls()
                .contains(&Call::PamDefer(pam.operation_id, pam.lease_token, 5)),
            "{label}"
        );
        assert!(
            context.state.calls().contains(&Call::Settle(
                row(false).source,
                12,
                mix_worker::SettlementCommand::Defer { delay_seconds: 30 }
            )),
            "{label}"
        );
    }

    for (label, queue) in [
        (
            "empty_delivery_does_not_claim_pam",
            MixOutboxQueue::Delivery,
        ),
        (
            "empty_pam_does_not_claim_delivery",
            MixOutboxQueue::PamResult,
        ),
    ] {
        let context = Context::new(1);
        let expected = match queue {
            MixOutboxQueue::Delivery => {
                context
                    .state
                    .pam
                    .lock()
                    .unwrap()
                    .push_back(vec![pam_result(0)]);
                Call::Claim(mix_worker::ClaimCommand {
                    limit: 1,
                    max_bytes: 8 * 1024 * 1024,
                })
            }
            MixOutboxQueue::PamResult => {
                context
                    .state
                    .rows
                    .lock()
                    .unwrap()
                    .push_back(owner_fixture::claimed_rows(false));
                Call::PamClaim(1)
            }
        };
        let work = claim_mix_outbox_work(
            context.clone(),
            CancellationToken::new(),
            CancellationToken::new(),
            queue,
            1,
        )
        .await
        .unwrap();
        assert!(work.is_empty(), "{label}");
        assert_eq!(context.state.calls(), vec![expected], "{label}");
    }

    // Exercise the actual startup wiring and retained lane slots. Two PAM
    // transport receipts stay pending, so a third row must remain unclaimed.
    let context = Context::new(16);
    let (tx, mut rx) = tokio::sync::mpsc::channel(4);
    let session = LocalSession {
        sender: northstar_stream::outbound::OutboundSender::new(tx),
        disconnect: CancellationToken::new(),
    };
    for index in 0..3 {
        context.state.pam.lock().unwrap().push_back(if index == 0 {
            vec![pam_result(0), pam_result(1)]
        } else {
            vec![pam_result(2)]
        });
    }
    *context.state.sessions.lock().unwrap() = vec![
        (pam_result(0).requester_full_jid, session.clone()),
        (pam_result(1).requester_full_jid, session),
    ];
    let registry = northstar_runtime::workers::WorkerRegistry::new();
    let cancel = CancellationToken::new();
    start_mix_delivery_outbox(context.clone(), registry.clone(), cancel.clone());
    context
        .state
        .until(|calls| {
            calls
                .iter()
                .filter(|call| matches!(call, Call::Sessions(jid) if jid.contains("resource-")))
                .count()
                == 2
        })
        .await;
    let first = rx.try_recv().unwrap();
    let second = rx.try_recv().unwrap();
    assert!(rx.try_recv().is_err());
    tokio::time::advance(Duration::from_millis(250)).await;
    assert_eq!(
        context
            .state
            .calls()
            .iter()
            .filter(|call| matches!(call, Call::PamClaim(_)))
            .count(),
        1
    );
    assert!(context.state.calls().contains(&Call::PamClaim(2)));
    cancel.cancel();
    first.confirm_transport_ownership();
    second.confirm_transport_ownership();
    let report = registry
        .shutdown_and_join(&cancel, Duration::from_secs(15))
        .await;
    assert_eq!(report.joined, 1);
    assert!(report.join_failures.is_empty());
}

#[tokio::test(start_paused = true)]
async fn pending_delivery_does_not_block_pam_or_claim_progress() {
    let context = Context::new(1);
    let gate = Arc::new(tokio::sync::Semaphore::new(0));
    *context.state.nodes_gate.lock().unwrap() = Some(gate.clone());
    let mut in_flight = FuturesUnordered::new();
    let delivery = outbox::OwnedAttempt::new(owner_fixture::attempt(false));
    let owner = delivery.observation();
    in_flight.push(process_mix_outbox_work(
        context.clone(),
        MixOutboxWork::Delivery(delivery),
        CancellationToken::new(),
    ));
    in_flight.push(process_mix_outbox_work(
        context.clone(),
        MixOutboxWork::PamResult(pam_result(0)),
        CancellationToken::new(),
    ));
    let mut claim = Some(process_mix_outbox_claim(
        context.clone(),
        CancellationToken::new(),
        CancellationToken::new(),
        MixOutboxQueue::Delivery,
        1,
    ));
    let mut maintenance = Some(process_mix_outbox_maintenance(
        context.clone(),
        CancellationToken::new(),
    ));
    assert!(matches!(
        next_mix_outbox_progress(&mut in_flight, &mut claim, &mut maintenance).await,
        MixOutboxProgress::InFlight(MixOutboxQueue::PamResult, Ok(()))
    ));
    assert!(
        matches!(next_mix_outbox_progress(&mut in_flight, &mut claim, &mut maintenance).await,
        MixOutboxProgress::Claim(Ok(rows)) if rows.is_empty())
    );
    assert!(matches!(
        next_mix_outbox_progress(&mut in_flight, &mut claim, &mut maintenance).await,
        MixOutboxProgress::Maintenance(Ok(()))
    ));
    assert!(claim.is_none());
    assert!(maintenance.is_none());
    assert_eq!(owner.snapshot().route, mix_worker::RoutePhase::Started);
    assert!(owner.snapshot().settlement.is_none());
    assert_eq!(context.state.admission.available_permits(), 1);
    assert_eq!(
        context
            .state
            .calls()
            .into_iter()
            .filter(|call| matches!(call, Call::Maintenance(_, _)))
            .collect::<Vec<_>>(),
        vec![
            Call::Maintenance("retention", 0),
            Call::Maintenance("business", 512),
            Call::Maintenance("iq", 512),
            Call::Maintenance("remote-pam", 128),
            Call::Maintenance("pam", 512),
        ]
    );
    gate.add_permits(1);
    assert!(matches!(
        next_mix_outbox_progress(&mut in_flight, &mut claim, &mut maintenance).await,
        MixOutboxProgress::InFlight(MixOutboxQueue::Delivery, Ok(()))
    ));
    assert_eq!(
        owner.snapshot().terminal,
        Some(mix_worker::TerminalReason::Completed)
    );

    // A maintenance wait must also keep polling the already claimed work
    // that owns the only permit needed by that maintenance turn.
    let permit = context.state.admission.acquire().await;
    let mut in_flight = FuturesUnordered::<MixOutboxTask>::new();
    in_flight.push(Box::pin(async move {
        drop(permit);
        (MixOutboxQueue::Delivery, Ok(()))
    }));
    let mut maintenance = Some(process_mix_outbox_maintenance(
        context,
        CancellationToken::new(),
    ));
    assert!(matches!(
        next_mix_outbox_progress(&mut in_flight, &mut None, &mut maintenance).await,
        MixOutboxProgress::InFlight(_, Ok(()))
    ));
    assert!(matches!(
        next_mix_outbox_progress(&mut in_flight, &mut None, &mut maintenance).await,
        MixOutboxProgress::Maintenance(Ok(()))
    ));
}

#[tokio::test(start_paused = true)]
async fn failed_lane_cancels_and_joins_peer() {
    for (label, delivery_fails, error, stopping) in [
        ("delivery_error", true, true, false),
        ("pam_error", false, true, false),
        ("unexpected_delivery_exit", true, false, false),
        ("unexpected_pam_exit", false, false, false),
        ("normal_stopped_delivery", true, false, true),
        ("normal_stopped_pam", false, false, true),
    ] {
        let stop = CancellationToken::new();
        let cancel = CancellationToken::new();
        let dropped = Arc::new(AtomicBool::new(false));
        let (release, released) = tokio::sync::oneshot::channel();
        let (peer_release, peer_released) = tokio::sync::oneshot::channel();
        let first: BoxFuture<'static, Result<()>> = Box::pin(async move {
            released.await.unwrap();
            if error {
                anyhow::bail!("lane failure");
            }
            Ok(())
        });
        let peer_cancel = cancel.clone();
        let marker = dropped.clone();
        let peer: BoxFuture<'static, Result<()>> = Box::pin(async move {
            let _drop = DropFlag(marker);
            if stopping {
                peer_released.await.unwrap();
            } else {
                peer_cancel.cancelled().await;
            }
            Ok(())
        });
        let (delivery, pam) = if delivery_fails {
            (first, peer)
        } else {
            (peer, first)
        };
        let mut joined = Box::pin(join_mix_outbox_lanes(
            stop.clone(),
            cancel.clone(),
            delivery,
            pam,
        ));
        assert!(futures::poll!(&mut joined).is_pending(), "{label}");
        if stopping {
            stop.cancel();
        }
        release.send(()).unwrap();
        if stopping {
            assert!(futures::poll!(&mut joined).is_pending(), "{label}");
            assert!(!cancel.is_cancelled(), "{label}");
            peer_release.send(()).unwrap();
        }
        let result = joined.await;
        assert_eq!(result.is_err(), error, "{label}");
        if let Err(result) = result {
            assert_eq!(result.to_string(), "lane failure", "{label}");
        }
        assert!(
            dropped.load(Ordering::SeqCst),
            "{label}: peer must be destroyed before return"
        );
        assert_eq!(cancel.is_cancelled(), !stopping, "{label}");
    }
}

#[tokio::test(start_paused = true)]
async fn stopped_claim_returns_and_drains() {
    let context = Context::new(1);
    let gate = Arc::new(tokio::sync::Semaphore::new(0));
    *context.state.claim_gate.lock().unwrap() = Some(gate.clone());
    context
        .state
        .rows
        .lock()
        .unwrap()
        .push_back(owner_fixture::claimed_rows(false));
    let stop = CancellationToken::new();
    let cancel = CancellationToken::new();
    let mut claim = claim_mix_outbox_work(
        context.clone(),
        stop.clone(),
        cancel.clone(),
        MixOutboxQueue::Delivery,
        1,
    );
    assert!(futures::poll!(&mut claim).is_pending());
    assert_eq!(context.state.admission.available_permits(), 0);
    stop.cancel();
    tokio::time::advance(Duration::from_secs(4)).await;
    assert!(futures::poll!(&mut claim).is_pending());
    gate.add_permits(1);
    let mut work = claim.await.unwrap();
    assert_eq!(work.len(), 1);
    let MixOutboxWork::Delivery(delivery) = work.pop().unwrap() else {
        panic!("wrong lane");
    };
    let owner = delivery.observation();
    assert_eq!(owner.row(), &row(false));
    let (queue, result) = process_mix_outbox_work(
        context.clone(),
        MixOutboxWork::Delivery(delivery),
        cancel.clone(),
    )
    .await;
    assert_eq!(queue, MixOutboxQueue::Delivery);
    result.unwrap();
    assert_eq!(
        owner.snapshot().terminal,
        Some(mix_worker::TerminalReason::Completed)
    );
    assert!(!cancel.is_cancelled());
    for queue in [MixOutboxQueue::Delivery, MixOutboxQueue::PamResult] {
        assert!(
            claim_mix_outbox_work(context.clone(), stop.clone(), cancel.clone(), queue, 1)
                .await
                .unwrap()
                .is_empty()
        );
    }
    assert_eq!(
        context
            .state
            .calls()
            .iter()
            .filter(|call| matches!(call, Call::Claim(_) | Call::PamClaim(_)))
            .count(),
        1
    );
    assert_eq!(context.state.admission.available_permits(), 1);

    let context = Context::new(1);
    let gate = Arc::new(tokio::sync::Semaphore::new(0));
    *context.state.claim_gate.lock().unwrap() = Some(gate.clone());
    context
        .state
        .rows
        .lock()
        .unwrap()
        .push_back(owner_fixture::claimed_rows(false));
    let registry = northstar_runtime::workers::WorkerRegistry::new();
    let stop = CancellationToken::new();
    start_mix_delivery_outbox(context.clone(), registry.clone(), stop.clone());
    context
        .state
        .until(|calls| calls.iter().any(|call| matches!(call, Call::Claim(_))))
        .await;
    stop.cancel();
    assert!(!context.state.claim_dropped.load(Ordering::SeqCst));
    gate.add_permits(1);
    let report = registry
        .shutdown_and_join(&stop, Duration::from_secs(15))
        .await;
    assert_eq!(report.joined, 1);
    assert!(report.join_failures.is_empty());
    assert_eq!(
        context
            .state
            .calls()
            .iter()
            .filter(|call| matches!(call, Call::Claim(_)))
            .count(),
        1
    );
    assert!(context.state.calls().contains(&Call::Settle(
        row(false).source,
        12,
        mix_worker::SettlementCommand::Defer { delay_seconds: 30 }
    )));
}

#[tokio::test(start_paused = true)]
async fn hard_cancel_wins_and_releases_children() {
    let context = Context::new(1);
    *context.state.claim_gate.lock().unwrap() = Some(Arc::new(tokio::sync::Semaphore::new(0)));
    let cancel = CancellationToken::new();
    let mut claim = claim_mix_outbox_work(
        context.clone(),
        CancellationToken::new(),
        cancel.clone(),
        MixOutboxQueue::Delivery,
        1,
    );
    assert!(futures::poll!(&mut claim).is_pending());
    cancel.cancel();
    let Err(error) = claim.await else {
        panic!("hard cancellation must reject the unknown response");
    };
    assert!(mix_outbox_is_shutting_down(&error));
    assert!(context.state.claim_dropped.load(Ordering::SeqCst));
    assert_eq!(context.state.admission.available_permits(), 1);

    let expired = tokio::time::Instant::now();
    let error = bounded_mix_outbox_turn(&cancel, expired, async { Ok(()) })
        .await
        .unwrap_err();
    assert!(
        mix_outbox_is_shutting_down(&error),
        "cancel_wins_over_expired_and_ready"
    );

    let (owner, port, mut run) = policy_run(row(false), Answer::Worker, CancellationToken::new());
    *port.route_gate.lock().unwrap() = Some(Arc::new(tokio::sync::Semaphore::new(0)));
    *port.renewal.lock().unwrap() = Renewal::Pending;
    assert!(futures::poll!(&mut run).is_pending());
    tokio::time::advance(Duration::from_secs(10)).await;
    assert!(futures::poll!(&mut run).is_pending());
    assert!(owner.snapshot().renewal.pending);
    drop(run);
    assert!(port.route_dropped.load(Ordering::SeqCst));
    assert!(port.renewal_dropped.load(Ordering::SeqCst));
    assert_eq!(port.permit.available_permits(), 1);
    assert_eq!(
        owner.snapshot().terminal,
        Some(mix_worker::TerminalReason::Cancelled)
    );
    assert!(owner.snapshot().settlement.is_none());

    // The production supervisor bounds a graceful drain independently of the
    // twenty-second attempt timer, and joins destruction of its children.
    let context = Context::new(1);
    context
        .state
        .rows
        .lock()
        .unwrap()
        .push_back(owner_fixture::claimed_rows(false));
    *context.state.nodes_gate.lock().unwrap() = Some(Arc::new(tokio::sync::Semaphore::new(0)));
    let registry = northstar_runtime::workers::WorkerRegistry::new();
    let stop = CancellationToken::new();
    start_mix_delivery_outbox(context.clone(), registry.clone(), stop.clone());
    context
        .state
        .until(|calls| {
            calls
                .iter()
                .any(|call| matches!(call, Call::Nodes(true, jid, _) if jid == "bob@local.test"))
        })
        .await;
    let drain_started = tokio::time::Instant::now();
    let mut shutdown = Box::pin(registry.shutdown_and_join(&stop, Duration::from_secs(15)));
    assert!(futures::poll!(&mut shutdown).is_pending());
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_millis(13_999)).await;
    assert!(futures::poll!(&mut shutdown).is_pending());
    assert!(!context.state.nodes_dropped.load(Ordering::SeqCst));
    tokio::time::advance(Duration::from_millis(1)).await;
    let report = shutdown.await;
    assert_eq!(
        tokio::time::Instant::now() - drain_started,
        Duration::from_secs(14)
    );
    assert_eq!(report.joined, 1);
    assert!(report.join_failures.is_empty());
    assert!(context.state.nodes_dropped.load(Ordering::SeqCst));
    assert_eq!(context.state.admission.available_permits(), 1);
    assert!(!context
        .state
        .calls()
        .iter()
        .any(|call| matches!(call, Call::Settle(_, _, _))));
}

#[tokio::test(start_paused = true)]
async fn attempt_deadline_is_not_reset() {
    let context = Context::new(1);
    *context.state.claim_gate.lock().unwrap() = Some(Arc::new(tokio::sync::Semaphore::new(0)));
    let claim_started = tokio::time::Instant::now();
    let mut claim = claim_mix_outbox_work(
        context.clone(),
        CancellationToken::new(),
        CancellationToken::new(),
        MixOutboxQueue::Delivery,
        1,
    );
    assert!(futures::poll!(&mut claim).is_pending());
    tokio::time::advance(Duration::from_millis(4_999)).await;
    assert!(futures::poll!(&mut claim).is_pending());
    tokio::time::advance(Duration::from_millis(1)).await;
    let Err(error) = claim.await else {
        panic!("claim must expire after five seconds");
    };
    assert!(mix_outbox_deadline_elapsed(&error));
    assert_eq!(
        tokio::time::Instant::now() - claim_started,
        Duration::from_secs(5)
    );
    assert!(context.state.claim_dropped.load(Ordering::SeqCst));
    assert_eq!(context.state.admission.available_permits(), 1);

    for (label, invalid, cancel_settlement) in [
        ("route_then_settlement", false, false),
        ("invalid_template", true, false),
        ("cancel_settlement", false, true),
        ("cancel_invalid_template", true, true),
    ] {
        let mut row = row(false);
        if invalid {
            row.stanza = "<message>".into();
        }
        let cancel = CancellationToken::new();
        let (owner, port, mut run) = policy_run(row, Answer::Worker, cancel.clone());
        let started = tokio::time::Instant::now();
        let release_route = Arc::new(tokio::sync::Semaphore::new(0));
        if !invalid {
            *port.route_gate.lock().unwrap() = Some(release_route.clone());
        }
        *port.renewal.lock().unwrap() = Renewal::Pending;
        *port.settle_gate.lock().unwrap() = Some(Arc::new(tokio::sync::Semaphore::new(0)));
        assert!(futures::poll!(&mut run).is_pending(), "{label}");
        tokio::time::advance(Duration::from_millis(9_999)).await;
        assert!(futures::poll!(&mut run).is_pending(), "{label}");
        assert!(
            !port
                .calls()
                .iter()
                .any(|call| matches!(call, PolicyCall::Renew(_))),
            "{label}: no immediate renewal"
        );
        tokio::time::advance(Duration::from_millis(1)).await;
        assert!(futures::poll!(&mut run).is_pending(), "{label}");
        assert_eq!(
            owner.snapshot().renewal.issued,
            u64::from(!invalid),
            "{label}"
        );
        tokio::time::advance(Duration::from_secs(9)).await;
        release_route.add_permits(1);
        assert!(futures::poll!(&mut run).is_pending(), "{label}");
        assert_eq!(
            port.calls()
                .iter()
                .filter(|call| matches!(call, PolicyCall::Settle(_, _, _)))
                .count(),
            1,
            "{label}"
        );
        if !invalid {
            assert!(port.renewal_dropped.load(Ordering::SeqCst), "{label}");
            assert!(owner.snapshot().renewal_scope_closed, "{label}");
        }
        tokio::time::advance(Duration::from_millis(999)).await;
        assert!(futures::poll!(&mut run).is_pending(), "{label}");
        if cancel_settlement {
            cancel.cancel();
        }
        tokio::time::advance(Duration::from_millis(1)).await;
        let warnings = Warnings::default();
        warnings.drive(&mut run).await.unwrap();
        assert_eq!(
            tokio::time::Instant::now() - started,
            Duration::from_secs(20),
            "{label}: original attempt deadline"
        );
        if !cancel_settlement {
            warnings.assert_row_identity(label);
        }
        assert!(port.settle_dropped.load(Ordering::SeqCst), "{label}");
        assert_eq!(
            owner.snapshot().terminal,
            Some(if cancel_settlement {
                mix_worker::TerminalReason::Cancelled
            } else {
                mix_worker::TerminalReason::TimedOut
            }),
            "{label}"
        );
        assert_eq!(port.permit.available_permits(), 1, "{label}");
    }

    let context = Context::new(1);
    *context.state.maintenance_gate.lock().unwrap() =
        Some(Arc::new(tokio::sync::Semaphore::new(0)));
    let started = tokio::time::Instant::now();
    let mut maintenance = process_mix_outbox_maintenance(context.clone(), CancellationToken::new());
    assert!(futures::poll!(&mut maintenance).is_pending());
    tokio::time::advance(Duration::from_millis(4_999)).await;
    assert!(futures::poll!(&mut maintenance).is_pending());
    tokio::time::advance(Duration::from_millis(1)).await;
    assert!(mix_outbox_deadline_elapsed(&maintenance.await.unwrap_err()));
    assert_eq!(
        tokio::time::Instant::now() - started,
        Duration::from_secs(5)
    );
    assert!(context.state.maintenance_dropped.load(Ordering::SeqCst));
    assert_eq!(context.state.admission.available_permits(), 1);
    assert_eq!(
        context.state.calls(),
        vec![Call::Maintenance("retention", 0)]
    );
}

#[tokio::test]
async fn durable_channel_uses_only_outbox_authority() {
    for (label, durable, remote) in [
        ("live_local", false, false),
        ("durable_local", true, false),
        ("live_federation", false, true),
        ("durable_federation", true, true),
    ] {
        let context = Context::new(1);
        let recipient = MixParticipant {
            participant_id: Uuid::from_u128(94),
            jid: if remote {
                "bob@remote.test"
            } else {
                "bob@local.test"
            }
            .into(),
            nick: Some("Bob".into()),
        };
        let stanza = format!(
            "<message to='{}'><body>owned</body></message>",
            recipient.jid
        );
        let source = row(false).source;
        let result = deliver_channel_stanza(
            context.as_ref(),
            ChannelStanzaDelivery {
                delivery_id: durable.then_some(source.delivery_id),
                mix_source: durable.then_some(source),
                channel_jid: "room@mix.local.test",
                recipient: &recipient,
                stanza: stanza.clone(),
                authoritative_stanza_id: Some(Uuid::from_u128(95)),
                archive: true,
                encrypted: true,
                durable,
                database_lane: if durable {
                    ChannelStanzaDatabaseLane::DurableOutbox
                } else {
                    ChannelStanzaDatabaseLane::LiveIngress
                },
            },
        )
        .await;
        let calls = context.state.calls();
        if remote {
            assert_eq!(
                result.unwrap(),
                ChannelStanzaDeliveryOutcome::CompletedByClaimingWorker,
                "{label}"
            );
            assert_eq!(
                calls,
                vec![Call::Federation(
                    durable,
                    "remote.test".into(),
                    stanza,
                    usize::from(!durable)
                )],
                "{label}"
            );
        } else {
            if durable {
                assert!(
                    result.unwrap_err().is::<MixDeliveryRoutePending>(),
                    "{label}"
                );
            } else {
                assert_eq!(
                    result.unwrap(),
                    ChannelStanzaDeliveryOutcome::CompletedByClaimingWorker,
                    "{label}"
                );
            }
            assert_eq!(calls.len(), 5, "{label}");
            assert_eq!(
                calls[0],
                Call::User("bob".into(), usize::from(!durable)),
                "{label}"
            );
            assert_eq!(
                calls[1],
                Call::Block(
                    Uuid::from_u128(81),
                    "room@mix.local.test".into(),
                    usize::from(!durable)
                ),
                "{label}"
            );
            let Call::Archive(command, permits) = &calls[2] else {
                panic!("{label}: missing archive");
            };
            assert_eq!(*permits, usize::from(!durable), "{label}");
            assert_eq!(command.owner_id, Uuid::from_u128(81), "{label}");
            assert_eq!(command.channel_jid, "room@mix.local.test", "{label}");
            assert_eq!(
                command.authoritative_stanza_id,
                Uuid::from_u128(95),
                "{label}"
            );
            assert_eq!(command.stanza.as_ref(), stanza, "{label}");
            assert!(command.encrypted, "{label}");
            assert_eq!(
                command.client_stanza_id,
                Some(Uuid::from_u128(95).to_string()),
                "{label}"
            );
            assert_eq!(calls[3], Call::Sessions(recipient.jid.clone()), "{label}");
            assert_eq!(
                calls[4],
                Call::Nodes(durable, recipient.jid.clone(), 1),
                "{label}"
            );
        }
        assert_eq!(context.state.admission.available_permits(), 1, "{label}");
    }
}

#[tokio::test]
async fn claimed_route_keeps_request_and_durable_lane() {
    for (label, archive, authoritative_id, replay) in [
        ("unarchived_without_id", false, None, false),
        (
            "unarchived_with_id",
            false,
            Some(Uuid::from_u128(95)),
            false,
        ),
        ("archived", true, Some(Uuid::from_u128(95)), false),
        (
            "archive_replay_continues_routing",
            true,
            Some(Uuid::from_u128(95)),
            true,
        ),
    ] {
        let context = Context::new(1);
        context.state.archive_replay.store(replay, Ordering::SeqCst);
        *context.state.nodes.lock().unwrap() = vec!["node-b".into()];
        *context.state.receipt.lock().unwrap() = NodeDeliveryReceipt {
            acknowledged: true,
            delivered: true,
            mix_supported: 1,
            ..Default::default()
        };
        let mut original = row(archive);
        original.authoritative_stanza_id = authoritative_id;
        original.encrypted = true;
        original.recipient_nick = Some("Bob".into());
        let attempt = attempt_from_row(original.clone());
        let owner = attempt.observation();
        let stanza = addressed_mix_delivery(&original.stanza, &original.recipient_jid).unwrap();
        let route = attempt.route(stanza.clone()).unwrap();
        let port = MixOutboxDeliveryPort {
            context: context.clone(),
        };
        assert_eq!(
            port.route(&route).await.expect(label),
            ChannelStanzaDeliveryOutcome::CompletedByClaimingWorker,
            "{label}"
        );
        assert_eq!(route.row(), &original, "{label}");
        assert_eq!(owner.snapshot().cluster.len(), 1, "{label}");
        assert!(owner.snapshot().cluster[0].returned, "{label}");
        assert!(
            context.state.calls().contains(&Call::Cluster(
                "node-b".into(),
                original.recipient_jid.clone(),
                stanza.clone(),
                Some(original.source),
                1
            )),
            "{label}"
        );
        let archives = context
            .state
            .calls()
            .into_iter()
            .filter_map(|call| {
                if let Call::Archive(command, permits) = call {
                    Some((command, permits))
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();
        assert_eq!(archives.len(), usize::from(archive), "{label}");
        if let Some((command, permits)) = archives.first() {
            assert_eq!(
                owner.snapshot().archive.knowledge,
                mix_worker::ArchiveKnowledge::ReceiptKnown(if replay {
                    mix_worker::ArchiveResult::Replay(Uuid::from_u128(82))
                } else {
                    mix_worker::ArchiveResult::Stored(command.personal_archive_id)
                }),
                "{label}"
            );
            assert_eq!(*permits, 0, "{label}");
            assert_eq!(command.stanza.as_ref(), stanza, "{label}");
            assert_eq!(command.channel_jid, original.channel_jid, "{label}");
            assert_eq!(
                Some(command.authoritative_stanza_id),
                authoritative_id,
                "{label}"
            );
            assert!(command.encrypted, "{label}");
        }
        let renewal = owner.renewal_request().unwrap();
        assert!(port.renew(&renewal).await.unwrap(), "{label}");
        let closed = owner.close_renewal_scope().unwrap();
        let settlement = route
            .returned(mix_worker::RouteResult::CompletedByWorker)
            .unwrap()
            .settlement(mix_worker::SettlementCommand::Ack, closed)
            .unwrap()
            .unwrap();
        assert_eq!(
            port.settle(&settlement).await.unwrap(),
            mix_worker::SettlementResult::Ack(true),
            "{label}"
        );
        assert!(
            context
                .state
                .calls()
                .contains(&Call::Renew(original.source)),
            "{label}"
        );
        assert!(
            context.state.calls().contains(&Call::Settle(
                original.source,
                original.route_wake_generation,
                mix_worker::SettlementCommand::Ack
            )),
            "{label}"
        );
    }
}

#[tokio::test(start_paused = true)]
async fn claimed_effects_preserve_observed_contracts() {
    local_and_cluster_contracts().await;
    shared_policy_contracts().await;
    ingress_contracts().await;
}

mod reflected_retraction;
