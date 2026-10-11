//! Tests of the shared claimed delivery policy.

use super::*;
use crate::services::mix::outbox::core;
use std::sync::Mutex;

// These ordinary policy controls supply route and repository facts. They
// do not provide transport-handoff or database execution evidence.
#[derive(Clone, Copy)]
enum RouteFact {
    Completed,
    Pending,
    Permanent,
    Retry,
    Shutdown,
    DeadlineError,
}

#[derive(Clone, Copy)]
enum RenewalFact {
    Pending,
    Lost,
    Error,
}

#[derive(Clone)]
struct SuppliedPort {
    owner: core::Observation,
    route: RouteFact,
    renewal: RenewalFact,
    wait_route: bool,
    release_route: Arc<tokio::sync::Notify>,
    settlement_result: Option<core::SettlementResult>,
    commands: Arc<Mutex<Vec<core::SettlementCommand>>>,
    events: Arc<Mutex<Vec<&'static str>>>,
}

struct ChildDrop {
    port: SuppliedPort,
    event: &'static str,
}

impl Drop for ChildDrop {
    fn drop(&mut self) {
        assert!(!self.port.owner.snapshot().renewal_scope_closed);
        assert_eq!(self.port.owner.snapshot().terminal, None);
        self.port.events.lock().unwrap().push(self.event);
    }
}

impl ClaimedMixDeliveryPort for SuppliedPort {
    async fn route(&self, request: &core::RouteRequest) -> Result<ChannelStanzaDeliveryOutcome> {
        assert!(std::ptr::eq(request.row(), self.owner.row()));
        assert_eq!(
            request.stanza(),
            addressed_mix_delivery(&self.owner.row().stanza, &self.owner.row().recipient_jid)?
        );
        request.start()?;
        let _child = ChildDrop {
            port: self.clone(),
            event: "route dropped",
        };
        self.events.lock().unwrap().push("route started");
        if self.wait_route {
            self.release_route.notified().await;
        }
        match self.route {
            RouteFact::Completed => Ok(ChannelStanzaDeliveryOutcome::CompletedByClaimingWorker),
            RouteFact::Pending => Err(MixDeliveryRoutePending.into()),
            RouteFact::Permanent => Err(permanent_mix_delivery_error("policy", "detail")),
            RouteFact::Retry => Err(anyhow::anyhow!("route failed")),
            RouteFact::Shutdown => Err(MixOutboxShutdown.into()),
            RouteFact::DeadlineError => Err(MixOutboxDeadlineElapsed.into()),
        }
    }

    async fn renew(&self, request: &core::RenewalRequest) -> Result<bool> {
        assert_eq!(request.source(), self.owner.row().source);
        request.start()?;
        let _child = ChildDrop {
            port: self.clone(),
            event: "renewal dropped",
        };
        self.events.lock().unwrap().push("renewal started");
        match self.renewal {
            RenewalFact::Pending => std::future::pending().await,
            RenewalFact::Lost => {
                let entered = request.enter_statement()?;
                request.received(entered, false)?;
                Ok(request.returned(false)?)
            }
            RenewalFact::Error => {
                request.failed()?;
                Err(anyhow::anyhow!("renewal failed"))
            }
        }
    }

    async fn settle(&self, request: &core::SettlementRequest) -> Result<core::SettlementResult> {
        assert_eq!(request.source(), self.owner.row().source);
        assert_eq!(
            request.route_wake_generation(),
            self.owner.row().route_wake_generation
        );
        assert!(self.owner.snapshot().renewal_scope_closed);
        if self.events.lock().unwrap().contains(&"route started") {
            assert!(self.events.lock().unwrap().contains(&"route dropped"));
        }
        if self.events.lock().unwrap().contains(&"renewal started") {
            assert!(self.events.lock().unwrap().contains(&"renewal dropped"));
        }
        self.commands
            .lock()
            .unwrap()
            .push(request.command().clone());
        request.start()?;
        let result = self.settlement_result.unwrap_or(match request.command() {
            core::SettlementCommand::Ack => core::SettlementResult::Ack(true),
            core::SettlementCommand::Defer { .. } => core::SettlementResult::Defer(true),
            core::SettlementCommand::Retry { .. } => {
                core::SettlementResult::Retry(core::RetryResult::Retried)
            }
            core::SettlementCommand::DeadLetter { .. } => core::SettlementResult::DeadLetter(true),
        });
        if matches!(result, core::SettlementResult::Defer(_)) {
            let entered = request.enter_statement()?;
            request.received(entered, result)?;
        } else {
            core::settlement_commit_observed(async { Ok::<_, anyhow::Error>(()) }, request, result)
                .await
                .map_err(outbox::commit_error)?;
        }
        Ok(request.returned(result)?)
    }
}

fn supplied_attempt(
    stanza: Option<&str>,
    route: RouteFact,
) -> (outbox::OwnedAttempt, SuppliedPort) {
    let mut row = (*outbox::fixture::claimed_rows(false)[0]).clone();
    if let Some(stanza) = stanza {
        row.stanza = stanza.to_owned();
    }
    let claim = core::ClaimObservation::new(core::ClaimCommand {
        limit: 1,
        max_bytes: 8 * 1024 * 1024,
    });
    let request = claim.request().unwrap();
    request.start().unwrap();
    let entered = request.enter_statement().unwrap();
    let rows: core::Rows = vec![Arc::new(row)].into();
    request.received(entered, rows.clone()).unwrap();
    let attempt = outbox::OwnedAttempt::new(request.returned(rows).unwrap().pop().unwrap());
    let port = SuppliedPort {
        owner: attempt.observation(),
        route,
        renewal: RenewalFact::Pending,
        wait_route: false,
        release_route: Arc::new(tokio::sync::Notify::new()),
        settlement_result: None,
        commands: Arc::new(Mutex::new(Vec::new())),
        events: Arc::new(Mutex::new(Vec::new())),
    };
    (attempt, port)
}

fn run_policy(
    attempt: outbox::OwnedAttempt,
    port: SuppliedPort,
    cancel: tokio_util::sync::CancellationToken,
) -> outbox::AttemptRun {
    attempt.run(move |attempt, handle| {
        process_claimed_mix_delivery_with_port(port, attempt, handle, cancel)
    })
}

#[tokio::test]
async fn shared_policy_ordinary_route_facts_select_exact_lazy_settlement() {
    for (fact, command) in [
        (RouteFact::Completed, core::SettlementCommand::Ack),
        (
            RouteFact::Pending,
            core::SettlementCommand::Defer {
                delay_seconds: MIX_DELIVERY_ROUTE_RECOVERY_DELAY_SECS,
            },
        ),
        (
            RouteFact::Permanent,
            core::SettlementCommand::DeadLetter {
                reason: "policy".into(),
                error: "detail".into(),
            },
        ),
        (
            RouteFact::Retry,
            core::SettlementCommand::Retry {
                error: "route failed".into(),
            },
        ),
        (
            RouteFact::DeadlineError,
            core::SettlementCommand::Retry {
                error: MixOutboxDeadlineElapsed.to_string(),
            },
        ),
    ] {
        let (attempt, port) = supplied_attempt(None, fact);
        run_policy(
            attempt,
            port.clone(),
            tokio_util::sync::CancellationToken::new(),
        )
        .await
        .unwrap();
        assert_eq!(*port.commands.lock().unwrap(), vec![command]);
        assert_eq!(
            *port.events.lock().unwrap(),
            vec!["route started", "route dropped"]
        );
        assert_eq!(port.owner.snapshot().renewal.issued, 0);
        assert_eq!(
            port.owner.snapshot().terminal,
            Some(core::TerminalReason::Completed)
        );
    }
}

#[tokio::test]
async fn shared_policy_ordinary_false_and_lease_lost_settlements_remain_exact() {
    for (fact, result) in [
        (RouteFact::Completed, core::SettlementResult::Ack(false)),
        (RouteFact::Pending, core::SettlementResult::Defer(false)),
        (
            RouteFact::Retry,
            core::SettlementResult::Retry(core::RetryResult::LeaseLost),
        ),
        (
            RouteFact::Permanent,
            core::SettlementResult::DeadLetter(false),
        ),
    ] {
        let (attempt, mut port) = supplied_attempt(None, fact);
        port.settlement_result = Some(result);
        run_policy(
            attempt,
            port.clone(),
            tokio_util::sync::CancellationToken::new(),
        )
        .await
        .unwrap();
        let snapshot = port.owner.snapshot();
        let settlement = snapshot.settlement.unwrap();
        assert_eq!(
            settlement.knowledge,
            core::SettlementKnowledge::ReceiptKnown(result)
        );
        assert_eq!(
            settlement.returned,
            Some(core::SettlementReturned::Outcome(result))
        );
        assert_eq!(port.commands.lock().unwrap().len(), 1);
    }
}

#[tokio::test]
async fn shared_policy_ordinary_invalid_template_never_routes_or_renews() {
    let (attempt, mut port) = supplied_attempt(Some("<message>"), RouteFact::Completed);
    port.settlement_result = Some(core::SettlementResult::DeadLetter(false));
    run_policy(
        attempt,
        port.clone(),
        tokio_util::sync::CancellationToken::new(),
    )
    .await
    .unwrap();
    let commands = port.commands.lock().unwrap();
    assert_eq!(commands.len(), 1);
    assert!(
        matches!(&commands[0], core::SettlementCommand::DeadLetter { reason, error }
            if reason == "invalid-template" && error == "invalid durable MIX stanza template")
    );
    assert!(port.events.lock().unwrap().is_empty());
    assert_eq!(port.owner.snapshot().renewal.issued, 0);
}

#[tokio::test]
async fn shared_policy_ordinary_route_shutdown_never_settles() {
    let (attempt, port) = supplied_attempt(None, RouteFact::Shutdown);
    run_policy(
        attempt,
        port.clone(),
        tokio_util::sync::CancellationToken::new(),
    )
    .await
    .unwrap();
    assert!(port.commands.lock().unwrap().is_empty());
    assert!(port.owner.snapshot().renewal_scope_closed);
    assert_eq!(
        port.owner.snapshot().terminal,
        Some(core::TerminalReason::Cancelled)
    );
}

#[tokio::test(start_paused = true)]
async fn shared_policy_ordinary_pending_renewal_drops_before_close_and_settlement() {
    let (attempt, mut port) = supplied_attempt(None, RouteFact::Completed);
    port.wait_route = true;
    let mut run = Box::pin(run_policy(
        attempt,
        port.clone(),
        tokio_util::sync::CancellationToken::new(),
    ));
    assert!(futures::poll!(&mut run).is_pending());
    tokio::time::advance(MIX_OUTBOX_LEASE_RENEWAL_INTERVAL).await;
    assert!(futures::poll!(&mut run).is_pending());
    assert_eq!(
        *port.events.lock().unwrap(),
        vec!["route started", "renewal started"]
    );
    port.release_route.notify_one();
    run.await.unwrap();
    assert_eq!(
        *port.events.lock().unwrap(),
        vec![
            "route started",
            "renewal started",
            "route dropped",
            "renewal dropped"
        ]
    );
    assert_eq!(
        *port.commands.lock().unwrap(),
        vec![core::SettlementCommand::Ack]
    );
    let snapshot = port.owner.snapshot();
    assert!(snapshot.renewal_scope_closed);
    assert!(snapshot.renewal.pending);
    assert_eq!(
        snapshot.renewal.knowledge,
        core::RenewalKnowledge::NotEntered
    );
    assert_eq!(snapshot.renewal.returned, None);
}

#[tokio::test(start_paused = true)]
async fn shared_policy_ordinary_renewal_loss_and_error_do_not_become_route_retry() {
    for fact in [RenewalFact::Lost, RenewalFact::Error] {
        let (attempt, mut port) = supplied_attempt(None, RouteFact::Completed);
        port.wait_route = true;
        port.renewal = fact;
        let mut run = Box::pin(run_policy(
            attempt,
            port.clone(),
            tokio_util::sync::CancellationToken::new(),
        ));
        assert!(futures::poll!(&mut run).is_pending());
        tokio::time::advance(MIX_OUTBOX_LEASE_RENEWAL_INTERVAL).await;
        let result = run.await;
        assert!(port.commands.lock().unwrap().is_empty());
        assert!(port.owner.snapshot().renewal_scope_closed);
        match fact {
            RenewalFact::Lost => {
                result.unwrap();
                assert!(port.owner.snapshot().lease_lost);
                assert_eq!(
                    port.owner.snapshot().renewal.returned,
                    Some(core::RenewalReturned::Outcome(false))
                );
            }
            RenewalFact::Error => {
                assert_eq!(result.unwrap_err().to_string(), "renewal failed");
                assert_eq!(
                    port.owner.snapshot().terminal,
                    Some(core::TerminalReason::BackendFailure)
                );
            }
            RenewalFact::Pending => unreachable!(),
        }
    }
}

#[tokio::test(start_paused = true)]
async fn shared_policy_ordinary_outer_drop_keeps_pending_knowledge_without_compensation() {
    let (attempt, mut port) = supplied_attempt(None, RouteFact::Completed);
    port.wait_route = true;
    let mut run = Box::pin(run_policy(
        attempt,
        port.clone(),
        tokio_util::sync::CancellationToken::new(),
    ));
    assert!(futures::poll!(&mut run).is_pending());
    tokio::time::advance(MIX_OUTBOX_LEASE_RENEWAL_INTERVAL).await;
    assert!(futures::poll!(&mut run).is_pending());
    drop(run);
    assert!(port.commands.lock().unwrap().is_empty());
    assert!(port.events.lock().unwrap().contains(&"route dropped"));
    assert!(port.events.lock().unwrap().contains(&"renewal dropped"));
    let snapshot = port.owner.snapshot();
    assert!(!snapshot.renewal_scope_closed);
    assert!(snapshot.renewal.pending);
    assert_eq!(snapshot.renewal.returned, None);
    assert_eq!(snapshot.terminal, Some(core::TerminalReason::Cancelled));
}

#[tokio::test(start_paused = true)]
async fn shared_policy_ordinary_cancellation_and_deadline_destroy_children_without_settlement() {
    for deadline in [false, true] {
        let (attempt, mut port) = supplied_attempt(None, RouteFact::Completed);
        port.wait_route = true;
        let cancel = tokio_util::sync::CancellationToken::new();
        let mut run = Box::pin(run_policy(attempt, port.clone(), cancel.clone()));
        assert!(futures::poll!(&mut run).is_pending());
        tokio::time::advance(MIX_OUTBOX_LEASE_RENEWAL_INTERVAL).await;
        assert!(futures::poll!(&mut run).is_pending());
        if deadline {
            tokio::time::advance(MIX_OUTBOX_ATTEMPT_DEADLINE - MIX_OUTBOX_LEASE_RENEWAL_INTERVAL)
                .await;
        } else {
            cancel.cancel();
        }
        run.await.unwrap();
        assert!(port.commands.lock().unwrap().is_empty());
        assert!(port.events.lock().unwrap().contains(&"route dropped"));
        assert!(port.events.lock().unwrap().contains(&"renewal dropped"));
        assert!(port.owner.snapshot().renewal_scope_closed);
        assert_eq!(
            port.owner.snapshot().terminal,
            Some(if deadline {
                core::TerminalReason::TimedOut
            } else {
                core::TerminalReason::Cancelled
            })
        );
    }
}
