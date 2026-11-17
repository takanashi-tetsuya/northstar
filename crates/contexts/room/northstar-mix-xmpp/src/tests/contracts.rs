use super::*;
use northstar_room_application::mix_service::foreground;
use northstar_room_core::mix_iq_relay::MixIqRelayIndex;

pub async fn local_and_cluster_contracts() {
    for (label, completion, boundary) in [
        (
            "socket_transfer",
            MixTransportCompletion::SocketFenced {
                connection_id: Uuid::from_u128(101),
            },
            mix_worker::TransferBoundary::SocketFenced(Uuid::from_u128(101)),
        ),
        (
            "sm_transfer",
            MixTransportCompletion::SmPersisted {
                session_id: Uuid::from_u128(102),
            },
            mix_worker::TransferBoundary::SmPersisted(Uuid::from_u128(102)),
        ),
        (
            "bosh_transfer",
            MixTransportCompletion::BoshPersisted {
                session_id: Uuid::from_u128(103),
            },
            mix_worker::TransferBoundary::BoshPersisted(Uuid::from_u128(103)),
        ),
    ] {
        let (owner, route) = owner_fixture::route(false);
        let request = route.local_request("bob@local.test/phone".into()).unwrap();
        let (tx, mut rx) = tokio::sync::mpsc::channel(1);
        let sender = northstar_stream::outbound::OutboundSender::new(tx);
        let disconnect = CancellationToken::new();
        let mut waiting = Box::pin(try_send_local_durable_mix_observed(
            &sender,
            &disconnect,
            &request,
        ));
        assert!(futures::poll!(&mut waiting).is_pending(), "{label}");
        let item = rx.try_recv().unwrap();
        assert_eq!(item.stanza, request.stanza(), "{label}");
        assert_eq!(item.mix_delivery(), Some(row(false).source), "{label}");
        assert!(owner.snapshot().local[0].started, "{label}");
        assert!(owner.snapshot().local[0].enqueued, "{label}");
        assert!(
            owner.snapshot().transfer.is_none(),
            "{label}: enqueue is not a transfer"
        );
        item.complete_mix_handoff(completion);
        assert_eq!(waiting.await.unwrap(), completion, "{label}");
        assert_eq!(
            owner.snapshot().transfer,
            Some(mix_worker::TransferFact {
                target: "bob@local.test/phone".into(),
                boundary
            }),
            "{label}"
        );
        assert!(!disconnect.is_cancelled(), "{label}");
        assert!(
            matches!(
                try_send_local_durable_mix_observed(&sender, &disconnect, &request).await,
                Err(local_delivery::MixLocalTransportFailure::Observation(_))
            ),
            "{label}"
        );
        assert!(
            rx.try_recv().is_err(),
            "{label}: repeated request cannot enqueue"
        );
    }
    for label in [
        "cancelled_wait",
        "closed_handoff",
        "full_queue",
        "closed_queue",
    ] {
        let (owner, route) = owner_fixture::route(false);
        let request = route.local_request("bob@local.test/phone".into()).unwrap();
        let (tx, mut rx) = tokio::sync::mpsc::channel(1);
        let sender = northstar_stream::outbound::OutboundSender::new(tx);
        let disconnect = CancellationToken::new();
        if label == "full_queue" {
            sender.try_send("predecessor".into()).unwrap();
        }
        if label == "closed_queue" {
            rx.close();
        }
        let mut waiting = Box::pin(try_send_local_durable_mix_observed(
            &sender,
            &disconnect,
            &request,
        ));
        if matches!(label, "full_queue" | "closed_queue") {
            let error = waiting.await.unwrap_err();
            assert_eq!(
                error,
                if label == "full_queue" {
                    local_delivery::MixLocalTransportFailure::QueueFull
                } else {
                    local_delivery::MixLocalTransportFailure::QueueClosed
                },
                "{label}"
            );
        } else {
            assert!(futures::poll!(&mut waiting).is_pending(), "{label}");
            let item = rx.try_recv().unwrap();
            if label == "closed_handoff" {
                drop(item);
                assert_eq!(
                    waiting.await.unwrap_err(),
                    local_delivery::MixLocalTransportFailure::HandoffClosed,
                    "{label}"
                );
            } else {
                drop(waiting);
                assert_eq!(owner.snapshot().local[0].returned, None, "{label}");
                drop(item);
            }
        }
        assert!(disconnect.is_cancelled(), "{label}");
        assert!(sender.backpressure_disconnect().is_cancelled(), "{label}");
        assert!(owner.snapshot().transfer.is_none(), "{label}");
        assert!(owner.snapshot().settlement.is_none(), "{label}");
    }

    for (label, handoff, boundary) in [
        (
            "cluster_socket",
            ClusterMixHandoff::SocketFenced,
            mix_worker::TransferBoundary::ClusterSocketFenced,
        ),
        (
            "cluster_sm",
            ClusterMixHandoff::SmPersisted,
            mix_worker::TransferBoundary::ClusterSmPersisted,
        ),
        (
            "cluster_bosh",
            ClusterMixHandoff::BoshPersisted,
            mix_worker::TransferBoundary::ClusterBoshPersisted,
        ),
    ] {
        for acknowledged in [false, true] {
            let context = Context::new(1);
            *context.state.receipt.lock().unwrap() = NodeDeliveryReceipt {
                acknowledged,
                delivered: true,
                mix_handoff: Some(handoff),
                ..Default::default()
            };
            let (owner, route) = owner_fixture::route(false);
            let request = route.cluster_request("node-b".into()).unwrap();
            let receipt = send_claimed_cluster_mix(context.as_ref(), &request)
                .await
                .unwrap();
            assert_eq!(receipt.acknowledged, acknowledged, "{label}");
            assert!(owner.snapshot().cluster[0].returned, "{label}");
            assert_eq!(
                owner.snapshot().transfer.as_ref().map(|fact| fact.boundary),
                acknowledged.then_some(boundary),
                "{label}"
            );
            assert_eq!(
                context.state.calls(),
                vec![Call::Cluster(
                    "node-b".into(),
                    "bob@local.test".into(),
                    request.stanza().into(),
                    Some(row(false).source),
                    1
                )],
                "{label}"
            );
        }
    }
    let context = Context::new(1);
    *context.state.receipt.lock().unwrap() = NodeDeliveryReceipt {
        acknowledged: true,
        delivered: true,
        ..Default::default()
    };
    let (owner, route) = owner_fixture::route(false);
    let request = route.cluster_request("node-b".into()).unwrap();
    send_claimed_cluster_mix(context.as_ref(), &request)
        .await
        .unwrap();
    assert!(
        owner.snapshot().transfer.is_none(),
        "delivered_boolean_does_not_transfer"
    );

    // Route through the real adapter: archive must finish before a sorted,
    // lazy capability lookup can enqueue the one exact recipient source.
    for (label, mismatch) in [
        ("archive_then_sorted_local_handoff", false),
        ("archive_receipt_mismatch", true),
    ] {
        let context = Context::new(1);
        context
            .state
            .archive_mismatch
            .store(mismatch, Ordering::SeqCst);
        let (tx, mut rx) = tokio::sync::mpsc::channel(2);
        let session = LocalSession {
            sender: northstar_stream::outbound::OutboundSender::new(tx),
            disconnect: CancellationToken::new(),
        };
        *context.state.sessions.lock().unwrap() = vec![
            ("bob@local.test/z".into(), session.clone()),
            ("bob@local.test/a".into(), session),
        ];
        let owned = outbox::OwnedAttempt::new(owner_fixture::attempt(true));
        let owner = owned.observation();
        let mut run = process_mix_outbox_work(
            context.clone(),
            MixOutboxWork::Delivery(owned),
            CancellationToken::new(),
        );
        if mismatch {
            let (_, result) = run.await;
            assert!(result.is_err(), "{label}");
            assert!(rx.try_recv().is_err(), "archive_receipt_mismatch");
            assert!(
                !context.state.calls().iter().any(|call| matches!(
                    call,
                    Call::Capability(_) | Call::Cluster(..) | Call::Settle(..)
                )),
                "archive_receipt_mismatch"
            );
        } else {
            let polled = futures::poll!(&mut run);
            assert!(polled.is_pending(), "{label}: {polled:?}");
            assert_eq!(
                context.state.admission.available_permits(),
                1,
                "local_wait_releases_database_permit"
            );
            let item = rx.try_recv().unwrap();
            assert_eq!(item.mix_delivery(), Some(row(true).source));
            assert_eq!(
                item.stanza,
                addressed_mix_delivery(&row(true).stanza, "bob@local.test").unwrap()
            );
            assert!(rx.try_recv().is_err());
            item.complete_mix_handoff(MixTransportCompletion::BoshPersisted {
                session_id: Uuid::from_u128(103),
            });
            run.await.1.unwrap();
            let calls = context.state.calls();
            assert!(matches!(&calls[2], Call::Archive(_, 0)));
            assert_eq!(calls[3], Call::Sessions("bob@local.test".into()));
            assert_eq!(calls[4], Call::Capability("bob@local.test/a".into()));
            assert_eq!(calls.len(), 5, "only_selected_resource_is_queried");
            assert!(owner.snapshot().renewal_scope_closed);
            assert_eq!(
                owner.snapshot().route_returned,
                Some(mix_worker::RouteResult::Transferred)
            );
            assert!(
                owner.snapshot().settlement.is_none(),
                "transferred_source_never_acknowledged"
            );
        }
        let calls = context.state.calls();
        let Call::Archive(command, 0) = &calls[2] else {
            panic!("{label}: missing observed archive turn");
        };
        let stored = mix_worker::ArchiveResult::Stored(command.personal_archive_id);
        let snapshot = owner.snapshot();
        assert_eq!(
            snapshot.archive.knowledge,
            mix_worker::ArchiveKnowledge::ReceiptKnown(stored),
            "{label}: the commit receipt uses the requested personal archive ID"
        );
        assert_eq!(
            snapshot.archive.returned,
            Some(mix_worker::ArchiveReturned::Outcome(if mismatch {
                mix_worker::ArchiveResult::Replay(Uuid::from_u128(83))
            } else {
                stored
            })),
            "{label}: compare the actual return with the recorded commit receipt"
        );
        assert_eq!(snapshot.aborted, mismatch, "{label}");
    }
}

pub async fn shared_policy_contracts() {
    use mix_worker::{RouteResult, SettlementCommand as Command, TerminalReason};
    let context = Context::new(1);
    let claim = claim_mix_outbox_work(
        context.clone(),
        CancellationToken::new(),
        CancellationToken::new(),
        MixOutboxQueue::Delivery,
        1,
    );
    drop(claim);
    assert!(
        context.state.calls().is_empty(),
        "unpolled_claim_has_no_effect"
    );
    let owned = outbox::OwnedAttempt::new(owner_fixture::attempt(false));
    let owner = owned.observation();
    let work = process_mix_outbox_work(
        context.clone(),
        MixOutboxWork::Delivery(owned),
        CancellationToken::new(),
    );
    drop(work);
    assert!(
        context.state.calls().is_empty(),
        "unpolled_attempt_has_no_effect"
    );
    assert_eq!(owner.snapshot().route, mix_worker::RoutePhase::Unprepared);
    assert_eq!(owner.snapshot().terminal, Some(TerminalReason::Cancelled));
    let owned = outbox::OwnedAttempt::new(owner_fixture::attempt(false));
    let owner = owned.observation();
    let cancel = CancellationToken::new();
    cancel.cancel();
    process_mix_outbox_work(context.clone(), MixOutboxWork::Delivery(owned), cancel)
        .await
        .1
        .unwrap();
    assert!(
        context.state.calls().is_empty(),
        "production_wrapper_preserves_cancellation"
    );
    assert_eq!(owner.snapshot().terminal, Some(TerminalReason::Cancelled));
    for (label, answer, route_result, command) in [
        (
            "worker_ack",
            Answer::Worker,
            RouteResult::CompletedByWorker,
            Command::Ack,
        ),
        (
            "pending_defer",
            Answer::Pending,
            RouteResult::Pending,
            Command::Defer { delay_seconds: 30 },
        ),
        (
            "permanent_dead_letter",
            Answer::Permanent,
            RouteResult::Permanent,
            Command::DeadLetter {
                reason: "policy-cancelled".into(),
                error: "blocked".into(),
            },
        ),
        (
            "transient_retry",
            Answer::Retry,
            RouteResult::Retry,
            Command::Retry {
                error: "route failed".into(),
            },
        ),
    ] {
        for matched in [true, false] {
            let (owner, port, mut run) = policy_run(row(false), answer, CancellationToken::new());
            port.matched.store(matched, Ordering::SeqCst);
            let warnings = Warnings::default();
            warnings.drive(&mut run).await.unwrap();
            let expected = settlement_result(&command, matched);
            assert_eq!(
                port.calls(),
                vec![
                    PolicyCall::Route(
                        Box::new(row(false)),
                        addressed_mix_delivery(&row(false).stanza, "bob@local.test").unwrap()
                    ),
                    PolicyCall::Settle(row(false).source, 12, command.clone()),
                ],
                "{label}"
            );
            let snapshot = owner.snapshot();
            assert_eq!(snapshot.route_returned, Some(route_result), "{label}");
            assert!(snapshot.renewal_scope_closed, "{label}");
            let settlement = snapshot.settlement.unwrap();
            assert_eq!(
                settlement.knowledge,
                mix_worker::SettlementKnowledge::ReceiptKnown(expected),
                "{label}"
            );
            assert_eq!(
                settlement.returned,
                Some(mix_worker::SettlementReturned::Outcome(expected)),
                "{label}"
            );
            assert_eq!(
                snapshot.terminal,
                Some(TerminalReason::Completed),
                "{label}"
            );
            if !matched {
                let warnings = warnings.0.lock().unwrap();
                assert_eq!(warnings.len(), 1, "{label}");
                for (name, value) in [
                    ("delivery_id", row(false).source.delivery_id),
                    ("event_id", row(false).event_id),
                    ("channel_id", row(false).channel_id),
                ] {
                    assert_eq!(
                        warnings[0].get(name),
                        Some(&value.to_string()),
                        "{label}: exact warning identity"
                    );
                }
                let message = warnings[0].get("message").unwrap();
                assert!(
                    message.contains(if matches!(command, Command::DeadLetter { .. }) {
                        "NotMoved"
                    } else {
                        "exact source fence"
                    }),
                    "{label}"
                );
            }
        }
    }
    for (label, answer) in [
        ("transport_transfer", Answer::Transfer),
        ("route_shutdown", Answer::Shutdown),
    ] {
        let (owner, port, run) = policy_run(row(false), answer, CancellationToken::new());
        run.await.unwrap();
        assert_eq!(port.calls().len(), 1, "{label}");
        assert!(owner.snapshot().settlement.is_none(), "{label}");
        assert_eq!(
            owner.snapshot().terminal,
            Some(if matches!(answer, Answer::Shutdown) {
                TerminalReason::Cancelled
            } else {
                TerminalReason::Completed
            }),
            "{label}"
        );
    }
    for (label, renewal, timed_out, cancel_route) in [
        ("lost_lease", Renewal::Lost, false, false),
        ("renewal_error", Renewal::Error, false, false),
        ("effect_deadline", Renewal::Pending, true, false),
        ("effect_cancelled", Renewal::Pending, false, true),
    ] {
        let cancel = CancellationToken::new();
        let (owner, port, mut run) = policy_run(row(false), Answer::Worker, cancel.clone());
        *port.route_gate.lock().unwrap() = Some(Arc::new(tokio::sync::Semaphore::new(0)));
        *port.renewal.lock().unwrap() = renewal;
        assert!(futures::poll!(&mut run).is_pending(), "{label}");
        tokio::time::advance(Duration::from_secs(10)).await;
        if timed_out || cancel_route {
            assert!(futures::poll!(&mut run).is_pending(), "{label}");
            if cancel_route {
                cancel.cancel();
            } else {
                tokio::time::advance(Duration::from_secs(10)).await;
            }
        }
        let warnings = Warnings::default();
        let result = warnings.drive(&mut run).await;
        if timed_out || matches!(renewal, Renewal::Lost) {
            warnings.assert_row_identity(label);
        }
        if matches!(renewal, Renewal::Error) {
            assert_eq!(result.unwrap_err().to_string(), "renewal failed", "{label}");
        } else {
            result.unwrap();
        }
        let snapshot = owner.snapshot();
        assert!(snapshot.renewal_scope_closed, "{label}");
        assert!(snapshot.settlement.is_none(), "{label}");
        assert!(port.route_dropped.load(Ordering::SeqCst), "{label}");
        assert!(port.renewal_dropped.load(Ordering::SeqCst), "{label}");
        assert_eq!(port.permit.available_permits(), 1, "{label}");
        assert_eq!(
            snapshot.terminal,
            Some(if timed_out {
                TerminalReason::TimedOut
            } else if cancel_route {
                TerminalReason::Cancelled
            } else if matches!(renewal, Renewal::Error) {
                TerminalReason::BackendFailure
            } else {
                TerminalReason::Completed
            }),
            "{label}"
        );
        assert_eq!(
            snapshot.lease_lost,
            matches!(renewal, Renewal::Lost),
            "{label}"
        );
    }

    for matched in [true, false] {
        let mut invalid = row(false);
        invalid.stanza = "<message>".into();
        let (owner, port, mut run) = policy_run(invalid, Answer::Worker, CancellationToken::new());
        port.matched.store(matched, Ordering::SeqCst);
        let warnings = Warnings::default();
        warnings.drive(&mut run).await.unwrap();
        assert!(
            matches!(port.calls().as_slice(), [PolicyCall::Settle(source, 12, Command::DeadLetter { reason, error })]
            if *source == row(false).source && reason == "invalid-template" && error.contains("invalid durable MIX stanza template"))
        );
        assert_eq!(owner.snapshot().route, mix_worker::RoutePhase::Unprepared);
        if !matched {
            warnings.assert_row_identity("invalid_template_not_moved");
        }
    }

    let mut invalid = row(false);
    invalid.stanza = "<message>".into();
    let (owner, port, run) = policy_run(invalid, Answer::Worker, CancellationToken::new());
    port.settle_mismatch.store(true, Ordering::SeqCst);
    assert_eq!(
        run.await.unwrap_err().to_string(),
        "invalid-template settlement result kind mismatch",
        "invalid_template_rejects_foreign_result_kind"
    );
    assert_eq!(
        owner.snapshot().terminal,
        Some(TerminalReason::BackendFailure)
    );

    let (owner, port, mut run) = policy_run(row(false), Answer::Worker, CancellationToken::new());
    let release = Arc::new(tokio::sync::Semaphore::new(0));
    *port.route_gate.lock().unwrap() = Some(release.clone());
    assert!(futures::poll!(&mut run).is_pending());
    tokio::time::advance(Duration::from_secs(10)).await;
    assert!(futures::poll!(&mut run).is_pending());
    assert_eq!(
        owner.snapshot().renewal.issued,
        1,
        "matched_renewal_waits_ten_seconds"
    );
    assert_eq!(
        owner.snapshot().renewal.returned,
        Some(mix_worker::RenewalReturned::Outcome(true))
    );
    tokio::time::advance(Duration::from_secs(9)).await;
    assert!(futures::poll!(&mut run).is_pending());
    assert_eq!(
        owner.snapshot().renewal.issued,
        1,
        "matched_renewal_does_not_tick_immediately"
    );
    release.add_permits(1);
    run.await.unwrap();
    assert!(owner.snapshot().renewal_scope_closed);
    assert_eq!(owner.snapshot().terminal, Some(TerminalReason::Completed));

    let (owner, port, run) = policy_run(row(false), Answer::Worker, CancellationToken::new());
    port.settle_error.store(true, Ordering::SeqCst);
    assert_eq!(run.await.unwrap_err().to_string(), "settlement failed");
    assert_eq!(
        owner.snapshot().terminal,
        Some(TerminalReason::BackendFailure)
    );
    assert_eq!(port.calls().len(), 2);

    let calls = std::cell::Cell::new(0);
    assert!(finish_mix_delivery_owner(
        ChannelStanzaDeliveryOutcome::TransferredToRecoverableTransport,
        || {
            calls.set(calls.get() + 1);
            async { Ok(false) }
        }
    )
    .await
    .unwrap());
    assert_eq!(calls.get(), 0, "transfer_does_not_construct_ack");
    assert!(!finish_mix_delivery_owner(
        ChannelStanzaDeliveryOutcome::CompletedByClaimingWorker,
        || {
            calls.set(calls.get() + 1);
            async { Ok(false) }
        }
    )
    .await
    .unwrap());
    assert_eq!(calls.get(), 1, "worker_ack_preserves_false");
    let error = finish_mix_delivery_owner(
        ChannelStanzaDeliveryOutcome::CompletedByClaimingWorker,
        || async { anyhow::bail!("ack failed") },
    )
    .await
    .unwrap_err();
    assert_eq!(error.to_string(), "ack failed");
}

// A scoped subscriber records only the policy poll on this thread. It never
// installs global logging state or depends on another test's subscriber.
type Fields = std::collections::BTreeMap<String, String>;
#[derive(Clone, Default)]
pub struct Warnings(Arc<Mutex<Vec<Fields>>>);
struct Visitor(Fields);
impl tracing::field::Visit for Visitor {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        self.0.insert(field.name().into(), format!("{value:?}"));
    }
}
impl tracing::Subscriber for Warnings {
    fn enabled(&self, metadata: &tracing::Metadata<'_>) -> bool {
        *metadata.level() == tracing::Level::WARN
    }
    fn new_span(&self, _attributes: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }
    fn record(&self, _span: &tracing::span::Id, _values: &tracing::span::Record<'_>) {}
    fn record_follows_from(&self, _span: &tracing::span::Id, _follows: &tracing::span::Id) {}
    fn event(&self, event: &tracing::Event<'_>) {
        let mut visitor = Visitor(Fields::new());
        event.record(&mut visitor);
        self.0.lock().unwrap().push(visitor.0);
    }
    fn enter(&self, _span: &tracing::span::Id) {}
    fn exit(&self, _span: &tracing::span::Id) {}
}
impl Warnings {
    pub fn assert_row_identity(&self, label: &str) {
        let warnings = self.0.lock().unwrap();
        assert_eq!(warnings.len(), 1, "{label}");
        for (name, value) in [
            ("delivery_id", row(false).source.delivery_id),
            ("event_id", row(false).event_id),
            ("channel_id", row(false).channel_id),
        ] {
            assert_eq!(
                warnings[0].get(name),
                Some(&value.to_string()),
                "{label}: exact warning identity"
            );
        }
    }
    pub async fn drive(&self, run: &mut outbox::AttemptRun) -> Result<()> {
        let dispatcher = tracing::Dispatch::new(self.clone());
        futures::future::poll_fn(|context| {
            tracing::dispatcher::with_default(&dispatcher, || {
                std::future::Future::poll(std::pin::Pin::new(&mut *run), context)
            })
        })
        .await
    }
}

struct Observer {
    state: Arc<State>,
    present: bool,
    reject: bool,
}
impl MixFrameObserver for Observer {
    fn enter(&self, stage: MixFrameStage) {
        self.state.record(Call::Frame(stage));
    }
    fn mix_foreground(
        &self,
        prepare: Box<
            dyn FnOnce() -> Result<foreground::PreparedIngress, foreground::Rejected> + '_,
        >,
    ) -> Result<Option<foreground::Observation>, foreground::Rejected> {
        self.state.record(Call::Register);
        if self.reject {
            return Err(foreground::Rejected::Input);
        }
        if !self.present {
            return Ok(None);
        }
        let owner = foreground::Observation::new(prepare()?);
        *self.state.foreground_owner.lock().unwrap() = Some(owner.clone());
        Ok(Some(owner))
    }
}
struct Host {
    context: Arc<Context>,
    relay: MixIqRelayIndex,
}
struct Relay;
impl MixIqRelayRoutePort for Relay {
    async fn deliver(&self, _recipient: &str, _stanza: String) {
        panic!("unexpected IQ relay");
    }
}
impl MixHost for Host {
    type Repository = Repository;
    type Session = LocalSession;
    type Federation = Federation;
    type IqRelayRoute = Relay;
    type OutboxContext = Context;
    fn mix_service(&self) -> &MixService<Repository> {
        &self.context.service
    }
    fn federation_outbox(&self) -> &Federation {
        &self.context.federation
    }
    fn local_domain(&self) -> &str {
        "local.test"
    }
    fn server_name(&self) -> &str {
        "owner tests"
    }
    fn pending_mix_iq(&self) -> &MixIqRelayIndex {
        &self.relay
    }
    fn federation_domain_allowed(&self, _domain: &str) -> bool {
        true
    }
    fn mix_muc_mirror_enabled(&self) -> bool {
        false
    }
    fn xmpp_extension_enabled(&self, _id: northstar_xep_core::XepId) -> bool {
        true
    }
    fn session_entries_for(&self, _jid: &str) -> Vec<(String, LocalSession)> {
        panic!("unexpected live route");
    }
    fn sessions_for(&self, _jid: &str) -> Vec<LocalSession> {
        panic!("unexpected sessions");
    }
    fn mix_iq_relay_route(&self) -> Relay {
        Relay
    }
    fn mix_outbox_context(&self) -> Context {
        self.context.as_ref().clone()
    }
    fn session_mix_capability(&self, _full_jid: &str) -> MixSessionCapability {
        panic!("unexpected capability lookup");
    }
    fn validate_routed_message(&self, _root: Node<'_, '_>) -> Result<(), &'static str> {
        Ok(())
    }
    fn local_mix_presence_route_is_current(
        &self,
        _full_jid: &str,
        _expected_connection_id: Uuid,
        _expected_gate: &Arc<tokio::sync::Mutex<()>>,
        _require_available: bool,
    ) -> bool {
        panic!("unexpected presence");
    }
    async fn deliver_roster_change(
        &self,
        _owner_id: Uuid,
        _owner: &str,
        _change: &northstar_roster_core::RosterChange,
        _participant_id: Option<&str>,
    ) -> Result<()> {
        panic!("unexpected roster");
    }
}
struct Session {
    host: Arc<Host>,
    observer: Observer,
    gate: Arc<tokio::sync::Mutex<()>>,
    suppressed: dashmap::DashSet<String>,
}
impl MixSession for Session {
    type Host = Host;
    fn host(&self) -> &Arc<Host> {
        &self.host
    }
    fn user(&self) -> Option<MixSessionUser<'_>> {
        Some(MixSessionUser {
            id: Uuid::from_u128(81),
            username: "bob",
        })
    }
    fn full_jid(&self) -> Option<&str> {
        Some("bob@local.test/phone")
    }
    fn connection_id(&self) -> Uuid {
        Uuid::from_u128(84)
    }
    fn mix_presence_gate(&self) -> &Arc<tokio::sync::Mutex<()>> {
        &self.gate
    }
    fn mix_presence_fallback_suppressed(&self) -> &dashmap::DashSet<String> {
        &self.suppressed
    }
    fn frame_observer(&self) -> &dyn MixFrameObserver {
        &self.observer
    }
}

pub async fn ingress_contracts() {
    for (label, shared, retract, federated) in [
        ("c2s_originating_observer", false, false, false),
        ("shared_optional_observer", true, false, false),
        ("retraction_admission", true, true, false),
        ("federated_without_frame", false, false, true),
    ] {
        let context = Context::new(1);
        let host = Arc::new(Host {
            context: context.clone(),
            relay: MixIqRelayIndex::new(),
        });
        let session = Session {
            host: host.clone(),
            observer: Observer {
                state: context.state.clone(),
                present: true,
                reject: false,
            },
            gate: Arc::new(tokio::sync::Mutex::new(())),
            suppressed: dashmap::DashSet::new(),
        };
        let raw = format!("<message type='groupchat' id='message' from='bob@{}/phone' to='room@mix.local.test'>{}</message>",
            if federated { "remote.test" } else { "local.test" },
            if retract { format!("<retract xmlns='urn:xmpp:mix:misc:0' id='{}'/>", Uuid::from_u128(95)) } else { "<body>ordinary</body><origin-id xmlns='urn:xmpp:sid:0' id='origin'/>".into() });
        let document = Document::parse(&raw).unwrap();
        if federated {
            assert!(
                federated_mix_message(host, "remote.test", raw.clone())
                    .await
                    .unwrap(),
                "{label}"
            );
        } else if shared {
            let result = process_channel_message(
                &host,
                "bob@local.test",
                "bob@local.test/phone",
                &raw,
                Some(&session.observer),
            )
            .await;
            if retract {
                assert!(
                    result.unwrap().unwrap().contains("item-not-found"),
                    "{label}"
                );
            } else {
                assert_eq!(
                    result.unwrap_err().to_string(),
                    "recorded observed store",
                    "{label}"
                );
            }
        } else {
            let other =
                "<message to='room@remote.test' type='groupchat'><body>ignored</body></message>";
            let other_document = Document::parse(other).unwrap();
            assert!(
                session::try_mix_message(&session, other_document.root_element(), other)
                    .await
                    .unwrap()
                    .is_none(),
                "{label}"
            );
            assert!(
                context.state.calls().is_empty(),
                "{label}: target selection precedes policy"
            );
            let result = session::try_mix_message(&session, document.root_element(), &raw).await;
            let Err(error) = result else {
                panic!("{label}: observed store must propagate its error");
            };
            assert_eq!(error.to_string(), "recorded observed store", "{label}");
        }
        let mut expected = vec![];
        if !federated {
            expected.push(Call::Frame(MixFrameStage::Policy));
            if !shared {
                expected.push(Call::Frame(MixFrameStage::Policy));
            }
        }
        expected.push(Call::Channel("mix.local.test".into(), "room".into()));
        if !federated && !retract {
            expected.push(Call::Register);
        }
        if !retract {
            expected.push(Call::Replay(!federated));
        }
        let actor = if federated {
            "bob@remote.test"
        } else {
            "bob@local.test"
        };
        expected.push(Call::Member(Uuid::from_u128(93), actor.into()));
        expected.push(Call::Preference(Uuid::from_u128(93), actor.into()));
        if !federated {
            expected.push(Call::Frame(MixFrameStage::Admission));
        }
        expected.push(if retract {
            Call::Retract(Uuid::from_u128(93), actor.into(), Uuid::from_u128(95))
        } else {
            Call::Store(!federated)
        });
        if federated {
            expected.push(Call::Federation(
                false,
                "remote.test".into(),
                message::message_error(
                    "message",
                    "room@mix.local.test",
                    "bob@remote.test/phone",
                    "auth",
                    "forbidden",
                ),
                1,
            ));
        }
        assert_eq!(context.state.calls(), expected, "{label}");
    }
    for (label, replay) in [
        (
            "authenticated_replay_skips_membership",
            MixBusinessReplay::Replay(Uuid::from_u128(70)),
        ),
        ("conflict_skips_membership", MixBusinessReplay::Conflict),
    ] {
        let context = Context::new(1);
        *context.state.replay.lock().unwrap() = replay;
        let host = Arc::new(Host {
            context: context.clone(),
            relay: MixIqRelayIndex::new(),
        });
        let session = Session {
            host,
            observer: Observer {
                state: context.state.clone(),
                present: true,
                reject: false,
            },
            gate: Arc::new(tokio::sync::Mutex::new(())),
            suppressed: dashmap::DashSet::new(),
        };
        let raw = "<message type='groupchat' id='message' to='room@mix.local.test'><body>ordinary</body><origin-id xmlns='urn:xmpp:sid:0' id='origin'/></message>";
        let document = Document::parse(raw).unwrap();
        let action = session::try_mix_message(&session, document.root_element(), raw)
            .await
            .unwrap();
        if matches!(replay, MixBusinessReplay::Replay(_)) {
            assert!(matches!(action, Some(MixAction::None)), "{label}");
        } else {
            assert!(
                matches!(action, Some(MixAction::Send(xml)) if xml.contains("conflict")),
                "{label}"
            );
        }
        assert_eq!(
            context.state.calls(),
            vec![
                Call::Frame(MixFrameStage::Policy),
                Call::Frame(MixFrameStage::Policy),
                Call::Channel("mix.local.test".into(), "room".into()),
                Call::Register,
                Call::Replay(true)
            ],
            "{label}"
        );
    }
    for (label, reject) in [
        ("registration_error_propagates", true),
        ("absent_frame_uses_compatibility", false),
    ] {
        let context = Context::new(1);
        let host = Arc::new(Host {
            context: context.clone(),
            relay: MixIqRelayIndex::new(),
        });
        let observer = Observer {
            state: context.state.clone(),
            present: false,
            reject,
        };
        let raw = "<message type='groupchat' id='message' to='room@mix.local.test'><body>ordinary</body><origin-id xmlns='urn:xmpp:sid:0' id='origin'/></message>";
        let result = process_channel_message(
            &host,
            "bob@local.test",
            "bob@local.test/phone",
            raw,
            Some(&observer),
        )
        .await;
        let mut expected = vec![
            Call::Frame(MixFrameStage::Policy),
            Call::Channel("mix.local.test".into(), "room".into()),
            Call::Register,
        ];
        if reject {
            assert!(result.unwrap_err().is::<foreground::Rejected>(), "{label}");
        } else {
            assert!(result.unwrap().unwrap().contains("forbidden"), "{label}");
            expected.extend([
                Call::Replay(false),
                Call::Member(Uuid::from_u128(93), "bob@local.test".into()),
                Call::Preference(Uuid::from_u128(93), "bob@local.test".into()),
                Call::Frame(MixFrameStage::Admission),
                Call::Store(false),
            ]);
        }
        assert_eq!(context.state.calls(), expected, "{label}");
    }
}
