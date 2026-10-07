//! Ordinary controls for the finite MIX owner adapter.
use super::*;
fn fixed(n: u128) -> wire::Id {
    wire::Id(Uuid::from_u128(n))
}
fn text<const N: usize>(s: &str) -> wire::Text<N> {
    wire::Text::new(s).unwrap()
}
fn claim(token: u128) -> wire::ClaimInput {
    wire::ClaimInput {
        limit: 1,
        max_bytes: 4096,
        lease_token: fixed(token),
        attempt_count: 0,
        route_wake_generation: 1,
        commit: wire::CommitCut::Complete,
    }
}
fn initial() -> wire::DeliveryRow<wire::Id> {
    wire::DeliveryRow {
        source: wire::MixSource {
            delivery_id: fixed(12),
            lease_token: fixed(13),
        },
        event_id: fixed(9),
        channel_id: fixed(10),
        channel_jid: text("c@mix.example.test"),
        participant_id: fixed(11),
        recipient_jid: text("u@example.test"),
        recipient_nick: wire::Nullable::Null(()),
        stanza: text("<message><body>ordinary</body></message>"),
        authoritative_stanza_id: wire::Nullable::Value(fixed(9)),
        archive: true,
        encrypted: false,
        attempt_count: 0,
        route_wake_generation: 1,
    }
}
fn route(connection: u128, routable: bool, resource: &str) -> wire::RouteInput {
    wire::RouteInput {
        full_jid: text(&format!("u@example.test/{resource}")),
        user_id: fixed(4),
        connection_id: fixed(connection),
        auth_generation: 1,
        routable,
        disconnected: false,
        lifecycle: wire::Lifecycle::Active,
        caps: wire::CapsInput {
            connection_id: fixed(connection),
            generation: 3,
            verified_features: wire::List::new(vec![wire::CapabilityFeature::MixCore]).unwrap(),
        },
        provenance: if routable {
            wire::RouteProvenance::InitiallyPublished(wire::Empty {})
        } else {
            wire::RouteProvenance::ActivatedByAuth(wire::ActivatedRoute { frame_id: fixed(1) })
        },
    }
}
fn attempt(token: u128, targets: Vec<wire::RouteInput>) -> wire::WorkerAttemptInput {
    wire::WorkerAttemptInput {
        claim: claim(token),
        archive: wire::ArchiveInput {
            reply: wire::ArchiveReply::Replay(wire::ArchiveReplayInput {
                original_archive_id: fixed(71),
            }),
            commit: wire::CommitCut::Complete,
        },
        route: wire::RouteEnvironment {
            enabled_account_id: fixed(4),
            privacy_blocked: false,
            targets: wire::List::new(targets).unwrap(),
            queue_capacity: 1,
        },
    }
}
fn recorder() -> Recorder {
    let c = wire::Case {
        schema: text(wire::CASE_SCHEMA),
        case_id: text("ordinary-bridge-control"),
        adapter_contract: text(wire::ADAPTER_CONTRACT),
        composition: wire::Composition::MixDefer(wire::DeferInput {
            worker: wire::WorkerInput {
                origin: wire::ClaimOrigin::InitialDurableRow(initial()),
                attempt: attempt(13, Vec::new()),
            },
            settlement_commit: wire::CommitCut::Complete,
            updated: true,
        }),
    };
    let bytes = serde_json::to_vec(&c).unwrap();
    let validated = wire::decode(&bytes).unwrap();
    Arc::new(Mutex::new(wire::Recorder::new(&validated)))
}
fn archive_id(owner: &mix_worker::Observation) -> Uuid {
    match owner.snapshot().archive.returned {
        Some(mix_worker::ArchiveReturned::Outcome(mix_worker::ArchiveResult::Replay(id))) => id,
        other => panic!("actual archive return is not Replay: {other:?}"),
    }
}
#[test]
fn staged_map_mapping_activation_and_caps_use_one_exact_route() {
    let recorder = recorder();
    let routes = RouteMap::new(recorder);
    let (handle, _receiver) = routes.install(&route(7, false, "auth"), 1).unwrap();
    let owner = || {
        wire::RouteLookupOwner::Auth(wire::OneId {
            id: map::id(Uuid::from_u128(1)),
        })
    };
    assert!(routes.lookup(owner(), "u@example.test").is_empty());
    assert!(handle.epoch_and_mapping(Some(19)));
    assert!(handle.activate());
    let entries = routes.lookup(owner(), "u@example.test");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].1.connection_id, handle.connection_id());
    assert!(Arc::ptr_eq(&entries[0].1.lifecycle, &handle.lifecycle()));
    assert_eq!(entries[0].1.user_agent_epoch, Some(19));
    assert_eq!(
        routes.classify(0, "u@example.test", &entries[0].0, &entries[0].1),
        MixSessionCapability::Supported
    );
    handle.disconnect().cancel();
    assert!(!handle.activate());
    assert_eq!(
        routes.classify(0, "u@example.test", &entries[0].0, &entries[0].1),
        MixSessionCapability::Unknown
    );
    // The second actual classification stays Unknown after exact stale
    // eviction; the bridge never reinstalls supplied caps to force success.
    assert_eq!(
        routes.classify(0, "u@example.test", &entries[0].0, &entries[0].1),
        MixSessionCapability::Unknown
    );
}
#[tokio::test]
async fn no_target_archives_then_closes_scope_and_defers_without_renewal() {
    let recorder = recorder();
    let bridge = Bridge::new("mix.example.test", recorder.clone()).unwrap();
    let row = bridge.initial_row(&initial()).unwrap();
    bridge
        .supply_defer(wire::CommitCut::Complete, true)
        .unwrap();
    let run = bridge
        .claim(
            row,
            &attempt(13, Vec::new()),
            ClaimSites::new(0).unwrap(),
            RouteMap::new(recorder),
        )
        .await
        .unwrap()
        .unwrap();
    let owner = run.observation();
    run.await.unwrap().unwrap();
    let actual = owner.snapshot();
    assert_eq!(archive_id(&owner), Uuid::from_u128(71));
    assert_eq!(
        actual.route_returned,
        Some(mix_worker::RouteResult::Pending)
    );
    assert!(actual.renewal_scope_closed);
    assert_eq!(actual.renewal.issued, 0);
    assert!(!actual.renewal.started);
    assert_eq!(
        actual.settlement.unwrap().returned,
        Some(mix_worker::SettlementReturned::Outcome(
            mix_worker::SettlementResult::Defer(true)
        ))
    );
    assert_eq!(actual.terminal, Some(mix_worker::TerminalReason::Completed));
}
#[tokio::test]
async fn dropped_pending_handoff_preserves_old_cancellation_and_replay_into_independent_replacement(
) {
    let recorder = recorder();
    let bridge = Bridge::new("mix.example.test", recorder.clone()).unwrap();
    let old_routes = RouteMap::new(recorder.clone());
    let old_input = route(7, true, "old");
    let (old, mut old_queue) = old_routes.install(&old_input, 1).unwrap();
    let row = bridge.initial_row(&initial()).unwrap();
    let mut first = Box::pin(
        bridge
            .claim(
                row.clone(),
                &attempt(13, vec![old_input]),
                ClaimSites::new(0).unwrap(),
                old_routes,
            )
            .await
            .unwrap()
            .unwrap(),
    );
    assert!(futures::poll!(first.as_mut()).is_pending());
    let item = old_queue.try_recv().unwrap();
    first.record_dequeued(&old, 0, &item);
    let first_owner = first.observation();
    assert!(!old.disconnect().is_cancelled());
    assert_eq!(first_owner.snapshot().local[0].returned, None);
    assert_eq!(first_owner.snapshot().settlement, None);
    drop(first);
    assert!(old.disconnect().is_cancelled());
    assert_eq!(
        first_owner.snapshot().terminal,
        Some(mix_worker::TerminalReason::Cancelled)
    );
    assert_eq!(first_owner.snapshot().local[0].returned, None);
    assert_eq!(archive_id(&first_owner), Uuid::from_u128(71));
    // Keep the actual old queued item alive through the replacement's lookup
    // and enqueue. It grants no new settlement right after owner destruction.
    let replacement_routes = RouteMap::new(recorder);
    let replacement_input = route(8, true, "new");
    let (replacement, mut replacement_queue) =
        replacement_routes.install(&replacement_input, 1).unwrap();
    assert!(!Arc::ptr_eq(&old.lifecycle(), &replacement.lifecycle()));
    assert!(!replacement.disconnect().is_cancelled());
    let replacement_row = bridge.replacement_row(&row, &claim(14)).unwrap();
    let mut second = Box::pin(
        bridge
            .claim(
                replacement_row,
                &attempt(14, vec![replacement_input]),
                ClaimSites::new(1).unwrap(),
                replacement_routes,
            )
            .await
            .unwrap()
            .unwrap(),
    );
    assert!(futures::poll!(second.as_mut()).is_pending());
    let replacement_item = replacement_queue.try_recv().unwrap();
    second.record_dequeued(&replacement, 1, &replacement_item);
    let second_owner = second.observation();
    assert_eq!(archive_id(&second_owner), archive_id(&first_owner));
    assert_eq!(
        replacement_item.mix_delivery().unwrap().lease_token,
        Uuid::from_u128(14)
    );
    assert_eq!(
        item.mix_delivery().unwrap().lease_token,
        Uuid::from_u128(13)
    );
    assert!(old.disconnect().is_cancelled());
    assert!(!replacement.disconnect().is_cancelled());
    drop(second);
    drop(replacement_item);
    drop(item);
    assert!(replacement.disconnect().is_cancelled());
}
#[tokio::test]
async fn actual_foreground_projection_is_the_retained_claim_row() {
    let recorder = recorder();
    let bridge = Bridge::new("mix.example.test", recorder.clone()).unwrap();
    let input = fresh_input();
    let row = bridge
        .fresh(
            &input,
            &wire::FreshProjectionOrigin {
                foreground_frame: fixed(1),
                recipient_ordinal: 0,
                declared_delivery_id: fixed(12),
            },
            &claim(13),
            ForegroundSite::new(0).unwrap(),
        )
        .await
        .unwrap()
        .unwrap();
    let retained = row.0.clone();
    bridge
        .supply_defer(wire::CommitCut::Complete, true)
        .unwrap();
    let worker = bridge
        .claim(
            row,
            &attempt(13, Vec::new()),
            ClaimSites::new(0).unwrap(),
            RouteMap::new(recorder),
        )
        .await
        .unwrap()
        .unwrap();
    let owner = worker.observation();
    assert!(std::ptr::eq(retained.as_ref(), owner.row()));
    worker.await.unwrap().unwrap();
    assert_eq!(
        owner.row().stanza,
        "<message><body>ordinary</body></message>"
    );
}
#[tokio::test]
async fn authenticated_foreground_replay_does_not_invoke_a_fresh_store_or_wake() {
    let canonical = "<body>ordinary</body>";
    let authenticators =
        crate::abuse::test_mix_message_content_keyring().authenticators(canonical.as_bytes());
    let primary = authenticators.primary();
    for corrupt in [false, true] {
        let bridge = Bridge::new("mix.example.test", recorder()).unwrap();
        let mut mac = primary.mac().to_vec();
        if corrupt {
            mac[0] ^= 1;
        }
        let input = wire::ReplayForeground {
            frame: wire::Frame {
                frame_id: fixed(1),
                connection_id: fixed(7),
                transport: wire::TransportKind::Bosh,
                input: text("<message type='groupchat'><body>ordinary</body></message>"),
            },
            configured_domain: text("mix.example.test"),
            ingress: wire::MixIngress {
                channel_id: fixed(10),
                channel_jid: text("c@mix.example.test"),
                actor_bare: text("u@example.test"),
                actor_full: text("u@example.test/m"),
                children: text(canonical),
                encrypted: false,
                identity: wire::Nullable::Value(wire::ReplayIdentityInput {
                    client_id: text("ordinary-replay"),
                    canonical_semantics: wire::Bytes::of(canonical.as_bytes()).unwrap(),
                }),
            },
            existing: wire::Existing {
                authoritative_id: fixed(9),
                semantic_key_id: text(primary.key_id()),
                semantic_mac: wire::Bytes::of(&mac).unwrap(),
                target_id: wire::Nullable::Null(()),
            },
            original_id: fixed(9),
        };
        let result = bridge
            .replay(&input, ForegroundSite::new(0).unwrap())
            .await
            .unwrap();
        assert_eq!(result.is_err(), corrupt);
        let state = bridge.repository.0.lock().unwrap();
        let actual = state.foreground.as_ref().unwrap().owner.snapshot();
        assert!(!actual.repository_started);
        assert_eq!(actual.wake, fg::Wake::Unavailable);
        assert!(matches!(actual.knowledge, fg::Knowledge::NoCommitRequested));
        assert_eq!(
            actual.replay.existing.authenticated,
            Some(if corrupt {
                room::Replay::Conflict
            } else {
                room::Replay::Replay(Uuid::from_u128(9))
            })
        );
    }
}
#[tokio::test]
async fn supplied_shutdown_cancels_exact_pending_handoff_before_owner_retirement() {
    let recorder = recorder();
    let bridge = Bridge::new("mix.example.test", recorder.clone()).unwrap();
    let routes = RouteMap::new(recorder);
    let input = route(7, true, "pending");
    let (route, mut queue) = routes.install(&input, 1).unwrap();
    let row = bridge.initial_row(&initial()).unwrap();
    let mut run = Box::pin(
        bridge
            .claim(
                row,
                &attempt(13, vec![input]),
                ClaimSites::new(0).unwrap(),
                routes,
            )
            .await
            .unwrap()
            .unwrap(),
    );
    assert!(futures::poll!(run.as_mut()).is_pending());
    let item = queue.try_recv().unwrap();
    run.record_dequeued(&route, 0, &item);
    let owner = run.observation();
    run.cancel();
    run.await.unwrap().unwrap();
    let actual = owner.snapshot();
    assert!(route.disconnect().is_cancelled());
    assert!(actual.renewal_scope_closed);
    assert_eq!(actual.terminal, Some(mix_worker::TerminalReason::Cancelled));
    assert!(actual.settlement.is_none());
    assert_eq!(actual.renewal.issued, 0);
    drop(item);
}

// Revision2 controls use the actual native bridge. They never call
// complete_mix_handoff, inject a completion, or manufacture an OutboundItem.
fn take_recorder(capture: Recorder) -> wire::Recorder {
    match Arc::try_unwrap(capture) {
        Ok(value) => value.into_inner().unwrap_or_else(|e| e.into_inner()),
        Err(_) => panic!("ordinary recorder still owned by live bridge/route/runner"),
    }
}
fn captured_envelope(capture: Recorder) -> wire::Envelope {
    // Consume the actual recorder exactly once. Never reset counters/loss or
    // swap a new recorder into still-live aliases to recover qualification.
    take_recorder(capture)
        .finish(wire::Execution::Complete)
        .unwrap()
}
fn native_input(connection: Uuid) -> wire::DurableNative {
    wire::DurableNative {
        connection_id: wire::Id(connection),
        write: wire::WriteScript {
            chunk_limit: 4096,
            fail_after_accepted_bytes: wire::Nullable::Null(()),
            flush: wire::FlushReply::Ok,
        },
        returned_fence: wire::MixSource {
            delivery_id: fixed(12),
            lease_token: fixed(15),
        },
        ack_commit: wire::CommitCut::Complete,
    }
}
async fn transport_actual_item(
    bridge: &Bridge,
    route: &RouteHandle,
    ordinal: u8,
    item: crate::outbound::OutboundItem,
    capture: Recorder,
) {
    let site = crate::xmpp::stage4_native::NativeSite::new(ordinal).unwrap();
    let input = native_input(route.connection_id());
    bridge.supply_native(&input).unwrap();
    let service = bridge.service();
    crate::xmpp::stage4_native::write_item(
        item,
        route.connection_id(),
        site,
        wire::ItemOwner::Mix(wire::MixItemOwner { attempt_ordinal: 0 }),
        input.write,
        Some(&service),
        capture,
    )
    .await
    .unwrap()
    .unwrap();
}
#[tokio::test]
async fn typed_handoff_keeps_the_nonzero_actual_dequeue_ordinal() {
    let capture = recorder();
    let bridge = Bridge::new("mix.example.test", capture.clone()).unwrap();
    let routes = RouteMap::new(capture.clone());
    let input = route(7, true, "nonzero");
    let (route, mut queue) = routes.install(&input, 1).unwrap();
    let row = bridge.initial_row(&initial()).unwrap();
    let mut run = Box::pin(
        bridge
            .claim(
                row,
                &attempt(13, vec![input]),
                ClaimSites::new(0).unwrap(),
                routes,
            )
            .await
            .unwrap()
            .unwrap(),
    );
    assert!(futures::poll!(run.as_mut()).is_pending());
    let item = queue.try_recv().unwrap();
    run.record_dequeued(&route, 1, &item);
    assert!(!run.capture.dequeue.lock().unwrap().handoff_join_consumed);
    transport_actual_item(&bridge, &route, 1, item, capture.clone()).await;
    let owner = run.observation();
    run.await.unwrap().unwrap();
    assert!(owner.snapshot().transfer.is_some());
    drop(route);
    drop(bridge);
    let actual = captured_envelope(capture);
    assert!(matches!(
        actual.observation_status,
        wire::ObservationStatus::Complete(_)
    ));
    let dequeues: Vec<_> = actual
        .facts
        .as_slice()
        .iter()
        .filter_map(|f| match &f.fact {
            wire::Fact::Worker(wire::WorkerFact::LocalQueue(q)) => Some(q.item.item_ordinal),
            _ => None,
        })
        .collect();
    let handoffs: Vec<_> = actual
        .facts
        .as_slice()
        .iter()
        .filter_map(|f| match &f.fact {
            wire::Fact::Worker(wire::WorkerFact::Handoff(h)) => Some((h.item_ordinal, &h.received)),
            _ => None,
        })
        .collect();
    assert_eq!(dequeues, vec![1]);
    assert_eq!(handoffs.len(), 1);
    assert_eq!(handoffs[0].0, 1);
    assert!(matches!(
        handoffs[0].1,
        wire::HandoffResult::Received(wire::TransferBoundary::SocketFenced(_))
    ));
    let introduced = actual
        .facts
        .as_slice()
        .iter()
        .find(|f| matches!(&f.fact, wire::Fact::Worker(wire::WorkerFact::LocalQueue(_))))
        .unwrap()
        .seq;
    let completed = actual
        .facts
        .as_slice()
        .iter()
        .find(|f| matches!(&f.fact, wire::Fact::Worker(wire::WorkerFact::Handoff(_))))
        .unwrap()
        .seq;
    assert!(introduced < completed);
}
#[tokio::test]
async fn missing_dequeue_observation_never_invents_a_handoff_ordinal() {
    let capture = recorder();
    let bridge = Bridge::new("mix.example.test", capture.clone()).unwrap();
    let routes = RouteMap::new(capture.clone());
    let input = route(7, true, "missing");
    let (route, mut queue) = routes.install(&input, 1).unwrap();
    let row = bridge.initial_row(&initial()).unwrap();
    let mut run = Box::pin(
        bridge
            .claim(
                row,
                &attempt(13, vec![input]),
                ClaimSites::new(0).unwrap(),
                routes,
            )
            .await
            .unwrap()
            .unwrap(),
    );
    assert!(futures::poll!(run.as_mut()).is_pending());
    let item = queue.try_recv().unwrap();
    // The real native owner still executes; only the dequeue observer call is
    // deliberately omitted. Missing evidence cannot be repaired from input.
    transport_actual_item(&bridge, &route, 1, item, capture.clone()).await;
    let owner = run.observation();
    run.await.unwrap().unwrap();
    assert!(owner.snapshot().transfer.is_some());
    drop(route);
    drop(bridge);
    let actual = captured_envelope(capture);
    assert!(matches!(
        actual.observation_status,
        wire::ObservationStatus::Lost(wire::LostObservation {
            reason: wire::Loss::MissingObservation,
            ..
        })
    ));
    assert!(!actual
        .facts
        .as_slice()
        .iter()
        .any(|f| matches!(&f.fact, wire::Fact::Worker(wire::WorkerFact::Handoff(_)))));
}
#[tokio::test]
async fn repeated_dequeue_introduction_is_loss_for_equal_or_changed_ordinals() {
    for repeated_ordinal in [1, 2] {
        let capture = recorder();
        let bridge = Bridge::new("mix.example.test", capture.clone()).unwrap();
        let routes = RouteMap::new(capture.clone());
        let input = route(7, true, "repeated");
        let (route, mut queue) = routes.install(&input, 1).unwrap();
        let row = bridge.initial_row(&initial()).unwrap();
        let mut run = Box::pin(
            bridge
                .claim(
                    row,
                    &attempt(13, vec![input]),
                    ClaimSites::new(0).unwrap(),
                    routes,
                )
                .await
                .unwrap()
                .unwrap(),
        );
        assert!(futures::poll!(run.as_mut()).is_pending());
        let item = queue.try_recv().unwrap();
        run.record_dequeued(&route, 1, &item);
        run.record_dequeued(&route, repeated_ordinal, &item);
        assert!(run.capture.dequeue.lock().unwrap().rejected);
        transport_actual_item(&bridge, &route, 1, item, capture.clone()).await;
        run.await.unwrap().unwrap();
        drop(route);
        drop(bridge);
        let actual = captured_envelope(capture);
        assert!(matches!(
            actual.observation_status,
            wire::ObservationStatus::Lost(wire::LostObservation {
                reason: wire::Loss::MissingObservation,
                ..
            })
        ));
        let introductions: Vec<_> = actual
            .facts
            .as_slice()
            .iter()
            .filter_map(|f| match &f.fact {
                wire::Fact::Worker(wire::WorkerFact::LocalQueue(q)) => Some(q.item.item_ordinal),
                _ => None,
            })
            .collect();
        assert_eq!(introductions, vec![1, repeated_ordinal]);
        assert!(!actual
            .facts
            .as_slice()
            .iter()
            .any(|f| matches!(&f.fact, wire::Fact::Worker(wire::WorkerFact::Handoff(_)))));
    }
}
#[tokio::test]
async fn mismatched_source_stanza_or_route_cannot_introduce_the_handoff_ordinal() {
    for mismatch in 0..3 {
        let capture = recorder();
        let bridge = Bridge::new("mix.example.test", capture.clone()).unwrap();
        let routes = RouteMap::new(capture.clone());
        let input = route(7, true, "mismatch");
        let (route, mut queue) = routes.install(&input, 1).unwrap();
        let row = bridge.initial_row(&initial()).unwrap();
        let mut run = Box::pin(
            bridge
                .claim(
                    row,
                    &attempt(13, vec![input.clone()]),
                    ClaimSites::new(0).unwrap(),
                    routes,
                )
                .await
                .unwrap()
                .unwrap(),
        );
        assert!(futures::poll!(run.as_mut()).is_pending());
        let item = queue.try_recv().unwrap();
        match mismatch {
            0 => {
                let mut changed = item.clone();
                let mut source = changed.mix_delivery().unwrap();
                source.lease_token = Uuid::from_u128(99);
                changed.durable_source =
                    Some(crate::outbound::TransportOwnershipSource::Mix(source));
                run.record_dequeued(&route, 1, &changed);
                assert!(run.capture.dequeue.lock().unwrap().rejected);
                drop(changed);
            }
            1 => {
                let mut changed = item.clone();
                changed.stanza.push('x');
                run.record_dequeued(&route, 1, &changed);
                assert!(run.capture.dequeue.lock().unwrap().rejected);
                drop(changed);
            }
            _ => {
                // Equal key and connection still cannot substitute a different
                // real route's lifecycle identity from another supplied map.
                let other_map = RouteMap::new(capture.clone());
                let (other_route, _other_queue) = other_map.install(&input, 1).unwrap();
                assert!(!Arc::ptr_eq(&route.lifecycle(), &other_route.lifecycle()));
                run.record_dequeued(&other_route, 1, &item);
                assert!(run.capture.dequeue.lock().unwrap().rejected);
            }
        }
        // A later apparently-correct introduction cannot heal earlier loss.
        run.record_dequeued(&route, 1, &item);
        assert!(run.capture.dequeue.lock().unwrap().rejected);
        transport_actual_item(&bridge, &route, 1, item, capture.clone()).await;
        run.await.unwrap().unwrap();
        drop(route);
        drop(bridge);
        let actual = captured_envelope(capture);
        assert!(matches!(
            actual.observation_status,
            wire::ObservationStatus::Lost(wire::LostObservation {
                reason: wire::Loss::MissingObservation,
                ..
            })
        ));
        assert!(!actual
            .facts
            .as_slice()
            .iter()
            .any(|f| matches!(&f.fact, wire::Fact::Worker(wire::WorkerFact::Handoff(_)))));
    }
}

fn fresh_input() -> wire::FreshForeground {
    wire::FreshForeground {
        frame: wire::Frame {
            frame_id: fixed(1),
            connection_id: fixed(2),
            transport: wire::TransportKind::Tcp,
            input: text("<message type='groupchat'><body>ordinary</body></message>"),
        },
        configured_domain: text("mix.example.test"),
        ingress: wire::MixIngress {
            channel_id: fixed(10),
            channel_jid: text("c@mix.example.test"),
            actor_bare: text("s@example.test"),
            actor_full: text("s@example.test/a"),
            children: text("<body>ordinary</body>"),
            encrypted: false,
            identity: wire::Nullable::Null(()),
        },
        command: wire::MixStoreCommand {
            channel_id: fixed(10),
            actor: text("s@example.test"),
            item_id: fixed(9),
            payload: text("<item/>"),
            identity: wire::Nullable::Null(()),
            delivery_payload: text("<body>ordinary</body>"),
            visible_jid: wire::Nullable::Null(()),
            encrypted: false,
        },
        stored: wire::Stored {
            authoritative_id: fixed(9),
            storage_id: fixed(19),
            channel_id: fixed(10),
            channel_jid: text("c@mix.example.test"),
            projection: wire::Nullable::Value(wire::DeliveryProjection {
                event_id: fixed(9),
                channel_id: fixed(10),
                channel_jid: text("c@mix.example.test"),
                stanza_template: text("<message><body>ordinary</body></message>"),
                authoritative_stanza_id: wire::Nullable::Value(fixed(9)),
                archive: true,
                encrypted: false,
                recipients: wire::List::new(vec![wire::RecipientProjection {
                    participant: wire::Participant {
                        participant_id: fixed(11),
                        jid: text("u@example.test"),
                        nick: wire::Nullable::Null(()),
                    },
                    delivery_id: fixed(12),
                    sequence: 1,
                }])
                .unwrap(),
            }),
        },
        commit: wire::CommitCut::Complete,
    }
}

fn admitted(capture: &Recorder) -> u8 {
    capture.lock().unwrap().admitted_owner_polls()
}
fn claim_observation(bridge: &Bridge) -> mix_worker::ClaimObservation {
    bridge
        .repository
        .0
        .lock()
        .unwrap()
        .last_claim_observation
        .clone()
        .unwrap()
}
fn replay_input() -> wire::ReplayForeground {
    let canonical = "<body>ordinary</body>";
    let authenticators =
        crate::abuse::test_mix_message_content_keyring().authenticators(canonical.as_bytes());
    let primary = authenticators.primary();
    wire::ReplayForeground {
        frame: wire::Frame {
            frame_id: fixed(1),
            connection_id: fixed(7),
            transport: wire::TransportKind::Bosh,
            input: text("<message type='groupchat'><body>ordinary</body></message>"),
        },
        configured_domain: text("mix.example.test"),
        ingress: wire::MixIngress {
            channel_id: fixed(10),
            channel_jid: text("c@mix.example.test"),
            actor_bare: text("u@example.test"),
            actor_full: text("u@example.test/m"),
            children: text(canonical),
            encrypted: false,
            identity: wire::Nullable::Value(wire::ReplayIdentityInput {
                client_id: text("ordinary-replay"),
                canonical_semantics: wire::Bytes::of(canonical.as_bytes()).unwrap(),
            }),
        },
        existing: wire::Existing {
            authoritative_id: fixed(9),
            semantic_key_id: text(primary.key_id()),
            semantic_mac: wire::Bytes::of(primary.mac()).unwrap(),
            target_id: wire::Nullable::Null(()),
        },
        original_id: fixed(9),
    }
}
#[tokio::test]
async fn sticky_or_conversion_loss_preserves_real_foreground_claim_and_worker_returns() {
    for conversion_failure in [false, true] {
        let capture = recorder();
        let bridge = Bridge::new("mix.example.test", capture.clone()).unwrap();
        if conversion_failure {
            observed(&capture, || -> Result<wire::Fact> {
                anyhow::bail!("ordinary unformable observation")
            });
        } else {
            missing(&capture);
        }
        let row = bridge
            .fresh(
                &fresh_input(),
                &wire::FreshProjectionOrigin {
                    foreground_frame: fixed(1),
                    recipient_ordinal: 0,
                    declared_delivery_id: fixed(12),
                },
                &claim(13),
                ForegroundSite::new(0).unwrap(),
            )
            .await
            .unwrap()
            .unwrap();
        let foreground = bridge
            .repository
            .0
            .lock()
            .unwrap()
            .foreground
            .as_ref()
            .unwrap()
            .owner
            .clone();
        assert_eq!(
            foreground.snapshot().terminal,
            Some(fg::TerminalReason::Completed)
        );
        assert_eq!(foreground.snapshot().wake, fg::Wake::Invoked);
        bridge
            .supply_defer(wire::CommitCut::Complete, true)
            .unwrap();
        let worker = bridge
            .claim(
                row,
                &attempt(13, Vec::new()),
                ClaimSites::new(0).unwrap(),
                RouteMap::new(capture.clone()),
            )
            .await
            .unwrap()
            .unwrap();
        let claim = claim_observation(&bridge);
        assert_eq!(
            claim.snapshot().terminal,
            Some(mix_worker::TerminalReason::Completed)
        );
        assert_eq!(
            claim.snapshot().returned,
            Some(mix_worker::ClaimReturned::Accepted(1))
        );
        let owner = worker.observation();
        worker.await.unwrap().unwrap();
        assert_eq!(
            owner.snapshot().terminal,
            Some(mix_worker::TerminalReason::Completed)
        );
        assert_eq!(
            owner.snapshot().settlement.unwrap().returned,
            Some(mix_worker::SettlementReturned::Outcome(
                mix_worker::SettlementResult::Defer(true)
            ))
        );
        // Exactly foreground, claim and worker; wrappers and nested repository
        // operations are not additional declared owner polls.
        assert_eq!(admitted(&capture), 3);
        assert!(driver::resource_stop(&capture).is_none());
        drop(bridge);
        let actual = captured_envelope(capture);
        assert!(matches!(
            actual.execution,
            wire::Nullable::Value(wire::Execution::Complete)
        ));
        assert!(matches!(
            actual.observation_status,
            wire::ObservationStatus::Lost(_)
        ));
        assert!(actual.resource_stop.get().is_none());
    }
}
#[tokio::test]
async fn sticky_loss_preserves_authenticated_replay_and_actual_backend_failure() {
    let capture = recorder();
    let bridge = Bridge::new("mix.example.test", capture.clone()).unwrap();
    missing(&capture);
    assert_eq!(
        bridge
            .replay(&replay_input(), ForegroundSite::new(0).unwrap())
            .await
            .unwrap()
            .unwrap(),
        Uuid::from_u128(9)
    );
    let replay = bridge
        .repository
        .0
        .lock()
        .unwrap()
        .foreground
        .as_ref()
        .unwrap()
        .owner
        .snapshot();
    assert_eq!(replay.terminal, Some(fg::TerminalReason::Completed));
    assert_eq!(replay.wake, fg::Wake::Unavailable);
    assert!(!replay.repository_started);
    assert_eq!(admitted(&capture), 1);
    assert!(driver::resource_stop(&capture).is_none());
    drop(bridge);
    let actual = captured_envelope(capture);
    assert!(matches!(
        actual.observation_status,
        wire::ObservationStatus::Lost(_)
    ));

    // An independent ordinary case supplies a genuine failing claim statement.
    // Loss must preserve this backend failure rather than manufacture success.
    let capture = recorder();
    let bridge = Bridge::new("mix.example.test", capture.clone()).unwrap();
    missing(&capture);
    let mut input = attempt(13, Vec::new());
    input.claim.commit = wire::CommitCut::Error;
    let row = bridge.initial_row(&initial()).unwrap();
    let actual = bridge
        .claim(
            row,
            &input,
            ClaimSites::new(0).unwrap(),
            RouteMap::new(capture.clone()),
        )
        .await
        .unwrap();
    assert!(actual.is_err());
    let snapshot = claim_observation(&bridge).snapshot();
    assert_eq!(snapshot.returned, Some(mix_worker::ClaimReturned::Error));
    assert_eq!(
        snapshot.terminal,
        Some(mix_worker::TerminalReason::BackendFailure)
    );
    assert_eq!(admitted(&capture), 1);
    assert!(driver::resource_stop(&capture).is_none());
    drop(bridge);
    let envelope = take_recorder(capture)
        .finish(wire::Execution::Failed)
        .unwrap();
    assert!(matches!(
        envelope.execution,
        wire::Nullable::Value(wire::Execution::Failed)
    ));
    assert!(envelope.resource_stop.get().is_none());
}
#[tokio::test]
async fn prior_loss_cannot_admit_a_sixty_fifth_claim_poll() {
    let capture = recorder();
    let bridge = Bridge::new("mix.example.test", capture.clone()).unwrap();
    missing(&capture);
    let mut input = attempt(13, Vec::new());
    input.claim.commit = wire::CommitCut::Pending;
    let row = bridge.initial_row(&initial()).unwrap();
    let mut run = Box::pin(bridge.claim(
        row,
        &input,
        ClaimSites::new(0).unwrap(),
        RouteMap::new(capture.clone()),
    ));
    for admitted_calls in 1..=wire::MAX_POLLS {
        assert!(futures::poll!(run.as_mut()).is_pending());
        assert_eq!(usize::from(admitted(&capture)), admitted_calls);
    }
    let owner = claim_observation(&bridge);
    assert_eq!(owner.snapshot().terminal, None);
    let stop = match futures::poll!(run.as_mut()) {
        Poll::Ready(Err(stop)) => stop,
        _ => panic!("poll65 was not refused before polling the claim"),
    };
    assert!(matches!(
        stop.resource_stop,
        wire::ResourceStop::DriverPoll(wire::DriverResourceStop {
            owner: wire::DriverOwner::Claim,
            owner_ordinal: 0,
            admitted_calls: 64
        })
    ));
    assert_eq!(admitted(&capture), 64);
    assert_eq!(
        owner.snapshot().terminal,
        Some(mix_worker::TerminalReason::Cancelled)
    );
    assert_eq!(owner.snapshot().returned, None);
    assert!(matches!(
        owner.snapshot().knowledge,
        mix_worker::ClaimKnowledge::AutocommitStatementEntered
    ));
    drop(run);
    drop(bridge);
    let actual = take_recorder(capture).finish_resource_stopped().unwrap();
    assert!(actual.execution.get().is_none() && actual.rejection.get().is_none());
    assert!(actual.resource_stop.get().is_some());
    assert!(matches!(
        actual.observation_status,
        wire::ObservationStatus::Lost(_)
    ));
}
#[tokio::test]
async fn worker_budget_refusal_drops_pending_handoff_after_prior_loss_without_a_backend_error() {
    let capture = recorder();
    let bridge = Bridge::new("mix.example.test", capture.clone()).unwrap();
    missing(&capture);
    let routes = RouteMap::new(capture.clone());
    let input_route = route(7, true, "budget");
    let (route, _queue) = routes.install(&input_route, 1).unwrap();
    let input = attempt(13, vec![input_route]);
    let row = bridge.initial_row(&initial()).unwrap();
    let mut run = Box::pin(
        bridge
            .claim(row, &input, ClaimSites::new(0).unwrap(), routes)
            .await
            .unwrap()
            .unwrap(),
    );
    assert_eq!(admitted(&capture), 1);
    let owner = run.observation();
    for admitted_calls in 2..=wire::MAX_POLLS {
        assert!(futures::poll!(run.as_mut()).is_pending());
        assert_eq!(usize::from(admitted(&capture)), admitted_calls);
    }
    assert!(!route.disconnect().is_cancelled());
    let stop = match futures::poll!(run.as_mut()) {
        Poll::Ready(Err(stop)) => stop,
        _ => panic!("poll65 was not refused before polling the worker"),
    };
    assert!(matches!(
        stop.resource_stop,
        wire::ResourceStop::DriverPoll(wire::DriverResourceStop {
            owner: wire::DriverOwner::Worker,
            owner_ordinal: 0,
            admitted_calls: 64
        })
    ));
    assert_eq!(admitted(&capture), 64);
    assert!(route.disconnect().is_cancelled());
    let actual = owner.snapshot();
    assert_eq!(actual.terminal, Some(mix_worker::TerminalReason::Cancelled));
    assert!(actual.settlement.is_none());
    assert_eq!(actual.local[0].returned, None);
    drop(run);
    drop(route);
    drop(bridge);
    let envelope = take_recorder(capture).finish_resource_stopped().unwrap();
    assert!(envelope.execution.get().is_none() && envelope.rejection.get().is_none());
}
#[tokio::test]
async fn foreground_budget_drop_stays_distinct_from_actual_frame_backend_error() {
    let capture = recorder();
    let bridge = Bridge::new("mix.example.test", capture.clone()).unwrap();
    missing(&capture);
    let mut input = fresh_input();
    input.commit = wire::CommitCut::Pending;
    let origin = wire::FreshProjectionOrigin {
        foreground_frame: fixed(1),
        recipient_ordinal: 0,
        declared_delivery_id: fixed(12),
    };
    let claim_input = claim(13);
    let mut run = Box::pin(bridge.fresh(
        &input,
        &origin,
        &claim_input,
        ForegroundSite::new(0).unwrap(),
    ));
    for admitted_calls in 1..=wire::MAX_POLLS {
        assert!(futures::poll!(run.as_mut()).is_pending());
        assert_eq!(usize::from(admitted(&capture)), admitted_calls);
    }
    let owner = bridge
        .repository
        .0
        .lock()
        .unwrap()
        .foreground
        .as_ref()
        .unwrap()
        .owner
        .clone();
    let stop = match futures::poll!(run.as_mut()) {
        Poll::Ready(Err(stop)) => stop,
        _ => panic!("foreground budget was flattened into its frame result"),
    };
    assert!(matches!(
        stop.resource_stop,
        wire::ResourceStop::DriverPoll(wire::DriverResourceStop {
            owner: wire::DriverOwner::Foreground,
            owner_ordinal: 0,
            admitted_calls: 64
        })
    ));
    assert_eq!(admitted(&capture), 64);
    assert_eq!(
        owner.snapshot().terminal,
        Some(fg::TerminalReason::Cancelled)
    );
    assert!(owner.snapshot().returned.is_none());
    assert!(matches!(
        owner.snapshot().knowledge,
        fg::Knowledge::CommitCallEntered(_)
    ));
    drop(run);
    drop(bridge);
    let envelope = take_recorder(capture).finish_resource_stopped().unwrap();
    assert!(envelope.execution.get().is_none() && envelope.rejection.get().is_none());

    let capture = recorder();
    let bridge = Bridge::new("mix.example.test", capture.clone()).unwrap();
    missing(&capture);
    let mut input = fresh_input();
    input.commit = wire::CommitCut::Error;
    let actual = bridge
        .fresh(
            &input,
            &origin,
            &claim_input,
            ForegroundSite::new(0).unwrap(),
        )
        .await
        .unwrap();
    assert!(actual.is_err());
    let owner = bridge
        .repository
        .0
        .lock()
        .unwrap()
        .foreground
        .as_ref()
        .unwrap()
        .owner
        .clone();
    assert_eq!(
        owner.snapshot().terminal,
        Some(fg::TerminalReason::BackendFailure)
    );
    assert!(matches!(
        owner.snapshot().returned,
        Some(fg::Returned::Error)
    ));
    assert!(driver::resource_stop(&capture).is_none());
    assert_eq!(admitted(&capture), 1);
    drop(bridge);
    let envelope = take_recorder(capture)
        .finish(wire::Execution::Failed)
        .unwrap();
    assert!(matches!(
        envelope.execution,
        wire::Nullable::Value(wire::Execution::Failed)
    ));
}
#[tokio::test]
async fn addressed_stanza_projection_overflow_does_not_become_a_route_or_repository_error() {
    let capture = recorder();
    let bridge = Bridge::new("mix.example.test", capture.clone()).unwrap();
    let mut input = initial();
    let prefix = "<message><body>";
    let suffix = "</body></message>";
    let stanza = format!(
        "{prefix}{}{suffix}",
        "x".repeat(wire::MAX_STANZA - prefix.len() - suffix.len())
    );
    assert_eq!(stanza.len(), wire::MAX_STANZA);
    input.stanza = text(&stanza);
    let row = bridge.initial_row(&input).unwrap();
    bridge
        .supply_defer(wire::CommitCut::Complete, true)
        .unwrap();
    let run = bridge
        .claim(
            row,
            &attempt(13, Vec::new()),
            ClaimSites::new(0).unwrap(),
            RouteMap::new(capture.clone()),
        )
        .await
        .unwrap()
        .unwrap();
    let owner = run.observation();
    let routed = run.capture.stanza.clone();
    run.await.unwrap().unwrap();
    assert!(routed.lock().unwrap().as_ref().unwrap().len() > wire::MAX_STANZA);
    let actual = owner.snapshot();
    assert_eq!(actual.terminal, Some(mix_worker::TerminalReason::Completed));
    assert_eq!(
        actual.route_returned,
        Some(mix_worker::RouteResult::Pending)
    );
    assert_eq!(archive_id(&owner), Uuid::from_u128(71));
    assert_eq!(
        actual.settlement.unwrap().returned,
        Some(mix_worker::SettlementReturned::Outcome(
            mix_worker::SettlementResult::Defer(true)
        ))
    );
    assert_eq!(admitted(&capture), 2);
    assert!(driver::resource_stop(&capture).is_none());
    drop(bridge);
    let envelope = captured_envelope(capture);
    assert!(matches!(
        envelope.observation_status,
        wire::ObservationStatus::Lost(wire::LostObservation {
            reason: wire::Loss::MissingObservation,
            ..
        })
    ));
    assert!(matches!(
        envelope.execution,
        wire::Nullable::Value(wire::Execution::Complete)
    ));
}

#[test]
fn production_binary_replay_semantics_round_trip_actual_input_and_both_projections() {
    let mut input = replay_input();
    let canonical = super::super::mix_replay_semantics(
        "message",
        input.ingress.actor_bare.as_str(),
        input.ingress.channel_jid.as_str(),
        None,
        input.ingress.children.as_str(),
    );
    assert!(canonical.contains(&0));
    let identity = wire::ReplayIdentityInput {
        client_id: text("binary-replay"),
        canonical_semantics: wire::Bytes::of(&canonical).unwrap(),
    };
    input.ingress.identity = wire::Nullable::Value(identity.clone());
    let actual_ingress = ingress_input(&input.ingress);
    assert_eq!(
        actual_ingress
            .identity
            .as_ref()
            .unwrap()
            .canonical_semantics,
        canonical
    );
    let observed_ingress = map::ingress(&actual_ingress).unwrap();
    assert_eq!(
        observed_ingress.identity.get().unwrap().canonical_semantics,
        identity.canonical_semantics
    );
    let mut command = fresh_input().command;
    command.identity = wire::Nullable::Value(identity.clone());
    let actual_command = command_input(&command);
    assert_eq!(
        actual_command
            .identity
            .as_ref()
            .unwrap()
            .canonical_semantics,
        canonical
    );
    let observed_command = map::command(&actual_command).unwrap();
    assert_eq!(
        observed_command.identity.get().unwrap().canonical_semantics,
        identity.canonical_semantics
    );
}

#[tokio::test]
async fn production_binary_replay_authenticates_and_old_mac_rejects_changed_canonical_byte() {
    for corrupt in [false, true] {
        let mut input = replay_input();
        let mut canonical = super::super::mix_replay_semantics(
            "message",
            input.ingress.actor_bare.as_str(),
            input.ingress.channel_jid.as_str(),
            None,
            input.ingress.children.as_str(),
        );
        assert!(canonical.contains(&0));
        let authenticators =
            crate::abuse::test_mix_message_content_keyring().authenticators(&canonical);
        let primary = authenticators.primary();
        input.existing.semantic_key_id = text(primary.key_id());
        input.existing.semantic_mac = wire::Bytes::of(primary.mac()).unwrap();
        if corrupt {
            *canonical.last_mut().unwrap() ^= 1;
        }
        input.ingress.identity = wire::Nullable::Value(wire::ReplayIdentityInput {
            client_id: text("binary-replay"),
            canonical_semantics: wire::Bytes::of(&canonical).unwrap(),
        });
        let bridge = Bridge::new("mix.example.test", recorder()).unwrap();
        let result = bridge
            .replay(&input, ForegroundSite::new(0).unwrap())
            .await
            .unwrap();
        assert_eq!(result.is_err(), corrupt);
        let state = bridge.repository.0.lock().unwrap();
        let actual = state.foreground.as_ref().unwrap().owner.snapshot();
        assert!(!actual.repository_started);
        assert_eq!(actual.wake, fg::Wake::Unavailable);
        assert!(matches!(actual.knowledge, fg::Knowledge::NoCommitRequested));
        assert_eq!(
            actual.replay.existing.authenticated,
            Some(if corrupt {
                room::Replay::Conflict
            } else {
                room::Replay::Replay(Uuid::from_u128(9))
            })
        );
    }
}
