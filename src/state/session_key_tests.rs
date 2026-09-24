use super::{
    admit_bounded_omemo_poll_ip, admit_omemo_poll_ip_window, api_keyrings,
    append_suspended_muc_suffix_to_snapshot, begin_suspended_muc_route_transition,
    canonical_suspended_muc_endpoint, complete_snapshot_owned_handoff, encode_api_control_entropy,
    ephemeral_api_control_secret, federation_rule_matches, insert_restored_muc_occupant,
    move_local_muc_nickname_exact_in, muc_actor_identity_matches, muc_departure_identity_matches,
    muc_suspended_teardown_identity_matches, promote_suspended_muc_buffer,
    publish_local_muc_join_if_vacant_in, refresh_local_muc_policy_exact_in,
    refresh_local_muc_presence_exact_in, remove_local_muc_occupant_exact_from,
    runtime_control_startup_retry_delay, seal_suspended_muc_buffer, service_control_applies,
    session_lookup, set_local_muc_affiliation_exact_in, set_local_muc_role_exact_in,
    snapshot_suspended_muc_buffer_for_resume, staged_route_activation_allowed,
    suspended_muc_resume_actor_matches, suspended_occupant_is_created,
    transfer_muc_suffix_to_checkpoint, FederationWritePolicy, JoinedMucMembership,
    LocalMucJoinPublication, LocalMucNicknameMove, LocalMucOccupantIdentity, MucOccupant,
    MucOccupantEndpoint, RouteIncarnationSignal, SerializableMucOccupant, SessionLookup,
    StagedRouteActivationCheck, StagedRouteIdentity, SuspendedMucBuffer, SuspendedMucEndpoint,
    SuspendedMucPhase, SuspendedMucRoute,
};
use dashmap::DashMap;
use std::collections::{BTreeSet, VecDeque};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc, Mutex,
};
use std::time::{Duration, Instant};

#[test]
fn runtime_control_startup_backoff_is_bounded_and_decorrelates_processes() {
    let first = runtime_control_startup_retry_delay(1, 17);
    assert!(first >= Duration::from_millis(10));
    assert!(first <= Duration::from_millis(500));

    let saturated = runtime_control_startup_retry_delay(128, 17);
    assert!(saturated <= Duration::from_millis(500));
    assert!(saturated >= first);

    let delays = (10_u32..110)
        .map(|process_id| runtime_control_startup_retry_delay(3, process_id))
        .collect::<BTreeSet<_>>();
    assert!(
        delays.len() > 16,
        "a cold-start cohort must not retry in one synchronized wave"
    );
}

#[test]
fn live_sm_shutdown_write_receipt_does_not_cross_the_suspension_fence() {
    let (sender, mut outbound) = tokio::sync::mpsc::channel(2);
    let endpoint = SuspendedMucEndpoint::new_live(
        uuid::Uuid::new_v4(),
        crate::outbound::OutboundSender::new(sender),
    );
    let (receipt, mut completion) = tokio::sync::mpsc::unbounded_channel();
    assert!(endpoint
        .try_send_live_write_notification("<presence/>".to_owned(), receipt)
        .unwrap());
    let item = outbound.try_recv().unwrap();
    item.confirm_transport_ownership();
    assert!(matches!(
        completion.try_recv(),
        Err(tokio::sync::mpsc::error::TryRecvError::Empty)
    ));
    item.confirm_transport_write();
    assert_eq!(completion.try_recv(), Ok(()));

    begin_suspended_muc_route_transition(&endpoint, 0, 0);
    let (receipt, mut completion) = tokio::sync::mpsc::unbounded_channel();
    assert!(!endpoint
        .try_send_live_write_notification("<presence/>".to_owned(), receipt)
        .unwrap());
    assert!(matches!(
        completion.try_recv(),
        Err(tokio::sync::mpsc::error::TryRecvError::Disconnected)
    ));
    assert!(matches!(
        outbound.try_recv(),
        Err(tokio::sync::mpsc::error::TryRecvError::Disconnected)
    ));
    assert_eq!(endpoint.buffer.try_lock().unwrap().bytes, 0);
}

#[test]
fn suspended_sm_shutdown_write_receipt_is_never_persisted_or_confirmed() {
    for endpoint in [
        SuspendedMucEndpoint::new_collecting(uuid::Uuid::new_v4(), 0, 0),
        SuspendedMucEndpoint::new_durable(uuid::Uuid::new_v4()),
    ] {
        let (receipt, mut completion) = tokio::sync::mpsc::unbounded_channel();
        assert!(!endpoint
            .try_send_live_write_notification("<presence/>".to_owned(), receipt)
            .unwrap());
        assert!(matches!(
            completion.try_recv(),
            Err(tokio::sync::mpsc::error::TryRecvError::Disconnected)
        ));
        assert!(endpoint.buffer.try_lock().unwrap().stanzas.is_empty());
    }
}

#[test]
fn route_removal_signal_retains_the_exact_terminal_state_for_late_subscribers() {
    let connection_id = uuid::Uuid::new_v4();
    let signal = RouteIncarnationSignal::new(connection_id);
    signal.publish_removed();

    let late = signal.subscribe();
    assert_eq!(signal.connection_id(), connection_id);
    assert!(
        *late.borrow(),
        "subscribing after compare-and-remove must not lose the terminal event"
    );
}

#[tokio::test]
async fn unchanged_island_refresh_does_not_wait_for_held_read_guard() {
    use std::future::Future;
    use std::task::{Context, Poll, Waker};

    for enabled in [false, true] {
        let policy = FederationWritePolicy::new(enabled);
        let held_read = if enabled {
            // A raw reader also proves the true no-op does not acquire
            // the exclusive gate; delivery itself is already forbidden.
            policy.gate.read().await
        } else {
            policy.permit().await.expect("federation starts enabled")
        };
        let mut refresh = std::pin::pin!(policy.refresh(enabled));
        let mut context = Context::from_waker(Waker::noop());
        assert_eq!(refresh.as_mut().poll(&mut context), Poll::Ready(enabled));
        assert_eq!(policy.enabled(), enabled);
        drop(held_read);
    }
}

#[tokio::test]
async fn island_refresh_transition_fences_queued_delivery_despite_concurrent_noop() {
    use std::future::Future;
    use std::task::{Context, Poll, Waker};

    let policy = FederationWritePolicy::new(false);
    let held_read = policy.permit().await.expect("federation starts enabled");
    let mut transition = std::pin::pin!(policy.refresh(true));
    let mut queued_delivery = std::pin::pin!(policy.permit());
    let mut context = Context::from_waker(Waker::noop());
    assert_eq!(transition.as_mut().poll(&mut context), Poll::Pending);
    assert!(queued_delivery.as_mut().poll(&mut context).is_pending());

    let mut unchanged = std::pin::pin!(policy.refresh(false));
    assert_eq!(unchanged.as_mut().poll(&mut context), Poll::Ready(false));
    assert!(!policy.enabled());
    assert_eq!(transition.as_mut().poll(&mut context), Poll::Pending);
    assert!(queued_delivery.as_mut().poll(&mut context).is_pending());

    drop(held_read);
    assert_eq!(transition.as_mut().poll(&mut context), Poll::Ready(false));
    assert!(policy.enabled());
    assert!(matches!(
        queued_delivery.as_mut().poll(&mut context),
        Poll::Ready(None)
    ));
}

#[tokio::test]
async fn island_refresh_reopening_waits_for_gate_and_returns_locked_previous_value() {
    use std::future::Future;
    use std::task::{Context, Poll, Waker};

    for concurrent_apply in [false, true] {
        let policy = FederationWritePolicy::new(true);
        let held_read = policy.gate.read().await;
        let mut earlier_apply = std::pin::pin!(policy.apply(false));
        let mut context = Context::from_waker(Waker::noop());
        if concurrent_apply {
            assert_eq!(earlier_apply.as_mut().poll(&mut context), Poll::Pending);
        }
        let mut transition = std::pin::pin!(policy.refresh(false));
        let mut queued_delivery = std::pin::pin!(policy.permit());
        assert_eq!(transition.as_mut().poll(&mut context), Poll::Pending);
        assert!(queued_delivery.as_mut().poll(&mut context).is_pending());
        assert!(policy.enabled());

        drop(held_read);
        if concurrent_apply {
            assert_eq!(earlier_apply.as_mut().poll(&mut context), Poll::Ready(()));
            assert!(queued_delivery.as_mut().poll(&mut context).is_pending());
        }
        // The slow path returns the swap's value after the exclusive
        // wait, including when an earlier apply changed the initial read.
        assert_eq!(
            transition.as_mut().poll(&mut context),
            Poll::Ready(!concurrent_apply)
        );
        assert!(!policy.enabled());
        assert!(matches!(
            queued_delivery.as_mut().poll(&mut context),
            Poll::Ready(Some(_))
        ));
    }
}

#[tokio::test]
async fn island_mode_transition_waits_for_and_fences_federation_writes() {
    let policy = Arc::new(FederationWritePolicy::new(false));
    let permit = policy.permit().await.expect("federation starts enabled");
    let transition_policy = Arc::clone(&policy);
    let transition = tokio::spawn(async move {
        transition_policy.apply(true).await;
    });

    tokio::task::yield_now().await;
    assert!(
        !transition.is_finished(),
        "the kill switch must wait for an in-flight socket-write boundary"
    );
    drop(permit);
    tokio::time::timeout(Duration::from_secs(1), transition)
        .await
        .expect("island transition completes after the write boundary")
        .expect("island transition task succeeds");
    assert!(policy.enabled());
    assert!(
        policy.permit().await.is_none(),
        "queued writers must observe island mode after the transition"
    );

    policy.apply(false).await;
    assert!(policy.permit().await.is_some());
}

#[test]
fn omemo_poll_active_ip_cap_is_linearizable() {
    let windows = Arc::new(dashmap::DashMap::new());
    let admission = Arc::new(std::sync::Mutex::new(()));
    let barrier = Arc::new(std::sync::Barrier::new(33));
    let now = Instant::now();
    let accepted = std::thread::scope(|scope| {
        let mut workers = Vec::new();
        for suffix in 1_u8..=32 {
            let windows = Arc::clone(&windows);
            let admission = Arc::clone(&admission);
            let barrier = Arc::clone(&barrier);
            workers.push(scope.spawn(move || {
                barrier.wait();
                admit_bounded_omemo_poll_ip(
                    &windows,
                    &admission,
                    std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, suffix)),
                    now,
                    false,
                    4,
                )
            }));
        }
        barrier.wait();
        workers
            .into_iter()
            .map(|worker| worker.join().expect("poll admission thread completes"))
            .filter(|accepted| *accepted)
            .count()
    });
    assert_eq!(accepted, 4);
    assert_eq!(windows.len(), 4);
}

fn suspended_buffer(stanzas: &[&str]) -> SuspendedMucBuffer {
    let mut buffer = SuspendedMucBuffer {
        phase: SuspendedMucPhase::Collecting,
        snapshot_owned: false,
        base_stanzas: 0,
        base_bytes: 0,
        bytes: 0,
        stanzas: VecDeque::new(),
    };
    for stanza in stanzas {
        assert!(buffer.enqueue_volatile((*stanza).to_owned(), 32, 4096));
    }
    buffer
}

fn queued(buffer: &SuspendedMucBuffer) -> Vec<&str> {
    buffer
        .stanzas
        .iter()
        .map(|stanza| stanza.xml.as_str())
        .collect()
}

fn sm_snapshot(outbound_h: u32, unacked: &[&str]) -> crate::services::sm::SmSessionSnapshot {
    crate::services::sm::SmSessionSnapshot {
        inbound_h: 0,
        outbound_h,
        acked_h: 0,
        available: true,
        carbons: false,
        priority: 0,
        blocklist_requested: false,
        roster_requested: false,
        active_privacy_list: None,
        privacy_requested: false,
        peer_ip: std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
        user_agent_id: None,
        joined_rooms: Vec::new(),
        directed_presence: Vec::new(),
        last_presence: None,
        unacked: unacked
            .iter()
            .map(|stanza| crate::outbound::SmUnackedStanza::plain((*stanza).to_owned()))
            .collect(),
    }
}

#[test]
fn disconnect_snapshot_preserves_fifo_budget_and_counter_wrap() {
    let mut snapshot = sm_snapshot(u32::MAX, &["old"]);
    let mut suffix = VecDeque::new();
    suffix.push_back(super::SuspendedMucStanza {
        source_id: uuid::Uuid::new_v4(),
        xml: "room-a".to_owned(),
    });
    suffix.push_back(super::SuspendedMucStanza {
        source_id: uuid::Uuid::new_v4(),
        xml: "room-b".to_owned(),
    });
    append_suspended_muc_suffix_to_snapshot(&mut snapshot, &suffix, 3, "oldroom-aroom-b".len())
        .expect("the complete session FIFO fits exactly");
    assert_eq!(snapshot.outbound_h, 1);
    assert_eq!(
        snapshot
            .unacked
            .iter()
            .map(|entry| entry.stanza.as_str())
            .collect::<Vec<_>>(),
        vec!["old", "room-a", "room-b"]
    );
    assert!(snapshot
        .unacked
        .iter()
        .all(|entry| entry.durable_delivery().is_none()));

    let before_h = snapshot.outbound_h;
    let before = snapshot.unacked.clone();
    assert!(
        append_suspended_muc_suffix_to_snapshot(&mut snapshot, &suffix, 4, usize::MAX).is_err()
    );
    assert_eq!(snapshot.outbound_h, before_h);
    assert_eq!(snapshot.unacked, before);
}

#[tokio::test]
async fn suspended_muc_durable_promotion_retains_first_and_mid_failure_exactly() {
    let mut first_failure = suspended_buffer(&["first", "second"]);
    let expected_bytes = "first".len() + "second".len();
    let mut outcomes = VecDeque::from([false]);
    let mut attempted = Vec::new();
    assert!(
        !promote_suspended_muc_buffer(&mut first_failure, |_source_id, stanza| {
            attempted.push(stanza);
            std::future::ready(outcomes.pop_front().unwrap())
        })
        .await
    );
    assert_eq!(attempted, vec!["first".to_owned()]);
    assert_eq!(queued(&first_failure), vec!["first", "second"]);
    assert_eq!(first_failure.bytes, expected_bytes);
    assert!(matches!(&first_failure.phase, SuspendedMucPhase::Sealed));
    assert!(!first_failure.enqueue_volatile("newer".to_owned(), 32, 4096));

    let mut mid_failure = suspended_buffer(&["first", "middle", "last"]);
    let mut outcomes = VecDeque::from([true, false]);
    let mut attempted = Vec::new();
    assert!(
        !promote_suspended_muc_buffer(&mut mid_failure, |source_id, stanza| {
            attempted.push((source_id, stanza));
            std::future::ready(outcomes.pop_front().unwrap())
        })
        .await
    );
    assert_eq!(
        attempted
            .iter()
            .map(|(_, stanza)| stanza.as_str())
            .collect::<Vec<_>>(),
        vec!["first", "middle"]
    );
    let ambiguous_source_id = attempted[1].0;
    assert_eq!(queued(&mid_failure), vec!["middle", "last"]);
    assert_eq!(mid_failure.bytes, "middle".len() + "last".len());
    assert!(matches!(&mid_failure.phase, SuspendedMucPhase::Sealed));

    let mut outcomes = VecDeque::from([true, true]);
    let mut retried = Vec::new();
    assert!(
        promote_suspended_muc_buffer(&mut mid_failure, |source_id, stanza| {
            retried.push((source_id, stanza));
            std::future::ready(outcomes.pop_front().unwrap())
        })
        .await
    );
    assert_eq!(retried[0].0, ambiguous_source_id);
    assert_eq!(
        retried
            .iter()
            .map(|(_, stanza)| stanza.as_str())
            .collect::<Vec<_>>(),
        vec!["middle", "last"]
    );
    assert!(mid_failure.stanzas.is_empty());
    assert_eq!(mid_failure.bytes, 0);
    assert!(matches!(&mid_failure.phase, SuspendedMucPhase::Durable));
}

#[tokio::test]
async fn suspended_muc_checkpoint_snapshot_keeps_ownership_until_commit() {
    let endpoint = Arc::new(SuspendedMucEndpoint::new(uuid::Uuid::new_v4()));
    {
        let mut buffer = endpoint.buffer.lock().await;
        assert!(buffer.enqueue_volatile("older-1".to_owned(), 8, 4096));
        assert!(buffer.enqueue_volatile("older-2".to_owned(), 8, 4096));
        buffer.phase = SuspendedMucPhase::Resuming;
    }
    let snapshot = snapshot_suspended_muc_buffer_for_resume(&endpoint)
        .await
        .expect("resuming gate can be checkpointed");
    assert_eq!(snapshot, vec!["older-1".to_owned(), "older-2".to_owned()]);
    {
        let mut buffer = endpoint.buffer.lock().await;
        assert_eq!(queued(&buffer), vec!["older-1", "older-2"]);
        assert!(matches!(&buffer.phase, SuspendedMucPhase::Committing));
        assert!(!buffer.enqueue_volatile("racing".to_owned(), 8, 4096));
    }
    // A failed durable checkpoint seals the original owner without taking
    // or clearing a byte, so cleanup can still promote the exact FIFO.
    seal_suspended_muc_buffer(&endpoint).await;
    {
        let buffer = endpoint.buffer.lock().await;
        assert!(matches!(&buffer.phase, SuspendedMucPhase::Sealed));
        assert_eq!(queued(&buffer), vec!["older-1", "older-2"]);
    }
}

#[tokio::test]
async fn checkpoint_owned_suffix_is_cleared_once_and_never_promoted_again() {
    let endpoint = Arc::new(SuspendedMucEndpoint::new(uuid::Uuid::new_v4()));
    {
        let mut buffer = endpoint.buffer.lock().await;
        assert!(buffer.enqueue_volatile("one".to_owned(), 8, 4096));
        assert!(buffer.enqueue_volatile("two".to_owned(), 8, 4096));
        buffer.phase = SuspendedMucPhase::Resuming;
    }
    assert_eq!(
        snapshot_suspended_muc_buffer_for_resume(&endpoint).await,
        Some(vec!["one".to_owned(), "two".to_owned()])
    );
    {
        let mut buffer = endpoint.buffer.lock().await;
        assert!(transfer_muc_suffix_to_checkpoint(&mut buffer));
        assert!(buffer.stanzas.is_empty());
        assert_eq!(buffer.bytes, 0);
        assert!(matches!(&buffer.phase, SuspendedMucPhase::CheckpointOwned));
        assert!(complete_snapshot_owned_handoff(&mut buffer));
        assert!(buffer.stanzas.is_empty());
        assert!(matches!(&buffer.phase, SuspendedMucPhase::Durable));
        assert!(!complete_snapshot_owned_handoff(&mut buffer));
    }
}

#[tokio::test]
async fn ambiguous_suspend_commit_can_be_claimed_without_replaying_backup_twice() {
    let endpoint = Arc::new(SuspendedMucEndpoint::new(uuid::Uuid::new_v4()));
    {
        let mut buffer = endpoint.buffer.lock().await;
        assert!(buffer.enqueue_volatile("already-in-db".to_owned(), 8, 4096));
        buffer.snapshot_owned = true;
        buffer.phase = SuspendedMucPhase::Resuming;
    }
    assert_eq!(
        snapshot_suspended_muc_buffer_for_resume(&endpoint).await,
        Some(Vec::new()),
        "the claimed PostgreSQL queue, not its retained backup, is replayed"
    );
    {
        let mut buffer = endpoint.buffer.lock().await;
        assert!(buffer.snapshot_owned);
        assert_eq!(queued(&buffer), vec!["already-in-db"]);
        assert!(transfer_muc_suffix_to_checkpoint(&mut buffer));
        assert!(buffer.stanzas.is_empty());
        assert!(complete_snapshot_owned_handoff(&mut buffer));
        assert!(!buffer.snapshot_owned);
        assert!(matches!(&buffer.phase, SuspendedMucPhase::Durable));
    }
}

#[tokio::test]
async fn disconnect_fence_survives_a_busy_checkpoint_buffer_without_clearing_it() {
    let (raw_sender, _receiver) = tokio::sync::mpsc::channel(2);
    let endpoint = Arc::new(SuspendedMucEndpoint::new_live(
        uuid::Uuid::new_v4(),
        crate::outbound::OutboundSender::new(raw_sender),
    ));
    let mut buffer = endpoint.buffer.lock().await;
    buffer.phase = SuspendedMucPhase::CheckpointOwned;
    buffer.snapshot_owned = true;
    begin_suspended_muc_route_transition(&endpoint, 7, 700);
    {
        let route = endpoint
            .route
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        assert!(matches!(&*route, SuspendedMucRoute::Transitioning));
    }
    assert!(buffer.snapshot_owned);
    assert!(matches!(&buffer.phase, SuspendedMucPhase::CheckpointOwned));
    drop(buffer);

    seal_suspended_muc_buffer(&endpoint).await;
    let buffer = endpoint.buffer.lock().await;
    assert!(buffer.snapshot_owned);
    assert!(matches!(&buffer.phase, SuspendedMucPhase::Sealed));
    let route = endpoint
        .route
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    assert!(matches!(&*route, SuspendedMucRoute::Suspended));
}

#[test]
fn live_route_send_and_transition_share_one_linearization_fence() {
    let (raw_sender, mut receiver) = tokio::sync::mpsc::channel(2);
    let endpoint = Arc::new(SuspendedMucEndpoint::new_live(
        uuid::Uuid::new_v4(),
        crate::outbound::OutboundSender::new(raw_sender),
    ));
    let barrier = Arc::new(std::sync::Barrier::new(2));
    std::thread::scope(|scope| {
        let live = endpoint
            .route
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let transition_endpoint = Arc::clone(&endpoint);
        let transition_barrier = Arc::clone(&barrier);
        let transition = scope.spawn(move || {
            transition_barrier.wait();
            let mut route = transition_endpoint
                .route
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            *route = SuspendedMucRoute::Transitioning;
        });
        barrier.wait();
        let SuspendedMucRoute::Live(sender) = &*live else {
            panic!("the route starts live");
        };
        sender
            .try_send("before-fence".to_owned())
            .expect("the write linearizes before transition");
        drop(live);
        transition.join().expect("transition thread completes");
    });
    let delivered = receiver.try_recv().expect("pre-fence stanza is delivered");
    assert_eq!(delivered.stanza, "before-fence");
    let route = endpoint
        .route
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    assert!(matches!(&*route, SuspendedMucRoute::Transitioning));
}

#[tokio::test]
async fn one_sm_gate_preserves_cross_room_fifo_and_global_budget() {
    let endpoint = Arc::new(SuspendedMucEndpoint::new_collecting(
        uuid::Uuid::new_v4(),
        2,
        8,
    ));
    {
        let mut buffer = endpoint.buffer.lock().await;
        assert!(buffer.enqueue_volatile("A".to_owned(), 3, 9));
        assert!(!buffer.enqueue_volatile("B".to_owned(), 4, 9));
        buffer.base_stanzas = 0;
        buffer.base_bytes = 0;
        assert!(buffer.enqueue_volatile("room-b:1".to_owned(), 8, 4096));
        assert!(buffer.enqueue_volatile("room-a:2".to_owned(), 8, 4096));
        buffer.phase = SuspendedMucPhase::Resuming;
    }
    assert_eq!(
        snapshot_suspended_muc_buffer_for_resume(&endpoint)
            .await
            .unwrap(),
        vec!["A".to_owned(), "room-b:1".to_owned(), "room-a:2".to_owned()]
    );
}

#[test]
fn suspended_removal_matches_only_the_exact_created_endpoint() {
    let session = uuid::Uuid::new_v4();
    let created = Arc::new(SuspendedMucEndpoint::new(session));
    let same_session_other_endpoint = Arc::new(SuspendedMucEndpoint::new(session));
    let mut occupant = test_muc_occupant(
        "alice@example.test/Phone",
        uuid::Uuid::new_v4(),
        uuid::Uuid::new_v4(),
    );
    occupant.endpoint = MucOccupantEndpoint::Suspended(same_session_other_endpoint);
    // Two distinct endpoints may share one SM session id; only the exact
    // Arc this restore created may ever be removed by its failure path.
    assert!(!suspended_occupant_is_created(&occupant, &created));
    occupant.endpoint = MucOccupantEndpoint::Suspended(Arc::clone(&created));
    assert!(suspended_occupant_is_created(&occupant, &created));
}

#[test]
fn stale_registry_miss_adopts_the_concurrent_canonical_resume_gate() {
    let registry = Arc::new(dashmap::DashMap::new());
    let session_id = uuid::Uuid::new_v4();
    assert!(registry.get(&session_id).is_none());
    let barrier = Arc::new(std::sync::Barrier::new(3));
    let endpoints = std::thread::scope(|scope| {
        let mut workers = Vec::new();
        for _ in 0..2 {
            let registry = Arc::clone(&registry);
            let barrier = Arc::clone(&barrier);
            workers.push(scope.spawn(move || {
                let proposed = Arc::new(SuspendedMucEndpoint::new_reserved(session_id, 0, 0));
                barrier.wait();
                canonical_suspended_muc_endpoint(&registry, session_id, proposed)
            }));
        }
        barrier.wait();
        workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .collect::<Vec<_>>()
    });
    assert!(Arc::ptr_eq(&endpoints[0], &endpoints[1]));
    assert_eq!(registry.len(), 1);
}

#[test]
fn stale_restore_miss_never_overwrites_a_concurrent_joiner() {
    let occupants = dashmap::DashMap::new();
    let key = "room@example.test\0nick".to_owned();
    assert!(occupants.get(&key).is_none());
    let joiner_connection = uuid::Uuid::new_v4();
    occupants.insert(
        key.clone(),
        test_muc_occupant(
            "alice@example.test/Joiner",
            joiner_connection,
            uuid::Uuid::new_v4(),
        ),
    );
    let restored = test_muc_occupant(
        "alice@example.test/Restored",
        uuid::Uuid::new_v4(),
        uuid::Uuid::new_v4(),
    );
    assert!(!insert_restored_muc_occupant(
        &occupants,
        key.clone(),
        restored
    ));
    assert_eq!(
        occupants.get(&key).unwrap().connection_id,
        joiner_connection
    );
}

#[tokio::test]
async fn restart_reserved_and_checkpoint_owned_gates_accept_no_volatile_suffix() {
    let endpoint = SuspendedMucEndpoint::new_reserved(uuid::Uuid::new_v4(), 0, 0);
    let mut buffer = endpoint.buffer.lock().await;
    assert!(matches!(&buffer.phase, SuspendedMucPhase::Reserved));
    assert!(!buffer.enqueue_volatile("during-db-await".to_owned(), 8, 4096));
    buffer.phase = SuspendedMucPhase::CheckpointOwned;
    assert!(!buffer.enqueue_volatile("before-resumed".to_owned(), 8, 4096));
    let route = endpoint
        .route
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    assert!(matches!(&*route, SuspendedMucRoute::Suspended));
}

#[test]
fn resumed_muc_actor_swap_rejects_every_aba_identity_change() {
    let sm_session_id = uuid::Uuid::new_v4();
    let connection_id = uuid::Uuid::new_v4();
    let cluster_epoch = uuid::Uuid::new_v4();
    let endpoint = Arc::new(SuspendedMucEndpoint::new(sm_session_id));
    let mut occupant = test_muc_occupant("alice@example.test/Phone", connection_id, cluster_epoch);
    occupant.sm_session_id = Some(sm_session_id);
    occupant.endpoint = MucOccupantEndpoint::Suspended(Arc::clone(&endpoint));
    let matches = |endpoint, full_jid, connection_id, cluster_epoch| {
        suspended_muc_resume_actor_matches(
            &occupant,
            endpoint,
            full_jid,
            connection_id,
            cluster_epoch,
            sm_session_id,
        )
    };
    assert!(matches(
        &endpoint,
        "alice@example.test/Phone",
        connection_id,
        cluster_epoch
    ));
    let unrelated_endpoint = Arc::new(SuspendedMucEndpoint::new(sm_session_id));
    assert!(!matches(
        &unrelated_endpoint,
        "alice@example.test/Phone",
        connection_id,
        cluster_epoch
    ));
    assert!(!matches(
        &endpoint,
        "alice@example.test/Other",
        connection_id,
        cluster_epoch
    ));
    assert!(!matches(
        &endpoint,
        "alice@example.test/Phone",
        uuid::Uuid::new_v4(),
        cluster_epoch
    ));
    assert!(!matches(
        &endpoint,
        "alice@example.test/Phone",
        connection_id,
        uuid::Uuid::new_v4()
    ));
}

#[tokio::test]
async fn suspended_muc_promotion_mutex_orders_concurrent_admission_after_the_prefix() {
    let endpoint = Arc::new(SuspendedMucEndpoint::new(uuid::Uuid::new_v4()));
    {
        let mut buffer = endpoint.buffer.lock().await;
        assert!(buffer.enqueue_volatile("older-1".to_owned(), 8, 4096));
        assert!(buffer.enqueue_volatile("older-2".to_owned(), 8, 4096));
    }
    let started = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    let order = Arc::new(Mutex::new(Vec::new()));
    let calls = Arc::new(AtomicUsize::new(0));
    let promote_endpoint = Arc::clone(&endpoint);
    let promote_started = Arc::clone(&started);
    let promote_release = Arc::clone(&release);
    let promote_order = Arc::clone(&order);
    let promote_calls = Arc::clone(&calls);
    let promotion = tokio::spawn(async move {
        let mut buffer = promote_endpoint.buffer.lock().await;
        promote_suspended_muc_buffer(&mut buffer, move |_source_id, stanza| {
            let started = Arc::clone(&promote_started);
            let release = Arc::clone(&promote_release);
            let order = Arc::clone(&promote_order);
            let call = promote_calls.fetch_add(1, Ordering::SeqCst);
            async move {
                order.lock().unwrap().push(stanza);
                if call == 0 {
                    started.notify_one();
                    release.notified().await;
                }
                true
            }
        })
        .await
    });
    started.notified().await;
    assert!(endpoint.buffer.try_lock().is_err());

    let writer_endpoint = Arc::clone(&endpoint);
    let writer_order = Arc::clone(&order);
    let writer = tokio::spawn(async move {
        let buffer = writer_endpoint.buffer.lock().await;
        assert!(matches!(&buffer.phase, SuspendedMucPhase::Durable));
        writer_order.lock().unwrap().push("newer".to_owned());
    });
    release.notify_one();
    assert!(promotion.await.unwrap());
    writer.await.unwrap();
    assert_eq!(
        *order.lock().unwrap(),
        vec![
            "older-1".to_owned(),
            "older-2".to_owned(),
            "newer".to_owned()
        ]
    );
}

#[test]
fn staged_route_cannot_reactivate_after_identity_or_revocation_fence_changes() {
    let connection = uuid::Uuid::new_v4();
    let user = uuid::Uuid::new_v4();
    let allowed = |actual_connection,
                   actual_user,
                   actual_generation,
                   same_lifecycle,
                   lifecycle_state,
                   session_cancelled,
                   owner_cancelled| {
        staged_route_activation_allowed(StagedRouteActivationCheck {
            session: StagedRouteIdentity {
                connection_id: actual_connection,
                user_id: actual_user,
                auth_generation: actual_generation,
            },
            expected: StagedRouteIdentity {
                connection_id: connection,
                user_id: user,
                auth_generation: 7,
            },
            same_lifecycle,
            lifecycle_state,
            session_cancelled,
            owner_cancelled,
        })
    };
    assert!(allowed(connection, user, 7, true, 0, false, false));
    assert!(!allowed(
        uuid::Uuid::new_v4(),
        user,
        7,
        true,
        0,
        false,
        false
    ));
    assert!(!allowed(connection, user, 6, true, 0, false, false));
    assert!(!allowed(connection, user, 7, false, 0, false, false));
    assert!(!allowed(connection, user, 7, true, 1, false, false));
    assert!(!allowed(connection, user, 7, true, 0, true, false));
    assert!(!allowed(connection, user, 7, true, 0, false, true));
}

#[test]
fn omemo_poll_ip_window_is_sliding_and_bounded() {
    let started = Instant::now();
    let mut window = VecDeque::new();
    for offset in 0..super::OMEMO_POLL_IP_REQUESTS_PER_MINUTE {
        assert!(admit_omemo_poll_ip_window(
            &mut window,
            started + Duration::from_millis(offset as u64),
        ));
    }
    assert!(!admit_omemo_poll_ip_window(
        &mut window,
        started + Duration::from_secs(1),
    ));
    assert!(admit_omemo_poll_ip_window(
        &mut window,
        started + Duration::from_secs(61),
    ));
    assert_eq!(window.len(), 1);
}

fn test_muc_occupant(
    full_jid: &str,
    connection_id: uuid::Uuid,
    cluster_epoch: uuid::Uuid,
) -> MucOccupant {
    let (sender, _receiver) = tokio::sync::mpsc::channel(1);
    MucOccupant {
        full_jid: full_jid.to_owned(),
        room_jid: "room@conference.example.test".to_owned(),
        nick: "Alice".to_owned(),
        endpoint: MucOccupantEndpoint::Local(crate::outbound::OutboundSender::new(sender)),
        affiliation: "member".to_owned(),
        role: "participant".to_owned(),
        room_non_anonymous: true,
        occupant_id: "opaque".to_owned(),
        cluster_epoch,
        connection_id,
        sm_session_id: None,
        payload: String::new(),
    }
}

#[test]
fn kicked_session_without_occupant_cannot_authorize_a_message() {
    let connection_id = uuid::Uuid::new_v4();
    let membership = JoinedMucMembership {
        nick: "Alice".to_owned(),
        cluster_epoch: uuid::Uuid::new_v4(),
    };
    let occupant: Option<&MucOccupant> = None;
    assert!(!occupant.is_some_and(|occupant| {
        muc_actor_identity_matches(
            occupant,
            "alice@example.test/Phone",
            connection_id,
            "room@conference.example.test",
            &membership,
        )
    }));
}

#[test]
fn reused_nickname_does_not_authorize_the_old_session() {
    let old_connection = uuid::Uuid::new_v4();
    let old_membership = JoinedMucMembership {
        nick: "Alice".to_owned(),
        cluster_epoch: uuid::Uuid::new_v4(),
    };
    let replacement = test_muc_occupant(
        "bob@example.test/Laptop",
        uuid::Uuid::new_v4(),
        uuid::Uuid::new_v4(),
    );
    assert!(!muc_actor_identity_matches(
        &replacement,
        "alice@example.test/Phone",
        old_connection,
        "room@conference.example.test",
        &old_membership,
    ));
}

#[test]
fn delayed_old_drop_cannot_remove_a_reused_nickname() {
    let old_connection = uuid::Uuid::new_v4();
    let old_epoch = uuid::Uuid::new_v4();
    let replacement = test_muc_occupant(
        "alice@example.test/Phone",
        uuid::Uuid::new_v4(),
        uuid::Uuid::new_v4(),
    );
    assert!(!muc_departure_identity_matches(
        &replacement,
        "alice@example.test/Phone",
        old_connection,
        old_epoch,
    ));
}

#[test]
fn exact_muc_removal_preserves_a_reused_nickname() {
    let old_connection = uuid::Uuid::new_v4();
    let old_epoch = uuid::Uuid::new_v4();
    let replacement = test_muc_occupant(
        "alice@example.test/Phone",
        uuid::Uuid::new_v4(),
        uuid::Uuid::new_v4(),
    );
    let key = crate::xmpp::xml_util::muc_occupant_key(&replacement.room_jid, &replacement.nick);
    let occupants = DashMap::new();
    occupants.insert(key.clone(), replacement.clone());

    let stale = LocalMucOccupantIdentity {
        room_jid: &replacement.room_jid,
        nick: &replacement.nick,
        full_jid: &replacement.full_jid,
        connection_id: old_connection,
        cluster_epoch: old_epoch,
    };
    assert!(remove_local_muc_occupant_exact_from(&occupants, stale).is_none());
    assert_eq!(
        occupants.get(&key).unwrap().connection_id,
        replacement.connection_id
    );

    let exact = LocalMucOccupantIdentity::from(&replacement);
    assert!(remove_local_muc_occupant_exact_from(
        &occupants,
        LocalMucOccupantIdentity {
            connection_id: uuid::Uuid::nil(),
            ..exact
        },
    )
    .is_none());
    assert!(remove_local_muc_occupant_exact_from(&occupants, exact).is_some());
    assert!(!occupants.contains_key(&key));
}

#[test]
fn joining_again_cannot_overwrite_a_reused_nickname() {
    let old = test_muc_occupant(
        "alice@example.test/Phone",
        uuid::Uuid::new_v4(),
        uuid::Uuid::new_v4(),
    );
    let mut replacement = old.clone();
    replacement.connection_id = uuid::Uuid::new_v4();
    replacement.cluster_epoch = uuid::Uuid::new_v4();
    let key = crate::xmpp::xml_util::muc_occupant_key(&old.room_jid, &old.nick);
    let occupants = DashMap::new();

    assert_eq!(
        publish_local_muc_join_if_vacant_in(&occupants, &old),
        LocalMucJoinPublication::Published
    );
    assert_eq!(
        publish_local_muc_join_if_vacant_in(&occupants, &old),
        LocalMucJoinPublication::AlreadyPublished
    );
    assert!(
        remove_local_muc_occupant_exact_from(&occupants, LocalMucOccupantIdentity::from(&old))
            .is_some()
    );
    assert_eq!(
        publish_local_muc_join_if_vacant_in(&occupants, &replacement),
        LocalMucJoinPublication::Published
    );
    assert_eq!(
        publish_local_muc_join_if_vacant_in(&occupants, &old),
        LocalMucJoinPublication::Occupied
    );
    let stale_snapshot = replacement.clone();
    let mut later = replacement.clone();
    later.connection_id = uuid::Uuid::new_v4();
    later.cluster_epoch = uuid::Uuid::new_v4();
    occupants.insert(key.clone(), later.clone());
    assert!(remove_local_muc_occupant_exact_from(
        &occupants,
        LocalMucOccupantIdentity::from(&stale_snapshot)
    )
    .is_none());
    assert_eq!(
        publish_local_muc_join_if_vacant_in(&occupants, &old),
        LocalMucJoinPublication::Occupied,
        "a failed exact eviction must leave the later actor untouched"
    );
    assert!(
        remove_local_muc_occupant_exact_from(&occupants, LocalMucOccupantIdentity::from(&old))
            .is_none()
    );
    assert_eq!(
        occupants.get(&key).unwrap().connection_id,
        later.connection_id
    );
}

#[test]
fn delayed_committed_join_does_not_evict_a_later_published_incarnation() {
    // A can commit in PG, then lose authority while awaiting a Redis
    // operation. B can subsequently commit and publish the same nickname.
    // A's late local publication must leave B intact for exact PG checks.
    let join_a = test_muc_occupant(
        "alice@example.test/Phone",
        uuid::Uuid::new_v4(),
        uuid::Uuid::new_v4(),
    );
    let join_b = test_muc_occupant(
        "bob@example.test/Laptop",
        uuid::Uuid::new_v4(),
        uuid::Uuid::new_v4(),
    );
    let key = crate::xmpp::xml_util::muc_occupant_key(&join_a.room_jid, &join_a.nick);
    let occupants = DashMap::new();

    assert_eq!(
        publish_local_muc_join_if_vacant_in(&occupants, &join_b),
        LocalMucJoinPublication::Published
    );
    assert_eq!(
        publish_local_muc_join_if_vacant_in(&occupants, &join_a),
        LocalMucJoinPublication::Occupied
    );
    let current = occupants.get(&key).unwrap();
    assert_eq!(current.full_jid, join_b.full_jid);
    assert_eq!(current.connection_id, join_b.connection_id);
    assert_eq!(current.cluster_epoch, join_b.cluster_epoch);
}

#[test]
fn exact_muc_profile_updates_reject_a_reused_nickname() {
    let old = test_muc_occupant(
        "alice@example.test/Phone",
        uuid::Uuid::new_v4(),
        uuid::Uuid::new_v4(),
    );
    let mut replacement =
        test_muc_occupant(&old.full_jid, uuid::Uuid::new_v4(), uuid::Uuid::new_v4());
    replacement.affiliation = "none".to_owned();
    replacement.role = "visitor".to_owned();
    let key = crate::xmpp::xml_util::muc_occupant_key(&old.room_jid, &old.nick);
    let occupants = DashMap::new();
    occupants.insert(key.clone(), replacement.clone());

    let stale = LocalMucOccupantIdentity::from(&old);
    assert!(
        set_local_muc_affiliation_exact_in(&occupants, stale, "owner", true, false, None,)
            .is_none()
    );
    assert!(
        set_local_muc_role_exact_in(&occupants, stale, "visitor", "participant", None).is_none()
    );
    assert!(
        refresh_local_muc_policy_exact_in(&occupants, stale, Some(false), Some(true)).is_none()
    );
    let current = occupants.get(&key).unwrap();
    assert_eq!(current.connection_id, replacement.connection_id);
    assert_eq!(current.affiliation, "none");
    assert_eq!(current.role, "visitor");
}

#[test]
fn exact_muc_updates_preserve_registration_and_presence_fields() {
    let mut occupant = test_muc_occupant(
        "alice@example.test/Phone",
        uuid::Uuid::new_v4(),
        uuid::Uuid::new_v4(),
    );
    occupant.affiliation = "none".to_owned();
    occupant.role = "visitor".to_owned();
    occupant.payload = "<show>away</show>".to_owned();
    let suspended = Arc::new(SuspendedMucEndpoint::new(uuid::Uuid::new_v4()));
    occupant.endpoint = MucOccupantEndpoint::Suspended(Arc::clone(&suspended));
    let key = crate::xmpp::xml_util::muc_occupant_key(&occupant.room_jid, &occupant.nick);
    let occupants = DashMap::new();
    occupants.insert(key.clone(), occupant.clone());
    let identity = LocalMucOccupantIdentity::from(&occupant);

    let unchanged = set_local_muc_affiliation_exact_in(
        &occupants,
        identity,
        "member",
        true,
        true,
        Some("member"),
    );
    assert!(
        unchanged.is_none(),
        "the expected affiliation is an ABA guard"
    );
    let registered =
        set_local_muc_affiliation_exact_in(&occupants, identity, "member", true, true, None)
            .unwrap();
    assert_eq!(registered.affiliation, "member");
    assert_eq!(registered.role, "participant");
    let still_registered =
        set_local_muc_affiliation_exact_in(&occupants, identity, "owner", true, true, None)
            .unwrap();
    assert_eq!(still_registered.affiliation, "member");
    assert_eq!(still_registered.role, "participant");
    let (policy, changed) =
        refresh_local_muc_policy_exact_in(&occupants, identity, Some(false), Some(false)).unwrap();
    assert!(changed);
    assert_eq!(policy.payload, "<show>away</show>");
    assert!(
        matches!(policy.endpoint, MucOccupantEndpoint::Suspended(ref endpoint) if Arc::ptr_eq(endpoint, &suspended))
    );
    assert!(!policy.room_non_anonymous);
    assert!(
        set_local_muc_role_exact_in(&occupants, identity, "visitor", "moderator", None).is_none()
    );
}

#[test]
fn presence_refresh_rejects_reused_or_suspended_transport() {
    let old = test_muc_occupant(
        "alice@example.test/Phone",
        uuid::Uuid::new_v4(),
        uuid::Uuid::new_v4(),
    );
    let mut prepared = old.clone();
    prepared.payload = "<show>chat</show>".to_owned();
    let mut replacement =
        test_muc_occupant(&old.full_jid, uuid::Uuid::new_v4(), uuid::Uuid::new_v4());
    replacement.payload = "<show>away</show>".to_owned();
    let key = crate::xmpp::xml_util::muc_occupant_key(&old.room_jid, &old.nick);
    let occupants = DashMap::new();
    occupants.insert(key.clone(), replacement.clone());
    assert!(refresh_local_muc_presence_exact_in(&occupants, &prepared, true).is_none());
    assert_eq!(occupants.get(&key).unwrap().payload, replacement.payload);

    let mut suspended = old.clone();
    suspended.endpoint =
        MucOccupantEndpoint::Suspended(Arc::new(SuspendedMucEndpoint::new(uuid::Uuid::new_v4())));
    occupants.insert(key.clone(), suspended);
    assert!(refresh_local_muc_presence_exact_in(&occupants, &prepared, true).is_none());
    assert!(matches!(
        &occupants.get(&key).unwrap().endpoint,
        MucOccupantEndpoint::Suspended(_)
    ));
}

#[test]
fn nickname_move_restores_local_actor_and_defers_cluster_collision() {
    let old = test_muc_occupant(
        "alice@example.test/Phone",
        uuid::Uuid::new_v4(),
        uuid::Uuid::new_v4(),
    );
    let mut renamed = old.clone();
    renamed.nick = "Bob".to_owned();
    let mut other = test_muc_occupant(
        "bob@example.test/Laptop",
        uuid::Uuid::new_v4(),
        uuid::Uuid::new_v4(),
    );
    other.nick = renamed.nick.clone();
    let old_key = crate::xmpp::xml_util::muc_occupant_key(&old.room_jid, &old.nick);
    let new_key = crate::xmpp::xml_util::muc_occupant_key(&renamed.room_jid, &renamed.nick);
    let occupants = DashMap::new();
    occupants.insert(old_key.clone(), old.clone());
    occupants.insert(new_key.clone(), other.clone());

    assert_eq!(
        move_local_muc_nickname_exact_in(
            &occupants,
            LocalMucOccupantIdentity::from(&old),
            &renamed,
            false,
        ),
        LocalMucNicknameMove::CollisionRestored
    );
    assert_eq!(
        occupants.get(&old_key).unwrap().connection_id,
        old.connection_id
    );
    assert_eq!(
        occupants.get(&new_key).unwrap().connection_id,
        other.connection_id
    );

    assert_eq!(
        move_local_muc_nickname_exact_in(
            &occupants,
            LocalMucOccupantIdentity::from(&old),
            &renamed,
            true,
        ),
        LocalMucNicknameMove::DeferredToReconciliation
    );
    assert!(!occupants.contains_key(&old_key));
    assert_eq!(
        occupants.get(&new_key).unwrap().connection_id,
        other.connection_id
    );

    occupants.remove(&new_key);
    assert_eq!(
        move_local_muc_nickname_exact_in(
            &occupants,
            LocalMucOccupantIdentity::from(&old),
            &renamed,
            true,
        ),
        LocalMucNicknameMove::DeferredToReconciliation
    );
    assert!(!occupants.contains_key(&new_key));
    occupants.insert(old_key, old.clone());
    assert_eq!(
        move_local_muc_nickname_exact_in(
            &occupants,
            LocalMucOccupantIdentity::from(&old),
            &renamed,
            false,
        ),
        LocalMucNicknameMove::Published
    );
    assert_eq!(
        occupants.get(&new_key).unwrap().connection_id,
        old.connection_id
    );
}

#[test]
fn delayed_suspended_teardown_cannot_remove_resumed_connection() {
    let sm_session_id = uuid::Uuid::new_v4();
    let old_connection_id = uuid::Uuid::new_v4();
    let new_connection_id = uuid::Uuid::new_v4();
    let cluster_epoch = uuid::Uuid::new_v4();
    let mut current =
        test_muc_occupant("alice@example.test/Phone", old_connection_id, cluster_epoch);
    current.sm_session_id = Some(sm_session_id);
    current.endpoint =
        MucOccupantEndpoint::Suspended(Arc::new(SuspendedMucEndpoint::new(sm_session_id)));
    let stale_teardown = SerializableMucOccupant::from(&current);
    assert!(muc_suspended_teardown_identity_matches(
        &current,
        sm_session_id,
        &stale_teardown,
    ));

    let (sender, _receiver) = tokio::sync::mpsc::channel(1);
    current.endpoint = MucOccupantEndpoint::Local(crate::outbound::OutboundSender::new(sender));
    current.connection_id = new_connection_id;
    assert_eq!(current.cluster_epoch, stale_teardown.cluster_epoch);
    assert!(!muc_suspended_teardown_identity_matches(
        &current,
        sm_session_id,
        &stale_teardown,
    ));
}

#[test]
fn full_session_lookup_is_exact_while_bare_lookup_is_canonical() {
    assert_eq!(
        session_lookup("ALICE@Example.test/Phone"),
        Some(SessionLookup::Full("alice@example.test/Phone".to_owned()))
    );
    assert_eq!(
        session_lookup("alice@example.test/phone"),
        Some(SessionLookup::Full("alice@example.test/phone".to_owned()))
    );
    assert_ne!(
        session_lookup("alice@example.test/Phone"),
        session_lookup("alice@example.test/phone")
    );
    assert_eq!(
        session_lookup("ALICE@Example.test"),
        Some(SessionLookup::Bare("alice@example.test".to_owned()))
    );
    assert_eq!(
        session_lookup("A\u{30a}LICE@B\u{fc}CHER.Example./DeviceA\u{30a}"),
        Some(SessionLookup::Full(
            "\u{e5}lice@b\u{fc}cher.example/Device\u{c5}".to_owned()
        ))
    );
    assert_eq!(session_lookup("alice@example.test/\u{0007}"), None);
    assert_eq!(session_lookup("alice@@example.test/Phone"), None);
}

#[test]
fn cluster_muc_epoch_is_backward_compatible_and_exact() {
    let legacy = serde_json::json!({
        "full_jid": "alice@example.test/Phone",
        "room_jid": "room@conference.example.test",
        "nick": "Alice",
        "affiliation": "member",
        "role": "participant",
        "room_non_anonymous": true,
        "occupant_id": "opaque",
        "payload": ""
    });
    let legacy: SerializableMucOccupant = serde_json::from_value(legacy).unwrap();
    assert_eq!(legacy.sm_session_id, None);
    assert!(legacy.cluster_epoch.is_nil());

    let id = uuid::Uuid::new_v4();
    let current = SerializableMucOccupant {
        sm_session_id: Some(id),
        ..legacy
    };
    let round_trip: SerializableMucOccupant =
        serde_json::from_str(&serde_json::to_string(&current).unwrap()).unwrap();
    assert_eq!(round_trip.sm_session_id, Some(id));
}

#[test]
fn federation_entity_rules_follow_domain_bare_and_full_jid_specificity() {
    let phone = crate::jid::CanonicalJid::parse("alice@remote.example/Phone").unwrap();
    let laptop = crate::jid::CanonicalJid::parse("alice@remote.example/Laptop").unwrap();
    let bob = crate::jid::CanonicalJid::parse("bob@remote.example/Phone").unwrap();
    assert!(federation_rule_matches("remote.example", &phone));
    assert!(federation_rule_matches("alice@remote.example", &phone));
    assert!(federation_rule_matches(
        "alice@remote.example/Phone",
        &phone
    ));
    assert!(!federation_rule_matches(
        "alice@remote.example/Phone",
        &laptop
    ));
    assert!(!federation_rule_matches("alice@remote.example", &bob));
    assert!(!federation_rule_matches("other.example", &phone));
}

#[test]
fn service_control_only_stops_processes_started_before_the_fire_epoch() {
    let fired_at = chrono::Utc::now();
    let control = crate::db::DurableServiceControl {
        generation: uuid::Uuid::new_v4(),
        action: "restart".to_owned(),
        execute_at: fired_at - chrono::Duration::seconds(1),
        fired_at: Some(fired_at),
        expires_at: fired_at + chrono::Duration::minutes(5),
    };
    assert!(service_control_applies(
        fired_at - chrono::Duration::seconds(1),
        &control
    ));
    assert!(!service_control_applies(fired_at, &control));
    assert!(!service_control_applies(
        fired_at + chrono::Duration::seconds(1),
        &control
    ));
    let pending = crate::db::DurableServiceControl {
        fired_at: None,
        ..control
    };
    assert!(!service_control_applies(
        fired_at - chrono::Duration::seconds(1),
        &pending
    ));
}

#[test]
fn api_cursor_rotation_uses_the_shared_api_secret_overlap() {
    use crate::api::cursor::{CursorBinding, CursorDirection, CursorPosition, CursorValue};

    let old_secret = b"old-shared-api-secret-000000000001";
    let current_secret = b"new-shared-api-secret-000000000002";
    let (_old_control, old_cursor) = api_keyrings(old_secret, None).unwrap();
    let binding = CursorBinding {
        endpoint: "admin/users",
        principal_scope: b"admin-account-id",
        filter_scope: b"enabled=true",
        sort: "created_at-id",
        direction: CursorDirection::Forward,
        node_incarnation: uuid::Uuid::nil(),
    };
    let position = CursorPosition {
        last: vec![CursorValue::I64(7)],
    };
    let token = old_cursor.issue(&binding, &position, 1_000, 300).unwrap();

    let (_rotating_control, rotating_cursor) =
        api_keyrings(current_secret, Some(old_secret)).unwrap();
    assert_eq!(
        rotating_cursor.verify(&token, &binding, 1_100).unwrap(),
        position
    );

    let (_current_control, current_cursor) = api_keyrings(current_secret, None).unwrap();
    assert!(current_cursor.verify(&token, &binding, 1_100).is_err());
}

#[test]
fn ephemeral_api_control_secret_is_fixed_lowercase_hex() {
    let secret = ephemeral_api_control_secret();
    assert_eq!(secret.len(), 64);
    assert!(secret
        .iter()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte)));
    assert!(!secret.contains(&0));
    assert!(api_keyrings(&secret, None).is_ok());
}

#[test]
fn nul_containing_entropy_is_encoded_before_keyring_validation() {
    let mut entropy = [0_u8; 32];
    entropy[1] = 0xff;
    entropy[31] = 0x80;
    assert!(api_keyrings(&entropy, None).is_err());

    let encoded = encode_api_control_entropy(entropy);
    assert_eq!(&encoded[..4], b"00ff");
    assert_eq!(&encoded[62..], b"80");
    assert!(!encoded.contains(&0));
    assert!(api_keyrings(&encoded, None).is_ok());
}
