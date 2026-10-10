//! Unit tests for the durable operation worker runtime.

use super::*;
use crate::services::operation_muc_destroy::MucDestroyAudience;
use crate::state::{remove_local_muc_occupant_exact_from, MucOccupant, MucOccupantEndpoint};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;
use tokio::sync::Notify;

fn session(
    user_id: Uuid,
    generation: i64,
    connection_id: Uuid,
    sender: tokio::sync::mpsc::Sender<crate::outbound::OutboundItem>,
) -> crate::state::OnlineSession {
    crate::state::OnlineSession {
        user_id,
        auth_generation: generation,
        user_agent_epoch: None,
        connection_id,
        route_incarnation: crate::state::RouteIncarnationSignal::new(connection_id),
        lifecycle: Arc::default(),
        metrics_counted: Arc::default(),
        routable: Arc::new(AtomicBool::new(true)),
        sender: crate::outbound::OutboundSender::new(sender),
        available: Arc::default(),
        availability_generation: Arc::default(),
        post_actions: crate::xmpp::protocol::PostActionHandle::default(),
        recovery_replay_inflight_epoch: Arc::default(),
        recovery_replay_completed_epoch: Arc::default(),
        bind2_mam_catchup: false,
        mix_presence_gate: Arc::default(),
        mix_presence_fallback_suppressed: Arc::default(),
        caps_observation_generation: Arc::default(),
        carbons: Arc::default(),
        priority: Arc::default(),
        show: Arc::default(),
        blocklist_requested: Arc::default(),
        roster_requested: Arc::default(),
        roster_sync: Arc::default(),
        mix_roster_annotations: Arc::default(),
        privacy_active: Arc::default(),
        privacy_requested: Arc::default(),
        directed_presence: Arc::default(),
        last_presence: Arc::default(),
        ip: None,
        resource: "fixture".into(),
        user_agent_id: None,
        sm_session_id: Arc::default(),
        muc_memberships: Arc::default(),
        connected_at: Instant::now(),
        last_activity: Arc::new(std::sync::RwLock::new(Instant::now())),
        disconnect: CancellationToken::new(),
    }
}

fn muc_occupant(
    room_jid: &str,
    full_jid: &str,
    nick: &str,
    incarnation: Uuid,
    connection_id: Uuid,
) -> MucOccupant {
    let (sender, _receiver) = tokio::sync::mpsc::channel(1);
    MucOccupant {
        full_jid: full_jid.into(),
        room_jid: room_jid.into(),
        nick: nick.into(),
        endpoint: MucOccupantEndpoint::Local(crate::outbound::OutboundSender::new(sender)),
        affiliation: "member".into(),
        role: "participant".into(),
        room_non_anonymous: false,
        occupant_id: "fixture".into(),
        cluster_epoch: incarnation,
        connection_id,
        sm_session_id: None,
        payload: String::new(),
    }
}

#[test]
fn committed_muc_destroy_only_removes_the_captured_occupant_generation() {
    let room_jid = "room@conference.example.test";
    let full_jid = "alice@example.test/phone";
    let nick = "Alice";
    let key = crate::xmpp::xml_util::muc_occupant_key(room_jid, nick);
    let old_incarnation = Uuid::new_v4();
    let old_connection = Uuid::new_v4();
    let committed = MucDestroyCommit {
        room_jid: room_jid.into(),
        destroyed: true,
        audience: vec![MucDestroyAudience {
            full_jid: full_jid.into(),
            nick: nick.into(),
            occupant_incarnation: old_incarnation,
            connection_id: old_connection,
        }],
    };
    let occupants = dashmap::DashMap::new();

    // After the tombstone commits, the same connection may join a newly
    // created room with the same JID and nick. Its new occupancy survives.
    let recreated_incarnation = Uuid::new_v4();
    occupants.insert(
        key.clone(),
        muc_occupant(
            room_jid,
            full_jid,
            nick,
            recreated_incarnation,
            old_connection,
        ),
    );
    let remove = |identity| remove_local_muc_occupant_exact_from(&occupants, identity).is_some();
    assert_eq!(remove_committed_muc_audience(&committed, remove), 0);
    assert_eq!(
        occupants.get(&key).unwrap().cluster_epoch,
        recreated_incarnation
    );

    // A resumed transport that replaced the old connection must also
    // survive this stale cleanup, even if its occupant incarnation matches.
    let resumed_connection = Uuid::new_v4();
    occupants.insert(
        key.clone(),
        muc_occupant(
            room_jid,
            full_jid,
            nick,
            old_incarnation,
            resumed_connection,
        ),
    );
    let remove = |identity| remove_local_muc_occupant_exact_from(&occupants, identity).is_some();
    assert_eq!(remove_committed_muc_audience(&committed, remove), 0);
    assert_eq!(
        occupants.get(&key).unwrap().connection_id,
        resumed_connection
    );

    occupants.insert(
        key.clone(),
        muc_occupant(room_jid, full_jid, nick, old_incarnation, old_connection),
    );
    let remove = |identity| remove_local_muc_occupant_exact_from(&occupants, identity).is_some();
    assert_eq!(remove_committed_muc_audience(&committed, remove), 1);
    assert!(!occupants.contains_key(&key));

    let unrelated_room = "other@conference.example.test";
    let unrelated_key = crate::xmpp::xml_util::muc_occupant_key(unrelated_room, nick);
    occupants.insert(
        unrelated_key.clone(),
        muc_occupant(
            unrelated_room,
            full_jid,
            nick,
            old_incarnation,
            old_connection,
        ),
    );
    let remove = |identity| remove_local_muc_occupant_exact_from(&occupants, identity).is_some();
    assert_eq!(remove_committed_muc_audience(&committed, remove), 0);
    assert!(occupants.contains_key(&unrelated_key));
}

#[tokio::test]
async fn panic_disconnect_cancels_every_local_route_before_sm_teardown() {
    let sessions = Arc::new(dashmap::DashMap::new());
    let routes = LocalPanicDisconnectRoutes::new(Arc::clone(&sessions));
    let add = |key: &str, routable: bool| {
        let (sender, _receiver) = tokio::sync::mpsc::channel(1);
        let session = session(Uuid::new_v4(), 3, Uuid::new_v4(), sender);
        session.routable.store(routable, Ordering::Release);
        let cancelled = session.disconnect.clone();
        sessions.insert(key.to_owned(), session);
        cancelled
    };
    let active = add("alice@example.test/phone", true);
    let pending = add("alice@example.test/pending", false);
    let previously_cancelled = add("bob@example.test/device", true);
    previously_cancelled.cancel();

    let result = panic_disconnect_with(&routes, || {
        assert!(active.is_cancelled());
        assert!(pending.is_cancelled());
        assert!(previously_cancelled.is_cancelled());
        async { Ok(12) }
    })
    .await
    .unwrap();
    assert_eq!(result, json!({"sessions_disconnected":3}));
    assert!(sessions
        .get("alice@example.test/phone")
        .unwrap()
        .routable
        .load(Ordering::Acquire));
    assert!(!sessions
        .get("alice@example.test/pending")
        .unwrap()
        .routable
        .load(Ordering::Acquire));

    let error = panic_disconnect_with(&routes, || {
        assert!(active.is_cancelled());
        async { anyhow::bail!("durable SM teardown failed") }
    })
    .await
    .unwrap_err();
    assert_eq!(error.to_string(), "durable SM teardown failed");
    assert_eq!(routes.cancel_all(), 3);
}

#[test]
fn exact_session_kick_cancels_pending_route_without_touching_replacements() {
    let sessions = Arc::new(dashmap::DashMap::new());
    let routes = LocalSessionKickRoutes::new(Arc::clone(&sessions));
    let user_id = Uuid::new_v4();
    let old_connection = Uuid::new_v4();
    let (old_sender, _old_receiver) = tokio::sync::mpsc::channel(1);
    let old = session(user_id, 4, old_connection, old_sender);
    old.routable.store(false, Ordering::Release);
    let old_disconnect = old.disconnect.clone();
    sessions.insert("alice@example.test/phone".into(), old);

    assert!(!routes.kick_exact(Uuid::new_v4(), 4, old_connection));
    assert!(!routes.kick_exact(user_id, 5, old_connection));
    assert!(!routes.kick_exact(user_id, 4, Uuid::new_v4()));
    assert!(!old_disconnect.is_cancelled());

    assert!(routes.kick_exact(user_id, 4, old_connection));
    assert!(old_disconnect.is_cancelled());
    assert!(routes.kick_exact(user_id, 4, old_connection));
    assert!(!sessions
        .get("alice@example.test/phone")
        .unwrap()
        .routable
        .load(Ordering::Acquire));

    let new_connection = Uuid::new_v4();
    let (new_sender, _new_receiver) = tokio::sync::mpsc::channel(1);
    let replacement = session(user_id, 5, new_connection, new_sender);
    let new_disconnect = replacement.disconnect.clone();
    sessions.insert("alice@example.test/phone".into(), replacement);
    assert!(!routes.kick_exact(user_id, 4, old_connection));
    assert!(!new_disconnect.is_cancelled());
    assert!(routes.kick_exact(user_id, 5, new_connection));
    assert!(new_disconnect.is_cancelled());
}

#[test]
fn session_kick_payload_errors_remain_at_effect_decoding() {
    let user_id = Uuid::new_v4();
    let connection_id = Uuid::new_v4();
    for (payload, expected) in [
        (json!({}), "user_id is missing"),
        (json!({"user_id":"not-a-uuid"}), "user_id is invalid"),
        (json!({"user_id":Uuid::nil()}), "user_id must not be nil"),
        (json!({"user_id":user_id}), "connection_id is missing"),
        (
            json!({"user_id":user_id,"connection_id":"not-a-uuid"}),
            "connection_id is invalid",
        ),
        (
            json!({"user_id":user_id,"connection_id":Uuid::nil()}),
            "connection_id must not be nil",
        ),
        (
            json!({"user_id":user_id,"connection_id":connection_id}),
            "auth generation is missing",
        ),
    ] {
        assert_eq!(
            session_kick_identity(&payload).unwrap_err().to_string(),
            expected
        );
    }
    assert_eq!(
        session_kick_identity(&json!({
            "user_id":user_id,
            "connection_id":connection_id,
            "auth_generation":7
        }))
        .unwrap(),
        (user_id, connection_id, 7)
    );
}

#[test]
fn generation_cleanup_counts_all_exact_resources_including_pending_on_retry() {
    let sessions = Arc::new(dashmap::DashMap::new());
    let routes = LocalGenerationCleanupRoutes::new(Arc::clone(&sessions));
    let user_id = Uuid::new_v4();
    let other_user = Uuid::new_v4();
    let add = |key: &str, owner: Uuid, generation: i64, routable: bool| {
        let (sender, _receiver) = tokio::sync::mpsc::channel(1);
        let session = session(owner, generation, Uuid::new_v4(), sender);
        session.routable.store(routable, Ordering::Release);
        let cancelled = session.disconnect.clone();
        sessions.insert(key.to_owned(), session);
        cancelled
    };
    let phone = add("alice@example.test/phone", user_id, 3, true);
    let pending = add("alice@example.test/pending", user_id, 3, false);
    let older = add("alice@example.test/older", user_id, 2, true);
    let newer = add("alice@example.test/newer", user_id, 4, true);
    let recreated = add("alice@example.test/recreated", other_user, 3, true);

    assert_eq!(routes.cancel_exact_generation(user_id, 3), 2);
    assert!(phone.is_cancelled());
    assert!(pending.is_cancelled());
    assert!(!older.is_cancelled());
    assert!(!newer.is_cancelled());
    assert!(!recreated.is_cancelled());
    assert!(!sessions
        .get("alice@example.test/pending")
        .unwrap()
        .routable
        .load(Ordering::Acquire));
    assert!(sessions
        .get("alice@example.test/phone")
        .unwrap()
        .routable
        .load(Ordering::Acquire));
    assert_eq!(routes.cancel_exact_generation(user_id, 3), 2);
    assert!(!older.is_cancelled());
    assert!(!newer.is_cancelled());
    assert!(!recreated.is_cancelled());
}

#[test]
fn generation_cleanup_payload_errors_match_effect_decoding() {
    let user_id = Uuid::new_v4();
    for (payload, expected) in [
        (json!({}), "user_id is missing"),
        (json!({"user_id":"not-a-uuid"}), "user_id is invalid"),
        (json!({"user_id":Uuid::nil()}), "user_id must not be nil"),
        (json!({"user_id":user_id}), "auth generation is missing"),
    ] {
        assert_eq!(
            generation_cleanup_identity(&payload)
                .unwrap_err()
                .to_string(),
            expected
        );
    }
    assert_eq!(
        generation_cleanup_identity(&json!({"user_id":user_id,"auth_generation":3})).unwrap(),
        (user_id, 3)
    );
}

#[test]
fn broadcast_effect_rechecks_snapshot_identity_and_does_not_send_to_replacement() {
    let sessions = Arc::new(dashmap::DashMap::new());
    let routes = LocalBroadcastRoutes::new(
        Arc::clone(&sessions),
        "example.test".into(),
        "node-1".into(),
    );
    let key = "alice@example.test/phone";
    let user_id = Uuid::new_v4();
    let old_connection = Uuid::new_v4();
    let (old_sender, mut old_receiver) = tokio::sync::mpsc::channel(1);
    sessions.insert(key.into(), session(user_id, 3, old_connection, old_sender));
    let operation_payload = json!({"message":"<&>'\""});
    let old_seed = routes
        .target_snapshot()
        .target_seeds(ClaimedOperation {
            kind: "admin.broadcast",
            payload: &operation_payload,
        })
        .unwrap()
        .pop()
        .unwrap();

    let new_connection = Uuid::new_v4();
    let (new_sender, mut new_receiver) = tokio::sync::mpsc::channel(1);
    sessions.insert(key.into(), session(user_id, 4, new_connection, new_sender));
    assert_eq!(
        routes.send_exact(&old_seed.payload).unwrap(),
        json!({"sent":false,"connection_id":old_connection})
    );
    assert!(old_receiver.try_recv().is_err());
    assert!(new_receiver.try_recv().is_err());

    let new_seed = routes
        .target_snapshot()
        .target_seeds(ClaimedOperation {
            kind: "admin.broadcast",
            payload: &operation_payload,
        })
        .unwrap()
        .pop()
        .unwrap();
    for (field, replacement) in [
        ("user_id", json!(Uuid::new_v4())),
        ("auth_generation", json!(3)),
        ("connection_id", json!(old_connection)),
    ] {
        let mut stale = new_seed.payload.clone();
        stale[field] = replacement;
        assert_eq!(
            stale.get("session_key"),
            new_seed.payload.get("session_key")
        );
        assert_eq!(routes.send_exact(&stale).unwrap()["sent"], false);
    }
    assert!(new_receiver.try_recv().is_err());
    sessions
        .get(key)
        .unwrap()
        .routable
        .store(false, Ordering::Release);
    assert_eq!(routes.send_exact(&new_seed.payload).unwrap()["sent"], false);
    sessions
        .get(key)
        .unwrap()
        .routable
        .store(true, Ordering::Release);

    assert_eq!(
        routes.send_exact(&new_seed.payload).unwrap(),
        json!({"sent":true,"connection_id":new_connection})
    );
    let stanza = new_receiver.try_recv().unwrap().stanza;
    assert!(stanza.contains("from='example.test' type='headline' id='"));
    assert!(stanza.contains("<body>&lt;&amp;&gt;&apos;&quot;</body>"));
}

#[test]
fn broadcast_effect_reports_full_queue_and_empty_snapshot_without_delivery() {
    let sessions = Arc::new(dashmap::DashMap::new());
    let routes = LocalBroadcastRoutes::new(
        Arc::clone(&sessions),
        "example.test".into(),
        "node-1".into(),
    );
    let operation_payload = json!({"message":"maintenance"});
    let empty = routes
        .target_snapshot()
        .target_seeds(ClaimedOperation {
            kind: "admin.broadcast",
            payload: &operation_payload,
        })
        .unwrap();
    assert_eq!(empty[0].target_key, "node:node-1");
    assert_eq!(empty[0].ordinal, 0);
    assert_eq!(
        routes.send_exact(&empty[0].payload).unwrap(),
        json!({"sent":false,"reason":"empty_snapshot"})
    );

    let key = "alice@example.test/phone";
    let connection_id = Uuid::new_v4();
    let (sender, mut receiver) = tokio::sync::mpsc::channel(1);
    sessions.insert(
        key.into(),
        session(Uuid::new_v4(), 3, connection_id, sender),
    );
    let seed = routes
        .target_snapshot()
        .target_seeds(ClaimedOperation {
            kind: "admin.broadcast",
            payload: &operation_payload,
        })
        .unwrap()
        .pop()
        .unwrap();
    assert_eq!(routes.send_exact(&seed.payload).unwrap()["sent"], true);
    assert_eq!(routes.send_exact(&seed.payload).unwrap()["sent"], false);
    assert!(receiver
        .try_recv()
        .unwrap()
        .stanza
        .contains("<body>maintenance</body>"));
    assert!(receiver.try_recv().is_err());
}

#[test]
fn broadcast_target_snapshot_preserves_connection_order_and_payload() {
    let alice = Uuid::new_v4();
    let bob = Uuid::new_v4();
    let alice_connection = Uuid::new_v4();
    let bob_connection = Uuid::new_v4();
    let operation_payload = json!({"message":"maintenance"});
    let seeds = target_seeds_for_operation(
        ClaimedOperation {
            kind: "admin.broadcast",
            payload: &operation_payload,
        },
        "node-1",
        [
            BroadcastRoute {
                session_key: "alice@example.test/phone".to_owned(),
                user_id: alice,
                auth_generation: 3,
                connection_id: alice_connection,
            },
            BroadcastRoute {
                session_key: "bob@example.test/laptop".to_owned(),
                user_id: bob,
                auth_generation: 5,
                connection_id: bob_connection,
            },
        ]
        .into_iter(),
    )
    .unwrap();
    assert_eq!(seeds.len(), 2);
    assert_eq!(
        seeds[0].target_key,
        format!("connection:{alice_connection}")
    );
    assert_eq!(seeds[0].ordinal, 0);
    assert_eq!(
        seeds[0].payload,
        json!({
            "message":"maintenance",
            "session_key":"alice@example.test/phone",
            "user_id":alice,
            "auth_generation":3,
            "connection_id":alice_connection,
        })
    );
    assert_eq!(seeds[1].target_key, format!("connection:{bob_connection}"));
    assert_eq!(seeds[1].ordinal, 1);
    assert_eq!(
        seeds[1].payload,
        json!({
            "message":"maintenance",
            "session_key":"bob@example.test/laptop",
            "user_id":bob,
            "auth_generation":5,
            "connection_id":bob_connection,
        })
    );
}

#[test]
fn empty_broadcast_and_nonbroadcast_target_fallbacks_are_exact() {
    for (kind, payload, expected_key) in [
        (
            "admin.broadcast",
            json!({"message":"maintenance"}),
            "node:node-1",
        ),
        ("admin.tls_reload", json!({}), "node:node-1"),
        (
            "admin.session_kick",
            json!({"connection_id":"exact-connection"}),
            "connection:exact-connection",
        ),
    ] {
        let seeds = target_seeds_for_operation(
            ClaimedOperation {
                kind,
                payload: &payload,
            },
            "node-1",
            std::iter::empty(),
        )
        .unwrap();
        assert_eq!(seeds.len(), 1);
        assert_eq!(seeds[0].target_key, expected_key);
        assert_eq!(seeds[0].ordinal, 0);
        assert_eq!(seeds[0].payload, payload);
    }
}

struct DropSignal(Arc<AtomicBool>);

impl Drop for DropSignal {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}

#[tokio::test]
async fn cleanup_effect_success_cancels_and_reaps_renewal() {
    let renewal_stopped = Arc::new(AtomicBool::new(false));
    let renewal_stopped_in_task = Arc::clone(&renewal_stopped);

    let value = execute_with_lease_renewal(async { Ok(42_u8) }, move |stop| async move {
        stop.cancelled().await;
        renewal_stopped_in_task.store(true, Ordering::Release);
        Ok(())
    })
    .await
    .expect("the cleanup effect must succeed");

    assert_eq!(value, 42);
    assert!(
        renewal_stopped.load(Ordering::Acquire),
        "the effect result must not escape before renewal observes cancellation"
    );
}

#[tokio::test]
async fn cleanup_effect_error_cancels_and_reaps_renewal() {
    let renewal_stopped = Arc::new(AtomicBool::new(false));
    let renewal_stopped_in_task = Arc::clone(&renewal_stopped);

    let error = execute_with_lease_renewal(
        async { Err::<(), anyhow::Error>(anyhow::anyhow!("injected cleanup effect failure")) },
        move |stop| async move {
            stop.cancelled().await;
            renewal_stopped_in_task.store(true, Ordering::Release);
            Ok(())
        },
    )
    .await
    .expect_err("the cleanup effect must preserve its failure");

    assert!(error
        .to_string()
        .contains("injected cleanup effect failure"));
    assert!(
        renewal_stopped.load(Ordering::Acquire),
        "the effect result must not escape before renewal observes cancellation"
    );
}

#[tokio::test]
async fn cleanup_attempt_cancellation_cannot_detach_renewal() {
    let renewal_started = Arc::new(Notify::new());
    let renewal_started_in_task = Arc::clone(&renewal_started);
    let renewal_dropped = Arc::new(AtomicBool::new(false));
    let renewal_dropped_in_task = Arc::clone(&renewal_dropped);

    let attempt = tokio::spawn(execute_with_lease_renewal(
        std::future::pending::<Result<()>>(),
        move |_stop| async move {
            let _drop_signal = DropSignal(renewal_dropped_in_task);
            renewal_started_in_task.notify_one();
            std::future::pending::<Result<()>>().await
        },
    ));
    tokio::time::timeout(Duration::from_secs(1), renewal_started.notified())
        .await
        .expect("renewal did not enter its structured scope");

    attempt.abort();
    let join_error = attempt
        .await
        .expect_err("the injected attempt cancellation must abort its parent future");
    assert!(join_error.is_cancelled());
    assert!(
        renewal_dropped.load(Ordering::Acquire),
        "dropping the parent attempt must synchronously drop its renewal child"
    );
}

#[tokio::test]
async fn renewal_failure_stops_the_cleanup_effect() {
    let effect_dropped = Arc::new(AtomicBool::new(false));
    let effect_dropped_in_task = Arc::clone(&effect_dropped);

    let error = execute_with_lease_renewal(
        async move {
            let _drop_signal = DropSignal(effect_dropped_in_task);
            std::future::pending::<Result<()>>().await
        },
        |_stop| async { anyhow::bail!("injected renewal failure") },
    )
    .await
    .expect_err("renewal failure must fence the cleanup effect");

    assert!(error.to_string().contains("lease renewal failed"));
    assert!(
        effect_dropped.load(Ordering::Acquire),
        "an effect must not outlive its failed renewal fence"
    );
}

#[tokio::test]
async fn spawned_heartbeat_stops_after_effect_completes() {
    let (tx, rx) = tokio::sync::oneshot::channel();
    let result = execute_with_spawned_heartbeat(async { 7 }, |stop| async move {
        stop.cancelled().await;
        let _ = tx.send(());
        Ok(())
    })
    .await
    .unwrap();

    assert_eq!(result, 7);
    rx.await.unwrap();
}

#[tokio::test]
async fn spawned_heartbeat_stops_when_effect_future_is_dropped() {
    let (tx, rx) = tokio::sync::oneshot::channel();
    let task = execute_with_spawned_heartbeat(std::future::pending::<()>(), |stop| async move {
        stop.cancelled().await;
        let _ = tx.send(());
        Ok(())
    });
    let timeout_result = tokio::time::timeout(Duration::from_millis(20), task).await;
    assert!(timeout_result.is_err()); // Times out, dropping the future

    tokio::time::timeout(Duration::from_secs(1), rx)
        .await
        .expect("should not time out waiting for receiver")
        .expect("should receive oneshot message");
}

#[tokio::test]
async fn spawned_heartbeat_failure_is_reported_after_effect() {
    let error = execute_with_spawned_heartbeat(
        async {
            tokio::time::sleep(Duration::from_millis(10)).await;
        },
        |_stop| async move { Err(anyhow::anyhow!("lease fencing was lost")) },
    )
    .await
    .expect_err("should return heartbeat error");

    assert!(error.to_string().contains("lease fencing was lost"));
}
