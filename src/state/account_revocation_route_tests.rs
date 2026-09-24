use super::*;
use std::time::Instant;

fn session(user_id: uuid::Uuid, generation: i64, routable: bool) -> OnlineSession {
    let connection_id = uuid::Uuid::new_v4();
    let (sender, _receiver) = tokio::sync::mpsc::channel(1);
    OnlineSession {
        user_id,
        auth_generation: generation,
        user_agent_epoch: None,
        connection_id,
        route_incarnation: RouteIncarnationSignal::new(connection_id),
        lifecycle: Arc::default(),
        metrics_counted: Arc::default(),
        routable: Arc::new(AtomicBool::new(routable)),
        sender: crate::outbound::OutboundSender::new(sender),
        available: Arc::default(),
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
        disconnect: tokio_util::sync::CancellationToken::new(),
    }
}

#[tokio::test]
async fn mix_recovery_rechecks_the_live_epoch_after_waiting_for_its_gate() {
    let sessions = Arc::new(DashMap::new());
    let full_jid = "alice@example.test/fixture";
    let current = session(uuid::Uuid::new_v4(), 1, true);
    current.available.store(true, Ordering::Release);
    current
        .caps_observation_generation
        .store(7, Ordering::Release);
    sessions.insert(full_jid.into(), current);
    let routes = mix_presence_recovery::MixPresenceRecoveryRoutes::new(Arc::clone(&sessions));
    let [(snapshot_jid, connection_id, generation)] = routes
        .local_epochs("alice@example.test")
        .try_into()
        .unwrap();
    assert_eq!(snapshot_jid, full_jid);
    let gate = routes.gate(full_jid, connection_id).unwrap();
    let held = Arc::clone(&gate).lock_owned().await;
    let (waiting_tx, waiting_rx) = tokio::sync::oneshot::channel();
    let recheck = tokio::spawn(async move {
        let _ = waiting_tx.send(());
        let _epoch = Arc::clone(&gate).lock_owned().await;
        routes.epoch_state(
            &snapshot_jid,
            connection_id,
            generation,
            &gate,
            "room@mix.example.test",
        )
    });
    waiting_rx.await.unwrap();
    sessions
        .get(full_jid)
        .unwrap()
        .caps_observation_generation
        .store(8, Ordering::Release);
    drop(held);
    assert_eq!(recheck.await.unwrap(), Some((false, false)));
}

#[test]
fn mix_recovery_rejects_a_replaced_route_even_when_its_generation_matches() {
    let sessions = Arc::new(DashMap::new());
    let full_jid = "alice@example.test/fixture";
    let old = session(uuid::Uuid::new_v4(), 1, true);
    old.available.store(true, Ordering::Release);
    sessions.insert(full_jid.into(), old);
    let routes = mix_presence_recovery::MixPresenceRecoveryRoutes::new(Arc::clone(&sessions));
    let [(snapshot_jid, connection_id, generation)] = routes
        .local_epochs("alice@example.test")
        .try_into()
        .unwrap();
    let old_gate = routes.gate(full_jid, connection_id).unwrap();
    let replacement = session(uuid::Uuid::new_v4(), 1, true);
    replacement.available.store(true, Ordering::Release);
    sessions.insert(full_jid.into(), replacement);
    assert!(routes.gate(full_jid, connection_id).is_none());
    assert_eq!(
        routes.epoch_state(
            &snapshot_jid,
            connection_id,
            generation,
            &old_gate,
            "room@mix.example.test",
        ),
        Some((false, false)),
    );
}

#[test]
fn narrow_revoker_fences_pending_old_generations_but_not_replacements() {
    let sessions = Arc::new(DashMap::new());
    let owner = uuid::Uuid::new_v4();
    sessions.insert("alice@example.test/old".into(), session(owner, 4, true));
    sessions.insert(
        "alice@example.test/pending".into(),
        session(owner, 4, false),
    );
    sessions.insert("alice@example.test/current".into(), session(owner, 5, true));
    sessions.insert(
        "alice@example.test/recreated".into(),
        session(uuid::Uuid::new_v4(), 2, true),
    );
    sessions.insert("bob@example.test/device".into(), session(owner, 1, true));

    let routes = AccountRevocationRoutes::new(Arc::clone(&sessions));
    assert_eq!(routes.revoke(owner, "alice@example.test", Some(5)), 2);
    for key in ["alice@example.test/old", "alice@example.test/pending"] {
        let entry = sessions.get(key).unwrap();
        assert!(!entry.routable.load(Ordering::Acquire));
        assert!(entry.disconnect.is_cancelled());
    }
    for key in [
        "alice@example.test/current",
        "alice@example.test/recreated",
        "bob@example.test/device",
    ] {
        let entry = sessions.get(key).unwrap();
        assert!(entry.routable.load(Ordering::Acquire));
        assert!(!entry.disconnect.is_cancelled());
    }

    routes.fence_all();
    assert!(sessions.iter().all(|entry| {
        !entry.routable.load(Ordering::Acquire) && entry.disconnect.is_cancelled()
    }));
}

#[test]
fn maintenance_snapshots_include_pending_routes_and_do_not_follow_replacements() {
    let sessions = DashMap::new();
    let key = "alice@example.test/phone";
    let user_id = uuid::Uuid::new_v4();
    let device_id = uuid::Uuid::new_v4();
    let mut old = session(user_id, 4, false);
    old.user_agent_id = Some(device_id);
    old.user_agent_epoch = Some(2);
    let old_connection_id = old.connection_id;
    sessions.insert(key.into(), old);

    let authority = local_session_authority_snapshots_in(&sessions);
    assert_eq!(authority.len(), 1);
    assert_eq!(authority[0].full_jid, key);
    assert_eq!(authority[0].authority.user_id, user_id);
    assert_eq!(authority[0].authority.auth_generation, 4);
    assert_eq!(authority[0].authority.device_id, Some(device_id));
    assert_eq!(authority[0].authority.device_epoch, Some(2));

    let replacement = session(user_id, 5, true);
    let replacement_connection_id = replacement.connection_id;
    sessions.insert(key.into(), replacement);
    let lease = local_session_lease_snapshots_in(&sessions);
    assert_eq!(lease.len(), 1);
    assert_eq!(lease[0].connection_id, replacement_connection_id);
    assert_ne!(lease[0].connection_id, old_connection_id);
    authority[0].disconnect.cancel();
    assert!(!sessions.get(key).unwrap().disconnect.is_cancelled());
}

#[test]
fn instance_and_occupancy_controls_cannot_cancel_rebound_routes() {
    let sessions = DashMap::new();
    let key = "alice@example.test/phone";
    let owner = uuid::Uuid::new_v4();
    let old = session(owner, 4, false);
    let old_connection_id = old.connection_id;
    sessions.insert(key.into(), old);

    assert!(!fence_local_session_in(
        &sessions,
        key,
        LocalSessionFence::Instance(uuid::Uuid::nil()),
    ));
    assert!(!fence_local_session_in(
        &sessions,
        key,
        LocalSessionFence::Instance(uuid::Uuid::new_v4()),
    ));
    assert!(!sessions.get(key).unwrap().disconnect.is_cancelled());
    assert!(fence_local_session_in(
        &sessions,
        key,
        LocalSessionFence::Instance(old_connection_id),
    ));
    assert!(sessions.get(key).unwrap().disconnect.is_cancelled());

    let rebound = session(owner, 5, true);
    sessions.insert(key.into(), rebound);
    assert!(!fence_local_session_in(
        &sessions,
        key,
        LocalSessionFence::Instance(old_connection_id),
    ));
    assert!(!cancel_local_session_if_connection_in(
        &sessions,
        key,
        old_connection_id,
    ));
    let current = sessions.get(key).unwrap();
    assert!(current.routable.load(Ordering::Acquire));
    assert!(!current.disconnect.is_cancelled());
}

#[test]
fn sm_and_admin_controls_require_exact_route_identity() {
    let sessions = DashMap::new();
    let key = "alice@example.test/phone";
    let owner = uuid::Uuid::new_v4();
    let sm_session_id = uuid::Uuid::new_v4();
    let live = session(owner, 4, true);
    let connection_id = live.connection_id;
    *live.sm_session_id.write().unwrap() = Some(sm_session_id);
    sessions.insert(key.into(), live);

    assert!(!fence_local_session_in(
        &sessions,
        key,
        LocalSessionFence::Sm(uuid::Uuid::new_v4()),
    ));
    for (user_id, generation, connection) in [
        (uuid::Uuid::new_v4(), 4, connection_id),
        (owner, 5, connection_id),
        (owner, 4, uuid::Uuid::new_v4()),
    ] {
        assert!(!fence_local_session_in(
            &sessions,
            key,
            LocalSessionFence::Admin {
                user_id,
                auth_generation: generation,
                connection_id: connection,
            },
        ));
    }
    assert!(sessions.get(key).unwrap().routable.load(Ordering::Acquire));
    assert!(!sessions.get(key).unwrap().disconnect.is_cancelled());
    assert!(fence_local_session_in(
        &sessions,
        key,
        LocalSessionFence::Admin {
            user_id: owner,
            auth_generation: 4,
            connection_id,
        },
    ));
    assert!(!sessions.get(key).unwrap().routable.load(Ordering::Acquire));

    let rebound = session(owner, 5, true);
    sessions.insert(key.into(), rebound);
    assert!(!fence_local_session_in(
        &sessions,
        key,
        LocalSessionFence::Sm(sm_session_id),
    ));
    assert!(!sessions.get(key).unwrap().disconnect.is_cancelled());
    *sessions.get(key).unwrap().sm_session_id.write().unwrap() = Some(sm_session_id);
    assert!(fence_local_session_in(
        &sessions,
        key,
        LocalSessionFence::Sm(sm_session_id),
    ));
    assert!(!sessions.get(key).unwrap().routable.load(Ordering::Acquire));
}

#[test]
fn staged_bind_reservation_rejects_a_second_connection() {
    let sessions = DashMap::new();
    let key = "alice@example.test/phone";
    let owner = uuid::Uuid::new_v4();
    let first = session(owner, 4, false);
    let first_connection = first.connection_id;
    assert!(try_stage_bound_session_in(&sessions, key.into(), first));
    assert!(!try_stage_bound_session_in(
        &sessions,
        key.into(),
        session(owner, 4, false),
    ));
    assert_eq!(sessions.get(key).unwrap().connection_id, first_connection);
    assert!(!sessions.get(key).unwrap().routable.load(Ordering::Acquire));
}

#[test]
fn sm_takeover_inspection_preserves_exact_owner_and_presence_gate() {
    let sessions = DashMap::new();
    let key = "alice@example.test/phone";
    let owner = uuid::Uuid::new_v4();
    let sm_id = uuid::Uuid::new_v4();
    let old = session(owner, 4, true);
    let old_connection = old.connection_id;
    *old.sm_session_id.write().unwrap() = Some(sm_id);
    let old_gate = Arc::clone(&old.mix_presence_gate);
    let old_signal = Arc::clone(&old.route_incarnation);
    sessions.insert(key.into(), old);
    let candidate = || session(owner, 4, false);

    assert!(matches!(
        stage_sm_resumed_session_in(
            &sessions,
            key.into(),
            candidate(),
            uuid::Uuid::new_v4(),
            sm_id,
            &old_gate,
        ),
        SmStagedRouteClaim::Conflict
    ));
    assert!(matches!(
        stage_sm_resumed_session_in(
            &sessions,
            key.into(),
            candidate(),
            owner,
            uuid::Uuid::new_v4(),
            &old_gate,
        ),
        SmStagedRouteClaim::Conflict
    ));
    let other_gate = Arc::new(tokio::sync::Mutex::new(()));
    let SmStagedRouteClaim::AdoptPresenceEpoch(epoch) = stage_sm_resumed_session_in(
        &sessions,
        key.into(),
        candidate(),
        owner,
        sm_id,
        &other_gate,
    ) else {
        panic!("SM takeover must adopt the current resource gate");
    };
    assert!(Arc::ptr_eq(&epoch.gate, &old_gate));
    let SmStagedRouteClaim::Replace {
        connection_id,
        route_incarnation,
        ..
    } = stage_sm_resumed_session_in(&sessions, key.into(), candidate(), owner, sm_id, &old_gate)
    else {
        panic!("SM takeover must name the exact old connection");
    };
    assert_eq!(connection_id, old_connection);
    assert!(Arc::ptr_eq(&route_incarnation, &old_signal));
    assert_eq!(sessions.get(key).unwrap().connection_id, old_connection);

    let vacant = DashMap::new();
    assert!(matches!(
        stage_sm_resumed_session_in(&vacant, key.into(), candidate(), owner, sm_id, &old_gate,),
        SmStagedRouteClaim::Inserted
    ));
    assert_eq!(vacant.len(), 1);
}
