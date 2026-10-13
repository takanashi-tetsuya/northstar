//! Tests of the local session route helpers.

use super::*;

const KEY: &str = "alice@example.test/fixture";

pub(super) fn session(
    connection_id: uuid::Uuid,
    user_id: uuid::Uuid,
    routable: bool,
) -> (
    OnlineSession,
    tokio::sync::mpsc::Receiver<crate::xmpp::outbound::OutboundItem>,
) {
    let (sender, receiver) = tokio::sync::mpsc::channel(1);
    let now = Instant::now();
    (
        OnlineSession {
            user_id,
            auth_generation: 7,
            user_agent_epoch: None,
            connection_id,
            route_incarnation: RouteIncarnationSignal::new(connection_id),
            lifecycle: Arc::default(),
            metrics_counted: Arc::default(),
            routable: Arc::new(AtomicBool::new(routable)),
            sender: crate::xmpp::outbound::OutboundSender::new(sender),
            available: Arc::default(),
            availability_generation: Arc::default(),
            post_actions: crate::xmpp::protocol::PostActionHandle::default(),
            recovery_replay_inflight_epoch: Arc::default(),
            recovery_replay_completed_epoch: Arc::default(),
            bind2_mam_catchup: false,
            mix_presence_gate: Arc::default(),
            mix_presence_fallback_suppressed: Arc::default(),
            caps_observation_generation: Arc::new(AtomicU64::new(11)),
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
            connected_at: now,
            last_activity: Arc::new(std::sync::RwLock::new(now)),
            disconnect: CancellationToken::new(),
        },
        receiver,
    )
}

#[test]
fn epoch_mapping_and_activation_publish_the_exact_staged_queue() {
    let sessions = DashMap::new();
    let (staged, mut receiver) = session(uuid::Uuid::from_u128(1), uuid::Uuid::from_u128(2), false);
    let (other, mut other_receiver) =
        session(uuid::Uuid::from_u128(3), uuid::Uuid::from_u128(2), false);
    sessions.insert(KEY.to_owned(), staged.clone());
    sessions.insert("alice@example.test/other".to_owned(), other);
    assert!(session_entries_for_in(&sessions, KEY).is_empty());
    assert!(session_entries_for_in(&sessions, "alice@example.test").is_empty());

    assert!(publish_user_agent_epoch_if_current_in(
        &sessions,
        KEY,
        staged.connection_id,
        staged.user_id,
        staged.auth_generation,
        &staged.lifecycle,
        Some(43),
    ));
    assert_eq!(sessions.get(KEY).unwrap().user_agent_epoch, Some(43));
    assert!(session_entries_for_in(&sessions, KEY).is_empty());
    assert!(activate_session_if_current_in(
        &sessions,
        KEY,
        staged.connection_id,
        staged.user_id,
        staged.auth_generation,
        &staged.lifecycle,
        &staged.disconnect,
    ));
    let targets = session_entries_for_in(&sessions, "ALICE@EXAMPLE.TEST/fixture");
    assert_eq!(targets.len(), 1);
    let (key, route) = &targets[0];
    assert_eq!(key, KEY);
    assert_eq!(route.connection_id, staged.connection_id);
    assert_eq!(route.user_id, staged.user_id);
    assert_eq!(route.auth_generation, staged.auth_generation);
    assert_eq!(route.user_agent_epoch, Some(43));
    assert!(Arc::ptr_eq(&route.lifecycle, &staged.lifecycle));
    assert!(Arc::ptr_eq(&route.routable, &staged.routable));
    assert_eq!(route.lifecycle.load(Ordering::Acquire), 0);
    assert!(route.routable.load(Ordering::Acquire));
    assert_eq!(
        session_entries_for_in(&sessions, "alice@example.test").len(),
        1
    );
    route.sender.try_send("<message/>".to_owned()).unwrap();
    assert_eq!(receiver.try_recv().unwrap().stanza, "<message/>");
    assert!(matches!(
        other_receiver.try_recv(),
        Err(tokio::sync::mpsc::error::TryRecvError::Empty)
    ));
    // A subsequent map write is possible after both helper calls and lookup.
    assert!(sessions.remove(KEY).is_some());
}

#[test]
fn epoch_mapping_assigns_the_supplied_option_without_activating() {
    for routable in [false, true] {
        let sessions = DashMap::new();
        let (route, _receiver) =
            session(uuid::Uuid::from_u128(1), uuid::Uuid::from_u128(2), routable);
        sessions.insert(KEY.to_owned(), route.clone());
        for epoch in [Some(0), Some(43), None] {
            assert!(publish_user_agent_epoch_if_current_in(
                &sessions,
                KEY,
                route.connection_id,
                route.user_id,
                route.auth_generation,
                &route.lifecycle,
                epoch,
            ));
            assert_eq!(sessions.get(KEY).unwrap().user_agent_epoch, epoch);
            assert_eq!(route.routable.load(Ordering::Acquire), routable);
        }
    }
}

#[test]
fn epoch_mapping_rejects_noncurrent_identity_and_closed_sessions() {
    for case in [
        "missing key",
        "noncanonical key",
        "connection",
        "user",
        "generation",
        "lifecycle pointer",
        "lifecycle one",
        "lifecycle two",
        "session cancelled",
    ] {
        let sessions = DashMap::new();
        let (mut route, _receiver) =
            session(uuid::Uuid::from_u128(1), uuid::Uuid::from_u128(2), false);
        route.user_agent_epoch = Some(13);
        let mut key = KEY;
        let mut connection = route.connection_id;
        let mut user = route.user_id;
        let mut generation = route.auth_generation;
        let mut lifecycle = Arc::clone(&route.lifecycle);
        match case {
            "missing key" => key = "alice@example.test/missing",
            "noncanonical key" => key = "ALICE@EXAMPLE.TEST/fixture",
            "connection" => connection = uuid::Uuid::from_u128(3),
            "user" => user = uuid::Uuid::from_u128(4),
            "generation" => generation += 1,
            "lifecycle pointer" => lifecycle = Arc::new(AtomicU8::new(0)),
            "lifecycle one" => route.lifecycle.store(1, Ordering::Release),
            "lifecycle two" => route.lifecycle.store(2, Ordering::Release),
            "session cancelled" => route.disconnect.cancel(),
            _ => unreachable!(),
        }
        sessions.insert(KEY.to_owned(), route.clone());
        assert!(
            !publish_user_agent_epoch_if_current_in(
                &sessions,
                key,
                connection,
                user,
                generation,
                &lifecycle,
                Some(43),
            ),
            "{case}"
        );
        assert_eq!(
            sessions.get(KEY).unwrap().user_agent_epoch,
            Some(13),
            "{case}"
        );
        assert!(!route.routable.load(Ordering::Acquire), "{case}");
        assert_eq!(sessions.len(), 1);
    }
}

#[test]
fn activation_rejects_noncurrent_identity_and_preclosed_routes() {
    for case in [
        "missing key",
        "noncanonical key",
        "connection",
        "user",
        "generation",
        "lifecycle pointer",
        "lifecycle one",
        "lifecycle two",
        "session cancelled",
        "owner cancelled",
    ] {
        let sessions = DashMap::new();
        let (route, _receiver) = session(uuid::Uuid::from_u128(1), uuid::Uuid::from_u128(2), false);
        let mut key = KEY;
        let mut connection = route.connection_id;
        let mut user = route.user_id;
        let mut generation = route.auth_generation;
        let mut lifecycle = Arc::clone(&route.lifecycle);
        let owner = CancellationToken::new();
        match case {
            "missing key" => key = "alice@example.test/missing",
            "noncanonical key" => key = "ALICE@EXAMPLE.TEST/fixture",
            "connection" => connection = uuid::Uuid::from_u128(3),
            "user" => user = uuid::Uuid::from_u128(4),
            "generation" => generation += 1,
            "lifecycle pointer" => lifecycle = Arc::new(AtomicU8::new(0)),
            "lifecycle one" => route.lifecycle.store(1, Ordering::Release),
            "lifecycle two" => route.lifecycle.store(2, Ordering::Release),
            "session cancelled" => route.disconnect.cancel(),
            "owner cancelled" => owner.cancel(),
            _ => unreachable!(),
        }
        sessions.insert(KEY.to_owned(), route.clone());
        assert!(
            !activate_session_if_current_in(
                &sessions, key, connection, user, generation, &lifecycle, &owner,
            ),
            "{case}"
        );
        assert!(!route.routable.load(Ordering::Acquire), "{case}");
        assert_eq!(sessions.get(KEY).unwrap().user_agent_epoch, None);
        assert!(session_entries_for_in(&sessions, KEY).is_empty());
        assert_eq!(sessions.len(), 1);
    }
}

#[test]
fn stale_route_capture_cannot_publish_or_activate_a_replacement() {
    let sessions = DashMap::new();
    let (old, _old_receiver) = session(uuid::Uuid::from_u128(1), uuid::Uuid::from_u128(2), false);
    let (mut replacement, mut receiver) = session(uuid::Uuid::from_u128(3), old.user_id, false);
    replacement.user_agent_epoch = Some(17);
    sessions.insert(KEY.to_owned(), old.clone());
    sessions.insert(KEY.to_owned(), replacement.clone());
    assert!(!publish_user_agent_epoch_if_current_in(
        &sessions,
        KEY,
        old.connection_id,
        old.user_id,
        old.auth_generation,
        &old.lifecycle,
        Some(43),
    ));
    assert!(!activate_session_if_current_in(
        &sessions,
        KEY,
        old.connection_id,
        old.user_id,
        old.auth_generation,
        &old.lifecycle,
        &old.disconnect,
    ));
    let current = sessions.get(KEY).unwrap().value().clone();
    assert_eq!(current.connection_id, replacement.connection_id);
    assert_eq!(current.user_agent_epoch, Some(17));
    assert!(Arc::ptr_eq(&current.lifecycle, &replacement.lifecycle));
    assert!(!current.routable.load(Ordering::Acquire));
    current.sender.try_send("<presence/>".to_owned()).unwrap();
    assert_eq!(receiver.try_recv().unwrap().stanza, "<presence/>");
}
