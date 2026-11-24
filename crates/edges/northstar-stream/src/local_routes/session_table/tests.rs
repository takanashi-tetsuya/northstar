use super::*;
use northstar_protocol_runtime::caps::{CapsKey, VerifiedCapsSummary};
use std::time::{Duration, Instant};
use uuid::Uuid;

const KEY: &str = "alice@example.test/fixture";

fn session(
    connection_id: uuid::Uuid,
    user_id: uuid::Uuid,
    routable: bool,
) -> (
    OnlineSession,
    tokio::sync::mpsc::Receiver<crate::outbound::OutboundItem>,
) {
    let (session, receiver) =
        super::super::session::test_online_session(user_id, 7, connection_id, "fixture", 1);
    session.routable.store(routable, Ordering::Relaxed);
    session
        .caps_observation_generation
        .store(11, Ordering::Relaxed);
    (session, receiver)
}

#[test]
fn pending_removal_rejects_foreign_identity_and_signals_exact_route() {
    let connection_id = Uuid::from_u128(1);
    let user_id = Uuid::from_u128(2);
    let sm_session_id = Uuid::from_u128(3);
    for cancel_live_route in [false, true] {
        for (label, key, connection, user, sm, exact) in [
            (
                "missing route",
                "alice@example.test/missing",
                connection_id,
                user_id,
                sm_session_id,
                false,
            ),
            (
                "wrong connection",
                KEY,
                Uuid::from_u128(4),
                user_id,
                sm_session_id,
                false,
            ),
            (
                "wrong user",
                KEY,
                connection_id,
                Uuid::from_u128(5),
                sm_session_id,
                false,
            ),
            (
                "wrong SM identity",
                KEY,
                connection_id,
                user_id,
                Uuid::from_u128(6),
                false,
            ),
            (
                "exact tuple",
                KEY,
                connection_id,
                user_id,
                sm_session_id,
                true,
            ),
        ] {
            let table = LocalSessionTable::new(Arc::new(DashMap::new()));
            let (route, _outbound) = session(connection_id, user_id, true);
            *route.sm_session_id.write().unwrap() = Some(sm_session_id);
            let disconnect = route.disconnect.clone();
            let incarnation = Arc::clone(&route.route_incarnation);
            table.insert(KEY.to_owned(), route);
            let (replacement, _replacement_outbound) = session(Uuid::from_u128(7), user_id, true);
            *replacement.sm_session_id.write().unwrap() = Some(sm_session_id);
            let replacement_disconnect = replacement.disconnect.clone();
            let replacement_removal = replacement.route_incarnation.subscribe();

            let removal =
                table.sm_pending_route_removal_signal(key, connection, user, sm, cancel_live_route);

            assert_eq!(removal.is_some(), exact, "{label}");
            assert_eq!(
                disconnect.is_cancelled(),
                exact && cancel_live_route,
                "{label}"
            );
            assert!(!replacement_disconnect.is_cancelled(), "{label}");
            if let Some(removal) = removal {
                assert!(!*removal.borrow(), "{label}");
                // Reusing the full JID must not move the old receiver to the new route.
                table.insert(KEY.to_owned(), replacement);
                incarnation.publish_removed();
                assert!(*removal.borrow(), "{label}");
                assert!(!*replacement_removal.borrow(), "{label}");
                assert!(!replacement_disconnect.is_cancelled(), "{label}");
            }
        }
    }
}

#[test]
fn privacy_list_active_locally_matches_any_resource() {
    let table = LocalSessionTable::new(Arc::new(DashMap::new()));
    let (inactive, _inactive_receiver) = session(Uuid::new_v4(), Uuid::new_v4(), true);
    let (active, _active_receiver) = session(Uuid::new_v4(), Uuid::new_v4(), true);
    *active.privacy_active.write().unwrap() = Some("friends".to_owned());
    table.insert(KEY.to_owned(), inactive);
    table.insert("alice@example.test/active".to_owned(), active);

    assert!(table.privacy_list_active_locally("alice@example.test", "friends"));
}

#[test]
fn privacy_list_active_locally_returns_false_without_a_match() {
    let table = LocalSessionTable::new(Arc::new(DashMap::new()));
    let (inactive, _inactive_receiver) = session(Uuid::new_v4(), Uuid::new_v4(), true);
    let (active, _active_receiver) = session(Uuid::new_v4(), Uuid::new_v4(), true);
    *active.privacy_active.write().unwrap() = Some("other".to_owned());
    table.insert(KEY.to_owned(), inactive);
    table.insert("alice@example.test/active".to_owned(), active);

    assert!(!table.privacy_list_active_locally("alice@example.test", "friends"));
    assert!(!table.privacy_list_active_locally("absent@example.test", "friends"));
}

#[test]
fn privacy_list_active_locally_ignores_other_accounts() {
    let table = LocalSessionTable::new(Arc::new(DashMap::new()));
    let (inactive, _inactive_receiver) = session(Uuid::new_v4(), Uuid::new_v4(), true);
    let (active, _active_receiver) = session(Uuid::new_v4(), Uuid::new_v4(), true);
    *active.privacy_active.write().unwrap() = Some("friends".to_owned());
    table.insert(KEY.to_owned(), inactive);
    table.insert("bob@example.test/active".to_owned(), active);

    assert!(!table.privacy_list_active_locally("alice@example.test", "friends"));
}

#[test]
fn privacy_list_active_locally_recovers_poisoned_lock() {
    let table = LocalSessionTable::new(Arc::new(DashMap::new()));
    let (active, _receiver) = session(Uuid::new_v4(), Uuid::new_v4(), true);
    let privacy_active = Arc::clone(&active.privacy_active);
    assert!(std::thread::spawn(move || {
        let mut guard = privacy_active.write().unwrap();
        *guard = Some("friends".to_owned());
        panic!("poison privacy_active");
    })
    .join()
    .is_err());
    assert!(active.privacy_active.is_poisoned());
    table.insert(KEY.to_owned(), active);

    assert!(table.privacy_list_active_locally("alice@example.test", "friends"));
    assert!(!table.privacy_list_active_locally("alice@example.test", "other"));
}

#[test]
fn try_send_to_available_entries_skips_unavailable_sessions() {
    let sessions = DashMap::new();
    let mut receivers = Vec::new();
    for (key, routable, available) in [
        (KEY, true, true),
        ("alice@example.test/unavailable", true, false),
        ("alice@example.test/pending", false, true),
        ("bob@example.test/fixture", true, true),
    ] {
        let (route, receiver) = session(Uuid::new_v4(), Uuid::new_v4(), routable);
        route.available.store(available, Ordering::Relaxed);
        sessions.insert(key.to_owned(), route);
        receivers.push((key, receiver));
    }
    let stanza = "<presence from='alice@example.test/gone' type='unavailable'/>";

    try_send_to_available_entries_in(&sessions, "alice@example.test", stanza);

    for (key, mut receiver) in receivers {
        if key == KEY {
            assert_eq!(
                receiver.try_recv().unwrap().stanza,
                northstar_xml_builder::rewrite::set_to(stanza, KEY)
            );
        }
        assert!(matches!(
            receiver.try_recv(),
            Err(tokio::sync::mpsc::error::TryRecvError::Empty)
        ));
    }
}

#[test]
fn try_send_to_entries_delivers_one_copy_to_each_matching_session() {
    for jid in ["alice@example.test", KEY] {
        let sessions = DashMap::new();
        let mut receivers = Vec::new();
        for (key, user_id, routable) in [
            (KEY, Uuid::from_u128(1), true),
            ("alice@example.test/other", Uuid::from_u128(1), true),
            ("alice@example.test/pending", Uuid::from_u128(1), false),
            ("bob@example.test/fixture", Uuid::from_u128(2), true),
        ] {
            let (route, receiver) = session(Uuid::new_v4(), user_id, routable);
            sessions.insert(key.to_owned(), route);
            receivers.push((key, receiver));
        }
        let expected = session_entries_for_in(&sessions, jid);
        assert_eq!(expected.len(), if jid == KEY { 1 } else { 2 });
        let stanza = "<presence/>";

        try_send_to_entries_in(&sessions, jid, stanza);

        for (key, mut receiver) in receivers {
            if expected.iter().any(|(full_jid, _)| full_jid == key) {
                assert_eq!(receiver.try_recv().unwrap().stanza, stanza);
            }
            assert!(matches!(
                receiver.try_recv(),
                Err(tokio::sync::mpsc::error::TryRecvError::Empty)
            ));
        }
    }
}

fn caps_key(version: &str) -> CapsKey {
    CapsKey {
        algorithm: "sha-1".to_owned(),
        node: "https://example.test/caps".to_owned(),
        version: version.to_owned(),
    }
}

fn supplied_summary(core: bool, pam: bool) -> Arc<VerifiedCapsSummary> {
    // Supplied verified environment; these tests do not run disco/hash verification.
    Arc::new(VerifiedCapsSummary::new(
        core,
        pam,
        String::new(),
        Vec::new(),
    ))
}

#[test]
fn local_caps_classification_uses_the_current_canonical_route_and_summary() {
    for (features, expected) in [
        (Some((true, false)), MixSessionCapability::Supported),
        (Some((false, true)), MixSessionCapability::Supported),
        (Some((false, false)), MixSessionCapability::Unsupported),
        (None, MixSessionCapability::Unknown),
    ] {
        let sessions = DashMap::new();
        let (route, _receiver) = session(Uuid::from_u128(1), Uuid::from_u128(2), true);
        let epoch = LocalCapsEpoch {
            connection_id: route.connection_id,
            generation: route.caps_observation_generation.load(Ordering::Acquire),
        };
        sessions.insert(KEY.to_owned(), route);
        let caps = CapsResourceIndex::new();
        let pending = PendingCapsIndex::new();
        let now = Instant::now();
        caps.observe_local(
            KEY.to_owned(),
            epoch,
            Some(caps_key("current")),
            features.map(|(core, pam)| supplied_summary(core, pam)),
            now,
        );
        assert!(pending.insert(
            "current".to_owned(),
            KEY.to_owned(),
            caps_key("current"),
            CapsObservationOwner::Local(epoch),
            now + Duration::from_secs(30),
        ));
        assert_eq!(
            session_mix_capability_in(&sessions, &caps, &pending, "ALICE@EXAMPLE.TEST/fixture"),
            expected
        );
        assert_eq!(caps.owner(KEY), Some(CapsObservationOwner::Local(epoch)));
        assert_eq!(caps.len(), 1);
        assert_eq!(pending.len(), 1);
        assert_eq!(
            pending.entries.get("current").unwrap().owner,
            CapsObservationOwner::Local(epoch)
        );
    }
}

#[test]
fn invalid_or_unobserved_caps_target_keeps_existing_indexes() {
    let sessions = DashMap::new();
    let (route, _receiver) = session(Uuid::from_u128(1), Uuid::from_u128(2), true);
    let epoch = LocalCapsEpoch {
        connection_id: route.connection_id,
        generation: route.caps_observation_generation.load(Ordering::Acquire),
    };
    sessions.insert(KEY.to_owned(), route);
    let caps = CapsResourceIndex::new();
    let pending = PendingCapsIndex::new();
    let now = Instant::now();
    caps.observe_local(
        KEY.to_owned(),
        epoch,
        Some(caps_key("current")),
        Some(supplied_summary(true, false)),
        now,
    );
    assert!(pending.insert(
        "current".to_owned(),
        KEY.to_owned(),
        caps_key("current"),
        CapsObservationOwner::Local(epoch),
        now + Duration::from_secs(30),
    ));
    for target in ["", "alice@example.test", "alice@example.test/missing"] {
        assert_eq!(
            session_mix_capability_in(&sessions, &caps, &pending, target),
            MixSessionCapability::Unknown,
            "{target}"
        );
        assert_eq!(caps.owner(KEY), Some(CapsObservationOwner::Local(epoch)));
        assert_eq!(caps.len(), 1);
        assert_eq!(pending.len(), 1);
    }
}

#[test]
fn stale_local_caps_evict_only_the_queried_epoch_and_preserve_other_observations() {
    for case in [
        "missing session",
        "connection",
        "generation",
        "unroutable",
        "session cancelled",
        "lifecycle one",
        "lifecycle two",
    ] {
        let sessions = DashMap::new();
        let (mut route, _receiver) = session(Uuid::from_u128(1), Uuid::from_u128(2), true);
        let epoch = LocalCapsEpoch {
            connection_id: route.connection_id,
            generation: route.caps_observation_generation.load(Ordering::Acquire),
        };
        match case {
            "missing session" => {}
            "connection" => {
                route.connection_id = Uuid::from_u128(3);
                route.route_incarnation =
                    northstar_session_application::RouteIncarnationSignal::new(route.connection_id);
            }
            "generation" => route
                .caps_observation_generation
                .store(12, Ordering::Release),
            "unroutable" => route.routable.store(false, Ordering::Release),
            "session cancelled" => route.disconnect.cancel(),
            "lifecycle one" => route.lifecycle.store(1, Ordering::Release),
            "lifecycle two" => route.lifecycle.store(2, Ordering::Release),
            _ => unreachable!(),
        }
        if case != "missing session" {
            sessions.insert(KEY.to_owned(), route);
        }
        let caps = CapsResourceIndex::new();
        let pending = PendingCapsIndex::new();
        let now = Instant::now();
        let summary = supplied_summary(true, false);
        for key in [KEY, "alice@example.test/other"] {
            caps.observe_local(
                key.to_owned(),
                epoch,
                Some(caps_key("old")),
                Some(Arc::clone(&summary)),
                now,
            );
        }
        let newer_epoch = LocalCapsEpoch {
            connection_id: epoch.connection_id,
            generation: epoch.generation + 1,
        };
        for (id, owner) in [("old", epoch), ("newer", newer_epoch)] {
            assert!(pending.insert(
                id.to_owned(),
                KEY.to_owned(),
                caps_key(id),
                CapsObservationOwner::Local(owner),
                now + Duration::from_secs(30),
            ));
        }
        assert_eq!(caps.len(), 2);
        assert_eq!(pending.len(), 2);
        assert_eq!(
            session_mix_capability_in(&sessions, &caps, &pending, "ALICE@EXAMPLE.TEST/fixture"),
            MixSessionCapability::Unknown,
            "{case}"
        );
        assert!(caps.owner(KEY).is_none(), "{case}");
        assert!(pending.entries.get("old").is_none(), "{case}");
        assert_eq!(
            pending.entries.get("newer").unwrap().owner,
            CapsObservationOwner::Local(newer_epoch),
            "{case}"
        );
        // The other target is also stale, but was never queried.
        assert_eq!(
            caps.owner("alice@example.test/other"),
            Some(CapsObservationOwner::Local(epoch)),
            "{case}"
        );
        assert_eq!(caps.len(), 1);
        assert_eq!(pending.len(), 1);
        assert_eq!(
            caps.admission.lock().unwrap().summary_bytes,
            summary.resident_charge()
        );
    }
}

#[test]
fn federated_caps_classification_does_not_apply_local_route_fences() {
    for (features, expected) in [
        (Some((false, true)), MixSessionCapability::Supported),
        (Some((false, false)), MixSessionCapability::Unsupported),
        (None, MixSessionCapability::Unknown),
    ] {
        let sessions = DashMap::new();
        let (route, _receiver) = session(Uuid::from_u128(1), Uuid::from_u128(2), false);
        route.disconnect.cancel();
        route.lifecycle.store(2, Ordering::Release);
        sessions.insert(KEY.to_owned(), route);
        let caps = CapsResourceIndex::new();
        let pending = PendingCapsIndex::new();
        let now = Instant::now();
        let owner = caps
            .observe_federated(
                KEY.to_owned(),
                Uuid::from_u128(3),
                "example.test".to_owned(),
                Some(caps_key("federated")),
                features.map(|(core, pam)| supplied_summary(core, pam)),
                now,
            )
            .unwrap();
        assert!(pending.insert(
            "federated".to_owned(),
            KEY.to_owned(),
            caps_key("federated"),
            owner,
            now + Duration::from_secs(30),
        ));
        assert_eq!(
            session_mix_capability_in(&sessions, &caps, &pending, KEY),
            expected
        );
        assert_eq!(caps.owner(KEY), Some(owner));
        assert_eq!(pending.entries.get("federated").unwrap().owner, owner);
        assert_eq!(caps.len(), 1);
        assert_eq!(pending.len(), 1);
    }
}

#[test]
fn epoch_publication_and_activation_fence_every_captured_route_argument() {
    for label in [
        "current",
        "missing key",
        "connection",
        "user",
        "generation",
        "lifecycle pointer",
        "finalizing",
        "superseded",
        "session cancelled",
        "owner cancelled",
        "replacement",
    ] {
        let sessions = Arc::new(DashMap::new());
        let table = LocalSessionTable::new(Arc::clone(&sessions));
        let (mut route, _receiver) = session(Uuid::from_u128(1), Uuid::from_u128(2), false);
        route.user_agent_epoch = Some(13);
        let mut key = KEY;
        let mut connection = route.connection_id;
        let mut user = route.user_id;
        let mut generation = route.auth_generation;
        let mut lifecycle = Arc::clone(&route.lifecycle);
        let owner_disconnect = CancellationToken::new();
        match label {
            "missing key" => key = "alice@example.test/missing",
            "connection" => connection = Uuid::from_u128(3),
            "user" => user = Uuid::from_u128(4),
            "generation" => generation += 1,
            "lifecycle pointer" => lifecycle = Arc::new(AtomicU8::new(0)),
            "finalizing" => route.lifecycle.store(1, Ordering::Release),
            "superseded" => route.lifecycle.store(2, Ordering::Release),
            "session cancelled" => route.disconnect.cancel(),
            "owner cancelled" => owner_disconnect.cancel(),
            "current" | "replacement" => {}
            _ => unreachable!(),
        }
        sessions.insert(KEY.to_owned(), route);
        if label == "replacement" {
            let (mut replacement, _replacement_receiver) = session(Uuid::from_u128(5), user, false);
            replacement.user_agent_epoch = Some(13);
            sessions.insert(KEY.to_owned(), replacement);
        }
        let epoch_allowed = matches!(label, "current" | "owner cancelled");
        // The epoch helper has no owner-cancellation argument. Both its direct
        // entry point and the table facade must assign the supplied Option.
        for epoch in [Some(43), None] {
            assert_eq!(
                publish_user_agent_epoch_if_current_in(
                    &sessions, key, connection, user, generation, &lifecycle, epoch
                ),
                epoch_allowed,
                "{label}: direct epoch publication"
            );
            assert_eq!(
                table.publish_user_agent_epoch_if_current(
                    key, connection, user, generation, &lifecycle, epoch
                ),
                epoch_allowed,
                "{label}: table epoch publication"
            );
            let stored = sessions.get(KEY).unwrap();
            assert_eq!(
                stored.user_agent_epoch,
                if epoch_allowed { epoch } else { Some(13) },
                "{label}"
            );
            assert!(
                !stored.routable.load(Ordering::Acquire),
                "{label}: epoch publication activated route"
            );
        }
        let activation_allowed = label == "current";
        assert_eq!(
            activate_session_if_current_in(
                &sessions,
                key,
                connection,
                user,
                generation,
                &lifecycle,
                &owner_disconnect
            ),
            activation_allowed,
            "{label}: direct activation"
        );
        assert_eq!(
            table.activate_session_if_current(
                key,
                connection,
                user,
                generation,
                &lifecycle,
                &owner_disconnect
            ),
            activation_allowed,
            "{label}: table activation"
        );
        assert_eq!(
            sessions.get(KEY).unwrap().routable.load(Ordering::Acquire),
            activation_allowed,
            "{label}"
        );
        assert_eq!(sessions.len(), 1, "{label}");
        // Both calls must have released their map guards.
        assert!(sessions.remove(KEY).is_some(), "{label}");
    }
}
