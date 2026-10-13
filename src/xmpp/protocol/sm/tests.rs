use super::{
    acknowledgement_delta, claim_sm_route_lifecycle, lock_mix_presence_gate_for_claim,
    matching_sm_route, muc_resume_failure_stanza, resumability_allowed,
    resumed_offline_replay_eligible, sm_resume_token_hash, stage_muc_replay_suffix,
    validated_sm_session_key, wait_for_exact_route_removal, ClaimBoundWaitAbort, RouteRemovalWait,
    SmRouteTakeover,
};
use roxmltree::Document;

#[tokio::test]
async fn ready_mix_gate_cannot_outlive_the_database_claim() {
    let gate = std::sync::Arc::new(tokio::sync::Mutex::new(()));
    let disconnect = tokio_util::sync::CancellationToken::new();
    let expired = tokio::time::Instant::now()
        .checked_sub(std::time::Duration::from_millis(1))
        .expect("a one millisecond earlier instant is representable");

    assert!(
        matches!(
            lock_mix_presence_gate_for_claim(gate, &disconnect, expired).await,
            Err(ClaimBoundWaitAbort::ClaimLeaseExpired)
        ),
        "an immediately ready mutex must not outrank an already-expired database lease"
    );
}

#[tokio::test]
async fn route_removal_wait_rechecks_the_map_and_cannot_miss_an_aba_replacement() {
    let key = "alice@example.test/Phone".to_owned();
    let old_connection = uuid::Uuid::new_v4();
    let replacement_connection = uuid::Uuid::new_v4();
    let routes = std::sync::Arc::new(dashmap::DashMap::new());
    routes.insert(key.clone(), old_connection);
    let (removed, receiver) = tokio::sync::watch::channel(false);
    let disconnect = tokio_util::sync::CancellationToken::new();

    let writer_routes = std::sync::Arc::clone(&routes);
    let writer_key = key.clone();
    let writer = tokio::spawn(async move {
        tokio::task::yield_now().await;
        assert!(writer_routes
            .remove_if(&writer_key, |_, connection| *connection == old_connection)
            .is_some());
        // Deliberately install the ABA replacement before publishing the
        // old incarnation's terminal event.
        writer_routes.insert(writer_key, replacement_connection);
        removed.send_replace(true);
    });

    assert_eq!(
        wait_for_exact_route_removal(
            receiver,
            &disconnect,
            tokio::time::Instant::now() + std::time::Duration::from_secs(1),
        )
        .await,
        RouteRemovalWait::Removed
    );
    writer.await.expect("writer completes");
    assert_eq!(
        routes.get(&key).map(|route| *route),
        Some(replacement_connection),
        "the old event is only permission to re-read; it is not proof of vacancy"
    );
}

#[tokio::test]
async fn route_removal_wait_observes_a_notification_published_before_subscribe() {
    let (removed, receiver) = tokio::sync::watch::channel(false);
    removed.send_replace(true);
    let disconnect = tokio_util::sync::CancellationToken::new();
    assert_eq!(
        wait_for_exact_route_removal(
            receiver,
            &disconnect,
            tokio::time::Instant::now() + std::time::Duration::from_secs(1),
        )
        .await,
        RouteRemovalWait::Removed
    );
}

#[tokio::test]
async fn route_removal_wait_is_bounded_only_by_cancellation_or_the_claim_lease() {
    let (_removed, receiver) = tokio::sync::watch::channel(false);
    let disconnect = tokio_util::sync::CancellationToken::new();
    disconnect.cancel();
    assert_eq!(
        wait_for_exact_route_removal(
            receiver,
            &disconnect,
            tokio::time::Instant::now() + std::time::Duration::from_secs(1),
        )
        .await,
        RouteRemovalWait::ConnectionCancelled
    );

    let (_removed, receiver) = tokio::sync::watch::channel(false);
    let disconnect = tokio_util::sync::CancellationToken::new();
    assert_eq!(
        wait_for_exact_route_removal(receiver, &disconnect, tokio::time::Instant::now()).await,
        RouteRemovalWait::ClaimLeaseExpired
    );
}

#[test]
fn resumed_muc_replay_suffix_is_tracked_after_the_unacked_prefix() {
    let unacked = std::collections::VecDeque::from([
        crate::outbound::SmUnackedStanza::plain("<queued-1/>".to_owned()),
        crate::outbound::SmUnackedStanza::plain("<queued-2/>".to_owned()),
    ]);
    let (unacked, outbound_h) = stage_muc_replay_suffix(
        &unacked,
        9_u32,
        vec!["<muc-newer/>".to_owned(), "<muc-newest/>".to_owned()],
        8,
        4_096,
    )
    .expect("the combined FIFO fits");
    let replay: Vec<&str> = unacked.iter().map(|entry| entry.stanza.as_str()).collect();
    assert_eq!(
        replay,
        [
            "<queued-1/>",
            "<queued-2/>",
            "<muc-newer/>",
            "<muc-newest/>"
        ]
    );
    assert_eq!(outbound_h, 11);
    assert!(
        unacked
            .iter()
            .all(|entry| entry.durable_delivery().is_none()),
        "volatile MUC traffic carries no durable delivery fence"
    );
}

#[test]
fn resumed_muc_suffix_cannot_open_a_second_sm_budget() {
    let unacked = std::collections::VecDeque::from([
        crate::outbound::SmUnackedStanza::plain("1234".to_owned()),
        crate::outbound::SmUnackedStanza::plain("5678".to_owned()),
    ]);
    assert!(stage_muc_replay_suffix(&unacked, 2, vec!["x".to_owned()], 2, 9,).is_none());
    assert!(stage_muc_replay_suffix(&unacked, 2, vec!["xx".to_owned()], 3, 9,).is_none());
}

#[test]
fn resume_failure_presence_332_consumes_the_same_global_budget() {
    let membership = crate::services::sm::SmMucMembership {
        room_jid: "room@conference.example.test".to_owned(),
        nick: "alice".to_owned(),
    };
    let failure = muc_resume_failure_stanza("alice@example.test/Phone", &membership);
    let document = Document::parse(&failure).expect("failure presence is valid XML");
    assert!(document.root_element().descendants().any(|node| {
        node.is_element()
            && node.tag_name().name() == "status"
            && node.attribute("code") == Some("332")
    }));
    let unacked = std::collections::VecDeque::from([crate::outbound::SmUnackedStanza::plain(
        "old".to_owned(),
    )]);
    let exact_bytes = "old".len() + failure.len();
    let (staged, _) = stage_muc_replay_suffix(&unacked, 1, vec![failure.clone()], 2, exact_bytes)
        .expect("the final allowed 332 presence fits the shared budget");
    assert_eq!(staged.len(), 2);
    assert!(stage_muc_replay_suffix(&unacked, 1, vec![failure.clone()], 1, exact_bytes).is_none());
    assert!(stage_muc_replay_suffix(&unacked, 1, vec![failure], 2, exact_bytes - 1).is_none());
}

#[test]
fn acknowledgements_handle_wrap_and_reject_ahead_or_stale_values() {
    assert_eq!(acknowledgement_delta(u32::MAX - 1, 1, 3), Some(3));
    assert_eq!(acknowledgement_delta(10, 12, 2), Some(2));
    assert_eq!(acknowledgement_delta(10, 13, 2), None);
    assert_eq!(acknowledgement_delta(10, 9, 512), None);
}

#[test]
fn duplicate_ack_is_idempotent() {
    assert_eq!(acknowledgement_delta(42, 42, 0), Some(0));
    assert_eq!(acknowledgement_delta(42, 42, 8), Some(0));
}

#[test]
fn sm_resume_only_replays_offline_to_an_eligible_resource() {
    assert!(resumed_offline_replay_eligible(true, 0));
    assert!(resumed_offline_replay_eligible(true, i16::MAX));
    assert!(!resumed_offline_replay_eligible(false, 0));
    assert!(!resumed_offline_replay_eligible(true, -1));
}

#[test]
fn strict_same_device_policy_does_not_issue_unclaimable_legacy_bearers() {
    assert!(resumability_allowed(true, true, true));
    assert!(resumability_allowed(true, false, false));
    assert!(!resumability_allowed(true, true, false));
    assert!(!resumability_allowed(false, false, true));
}

#[test]
fn impossible_ack_uses_the_required_terminal_stream_error() {
    let xml = northstar_xep_0198::build_handled_count_too_high_stream_error(10, 8);
    let document = Document::parse(&xml).unwrap();
    let root = document.root_element();
    assert_eq!(
        root.tag_name().namespace(),
        Some("http://etherx.jabber.org/streams")
    );
    let detail = root
        .children()
        .find(|child| {
            child.is_element()
                && child.tag_name().namespace() == Some("urn:xmpp:sm:3")
                && child.tag_name().name() == "handled-count-too-high"
        })
        .unwrap();
    assert_eq!(detail.attribute("h"), Some("10"));
    assert_eq!(detail.attribute("send-count"), Some("8"));
}

#[test]
fn resume_identity_canonicalizes_account_but_matches_resource_exactly() {
    assert_eq!(
        validated_sm_session_key("ALICE@Example.test/Phone", "Phone", "alice@example.test"),
        Some("alice@example.test/Phone".to_owned())
    );
    assert_eq!(
        validated_sm_session_key("alice@example.test/Phone", "phone", "alice@example.test"),
        None
    );
    assert_eq!(
        validated_sm_session_key("mallory@example.test/Phone", "Phone", "alice@example.test"),
        None
    );
}

#[test]
fn immediate_takeover_is_exact_and_old_drop_cannot_win_afterward() {
    let user = uuid::Uuid::new_v4();
    let other = uuid::Uuid::new_v4();
    let stream = uuid::Uuid::new_v4();
    assert!(matching_sm_route(user, Some(stream), user, stream));
    assert!(!matching_sm_route(other, Some(stream), user, stream));
    assert!(!matching_sm_route(
        user,
        Some(uuid::Uuid::new_v4()),
        user,
        stream
    ));

    let lifecycle = std::sync::atomic::AtomicU8::new(0);
    assert_eq!(
        claim_sm_route_lifecycle(&lifecycle),
        SmRouteTakeover::Acquired
    );
    assert_eq!(lifecycle.load(std::sync::atomic::Ordering::Acquire), 2);
    assert!(lifecycle
        .compare_exchange(
            0,
            1,
            std::sync::atomic::Ordering::AcqRel,
            std::sync::atomic::Ordering::Acquire
        )
        .is_err());

    let dropping = std::sync::atomic::AtomicU8::new(1);
    assert_eq!(
        claim_sm_route_lifecycle(&dropping),
        SmRouteTakeover::Dropping
    );
}

#[test]
fn emitted_resume_bearer_is_the_exact_persisted_and_claimed_hash_input() {
    use base64::Engine;
    use sha2::{Digest, Sha256};

    let raw = [0xA7_u8; 32];
    let emitted = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw);
    let persisted = sm_resume_token_hash(&emitted);
    let claim_input: [u8; 32] = Sha256::digest(emitted.as_bytes()).into();
    let unreachable_raw_hash: [u8; 32] = Sha256::digest(raw).into();
    assert_eq!(persisted, claim_input);
    assert_ne!(persisted, unreachable_raw_hash);
}
