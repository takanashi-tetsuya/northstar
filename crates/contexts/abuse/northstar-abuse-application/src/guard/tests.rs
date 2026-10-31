use super::*;

fn guard() -> AbuseGuard {
    AbuseGuard::new(AbuseConfig {
        base_work_factor: 100,
        max_work_factor: 10_000,
        window: Duration::from_secs(60),
        cooldown_step: Duration::from_secs(60),
        max_wait: Duration::from_secs(900),
        message_free_burst: 6,
        approximate_max_device_seconds: 8,
    })
}

#[tokio::test]
async fn shared_nat_state_waits_before_a_database_connection_is_acquired() {
    let guard = guard();
    let first = vec![
        "ip:203.0.113.9".to_owned(),
        "user:first".to_owned(),
        "behavior:first".to_owned(),
    ];
    let second = vec![
        "ip:203.0.113.9".to_owned(),
        "user:second".to_owned(),
        "behavior:second".to_owned(),
    ];
    let held = guard
        .acquire_db_state_gates(AbuseAction::Message, &first)
        .await;
    assert!(
        tokio::time::timeout(
            Duration::from_millis(20),
            guard.acquire_db_state_gates(AbuseAction::Message, &second),
        )
        .await
        .is_err(),
        "a second user behind the same NAT must queue outside PgPool"
    );
    drop(held);
    let released = tokio::time::timeout(
        Duration::from_secs(1),
        guard.acquire_db_state_gates(AbuseAction::Message, &second),
    )
    .await;
    assert!(released.is_ok());
}

#[test]
fn actor_state_contention_is_a_distinct_retryable_condition() {
    let error = anyhow::Error::new(AbuseStateBusy);
    assert!(is_abuse_state_busy(&error));
    assert!(!is_abuse_state_busy(&anyhow::anyhow!("database offline")));
}

fn solve(challenge: &PowChallenge) -> PowProof {
    let target = u64::MAX / challenge.requirement.work_factor.max(1);
    for nonce in 0_u64.. {
        let nonce = nonce.to_string();
        let mut hasher = Sha256::new();
        hasher.update(challenge.prefix.as_bytes());
        hasher.update(nonce.as_bytes());
        let digest = hasher.finalize();
        let value = u64::from_be_bytes(digest[..8].try_into().unwrap());
        if value <= target {
            return PowProof {
                challenge_id: challenge.challenge_id,
                nonce,
            };
        }
    }
    unreachable!()
}

#[test]
fn canonical_json_digest_is_order_independent_and_value_sensitive() {
    let first = serde_json::json!({"z":[3, {"b":true,"a":"value"}],"a":null});
    let reordered = serde_json::json!({"a":null,"z":[3, {"a":"value","b":true}]});
    let changed = serde_json::json!({"a":null,"z":[3, {"a":"changed","b":true}]});
    assert_eq!(
        canonical_json_body_digest(&first),
        canonical_json_body_digest(&reordered)
    );
    assert_ne!(
        canonical_json_body_digest(&first),
        canonical_json_body_digest(&changed)
    );
    let browser_vector = serde_json::json!({
        "username":"alice",
        "password":"秘密pass123",
        "invitation_token":null
    });
    assert_eq!(
        URL_SAFE_NO_PAD.encode(canonical_json_body_digest(&browser_vector)),
        "YQTJXLqYiX5ozfSad42LkiW0yxb40r7JzrfODA-h1YY"
    );
    let non_bmp_key_vector = serde_json::json!({"😀":2,"":1});
    assert_eq!(
        URL_SAFE_NO_PAD.encode(canonical_json_body_digest(&non_bmp_key_vector)),
        "hxlUUxhZx1csYnn5Drg6WU3cOiiei9wo0qhP-4waFwM",
        "browser and Rust sort object keys by Unicode scalar value, not UTF-16 code unit"
    );
}

#[test]
fn xmpp_registration_intent_is_transport_independent_and_field_bound() {
    let first =
        PowIntent::xmpp_registration("alice", "correct horse battery staple", Some("invite-1"));
    let same =
        PowIntent::xmpp_registration("alice", "correct horse battery staple", Some("invite-1"));
    assert_eq!(first, same);
    assert_ne!(
        first,
        PowIntent::xmpp_registration("alice", "correct horse battery staple!", Some("invite-1"),)
    );
    assert_ne!(
        first,
        PowIntent::xmpp_registration("alice", "correct horse battery staple", Some("invite-2"),)
    );
    assert_ne!(
        PowIntent::xmpp_registration("ab", "cdefghijkl", None),
        PowIntent::xmpp_registration("a", "bcdefghijkl", None),
        "length prefixes must make adjacent-field splits unambiguous"
    );
    assert_ne!(
        PowIntent::xmpp_registration("alice", "correct horse battery staple", None),
        PowIntent::xmpp_registration("alice", "correct horse battery staple", Some("")),
        "missing and present-empty optional fields are distinct"
    );
}

#[tokio::test]
async fn v2_challenge_is_bound_to_method_path_body_and_subject() {
    let actors = vec!["user:pow-v2".to_owned()];
    let expected = PowIntent::http_json(
        AbuseAction::Report,
        "/api/v1/reports",
        &serde_json::json!({"body":"one"}),
    );

    for changed in [
        PowIntent::unvalidated("XMPP", expected.path(), *expected.body_sha256()),
        PowIntent::unvalidated(
            expected.method(),
            "/api/v1/reports/other",
            *expected.body_sha256(),
        ),
        PowIntent::http_json(
            AbuseAction::Report,
            "/api/v1/reports",
            &serde_json::json!({"body":"two"}),
        ),
    ] {
        let guard = guard();
        let challenge = guard
            .issue_v2(AbuseAction::Report, "report:pow-v2", &actors, &expected)
            .await
            .unwrap();
        let proof = solve(&challenge);
        assert!(guard
            .verify_or_allow_v2(
                AbuseAction::Report,
                "report:pow-v2",
                &actors,
                Some(&proof),
                &changed,
            )
            .await
            .unwrap()
            .is_err());
    }

    let subject_mismatch_guard = guard();
    let challenge = subject_mismatch_guard
        .issue_v2(AbuseAction::Report, "report:pow-v2", &actors, &expected)
        .await
        .unwrap();
    let proof = solve(&challenge);
    assert!(subject_mismatch_guard
        .verify_or_allow_v2(
            AbuseAction::Report,
            "report:another-subject",
            &actors,
            Some(&proof),
            &expected,
        )
        .await
        .unwrap()
        .is_err());

    let actor_mismatch_guard = guard();
    let challenge = actor_mismatch_guard
        .issue_v2(AbuseAction::Report, "report:pow-v2", &actors, &expected)
        .await
        .unwrap();
    let proof = solve(&challenge);
    assert!(actor_mismatch_guard
        .verify_or_allow_v2(
            AbuseAction::Report,
            "report:pow-v2",
            &["user:another-actor".to_owned()],
            Some(&proof),
            &expected,
        )
        .await
        .unwrap()
        .is_err());

    let valid_guard = guard();
    let challenge = valid_guard
        .issue_v2(AbuseAction::Report, "report:pow-v2", &actors, &expected)
        .await
        .unwrap();
    assert_eq!(challenge.version, POW_INTENT_VERSION);
    assert!(challenge.intent.is_some());
    let proof = solve(&challenge);
    assert!(valid_guard
        .verify_or_allow_v2(
            AbuseAction::Report,
            "report:pow-v2",
            &actors,
            Some(&proof),
            &expected,
        )
        .await
        .unwrap()
        .is_ok());
}

#[tokio::test]
async fn parallel_message_challenges_remain_one_use_and_cannot_cross_a_work_step() {
    let guard = guard();
    let actors = vec!["user:parallel-message-pow".to_owned()];
    let subject = "message:parallel-message-pow";
    let intents = (0..7)
        .map(|index| {
            PowIntent::xmpp(
                AbuseAction::Message,
                "/xmpp/message",
                format!("<message id='{index}'><body>{index}</body></message>").as_bytes(),
            )
        })
        .collect::<Vec<_>>();
    let mut challenges = Vec::new();
    for intent in &intents {
        challenges.push(
            guard
                .issue_v2(AbuseAction::Message, subject, &actors, intent)
                .await
                .unwrap(),
        );
    }
    assert_eq!(guard.challenges.len(), 7);

    for (challenge, intent) in challenges.iter().zip(&intents).take(6) {
        assert!(guard
            .verify_or_allow_v2(
                AbuseAction::Message,
                subject,
                &actors,
                Some(&solve(challenge)),
                intent,
            )
            .await
            .unwrap()
            .is_ok());
    }

    // The seventh proof was issued at the free step. Six accepted sends
    // have now raised the live requirement, so it must fail closed rather
    // than spend a stale cheap proof across that boundary.
    assert!(guard
        .verify_or_allow_v2(
            AbuseAction::Message,
            subject,
            &actors,
            Some(&solve(&challenges[6])),
            &intents[6],
        )
        .await
        .unwrap()
        .is_err());

    let replay = guard
        .verify_or_allow_v2(
            AbuseAction::Message,
            subject,
            &actors,
            Some(&solve(&challenges[0])),
            &intents[0],
        )
        .await
        .unwrap()
        .unwrap_err();
    assert!(replay.message().contains("already used"));
}

#[test]
fn v2_intent_request_rejects_noncanonical_routes_and_digests() {
    let digest = URL_SAFE_NO_PAD.encode([7_u8; 32]);
    assert!(PowIntent::from_request(
        AbuseAction::Report,
        &PowIntentRequest {
            version: 2,
            method: "POST".to_owned(),
            path: "/api/v1/reports".to_owned(),
            body_sha256: digest.clone(),
        },
    )
    .is_ok());
    for (version, method, path, body_sha256) in [
        (1, "POST", "/api/v1/reports", digest.as_str()),
        (2, "post", "/api/v1/reports", digest.as_str()),
        (2, "GET", "/api/v1/reports", digest.as_str()),
        (2, "POST", "/api/v1/reports?scope=other", digest.as_str()),
        (2, "POST", "/api/v1/../reports", digest.as_str()),
        (2, "POST", "/api/v1/reports", "not-base64"),
    ] {
        assert!(PowIntent::from_request(
            AbuseAction::Report,
            &PowIntentRequest {
                version,
                method: method.to_owned(),
                path: path.to_owned(),
                body_sha256: body_sha256.to_owned(),
            },
        )
        .is_err());
    }
}

#[tokio::test]
async fn closed_v1_window_rejects_issue_and_consumption_but_v2_remains_available() {
    let mut guard = guard();
    let actors = vec!["user:pow-v2-only".to_owned()];
    let legacy = guard
        .issue(AbuseAction::Report, "report:legacy", &actors)
        .await
        .unwrap();
    let legacy_proof = solve(&legacy);
    guard.legacy_v1_compatibility_until = None;
    assert!(guard
        .verify_or_allow(
            AbuseAction::Report,
            "report:legacy",
            &actors,
            Some(&legacy_proof),
        )
        .await
        .unwrap()
        .is_err());
    assert!(guard
        .issue(AbuseAction::Report, "report:v1", &actors)
        .await
        .unwrap_err()
        .downcast_ref::<LegacyPowV1Disabled>()
        .is_some());
    let intent = PowIntent::http_json(
        AbuseAction::Report,
        "/api/v1/reports",
        &serde_json::json!({"body":"v2"}),
    );
    assert!(guard
        .issue_v2(AbuseAction::Report, "report:v2", &actors, &intent)
        .await
        .is_ok());
}

#[test]
fn message_admission_hmac_is_domain_separated_and_sharded() {
    let secret = b"message-admission-property-secret-0001";
    let actor_id = Uuid::new_v4();
    let actors = vec![format!("user:{actor_id}")];
    let baseline = MessageAdmissionRequest {
        actor_id,
        account_bare: "alice@example.test",
        normalized_target: "bob@example.test",
        origin_id: Some("origin-1"),
        normalized_payload: "<message to='bob@example.test'><body>one</body></message>",
        pow_intent_payload: "<message to='bob@example.test'><body>one</body></message>",
        subject: "message:alice",
        actors: &actors,
        proof: None,
    };
    let (base_key, base_payload) =
        message_admission_material(&baseline, secret, b"origin-id", b"origin-1");
    let (same_key, same_payload) =
        message_admission_material(&baseline, secret, b"origin-id", b"origin-1");
    assert_eq!(base_key, same_key);
    assert_eq!(base_payload, same_payload);
    let stable_identity = message_admission_identity_digest(&baseline, b"origin-id", b"origin-1");
    assert_eq!(stable_identity.len(), 32);

    let changed_payload = MessageAdmissionRequest {
        normalized_payload: "<message to='bob@example.test'><body>two</body></message>",
        pow_intent_payload: "<message to='bob@example.test'><body>two</body></message>",
        ..baseline
    };
    let (payload_key, payload_mac) =
        message_admission_material(&changed_payload, secret, b"origin-id", b"origin-1");
    assert_eq!(
        base_key, payload_key,
        "content must not change the retry key"
    );
    assert_ne!(
        base_payload, payload_mac,
        "content must change the keyed payload digest"
    );
    assert_eq!(
        stable_identity,
        message_admission_identity_digest(&changed_payload, b"origin-id", b"origin-1"),
        "the offline lookup identity must be a stable SHA-256 value, independent of payload and HMAC rotation"
    );

    for (account, target, kind, identity) in [
        (
            "mallory@example.test",
            "bob@example.test",
            b"origin-id".as_slice(),
            b"origin-1".as_slice(),
        ),
        (
            "alice@example.test",
            "carol@example.test",
            b"origin-id".as_slice(),
            b"origin-1".as_slice(),
        ),
        (
            "alice@example.test",
            "bob@example.test",
            b"origin-id".as_slice(),
            b"origin-2".as_slice(),
        ),
        (
            "alice@example.test",
            "bob@example.test",
            b"challenge".as_slice(),
            b"origin-1".as_slice(),
        ),
    ] {
        let variant = MessageAdmissionRequest {
            account_bare: account,
            normalized_target: target,
            ..baseline
        };
        let (key, mac) = message_admission_material(&variant, secret, kind, identity);
        assert_ne!(base_key, key);
        assert_ne!(base_payload, mac);
        assert_ne!(
            stable_identity,
            message_admission_identity_digest(&variant, kind, identity)
        );
    }

    let mut shards = HashSet::new();
    for index in 0..10_000_u32 {
        let origin = format!("origin-{index}");
        let (key, _) =
            message_admission_material(&baseline, secret, b"origin-id", origin.as_bytes());
        let shard = message_admission_capacity_shard(&key);
        assert!((0..64).contains(&shard));
        shards.insert(shard);
    }
    assert_eq!(shards.len(), 64, "all capacity shards must be reachable");
}

#[test]
fn message_work_grows_quadratically_after_free_burst() {
    let guard = guard();
    let actors = vec!["user:1".to_owned()];
    for _ in 0..6 {
        let requirement = guard
            .verify_memory(AbuseAction::Message, "user:1", &actors, None)
            .unwrap();
        assert_eq!(requirement.work_factor, 1);
    }
    let requirement = guard.requirement(AbuseAction::Message, &actors, Instant::now());
    assert_eq!(requirement.step, 1);
    assert_eq!(requirement.work_factor, 100);
    let challenge = guard
        .issue_memory(AbuseAction::Message, "user:1", &actors)
        .unwrap();
    guard
        .verify_memory(
            AbuseAction::Message,
            "user:1",
            &actors,
            Some(&solve(&challenge)),
        )
        .unwrap();
    let requirement = guard.requirement(AbuseAction::Message, &actors, Instant::now());
    assert_eq!(requirement.step, 2);
    assert_eq!(requirement.work_factor, 400);

    let challenge = guard
        .issue_memory(AbuseAction::Message, "user:1", &actors)
        .unwrap();
    guard
        .verify_memory(
            AbuseAction::Message,
            "user:1",
            &actors,
            Some(&solve(&challenge)),
        )
        .unwrap();
    let requirement = guard.requirement(AbuseAction::Message, &actors, Instant::now());
    assert_eq!(requirement.step, 3);
    assert_eq!(requirement.work_factor, 900);
}

#[test]
fn message_escalation_has_bounded_quadratic_work_and_hard_wait_gates() {
    let config = &guard().config;
    let policy = Policy {
        free_burst: 0,
        base_work: config.base_work_factor,
    };
    for (events, expected_work, expected_wait) in [
        (0, 100, 0),
        (1, 400, 0),
        (3, 1_600, 2),
        (7, 6_400, 10),
        (11, 10_000, 30),
        (15, 10_000, 120),
        (10_000, 10_000, 120),
    ] {
        let requirement = build_requirement(AbuseAction::Message, policy, events, 0, 0, config);
        assert_eq!(requirement.work_factor, expected_work);
        assert_eq!(requirement.hard_wait_seconds, expected_wait);
        assert!(requirement.work_factor <= requirement.max_work_factor);
        assert_eq!(requirement.approximate_max_device_seconds, 8);
    }
}

#[test]
fn cooldown_notice_and_penalty_decay_follow_exponential_steps() {
    let config = AbuseConfig {
        window: Duration::from_secs(45),
        cooldown_step: Duration::from_secs(30),
        ..guard().config
    };
    let policy = Policy {
        free_burst: 0,
        base_work: config.base_work_factor,
    };
    let ordinary = build_requirement(AbuseAction::Message, policy, 0, 0, 0, &config);
    assert_eq!(ordinary.cooldown_seconds, 45);
    let penalized = build_requirement(AbuseAction::Message, policy, 0, 3, 0, &config);
    assert_eq!(penalized.cooldown_seconds, 240);
    assert_eq!(penalized.work_factor, 800);

    assert_eq!(
        decayed_penalty(3, Duration::from_secs(239), config.cooldown_step),
        (3, Duration::ZERO)
    );
    assert_eq!(
        decayed_penalty(3, Duration::from_secs(240), config.cooldown_step),
        (2, Duration::from_secs(240))
    );
    assert_eq!(
        decayed_penalty(3, Duration::from_secs(360), config.cooldown_step),
        (1, Duration::from_secs(360))
    );
}

#[test]
fn standards_only_client_is_throttled_then_recovers_after_window() {
    let guard = guard();
    let actors = vec!["user:standards-client".to_owned()];
    for _ in 0..6 {
        assert!(guard
            .verify_memory(AbuseAction::Message, "user:standards-client", &actors, None,)
            .is_ok());
    }
    let limited = guard
        .verify_memory(AbuseAction::Message, "user:standards-client", &actors, None)
        .unwrap_err();
    assert_eq!(limited.requirement().step, 1);
    assert_eq!(limited.requirement().work_factor, 100);

    let old = Instant::now() - Duration::from_secs(61);
    let key = state_key(AbuseAction::Message, &actors[0]);
    let mut state = guard.states.get_mut(&key).unwrap();
    state.events = VecDeque::from([old; 7]);
    state.penalty_level = 0;
    state.last_activity = old;
    state.blocked_until = old;
    drop(state);
    let recovered = guard.requirement(AbuseAction::Message, &actors, Instant::now());
    assert_eq!(recovered.step, 0);
    assert_eq!(recovered.work_factor, 1);
    assert_eq!(recovered.retry_after_seconds, 0);
}

#[test]
fn prefetched_pow_is_accepted_once_and_replay_is_rejected() {
    let guard = guard();
    let actors = vec!["user:pow-client".to_owned()];
    let challenge = guard
        .issue_memory(AbuseAction::Report, "report:pow-client", &actors)
        .unwrap();
    let proof = solve(&challenge);
    assert!(guard
        .verify_memory(
            AbuseAction::Report,
            "report:pow-client",
            &actors,
            Some(&proof),
        )
        .is_ok());
    let replay = guard
        .verify_memory(
            AbuseAction::Report,
            "report:pow-client",
            &actors,
            Some(&proof),
        )
        .unwrap_err();
    assert!(replay.message().contains("already used"));
}

#[test]
fn challenge_issuance_is_hard_bounded_in_memory() {
    let account_guard = guard();
    let account_actors = vec!["user:capacity-account".to_owned()];
    for index in 0..MAX_ACTIVE_POW_CHALLENGES_PER_ACTOR {
        account_guard
            .issue_memory(
                AbuseAction::Message,
                &format!("message:capacity-account:{index}"),
                &account_actors,
            )
            .unwrap();
    }
    let limited = account_guard
        .issue_memory(
            AbuseAction::Message,
            "message:capacity-account:overflow",
            &account_actors,
        )
        .unwrap_err();
    assert!(limited
        .downcast_ref::<ChallengeCapacityExceeded>()
        .is_some());

    // A second challenge for the same subject is a distinct active slot;
    // it must not bypass the per-actor cap. An expired row immediately
    // makes capacity available.
    let limited = account_guard
        .issue_memory(
            AbuseAction::Message,
            "message:capacity-account:0",
            &account_actors,
        )
        .unwrap_err();
    assert!(limited
        .downcast_ref::<ChallengeCapacityExceeded>()
        .is_some());
    let expired_id = *account_guard.challenges.iter().next().unwrap().key();
    account_guard
        .challenges
        .get_mut(&expired_id)
        .unwrap()
        .expires_at = Instant::now();
    account_guard
        .issue_memory(
            AbuseAction::Message,
            "message:capacity-account:after-expiry",
            &account_actors,
        )
        .unwrap();

    let ip_guard = guard();
    let ip_actors = vec!["ip:192.0.2.44".to_owned()];
    for index in 0..MAX_ACTIVE_POW_CHALLENGES_PER_IP {
        ip_guard
            .issue_memory(
                AbuseAction::Registration,
                &format!("registration:capacity-ip:{index}"),
                &ip_actors,
            )
            .unwrap();
    }
    let limited = ip_guard
        .issue_memory(
            AbuseAction::Registration,
            "registration:capacity-ip:overflow",
            &ip_actors,
        )
        .unwrap_err();
    assert!(limited
        .downcast_ref::<ChallengeCapacityExceeded>()
        .is_some());

    let issue_guard = guard();
    for _ in 0..MAX_CHALLENGE_ISSUES_PER_IP_WINDOW {
        let challenge = issue_guard
            .issue_memory(
                AbuseAction::Registration,
                "registration:replace",
                &ip_actors,
            )
            .unwrap();
        issue_guard.challenges.remove(&challenge.challenge_id);
    }
    let limited = issue_guard
        .issue_memory(
            AbuseAction::Registration,
            "registration:replace",
            &ip_actors,
        )
        .unwrap_err();
    assert!(limited
        .downcast_ref::<ChallengeCapacityExceeded>()
        .is_some());

    let global_guard = guard();
    let now = Instant::now();
    let requirement = global_guard.requirement(
        AbuseAction::Registration,
        &["ip:198.51.100.9".to_owned()],
        now,
    );
    for _ in 0..MAX_ACTIVE_POW_CHALLENGES_GLOBAL {
        global_guard.challenges.insert(
            Uuid::new_v4(),
            StoredChallenge {
                protocol_version: 1,
                action: AbuseAction::Registration,
                subject: "preloaded".to_owned(),
                intent: None,
                key_id: global_guard.actor_key_id.clone(),
                prefix: String::new(),
                work_factor: 1,
                issued_at: chrono::Utc::now(),
                expires_at_wall: chrono::Utc::now() + chrono::Duration::seconds(60),
                server_nonce: "test-only-server-nonce".to_owned(),
                not_before: now,
                expires_at: now + Duration::from_secs(60),
                actor_sequences: Vec::new(),
                capacity_actors: Vec::new(),
                requirement: requirement.clone(),
            },
        );
    }
    let limited = global_guard
        .issue_memory(
            AbuseAction::Registration,
            "registration:global-overflow",
            &["ip:198.51.100.9".to_owned()],
        )
        .unwrap_err();
    assert!(limited
        .downcast_ref::<ChallengeCapacityExceeded>()
        .is_some());
}

#[test]
fn capable_message_client_can_prefetch_through_the_normal_burst() {
    let guard = guard();
    let actors = vec!["user:prefetch".to_owned()];
    for _ in 0..guard.config.message_free_burst {
        let challenge = guard
            .issue_memory(AbuseAction::Message, "message:prefetch", &actors)
            .unwrap();
        guard
            .verify_memory(
                AbuseAction::Message,
                "message:prefetch",
                &actors,
                Some(&solve(&challenge)),
            )
            .unwrap();
    }
    let requirement = guard.requirement(AbuseAction::Message, &actors, Instant::now());
    assert_eq!(requirement.step, 1);
    assert_eq!(requirement.work_factor, 100);
    assert_eq!(requirement.retry_after_seconds, 0);
}

#[test]
fn shared_ip_is_a_high_threshold_signal_not_a_nat_wide_penalty() {
    let guard = guard();
    let ip = "ip:198.51.100.10".to_owned();
    let user_a = vec![ip.clone(), "user:a".to_owned(), "behavior:a".to_owned()];
    let user_b = vec![ip.clone(), "user:b".to_owned(), "behavior:b".to_owned()];
    let now = Instant::now();
    let free = WorkRequirement {
        action: "message".to_owned(),
        step: 0,
        work_factor: 1,
        max_work_factor: 10_000,
        hard_wait_seconds: 0,
        retry_after_seconds: 0,
        cooldown_seconds: 60,
        approximate_max_device_seconds: 8,
        notice: String::new(),
    };
    for _ in 0..60 {
        guard.record(AbuseAction::Message, &user_a, now, &free);
    }
    let b = guard.requirement(AbuseAction::Message, &user_b, now);
    assert_eq!(
        b.step, 0,
        "one active account must not exhaust its NAT peers"
    );

    // The shared IP still acts as a high-volume circuit breaker.  At 20x
    // the account burst it begins contributing a rate-limit step.
    for _ in 0..80 {
        guard.record(AbuseAction::Message, &user_a, now, &free);
    }
    let b = guard.requirement(AbuseAction::Message, &user_b, now);
    assert_eq!(b.step, 2);
    assert_eq!(b.work_factor, 400);
}

#[test]
fn reports_require_pow_immediately_and_appeals_are_stricter() {
    let guard = guard();
    let actors = vec!["user:1".to_owned()];
    assert_eq!(
        guard
            .requirement(AbuseAction::Report, &actors, Instant::now())
            .work_factor,
        200
    );
    let appeal = guard.requirement(AbuseAction::Appeal, &actors, Instant::now());
    assert_eq!(appeal.work_factor, 800);
    assert_eq!(appeal.hard_wait_seconds, 15);
}

#[test]
fn password_change_failures_get_a_separate_strict_policy() {
    let guard = guard();
    let actors = vec!["user:1".to_owned()];
    for _ in 0..3 {
        guard.record_failure_memory(AbuseAction::PasswordChange, &actors);
    }
    let requirement = guard.requirement(AbuseAction::PasswordChange, &actors, Instant::now());
    assert_eq!(requirement.step, 1);
    assert_eq!(requirement.work_factor, 400);
    assert_eq!(requirement.hard_wait_seconds, 0);
}

#[test]
fn sasl_failures_are_account_primary_and_do_not_lock_a_nat_peer() {
    let guard = guard();
    let ip = "ip:203.0.113.20".to_owned();
    let account_a = vec![ip.clone(), "login-account:a".to_owned()];
    let account_b = vec![ip, "login-account:b".to_owned()];
    for _ in 0..5 {
        guard.record_failure_memory(AbuseAction::Login, &account_a);
    }
    let limited = guard.requirement(AbuseAction::Login, &account_a, Instant::now());
    assert_eq!(limited.step, 1);
    assert!(limited.work_factor > 1);
    let peer = guard.requirement(AbuseAction::Login, &account_b, Instant::now());
    assert_eq!(peer.step, 0);
    assert_eq!(peer.work_factor, 1);
    assert_eq!(peer.retry_after_seconds, 0);
}

#[test]
fn registration_escalates_to_real_work_after_the_free_burst() {
    let guard = guard();
    let actors = vec!["ip:127.0.0.1".to_owned()];
    guard
        .verify_memory(
            AbuseAction::Registration,
            "registration:local",
            &actors,
            None,
        )
        .unwrap();
    let requirement = guard.requirement(AbuseAction::Registration, &actors, Instant::now());
    assert_eq!(requirement.step, 1);
    assert_eq!(requirement.work_factor, 100);
}

#[test]
fn cleanup_removes_fully_cooled_actor_and_challenge_issue_keys() {
    let guard = guard();
    let retention = guard
        .config
        .window
        .max(guard.config.max_wait)
        .max(max_penalty_decay_horizon(guard.config.cooldown_step));
    let old = Instant::now() - retention - Duration::from_secs(1);
    guard.states.insert(
        "message:ip:stale".to_owned(),
        ActorState {
            events: VecDeque::new(),
            penalty_level: 0,
            last_activity: old,
            blocked_until: old,
            sequence: 1,
        },
    );
    guard
        .challenge_issues
        .insert("challenge:ip:stale".to_owned(), VecDeque::from([old]));
    guard.cleanup_challenges_memory();
    assert!(guard.states.is_empty());
    assert!(guard.challenge_issues.is_empty());
}

/// The key schedule below never reaches persistence.
struct UnusedPersistence;

impl AbusePersistence for UnusedPersistence {
    fn issue<'a>(
        &'a self,
        _: records::IssueRequest,
        _: IssueDecision<'a>,
    ) -> AbusePersistenceFuture<'a, PowChallenge> {
        unreachable!()
    }

    fn verify<'a>(
        &'a self,
        _: &'a [String],
        _: Option<Uuid>,
        _: VerificationPolicy<'a>,
        _: Option<&'a dyn AdmissionCommitObserver>,
    ) -> AbusePersistenceFuture<'a, Result<WorkRequirement, GuardError>> {
        unreachable!()
    }

    fn current_requirement<'a>(
        &'a self,
        _: &'a [String],
        _: RequirementPolicy<'a>,
    ) -> AbusePersistenceFuture<'a, WorkRequirement> {
        unreachable!()
    }

    fn record_failure<'a>(
        &'a self,
        _: &'a [String],
        _: FailurePolicy<'a>,
    ) -> AbusePersistenceFuture<'a, ()> {
        unreachable!()
    }

    fn begin_message_admission<'a, 'r: 'a>(
        &'a self,
        _: &'a AbuseGuard,
        _: &'a MessageAdmissionRequest<'r>,
        _: &'a [MessageAdmissionCandidate],
        _: MessageDedupeIdentity,
        _: &'a dyn AdmissionCommitObserver,
    ) -> AbusePersistenceFuture<'a, MessageAdmissionStart> {
        unreachable!()
    }

    fn cleanup<'a>(&'a self, _: u64, _: u64) -> AbusePersistenceFuture<'a, ()> {
        unreachable!()
    }
}

#[tokio::test]
async fn overlap_keeps_previous_primary_until_retirement_is_fenced() {
    let config = guard().config;
    let old_secret = b"rotation-unit-old-secret-at-least-32-bytes";
    let new_secret = b"rotation-unit-new-secret-at-least-32-bytes";
    let old = AbuseGuard::new_persistent_for_deployment(
        config,
        Arc::new(UnusedPersistence),
        Some(old_secret),
        None,
        false,
        Some(chrono::DateTime::<chrono::Utc>::MAX_UTC),
    );
    let overlap = AbuseGuard::new_persistent_for_deployment(
        config,
        Arc::new(UnusedPersistence),
        Some(new_secret),
        Some(old_secret),
        true,
        Some(chrono::DateTime::<chrono::Utc>::MAX_UTC),
    );
    let retiring = AbuseGuard::new_persistent_for_deployment(
        config,
        Arc::new(UnusedPersistence),
        Some(new_secret),
        Some(old_secret),
        false,
        Some(chrono::DateTime::<chrono::Utc>::MAX_UTC),
    );

    assert_eq!(overlap.primary_actor_key().0, old.actor_key_id);
    assert_eq!(
        overlap.persistent_actor_key_candidates()[0].0,
        old.actor_key_id
    );
    assert_eq!(
        overlap.actor_secret_for_id("legacy-current").unwrap(),
        old.actor_key_secret.as_slice()
    );
    assert_eq!(retiring.primary_actor_key().0, retiring.actor_key_id);
    assert_eq!(
        retiring.persistent_actor_key_candidates()[1].0,
        old.actor_key_id
    );
    let payload = b"canonical content identity";
    let overlap_message = overlap
        .personal_message_content_keyring()
        .authenticators(payload);
    let overlap_retraction = overlap
        .personal_retraction_content_keyring()
        .authenticators(payload);
    let overlap_mix_message = overlap
        .mix_message_content_keyring()
        .authenticators(payload);
    let overlap_mix_retraction = overlap
        .mix_retraction_content_keyring()
        .authenticators(payload);
    let retiring_message = retiring
        .personal_message_content_keyring()
        .authenticators(payload);
    assert_eq!(overlap_message.primary().key_id(), old.actor_key_id);
    assert_eq!(retiring_message.primary().key_id(), retiring.actor_key_id);
    assert_eq!(overlap_message.candidates().len(), 2);
    assert!(retiring_message.verifies(
        overlap_message.primary().key_id(),
        overlap_message.primary().mac(),
    ));
    let changed_message = retiring
        .personal_message_content_keyring()
        .authenticators(b"changed canonical content identity");
    assert!(!changed_message.verifies(
        overlap_message.primary().key_id(),
        overlap_message.primary().mac(),
    ));
    assert_ne!(
        overlap_message.primary().mac(),
        overlap_retraction.primary().mac(),
        "a service-purpose key must not authenticate another service's content"
    );
    let purpose_macs = [
        overlap_message.primary().mac(),
        overlap_retraction.primary().mac(),
        overlap_mix_message.primary().mac(),
        overlap_mix_retraction.primary().mac(),
    ];
    for left in 0..purpose_macs.len() {
        for right in (left + 1)..purpose_macs.len() {
            assert_ne!(
                purpose_macs[left], purpose_macs[right],
                "every durable replay journal must use a distinct purpose subkey"
            );
        }
    }
    assert!(!retiring_message.verifies("unknown-generation", &[0_u8; 32]));
    assert!(!retiring_message.verifies(retiring_message.primary().key_id(), &[0_u8; 31]));
    assert!(overlap.minimum_key_rotation_overlap() >= OFFLINE_MESSAGE_ADMISSION_REPLAY_GRACE);
}
