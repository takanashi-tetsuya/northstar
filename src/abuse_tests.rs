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
        PowIntent {
            method: "XMPP".to_owned(),
            ..expected.clone()
        },
        PowIntent {
            path: "/api/v1/reports/other".to_owned(),
            ..expected.clone()
        },
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

#[tokio::test]
async fn closed_persistent_backend_is_never_treated_as_an_allow() {
    let pool = sqlx::postgres::PgPoolOptions::new()
        .connect_lazy("postgres://closed:closed@127.0.0.1:9/closed")
        .unwrap();
    pool.close().await;
    let guard = AbuseGuard::new_persistent(
        guard().config,
        pool,
        Some(b"test-only-abuse-state-key-at-least-32-bytes"),
        None,
    );
    let outcome = tokio::time::timeout(
        Duration::from_secs(1),
        guard.verify_or_allow(
            AbuseAction::Message,
            "message:closed",
            &["user:closed".to_owned()],
            None,
        ),
    )
    .await
    .expect("closed backend must fail immediately");
    assert!(outcome.is_err(), "backend failure must not fail open");
}

#[tokio::test]
async fn overlap_keeps_previous_primary_until_retirement_is_fenced() {
    let pool = sqlx::postgres::PgPoolOptions::new()
        .connect_lazy("postgres://unused:unused@127.0.0.1:9/unused")
        .unwrap();
    let config = guard().config;
    let old_secret = b"rotation-unit-old-secret-at-least-32-bytes";
    let new_secret = b"rotation-unit-new-secret-at-least-32-bytes";
    let old = AbuseGuard::new_persistent(config, pool.clone(), Some(old_secret), None);
    let overlap = AbuseGuard::new_persistent_for_deployment(
        config,
        pool.clone(),
        Some(new_secret),
        Some(old_secret),
        true,
        Some(chrono::DateTime::<chrono::Utc>::MAX_UTC),
    );
    let retiring = AbuseGuard::new_persistent_for_deployment(
        config,
        pool,
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

#[test]
fn offline_replay_grace_matches_the_database_trigger() {
    assert_eq!(
        OFFLINE_MESSAGE_ADMISSION_REPLAY_GRACE,
        Duration::from_secs(30 * 24 * 60 * 60)
    );
    assert!(
        include_str!("../migrations/0079_offline_message_dedupe.sql")
            .contains("INTERVAL '30 days'")
    );
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn postgres_v2_intent_mismatch_consumes_but_rollback_restores_proof() {
    let url = std::env::var("TEST_DATABASE_URL")
        .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(4)
        .connect(&url)
        .await
        .unwrap();
    crate::db::migrate(&pool).await.unwrap();
    let guard = AbuseGuard::new_persistent(
        guard().config,
        pool.clone(),
        Some(b"postgres-v2-intent-test-key-at-least-32-bytes"),
        None,
    );
    let marker = Uuid::new_v4();
    let actors = vec![format!("user:v2-intent:{marker}")];
    let subject = format!("report:v2-intent:{marker}");
    let expected = PowIntent::http_json(
        AbuseAction::Report,
        "/api/v1/reports",
        &serde_json::json!({"body":"bound"}),
    );
    let changed = PowIntent::http_json(
        AbuseAction::Report,
        "/api/v1/reports",
        &serde_json::json!({"body":"changed"}),
    );

    let mismatch = guard
        .issue_v2(AbuseAction::Report, &subject, &actors, &expected)
        .await
        .unwrap();
    let stored: (i16, String, String, Vec<u8>, String) = sqlx::query_as(
        "SELECT protocol_version,intent_method,intent_path,body_sha256,server_nonce
         FROM abuse_pow_challenges WHERE id=$1",
    )
    .bind(mismatch.challenge_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(stored.0, POW_INTENT_VERSION as i16);
    assert_eq!(stored.1, "POST");
    assert_eq!(stored.2, "/api/v1/reports");
    assert_eq!(stored.3, expected.body_sha256);
    assert!(stored.4.len() >= 16);

    tokio::time::sleep(
        Duration::from_secs(mismatch.requirement.hard_wait_seconds) + Duration::from_millis(50),
    )
    .await;
    let mut mismatch_tx = pool.begin().await.unwrap();
    let mismatch_result = crate::db::abuse_transaction_repository::verify_in_tx(
        &mut mismatch_tx,
        &guard,
        AbuseAction::Report,
        &subject,
        &actors,
        Some(&solve(&mismatch)),
        Some(&changed),
    )
    .await
    .unwrap();
    assert!(matches!(
        mismatch_result,
        TransactionalGuardOutcome::DeniedNeedsCommit(_)
    ));
    mismatch_tx.commit().await.unwrap();
    let mismatch_remaining: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM abuse_pow_challenges WHERE id=$1")
            .bind(mismatch.challenge_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(mismatch_remaining, 0, "a mismatched proof is one-use");

    let rollback = guard
        .issue_v2(AbuseAction::Report, &subject, &actors, &expected)
        .await
        .unwrap();
    let proof = solve(&rollback);
    tokio::time::sleep(
        Duration::from_secs(rollback.requirement.hard_wait_seconds) + Duration::from_millis(50),
    )
    .await;
    let mut rollback_tx = pool.begin().await.unwrap();
    assert!(matches!(
        crate::db::abuse_transaction_repository::verify_in_tx(
            &mut rollback_tx,
            &guard,
            AbuseAction::Report,
            &subject,
            &actors,
            Some(&proof),
            Some(&expected),
        )
        .await
        .unwrap(),
        TransactionalGuardOutcome::Allowed
    ));
    rollback_tx.rollback().await.unwrap();
    let restored: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM abuse_pow_challenges WHERE id=$1")
        .bind(rollback.challenge_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(restored, 1, "rolling back the mutation restores its proof");

    let mut commit_tx = pool.begin().await.unwrap();
    assert!(matches!(
        crate::db::abuse_transaction_repository::verify_in_tx(
            &mut commit_tx,
            &guard,
            AbuseAction::Report,
            &subject,
            &actors,
            Some(&proof),
            Some(&expected),
        )
        .await
        .unwrap(),
        TransactionalGuardOutcome::Allowed
    ));
    commit_tx.commit().await.unwrap();
    let consumed: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM abuse_pow_challenges WHERE id=$1")
        .bind(rollback.challenge_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(consumed, 0);

    let before_rotation = guard
        .issue_v2(AbuseAction::Report, &subject, &actors, &expected)
        .await
        .unwrap();
    tokio::time::sleep(
        Duration::from_secs(before_rotation.requirement.hard_wait_seconds)
            + Duration::from_millis(50),
    )
    .await;
    let rotated = AbuseGuard::new_persistent_for_deployment(
        guard.config,
        pool.clone(),
        Some(b"postgres-v2-rotated-test-key-at-least-32-bytes"),
        Some(b"postgres-v2-intent-test-key-at-least-32-bytes"),
        false,
        None,
    );
    assert!(rotated
        .verify_or_allow_v2(
            AbuseAction::Report,
            &subject,
            &actors,
            Some(&solve(&before_rotation)),
            &expected,
        )
        .await
        .unwrap()
        .is_ok());
    pool.close().await;
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn postgres_parallel_message_challenges_are_independent_bounded_and_one_use() {
    let url = std::env::var("TEST_DATABASE_URL")
        .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(8)
        .connect(&url)
        .await
        .unwrap();
    crate::db::migrate(&pool).await.unwrap();
    let guard = AbuseGuard::new_persistent(
        guard().config,
        pool.clone(),
        Some(b"parallel-message-pow-test-key-32bytes"),
        None,
    );
    let marker = Uuid::new_v4();
    let actors = vec![format!("user:parallel-message:{marker}")];
    let subject = format!("message:parallel-message:{marker}");
    let first_intent = PowIntent::xmpp(
        AbuseAction::Message,
        "/xmpp/message",
        b"<message id='parallel-one'><body>one</body></message>",
    );
    let second_intent = PowIntent::xmpp(
        AbuseAction::Message,
        "/xmpp/message",
        b"<message id='parallel-two'><body>two</body></message>",
    );

    let (first, second) = tokio::join!(
        guard.issue_v2(AbuseAction::Message, &subject, &actors, &first_intent),
        guard.issue_v2(AbuseAction::Message, &subject, &actors, &second_intent),
    );
    let first = first.unwrap();
    let second = second.unwrap();
    assert_ne!(first.challenge_id, second.challenge_id);
    let stored: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM abuse_pow_challenges WHERE id=ANY($1::uuid[])")
            .bind(vec![first.challenge_id, second.challenge_id])
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        stored, 2,
        "same-subject challenges must not replace each other"
    );

    let first_proof = solve(&first);
    let second_proof = solve(&second);
    let (first_result, second_result) = tokio::join!(
        guard.verify_or_allow_v2(
            AbuseAction::Message,
            &subject,
            &actors,
            Some(&first_proof),
            &first_intent,
        ),
        guard.verify_or_allow_v2(
            AbuseAction::Message,
            &subject,
            &actors,
            Some(&second_proof),
            &second_intent,
        ),
    );
    assert!(first_result.unwrap().is_ok());
    assert!(second_result.unwrap().is_ok());

    let mut capacity_ids = Vec::new();
    for index in 0..MAX_ACTIVE_POW_CHALLENGES_PER_ACTOR {
        let intent = PowIntent::xmpp(
            AbuseAction::Message,
            "/xmpp/message",
            format!("<message id='capacity-{index}'/>").as_bytes(),
        );
        capacity_ids.push(
            guard
                .issue_v2(AbuseAction::Message, &subject, &actors, &intent)
                .await
                .unwrap()
                .challenge_id,
        );
    }
    let overflow_intent = PowIntent::xmpp(
        AbuseAction::Message,
        "/xmpp/message",
        b"<message id='capacity-overflow'/>",
    );
    let overflow = guard
        .issue_v2(AbuseAction::Message, &subject, &actors, &overflow_intent)
        .await
        .unwrap_err();
    assert!(overflow
        .downcast_ref::<ChallengeCapacityExceeded>()
        .is_some());
    let capacity_rows: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM abuse_pow_challenges WHERE id=ANY($1::uuid[])")
            .bind(&capacity_ids)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        capacity_rows,
        i64::try_from(MAX_ACTIVE_POW_CHALLENGES_PER_ACTOR).unwrap(),
        "capacity rejection must not replace or add a challenge row"
    );

    let replay = guard
        .verify_or_allow_v2(
            AbuseAction::Message,
            &subject,
            &actors,
            Some(&first_proof),
            &first_intent,
        )
        .await
        .unwrap()
        .unwrap_err();
    assert!(replay.message().contains("already used"));
    pool.close().await;
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn postgres_challenges_are_one_use_restart_safe_and_deidentified() {
    let url = std::env::var("TEST_DATABASE_URL")
        .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(12)
        .connect(&url)
        .await
        .unwrap();
    crate::db::migrate(&pool).await.unwrap();
    let config = AbuseConfig {
        base_work_factor: 32,
        max_work_factor: 4_096,
        window: Duration::from_secs(60),
        cooldown_step: Duration::from_secs(60),
        max_wait: Duration::from_secs(900),
        message_free_burst: 60,
        approximate_max_device_seconds: 8,
    };
    let secret = b"test-only-shared-abuse-key-at-least-32-bytes";
    let guard = std::sync::Arc::new(AbuseGuard::new_persistent(
        config,
        pool.clone(),
        Some(secret),
        None,
    ));
    let marker = Uuid::new_v4();
    let actors = vec![
        format!("ip:198.51.100.{}", marker.as_bytes()[0]),
        format!("user:{marker}"),
        format!("behavior:{marker}"),
    ];
    let subject = format!("report:{marker}");
    let challenge = guard
        .issue(AbuseAction::Report, &subject, &actors)
        .await
        .unwrap();
    // 0057 labels challenges that predate the key-id column as
    // legacy-current. An upgrade that keeps the current abuse key must
    // preserve those proofs instead of burning them unconditionally.
    sqlx::query("UPDATE abuse_pow_challenges SET key_id='legacy-current' WHERE id=$1")
        .bind(challenge.challenge_id)
        .execute(&pool)
        .await
        .unwrap();
    let proof = solve(&challenge);
    let first = {
        let guard = std::sync::Arc::clone(&guard);
        let actors = actors.clone();
        let subject = subject.clone();
        let proof = proof.clone();
        tokio::spawn(async move {
            guard
                .verify_or_allow(AbuseAction::Report, &subject, &actors, Some(&proof))
                .await
                .unwrap()
        })
    };
    let second = {
        let guard = std::sync::Arc::clone(&guard);
        let actors = actors.clone();
        let subject = subject.clone();
        tokio::spawn(async move {
            guard
                .verify_or_allow(AbuseAction::Report, &subject, &actors, Some(&proof))
                .await
                .unwrap()
        })
    };
    let outcomes = [first.await.unwrap(), second.await.unwrap()];
    assert_eq!(outcomes.iter().filter(|outcome| outcome.is_ok()).count(), 1);
    assert_eq!(
        outcomes.iter().filter(|outcome| outcome.is_err()).count(),
        1
    );

    let restarted = AbuseGuard::new_persistent(config, pool.clone(), Some(secret), None);
    let requirement = restarted
        .current_requirement(AbuseAction::Report, &actors)
        .await
        .unwrap();
    assert!(requirement.step >= 2, "accepted proof must survive restart");

    let keys: Vec<String> =
        sqlx::query_scalar("SELECT state_key FROM abuse_actor_states ORDER BY state_key")
            .fetch_all(&pool)
            .await
            .unwrap();
    assert!(keys.iter().all(|key| {
        !actors.iter().any(|actor| key.contains(actor))
            && !key.contains("198.51.100")
            && !key.contains(&marker.to_string())
    }));

    // Rotation overlaps old and new actor keys. Mutations during the
    // overlap are copied to the new key so removing PREVIOUS later does
    // not reset the surviving penalty history.
    let new_secret = b"test-only-new-abuse-key-at-least-32-bytes";
    let issued_before_rotation = restarted
        .issue(AbuseAction::Report, &subject, &actors)
        .await
        .unwrap();
    let rotated = AbuseGuard::new_persistent_for_deployment(
        config,
        pool.clone(),
        Some(new_secret),
        Some(secret),
        true,
        Some(chrono::DateTime::<chrono::Utc>::MAX_UTC),
    );
    tokio::time::sleep(
        Duration::from_secs(issued_before_rotation.requirement.hard_wait_seconds)
            + Duration::from_millis(100),
    )
    .await;
    rotated
        .verify_or_allow(
            AbuseAction::Report,
            &subject,
            &actors,
            Some(&solve(&issued_before_rotation)),
        )
        .await
        .unwrap()
        .unwrap();
    let before = rotated
        .current_requirement(AbuseAction::Report, &actors)
        .await
        .unwrap();
    assert!(before.step >= 2);
    let rotated_challenge = rotated
        .issue(AbuseAction::Report, &subject, &actors)
        .await
        .unwrap();
    let rotated_challenge_key_id: String =
        sqlx::query_scalar("SELECT key_id FROM abuse_pow_challenges WHERE id=$1")
            .bind(rotated_challenge.challenge_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(rotated_challenge_key_id, restarted.actor_key_id);
    tokio::time::sleep(
        Duration::from_secs(rotated_challenge.requirement.hard_wait_seconds)
            + Duration::from_millis(100),
    )
    .await;
    restarted
        .verify_or_allow(
            AbuseAction::Report,
            &subject,
            &actors,
            Some(&solve(&rotated_challenge)),
        )
        .await
        .unwrap()
        .unwrap();
    // A dual-key read mirrors the old-only node's accepted transition into
    // the new generation before the previous generation is removed.
    rotated
        .current_requirement(AbuseAction::Report, &actors)
        .await
        .unwrap();
    let after_overlap = AbuseGuard::new_persistent(config, pool.clone(), Some(new_secret), None)
        .current_requirement(AbuseAction::Report, &actors)
        .await
        .unwrap();
    assert!(after_overlap.step > before.step);

    // Challenge issuance windows rotate as one lock-ordered state. An
    // actor at limit-1 under the old key has exactly one issuance left,
    // not a fresh window under the new key.
    let issue_actor = format!("user:issue-window-{}", Uuid::new_v4());
    let issue_actors = vec![issue_actor.clone()];
    let issue_subject = format!("report:issue-window:{issue_actor}");
    let old_issue_guard = AbuseGuard::new_persistent(config, pool.clone(), Some(secret), None);
    for _ in 0..(old_issue_guard.challenge_issue_limit(AbuseAction::Report) - 1) {
        let issued = old_issue_guard
            .issue(AbuseAction::Report, &issue_subject, &issue_actors)
            .await
            .unwrap();
        // This section isolates issuance-window continuity across key
        // rotation. Expire each proof after issuance so the independent
        // active-challenge ceiling cannot become the first limiter.
        sqlx::query(
            "UPDATE abuse_pow_challenges
                SET expires_at=clock_timestamp()
              WHERE id=$1",
        )
        .bind(issued.challenge_id)
        .execute(&pool)
        .await
        .unwrap();
    }
    let rotated_issue_guard = AbuseGuard::new_persistent_for_deployment(
        config,
        pool.clone(),
        Some(new_secret),
        Some(secret),
        true,
        Some(chrono::DateTime::<chrono::Utc>::MAX_UTC),
    );
    rotated_issue_guard
        .issue(AbuseAction::Report, &issue_subject, &issue_actors)
        .await
        .unwrap();
    let old_issue_key = format!(
        "challenge:{}",
        opaque_actor_key(
            AbuseAction::Report,
            &issue_actor,
            old_issue_guard.actor_key_secret.as_slice(),
        )
    );
    let new_issue_key = format!(
        "challenge:{}",
        opaque_actor_key(
            AbuseAction::Report,
            &issue_actor,
            rotated_issue_guard.actor_key_secret.as_slice(),
        )
    );
    let event_counts: Vec<i64> = sqlx::query_scalar(
        "SELECT cardinality(event_times)::bigint
         FROM abuse_challenge_issue_windows
         WHERE actor_key=ANY($1) ORDER BY actor_key",
    )
    .bind(vec![old_issue_key.clone(), new_issue_key.clone()])
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(event_counts, vec![30, 30]);
    let limited = rotated_issue_guard
        .issue(AbuseAction::Report, &issue_subject, &issue_actors)
        .await
        .unwrap_err();
    assert!(limited
        .downcast_ref::<ChallengeCapacityExceeded>()
        .is_some());
    let after_limit: Vec<i64> = sqlx::query_scalar(
        "SELECT cardinality(event_times)::bigint
         FROM abuse_challenge_issue_windows
         WHERE actor_key=ANY($1) ORDER BY actor_key",
    )
    .bind(vec![old_issue_key, new_issue_key])
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(after_limit, vec![30, 30]);

    // A cleanup pass is bounded to 1000 rows; a second pass drains the
    // remainder. This keeps maintenance latency bounded under attack.
    let cleanup_prefix = format!("cleanup-{marker}-");
    sqlx::query(
        "INSERT INTO abuse_actor_states (state_key,last_activity,blocked_until)
         SELECT $1 || value::text,
                clock_timestamp() - INTERVAL '10 days',
                clock_timestamp() - INTERVAL '10 days'
         FROM generate_series(1,1001) AS value",
    )
    .bind(&cleanup_prefix)
    .execute(&pool)
    .await
    .unwrap();
    rotated.cleanup_challenges().await.unwrap();
    let remaining: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM abuse_actor_states WHERE state_key LIKE $1")
            .bind(format!("{cleanup_prefix}%"))
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(remaining, 1);
    rotated.cleanup_challenges().await.unwrap();

    for key in actor_state_keys(AbuseAction::Report, &actors, &restarted.actor_key_secret) {
        sqlx::query("DELETE FROM abuse_actor_states WHERE state_key=$1")
            .bind(key)
            .execute(&pool)
            .await
            .unwrap();
    }
    pool.close().await;
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn postgres_challenge_capacity_is_concurrent_restart_safe_and_hard_limited() {
    let url = std::env::var("TEST_DATABASE_URL")
        .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(24)
        .connect(&url)
        .await
        .unwrap();
    crate::db::migrate(&pool).await.unwrap();
    let config = AbuseConfig {
        base_work_factor: 2,
        max_work_factor: 4_096,
        window: Duration::from_secs(60),
        cooldown_step: Duration::from_secs(60),
        max_wait: Duration::from_secs(8),
        message_free_burst: 60,
        approximate_max_device_seconds: 8,
    };
    let secret = b"challenge-capacity-test-secret-00000001";
    let guard = std::sync::Arc::new(AbuseGuard::new_persistent(
        config,
        pool.clone(),
        Some(secret),
        None,
    ));
    let account_actor = format!("user:capacity-{}", Uuid::new_v4());
    let account_actors = vec![account_actor.clone()];
    let mut tasks = Vec::new();
    for index in 0..24 {
        let guard = std::sync::Arc::clone(&guard);
        let actors = account_actors.clone();
        tasks.push(tokio::spawn(async move {
            let subject = format!("message:concurrent-capacity:{index}");
            (
                index,
                guard.issue(AbuseAction::Message, &subject, &actors).await,
            )
        }));
    }
    let mut successful_subject = None;
    let mut successful_challenge_id = None;
    let mut issued_challenge_ids = Vec::new();
    let mut accepted = 0;
    let mut limited = 0;
    for task in tasks {
        let (index, outcome) = task.await.unwrap();
        match outcome {
            Ok(challenge) => {
                accepted += 1;
                successful_subject
                    .get_or_insert_with(|| format!("message:concurrent-capacity:{index}"));
                successful_challenge_id.get_or_insert(challenge.challenge_id);
                issued_challenge_ids.push(challenge.challenge_id);
            }
            Err(error) => {
                assert!(error.downcast_ref::<ChallengeCapacityExceeded>().is_some());
                limited += 1;
            }
        }
    }
    assert_eq!(accepted, MAX_ACTIVE_POW_CHALLENGES_PER_ACTOR);
    assert_eq!(limited, 24 - MAX_ACTIVE_POW_CHALLENGES_PER_ACTOR);

    let restarted = AbuseGuard::new_persistent(config, pool.clone(), Some(secret), None);
    let error = restarted
        .issue(
            AbuseAction::Message,
            "message:concurrent-capacity:restart-overflow",
            &account_actors,
        )
        .await
        .unwrap_err();
    assert!(error.downcast_ref::<ChallengeCapacityExceeded>().is_some());
    let error = restarted
        .issue(
            AbuseAction::Message,
            successful_subject.as_deref().unwrap(),
            &account_actors,
        )
        .await
        .unwrap_err();
    assert!(error.downcast_ref::<ChallengeCapacityExceeded>().is_some());

    let expired = sqlx::query(
        "UPDATE abuse_pow_challenges SET expires_at=clock_timestamp()
         WHERE id=$1 AND expires_at > clock_timestamp()",
    )
    .bind(successful_challenge_id.expect("at least one account challenge was accepted"))
    .execute(&pool)
    .await
    .unwrap();
    assert_eq!(expired.rows_affected(), 1);
    let after_expiry = restarted
        .issue(
            AbuseAction::Message,
            "message:concurrent-capacity:after-expiry",
            &account_actors,
        )
        .await
        .unwrap();
    issued_challenge_ids.push(after_expiry.challenge_id);

    let ip_actor = format!("ip:198.51.100.{}", Uuid::new_v4().as_bytes()[0]);
    let ip_actors = vec![ip_actor.clone()];
    for index in 0..MAX_ACTIVE_POW_CHALLENGES_PER_IP {
        let challenge = restarted
            .issue(
                AbuseAction::Registration,
                &format!("registration:ip-capacity:{index}"),
                &ip_actors,
            )
            .await
            .unwrap();
        issued_challenge_ids.push(challenge.challenge_id);
    }
    let error = restarted
        .issue(
            AbuseAction::Registration,
            "registration:ip-capacity:overflow",
            &ip_actors,
        )
        .await
        .unwrap_err();
    assert!(error.downcast_ref::<ChallengeCapacityExceeded>().is_some());

    let window_ip = format!("ip:203.0.113.{}", Uuid::new_v4().as_bytes()[0]);
    let window_actors = vec![window_ip];
    let issue_keys = restarted
        .challenge_issue_groups(AbuseAction::Registration, &window_actors)
        .into_iter()
        .flat_map(|(keys, _)| keys)
        .collect::<Vec<_>>();
    sqlx::query(
        "INSERT INTO abuse_challenge_issue_windows(actor_key,event_times,updated_at)
         SELECT actor_key,events,clock_timestamp()
         FROM UNNEST($1::text[]) AS actor_key
         CROSS JOIN LATERAL (
             SELECT array_agg(clock_timestamp()-(value*INTERVAL '1 millisecond')
                              ORDER BY value) AS events
             FROM generate_series(0,$2::integer-1) AS value
         ) AS seeded
         ON CONFLICT(actor_key) DO UPDATE
         SET event_times=EXCLUDED.event_times,updated_at=EXCLUDED.updated_at",
    )
    .bind(&issue_keys)
    .bind(i32::try_from(MAX_CHALLENGE_ISSUES_PER_IP_WINDOW).unwrap())
    .execute(&pool)
    .await
    .unwrap();
    let seeded_issue_count: i64 = sqlx::query_scalar(
        "SELECT COALESCE(MAX(cardinality(event_times)),0)::bigint
         FROM abuse_challenge_issue_windows WHERE actor_key=ANY($1)",
    )
    .bind(&issue_keys)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        seeded_issue_count,
        i64::try_from(MAX_CHALLENGE_ISSUES_PER_IP_WINDOW).unwrap()
    );
    let challenge_count_before: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM abuse_pow_challenges")
            .fetch_one(&pool)
            .await
            .unwrap();
    let error = restarted
        .issue(
            AbuseAction::Registration,
            "registration:issue-window-overflow",
            &window_actors,
        )
        .await
        .unwrap_err();
    let capacity = error
        .downcast_ref::<ChallengeCapacityExceeded>()
        .expect("issue-window overflow must be typed");
    assert!((1..=60).contains(&capacity.retry_after_seconds()));
    let challenge_count_after: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM abuse_pow_challenges")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(challenge_count_after, challenge_count_before);

    let active_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM abuse_pow_challenges WHERE expires_at > clock_timestamp()",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    let fill_count = i64::try_from(MAX_ACTIVE_POW_CHALLENGES_GLOBAL).unwrap() - active_count;
    let marker = Uuid::new_v4().simple().to_string();
    sqlx::query(
        "INSERT INTO abuse_pow_challenges(
             id,action,subject_hash,key_id,prefix,work_factor,not_before,
             expires_at,actor_sequences,requirement,capacity_actor_keys
         )
         SELECT md5($1 || value::text)::uuid,'login',int8send(value),$1,
                $1 || value::text,1,clock_timestamp(),
                clock_timestamp()+INTERVAL '2 minutes','{}'::jsonb,'{}'::jsonb,'{}'::text[]
         FROM generate_series(1,$2) AS value",
    )
    .bind(&marker)
    .bind(fill_count)
    .execute(&pool)
    .await
    .unwrap();
    let error = restarted
        .issue(
            AbuseAction::Registration,
            "registration:global-overflow",
            &["ip:192.0.2.250".to_owned()],
        )
        .await
        .unwrap_err();
    assert!(error.downcast_ref::<ChallengeCapacityExceeded>().is_some());
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM abuse_pow_challenges WHERE expires_at > clock_timestamp()",
        )
        .fetch_one(&pool)
        .await
        .unwrap(),
        i64::try_from(MAX_ACTIVE_POW_CHALLENGES_GLOBAL).unwrap()
    );

    let persisted_capacity_keys: Vec<String> = sqlx::query_scalar(
        "SELECT UNNEST(capacity_actor_keys) FROM abuse_pow_challenges
         WHERE cardinality(capacity_actor_keys) > 0 LIMIT 32",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert!(persisted_capacity_keys
        .iter()
        .all(|key| { !key.contains(&account_actor) && !key.contains("198.51.100") }));

    // This test deliberately fills the process-wide challenge ceiling.
    // The WSL invariant suite runs several PostgreSQL tests in one
    // isolated schema, so retain only pre-existing fixture rows and remove
    // every challenge created here before the next test process starts.
    let cleaned = sqlx::query(
        "DELETE FROM abuse_pow_challenges
         WHERE id=ANY($1) OR key_id=$2",
    )
    .bind(&issued_challenge_ids)
    .bind(&marker)
    .execute(&pool)
    .await
    .unwrap();
    let expected_cleaned =
        u64::try_from(issued_challenge_ids.len()).unwrap() + u64::try_from(fill_count).unwrap();
    assert_eq!(cleaned.rows_affected(), expected_cleaned);

    pool.close().await;
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn postgres_message_admission_is_crash_atomic_fenced_and_rotation_safe() {
    let url = std::env::var("TEST_DATABASE_URL")
        .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(32)
        .connect(&url)
        .await
        .unwrap();
    crate::db::migrate(&pool).await.unwrap();
    let marker = Uuid::new_v4();
    let username = format!("msgpow{}", &marker.simple().to_string()[..16]);
    let user = crate::db::create_user(
        &pool,
        &username,
        "message-admission-test-password-42",
        false,
        true,
        crate::auth::MIN_SCRAM_ITERATIONS,
        false,
    )
    .await
    .unwrap();
    let config = AbuseConfig {
        base_work_factor: 2,
        max_work_factor: 4_096,
        window: Duration::from_secs(60),
        cooldown_step: Duration::from_secs(60),
        max_wait: Duration::from_secs(8),
        message_free_burst: 60,
        approximate_max_device_seconds: 8,
    };
    let old_secret = b"message-admission-old-secret-00000001";
    let guard = std::sync::Arc::new(AbuseGuard::new_persistent(
        config,
        pool.clone(),
        Some(old_secret),
        None,
    ));
    let account = format!("{username}@example.test");
    let target = "bob@example.test".to_owned();
    let origin = format!("origin-{marker}");
    let payload = format!(
        "<message to='{target}' type='chat'><body>atomic</body><origin-id xmlns='urn:xmpp:sid:0' id='{origin}'/></message>"
    );
    let actors = vec![
        "ip:198.51.100.81".to_owned(),
        format!("user:{}", user.id),
        format!("behavior:{}", user.id),
    ];
    let subject = format!("message:{}", user.id);
    let challenge = guard
        .issue(AbuseAction::Message, &subject, &actors)
        .await
        .unwrap();
    let proof = solve(&challenge);

    let mut tasks = Vec::new();
    for _ in 0..24 {
        let guard = std::sync::Arc::clone(&guard);
        let account = account.clone();
        let target = target.clone();
        let origin = origin.clone();
        let payload = payload.clone();
        let actors = actors.clone();
        let subject = subject.clone();
        let proof = proof.clone();
        tasks.push(tokio::spawn(async move {
            guard
                .begin_message_admission(&MessageAdmissionRequest {
                    actor_id: user.id,
                    account_bare: &account,
                    normalized_target: &target,
                    origin_id: Some(&origin),
                    normalized_payload: &payload,
                    pow_intent_payload: &payload,
                    subject: &subject,
                    actors: &actors,
                    proof: Some(&proof),
                })
                .await
                .unwrap()
        }));
    }
    let mut first_lease = None;
    let mut proceeded = 0;
    let mut in_progress = 0;
    for task in tasks {
        match task.await.unwrap() {
            MessageAdmissionStart::Proceed {
                lease: Some(lease), ..
            } => {
                proceeded += 1;
                first_lease = Some(lease);
            }
            MessageAdmissionStart::InProgress { requirement } => {
                assert!((1..=MESSAGE_ADMISSION_LEASE.as_secs())
                    .contains(&requirement.retry_after_seconds));
                in_progress += 1;
            }
            other => panic!("unexpected concurrent message admission outcome: {other:?}"),
        }
    }
    assert_eq!(proceeded, 1);
    assert_eq!(in_progress, 23);
    let first_lease = first_lease.unwrap();
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM abuse_message_admissions WHERE actor_id=$1",
        )
        .bind(user.id)
        .fetch_one(&pool)
        .await
        .unwrap(),
        1
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM abuse_pow_challenges WHERE id=$1",)
            .bind(proof.challenge_id)
            .fetch_one(&pool)
            .await
            .unwrap(),
        0
    );
    let actor_keys = actor_state_keys(AbuseAction::Message, &actors, &guard.actor_key_secret);
    let sequences: Vec<i64> = sqlx::query_scalar(
        "SELECT sequence FROM abuse_actor_states WHERE state_key=ANY($1) ORDER BY state_key",
    )
    .bind(&actor_keys)
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(sequences, vec![1; actor_keys.len()]);

    // Simulate a process crash after the proof/actor/pending commit. The
    // restarted worker may take over only after the fencing lease expires,
    // and it must not advance any actor a second time.
    sqlx::query(
        "UPDATE abuse_message_admissions
         SET lease_expires_at=created_at
         WHERE actor_id=$1",
    )
    .bind(user.id)
    .execute(&pool)
    .await
    .unwrap();
    let restarted = AbuseGuard::new_persistent(config, pool.clone(), Some(old_secret), None);
    let takeover = restarted
        .begin_message_admission(&MessageAdmissionRequest {
            actor_id: user.id,
            account_bare: &account,
            normalized_target: &target,
            origin_id: Some(&origin),
            normalized_payload: &payload,
            pow_intent_payload: &payload,
            subject: &subject,
            actors: &actors,
            proof: Some(&proof),
        })
        .await
        .unwrap();
    let takeover_lease = match takeover {
        MessageAdmissionStart::Proceed {
            lease: Some(lease), ..
        } => lease,
        other => panic!("expired pending admission was not resumed: {other:?}"),
    };
    let resumed_sequences: Vec<i64> = sqlx::query_scalar(
        "SELECT sequence FROM abuse_actor_states WHERE state_key=ANY($1) ORDER BY state_key",
    )
    .bind(&actor_keys)
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(resumed_sequences, sequences);
    assert!(
        crate::db::message_admission_repository::accept_message_admission(
            &pool,
            &first_lease.acceptance(),
        )
        .await
        .is_err()
    );
    crate::db::message_admission_repository::accept_message_admission(
        &pool,
        &takeover_lease.acceptance(),
    )
    .await
    .unwrap();
    assert!(matches!(
        restarted
            .begin_message_admission(&MessageAdmissionRequest {
                actor_id: user.id,
                account_bare: &account,
                normalized_target: &target,
                origin_id: Some(&origin),
                normalized_payload: &payload,
                pow_intent_payload: &payload,
                subject: &subject,
                actors: &actors,
                proof: Some(&proof),
            })
            .await
            .unwrap(),
        MessageAdmissionStart::ReplayAccepted
    ));
    let conflicting_payload = payload.replace("atomic", "different");
    assert!(matches!(
        restarted
            .begin_message_admission(&MessageAdmissionRequest {
                actor_id: user.id,
                account_bare: &account,
                normalized_target: &target,
                origin_id: Some(&origin),
                normalized_payload: &conflicting_payload,
                pow_intent_payload: &conflicting_payload,
                subject: &subject,
                actors: &actors,
                proof: Some(&proof),
            })
            .await
            .unwrap(),
        MessageAdmissionStart::Conflict
    ));

    // A capacity rejection happens after transactional proof verification,
    // but rolls the proof deletion and actor update back together.
    let rollback_origin = format!("rollback-{marker}");
    let rollback_payload = format!(
        "<message to='{target}'><body>rollback</body><origin-id xmlns='urn:xmpp:sid:0' id='{rollback_origin}'/></message>"
    );
    let rollback_challenge = restarted
        .issue(AbuseAction::Message, &subject, &actors)
        .await
        .unwrap();
    let rollback_proof = solve(&rollback_challenge);
    let rollback_request = MessageAdmissionRequest {
        actor_id: user.id,
        account_bare: &account,
        normalized_target: &target,
        origin_id: Some(&rollback_origin),
        normalized_payload: &rollback_payload,
        pow_intent_payload: &rollback_payload,
        subject: &subject,
        actors: &actors,
        proof: Some(&rollback_proof),
    };
    let (rollback_key, _) = message_admission_material(
        &rollback_request,
        &restarted.actor_key_secret,
        b"origin-id",
        rollback_origin.as_bytes(),
    );
    let rollback_shard = message_admission_capacity_shard(&rollback_key);
    sqlx::query("UPDATE abuse_message_admission_capacity SET active_records=$2 WHERE shard=$1")
        .bind(rollback_shard)
        .bind(MAX_ACTIVE_MESSAGE_ADMISSIONS_PER_SHARD)
        .execute(&pool)
        .await
        .unwrap();
    let sequence_before_rollback: i64 =
        sqlx::query_scalar("SELECT MAX(sequence) FROM abuse_actor_states WHERE state_key=ANY($1)")
            .bind(&actor_keys)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(matches!(
        restarted
            .begin_message_admission(&rollback_request)
            .await
            .unwrap(),
        MessageAdmissionStart::CapacityLimited
    ));
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM abuse_pow_challenges WHERE id=$1")
            .bind(rollback_proof.challenge_id)
            .fetch_one(&pool)
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT MAX(sequence) FROM abuse_actor_states WHERE state_key=ANY($1)",
        )
        .bind(&actor_keys)
        .fetch_one(&pool)
        .await
        .unwrap(),
        sequence_before_rollback
    );
    let actual_shard_count: i32 = sqlx::query_scalar(
        "SELECT COUNT(*)::integer FROM abuse_message_admissions WHERE capacity_shard=$1",
    )
    .bind(rollback_shard)
    .fetch_one(&pool)
    .await
    .unwrap();
    sqlx::query("UPDATE abuse_message_admission_capacity SET active_records=$2 WHERE shard=$1")
        .bind(rollback_shard)
        .bind(actual_shard_count)
        .execute(&pool)
        .await
        .unwrap();

    // A deferred failure fires after INSERT at COMMIT, covering the last
    // crash cut. The challenge, actor sequence, capacity and pending row
    // must all roll back and the exact proof must remain usable.
    let suffix = marker.simple().to_string();
    let function_name = format!("test_message_admission_fail_{suffix}");
    let trigger_name = format!("test_message_admission_trigger_{suffix}");
    sqlx::query(&format!(
        "CREATE FUNCTION {function_name}() RETURNS TRIGGER AS $$
         BEGIN RAISE EXCEPTION 'injected message admission commit failure'; END;
         $$ LANGUAGE plpgsql"
    ))
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(&format!(
        "CREATE CONSTRAINT TRIGGER {trigger_name}
         AFTER INSERT ON abuse_message_admissions
         DEFERRABLE INITIALLY DEFERRED FOR EACH ROW
         EXECUTE FUNCTION {function_name}()"
    ))
    .execute(&pool)
    .await
    .unwrap();
    assert!(restarted
        .begin_message_admission(&rollback_request)
        .await
        .is_err());
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM abuse_pow_challenges WHERE id=$1")
            .bind(rollback_proof.challenge_id)
            .fetch_one(&pool)
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM abuse_message_admissions WHERE admission_key=$1",
        )
        .bind(&rollback_key)
        .fetch_one(&pool)
        .await
        .unwrap(),
        0
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT MAX(sequence) FROM abuse_actor_states WHERE state_key=ANY($1)",
        )
        .bind(&actor_keys)
        .fetch_one(&pool)
        .await
        .unwrap(),
        sequence_before_rollback
    );
    sqlx::query(&format!(
        "DROP TRIGGER {trigger_name} ON abuse_message_admissions"
    ))
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(&format!("DROP FUNCTION {function_name}()"))
        .execute(&pool)
        .await
        .unwrap();
    assert!(matches!(
        restarted
            .begin_message_admission(&rollback_request)
            .await
            .unwrap(),
        MessageAdmissionStart::Proceed { lease: Some(_), .. }
    ));

    let new_secret = b"message-admission-new-secret-00000002";
    let rotated = AbuseGuard::new_persistent_for_deployment(
        config,
        pool.clone(),
        Some(new_secret),
        Some(old_secret),
        true,
        Some(chrono::DateTime::<chrono::Utc>::MAX_UTC),
    );
    assert!(matches!(
        rotated
            .begin_message_admission(&MessageAdmissionRequest {
                actor_id: user.id,
                account_bare: &account,
                normalized_target: &target,
                origin_id: Some(&origin),
                normalized_payload: &payload,
                pow_intent_payload: &payload,
                subject: &subject,
                actors: &actors,
                proof: Some(&proof),
            })
            .await
            .unwrap(),
        MessageAdmissionStart::ReplayAccepted
    ));

    // A fresh admission created by a dual-key overlap node remains fully
    // interoperable with an old-only node. The admission and its offline
    // dedupe projection are both written under the old primary key; the
    // new key is retained only as a verification candidate.
    let rotation_origin = format!("rotation-{marker}");
    let rotation_payload = format!(
        "<message to='{target}' type='chat'><body>rotation</body><origin-id xmlns='urn:xmpp:sid:0' id='{rotation_origin}'/></message>"
    );
    let rotation_challenge = rotated
        .issue(AbuseAction::Message, &subject, &actors)
        .await
        .unwrap();
    let rotation_proof = solve(&rotation_challenge);
    let rotation_request = MessageAdmissionRequest {
        actor_id: user.id,
        account_bare: &account,
        normalized_target: &target,
        origin_id: Some(&rotation_origin),
        normalized_payload: &rotation_payload,
        pow_intent_payload: &rotation_payload,
        subject: &subject,
        actors: &actors,
        proof: Some(&rotation_proof),
    };
    let rotation_lease = match rotated
        .begin_message_admission(&rotation_request)
        .await
        .unwrap()
    {
        MessageAdmissionStart::Proceed {
            lease: Some(lease), ..
        } => lease,
        other => panic!("overlap admission was not accepted: {other:?}"),
    };
    assert_eq!(
        rotation_lease.offline_dedupe.candidates[0].key_id,
        restarted.actor_key_id
    );
    assert_eq!(
        rotation_lease.offline_dedupe.candidates[1].key_id,
        rotated.actor_key_id
    );
    let stored_admission_key_id: String =
        sqlx::query_scalar("SELECT key_id FROM abuse_message_admissions WHERE admission_key=$1")
            .bind(&rotation_lease.admission_key)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(stored_admission_key_id, restarted.actor_key_id);

    let offline_policy = crate::db::OfflineStorePolicy {
        max_messages: 100,
        max_bytes: 1_048_576,
        ttl_days: 30,
        mam_backed: false,
    };
    assert_eq!(
        crate::db::store_offline_idempotent(
            &pool,
            user.id,
            &account,
            &rotation_payload,
            true,
            offline_policy,
            Some(&rotation_lease.offline_dedupe),
        )
        .await
        .unwrap(),
        crate::db::OfflineStoreOutcome::Stored
    );
    let stored_offline_key_id: String = sqlx::query_scalar(
        "SELECT payload_key_id FROM offline_message_admissions WHERE identity_digest=$1",
    )
    .bind(&rotation_lease.offline_dedupe.identity_digest)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(stored_offline_key_id, restarted.actor_key_id);

    let (identity_kind, identity_value) = message_admission_identity(&rotation_request).unwrap();
    let (_, old_payload_mac) = message_admission_material(
        &rotation_request,
        &restarted.actor_key_secret,
        identity_kind,
        &identity_value,
    );
    let old_only_dedupe = MessageDedupeIdentity {
        identity_digest: message_admission_identity_digest(
            &rotation_request,
            identity_kind,
            &identity_value,
        ),
        candidates: vec![MessageDedupeCandidate {
            key_id: restarted.actor_key_id.clone(),
            payload_mac: old_payload_mac,
        }],
    };
    assert_eq!(
        crate::db::store_offline_idempotent(
            &pool,
            user.id,
            &account,
            &rotation_payload,
            true,
            offline_policy,
            Some(&old_only_dedupe),
        )
        .await
        .unwrap(),
        crate::db::OfflineStoreOutcome::Replay
    );
    crate::db::message_admission_repository::accept_message_admission(
        &pool,
        &rotation_lease.acceptance(),
    )
    .await
    .unwrap();
    assert!(matches!(
        restarted
            .begin_message_admission(&rotation_request)
            .await
            .unwrap(),
        MessageAdmissionStart::ReplayAccepted
    ));

    let over_rotated = AbuseGuard::new_persistent(
        config,
        pool.clone(),
        Some(b"message-admission-third-secret-000003"),
        None,
    );
    assert!(matches!(
        over_rotated
            .begin_message_admission(&MessageAdmissionRequest {
                actor_id: user.id,
                account_bare: &account,
                normalized_target: &target,
                origin_id: Some(&origin),
                normalized_payload: &payload,
                pow_intent_payload: &payload,
                subject: &subject,
                actors: &actors,
                proof: Some(&proof),
            })
            .await
            .unwrap(),
        MessageAdmissionStart::Denied(_)
    ));

    // A proof for a missing challenge is denied and penalized in one
    // transaction; it must never leave a pending admission behind.
    let denied_origin = format!("denied-{marker}");
    let denied_payload = format!(
        "<message to='{target}'><body>denied</body><origin-id xmlns='urn:xmpp:sid:0' id='{denied_origin}'/></message>"
    );
    let denied_actors = vec![format!("user:denied:{marker}")];
    let denied_subject = format!("message:denied:{marker}");
    let missing_proof = PowProof {
        challenge_id: Uuid::new_v4(),
        nonce: "0".to_owned(),
    };
    let denied_request = MessageAdmissionRequest {
        actor_id: user.id,
        account_bare: &account,
        normalized_target: &target,
        origin_id: Some(&denied_origin),
        normalized_payload: &denied_payload,
        pow_intent_payload: &denied_payload,
        subject: &denied_subject,
        actors: &denied_actors,
        proof: Some(&missing_proof),
    };
    assert!(matches!(
        over_rotated
            .begin_message_admission(&denied_request)
            .await
            .unwrap(),
        MessageAdmissionStart::Denied(GuardError::Invalid(_, _))
    ));
    let (identity_kind, identity_value) = message_admission_identity(&denied_request).unwrap();
    let (denied_key, _) = message_admission_material(
        &denied_request,
        &over_rotated.actor_key_secret,
        identity_kind,
        &identity_value,
    );
    let denied_rows: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM abuse_message_admissions WHERE admission_key=$1")
            .bind(&denied_key)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(denied_rows, 0);
    let denied_state_key = actor_state_keys(
        AbuseAction::Message,
        &denied_actors,
        &over_rotated.actor_key_secret,
    );
    let denied_sequence: i64 =
        sqlx::query_scalar("SELECT sequence FROM abuse_actor_states WHERE state_key=$1")
            .bind(&denied_state_key[0])
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(denied_sequence, 1);

    sqlx::query("DELETE FROM users WHERE id=$1")
        .bind(user.id)
        .execute(&pool)
        .await
        .unwrap();
    pool.close().await;
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn postgres_message_admission_capacity_and_cleanup_are_bounded() {
    let url = std::env::var("TEST_DATABASE_URL")
        .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(16)
        .connect(&url)
        .await
        .unwrap();
    crate::db::migrate(&pool).await.unwrap();
    let marker = Uuid::new_v4();
    let marker_text = marker.simple().to_string();
    let username = format!("msgcap{}", &marker_text[..16]);
    let user = crate::db::create_user(
        &pool,
        &username,
        "message-capacity-test-password-42",
        false,
        true,
        crate::auth::MIN_SCRAM_ITERATIONS,
        false,
    )
    .await
    .unwrap();
    let config = AbuseConfig {
        base_work_factor: 2,
        max_work_factor: 4_096,
        window: Duration::from_secs(60),
        cooldown_step: Duration::from_secs(60),
        max_wait: Duration::from_secs(8),
        message_free_burst: 60,
        approximate_max_device_seconds: 8,
    };
    let secret = b"message-admission-capacity-secret-0001";
    let guard = AbuseGuard::new_persistent(config, pool.clone(), Some(secret), None);
    let account = format!("{username}@example.test");
    let target = "bob@example.test";
    let actors = vec![format!("user:{}", user.id)];
    let subject = format!("message:{}", user.id);
    let challenge = guard
        .issue(AbuseAction::Message, &subject, &actors)
        .await
        .unwrap();
    let proof = solve(&challenge);
    let payload = "<message to='bob@example.test'><body>capacity</body></message>";

    let mut origins_by_shard = vec![None; usize::from(MESSAGE_ADMISSION_CAPACITY_SHARDS)];
    for index in 0..100_000_u32 {
        let origin = format!("capacity-{marker}-{index}");
        let request = MessageAdmissionRequest {
            actor_id: user.id,
            account_bare: &account,
            normalized_target: target,
            origin_id: Some(&origin),
            normalized_payload: payload,
            pow_intent_payload: payload,
            subject: &subject,
            actors: &actors,
            proof: Some(&proof),
        };
        let (key, _) = message_admission_material(
            &request,
            &guard.actor_key_secret,
            b"origin-id",
            origin.as_bytes(),
        );
        let shard = usize::try_from(message_admission_capacity_shard(&key)).unwrap();
        origins_by_shard[shard].get_or_insert(origin);
        if origins_by_shard.iter().all(Option::is_some) {
            break;
        }
    }
    assert!(origins_by_shard.iter().all(Option::is_some));
    for (shard, origin) in origins_by_shard.iter().enumerate() {
        let shard = i16::try_from(shard).unwrap();
        let actual: i32 = sqlx::query_scalar(
            "SELECT COUNT(*)::integer FROM abuse_message_admissions WHERE capacity_shard=$1",
        )
        .bind(shard)
        .fetch_one(&pool)
        .await
        .unwrap();
        sqlx::query("UPDATE abuse_message_admission_capacity SET active_records=$2 WHERE shard=$1")
            .bind(shard)
            .bind(MAX_ACTIVE_MESSAGE_ADMISSIONS_PER_SHARD)
            .execute(&pool)
            .await
            .unwrap();
        let outcome = guard
            .begin_message_admission(&MessageAdmissionRequest {
                actor_id: user.id,
                account_bare: &account,
                normalized_target: target,
                origin_id: origin.as_deref(),
                normalized_payload: payload,
                pow_intent_payload: payload,
                subject: &subject,
                actors: &actors,
                proof: Some(&proof),
            })
            .await
            .unwrap();
        assert!(matches!(outcome, MessageAdmissionStart::CapacityLimited));
        sqlx::query("UPDATE abuse_message_admission_capacity SET active_records=$2 WHERE shard=$1")
            .bind(shard)
            .bind(actual)
            .execute(&pool)
            .await
            .unwrap();
    }
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM abuse_pow_challenges WHERE id=$1")
            .bind(proof.challenge_id)
            .fetch_one(&pool)
            .await
            .unwrap(),
        1,
        "every full-shard rejection must roll the proof back"
    );
    let first_origin = origins_by_shard[0].as_deref().unwrap();
    assert!(matches!(
        guard
            .begin_message_admission(&MessageAdmissionRequest {
                actor_id: user.id,
                account_bare: &account,
                normalized_target: target,
                origin_id: Some(first_origin),
                normalized_payload: payload,
                pow_intent_payload: payload,
                subject: &subject,
                actors: &actors,
                proof: Some(&proof),
            })
            .await
            .unwrap(),
        MessageAdmissionStart::Proceed { lease: Some(_), .. }
    ));

    // Fill the per-account boundary in one set-based transaction. The
    // counter update and fixture rows mirror the production reservation;
    // trigger-backed deletion later proves exact capacity release.
    let existing_for_user: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM abuse_message_admissions WHERE actor_id=$1")
            .bind(user.id)
            .fetch_one(&pool)
            .await
            .unwrap();
    let fixture_count = MAX_ACTIVE_MESSAGE_ADMISSIONS_PER_USER - existing_for_user;
    let fixture_shard = 63_i16;
    let mut fixture_tx = pool.begin().await.unwrap();
    sqlx::query(
        "UPDATE abuse_message_admission_capacity
         SET active_records=active_records+$2 WHERE shard=$1",
    )
    .bind(fixture_shard)
    .bind(i32::try_from(fixture_count).unwrap())
    .execute(&mut *fixture_tx)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO abuse_message_admissions
         (admission_key,key_id,actor_id,capacity_shard,payload_mac,state,
          lease_token,lease_expires_at,expires_at)
         SELECT decode(md5($1 || value::text) || md5('key:' || $1 || value::text),'hex'),
                'capacity-fixture',$2,$3,
                decode(md5('payload:' || $1 || value::text) || md5('mac:' || $1 || value::text),'hex'),
                'pending',
                ('10000000-0000-4000-8000-' || lpad(value::text,12,'0'))::uuid,
                clock_timestamp()+INTERVAL '10 minutes',
                clock_timestamp()+INTERVAL '20 minutes'
         FROM generate_series(1,$4::integer) AS value",
    )
    .bind(&marker_text)
    .bind(user.id)
    .bind(fixture_shard)
    .bind(i32::try_from(fixture_count).unwrap())
    .execute(&mut *fixture_tx)
    .await
    .unwrap();
    fixture_tx.commit().await.unwrap();
    let overflow_origin = format!("user-overflow-{marker}");
    let overflow_challenge = guard
        .issue(AbuseAction::Message, &subject, &actors)
        .await
        .unwrap();
    let overflow_proof = solve(&overflow_challenge);
    let overflow_request = MessageAdmissionRequest {
        actor_id: user.id,
        account_bare: &account,
        normalized_target: target,
        origin_id: Some(&overflow_origin),
        normalized_payload: payload,
        pow_intent_payload: payload,
        subject: &subject,
        actors: &actors,
        proof: Some(&overflow_proof),
    };
    assert!(matches!(
        guard
            .begin_message_admission(&overflow_request)
            .await
            .unwrap(),
        MessageAdmissionStart::CapacityLimited
    ));
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM abuse_pow_challenges WHERE id=$1")
            .bind(overflow_proof.challenge_id)
            .fetch_one(&pool)
            .await
            .unwrap(),
        1
    );
    sqlx::query("DELETE FROM abuse_message_admissions WHERE key_id='capacity-fixture'")
        .execute(&pool)
        .await
        .unwrap();
    assert!(matches!(
        guard
            .begin_message_admission(&overflow_request)
            .await
            .unwrap(),
        MessageAdmissionStart::Proceed { lease: Some(_), .. }
    ));

    // More expired rows than one maintenance batch leave exactly the
    // bounded remainder. A live row with an active fencing lease is never
    // selected, and capacity counters equal physical rows after both runs.
    let cleanup_shard = 62_i16;
    let expired_count = MESSAGE_ADMISSION_CLEANUP_BATCH + 1;
    let mut cleanup_tx = pool.begin().await.unwrap();
    sqlx::query(
        "UPDATE abuse_message_admission_capacity
         SET active_records=active_records+$2 WHERE shard=$1",
    )
    .bind(cleanup_shard)
    .bind(i32::try_from(expired_count + 1).unwrap())
    .execute(&mut *cleanup_tx)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO abuse_message_admissions
         (admission_key,key_id,actor_id,capacity_shard,payload_mac,state,
          lease_token,lease_expires_at,expires_at)
         SELECT decode(md5('expired:' || $1 || value::text) || md5('expired-key:' || $1 || value::text),'hex'),
                'cleanup-expired',$2,$3,
                decode(md5('expired-payload:' || $1 || value::text) || md5('expired-mac:' || $1 || value::text),'hex'),
                'pending',
                ('20000000-0000-4000-8000-' || lpad(value::text,12,'0'))::uuid,
                clock_timestamp()+INTERVAL '10 minutes',
                clock_timestamp()-INTERVAL '1 second'
         FROM generate_series(1,$4::integer) AS value",
    )
    .bind(&marker_text)
    .bind(user.id)
    .bind(cleanup_shard)
    .bind(i32::try_from(expired_count).unwrap())
    .execute(&mut *cleanup_tx)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO abuse_message_admissions
         (admission_key,key_id,actor_id,capacity_shard,payload_mac,state,
          lease_token,lease_expires_at,expires_at)
         VALUES(decode(md5('active:' || $1) || md5('active-key:' || $1),'hex'),
                'cleanup-active',$2,$3,
                decode(md5('active-payload:' || $1) || md5('active-mac:' || $1),'hex'),
                'pending','30000000-0000-4000-8000-000000000001',
                clock_timestamp()+INTERVAL '10 minutes',
                clock_timestamp()+INTERVAL '20 minutes')",
    )
    .bind(&marker_text)
    .bind(user.id)
    .bind(cleanup_shard)
    .execute(&mut *cleanup_tx)
    .await
    .unwrap();
    cleanup_tx.commit().await.unwrap();
    guard.cleanup_challenges().await.unwrap();
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM abuse_message_admissions WHERE key_id='cleanup-expired'",
        )
        .fetch_one(&pool)
        .await
        .unwrap(),
        1
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM abuse_message_admissions WHERE key_id='cleanup-active'",
        )
        .fetch_one(&pool)
        .await
        .unwrap(),
        1
    );
    guard.cleanup_challenges().await.unwrap();
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM abuse_message_admissions WHERE key_id='cleanup-expired'",
        )
        .fetch_one(&pool)
        .await
        .unwrap(),
        0
    );
    let shard_rows: i32 = sqlx::query_scalar(
        "SELECT COUNT(*)::integer FROM abuse_message_admissions WHERE capacity_shard=$1",
    )
    .bind(cleanup_shard)
    .fetch_one(&pool)
    .await
    .unwrap();
    let shard_capacity: i32 = sqlx::query_scalar(
        "SELECT active_records FROM abuse_message_admission_capacity WHERE shard=$1",
    )
    .bind(cleanup_shard)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(shard_capacity, shard_rows);

    sqlx::query("DELETE FROM users WHERE id=$1")
        .bind(user.id)
        .execute(&pool)
        .await
        .unwrap();
    let counters_match: bool = sqlx::query_scalar(
        "SELECT NOT EXISTS(
             SELECT 1 FROM abuse_message_admission_capacity capacity
             WHERE capacity.active_records <> (
                 SELECT COUNT(*)::integer FROM abuse_message_admissions admission
                 WHERE admission.capacity_shard=capacity.shard
             )
         )",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(counters_match);
    pool.close().await;
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn postgres_accepts_one_thousand_independent_actor_decisions() {
    let url = std::env::var("TEST_DATABASE_URL")
        .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(32)
        .connect(&url)
        .await
        .unwrap();
    crate::db::migrate(&pool).await.unwrap();
    let guard = std::sync::Arc::new(AbuseGuard::new_persistent(
        AbuseConfig {
            base_work_factor: 32,
            max_work_factor: 4_096,
            window: Duration::from_secs(60),
            cooldown_step: Duration::from_secs(60),
            max_wait: Duration::from_secs(900),
            message_free_burst: 60,
            approximate_max_device_seconds: 8,
        },
        pool.clone(),
        Some(b"test-only-throughput-key-at-least-32-bytes"),
        None,
    ));
    let marker = Uuid::new_v4();
    let started = Instant::now();
    let mut tasks = Vec::with_capacity(1_000);
    for index in 0..1_000 {
        let guard = std::sync::Arc::clone(&guard);
        let actor = format!("user:{marker}:{index}");
        tasks.push(tokio::spawn(async move {
            guard
                .verify_or_allow(
                    AbuseAction::Message,
                    &format!("message:{actor}"),
                    std::slice::from_ref(&actor),
                    None,
                )
                .await
                .unwrap()
                .unwrap();
        }));
    }
    tokio::time::timeout(Duration::from_secs(60), async {
        for task in tasks {
            task.await.unwrap();
        }
    })
    .await
    .expect("1000 independent actor decisions exceeded 60 seconds");
    let elapsed = started.elapsed();
    eprintln!(
        "1000 durable abuse decisions: {:.2}s ({:.0} decisions/s)",
        elapsed.as_secs_f64(),
        1_000_f64 / elapsed.as_secs_f64()
    );
    let state_rows: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM abuse_actor_states WHERE jsonb_array_length(to_jsonb(event_times))=1",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(state_rows >= 1_000);
    pool.close().await;
}
