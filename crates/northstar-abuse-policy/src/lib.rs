#![forbid(unsafe_code)]
#![doc = include_str!("../MIGRATION.md")]

pub mod admission;
pub mod config;
pub mod cooldown;
pub mod escalation;
pub mod model;
pub mod pow;

pub use admission::{
    build_message_dedupe_identity, decay_actor_state_snapshot, evaluate_challenge_proof,
    merge_previous_actor_snapshot, message_admission_capacity_shard,
    message_admission_identity_digest, message_admission_lock_id, message_admission_material,
    record_failure_in_snapshot, record_success_in_snapshot, requirement_from_snapshots,
    resolve_message_admission_identity, ActorStateSnapshot, ChallengeVerificationContext,
};
pub use config::{AbuseConfig, AbuseConfigBuilder, ConfigError};
pub use cooldown::{
    decay_penalty_level_utc, decayed_penalty, max_penalty_decay_horizon,
    minimum_key_rotation_overlap, penalty_cooldown_interval, punish_penalty_and_wait,
    trim_event_timestamps_utc,
};
pub use escalation::{
    build_requirement, calculate_work_factor, hard_wait_seconds, policy,
    prefetched_message_challenge_remains_sufficient, step_from_events, Policy, ABUSE_NOTICE,
};
pub use model::{
    action_accepts_intent, canonical_json_body_digest, canonical_pow_path, AbuseAction,
    ActorDimension, ContentIdentityAuthenticator, ContentIdentityAuthenticators,
    ContentIdentityPurpose, GuardError, IntentError, MessageAdmissionRequest,
    MessageDedupeCandidate, MessageDedupeIdentity, PowChallenge, PowIntent, PowIntentRequest,
    PowIntentView, PowProof, WorkRequirement, ABUSE_STATE_ADVISORY_HASH_SEED,
    ABUSE_STATE_GATE_SHARDS, CHALLENGE_CAPACITY_ADVISORY_LOCK,
    MAX_ACTIVE_MESSAGE_ADMISSIONS_PER_SHARD, MAX_ACTIVE_MESSAGE_ADMISSIONS_PER_USER,
    MAX_ACTIVE_POW_CHALLENGES_GLOBAL, MAX_ACTIVE_POW_CHALLENGES_PER_ACTOR,
    MAX_ACTIVE_POW_CHALLENGES_PER_IP, MAX_CHALLENGE_ISSUES_PER_IP_WINDOW, MAX_PENALTY_LEVEL,
    MESSAGE_ADMISSION_ACCEPTED_TTL, MESSAGE_ADMISSION_CAPACITY_SHARDS,
    MESSAGE_ADMISSION_CLEANUP_BATCH, MESSAGE_ADMISSION_LEASE, MESSAGE_ADMISSION_PENDING_TTL,
    OFFLINE_MESSAGE_ADMISSION_REPLAY_GRACE, POW_BODY_DIGEST_BYTES, POW_INTENT_PATH_MAX_BYTES,
    POW_INTENT_VERSION,
};
pub use pow::{
    actor_key_id, compute_content_identity_authenticator, compute_content_identity_authenticators,
    compute_pow_prefix, compute_pow_prefix_with_commitment, derive_actor_key_secret,
    derive_content_identity_key, opaque_actor_key, opaque_challenge_capacity_key, subject_hash,
    verify_pow_nonce, verify_pow_prefix_binding, PowIntentCommitment, PowVerifyError,
};

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};
    use std::time::Duration;
    use uuid::Uuid;

    fn test_config() -> AbuseConfig {
        AbuseConfig::builder()
            .base_work_factor(100)
            .max_work_factor(10_000)
            .window(Duration::from_secs(60))
            .cooldown_step(Duration::from_secs(60))
            .max_wait(Duration::from_secs(900))
            .message_free_burst(6)
            .approximate_max_device_seconds(8)
            .build()
            .unwrap()
    }

    fn solve(prefix: &str, work_factor: u64) -> String {
        let target = u64::MAX / work_factor.max(1);
        for nonce in 0_u64.. {
            let nonce_str = nonce.to_string();
            let mut hasher = Sha256::new();
            hasher.update(prefix.as_bytes());
            hasher.update(nonce_str.as_bytes());
            let digest = hasher.finalize();
            let value = u64::from_be_bytes(digest[..8].try_into().unwrap());
            if value <= target {
                return nonce_str;
            }
        }
        unreachable!()
    }

    #[test]
    fn full_challenge_issuance_and_deterministic_admission_flow() {
        let config = test_config();
        let secret = b"deterministic-policy-test-secret-at-least-32";
        let actor_secret = derive_actor_key_secret(secret);
        let key_id = actor_key_id(&actor_secret);
        let now = chrono::DateTime::parse_from_rfc3339("2026-09-02T12:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);

        let actors = vec!["user:alice".to_owned(), "ip:198.51.100.1".to_owned()];
        let mut alice_state = ActorStateSnapshot::new("user:alice".to_owned(), now);
        let mut ip_state = ActorStateSnapshot::new("ip:198.51.100.1".to_owned(), now);

        let shared_ip_keys = [ip_state.state_key.clone()].into_iter().collect();

        // 1. Initial requirement: within free burst (step 0, work factor 1)
        let states = vec![alice_state.clone(), ip_state.clone()];
        let req0 = requirement_from_snapshots(
            AbuseAction::Message,
            &states,
            &shared_ip_keys,
            now,
            &config,
        );
        assert_eq!(req0.step, 0);
        assert_eq!(req0.work_factor, 1);
        assert_eq!(req0.hard_wait_seconds, 0);

        // Direct allow without proof
        let direct = evaluate_challenge_proof(
            AbuseAction::Message,
            "message:alice",
            &actors,
            None,
            None,
            &req0,
            None,
            true,
        );
        assert!(direct.is_ok());

        // Simulate 6 free messages
        for _ in 0..6 {
            record_success_in_snapshot(&mut alice_state, now, 0, false);
            record_success_in_snapshot(&mut ip_state, now, 0, true);
        }

        // 2. Escalated requirement: 7th message requires PoW (step 1, work 100)
        let states = vec![alice_state.clone(), ip_state.clone()];
        let req1 = requirement_from_snapshots(
            AbuseAction::Message,
            &states,
            &shared_ip_keys,
            now,
            &config,
        );
        assert_eq!(req1.step, 1);
        assert_eq!(req1.work_factor, 100);

        // Attempt without proof is rejected
        let denied = evaluate_challenge_proof(
            AbuseAction::Message,
            "message:alice",
            &actors,
            None,
            None,
            &req1,
            None,
            true,
        );
        assert!(matches!(denied, Err(GuardError::Required(_))));

        // Create intent and challenge
        let intent = PowIntent::xmpp(
            AbuseAction::Message,
            "/xmpp/message",
            b"<message><body>hello</body></message>",
        )
        .unwrap();

        let challenge_id = Uuid::from_u128(0xa000_0000_0000_4000_8000_0000_0000_0001);
        let expires_at = now + chrono::Duration::seconds(120);
        let server_nonce = "sample-server-nonce-123";

        let prefix = compute_pow_prefix(
            &actor_secret,
            POW_INTENT_VERSION,
            challenge_id,
            AbuseAction::Message,
            &key_id,
            "message:alice",
            &actors,
            req1.work_factor,
            now,
            expires_at,
            server_nonce,
            Some(&intent),
        );

        let sub_hash = subject_hash(AbuseAction::Message, "message:alice", &actor_secret);
        let ctx = ChallengeVerificationContext {
            protocol_version: POW_INTENT_VERSION,
            action: AbuseAction::Message,
            key_id: key_id.clone(),
            prefix: prefix.clone(),
            work_factor: req1.work_factor,
            issued_at: now,
            expires_at,
            not_before: now,
            server_nonce: server_nonce.to_owned(),
            subject_hash: sub_hash,
            actor_secret: &actor_secret,
            intent: Some(intent.clone()),
            requirement: req1.clone(),
            sequences_match: true,
            now,
        };

        // Solve challenge
        let solved_nonce = solve(&prefix, req1.work_factor);
        let proof = PowProof {
            challenge_id,
            nonce: solved_nonce,
        };

        // Evaluate valid proof
        let evaluated = evaluate_challenge_proof(
            AbuseAction::Message,
            "message:alice",
            &actors,
            Some(&proof),
            Some(&intent),
            &req1,
            Some(&ctx),
            true,
        );
        assert!(evaluated.is_ok());

        // Mismatched intent rejected
        let mismatched_intent = PowIntent::xmpp(
            AbuseAction::Message,
            "/xmpp/message",
            b"<message><body>different content</body></message>",
        )
        .unwrap();
        let mismatch = evaluate_challenge_proof(
            AbuseAction::Message,
            "message:alice",
            &actors,
            Some(&proof),
            Some(&mismatched_intent),
            &req1,
            Some(&ctx),
            true,
        );
        assert!(matches!(mismatch, Err(GuardError::Invalid(..))));
    }

    #[test]
    fn shared_nat_peers_do_not_exhaust_each_other() {
        let config = test_config();
        let now = chrono::DateTime::parse_from_rfc3339("2026-09-02T12:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let ip_key = "ip:203.0.113.50".to_owned();

        let mut user_a = ActorStateSnapshot::new("user:alice".to_owned(), now);
        let user_b = ActorStateSnapshot::new("user:bob".to_owned(), now);
        let mut ip_state = ActorStateSnapshot::new(ip_key.clone(), now);

        let shared_ip_keys = [ip_key].into_iter().collect();

        // Alice sends 50 messages
        for _ in 0..50 {
            record_success_in_snapshot(&mut user_a, now, 0, false);
            record_success_in_snapshot(&mut ip_state, now, 0, true);
        }

        // Alice has escalated work
        let alice_states = vec![user_a.clone(), ip_state.clone()];
        let alice_req = requirement_from_snapshots(
            AbuseAction::Message,
            &alice_states,
            &shared_ip_keys,
            now,
            &config,
        );
        assert!(alice_req.step >= 44);

        // Bob behind the same NAT has step 0 because IP count (50 / 20 = 2) is below free burst (6)
        let bob_states = vec![user_b.clone(), ip_state.clone()];
        let bob_req = requirement_from_snapshots(
            AbuseAction::Message,
            &bob_states,
            &shared_ip_keys,
            now,
            &config,
        );
        assert_eq!(bob_req.step, 0);
        assert_eq!(bob_req.work_factor, 1);
    }

    #[test]
    fn property_monotonic_escalation_under_increasing_events() {
        let config = test_config();
        for action in [
            AbuseAction::Registration,
            AbuseAction::Message,
            AbuseAction::Report,
            AbuseAction::Appeal,
            AbuseAction::Login,
            AbuseAction::PasswordChange,
        ] {
            let p = policy(action, config.base_work_factor, config.message_free_burst);
            let mut prev_work = 0;
            let mut prev_delay = 0;

            for events in 0..500 {
                let req = build_requirement(action, p, events, 0, 0, &config);
                assert!(
                    req.work_factor >= prev_work,
                    "work factor decreased for action {action:?} at event {events}: {prev_work} -> {}",
                    req.work_factor
                );
                assert!(
                    req.hard_wait_seconds >= prev_delay,
                    "delay decreased for action {action:?} at event {events}: {prev_delay} -> {}",
                    req.hard_wait_seconds
                );
                assert!(req.work_factor <= config.max_work_factor);
                assert!(req.hard_wait_seconds <= config.max_wait.as_secs());

                prev_work = req.work_factor;
                prev_delay = req.hard_wait_seconds;
            }
        }
    }

    #[test]
    fn property_monotonic_penalty_decay_over_time() {
        let step = Duration::from_secs(30);
        for initial_level in 0..=MAX_PENALTY_LEVEL {
            let mut prev_level = initial_level;
            let mut prev_consumed = Duration::ZERO;

            for secs in (0..=3_000).step_by(10) {
                let elapsed = Duration::from_secs(secs);
                let (level, consumed) = decayed_penalty(initial_level, elapsed, step);

                assert!(
                    level <= prev_level,
                    "penalty level increased from {prev_level} to {level} at elapsed {secs}s"
                );
                assert!(
                    consumed >= prev_consumed,
                    "consumed duration decreased from {prev_consumed:?} to {consumed:?} at elapsed {secs}s"
                );

                prev_level = level;
                prev_consumed = consumed;
            }

            // After complete horizon (cooldown_step * 2046 = 61380s), it must reach level 0
            let horizon = max_penalty_decay_horizon(step);
            let (final_level, final_consumed) = decayed_penalty(initial_level, horizon, step);
            assert_eq!(final_level, 0);
            assert!(final_consumed <= horizon);
        }
    }

    #[test]
    fn property_replay_and_expiry_rejections() {
        let config = test_config();
        let actors = vec!["user:carol".to_owned()];
        let req = build_requirement(
            AbuseAction::Report,
            policy(
                AbuseAction::Report,
                config.base_work_factor,
                config.message_free_burst,
            ),
            0,
            0,
            0,
            &config,
        );

        let now = chrono::DateTime::parse_from_rfc3339("2026-09-02T12:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let proof = PowProof {
            challenge_id: Uuid::from_u128(0xb000_0000_0000_4000_8000_0000_0000_0002),
            nonce: "12345".to_owned(),
        };

        // 1. Missing challenge context (already consumed / replayed)
        let missing = evaluate_challenge_proof(
            AbuseAction::Report,
            "report:carol",
            &actors,
            Some(&proof),
            None,
            &req,
            None,
            true,
        );
        assert!(matches!(
            missing,
            Err(GuardError::Invalid(
                "proof-of-work challenge is missing or already used",
                _
            ))
        ));

        // 2. Expired challenge
        let secret = b"property-test-secret-at-least-32-bytes";
        let actor_secret = derive_actor_key_secret(secret);
        let key_id = actor_key_id(&actor_secret);
        let sub_hash = subject_hash(AbuseAction::Report, "report:carol", &actor_secret);

        let expired_ctx = ChallengeVerificationContext {
            protocol_version: 1,
            action: AbuseAction::Report,
            key_id: key_id.clone(),
            prefix: "prefix".to_owned(),
            work_factor: 100,
            issued_at: now - chrono::Duration::seconds(200),
            expires_at: now - chrono::Duration::seconds(10), // Expired 10s ago
            not_before: now - chrono::Duration::seconds(200),
            server_nonce: "nonce".to_owned(),
            subject_hash: sub_hash,
            actor_secret: &actor_secret,
            intent: None,
            requirement: req.clone(),
            sequences_match: true,
            now,
        };

        let expired = evaluate_challenge_proof(
            AbuseAction::Report,
            "report:carol",
            &actors,
            Some(&proof),
            None,
            &req,
            Some(&expired_ctx),
            true,
        );
        assert!(matches!(
            expired,
            Err(GuardError::Invalid("proof-of-work challenge expired", _))
        ));

        // 3. Hard cooldown still active (now < not_before)
        let cooldown_active_ctx = ChallengeVerificationContext {
            not_before: now + chrono::Duration::seconds(30), // 30s remaining
            expires_at: now + chrono::Duration::seconds(120),
            ..expired_ctx
        };

        let active_cd = evaluate_challenge_proof(
            AbuseAction::Report,
            "report:carol",
            &actors,
            Some(&proof),
            None,
            &req,
            Some(&cooldown_active_ctx),
            true,
        );
        assert!(matches!(
            active_cd,
            Err(GuardError::Invalid("hard cooldown has not finished", _))
        ));
    }

    #[test]
    fn property_deterministic_injected_time() {
        let config = test_config();
        let t0 = chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap();
        // For penalty level 2 with cooldown_step 60s, level 2 requires 60 * 4 = 240s to drop to level 1.
        let t1 = chrono::DateTime::from_timestamp(1_700_000_250, 0).unwrap(); // +250s

        let mut s1 = ActorStateSnapshot::new("message:user:alice".to_owned(), t0);
        s1.events.push(t0);
        s1.penalty_level = 2;
        s1.last_activity = t0;

        let mut s2 = s1.clone();

        decay_actor_state_snapshot(&mut s1, t1, &config);
        decay_actor_state_snapshot(&mut s2, t1, &config);

        assert_eq!(
            s1, s2,
            "pure state decay with identical injected time must be 100% deterministic"
        );
        assert_eq!(
            s1.penalty_level, 1,
            "penalty level 2 should decay to level 1 after 250s (> 240s)"
        );
        assert_eq!(
            s1.events.len(),
            0,
            "events older than 60s window must be trimmed"
        );
    }
}
