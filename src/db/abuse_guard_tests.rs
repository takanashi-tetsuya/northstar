//! The guard over its PostgreSQL adapter, and the tests that need root's other tables.
use crate::db::abuse_effects::persistent_guard;
use crate::services::message_admission::{begin_command, operation};
use northstar_abuse_application::guard::test_support::{
    actor_state_keys, message_admission_identity, message_admission_identity_digest,
    message_admission_material, opaque_actor_key,
};
use northstar_abuse_application::guard::{
    acceptance_fence, AbuseGuard, ChallengeCapacityExceeded, MessageAdmissionAcceptance,
    MessageAdmissionStart, TransactionalGuardOutcome,
};
use northstar_abuse_policy::admission_execution::Command;
use northstar_abuse_policy::admission_transaction::FinalizeDecision;
use northstar_abuse_policy::*;
use northstar_abuse_postgres::message_admission::accept_observed;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use std::{
    sync::Arc,
    time::{Duration, Instant},
};
use uuid::Uuid;

fn test_config() -> AbuseConfig {
    AbuseConfig {
        base_work_factor: 100,
        max_work_factor: 10_000,
        window: Duration::from_secs(60),
        cooldown_step: Duration::from_secs(60),
        max_wait: Duration::from_secs(900),
        message_free_burst: 6,
        approximate_max_device_seconds: 8,
    }
}

/// One acceptance outside the message workflow, as its own operation.
async fn accept_message_admission(
    pool: &PgPool,
    acceptance: &MessageAdmissionAcceptance<'_>,
) -> anyhow::Result<()> {
    let (_, witness) = operation(Command::Finalize(acceptance_fence(acceptance)));
    match accept_observed(pool, acceptance, &witness).await? {
        FinalizeDecision::AlreadyAccepted | FinalizeDecision::AcceptPending => Ok(()),
        FinalizeDecision::Missing => {
            anyhow::bail!("message admission disappeared before acceptance")
        }
        FinalizeDecision::PayloadConflict => {
            anyhow::bail!("message admission payload changed before acceptance")
        }
        FinalizeDecision::LostFence => {
            anyhow::bail!("message admission fencing lease was lost before acceptance")
        }
    }
}

/// One admission attempt outside the message workflow, as its own operation.
trait BeginMessageAdmission {
    async fn begin_message_admission(
        &self,
        request: &MessageAdmissionRequest<'_>,
    ) -> anyhow::Result<MessageAdmissionStart>;
}

impl BeginMessageAdmission for AbuseGuard {
    async fn begin_message_admission(
        &self,
        request: &MessageAdmissionRequest<'_>,
    ) -> anyhow::Result<MessageAdmissionStart> {
        let (_, witness) = operation(begin_command(request)?);
        self.begin_message_admission_observed(request, &witness)
            .await
    }
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

#[tokio::test]
async fn closed_persistent_backend_is_never_treated_as_an_allow() {
    let pool = sqlx::postgres::PgPoolOptions::new()
        .connect_lazy("postgres://closed:closed@127.0.0.1:9/closed")
        .unwrap();
    pool.close().await;
    let guard = persistent_guard(
        test_config(),
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

#[test]
fn offline_replay_grace_matches_the_database_trigger() {
    assert_eq!(
        OFFLINE_MESSAGE_ADMISSION_REPLAY_GRACE,
        Duration::from_secs(30 * 24 * 60 * 60)
    );
    assert!(
        include_str!("../../migrations/0079_offline_message_dedupe.sql")
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
    let guard = persistent_guard(
        test_config(),
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
    assert_eq!(stored.3, *expected.body_sha256());
    assert!(stored.4.len() >= 16);

    tokio::time::sleep(
        Duration::from_secs(mismatch.requirement.hard_wait_seconds) + Duration::from_millis(50),
    )
    .await;
    let mut mismatch_tx = pool.begin().await.unwrap();
    let mismatch_result = northstar_abuse_postgres::transaction::verify_in_tx(
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
        northstar_abuse_postgres::transaction::verify_in_tx(
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
        northstar_abuse_postgres::transaction::verify_in_tx(
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
        test_config(),
        Arc::new(
            northstar_abuse_postgres::persistence::PostgresAbusePersistence::new(
                pool.clone(),
                crate::db::abuse_effects::RootAbuseEffects,
            ),
        ),
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
    let guard = persistent_guard(
        test_config(),
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
    let guard = std::sync::Arc::new(persistent_guard(config, pool.clone(), Some(secret), None));
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

    let restarted = persistent_guard(config, pool.clone(), Some(secret), None);
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
        Arc::new(
            northstar_abuse_postgres::persistence::PostgresAbusePersistence::new(
                pool.clone(),
                crate::db::abuse_effects::RootAbuseEffects,
            ),
        ),
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
    assert_eq!(rotated_challenge_key_id, restarted.actor_key_id());
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
    let after_overlap = persistent_guard(config, pool.clone(), Some(new_secret), None)
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
    let old_issue_guard = persistent_guard(config, pool.clone(), Some(secret), None);
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
        Arc::new(
            northstar_abuse_postgres::persistence::PostgresAbusePersistence::new(
                pool.clone(),
                crate::db::abuse_effects::RootAbuseEffects,
            ),
        ),
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
            old_issue_guard.actor_key_secret(),
        )
    );
    let new_issue_key = format!(
        "challenge:{}",
        opaque_actor_key(
            AbuseAction::Report,
            &issue_actor,
            rotated_issue_guard.actor_key_secret(),
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

    for key in actor_state_keys(AbuseAction::Report, &actors, restarted.actor_key_secret()) {
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
    let guard = std::sync::Arc::new(persistent_guard(config, pool.clone(), Some(secret), None));
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

    let restarted = persistent_guard(config, pool.clone(), Some(secret), None);
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
    let user = northstar_auth_postgres::users::create_user(
        &pool,
        &username,
        "message-admission-test-password-42",
        false,
        true,
        northstar_auth_core::MIN_SCRAM_ITERATIONS,
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
    let guard = std::sync::Arc::new(persistent_guard(
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
    let actor_keys = actor_state_keys(AbuseAction::Message, &actors, guard.actor_key_secret());
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
    let restarted = persistent_guard(config, pool.clone(), Some(old_secret), None);
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
    assert!(accept_message_admission(&pool, &first_lease.acceptance(),)
        .await
        .is_err());
    accept_message_admission(&pool, &takeover_lease.acceptance())
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
        restarted.actor_key_secret(),
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
        Arc::new(
            northstar_abuse_postgres::persistence::PostgresAbusePersistence::new(
                pool.clone(),
                crate::db::abuse_effects::RootAbuseEffects,
            ),
        ),
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
        restarted.actor_key_id()
    );
    assert_eq!(
        rotation_lease.offline_dedupe.candidates[1].key_id,
        rotated.actor_key_id()
    );
    let stored_admission_key_id: String =
        sqlx::query_scalar("SELECT key_id FROM abuse_message_admissions WHERE admission_key=$1")
            .bind(rotation_lease.admission_key())
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(stored_admission_key_id, restarted.actor_key_id());

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
    assert_eq!(stored_offline_key_id, restarted.actor_key_id());

    let (identity_kind, identity_value) = message_admission_identity(&rotation_request).unwrap();
    let (_, old_payload_mac) = message_admission_material(
        &rotation_request,
        restarted.actor_key_secret(),
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
            key_id: restarted.actor_key_id().to_owned(),
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
    accept_message_admission(&pool, &rotation_lease.acceptance())
        .await
        .unwrap();
    assert!(matches!(
        restarted
            .begin_message_admission(&rotation_request)
            .await
            .unwrap(),
        MessageAdmissionStart::ReplayAccepted
    ));

    let over_rotated = persistent_guard(
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
        over_rotated.actor_key_secret(),
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
        over_rotated.actor_key_secret(),
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
    let user = northstar_auth_postgres::users::create_user(
        &pool,
        &username,
        "message-capacity-test-password-42",
        false,
        true,
        northstar_auth_core::MIN_SCRAM_ITERATIONS,
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
    let guard = persistent_guard(config, pool.clone(), Some(secret), None);
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
            guard.actor_key_secret(),
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
    let guard = std::sync::Arc::new(persistent_guard(
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
