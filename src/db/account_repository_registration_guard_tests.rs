use base64::Engine as _;
use northstar_abuse_policy::{AbuseAction, AbuseConfig, PowChallenge, PowIntent, PowProof};
use northstar_auth_application::account::*;
use northstar_operations_core::api_mutations::{
    api_request_fingerprint, ApiPrincipalKind, IdempotencyRequest,
};
use northstar_workflows::roster::RootAccountRepository;
use ring::rand::{SecureRandom, SystemRandom};
use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use uuid::Uuid;

fn test_key() -> String {
    let mut key = [0_u8; 32];
    SystemRandom::new().fill(&mut key).unwrap();
    base64::engine::general_purpose::STANDARD.encode(key)
}

fn solve_pow(challenge: &PowChallenge) -> PowProof {
    let target = u64::MAX / challenge.requirement.work_factor.max(1);
    for nonce in 0_u64.. {
        let nonce = nonce.to_string();
        let mut hasher = Sha256::new();
        hasher.update(challenge.prefix.as_bytes());
        hasher.update(nonce.as_bytes());
        let digest = hasher.finalize();
        if u64::from_be_bytes(digest[..8].try_into().unwrap()) <= target {
            return PowProof {
                challenge_id: challenge.challenge_id,
                nonce,
            };
        }
    }
    unreachable!()
}

async fn register_http_once(
    service: &AccountService<RootAccountRepository>,
    availability: &HttpRegistrationAvailability,
    username: &str,
    key: &str,
    request_id: Uuid,
    scope: &str,
    proof: Option<&PowProof>,
) -> HttpRegistrationOutcome {
    let password = "correct horse battery staple";
    let body = serde_json::json!({
        "username": username,
        "password": password,
        "invitation_token": null,
    });
    let raw_body = serde_json::to_vec(&serde_json::json!({
        "username": username,
        "password": password,
        "invitation_token": null,
        "pow": proof.map(|proof| serde_json::json!({
            "challenge_id": proof.challenge_id,
            "nonce": proof.nonce,
        })),
    }))
    .unwrap();
    let intent = PowIntent::http_json(AbuseAction::Registration, "/api/v1/register", &body);
    let actors = vec![scope.to_owned()];
    service
        .register_http(HttpRegistrationRequest {
            idempotency: IdempotencyRequest {
                request_id,
                actor_id: None,
                principal_scope: scope.as_bytes(),
                capacity_scope: scope.as_bytes(),
                target_scope: b"",
                principal_kind: ApiPrincipalKind::Anonymous,
                method: "POST",
                route: "/api/v1/register",
                idempotency_key: key,
                request_fingerprint: api_request_fingerprint("application/json", &raw_body),
                ttl_seconds: 3_600,
                lease_seconds: 30,
            },
            username,
            password,
            invitation_token: None,
            proof,
            intent: &intent,
            subject: scope,
            actors: &actors,
            availability: availability.clone(),
        })
        .await
        .unwrap()
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL pointing at an isolated PostgreSQL database"]
async fn http_registration_replays_exact_created_and_rejected_responses_after_policy_closure() {
    let url = std::env::var("TEST_DATABASE_URL").expect("set TEST_DATABASE_URL");
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(4)
        .connect(&url)
        .await
        .unwrap();
    crate::db::migrate(&pool).await.unwrap();
    northstar_operations_postgres::admin_commands::initialize_admin_runtime_settings(
        &pool, false, false, false,
    )
    .await
    .unwrap();
    let guard = Arc::new(northstar_workflows::abuse_effects::persistent_guard(
        AbuseConfig {
            base_work_factor: 2,
            max_work_factor: 64,
            window: Duration::from_secs(60),
            cooldown_step: Duration::from_secs(60),
            max_wait: Duration::from_secs(900),
            message_free_burst: 6,
            approximate_max_device_seconds: 8,
        },
        pool.clone(),
        Some(test_key().as_bytes()),
        None,
    ));
    let api_control = Arc::new(
        northstar_operations_postgres::api_control::ApiControlKeyring::new(
            test_key().as_bytes(),
            None,
        )
        .unwrap(),
    );
    let service = AccountService::new(
        RootAccountRepository::new(
            pool.clone(),
            "example.test".into(),
            guard,
            northstar_workflows::roster::WorkflowRosterEffects,
        )
        .with_api_control(api_control),
        false,
        1_000_000,
        northstar_auth_core::MIN_SCRAM_ITERATIONS,
        false,
    );
    let closed = Arc::new(AtomicBool::new(false));
    let availability = HttpRegistrationAvailability::new(Arc::clone(&closed), false, false);
    let suffix = Uuid::new_v4().simple().to_string();
    let username = format!("registration-{suffix}");
    let created_key = format!("created-{suffix}");
    let created_id = Uuid::new_v4();
    let created_scope = format!("registration:192.0.2.{}", 40);
    let created = register_http_once(
        &service,
        &availability,
        &username,
        &created_key,
        created_id,
        &created_scope,
        None,
    )
    .await;
    let HttpRegistrationOutcome::Created(created_body) = created else {
        panic!("expected newly created account");
    };
    assert_eq!(
        created_body,
        serde_json::to_vec(&serde_json::json!({"jid": format!("{username}@example.test")}))
            .unwrap()
    );
    closed.store(true, Ordering::Release);
    let replayed = register_http_once(
        &service,
        &availability,
        &username,
        &created_key,
        created_id,
        &created_scope,
        None,
    )
    .await;
    let HttpRegistrationOutcome::Replay(replayed) = replayed else {
        panic!("created response must replay before closure check");
    };
    assert_eq!(replayed.request_id, created_id);
    assert_eq!(replayed.status, 201);
    assert_eq!(
        replayed.headers,
        northstar_operations_core::api_mutations::json_replay_headers()
    );
    assert_eq!(replayed.body, created_body);

    closed.store(false, Ordering::Release);
    let rejected_key = format!("rejected-{suffix}");
    let rejected_id = Uuid::new_v4();
    let rejected_scope = "registration:192.0.2.41";
    let rejected = register_http_once(
        &service,
        &availability,
        &username,
        &rejected_key,
        rejected_id,
        rejected_scope,
        None,
    )
    .await;
    let HttpRegistrationOutcome::Rejected(rejected_body) = rejected else {
        panic!("expected deterministic username rejection");
    };
    assert_eq!(
        rejected_body,
        serde_json::to_vec(&serde_json::json!({
            "error": {
                "code": "bad_request",
                "message": "registration request could not be accepted"
            }
        }))
        .unwrap()
    );
    closed.store(true, Ordering::Release);
    let replayed = register_http_once(
        &service,
        &availability,
        &username,
        &rejected_key,
        rejected_id,
        rejected_scope,
        None,
    )
    .await;
    let HttpRegistrationOutcome::Replay(replayed) = replayed else {
        panic!("rejection must replay before closure check");
    };
    assert_eq!(replayed.request_id, rejected_id);
    assert_eq!(replayed.status, 400);
    assert_eq!(
        replayed.headers,
        northstar_operations_core::api_mutations::json_replay_headers()
    );
    assert_eq!(replayed.body, rejected_body);
    pool.close().await;
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL pointing at an isolated PostgreSQL database"]
async fn http_registration_overload_preserves_committed_proof_marker_for_exact_retry() {
    let url = std::env::var("TEST_DATABASE_URL").expect("set TEST_DATABASE_URL");
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(4)
        .connect(&url)
        .await
        .unwrap();
    crate::db::migrate(&pool).await.unwrap();
    northstar_operations_postgres::admin_commands::initialize_admin_runtime_settings(
        &pool, false, false, false,
    )
    .await
    .unwrap();
    let guard = Arc::new(northstar_workflows::abuse_effects::persistent_guard(
        AbuseConfig {
            base_work_factor: 2,
            max_work_factor: 64,
            window: Duration::from_secs(60),
            cooldown_step: Duration::from_secs(60),
            max_wait: Duration::from_secs(900),
            message_free_burst: 6,
            approximate_max_device_seconds: 8,
        },
        pool.clone(),
        Some(test_key().as_bytes()),
        None,
    ));
    let api_control = Arc::new(
        northstar_operations_postgres::api_control::ApiControlKeyring::new(
            test_key().as_bytes(),
            None,
        )
        .unwrap(),
    );
    let service = AccountService::new(
        RootAccountRepository::new(
            pool.clone(),
            "example.test".into(),
            Arc::clone(&guard),
            northstar_workflows::roster::WorkflowRosterEffects,
        )
        .with_api_control(api_control),
        false,
        1_000_000,
        northstar_auth_core::MIN_SCRAM_ITERATIONS,
        false,
    );
    let availability =
        HttpRegistrationAvailability::new(Arc::new(AtomicBool::new(false)), false, false);
    let suffix = Uuid::new_v4().simple().to_string();
    let username = format!("retry-{suffix}");
    let key = format!("retry-{suffix}");
    let request_id = Uuid::new_v4();
    let scope = "registration:192.0.2.42";
    let actors = vec![scope.to_owned()];
    let body = serde_json::json!({
        "username": username,
        "password": "correct horse battery staple",
        "invitation_token": null,
    });
    let intent = PowIntent::http_json(AbuseAction::Registration, "/api/v1/register", &body);
    assert!(guard
        .verify_or_allow_v2(AbuseAction::Registration, scope, &actors, None, &intent)
        .await
        .unwrap()
        .is_ok());
    let challenge = guard
        .issue_v2(AbuseAction::Registration, scope, &actors, &intent)
        .await
        .unwrap();
    let proof = solve_pow(&challenge);
    let mut admissions = Vec::new();
    while let Ok(admission) = northstar_security::password_work::admit() {
        admissions.push(admission);
    }
    assert!(!admissions.is_empty());
    let overloaded = register_http_once(
        &service,
        &availability,
        &username,
        &key,
        request_id,
        scope,
        Some(&proof),
    )
    .await;
    assert!(matches!(
        overloaded,
        HttpRegistrationOutcome::PasswordWorkOverloaded
    ));
    let marker: bool = sqlx::query_scalar(
        "SELECT guard_verified_at IS NOT NULL FROM api_idempotency_records WHERE request_id=$1",
    )
    .bind(request_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(
        marker,
        "the pre-hash guard marker must survive worker overload"
    );
    let proof_retained: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM abuse_pow_challenges WHERE id=$1)")
            .bind(proof.challenge_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(
        !proof_retained,
        "proof consumption must commit with the marker"
    );
    drop(admissions);
    let retried = register_http_once(
        &service,
        &availability,
        &username,
        &key,
        request_id,
        scope,
        Some(&proof),
    )
    .await;
    assert!(matches!(retried, HttpRegistrationOutcome::Created(_)));
    pool.close().await;
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL pointing at an isolated PostgreSQL database"]
async fn registration_guard_consumes_v2_proof_with_marker_and_fences_old_worker() {
    let url = std::env::var("TEST_DATABASE_URL").expect("set TEST_DATABASE_URL");
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(4)
        .connect(&url)
        .await
        .unwrap();
    crate::db::migrate(&pool).await.unwrap();
    northstar_operations_postgres::admin_commands::initialize_admin_runtime_settings(
        &pool, false, false, false,
    )
    .await
    .unwrap();
    let abuse_key = test_key();
    let api_key = test_key();
    let guard = Arc::new(northstar_workflows::abuse_effects::persistent_guard(
        AbuseConfig {
            base_work_factor: 2,
            max_work_factor: 64,
            window: Duration::from_secs(60),
            cooldown_step: Duration::from_secs(60),
            max_wait: Duration::from_secs(900),
            message_free_burst: 6,
            approximate_max_device_seconds: 8,
        },
        pool.clone(),
        Some(abuse_key.as_bytes()),
        None,
    ));
    let repository = RootAccountRepository::new(
        pool.clone(),
        "example.test".into(),
        Arc::clone(&guard),
        northstar_workflows::roster::WorkflowRosterEffects,
    );
    let keys = northstar_operations_postgres::api_control::ApiControlKeyring::new(
        api_key.as_bytes(),
        None,
    )
    .unwrap();
    let suffix = Uuid::new_v4().simple().to_string();
    let key = format!("registration-guard-{suffix}");
    let scope = "registration:192.0.2.40";
    let actors = vec!["ip:192.0.2.40".to_owned()];
    let body = serde_json::json!({"username":"alice","password":"test password"});
    let raw_body = serde_json::to_vec(&body).unwrap();
    let intent = PowIntent::http_json(AbuseAction::Registration, "/api/v1/register", &body);
    // Spend the free burst, then issue the exact body-bound v2 proof that
    // the guarded idempotent request must consume.
    assert!(guard
        .verify_or_allow_v2(AbuseAction::Registration, scope, &actors, None, &intent)
        .await
        .unwrap()
        .is_ok());
    let challenge = guard
        .issue_v2(AbuseAction::Registration, scope, &actors, &intent)
        .await
        .unwrap();
    let proof = solve_pow(&challenge);
    let request = IdempotencyRequest {
        request_id: Uuid::new_v4(),
        actor_id: None,
        principal_scope: scope.as_bytes(),
        capacity_scope: actors[0].as_bytes(),
        target_scope: b"",
        principal_kind: ApiPrincipalKind::Anonymous,
        method: "POST",
        route: "/api/v1/register",
        idempotency_key: &key,
        request_fingerprint: api_request_fingerprint("application/json", &raw_body),
        ttl_seconds: 3_600,
        lease_seconds: 30,
    };
    let mut reserve = pool.begin().await.unwrap();
    let lease = match northstar_operations_postgres::api_control::acquire_idempotency_in_tx(
        &keys,
        &mut reserve,
        &request,
    )
    .await
    .unwrap()
    {
        northstar_operations_postgres::api_control::IdempotencyAcquire::Acquired(lease) => lease,
        other => panic!("expected acquired registration lease, got {other:?}"),
    };
    reserve.commit().await.unwrap();

    let fence = RegistrationGuardLease {
        record_id: lease.record_id,
        lease_token: lease.lease_token(),
    };
    let outcome = repository
        .verify_registration_guard(RegistrationGuardRequest {
            lease: fence,
            lease_seconds: 30,
            subject: scope,
            actors: &actors,
            proof: Some(&proof),
            intent: &intent,
        })
        .await
        .unwrap();
    assert!(matches!(outcome, RegistrationGuardOutcome::Verified));
    let marker: bool = sqlx::query_scalar(
        "SELECT guard_verified_at IS NOT NULL FROM api_idempotency_records WHERE id=$1",
    )
    .bind(lease.record_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(marker);
    let proof_retained: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM abuse_pow_challenges WHERE id=$1)")
            .bind(proof.challenge_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(
        !proof_retained,
        "proof must be consumed with the guard marker"
    );

    assert!(
        northstar_operations_postgres::api_control::yield_idempotency_lease(&pool, &lease)
            .await
            .unwrap()
    );
    let mut takeover = pool.begin().await.unwrap();
    let replacement = match northstar_operations_postgres::api_control::acquire_idempotency_in_tx(
        &keys,
        &mut takeover,
        &request,
    )
    .await
    .unwrap()
    {
        northstar_operations_postgres::api_control::IdempotencyAcquire::Acquired(lease) => lease,
        other => panic!("expected guard-verified takeover, got {other:?}"),
    };
    assert!(replacement.guard_verified);
    takeover.commit().await.unwrap();

    // A fresh valid proof makes the stale-owner check observable: the
    // old worker must neither consume it nor advance actor state.
    let fresh_challenge = guard
        .issue_v2(AbuseAction::Registration, scope, &actors, &intent)
        .await
        .unwrap();
    let fresh_proof = solve_pow(&fresh_challenge);
    let events_before: i64 = sqlx::query_scalar(
        "SELECT COALESCE(SUM(cardinality(event_times)),0)::BIGINT FROM abuse_actor_states",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(matches!(
        repository
            .verify_registration_guard(RegistrationGuardRequest {
                lease: fence,
                lease_seconds: 30,
                subject: scope,
                actors: &actors,
                proof: Some(&fresh_proof),
                intent: &intent,
            })
            .await
            .unwrap(),
        RegistrationGuardOutcome::LeaseLost
    ));
    let fresh_retained: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM abuse_pow_challenges WHERE id=$1)")
            .bind(fresh_proof.challenge_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(
        fresh_retained,
        "stale worker must not consume a fresh proof"
    );
    let events_after: i64 = sqlx::query_scalar(
        "SELECT COALESCE(SUM(cardinality(event_times)),0)::BIGINT FROM abuse_actor_states",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(events_after, events_before);
    let (active_token, active_marker): (Uuid, bool) = sqlx::query_as(
        "SELECT lease_token,guard_verified_at IS NOT NULL FROM api_idempotency_records WHERE id=$1",
    )
    .bind(replacement.record_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(active_token, replacement.lease_token());
    assert!(active_marker);

    // Reusing the consumed proof for another request must commit a
    // denial, remove only that request's lease, and leave the replacement
    // lease available to its rightful worker.
    let denied_key = format!("registration-guard-denied-{suffix}");
    let denied_request = IdempotencyRequest {
        request_id: Uuid::new_v4(),
        actor_id: None,
        principal_scope: scope.as_bytes(),
        capacity_scope: actors[0].as_bytes(),
        target_scope: b"",
        principal_kind: ApiPrincipalKind::Anonymous,
        method: "POST",
        route: "/api/v1/register",
        idempotency_key: &denied_key,
        request_fingerprint: api_request_fingerprint("application/json", &raw_body),
        ttl_seconds: 3_600,
        lease_seconds: 30,
    };
    let mut reserve_denied = pool.begin().await.unwrap();
    let denied_lease = match northstar_operations_postgres::api_control::acquire_idempotency_in_tx(
        &keys,
        &mut reserve_denied,
        &denied_request,
    )
    .await
    .unwrap()
    {
        northstar_operations_postgres::api_control::IdempotencyAcquire::Acquired(lease) => lease,
        other => panic!("expected second registration lease, got {other:?}"),
    };
    reserve_denied.commit().await.unwrap();
    assert!(matches!(
        repository
            .verify_registration_guard(RegistrationGuardRequest {
                lease: RegistrationGuardLease {
                    record_id: denied_lease.record_id,
                    lease_token: denied_lease.lease_token(),
                },
                lease_seconds: 30,
                subject: scope,
                actors: &actors,
                proof: Some(&proof),
                intent: &intent,
            })
            .await
            .unwrap(),
        RegistrationGuardOutcome::Denied(northstar_abuse_policy::GuardError::Invalid(..))
    ));
    let retained: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM api_idempotency_records WHERE id=$1")
            .bind(denied_lease.record_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(retained, 0);
    let (surviving_token, surviving_marker): (Uuid, bool) = sqlx::query_as(
        "SELECT lease_token,guard_verified_at IS NOT NULL FROM api_idempotency_records WHERE id=$1",
    )
    .bind(replacement.record_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(surviving_token, replacement.lease_token());
    assert!(surviving_marker);
    pool.close().await;
}
