use super::*;

#[tokio::test]
#[ignore = "requires the ordinary-role random schema and TEST_DATABASE_URL"]
async fn registration_commits_one_reservation_before_guard_and_rejects_before_password_preparation()
{
    let pool = crate::support::operation_mutation_pool().await;
    northstar_operations_postgres::admin_commands::initialize_admin_runtime_settings(
        &pool, false, false, false,
    )
    .await
    .unwrap();
    let guard = Arc::new(northstar_workflows::abuse_effects::persistent_guard(
        AbuseConfig {
            base_work_factor: 1,
            max_work_factor: 16,
            window: Duration::from_secs(60),
            cooldown_step: Duration::from_secs(60),
            max_wait: Duration::from_secs(8),
            message_free_burst: 6,
            approximate_max_device_seconds: 8,
        },
        pool.clone(),
        Some(b"registration-conformance-secret-32-bytes"),
        None,
    ));
    let actors = vec!["registration:conformance".to_owned()];
    let unrelated_intent = PowIntent::http_json(
        AbuseAction::Registration,
        "/api/v1/register",
        &serde_json::json!({"username":"another-body"}),
    );
    let challenge = guard
        .issue_v2(
            AbuseAction::Registration,
            &actors[0],
            &actors,
            &unrelated_intent,
        )
        .await
        .unwrap();
    let proof = solve_pow(&challenge);
    let service = AccountService::new(
        WorkflowAccountRepository::new(
            pool.clone(),
            "example.test".into(),
            guard,
            northstar_workflows::roster::WorkflowRosterEffects,
        )
        .with_api_control(Arc::new(
            northstar_operations_postgres::api_control::ApiControlKeyring::new(
                b"registration-api-conformance-secret-32-bytes",
                None,
            )
            .unwrap(),
        )),
        false,
        1_000_000,
        northstar_auth_core::MIN_SCRAM_ITERATIONS,
        false,
    );
    let mut blocker = pool.begin().await.unwrap();
    sqlx::query("SELECT id FROM abuse_pow_challenges WHERE id=$1 FOR UPDATE")
        .bind(proof.challenge_id)
        .fetch_one(&mut *blocker)
        .await
        .unwrap();
    let blocker_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *blocker)
        .await
        .unwrap();
    let worker_service = service.clone();
    let worker_proof = proof.clone();
    let request_id = Uuid::from_u128(0x573_3701);
    let worker = tokio::spawn(async move {
        register_http_once(
            &worker_service,
            &HttpRegistrationAvailability::new(Arc::new(AtomicBool::new(false)), false, false),
            "invalid/username",
            "reservation-before-guard",
            request_id,
            "registration:conformance",
            Some(&worker_proof),
        )
        .await
    });
    let worker_pid = crate::support::blocked_backend(&pool, blocker_pid).await;
    let mut observer = pool.acquire().await.unwrap();
    let reserved: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM api_idempotency_records WHERE request_id=$1 AND guard_verified_at IS NULL")
        .bind(request_id).fetch_one(&mut *observer).await.unwrap();
    assert_eq!(
        reserved, 1,
        "guard waits after the reservation has committed on another connection"
    );
    drop(observer);
    let duplicate_proof = proof.clone();
    let duplicate = tokio::spawn(async move {
        register_http_once(
            &service,
            &HttpRegistrationAvailability::new(Arc::new(AtomicBool::new(false)), false, false),
            "invalid/username",
            "reservation-before-guard",
            Uuid::from_u128(0x573_3702),
            "registration:conformance",
            Some(&duplicate_proof),
        )
        .await
    });
    let duplicate_pid = crate::support::blocked_backend(&pool, worker_pid).await;
    duplicate.abort();
    let Err(cancelled) = duplicate.await else {
        panic!("blocked retry unexpectedly completed");
    };
    assert!(cancelled.is_cancelled());
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let released: bool = sqlx::query_scalar("SELECT NOT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=$1 AND xact_start IS NOT NULL)")
                .bind(duplicate_pid).fetch_one(&pool).await.unwrap();
            if released { break; }
            tokio::task::yield_now().await;
        }
    }).await.expect("cancelled retry retained its reservation transaction");
    blocker.rollback().await.unwrap();
    assert!(
        matches!(
            worker.await.unwrap(),
            HttpRegistrationOutcome::AbuseDenied(_)
        ),
        "guard rejection precedes invalid-username password preparation"
    );
    let mut observer = pool.acquire().await.unwrap();
    let user_exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM users WHERE username='invalid/username')")
            .fetch_one(&mut *observer)
            .await
            .unwrap();
    assert!(!user_exists, "guard denial cannot publish an account");
    let challenge_exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM abuse_pow_challenges WHERE id=$1)")
            .bind(proof.challenge_id)
            .fetch_one(&mut *observer)
            .await
            .unwrap();
    assert!(
        !challenge_exists,
        "intent-mismatched proof is consumed by the committed denial"
    );
    drop(observer);
    pool.close().await;
}

#[tokio::test]
#[ignore = "requires the ordinary-role random schema and TEST_DATABASE_URL"]
async fn account_repository_recovery_preserves_claim_tokens_and_commits_retry_backoff() {
    let pool = crate::support::operation_mutation_pool().await;
    let user = Uuid::from_u128(0x573_22101);
    sqlx::query(
        "INSERT INTO users(id,username,password_hash) VALUES($1,'repository-recovery','test-only')",
    )
    .bind(user)
    .execute(&pool)
    .await
    .unwrap();
    assert!(
        northstar_workflows::account_lifecycle::begin_account_deletion_quiesce(&pool, user)
            .await
            .unwrap()
    );
    sqlx::query("UPDATE account_deletion_requests SET recovery_after=clock_timestamp()-INTERVAL '1 second' WHERE user_id=$1")
        .bind(user).execute(&pool).await.unwrap();
    let guard = Arc::new(northstar_workflows::abuse_effects::persistent_guard(
        AbuseConfig {
            base_work_factor: 1,
            max_work_factor: 16,
            window: Duration::from_secs(60),
            cooldown_step: Duration::from_secs(60),
            max_wait: Duration::from_secs(8),
            message_free_burst: 6,
            approximate_max_device_seconds: 8,
        },
        pool.clone(),
        Some(b"deletion-recovery-conformance-secret-32-bytes"),
        None,
    ));
    let service = AccountService::new(
        WorkflowAccountRepository::new(
            pool.clone(),
            "example.test".into(),
            guard,
            northstar_workflows::roster::WorkflowRosterEffects,
        ),
        false,
        1_000_000,
        northstar_auth_core::MIN_SCRAM_ITERATIONS,
        false,
    );
    let mut jobs = service.claim_deletion_recovery(1, 60).await.unwrap();
    assert_eq!(jobs.len(), 1);
    let job = jobs.pop().unwrap();
    assert_eq!(job.user_id, user);
    assert_eq!(job.username, "repository-recovery");
    let replacement_token = Uuid::from_u128(0x573_22102);
    sqlx::query("UPDATE account_deletion_requests SET claim_token=$2 WHERE user_id=$1")
        .bind(user)
        .bind(replacement_token)
        .execute(&pool)
        .await
        .unwrap();
    assert!(!service
        .release_deletion_recovery(&job, "stale-worker")
        .await
        .unwrap());
    let mut observer = pool.acquire().await.unwrap();
    let actual: Uuid =
        sqlx::query_scalar("SELECT claim_token FROM account_deletion_requests WHERE user_id=$1")
            .bind(user)
            .fetch_one(&mut *observer)
            .await
            .unwrap();
    assert_eq!(
        actual, replacement_token,
        "repository forwarded the original token"
    );
    drop(observer);
    let attempts = job.attempts();
    let replacement =
        DeletionRecoveryJob::from_lease(user, job.username, replacement_token, attempts);
    assert!(service
        .release_deletion_recovery(&replacement, "dependency-refused")
        .await
        .unwrap());
    let mut observer = pool.acquire().await.unwrap();
    let state: (Option<Uuid>, bool, bool, String) = sqlx::query_as(
        "SELECT claim_token,claim_until IS NULL,recovery_after>clock_timestamp(),last_error_code FROM account_deletion_requests WHERE user_id=$1",
    ).bind(user).fetch_one(&mut *observer).await.unwrap();
    assert_eq!(
        state,
        (None, true, true, "dependency-refused".into()),
        "matching retry commits release and backoff together"
    );
    drop(observer);
    sqlx::query("DELETE FROM users WHERE id=$1")
        .bind(user)
        .execute(&pool)
        .await
        .unwrap();
    pool.close().await;
}

#[tokio::test]
#[ignore = "requires the ordinary-role random schema and TEST_DATABASE_URL"]
async fn guarded_account_mutations_commit_denial_without_password_or_deletion_effects() {
    let pool = crate::support::operation_mutation_pool().await;
    let user = Uuid::from_u128(0x573_12401);
    sqlx::query("INSERT INTO users(id,username,password_hash) VALUES($1,'guarded-account-conformance','original-verifier')")
        .bind(user).execute(&pool).await.unwrap();
    let guard = Arc::new(northstar_workflows::abuse_effects::persistent_guard(
        AbuseConfig {
            base_work_factor: 1,
            max_work_factor: 16,
            window: Duration::from_secs(60),
            cooldown_step: Duration::from_secs(60),
            max_wait: Duration::from_secs(8),
            message_free_burst: 6,
            approximate_max_device_seconds: 8,
        },
        pool.clone(),
        Some(b"account-mutation-conformance-secret-32-bytes"),
        None,
    ));
    let service = AccountService::new(
        WorkflowAccountRepository::new(
            pool.clone(),
            "example.test".into(),
            Arc::clone(&guard),
            northstar_workflows::roster::WorkflowRosterEffects,
        ),
        false,
        1_000_000,
        northstar_auth_core::MIN_SCRAM_ITERATIONS,
        false,
    );
    for label in ["XMPP registration", "password rotation", "account removal"] {
        let actors = vec![format!("user:guarded-account:{label}")];
        let proof = PowProof {
            challenge_id: Uuid::from_u128(0x573_12402),
            nonce: "0".into(),
        };
        let action = if label == "XMPP registration" {
            AbuseAction::Registration
        } else {
            AbuseAction::PasswordChange
        };
        let intent = if label == "XMPP registration" {
            PowIntent::xmpp_registration("invalid/username", "", None)
        } else {
            PowIntent::xmpp(
                action,
                if label == "password rotation" {
                    "/xmpp/password-change"
                } else {
                    "/xmpp/account-remove"
                },
                b"original client body",
            )
        };
        match label {
            "XMPP registration" => assert!(
                matches!(
                    service
                        .register(RegistrationRequest {
                            username: "invalid/username",
                            password: "",
                            invitation_token: None,
                            proof: Some(&proof),
                            intent: &intent,
                            subject: label,
                            actors: &actors,
                        })
                        .await
                        .unwrap(),
                    RegistrationOutcome::AbuseDenied(_)
                ),
                "registration verifies proof before password preparation"
            ),
            "password rotation" => assert!(matches!(
                service
                    .change_password(PasswordChangeRequest {
                        subject: label,
                        actors: &actors,
                        proof: Some(&proof),
                        intent: &intent,
                        user_id: user,
                        expected_auth_generation: 0,
                        password: "",
                    })
                    .await
                    .unwrap(),
                PasswordChangeOutcome::AbuseDenied(_)
            )),
            "account removal" => assert!(matches!(
                service
                    .quiesce_for_deletion(DeletionQuiesceRequest {
                        subject: label,
                        actors: &actors,
                        proof: Some(&proof),
                        intent: &intent,
                        user_id: user,
                        expected_auth_generation: 0,
                    })
                    .await
                    .unwrap(),
                DeletionQuiesceOutcome::AbuseDenied(_)
            )),
            _ => unreachable!(),
        }
        let mut observer = pool.acquire().await.unwrap();
        let account: (String, i64, bool) = sqlx::query_as(
            "SELECT password_hash,auth_generation,is_disabled FROM users WHERE id=$1",
        )
        .bind(user)
        .fetch_one(&mut *observer)
        .await
        .unwrap();
        assert_eq!(
            account,
            ("original-verifier".into(), 0, false),
            "{label}: no protected account mutation"
        );
        let recovery: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM account_deletion_requests WHERE user_id=$1)",
        )
        .bind(user)
        .fetch_one(&mut *observer)
        .await
        .unwrap();
        assert!(!recovery, "{label}: no partial deletion owner");
        let keys = northstar_abuse_application::guard::test_support::actor_state_keys(
            action,
            &actors,
            guard.actor_key_secret(),
        );
        let sequence: i64 =
            sqlx::query_scalar("SELECT sequence FROM abuse_actor_states WHERE state_key=$1")
                .bind(&keys[0])
                .fetch_one(&mut *observer)
                .await
                .unwrap();
        assert_eq!(
            sequence, 1,
            "{label}: denial penalty committed independently"
        );
    }
    sqlx::query("DELETE FROM users WHERE id=$1")
        .bind(user)
        .execute(&pool)
        .await
        .unwrap();
    pool.close().await;
}

#[tokio::test]
#[ignore = "requires the ordinary-role random schema and TEST_DATABASE_URL"]
async fn guarded_password_and_deletion_restore_proof_on_stale_generation_and_consume_it_with_the_mutation(
) {
    let pool = crate::support::operation_mutation_pool().await;
    let guard = Arc::new(northstar_workflows::abuse_effects::persistent_guard(
        AbuseConfig {
            base_work_factor: 1,
            max_work_factor: 16,
            window: Duration::from_secs(60),
            cooldown_step: Duration::from_secs(60),
            max_wait: Duration::from_secs(8),
            message_free_burst: 6,
            approximate_max_device_seconds: 8,
        },
        pool.clone(),
        Some(b"guarded-atomic-mutation-secret-at-least-32-bytes"),
        None,
    ));
    let service = AccountService::new(
        WorkflowAccountRepository::new(
            pool.clone(),
            "example.test".into(),
            Arc::clone(&guard),
            northstar_workflows::roster::WorkflowRosterEffects,
        ),
        false,
        1_000_000,
        northstar_auth_core::MIN_SCRAM_ITERATIONS,
        false,
    );
    for (ordinal, label, route) in [
        (0, "password rotation", "/xmpp/password-change"),
        (1, "account removal", "/xmpp/account-remove"),
    ] {
        let user = Uuid::from_u128(0x573_210100 + ordinal);
        sqlx::query(
            "INSERT INTO users(id,username,password_hash) VALUES($1,$2,'original-verifier')",
        )
        .bind(user)
        .bind(format!("guarded-atomic-{ordinal}"))
        .execute(&pool)
        .await
        .unwrap();
        let actors = vec![format!("user:guarded-atomic-{ordinal}")];
        let intent = PowIntent::xmpp(AbuseAction::PasswordChange, route, b"original client body");
        let challenge = guard
            .issue_v2(AbuseAction::PasswordChange, label, &actors, &intent)
            .await
            .unwrap();
        let proof = solve_pow(&challenge);
        if label == "password rotation" {
            let result = service
                .change_password(PasswordChangeRequest {
                    subject: label,
                    actors: &actors,
                    proof: Some(&proof),
                    intent: &intent,
                    user_id: user,
                    expected_auth_generation: 1,
                    password: "new guarded credential",
                })
                .await;
            let Err(error) = result else {
                panic!("stale password generation was accepted");
            };
            assert!(format!("{error:#}").contains("generation became stale"));
        } else {
            assert!(matches!(
                service
                    .quiesce_for_deletion(DeletionQuiesceRequest {
                        subject: label,
                        actors: &actors,
                        proof: Some(&proof),
                        intent: &intent,
                        user_id: user,
                        expected_auth_generation: 1,
                    })
                    .await
                    .unwrap(),
                DeletionQuiesceOutcome::Missing
            ));
        }
        let mut observer = pool.acquire().await.unwrap();
        let before: (String, i64, bool) = sqlx::query_as(
            "SELECT password_hash,auth_generation,is_disabled FROM users WHERE id=$1",
        )
        .bind(user)
        .fetch_one(&mut *observer)
        .await
        .unwrap();
        assert_eq!(
            before,
            ("original-verifier".into(), 0, false),
            "{label}: stale mutation rolled back"
        );
        let restored: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM abuse_pow_challenges WHERE id=$1)")
                .bind(proof.challenge_id)
                .fetch_one(&mut *observer)
                .await
                .unwrap();
        assert!(restored, "{label}: rollback restores the consumed proof");
        let recovery: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM account_deletion_requests WHERE user_id=$1)",
        )
        .bind(user)
        .fetch_one(&mut *observer)
        .await
        .unwrap();
        assert!(!recovery, "{label}: rollback creates no recovery owner");
        drop(observer);
        if label == "password rotation" {
            assert!(matches!(
                service
                    .change_password(PasswordChangeRequest {
                        subject: label,
                        actors: &actors,
                        proof: Some(&proof),
                        intent: &intent,
                        user_id: user,
                        expected_auth_generation: 0,
                        password: "new guarded credential",
                    })
                    .await
                    .unwrap(),
                PasswordChangeOutcome::Changed
            ));
        } else {
            assert!(matches!(
                service
                    .quiesce_for_deletion(DeletionQuiesceRequest {
                        subject: label,
                        actors: &actors,
                        proof: Some(&proof),
                        intent: &intent,
                        user_id: user,
                        expected_auth_generation: 0,
                    })
                    .await
                    .unwrap(),
                DeletionQuiesceOutcome::Quiesced
            ));
        }
        let mut observer = pool.acquire().await.unwrap();
        let after: (String, i64, bool) = sqlx::query_as(
            "SELECT password_hash,auth_generation,is_disabled FROM users WHERE id=$1",
        )
        .bind(user)
        .fetch_one(&mut *observer)
        .await
        .unwrap();
        assert_eq!(after.1, 1, "{label}: exact generation rotated once");
        assert_eq!(after.2, label == "account removal", "{label}");
        assert_eq!(
            after.0 == "original-verifier",
            label == "account removal",
            "{label}"
        );
        let consumed: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM abuse_pow_challenges WHERE id=$1)")
                .bind(proof.challenge_id)
                .fetch_one(&mut *observer)
                .await
                .unwrap();
        assert!(
            !consumed,
            "{label}: proof consumption commits with the protected mutation"
        );
        let recovery: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM account_deletion_requests WHERE user_id=$1)",
        )
        .bind(user)
        .fetch_one(&mut *observer)
        .await
        .unwrap();
        assert_eq!(
            recovery,
            label == "account removal",
            "{label}: quiesce commits its recovery owner"
        );
        drop(observer);
        sqlx::query("DELETE FROM users WHERE id=$1")
            .bind(user)
            .execute(&pool)
            .await
            .unwrap();
    }
    pool.close().await;
}
