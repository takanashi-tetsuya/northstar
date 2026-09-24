use super::*;

#[test]
fn authentication_verifiers_are_redacted_from_debug_output() {
    let verifier = "$argon2id$verifier-that-must-not-reach-a-log";
    let user = User {
        id: Uuid::nil(),
        username: "alice".to_owned(),
        password_hash: Zeroizing::new(verifier.to_owned()),
        scram_iterations: Some(600_000),
        scram_iteration_floor: 600_000,
        scram_sha1_iterations: None,
        scram_sha1_iteration_floor: auth::MIN_SCRAM_ITERATIONS,
        display_name: None,
        is_admin: false,
        is_disabled: false,
        auth_generation: 3,
        created_at: Utc::now(),
        last_login_at: None,
    };
    let formatted = format!("{user:?}");
    assert!(!formatted.contains(verifier));
    assert!(!formatted.contains("password_hash"));

    let scram_secret = vec![0xa5; 32];
    let credentials = ScramCredentials {
        salt: vec![0x51; 32],
        iterations: 600_000,
        stored_key: scram_secret.clone(),
        server_key: scram_secret,
    };
    let formatted = format!("{credentials:?}");
    assert!(formatted.contains("stored_key_bytes: 32"));
    assert!(!formatted.contains("165"));
}

#[test]
fn scram_family_upgrade_targets_never_lower_existing_costs() {
    let (sha256, sha1, required) = scram_upgrade_targets(
        Some(1_000_000),
        1_000_000,
        None,
        auth::MIN_SCRAM_ITERATIONS,
        600_000,
        true,
    );
    assert_eq!(sha256, 1_000_000);
    assert_eq!(sha1, Some(600_000));
    assert!(required);

    let (sha256, sha1, required) = scram_upgrade_targets(
        Some(600_000),
        600_000,
        Some(1_000_000),
        1_000_000,
        700_000,
        true,
    );
    assert_eq!(sha256, 700_000);
    assert_eq!(sha1, Some(1_000_000));
    assert!(required);

    let (_, sha1, required) = scram_upgrade_targets(
        Some(600_000),
        600_000,
        Some(900_000),
        900_000,
        600_000,
        false,
    );
    assert_eq!(sha1, None);
    assert!(required);
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn login_publication_preserves_each_scram_family_across_rolling_configuration() {
    let url = std::env::var("TEST_DATABASE_URL")
        .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(4)
        .connect(&url)
        .await
        .unwrap();
    crate::db::migrate(&pool).await.unwrap();

    let suffix = Uuid::new_v4().simple().to_string();
    let username = format!("rollscram{}", &suffix[..10]);
    let password = "rolling SCRAM configuration password";
    let account = create_user(
        &pool,
        &username,
        password,
        false,
        false,
        auth::MIN_SCRAM_ITERATIONS,
        true,
    )
    .await
    .unwrap();

    // Establish valid but intentionally independent family histories:
    // SHA-256 is already at 10k while compatibility SHA-1 is at 4,096.
    let sha256_salt = auth::generate_scram_salt();
    let (sha256_stored_key, sha256_server_key) =
        auth::compute_scram_sha256(password, &sha256_salt, 10_000);
    sqlx::query(
        "UPDATE users
            SET scram_sha256_salt=$2,scram_sha256_iterations=$3,
                scram_sha256_stored_key=$4,scram_sha256_server_key=$5
          WHERE id=$1",
    )
    .bind(account.id)
    .bind(sha256_salt)
    .bind(10_000_i32)
    .bind(sha256_stored_key)
    .bind(sha256_server_key)
    .execute(&pool)
    .await
    .unwrap();

    // Both nodes finish password work before either publishes. The newer
    // node raises only SHA-1 to 8k (SHA-256 remains 10k); the older node's
    // otherwise-valid 6k publication must then lose under the row lock.
    let newer = prepare_login(&pool, &username, password, 8_000, true)
        .await
        .unwrap()
        .unwrap();
    let older = prepare_login(&pool, &username, password, 6_000, true)
        .await
        .unwrap()
        .unwrap();
    let mut newer_tx = pool.begin().await.unwrap();
    assert!(apply_prepared_login_in_tx(&mut newer_tx, newer)
        .await
        .unwrap());
    newer_tx.commit().await.unwrap();

    let mut older_tx = pool.begin().await.unwrap();
    let error = apply_prepared_login_in_tx(&mut older_tx, older)
        .await
        .unwrap_err();
    older_tx.rollback().await.unwrap();
    assert!(
        format!("{error:#}").contains("invalid or downgraded SCRAM login upgrade"),
        "{error:#}"
    );
    let iterations: (i32, i32) = sqlx::query_as(
        "SELECT scram_sha256_iterations,scram_sha1_iterations
           FROM users WHERE id=$1",
    )
    .bind(account.id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(iterations, (10_000, 8_000));

    // A compatibility-off node may deliberately clear SHA-1. The durable
    // high-water mark survives, and an older compatibility-on node derives
    // the missing verifier at 8k rather than recreating it at its 6k
    // configured floor.
    clear_scram_sha1_credentials(&pool).await.unwrap();
    let cleared = find_user_by_id(&pool, account.id).await.unwrap().unwrap();
    assert_eq!(cleared.scram_sha1_iterations, None);
    assert_eq!(cleared.scram_sha1_iteration_floor, 8_000);
    let rebuilt = prepare_login(&pool, &username, password, 6_000, true)
        .await
        .unwrap()
        .unwrap();
    let mut rebuild_tx = pool.begin().await.unwrap();
    assert!(apply_prepared_login_in_tx(&mut rebuild_tx, rebuilt)
        .await
        .unwrap());
    rebuild_tx.commit().await.unwrap();
    let rebuilt_iterations: (i32, i32) = sqlx::query_as(
        "SELECT scram_sha256_iterations,scram_sha1_iterations
           FROM users WHERE id=$1",
    )
    .bind(account.id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(rebuilt_iterations, (10_000, 8_000));
}

fn solve_pow(challenge: &crate::abuse::PowChallenge) -> crate::abuse::PowProof {
    use sha2::{Digest, Sha256};

    let target = u64::MAX / challenge.requirement.work_factor.max(1);
    for nonce in 0_u64.. {
        let nonce = nonce.to_string();
        let mut hasher = Sha256::new();
        hasher.update(challenge.prefix.as_bytes());
        hasher.update(nonce.as_bytes());
        let digest = hasher.finalize();
        if u64::from_be_bytes(digest[..8].try_into().unwrap()) <= target {
            return crate::abuse::PowProof {
                challenge_id: challenge.challenge_id,
                nonce,
            };
        }
    }
    unreachable!()
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL pointing at a disposable random PostgreSQL schema"]
async fn scram_families_hide_unknown_and_disabled_accounts_but_surface_corruption() {
    let url = std::env::var("TEST_DATABASE_URL")
        .expect("set TEST_DATABASE_URL to a disposable random PostgreSQL schema");
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(4)
        .connect(&url)
        .await
        .unwrap();
    crate::db::migrate(&pool).await.unwrap();
    crate::db::upload::validate_upload_capacity_policy(&pool, 128, 10_000, 1024 * 1024 * 1024)
        .await
        .unwrap();

    let suffix = Uuid::new_v4().simple().to_string();
    let username = format!("scramdb{}", &suffix[..12]);
    let unknown = format!("missing{}", &suffix[..12]);
    let user = create_user(
        &pool,
        &username,
        "independent-scram-family-test-password",
        false,
        false,
        auth::MIN_SCRAM_ITERATIONS,
        true,
    )
    .await
    .unwrap();
    assert_eq!(
        enabled_user_id(&pool, &username).await.unwrap(),
        Some(user.id)
    );
    let enabled = find_enabled_user(&pool, &username).await.unwrap().unwrap();
    assert_eq!(enabled.id, user.id);
    assert_eq!(enabled.username, username);
    assert_eq!(
        find_enabled_user_by_id(&pool, user.id)
            .await
            .unwrap()
            .map(|account| account.id),
        Some(user.id)
    );

    for algorithm in [auth::ScramAlgorithm::Sha256, auth::ScramAlgorithm::Sha1] {
        let credentials = get_scram_credentials(&pool, &username, algorithm)
            .await
            .unwrap()
            .expect("new accounts have both independent SCRAM verifiers");
        assert_eq!(credentials.stored_key.len(), algorithm.key_len());
        assert_eq!(credentials.server_key.len(), algorithm.key_len());
        assert!(!credentials.salt.is_empty());
        assert_eq!(credentials.iterations, auth::MIN_SCRAM_ITERATIONS);
        assert!(get_scram_credentials(&pool, &unknown, algorithm)
            .await
            .unwrap()
            .is_none());
    }

    sqlx::query("UPDATE users SET is_disabled=TRUE WHERE id=$1")
        .bind(user.id)
        .execute(&pool)
        .await
        .unwrap();
    assert!(enabled_user_id(&pool, &username).await.unwrap().is_none());
    assert!(find_enabled_user(&pool, &username).await.unwrap().is_none());
    assert!(find_enabled_user_by_id(&pool, user.id)
        .await
        .unwrap()
        .is_none());
    for algorithm in [auth::ScramAlgorithm::Sha256, auth::ScramAlgorithm::Sha1] {
        assert!(get_scram_credentials(&pool, &username, algorithm)
            .await
            .unwrap()
            .is_none());
    }

    sqlx::query(
        "UPDATE users
            SET is_disabled=FALSE,
                scram_sha1_server_key=NULL
          WHERE id=$1",
    )
    .bind(user.id)
    .execute(&pool)
    .await
    .unwrap();
    let partial = get_scram_credentials(&pool, &username, auth::ScramAlgorithm::Sha1)
        .await
        .unwrap_err()
        .to_string();
    assert!(partial.contains("incomplete"), "{partial}");

    sqlx::query(
        "UPDATE users
            SET scram_sha1_salt=NULL,scram_sha1_iterations=NULL,
                scram_sha1_stored_key=NULL,scram_sha1_server_key=NULL
          WHERE id=$1",
    )
    .bind(user.id)
    .execute(&pool)
    .await
    .unwrap();
    assert!(
        get_scram_credentials(&pool, &username, auth::ScramAlgorithm::Sha1)
            .await
            .unwrap()
            .is_none()
    );

    sqlx::query(
        "UPDATE users
            SET scram_sha1_salt=decode(repeat('11',32),'hex'),
                scram_sha1_iterations=$2,
                scram_sha1_stored_key=decode(repeat('00',20),'hex'),
                scram_sha1_server_key=decode(repeat('00',20),'hex'),
                scram_sha256_stored_key=decode(repeat('00',31),'hex')
          WHERE id=$1",
    )
    .bind(user.id)
    .bind(i32::try_from(auth::MIN_SCRAM_ITERATIONS).unwrap())
    .execute(&pool)
    .await
    .unwrap();
    let invalid = get_scram_credentials(&pool, &username, auth::ScramAlgorithm::Sha256)
        .await
        .unwrap_err()
        .to_string();
    assert!(invalid.contains("invalid"), "{invalid}");
}

fn password_idempotency_request<'a>(
    token: &'a str,
    key: &'a str,
    body: &[u8],
) -> crate::db::IdempotencyRequest<'a> {
    crate::db::IdempotencyRequest {
        request_id: Uuid::new_v4(),
        actor_id: None,
        principal_scope: token.as_bytes(),
        capacity_scope: token.as_bytes(),
        target_scope: b"",
        principal_kind: crate::db::ApiPrincipalKind::User,
        method: "PATCH",
        route: "/api/v1/me/password",
        idempotency_key: key,
        request_fingerprint: crate::db::api_request_fingerprint("application/json", body),
        ttl_seconds: 3600,
        lease_seconds: 180,
    }
}

fn acquired(outcome: crate::db::IdempotencyAcquire) -> crate::db::IdempotencyLease {
    match outcome {
        crate::db::IdempotencyAcquire::Acquired(lease) => lease,
        other => panic!("expected acquired idempotency lease, got {other:?}"),
    }
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn concurrent_registration_cannot_exceed_the_global_hourly_limit() {
    let url = std::env::var("TEST_DATABASE_URL")
        .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(8)
        .connect(&url)
        .await
        .unwrap();
    crate::db::migrate(&pool).await.unwrap();
    crate::db::initialize_admin_runtime_settings(&pool, false, false, false)
        .await
        .unwrap();

    let existing = registrations_last_hour(&pool).await.unwrap();
    let limit = u32::try_from(existing + 2).unwrap();
    let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(5));
    let suffix = Uuid::new_v4().simple().to_string();
    let mut tasks = Vec::new();
    for index in 0..4 {
        let pool = pool.clone();
        let barrier = std::sync::Arc::clone(&barrier);
        let username = format!("r{index}{}", &suffix[..10]);
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            create_user_with_invitation(
                &pool,
                &username,
                "registration-test-password",
                None,
                false,
                limit,
                auth::MIN_SCRAM_ITERATIONS,
            )
            .await
        }));
    }
    barrier.wait().await;

    let mut created = Vec::new();
    let mut limited = 0;
    for task in tasks {
        match task.await.unwrap() {
            Ok(user) => created.push(user.id),
            Err(RegistrationError::RateLimited) => limited += 1,
            Err(error) => panic!("unexpected registration error: {error}"),
        }
    }
    assert_eq!(created.len(), 2);
    assert_eq!(limited, 2);
    assert_eq!(registrations_last_hour(&pool).await.unwrap(), existing + 2);

    sqlx::query("DELETE FROM users WHERE id = ANY($1)")
        .bind(&created)
        .execute(&pool)
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL pointing at a disposable random PostgreSQL schema"]
async fn guarded_registration_rolls_back_and_replays_proof_invitation_user_and_audit() {
    use crate::abuse::{AbuseConfig, AbuseGuard};
    use std::time::Duration;

    let url = std::env::var("TEST_DATABASE_URL")
        .expect("set TEST_DATABASE_URL to a disposable random PostgreSQL schema");
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(8)
        .connect(&url)
        .await
        .unwrap();
    crate::db::migrate(&pool).await.unwrap();
    crate::db::initialize_admin_runtime_settings(&pool, false, false, false)
        .await
        .unwrap();

    let guard = std::sync::Arc::new(AbuseGuard::new_persistent(
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
        Some(b"guarded-registration-test-key-at-least-32-bytes"),
        None,
    ));
    let suffix = Uuid::new_v4().simple().to_string();
    let username = format!("atomic{}", &suffix[..12]);
    let replay_username = format!("replay{}", &suffix[..12]);
    let invitation = format!("{}{}", suffix, suffix);
    sqlx::query(
        "INSERT INTO invitation_tokens(id,token_hash,label,max_uses) VALUES($1,$2,'guarded registration',2)",
    )
    .bind(Uuid::new_v4())
    .bind(auth::token_hash(&invitation))
    .execute(&pool)
    .await
    .unwrap();
    let actors = vec![format!("ip:198.51.100.{}", suffix.as_bytes()[0])];
    let subject = format!("registration:{}", actors[0]);
    let registration_password = "guarded-registration-password";
    let intent = crate::abuse::PowIntent::xmpp_registration(
        &username,
        registration_password,
        Some(&invitation),
    );

    // Advance the free burst so the transaction must consume a durable,
    // one-use proof instead of succeeding on an unchallenged first use.
    assert!(guard
        .verify_or_allow_v2(AbuseAction::Registration, &subject, &actors, None, &intent,)
        .await
        .unwrap()
        .is_ok());
    let challenge = guard
        .issue_v2(AbuseAction::Registration, &subject, &actors, &intent)
        .await
        .unwrap();
    let proof = solve_pow(&challenge);
    let initial_audit_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM audit_log WHERE action='user.register'")
            .fetch_one(&pool)
            .await
            .unwrap();

    let prepared = prepare_registration(
        &username,
        registration_password,
        auth::MIN_SCRAM_ITERATIONS,
        false,
    )
    .await
    .unwrap();
    let mut crashed = pool.begin().await.unwrap();
    assert!(matches!(
        create_user_with_invitation_guarded_in_tx_v2(
            &mut crashed,
            &guard,
            &subject,
            &actors,
            Some(&proof),
            &intent,
            false,
            prepared,
            Some(&invitation),
            true,
            1_000_000,
            None,
        )
        .await
        .unwrap(),
        GuardedRegistrationOutcome::Created(_)
    ));
    crashed.rollback().await.unwrap();

    assert!(find_user(&pool, &username).await.unwrap().is_none());
    assert_eq!(
        sqlx::query_scalar::<_, i32>("SELECT use_count FROM invitation_tokens WHERE token_hash=$1")
            .bind(auth::token_hash(&invitation))
            .fetch_one(&pool)
            .await
            .unwrap(),
        0
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM audit_log WHERE action='user.register'")
            .fetch_one(&pool)
            .await
            .unwrap(),
        initial_audit_count
    );
    assert!(sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM abuse_pow_challenges WHERE id=$1)"
    )
    .bind(proof.challenge_id)
    .fetch_one(&pool)
    .await
    .unwrap());

    let service = crate::services::account::AccountService::new(
        crate::db::account_repository::PostgresAccountRepository::new(
            pool.clone(),
            "example.test".to_owned(),
            std::sync::Arc::clone(&guard),
        ),
        true,
        1_000_000,
        auth::MIN_SCRAM_ITERATIONS,
        false,
    );
    let request = crate::services::account::RegistrationRequest {
        username: &username,
        password: registration_password,
        invitation_token: Some(&invitation),
        proof: Some(&proof),
        intent: &intent,
        subject: &subject,
        actors: &actors,
    };
    let crate::services::account::RegistrationOutcome::Created(created) =
        service.register(request).await.unwrap()
    else {
        panic!("a rolled-back proof and invitation must remain usable");
    };
    assert_eq!(created.username, username);

    let replay_intent = crate::abuse::PowIntent::xmpp_registration(
        &replay_username,
        registration_password,
        Some(&invitation),
    );
    let replay = crate::services::account::RegistrationRequest {
        username: &replay_username,
        password: registration_password,
        invitation_token: Some(&invitation),
        proof: Some(&proof),
        intent: &replay_intent,
        subject: &subject,
        actors: &actors,
    };
    assert!(matches!(
        service.register(replay).await.unwrap(),
        crate::services::account::RegistrationOutcome::AbuseDenied(_)
    ));
    assert!(find_user(&pool, &replay_username).await.unwrap().is_none());
    assert_eq!(
        sqlx::query_scalar::<_, i32>("SELECT use_count FROM invitation_tokens WHERE token_hash=$1")
            .bind(auth::token_hash(&invitation))
            .fetch_one(&pool)
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM audit_log WHERE action='user.register'")
            .fetch_one(&pool)
            .await
            .unwrap(),
        initial_audit_count + 1
    );
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn api_session_cap_and_disable_revocation_are_atomic() {
    let url = std::env::var("TEST_DATABASE_URL")
        .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(8)
        .connect(&url)
        .await
        .unwrap();
    crate::db::migrate(&pool).await.unwrap();
    // A normal restart must treat every already-recorded migration,
    // including 0056, as an idempotent no-op.
    crate::db::migrate(&pool).await.unwrap();

    let suffix = Uuid::new_v4().simple().to_string();
    let actor_id = Uuid::new_v4();
    let second_admin_id = Uuid::new_v4();
    let target_id = Uuid::new_v4();
    for (id, username, is_admin) in [
        (actor_id, format!("a{}", &suffix[..12]), true),
        (second_admin_id, format!("b{}", &suffix[..12]), true),
        (target_id, format!("u{}", &suffix[..12]), false),
    ] {
        sqlx::query(
            "INSERT INTO users (id, username, password_hash, is_admin) VALUES ($1, $2, 'test-only-invalid-hash', $3)",
        )
        .bind(id)
        .bind(username)
        .bind(is_admin)
        .execute(&pool)
        .await
        .unwrap();
    }

    let mut newest_token = String::new();
    for _ in 0..40 {
        newest_token = create_api_session(&pool, target_id, 1).await.unwrap();
    }
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM api_sessions WHERE user_id=$1")
        .bind(target_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, MAX_API_SESSIONS_PER_USER);
    assert!(user_for_token(&pool, &newest_token)
        .await
        .unwrap()
        .is_some());

    set_user_status(&pool, actor_id, target_id, Some(true), None)
        .await
        .unwrap();
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM api_sessions WHERE user_id=$1")
        .bind(target_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 0);
    assert!(user_for_token(&pool, &newest_token)
        .await
        .unwrap()
        .is_none());

    set_user_status(&pool, actor_id, second_admin_id, None, Some(false))
        .await
        .unwrap();
    assert!(matches!(
        set_user_status(&pool, second_admin_id, actor_id, None, Some(false)).await,
        Err(UserStatusError::LastAdministrator)
    ));

    sqlx::query("DELETE FROM users WHERE id = ANY($1)")
        .bind([actor_id, second_admin_id, target_id])
        .execute(&pool)
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn rest_password_cas_and_admin_authorization_are_atomic() {
    let url = std::env::var("TEST_DATABASE_URL")
        .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(8)
        .connect(&url)
        .await
        .unwrap();
    crate::db::migrate(&pool).await.unwrap();

    let suffix = Uuid::new_v4().simple().to_string();
    let admin_a = create_user(
        &pool,
        &format!("aa{}", &suffix[..10]),
        "admin-a-old-password",
        true,
        true,
        auth::MIN_SCRAM_ITERATIONS,
        false,
    )
    .await
    .unwrap();
    let admin_b = create_user(
        &pool,
        &format!("ab{}", &suffix[..10]),
        "admin-b-old-password",
        true,
        true,
        auth::MIN_SCRAM_ITERATIONS,
        false,
    )
    .await
    .unwrap();
    let target = create_user(
        &pool,
        &format!("u{}", &suffix[..10]),
        "target-old-password",
        false,
        true,
        auth::MIN_SCRAM_ITERATIONS,
        false,
    )
    .await
    .unwrap();
    let target_token = create_api_session(&pool, target.id, 1).await.unwrap();
    let fast_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO fast_tokens
         (id,user_id,device_id,mechanism,channel_binding,slot,derivation_nonce,token_hash,
          expires_at,auth_generation,strong_auth_at,chain_expires_at)
         VALUES($1,$2,$3,'HT-SHA-256-NONE','none','current',$4,$5,
                NOW()+INTERVAL '1 day',$6,NOW(),NOW()+INTERVAL '1 day')",
    )
    .bind(fast_id)
    .bind(target.id)
    .bind(Uuid::new_v4())
    .bind(vec![7_u8; 32])
    .bind(vec![8_u8; 32])
    .bind(target.auth_generation)
    .execute(&pool)
    .await
    .unwrap();
    let sm_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO sm_resume_sessions
         (id,token_hash,user_id,auth_generation,full_jid,resource,connection_id,
          resume_timeout_seconds,peer_ip,live_lease_until,expires_at,resumable)
         VALUES($1,$2,$3,$4,$5,'phone',$6,300,'127.0.0.1',
                NOW()+INTERVAL '5 minutes',NOW()+INTERVAL '5 minutes',TRUE)",
    )
    .bind(sm_id)
    .bind(vec![9_u8; 32])
    .bind(target.id)
    .bind(target.auth_generation)
    .bind(format!("{}@example.test/phone", target.username))
    .bind(Uuid::new_v4())
    .execute(&pool)
    .await
    .unwrap();

    assert_eq!(
        change_password_cas(
            &pool,
            target.id,
            &target.password_hash,
            target.auth_generation,
            &target_token,
            "target-old-password",
            "target-new-password",
            auth::MIN_SCRAM_ITERATIONS,
        )
        .await
        .unwrap(),
        PasswordChangeOutcome::Changed
    );
    let rotated = find_user_by_id(&pool, target.id).await.unwrap().unwrap();
    assert_eq!(
        rotated.auth_generation,
        target.auth_generation.saturating_add(1)
    );
    assert!(!auth::verify_password(&rotated.password_hash, "target-old-password").unwrap());
    assert!(auth::verify_password(&rotated.password_hash, "target-new-password").unwrap());
    assert!(user_for_token(&pool, &target_token)
        .await
        .unwrap()
        .is_none());
    let fast_revoked: bool =
        sqlx::query_scalar("SELECT revoked_at IS NOT NULL FROM fast_tokens WHERE id=$1")
            .bind(fast_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(fast_revoked);
    let sm_expired: bool = sqlx::query_scalar(
        "SELECT NOT resumable AND expires_at <= clock_timestamp()
         FROM sm_resume_sessions WHERE id=$1",
    )
    .bind(sm_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(sm_expired);
    let audit_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit_log
         WHERE actor_id=$1 AND action='user.password.change'",
    )
    .bind(target.id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(audit_count, 1);

    // A handler that derived a new password while its observed account
    // generation became stale must not overwrite the newer credential.
    let stale_token = create_api_session(&pool, target.id, 1).await.unwrap();
    sqlx::query("UPDATE users SET auth_generation=auth_generation+1 WHERE id=$1")
        .bind(target.id)
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(
        change_password_cas(
            &pool,
            target.id,
            &rotated.password_hash,
            rotated.auth_generation,
            &stale_token,
            "target-new-password",
            "stale-write-must-not-win",
            auth::MIN_SCRAM_ITERATIONS,
        )
        .await
        .unwrap(),
        PasswordChangeOutcome::StaleAuthorization
    );
    let after_stale = find_user_by_id(&pool, target.id).await.unwrap().unwrap();
    assert_eq!(after_stale.password_hash, rotated.password_hash);

    let token_a = create_api_session(&pool, admin_a.id, 1).await.unwrap();
    let token_b = create_api_session(&pool, admin_b.id, 1).await.unwrap();
    assert!(matches!(
        set_user_status_api(
            &pool,
            admin_a.id,
            admin_a.auth_generation,
            &token_a,
            admin_a.id,
            Some(true),
            None,
        )
        .await,
        Err(UserStatusError::SelfMutation)
    ));

    // The advisory lock plus in-transaction bearer revalidation means
    // concurrent administrators cannot both demote the other and leave
    // the service without a usable administrator. The winner revokes the
    // loser's bearer before the second transaction authorizes.
    let (demote_b, demote_a) = tokio::join!(
        set_user_status_api(
            &pool,
            admin_a.id,
            admin_a.auth_generation,
            &token_a,
            admin_b.id,
            None,
            Some(false),
        ),
        set_user_status_api(
            &pool,
            admin_b.id,
            admin_b.auth_generation,
            &token_b,
            admin_a.id,
            None,
            Some(false),
        )
    );
    let outcomes = [demote_b, demote_a];
    assert_eq!(outcomes.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        outcomes
            .iter()
            .filter(|result| matches!(result, Err(UserStatusError::Unauthorized)))
            .count(),
        1
    );
    let enabled_admins: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE is_admin AND NOT is_disabled")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(enabled_admins, 1);
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn rest_password_idempotency_logout_and_lock_order_are_atomic() {
    use crate::abuse::{AbuseAction, AbuseConfig, AbuseGuard, TransactionalGuardOutcome};
    use std::collections::BTreeMap;
    use std::sync::Arc;
    use std::time::Duration;

    let url = std::env::var("TEST_DATABASE_URL")
        .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(12)
        .connect(&url)
        .await
        .unwrap();
    crate::db::migrate(&pool).await.unwrap();
    let suffix = Uuid::new_v4().simple().to_string();
    let user = create_user(
        &pool,
        &format!("pw{}", &suffix[..10]),
        "password-before-change",
        false,
        true,
        auth::MIN_SCRAM_ITERATIONS,
        false,
    )
    .await
    .unwrap();
    let token = create_api_session(&pool, user.id, 1).await.unwrap();
    let keyring = Arc::new(
        crate::db::ApiControlKeyring::new(b"password-api-control-test-key-000001", None).unwrap(),
    );
    let guard = AbuseGuard::new_persistent(
        AbuseConfig {
            base_work_factor: 2,
            max_work_factor: 1024,
            window: Duration::from_secs(60),
            cooldown_step: Duration::from_secs(60),
            max_wait: Duration::from_secs(900),
            message_free_burst: 6,
            approximate_max_device_seconds: 8,
        },
        pool.clone(),
        Some(b"password-abuse-test-key-at-least-32-bytes"),
        None,
    );
    let request_key = "password-change-key-0001".to_owned();
    let request = password_idempotency_request(
        &token,
        &request_key,
        br#"{"current_password":"password-before-change","new_password":"password-after-change"}"#,
    );
    let headers = BTreeMap::from([
        ("cache-control".to_owned(), "no-store, max-age=0".to_owned()),
        ("content-type".to_owned(), "application/json".to_owned()),
    ]);
    let response_body = br#"{"changed":true,"sessions_revoked":true}"#;

    let mut lookup = pool.begin().await.unwrap();
    assert!(matches!(
        crate::db::lookup_password_change_replay_in_tx(&keyring, &mut lookup, &request)
            .await
            .unwrap(),
        crate::db::IdempotencyReplayLookup::Miss
    ));
    lookup.commit().await.unwrap();

    let mut reserve = pool.begin().await.unwrap();
    assert!(user_for_token_in_tx(&mut reserve, &token)
        .await
        .unwrap()
        .is_some());
    let lease = acquired(
        crate::db::acquire_idempotency_in_tx(&keyring, &mut reserve, &request)
            .await
            .unwrap(),
    );
    let actors = vec![format!("user:{}", user.id)];
    assert!(matches!(
        crate::db::abuse_transaction_repository::verify_in_tx(
            &mut reserve,
            &guard,
            AbuseAction::PasswordChange,
            &format!("password_change:{}", user.id),
            &actors,
            None,
            None,
        )
        .await
        .unwrap(),
        TransactionalGuardOutcome::Allowed
    ));
    assert!(
        crate::db::mark_idempotency_guard_verified_in_tx(&mut reserve, &lease)
            .await
            .unwrap()
    );
    reserve.commit().await.unwrap();

    let mut prework = pool.begin().await.unwrap();
    assert!(
        crate::db::resume_idempotency_lease_in_tx(&mut prework, &lease, 180)
            .await
            .unwrap()
    );
    prework.commit().await.unwrap();
    let prepared = prepare_password_change(
        &user.password_hash,
        "password-before-change",
        "password-after-change",
        auth::MIN_SCRAM_ITERATIONS,
        false,
    )
    .await
    .unwrap();

    // Crash after every database consequence was staged: rollback must
    // restore credentials, sessions, audit and replay state together.
    let mut crashed = pool.begin().await.unwrap();
    assert!(
        crate::db::resume_idempotency_lease_in_tx(&mut crashed, &lease, 180)
            .await
            .unwrap()
    );
    assert!(
        crate::db::bind_idempotency_actor_in_tx(&mut crashed, &lease, user.id)
            .await
            .unwrap()
    );
    assert_eq!(
        apply_prepared_password_change_in_tx(
            &mut crashed,
            user.id,
            &user.password_hash,
            user.auth_generation,
            &token,
            prepared,
            Some(lease.request_id),
        )
        .await
        .unwrap(),
        PasswordChangeOutcome::Changed
    );
    assert!(crate::db::complete_idempotency_in_tx(
        &keyring,
        &mut crashed,
        &lease,
        200,
        &headers,
        response_body,
    )
    .await
    .unwrap());
    crashed.rollback().await.unwrap();
    assert!(user_for_token(&pool, &token).await.unwrap().is_some());
    assert!(auth::verify_password(
        &find_user_by_id(&pool, user.id)
            .await
            .unwrap()
            .unwrap()
            .password_hash,
        "password-before-change"
    )
    .unwrap());

    // Simulate process loss and lease takeover. The committed guard marker
    // survives, but the rolled-back password mutation does not.
    sqlx::query(
        "UPDATE api_idempotency_records
         SET lease_expires_at=clock_timestamp()-INTERVAL '1 second'
         WHERE request_id=$1",
    )
    .bind(lease.request_id)
    .execute(&pool)
    .await
    .unwrap();
    let mut takeover = pool.begin().await.unwrap();
    assert!(user_for_token_in_tx(&mut takeover, &token)
        .await
        .unwrap()
        .is_some());
    let takeover_lease = acquired(
        crate::db::acquire_idempotency_in_tx(&keyring, &mut takeover, &request)
            .await
            .unwrap(),
    );
    assert!(takeover_lease.guard_verified);
    takeover.commit().await.unwrap();
    let retry_prepared = prepare_password_change(
        &user.password_hash,
        "password-before-change",
        "password-after-change",
        auth::MIN_SCRAM_ITERATIONS,
        false,
    )
    .await
    .unwrap();
    let mut final_tx = pool.begin().await.unwrap();
    assert!(
        crate::db::resume_idempotency_lease_in_tx(&mut final_tx, &takeover_lease, 180,)
            .await
            .unwrap()
    );
    assert!(
        crate::db::bind_idempotency_actor_in_tx(&mut final_tx, &takeover_lease, user.id,)
            .await
            .unwrap()
    );
    assert_eq!(
        apply_prepared_password_change_in_tx(
            &mut final_tx,
            user.id,
            &user.password_hash,
            user.auth_generation,
            &token,
            retry_prepared,
            Some(takeover_lease.request_id),
        )
        .await
        .unwrap(),
        PasswordChangeOutcome::Changed
    );
    assert!(crate::db::complete_idempotency_in_tx(
        &keyring,
        &mut final_tx,
        &takeover_lease,
        200,
        &headers,
        response_body,
    )
    .await
    .unwrap());
    final_tx.commit().await.unwrap();
    assert!(user_for_token(&pool, &token).await.unwrap().is_none());
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM audit_log
             WHERE actor_id=$1 AND action='user.password.change' AND request_id=$2"
        )
        .bind(user.id)
        .bind(takeover_lease.request_id)
        .fetch_one(&pool)
        .await
        .unwrap(),
        1
    );
    let mut replay = pool.begin().await.unwrap();
    match crate::db::lookup_password_change_replay_in_tx(&keyring, &mut replay, &request)
        .await
        .unwrap()
    {
        crate::db::IdempotencyReplayLookup::Replay(response) => {
            assert_eq!(response.status, 200);
            assert_eq!(response.body, response_body);
        }
        other => panic!("expected password response replay, got {other:?}"),
    }
    replay.commit().await.unwrap();

    // A new key cannot use the now-revoked bearer to create a mutation.
    let new_key = "password-change-key-0002".to_owned();
    let new_request = password_idempotency_request(
        &token,
        &new_key,
        br#"{"current_password":"password-after-change","new_password":"another-password"}"#,
    );
    let mut unauthenticated = pool.begin().await.unwrap();
    assert!(user_for_token_in_tx(&mut unauthenticated, &token)
        .await
        .unwrap()
        .is_none());
    unauthenticated.rollback().await.unwrap();
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM api_idempotency_records WHERE route='/api/v1/me/password'"
        )
        .fetch_one(&pool)
        .await
        .unwrap(),
        1
    );
    let mut new_lookup = pool.begin().await.unwrap();
    assert!(matches!(
        crate::db::lookup_password_change_replay_in_tx(&keyring, &mut new_lookup, &new_request,)
            .await
            .unwrap(),
        crate::db::IdempotencyReplayLookup::Miss
    ));
    new_lookup.commit().await.unwrap();

    // Logout is naturally idempotent: only the successful DELETE writes
    // its audit row; repeats and random well-formed tokens are identical.
    let logout_user = create_user(
        &pool,
        &format!("lo{}", &suffix[..10]),
        "logout-test-password",
        false,
        true,
        auth::MIN_SCRAM_ITERATIONS,
        false,
    )
    .await
    .unwrap();
    let logout_token = create_api_session(&pool, logout_user.id, 1).await.unwrap();
    let first_logout_request = Uuid::new_v4();
    let mut logout_tx = pool.begin().await.unwrap();
    assert!(
        delete_api_session_audited_in_tx(&mut logout_tx, &logout_token, first_logout_request,)
            .await
            .unwrap()
    );
    logout_tx.commit().await.unwrap();
    let mut repeated_logout = pool.begin().await.unwrap();
    assert!(
        !delete_api_session_audited_in_tx(&mut repeated_logout, &logout_token, Uuid::new_v4(),)
            .await
            .unwrap()
    );
    repeated_logout.commit().await.unwrap();
    let mut random_logout = pool.begin().await.unwrap();
    assert!(!delete_api_session_audited_in_tx(
        &mut random_logout,
        &auth::new_session_token(),
        Uuid::new_v4(),
    )
    .await
    .unwrap());
    random_logout.commit().await.unwrap();
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM audit_log
             WHERE actor_id=$1 AND action='user.session.logout'"
        )
        .bind(logout_user.id)
        .fetch_one(&pool)
        .await
        .unwrap(),
        1
    );

    // Password and report-style mutations both lock user/session before
    // idempotency. Starting them together must not form the former cycle.
    let lock_user = create_user(
        &pool,
        &format!("lk{}", &suffix[..10]),
        "lock-order-password",
        false,
        true,
        auth::MIN_SCRAM_ITERATIONS,
        false,
    )
    .await
    .unwrap();
    let lock_token = create_api_session(&pool, lock_user.id, 1).await.unwrap();
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum InitialAdmission {
        Acquired,
        Busy,
    }

    let authorization_barrier = Arc::new(tokio::sync::Barrier::new(2));
    let admission_barrier = Arc::new(tokio::sync::Barrier::new(2));
    let rollback_barrier = Arc::new(tokio::sync::Barrier::new(2));
    let password_lock = {
        let pool = pool.clone();
        let keyring = Arc::clone(&keyring);
        let authorization_barrier = Arc::clone(&authorization_barrier);
        let admission_barrier = Arc::clone(&admission_barrier);
        let rollback_barrier = Arc::clone(&rollback_barrier);
        let lock_token = lock_token.clone();
        tokio::spawn(async move {
            let key = "lock-password-key-0001".to_owned();
            let request = password_idempotency_request(&lock_token, &key, b"password-lock");
            let mut tx = pool.begin().await.unwrap();
            sqlx::query("SET LOCAL lock_timeout='2s'")
                .execute(&mut *tx)
                .await
                .unwrap();
            assert!(user_for_token_in_tx(&mut tx, &lock_token)
                .await
                .unwrap()
                .is_some());
            authorization_barrier.wait().await;
            let outcome = crate::db::acquire_idempotency_in_tx(&keyring, &mut tx, &request)
                .await
                .unwrap();
            let initial = match outcome {
                crate::db::IdempotencyAcquire::Acquired(_) => InitialAdmission::Acquired,
                crate::db::IdempotencyAcquire::Busy {
                    retry_after_seconds: 1,
                } => InitialAdmission::Busy,
                other => panic!("unexpected password idempotency outcome: {other:?}"),
            };
            // Keep the winner's singleton row lock until the competing
            // transaction has observed fail-fast Busy. This makes the
            // capacity-lock contract deterministic rather than scheduler
            // dependent.
            admission_barrier.wait().await;
            tx.rollback().await.unwrap();
            rollback_barrier.wait().await;

            if initial == InitialAdmission::Busy {
                let mut retry = pool.begin().await.unwrap();
                sqlx::query("SET LOCAL lock_timeout='2s'")
                    .execute(&mut *retry)
                    .await
                    .unwrap();
                assert!(user_for_token_in_tx(&mut retry, &lock_token)
                    .await
                    .unwrap()
                    .is_some());
                let retried = crate::db::acquire_idempotency_in_tx(&keyring, &mut retry, &request)
                    .await
                    .unwrap();
                assert!(
                    matches!(retried, crate::db::IdempotencyAcquire::Acquired(_)),
                    "password Busy admission did not recover: {retried:?}"
                );
                retry.rollback().await.unwrap();
            }
            initial
        })
    };
    let report_lock = {
        let pool = pool.clone();
        let keyring = Arc::clone(&keyring);
        let authorization_barrier = Arc::clone(&authorization_barrier);
        let admission_barrier = Arc::clone(&admission_barrier);
        let rollback_barrier = Arc::clone(&rollback_barrier);
        let lock_token = lock_token.clone();
        tokio::spawn(async move {
            let key = "lock-report-key-0001".to_owned();
            let body = crate::db::api_request_fingerprint("application/json", b"report-lock");
            let request = crate::db::IdempotencyRequest {
                request_id: Uuid::new_v4(),
                actor_id: Some(lock_user.id),
                principal_scope: lock_user.id.as_bytes(),
                capacity_scope: lock_user.id.as_bytes(),
                target_scope: b"",
                principal_kind: crate::db::ApiPrincipalKind::User,
                method: "POST",
                route: "/api/v1/reports",
                idempotency_key: &key,
                request_fingerprint: body,
                ttl_seconds: 3600,
                lease_seconds: 180,
            };
            let mut tx = pool.begin().await.unwrap();
            sqlx::query("SET LOCAL lock_timeout='2s'")
                .execute(&mut *tx)
                .await
                .unwrap();
            assert!(authorize_user_in_tx(
                &mut tx,
                lock_user.id,
                lock_user.auth_generation,
                &lock_token,
            )
            .await
            .unwrap());
            authorization_barrier.wait().await;
            let outcome = crate::db::acquire_idempotency_in_tx(&keyring, &mut tx, &request)
                .await
                .unwrap();
            let initial = match outcome {
                crate::db::IdempotencyAcquire::Acquired(_) => InitialAdmission::Acquired,
                crate::db::IdempotencyAcquire::Busy {
                    retry_after_seconds: 1,
                } => InitialAdmission::Busy,
                other => panic!("unexpected report idempotency outcome: {other:?}"),
            };
            admission_barrier.wait().await;
            tx.rollback().await.unwrap();
            rollback_barrier.wait().await;

            if initial == InitialAdmission::Busy {
                let mut retry = pool.begin().await.unwrap();
                sqlx::query("SET LOCAL lock_timeout='2s'")
                    .execute(&mut *retry)
                    .await
                    .unwrap();
                assert!(authorize_user_in_tx(
                    &mut retry,
                    lock_user.id,
                    lock_user.auth_generation,
                    &lock_token,
                )
                .await
                .unwrap());
                let retried = crate::db::acquire_idempotency_in_tx(&keyring, &mut retry, &request)
                    .await
                    .unwrap();
                assert!(
                    matches!(retried, crate::db::IdempotencyAcquire::Acquired(_)),
                    "report Busy admission did not recover: {retried:?}"
                );
                retry.rollback().await.unwrap();
            }
            initial
        })
    };
    let (password_initial, report_initial) = tokio::time::timeout(Duration::from_secs(5), async {
        (password_lock.await.unwrap(), report_lock.await.unwrap())
    })
    .await
    .expect("password/report lock-order barrier timed out");
    assert!(matches!(
        (password_initial, report_initial),
        (InitialAdmission::Acquired, InitialAdmission::Busy)
            | (InitialAdmission::Busy, InitialAdmission::Acquired)
    ));
    pool.close().await;
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn account_deletion_atomically_cancels_local_reverse_rosters() {
    let url = std::env::var("TEST_DATABASE_URL")
        .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(4)
        .connect(&url)
        .await
        .unwrap();
    crate::db::migrate(&pool).await.unwrap();
    // This fixture writes a complete upload locator directly. Migrations
    // deliberately leave the durable capacity authority unbound until the
    // runtime establishes its deployment policy, and the locator update
    // must consequently fail closed without this explicit setup. Bind the
    // same isolated-test policy used by the upload integration suite here
    // rather than relying on a preceding test command to have bound state
    // in this schema.
    let (policy_generation, recovery_draining) =
        crate::db::upload::validate_upload_capacity_policy(&pool, 128, 10_000, 1024 * 1024 * 1024)
            .await
            .unwrap();
    assert!(policy_generation > 0);
    assert!(!recovery_draining);

    let suffix = Uuid::new_v4().simple().to_string();
    let removed_id = Uuid::new_v4();
    let contact_id = Uuid::new_v4();
    let removed_name = format!("d{}", &suffix[..12]);
    let contact_name = format!("c{}", &suffix[..12]);
    for (id, username) in [
        (removed_id, removed_name.as_str()),
        (contact_id, contact_name.as_str()),
    ] {
        sqlx::query("INSERT INTO users(id,username,password_hash) VALUES($1,$2,'test-only')")
            .bind(id)
            .bind(username)
            .execute(&pool)
            .await
            .unwrap();
    }
    let removed_jid = format!("{removed_name}@example.test");
    let contact_jid = format!("{contact_name}@example.test");
    let removed_pubsub_node = Uuid::new_v4();
    let shared_pubsub_node = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO pubsub_nodes(id,node,creator_jid,children_association_whitelist)
         VALUES($1,$2,$3,ARRAY[$3]),($4,$5,$6,ARRAY[$3,$6])",
    )
    .bind(removed_pubsub_node)
    .bind(format!("delete-owned-{suffix}"))
    .bind(&removed_jid)
    .bind(shared_pubsub_node)
    .bind(format!("delete-shared-{suffix}"))
    .bind(&contact_jid)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO pubsub_affiliations(node_id,jid,affiliation)
         VALUES($1,$2,'owner'),($3,$2,'owner'),($3,$4,'owner')",
    )
    .bind(removed_pubsub_node)
    .bind(&removed_jid)
    .bind(shared_pubsub_node)
    .bind(&contact_jid)
    .execute(&pool)
    .await
    .unwrap();
    let removed_resource = format!("{removed_jid}/phone");
    sqlx::query(
        "INSERT INTO pubsub_subscriptions(node_id,jid,state,subid,digest)
         VALUES($1,$2,'subscribed',$3,TRUE)",
    )
    .bind(shared_pubsub_node)
    .bind(&removed_resource)
    .bind(Uuid::new_v4().to_string())
    .execute(&pool)
    .await
    .unwrap();
    let digest_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO pubsub_digest_queue
         (id,subscription_node_id,subscriber_jid,event_xml,deliver_after)
         VALUES($1,$2,$3,'<event/>',NOW()+INTERVAL '1 hour')",
    )
    .bind(digest_id)
    .bind(shared_pubsub_node)
    .bind(&removed_resource)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query("INSERT INTO roster_items(owner_id,contact_jid,subscription,groups) VALUES($1,$2,'both','[]'::jsonb),($3,$4,'both','[1]'::jsonb)")
        .bind(removed_id)
        .bind(&contact_jid)
        .bind(contact_id)
        .bind(&removed_jid)
        .execute(&pool)
        .await
        .unwrap();
    let upload_id = Uuid::new_v4();
    let upload_digest = vec![0x42_u8; 32];
    sqlx::query(
        "INSERT INTO upload_slots
         (id,user_id,filename,content_type,size,token_hash,expires_at,put_expires_at)
         VALUES($1,$2,'cipher.bin','application/octet-stream',4,'test-token',
                NOW()+INTERVAL '1 day',NOW()+INTERVAL '5 minutes')",
    )
    .bind(upload_id)
    .bind(removed_id)
    .execute(&pool)
    .await
    .unwrap();
    // Build a complete current committed projection through UPDATE so the
    // cleanup-debt trigger reserves its cascade obligation exactly as it
    // does for the production finalization path.
    sqlx::query(
        "UPDATE upload_slots
         SET uploaded=TRUE,content_sha256=$2,completed_at=clock_timestamp(),
             storage_state='committed',storage_object_key=id::text,
             storage_sha256=$2,storage_size=size
         WHERE id=$1",
    )
    .bind(upload_id)
    .bind(&upload_digest)
    .execute(&pool)
    .await
    .unwrap();

    let api_token = create_api_session(&pool, removed_id, 1).await.unwrap();
    let fast_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO fast_tokens
         (id,user_id,device_id,mechanism,channel_binding,slot,derivation_nonce,token_hash,
          expires_at,auth_generation,strong_auth_at,chain_expires_at)
         VALUES($1,$2,$3,'HT-SHA-256-NONE','none','current',$4,$5,
                NOW()+INTERVAL '1 day',0,NOW(),NOW()+INTERVAL '1 day')",
    )
    .bind(fast_id)
    .bind(removed_id)
    .bind(Uuid::new_v4())
    .bind(vec![7_u8; 32])
    .bind(vec![8_u8; 32])
    .execute(&pool)
    .await
    .unwrap();
    let sm_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO sm_resume_sessions
         (id,token_hash,user_id,auth_generation,full_jid,resource,connection_id,
          resume_timeout_seconds,peer_ip,live_lease_until,expires_at)
         VALUES($1,$2,$3,0,$4,'phone',$5,300,'127.0.0.1',NOW(),NOW()+INTERVAL '5 minutes')",
    )
    .bind(sm_id)
    .bind(vec![9_u8; 32])
    .bind(removed_id)
    .bind(format!("{removed_jid}/phone"))
    .bind(Uuid::new_v4())
    .execute(&pool)
    .await
    .unwrap();
    let archive_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO message_archive
         (id,owner_id,peer_jid,peer_full_jid,stanza,encrypted)
         VALUES($1,$2,$3,$3,'<message xmlns=\"jabber:client\"/>',FALSE)",
    )
    .bind(archive_id)
    .bind(removed_id)
    .bind(&contact_jid)
    .execute(&pool)
    .await
    .unwrap();
    let admission_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO personal_message_admissions
         (id,identity_kind,actor_scope_raw,actor_scope,target_scope,identity_value,
          identity_digest,payload_key_id,payload_mac,sender_archive_id)
         VALUES($1,'local-origin',$2,$2,$3,'delete-test',$4,'AAAAAAAAAAAAAAAA',$5,$6)",
    )
    .bind(admission_id)
    .bind(&removed_jid)
    .bind(&contact_jid)
    .bind(vec![10_u8; 32])
    .bind(vec![11_u8; 32])
    .bind(archive_id)
    .execute(&pool)
    .await
    .unwrap();
    // Retention must preserve an identity while only one of its durable
    // projections expires, but account deletion must erase both outgoing
    // (actor scope) and incoming (target scope) identities atomically.
    let incoming_archive_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO message_archive
         (id,owner_id,peer_jid,peer_full_jid,stanza,encrypted)
         VALUES($1,$2,$3,$3,'<message xmlns=\"jabber:client\"/>',FALSE)",
    )
    .bind(incoming_archive_id)
    .bind(removed_id)
    .bind(&contact_jid)
    .execute(&pool)
    .await
    .unwrap();
    let incoming_admission_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO personal_message_admissions
         (id,identity_kind,actor_scope_raw,actor_scope,target_scope,identity_value,
          identity_digest,payload_key_id,payload_mac,recipient_archive_id)
         VALUES($1,'remote-stanza',$2,$2,$3,'delete-test-incoming',$4,
                'AAAAAAAAAAAAAAAA',$5,$6)",
    )
    .bind(incoming_admission_id)
    .bind(&contact_jid)
    .bind(&removed_jid)
    .bind(vec![12_u8; 32])
    .bind(vec![13_u8; 32])
    .bind(incoming_archive_id)
    .execute(&pool)
    .await
    .unwrap();

    // Invalid historical group data makes journal materialization fail.
    // The reverse subscription update and user delete must both roll back.
    assert!(delete_user_with_roster(&pool, removed_id, "example.test")
        .await
        .is_err());
    assert!(find_user(&pool, &removed_name).await.unwrap().is_some());
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM pubsub_nodes WHERE id = ANY($1)")
            .bind([removed_pubsub_node, shared_pubsub_node])
            .fetch_one(&pool)
            .await
            .unwrap(),
        2,
        "PubSub cleanup must roll back with a failed account deletion"
    );
    let cleanup_after_rollback: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM upload_cleanup_queue WHERE object_id=$1")
            .bind(upload_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(cleanup_after_rollback, 0);
    let reverse: String = sqlx::query_scalar(
        "SELECT subscription FROM roster_items WHERE owner_id=$1 AND contact_jid=$2",
    )
    .bind(contact_id)
    .bind(&removed_jid)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(reverse, "both");
    assert!(user_for_token(&pool, &api_token).await.unwrap().is_some());
    for (table, id) in [
        ("fast_tokens", fast_id),
        ("sm_resume_sessions", sm_id),
        ("message_archive", archive_id),
        ("message_archive", incoming_archive_id),
        ("personal_message_admissions", admission_id),
        ("personal_message_admissions", incoming_admission_id),
    ] {
        let count: i64 = sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {table} WHERE id=$1"))
            .bind(id)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count, 1, "{table} must survive a rolled-back deletion");
    }

    sqlx::query("UPDATE roster_items SET groups='[]'::jsonb WHERE owner_id=$1 AND contact_jid=$2")
        .bind(contact_id)
        .bind(&removed_jid)
        .execute(&pool)
        .await
        .unwrap();
    let removed = delete_user_with_roster(&pool, removed_id, "example.test")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(removed.roster.len(), 1);
    assert_eq!(removed.reverse_roster_changes.len(), 1);
    assert_eq!(removed.reverse_roster_changes[0].0, contact_id);
    assert_eq!(removed.reverse_roster_changes[0].1, contact_name);
    assert_eq!(
        removed.reverse_roster_changes[0].2.subscription.as_deref(),
        Some("none")
    );
    assert!(find_user(&pool, &removed_name).await.unwrap().is_none());
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM pubsub_nodes WHERE id=$1")
            .bind(removed_pubsub_node)
            .fetch_one(&pool)
            .await
            .unwrap(),
        0,
        "creator-owned PubSub node was not deleted"
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM pubsub_nodes WHERE id=$1")
            .bind(shared_pubsub_node)
            .fetch_one(&pool)
            .await
            .unwrap(),
        1,
        "co-owned PubSub node should survive"
    );
    for (table, predicate) in [
        ("pubsub_affiliations", "node_id=$1 AND jid=$2"),
        (
            "pubsub_subscriptions",
            "node_id=$1 AND split_part(jid, '/', 1)=$2",
        ),
        (
            "pubsub_digest_queue",
            "subscription_node_id=$1 AND split_part(subscriber_jid, '/', 1)=$2",
        ),
    ] {
        let count: i64 =
            sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {table} WHERE {predicate}"))
                .bind(shared_pubsub_node)
                .bind(&removed_jid)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(count, 0, "{table} retained the deleted account");
    }
    let whitelist: Vec<String> =
        sqlx::query_scalar("SELECT children_association_whitelist FROM pubsub_nodes WHERE id=$1")
            .bind(shared_pubsub_node)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(whitelist.as_slice(), std::slice::from_ref(&contact_jid));
    let cleanup_after_commit: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM upload_cleanup_queue WHERE object_id=$1")
            .bind(upload_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(cleanup_after_commit, 1);
    let reverse: String = sqlx::query_scalar(
        "SELECT subscription FROM roster_items WHERE owner_id=$1 AND contact_jid=$2",
    )
    .bind(contact_id)
    .bind(&removed_jid)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(reverse, "none");
    assert!(user_for_token(&pool, &api_token).await.unwrap().is_none());
    for (table, id) in [
        ("fast_tokens", fast_id),
        ("sm_resume_sessions", sm_id),
        ("message_archive", archive_id),
        ("message_archive", incoming_archive_id),
        ("personal_message_admissions", admission_id),
        ("personal_message_admissions", incoming_admission_id),
    ] {
        let count: i64 = sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {table} WHERE id=$1"))
            .bind(id)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count, 0, "{table} must be removed with the account");
    }

    sqlx::query("DELETE FROM users WHERE id=$1")
        .bind(contact_id)
        .execute(&pool)
        .await
        .unwrap();
}
