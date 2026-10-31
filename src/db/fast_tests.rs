use northstar_auth_core as auth;
use northstar_auth_postgres::fast::*;
use sqlx::PgPool;
use uuid::Uuid;

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn durable_fast_tokens_support_optional_counts_replay_and_status_revocation() {
    let url = std::env::var("TEST_DATABASE_URL")
        .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(8)
        .connect(&url)
        .await
        .unwrap();
    crate::db::migrate(&pool).await.unwrap();

    let user_id = Uuid::new_v4();
    let admin_id = Uuid::new_v4();
    for (id, prefix, admin) in [(user_id, "fast", false), (admin_id, "admin", true)] {
        sqlx::query(
            "INSERT INTO users(id,username,password_hash,is_admin) VALUES($1,$2,'test-only',$3)",
        )
        .bind(id)
        .bind(format!("{prefix}-{}", &id.simple().to_string()[..10]))
        .bind(admin)
        .execute(&pool)
        .await
        .unwrap();
    }
    let device_id = Uuid::new_v4();
    let master = [0x51_u8; 32];
    let issued = issue_fast_token(
        &pool,
        &master,
        user_id,
        device_id,
        "HT-SHA-256-NONE",
        0,
        30,
        90,
        None,
    )
    .await
    .unwrap();
    let proof = auth::fast_proof(&issued.token, false, &[]);
    let authenticate = |counter| FastAuthenticationRequest {
        user_id,
        device_id,
        mechanism: "HT-SHA-256-NONE",
        counter,
        initiator_proof: &proof,
        channel_binding: &[],
        invalidate: false,
        rotate_within_days: 7,
    };

    // The bearer is installation-bound. Reusing an otherwise valid proof
    // under a different XEP-0388 user-agent UUID cannot discover or use
    // the credential.
    assert!(matches!(
        authenticate_fast_token(
            &pool,
            &master,
            FastAuthenticationRequest {
                user_id,
                device_id: Uuid::new_v4(),
                mechanism: "HT-SHA-256-NONE",
                counter: None,
                initiator_proof: &proof,
                channel_binding: &[],
                invalidate: false,
                rotate_within_days: 7,
            },
        )
        .await
        .unwrap(),
        FastAuthentication::CredentialsExpired
    ));

    // Non-0RTT clients are conforming without a count and may reuse the
    // current token. PostgreSQL still advances a private use counter.
    assert!(matches!(
        authenticate_fast_token(&pool, &master, authenticate(None))
            .await
            .unwrap(),
        FastAuthentication::Success(_)
    ));
    assert!(matches!(
        authenticate_fast_token(&pool, &master, authenticate(None))
            .await
            .unwrap(),
        FastAuthentication::Success(_)
    ));

    assert!(matches!(
        authenticate_fast_token(&pool, &master, authenticate(Some(9)))
            .await
            .unwrap(),
        FastAuthentication::Success(_)
    ));
    assert!(matches!(
        authenticate_fast_token(&pool, &master, authenticate(Some(9)))
            .await
            .unwrap(),
        FastAuthentication::Replayed
    ));

    // A concurrent duplicate counter succeeds at most once across pools
    // and therefore across Northstar processes.
    let first_pool = pool.clone();
    let second_pool = pool.clone();
    let first_master = master;
    let second_master = master;
    let first_proof = proof.clone();
    let second_proof = proof.clone();
    let first = tokio::spawn(async move {
        authenticate_fast_token(
            &first_pool,
            &first_master,
            FastAuthenticationRequest {
                user_id,
                device_id,
                mechanism: "HT-SHA-256-NONE",
                counter: Some(10),
                initiator_proof: &first_proof,
                channel_binding: &[],
                invalidate: false,
                rotate_within_days: 7,
            },
        )
        .await
        .unwrap()
    });
    let second = tokio::spawn(async move {
        authenticate_fast_token(
            &second_pool,
            &second_master,
            FastAuthenticationRequest {
                user_id,
                device_id,
                mechanism: "HT-SHA-256-NONE",
                counter: Some(10),
                initiator_proof: &second_proof,
                channel_binding: &[],
                invalidate: false,
                rotate_within_days: 7,
            },
        )
        .await
        .unwrap()
    });
    let outcomes = [first.await.unwrap(), second.await.unwrap()];
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(outcome, FastAuthentication::Success(_)))
            .count(),
        1
    );

    // Expiry is enforced from PostgreSQL rather than process memory, so
    // it survives restarts and is shared by every frontend instance.
    let expired_device = Uuid::new_v4();
    let expired = issue_fast_token(
        &pool,
        &master,
        user_id,
        expired_device,
        "HT-SHA-256-NONE",
        0,
        30,
        90,
        None,
    )
    .await
    .unwrap();
    sqlx::query(
        "UPDATE fast_tokens
         SET strong_auth_at=clock_timestamp()-INTERVAL '2 seconds',
             expires_at=clock_timestamp()-INTERVAL '1 second'
         WHERE user_id=$1 AND device_id=$2",
    )
    .bind(user_id)
    .bind(expired_device)
    .execute(&pool)
    .await
    .unwrap();
    let expired_proof = auth::fast_proof(&expired.token, false, &[]);
    let restarted_pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .unwrap();
    assert!(matches!(
        authenticate_fast_token(
            &restarted_pool,
            &master,
            FastAuthenticationRequest {
                user_id,
                device_id: expired_device,
                mechanism: "HT-SHA-256-NONE",
                counter: None,
                initiator_proof: &expired_proof,
                channel_binding: &[],
                invalidate: false,
                rotate_within_days: 7,
            },
        )
        .await
        .unwrap(),
        FastAuthentication::CredentialsExpired
    ));

    let rotating_device = Uuid::new_v4();
    let rotating = issue_fast_token(
        &pool,
        &master,
        user_id,
        rotating_device,
        "HT-SHA-256-NONE",
        0,
        30,
        90,
        None,
    )
    .await
    .unwrap();
    let rotating_proof = auth::fast_proof(&rotating.token, false, &[]);
    let rotating_verified = match authenticate_fast_token(
        &restarted_pool,
        &master,
        FastAuthenticationRequest {
            user_id,
            device_id: rotating_device,
            mechanism: "HT-SHA-256-NONE",
            counter: Some(1),
            initiator_proof: &rotating_proof,
            channel_binding: &[],
            invalidate: true,
            rotate_within_days: 31,
        },
    )
    .await
    .unwrap()
    {
        FastAuthentication::Success(verified) => verified,
        other => panic!("expected restart-safe FAST success, got {other:?}"),
    };
    // Invalidation suppresses automatic rotation even inside the
    // rotation window and takes effect only when success is committed.
    assert!(!rotating_verified.should_rotate);
    assert!(finalize_fast_token(
        &restarted_pool,
        rotating_verified.id,
        rotating_verified.was_new,
        true,
        rotating_verified.auth_generation,
    )
    .await
    .unwrap());
    assert!(matches!(
        authenticate_fast_token(
            &pool,
            &master,
            FastAuthenticationRequest {
                user_id,
                device_id: rotating_device,
                mechanism: "HT-SHA-256-NONE",
                counter: Some(2),
                initiator_proof: &rotating_proof,
                channel_binding: &[],
                invalidate: false,
                rotate_within_days: 31,
            },
        )
        .await
        .unwrap(),
        FastAuthentication::CredentialsExpired
    ));

    let replacement_device = Uuid::new_v4();
    let current = issue_fast_token(
        &pool,
        &master,
        user_id,
        replacement_device,
        "HT-SHA-256-NONE",
        0,
        30,
        90,
        None,
    )
    .await
    .unwrap();
    let current_proof = auth::fast_proof(&current.token, false, &[]);
    let current_verified = match authenticate_fast_token(
        &restarted_pool,
        &master,
        FastAuthenticationRequest {
            user_id,
            device_id: replacement_device,
            mechanism: "HT-SHA-256-NONE",
            counter: Some(1),
            initiator_proof: &current_proof,
            channel_binding: &[],
            invalidate: false,
            rotate_within_days: 31,
        },
    )
    .await
    .unwrap()
    {
        FastAuthentication::Success(verified) => verified,
        other => panic!("expected rotation-eligible FAST success, got {other:?}"),
    };
    assert!(current_verified.should_rotate);
    let replacement_plan = FastCommitPlan {
        token_id: Some(current_verified.id),
        token_was_new: current_verified.was_new,
        invalidate: false,
        issue: Some(FastTokenIssue {
            device_id: replacement_device,
            mechanism: "HT-SHA-256-NONE".to_owned(),
            ttl_days: 30,
            strong_reauth_max_days: 90,
            inherited_chain: Some((
                current_verified.strong_auth_at,
                current_verified.chain_expires_at,
            )),
        }),
    };
    let (replacement, _) = commit_fast_state_with_login_epoch(
        &restarted_pool,
        &master,
        user_id,
        current_verified.auth_generation,
        &replacement_plan,
        None,
    )
    .await
    .unwrap()
    .expect("rotation generation must remain current");
    let replacement = replacement.expect("rotation must issue a pending replacement");
    let slots: Vec<String> = sqlx::query_scalar(
        "SELECT slot FROM fast_tokens WHERE user_id=$1 AND device_id=$2 ORDER BY slot",
    )
    .bind(user_id)
    .bind(replacement_device)
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(slots, vec!["current".to_owned(), "new".to_owned()]);
    let replacement_proof = auth::fast_proof(&replacement.token, false, &[]);
    let replacement_verified = match authenticate_fast_token(
        &pool,
        &master,
        FastAuthenticationRequest {
            user_id,
            device_id: replacement_device,
            mechanism: "HT-SHA-256-NONE",
            counter: Some(1),
            initiator_proof: &replacement_proof,
            channel_binding: &[],
            invalidate: false,
            rotate_within_days: 7,
        },
    )
    .await
    .unwrap()
    {
        FastAuthentication::Success(verified) => verified,
        other => panic!("expected pending FAST replacement success, got {other:?}"),
    };
    assert!(replacement_verified.was_new);
    assert!(finalize_fast_token(
        &pool,
        replacement_verified.id,
        true,
        false,
        replacement_verified.auth_generation,
    )
    .await
    .unwrap());
    let remaining_ids: Vec<Uuid> = sqlx::query_scalar(
        "SELECT id FROM fast_tokens WHERE user_id=$1 AND device_id=$2 ORDER BY id",
    )
    .bind(user_id)
    .bind(replacement_device)
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(remaining_ids, vec![replacement_verified.id]);
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(outcome, FastAuthentication::Replayed))
            .count(),
        1
    );

    // Two slots are global to a client installation, rather than two per
    // mechanism. Promotion across mechanisms preserves the original
    // strong-authentication deadline.
    let original = match authenticate_fast_token(&pool, &master, authenticate(Some(11)))
        .await
        .unwrap()
    {
        FastAuthentication::Success(verified) => verified,
        other => panic!("expected FAST success, got {other:?}"),
    };
    assert!(finalize_fast_token(
        &pool,
        original.id,
        original.was_new,
        false,
        original.auth_generation,
    )
    .await
    .unwrap());
    let endpoint = issue_fast_token(
        &pool,
        &master,
        user_id,
        device_id,
        "HT-SHA-256-ENDP",
        original.auth_generation,
        30,
        90,
        Some((original.strong_auth_at, original.chain_expires_at)),
    )
    .await
    .unwrap();
    let slots: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM fast_tokens
         WHERE user_id=$1 AND device_id=$2 AND revoked_at IS NULL",
    )
    .bind(user_id)
    .bind(device_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(slots, 2);
    let endpoint_binding = b"endpoint-binding";
    let endpoint_proof = auth::fast_proof(&endpoint.token, false, endpoint_binding);
    let promoted = match authenticate_fast_token(
        &pool,
        &master,
        FastAuthenticationRequest {
            user_id,
            device_id,
            mechanism: "HT-SHA-256-ENDP",
            counter: Some(1),
            initiator_proof: &endpoint_proof,
            channel_binding: endpoint_binding,
            invalidate: false,
            rotate_within_days: 7,
        },
    )
    .await
    .unwrap()
    {
        FastAuthentication::Success(verified) => verified,
        other => panic!("expected promoted FAST success, got {other:?}"),
    };
    assert_eq!(promoted.chain_expires_at, original.chain_expires_at);
    assert!(finalize_fast_token(
        &pool,
        promoted.id,
        promoted.was_new,
        false,
        promoted.auth_generation,
    )
    .await
    .unwrap());
    let remaining: (i64, String) = sqlx::query_as(
        "SELECT COUNT(*)::BIGINT, MIN(mechanism) FROM fast_tokens
         WHERE user_id=$1 AND device_id=$2 AND revoked_at IS NULL",
    )
    .bind(user_id)
    .bind(device_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(remaining, (1, "HT-SHA-256-ENDP".to_owned()));

    let epoch_device = Uuid::new_v4();
    let mut tasks = Vec::new();
    for _ in 0..16 {
        let pool = pool.clone();
        tasks.push(tokio::spawn(async move {
            northstar_auth_postgres::users::next_user_agent_login_epoch(
                &pool,
                user_id,
                epoch_device,
                0,
            )
            .await
            .unwrap()
            .unwrap()
        }));
    }
    let mut epochs = Vec::new();
    for task in tasks {
        epochs.push(task.await.unwrap());
    }
    epochs.sort_unstable();
    assert_eq!(epochs, (1..=16).collect::<Vec<_>>());

    crate::db::set_user_status(&pool, admin_id, user_id, Some(true), None)
        .await
        .unwrap();
    assert!(matches!(
        authenticate_fast_token(&pool, &master, authenticate(None))
            .await
            .unwrap(),
        FastAuthentication::CredentialsExpired
    ));
    assert!(issue_fast_token(
        &pool,
        &master,
        user_id,
        device_id,
        "HT-SHA-256-NONE",
        1,
        30,
        90,
        None,
    )
    .await
    .is_err());
    assert_eq!(
        northstar_auth_postgres::users::next_user_agent_login_epoch(
            &pool,
            user_id,
            epoch_device,
            1
        )
        .await
        .unwrap(),
        None
    );
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn fast_derivation_integrity_failures_are_side_effect_free() {
    let url = std::env::var("TEST_DATABASE_URL")
        .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(4)
        .connect(&url)
        .await
        .unwrap();
    crate::db::migrate(&pool).await.unwrap();
    let user_id = Uuid::new_v4();
    let device_id = Uuid::new_v4();
    sqlx::query("INSERT INTO users(id,username,password_hash) VALUES($1,$2,'test-only')")
        .bind(user_id)
        .bind(format!("fast-integrity-{}", user_id.simple()))
        .execute(&pool)
        .await
        .unwrap();
    let master = [0x83_u8; 32];
    let wrong_master = [0x84_u8; 32];
    let issued = issue_fast_token(
        &pool,
        &master,
        user_id,
        device_id,
        "HT-SHA-256-NONE",
        0,
        30,
        90,
        None,
    )
    .await
    .unwrap();
    let proof = auth::fast_proof(&issued.token, false, &[]);
    assert!(matches!(
        authenticate_fast_token(
            &pool,
            &wrong_master,
            FastAuthenticationRequest {
                user_id,
                device_id,
                mechanism: "HT-SHA-256-NONE",
                counter: Some(41),
                initiator_proof: &proof,
                channel_binding: &[],
                // Even an integrity failure carrying an invalidate request
                // must not revoke the durable credential.
                invalidate: true,
                rotate_within_days: 7,
            },
        )
        .await
        .unwrap(),
        FastAuthentication::IntegrityFailure
    ));
    let unchanged_after_wrong_key: (i64, bool, bool) = sqlx::query_as(
        "SELECT last_counter,used_at IS NULL,revoked_at IS NULL
           FROM fast_tokens WHERE user_id=$1 AND device_id=$2",
    )
    .bind(user_id)
    .bind(device_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(unchanged_after_wrong_key, (-1, true, true));

    sqlx::query("UPDATE fast_tokens SET token_hash=$3 WHERE user_id=$1 AND device_id=$2")
        .bind(user_id)
        .bind(device_id)
        .bind(vec![0_u8; 32])
        .execute(&pool)
        .await
        .unwrap();
    assert!(matches!(
        authenticate_fast_token(
            &pool,
            &master,
            FastAuthenticationRequest {
                user_id,
                device_id,
                mechanism: "HT-SHA-256-NONE",
                counter: Some(41),
                initiator_proof: &proof,
                channel_binding: &[],
                invalidate: true,
                rotate_within_days: 7,
            },
        )
        .await
        .unwrap(),
        FastAuthentication::IntegrityFailure
    ));
    let unchanged_after_tamper: (i64, bool, bool) = sqlx::query_as(
        "SELECT last_counter,used_at IS NULL,revoked_at IS NULL
           FROM fast_tokens WHERE user_id=$1 AND device_id=$2",
    )
    .bind(user_id)
    .bind(device_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(unchanged_after_tamper, (-1, true, true));
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn bind2_fast_side_effects_rollback_with_route_sql_and_commit_failures() {
    let url = std::env::var("TEST_DATABASE_URL")
        .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(4)
        .connect(&url)
        .await
        .unwrap();
    crate::db::migrate(&pool).await.unwrap();

    let user_id = Uuid::new_v4();
    let device_id = Uuid::new_v4();
    sqlx::query("INSERT INTO users(id,username,password_hash) VALUES($1,$2,'test-only')")
        .bind(user_id)
        .bind(format!(
            "atomic-fast-{}",
            &user_id.simple().to_string()[..10]
        ))
        .execute(&pool)
        .await
        .unwrap();
    let master = [0x73_u8; 32];
    let original = issue_fast_token(
        &pool,
        &master,
        user_id,
        device_id,
        "HT-SHA-256-NONE",
        0,
        30,
        90,
        None,
    )
    .await
    .unwrap();
    let proof = auth::fast_proof(&original.token, false, &[]);
    let verified = match authenticate_fast_token(
        &pool,
        &master,
        FastAuthenticationRequest {
            user_id,
            device_id,
            mechanism: "HT-SHA-256-NONE",
            counter: Some(1),
            initiator_proof: &proof,
            channel_binding: &[],
            invalidate: false,
            rotate_within_days: 7,
        },
    )
    .await
    .unwrap()
    {
        FastAuthentication::Success(verified) => verified,
        other => panic!("expected FAST success, got {other:?}"),
    };
    let plan = FastCommitPlan {
        token_id: Some(verified.id),
        token_was_new: verified.was_new,
        invalidate: false,
        issue: Some(FastTokenIssue {
            device_id,
            mechanism: "HT-SHA-256-ENDP".to_owned(),
            ttl_days: 30,
            strong_reauth_max_days: 90,
            inherited_chain: Some((verified.strong_auth_at, verified.chain_expires_at)),
        }),
    };

    // This is the exact transaction shape used by Bind 2. A route
    // conflict/Redis failure rolls it back before the pending route is
    // removed, so neither the installation epoch nor FAST slots change.
    let mut tx = northstar_auth_postgres::users::lock_auth_generation(&pool, user_id, 0)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        northstar_auth_postgres::users::next_user_agent_login_epoch_in_transaction(
            &mut tx, user_id, device_id, 0
        )
        .await
        .unwrap(),
        Some(1)
    );
    assert!(matches!(
        commit_fast_state_in_transaction(&mut tx, &master, user_id, 0, &plan)
            .await
            .unwrap(),
        FastCommitOutcome::Committed(Some(_))
    ));
    tx.rollback().await.unwrap();
    assert_bind_side_effects_absent(&pool, user_id, device_id, verified.id).await;

    // Exercise the production unbound-SASL2 helper. A late issuance
    // error occurs after both epoch allocation and promotion SQL have
    // run; dropping its transaction must leak neither side effect.
    let mut invalid_plan = plan.clone();
    invalid_plan.issue.as_mut().unwrap().mechanism = "unsupported".to_owned();
    assert!(commit_fast_state_with_login_epoch(
        &pool,
        &master,
        user_id,
        0,
        &invalid_plan,
        Some(device_id),
    )
    .await
    .is_err());
    assert_bind_side_effects_absent(&pool, user_id, device_id, verified.id).await;

    // Force a real commit-time PostgreSQL failure with a deferred FK.
    // The FAST/epoch writes share that transaction and must roll back.
    sqlx::query("CREATE TABLE IF NOT EXISTS test_fast_commit_parent(id BIGINT PRIMARY KEY)")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS test_fast_commit_child(
           id BIGINT PRIMARY KEY,
           parent_id BIGINT REFERENCES test_fast_commit_parent(id)
             DEFERRABLE INITIALLY DEFERRED
         )",
    )
    .execute(&pool)
    .await
    .unwrap();
    let mut tx = northstar_auth_postgres::users::lock_auth_generation(&pool, user_id, 0)
        .await
        .unwrap()
        .unwrap();
    northstar_auth_postgres::users::next_user_agent_login_epoch_in_transaction(
        &mut tx, user_id, device_id, 0,
    )
    .await
    .unwrap()
    .unwrap();
    assert!(matches!(
        commit_fast_state_in_transaction(&mut tx, &master, user_id, 0, &plan)
            .await
            .unwrap(),
        FastCommitOutcome::Committed(Some(_))
    ));
    sqlx::query("INSERT INTO test_fast_commit_child(id,parent_id) VALUES(1,999999)")
        .execute(&mut *tx)
        .await
        .unwrap();
    assert!(tx.commit().await.is_err());
    assert_bind_side_effects_absent(&pool, user_id, device_id, verified.id).await;
}

async fn assert_bind_side_effects_absent(
    pool: &PgPool,
    user_id: Uuid,
    device_id: Uuid,
    original_id: Uuid,
) {
    let rows: Vec<(Uuid, String, String)> = sqlx::query_as(
        "SELECT id,slot,mechanism FROM fast_tokens
         WHERE user_id=$1 AND device_id=$2 ORDER BY slot,id",
    )
    .bind(user_id)
    .bind(device_id)
    .fetch_all(pool)
    .await
    .unwrap();
    assert_eq!(
        rows,
        vec![(original_id, "new".to_owned(), "HT-SHA-256-NONE".to_owned())]
    );
    let epoch: Option<i64> = sqlx::query_scalar(
        "SELECT epoch FROM user_agent_login_epochs WHERE user_id=$1 AND device_id=$2",
    )
    .bind(user_id)
    .bind(device_id)
    .fetch_optional(pool)
    .await
    .unwrap();
    assert_eq!(epoch, None);
}
