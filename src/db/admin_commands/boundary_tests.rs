use super::*;
use sha2::Digest;
use std::time::Instant;

async fn database() -> PgPool {
    let url = std::env::var("TEST_DATABASE_URL")
        .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(8)
        .connect(&url)
        .await
        .unwrap();
    crate::db::migrate(&pool).await.unwrap();
    pool
}

async fn insert_account(pool: &PgPool, id: Uuid, username: &str, admin: bool) {
    sqlx::query(
        "INSERT INTO users(id,username,password_hash,is_admin)
             VALUES($1,$2,'test-only',$3)",
    )
    .bind(id)
    .bind(username)
    .bind(admin)
    .execute(pool)
    .await
    .unwrap();
}

async fn begin_test_execution(
    pool: &PgPool,
    actor_id: Uuid,
    actor_name: &str,
    node: &str,
    label: &str,
) -> (zeroize::Zeroizing<String>, AdminCommandClaim, Vec<u8>) {
    let owner = format!("{actor_name}@example.test/console");
    let bearer =
        create_admin_command_session(pool, actor_id, &owner, "example.test", 0, node, "form")
            .await
            .unwrap()
            .expect("test command session must be created");
    let digest = sha2::Sha256::digest(label.as_bytes()).to_vec();
    let claim = match begin_admin_command_execution(
        pool,
        bearer.as_str(),
        actor_id,
        &owner,
        0,
        node,
        &digest,
    )
    .await
    .unwrap()
    {
        AdminCommandExecutionState::Started(claim) => claim,
        other => panic!("unexpected execution outcome: {other:?}"),
    };
    (bearer, claim, digest)
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn service_control_poll_isolates_traffic_exhaustion_and_fails_closed_on_lock() {
    let pool = database().await;
    let url = std::env::var("TEST_DATABASE_URL")
        .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
    let traffic_pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_millis(100))
        .connect(&url)
        .await
        .unwrap();
    let control_pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .min_connections(1)
        .acquire_timeout(Duration::from_millis(500))
        .connect(&url)
        .await
        .unwrap();

    // Saturating the traffic pool must not prevent the separate
    // service-control connection from reading durable authority.
    let traffic_lease = traffic_pool.acquire().await.unwrap();
    let mut control_connection = control_pool.acquire().await.unwrap();
    assert!(
        poll_admin_service_control(&mut control_connection)
            .await
            .is_ok(),
        "a traffic-pool stall must not make service control unavailable"
    );
    drop(traffic_lease);

    let suffix = Uuid::new_v4().simple().to_string();
    let actor_id = Uuid::new_v4();
    let actor_name = format!("service-control-admin-{}", &suffix[..10]);
    insert_account(&pool, actor_id, &actor_name, true).await;
    assert!(
        schedule_admin_service_control(&pool, actor_id, 0, "shutdown", 5, None,)
            .await
            .unwrap()
            .is_some()
    );

    let lock_pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .unwrap();
    let mut lock = lock_pool.begin().await.unwrap();
    sqlx::query("SELECT singleton FROM admin_service_control WHERE singleton FOR UPDATE")
        .execute(&mut *lock)
        .await
        .unwrap();

    let started = Instant::now();
    let locked = poll_admin_service_control(&mut control_connection).await;
    assert!(
        locked.is_err(),
        "a locked control row must not be treated as healthy"
    );
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "a blocked control poll must fail below the three-second worker heartbeat deadline"
    );
    lock.rollback().await.unwrap();
    assert!(
        poll_admin_service_control(&mut control_connection)
            .await
            .unwrap()
            .is_none(),
        "a bounded lock failure must leave the scheduled control generation intact"
    );
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn admin_cleanup_effects_are_atomic_lease_fenced_and_compacted() {
    let pool = database().await;
    let suffix = Uuid::new_v4().simple().to_string();
    let actor_id = Uuid::new_v4();
    let target_id = Uuid::new_v4();
    let actor_name = format!("cleanup-admin-{}", &suffix[..10]);
    let target_name = format!("cleanup-user-{}", &suffix[..10]);
    insert_account(&pool, actor_id, &actor_name, true).await;
    insert_account(&pool, target_id, &target_name, false).await;
    let node = "http://jabber.org/protocol/admin#disable-user";
    let (_bearer, claim, digest) =
        begin_test_execution(&pool, actor_id, &actor_name, node, "cleanup-atomic").await;
    let targets = [AdminAccountMutationTarget {
        id: target_id,
        username: target_name.clone(),
        exact_full_jid: None,
    }];

    let failed = mutate_admin_accounts_authorized_with_failure_after(
        &pool,
        AdminCommandFence {
            claim_token: claim.token.as_str(),
            actor_id,
            actor_username: &actor_name,
            actor_generation: 0,
            node,
            target_digest: &digest,
            result_payload: "<done/>",
        },
        &targets,
        AdminAccountMutationAction::Disable,
        "example.test",
        1,
    )
    .await;
    assert!(
        failed.is_err(),
        "test fault must abort the command transaction"
    );
    assert!(
        !sqlx::query_scalar::<_, bool>("SELECT is_disabled FROM users WHERE id=$1")
            .bind(target_id)
            .fetch_one(&pool)
            .await
            .unwrap()
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM admin_session_cleanup_effects WHERE user_id=$1",
        )
        .bind(target_id)
        .fetch_one(&pool)
        .await
        .unwrap(),
        0,
        "a cleanup effect cannot escape a rolled-back mutation"
    );

    let foreign_domain = mutate_admin_accounts_authorized(
        &pool,
        AdminCommandFence {
            claim_token: claim.token.as_str(),
            actor_id,
            actor_username: &actor_name,
            actor_generation: 0,
            node,
            target_digest: &digest,
            result_payload: "<done/>",
        },
        &targets,
        AdminAccountMutationAction::Disable,
        "foreign.example",
    )
    .await;
    assert!(
        foreign_domain.is_err(),
        "the database issuer must reject a cleanup outside the command owner's XMPP domain"
    );
    assert!(
        !sqlx::query_scalar::<_, bool>("SELECT is_disabled FROM users WHERE id=$1")
            .bind(target_id)
            .fetch_one(&pool)
            .await
            .unwrap(),
        "a rejected foreign-domain cleanup must roll back the account mutation"
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM admin_session_cleanup_effects WHERE user_id=$1",
        )
        .bind(target_id)
        .fetch_one(&pool)
        .await
        .unwrap(),
        0,
        "a rejected foreign-domain cleanup must not consume queue capacity"
    );

    assert!(matches!(
        mutate_admin_accounts_authorized(
            &pool,
            AdminCommandFence {
                claim_token: claim.token.as_str(),
                actor_id,
                actor_username: &actor_name,
                actor_generation: 0,
                node,
                target_digest: &digest,
                result_payload: "<done/>",
            },
            &targets,
            AdminAccountMutationAction::Disable,
            "example.test",
        )
        .await
        .unwrap(),
        AdminBatchAccountWriteOutcome::Applied(_)
    ));
    let first_worker = Uuid::new_v4();
    let first = claim_admin_session_cleanup(&pool, first_worker, 60)
        .await
        .unwrap()
        .expect("committed mutation must publish one effect");
    assert_eq!(first.kind, AdminSessionCleanupKind::AccountGeneration);
    assert_eq!(first.user_id, target_id);
    assert_eq!(first.auth_generation, 1);
    assert!(
        retry_admin_session_cleanup(&pool, &first, first_worker, "test_retry")
            .await
            .unwrap()
    );
    sqlx::query(
        "UPDATE admin_session_cleanup_effects SET next_attempt_at=clock_timestamp()
              WHERE id=$1",
    )
    .bind(first.id)
    .execute(&pool)
    .await
    .unwrap();
    let second_worker_a = Uuid::new_v4();
    let second_worker_b = Uuid::new_v4();
    let (second_a, second_b) = tokio::join!(
        claim_admin_session_cleanup(&pool, second_worker_a, 60),
        claim_admin_session_cleanup(&pool, second_worker_b, 60),
    );
    let second_a = second_a.unwrap();
    let second_b = second_b.unwrap();
    assert_eq!(
        usize::from(second_a.is_some()) + usize::from(second_b.is_some()),
        1,
        "SKIP LOCKED must give a due effect to exactly one concurrent claimant"
    );
    let (second_worker, second) = match (second_a, second_b) {
        (Some(lease), None) => (second_worker_a, lease),
        (None, Some(lease)) => (second_worker_b, lease),
        _ => unreachable!("exactly one concurrent claimant was asserted"),
    };
    assert_eq!(second.id, first.id);
    assert!(
        !complete_admin_session_cleanup(&pool, &first, first_worker)
            .await
            .unwrap(),
        "a superseded lease cannot acknowledge the effect"
    );
    sqlx::query(
        "UPDATE admin_session_cleanup_effects
                SET lease_expires_at=clock_timestamp()-INTERVAL '1 second'
              WHERE id=$1",
    )
    .bind(second.id)
    .execute(&pool)
    .await
    .unwrap();
    let recovery_worker = Uuid::new_v4();
    let recovered = claim_admin_session_cleanup(&pool, recovery_worker, 60)
        .await
        .unwrap()
        .expect("an effect abandoned at the crash window must be reclaimed");
    assert_eq!(recovered.id, second.id);
    assert!(
        !complete_admin_session_cleanup(&pool, &second, second_worker)
            .await
            .unwrap(),
        "an expired worker lease cannot acknowledge a reclaimed effect"
    );
    assert!(
        complete_admin_session_cleanup(&pool, &recovered, recovery_worker)
            .await
            .unwrap()
    );
    let snapshot = admin_session_cleanup_snapshot(&pool).await.unwrap();
    assert_eq!(snapshot.queued, 0);
    assert_eq!(snapshot.pending + snapshot.running, 0);
    pool.close().await;
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn admin_cleanup_effects_survive_delete_and_do_not_retarget_rebinds() {
    let pool = database().await;
    let suffix = Uuid::new_v4().simple().to_string();
    let actor_id = Uuid::new_v4();
    let deleted_id = Uuid::new_v4();
    let actor_name = format!("delete-admin-{}", &suffix[..10]);
    let username = format!("delete-user-{}", &suffix[..10]);
    insert_account(&pool, actor_id, &actor_name, true).await;
    insert_account(&pool, deleted_id, &username, false).await;
    let delete_node = "http://jabber.org/protocol/admin#delete-user";
    let (_bearer, delete_claim, delete_digest) =
        begin_test_execution(&pool, actor_id, &actor_name, delete_node, "cleanup-delete").await;
    let mut deletion = pool.begin().await.unwrap();
    let issued: bool = sqlx::query_scalar(
        "SELECT northstar_admin_command_issue_delete_cleanup(
              $1,$2,$3,$4,$5,$6,$7,$8,$9)",
    )
    .bind(delete_claim.token.as_str())
    .bind(actor_id)
    .bind(&actor_name)
    .bind(0_i64)
    .bind(delete_node)
    .bind(&delete_digest)
    .bind(deleted_id)
    .bind(&username)
    .bind(format!("{username}@example.test"))
    .fetch_one(&mut *deletion)
    .await
    .unwrap();
    assert!(issued);
    let replayed: bool = sqlx::query_scalar(
        "SELECT northstar_admin_command_issue_delete_cleanup(
              $1,$2,$3,$4,$5,$6,$7,$8,$9)",
    )
    .bind(delete_claim.token.as_str())
    .bind(actor_id)
    .bind(&actor_name)
    .bind(0_i64)
    .bind(delete_node)
    .bind(&delete_digest)
    .bind(deleted_id)
    .bind(&username)
    .bind(format!("{username}@example.test"))
    .fetch_one(&mut *deletion)
    .await
    .unwrap();
    assert!(replayed);
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM admin_session_cleanup_effects
                  WHERE command_operation_id=$1",
        )
        .bind(delete_claim.operation_id)
        .fetch_one(&mut *deletion)
        .await
        .unwrap(),
        1,
        "replaying an issuer must not duplicate its stable effect"
    );
    sqlx::query("DELETE FROM users WHERE id=$1")
        .bind(deleted_id)
        .execute(&mut *deletion)
        .await
        .unwrap();
    deletion.commit().await.unwrap();
    let replacement_id = Uuid::new_v4();
    insert_account(&pool, replacement_id, &username, false).await;
    let delete_effect = sqlx::query(
        "SELECT user_id,auth_generation FROM admin_session_cleanup_effects
              WHERE command_operation_id=$1",
    )
    .bind(delete_claim.operation_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(delete_effect.get::<Uuid, _>("user_id"), deleted_id);
    assert_ne!(delete_effect.get::<Uuid, _>("user_id"), replacement_id);
    assert_eq!(delete_effect.get::<i64, _>("auth_generation"), 1);
    let worker = Uuid::new_v4();
    let lease = claim_admin_session_cleanup(&pool, worker, 60)
        .await
        .unwrap()
        .unwrap();
    assert!(complete_admin_session_cleanup(&pool, &lease, worker)
        .await
        .unwrap());

    let exact_target_id = Uuid::new_v4();
    let exact_name = format!("exact-user-{}", &suffix[..10]);
    insert_account(&pool, exact_target_id, &exact_name, false).await;
    let full_jid = format!("{exact_name}@example.test/phone");
    let sibling_jid = format!("{exact_name}@example.test/laptop");
    let old_connection = Uuid::new_v4();
    let sibling_connection = Uuid::new_v4();
    for (full, connection) in [
        (full_jid.as_str(), old_connection),
        (sibling_jid.as_str(), sibling_connection),
    ] {
        sqlx::query(
            "INSERT INTO deployment_session_leases(
                   lease_id,connection_id,user_id,full_jid,lease_until
                 ) VALUES($1,$1,$2,$3,clock_timestamp()+INTERVAL '5 minutes')",
        )
        .bind(connection)
        .bind(exact_target_id)
        .bind(full)
        .execute(&pool)
        .await
        .unwrap();
    }
    let exact_node = "http://jabber.org/protocol/admin#end-user-session";
    let (_bearer, exact_claim, exact_digest) =
        begin_test_execution(&pool, actor_id, &actor_name, exact_node, "cleanup-exact").await;
    let exact_outcome = mutate_admin_accounts_authorized(
        &pool,
        AdminCommandFence {
            claim_token: exact_claim.token.as_str(),
            actor_id,
            actor_username: &actor_name,
            actor_generation: 0,
            node: exact_node,
            target_digest: &exact_digest,
            result_payload: "<done/>",
        },
        &[AdminAccountMutationTarget {
            id: exact_target_id,
            username: exact_name,
            exact_full_jid: Some(full_jid.clone()),
        }],
        AdminAccountMutationAction::EndSessions,
        "example.test",
    )
    .await
    .unwrap();
    assert!(matches!(
        exact_outcome,
        AdminBatchAccountWriteOutcome::Applied(_)
    ));
    let worker = Uuid::new_v4();
    let exact_effect = claim_admin_session_cleanup(&pool, worker, 60)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(exact_effect.kind, AdminSessionCleanupKind::ExactConnection);
    assert!(
        admin_session_cleanup_target_current(&pool, &exact_effect, worker)
            .await
            .unwrap()
    );
    sqlx::query("UPDATE users SET auth_generation=auth_generation+1 WHERE id=$1")
        .bind(exact_target_id)
        .execute(&pool)
        .await
        .unwrap();
    assert!(
        !admin_session_cleanup_target_current(&pool, &exact_effect, worker)
            .await
            .unwrap(),
        "an exact effect cannot target a later account generation"
    );
    sqlx::query("UPDATE users SET auth_generation=auth_generation-1 WHERE id=$1")
        .bind(exact_target_id)
        .execute(&pool)
        .await
        .unwrap();
    assert!(
        admin_session_cleanup_target_current(&pool, &exact_effect, worker)
            .await
            .unwrap()
    );
    sqlx::query("DELETE FROM deployment_session_leases WHERE connection_id=$1")
        .bind(old_connection)
        .execute(&pool)
        .await
        .unwrap();
    let replacement_connection = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO deployment_session_leases(
               lease_id,connection_id,user_id,full_jid,lease_until
             ) VALUES($1,$1,$2,$3,clock_timestamp()+INTERVAL '5 minutes')",
    )
    .bind(replacement_connection)
    .bind(exact_target_id)
    .bind(&full_jid)
    .execute(&pool)
    .await
    .unwrap();
    assert!(
        !admin_session_cleanup_target_current(&pool, &exact_effect, worker)
            .await
            .unwrap(),
        "an old exact effect cannot retarget a replacement connection"
    );
    assert_eq!(
        sqlx::query_scalar::<_, Uuid>(
            "SELECT connection_id FROM deployment_session_leases WHERE full_jid=$1",
        )
        .bind(&sibling_jid)
        .fetch_one(&pool)
        .await
        .unwrap(),
        sibling_connection,
        "an exact effect cannot select a sibling full JID"
    );
    assert!(complete_admin_session_cleanup(&pool, &exact_effect, worker)
        .await
        .unwrap());
    pool.close().await;
}

// These pre-capability transaction tests are retained only as historical
// race documentation.  The executable positive/negative/concurrency
// coverage now lives in database-role-boundary-db-ci.sh, where the
// migrator, runtime, and command identities are actually distinct.
#[cfg(any())]
#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn admin_batch_rejects_concurrent_demotion_and_password_rotation() {
    let pool = database().await;
    let suffix = Uuid::new_v4().simple().to_string();
    let low = u64::from_be_bytes(Uuid::new_v4().as_bytes()[..8].try_into().unwrap());
    let target_id = Uuid::from_u128(low as u128);
    let actor_id = Uuid::from_u128((u128::from(u64::MAX) << 64) | low as u128);
    let actor_name = format!("admin-{}", &suffix[..12]);
    let target_name = format!("member-{}", &suffix[..12]);
    insert_account(&pool, actor_id, &actor_name, true).await;
    insert_account(&pool, target_id, &target_name, false).await;
    let targets = vec![AdminAccountMutationTarget {
        id: target_id,
        username: target_name.clone(),
        exact_full_jid: None,
    }];

    let mut blocker = pool.begin().await.unwrap();
    sqlx::query("SELECT id FROM users WHERE id=$1 FOR UPDATE")
        .bind(target_id)
        .fetch_one(&mut *blocker)
        .await
        .unwrap();
    let task_pool = pool.clone();
    let task_targets = targets.clone();
    let task_actor = actor_name.clone();
    let task = tokio::spawn(async move {
        mutate_admin_accounts_authorized(
            &task_pool,
            actor_id,
            &task_actor,
            0,
            &task_targets,
            AdminAccountMutationAction::Disable,
            "example.test",
        )
        .await
        .unwrap()
    });
    tokio::task::yield_now().await;
    sqlx::query("UPDATE users SET is_admin=FALSE WHERE id=$1")
        .bind(actor_id)
        .execute(&pool)
        .await
        .unwrap();
    blocker.rollback().await.unwrap();
    assert_eq!(
        task.await.unwrap(),
        AdminBatchAccountWriteOutcome::Unauthorized
    );
    assert!(
        !sqlx::query_scalar::<_, bool>("SELECT is_disabled FROM users WHERE id=$1")
            .bind(target_id)
            .fetch_one(&pool)
            .await
            .unwrap()
    );

    sqlx::query("UPDATE users SET is_admin=TRUE WHERE id=$1")
        .bind(actor_id)
        .execute(&pool)
        .await
        .unwrap();
    let mut blocker = pool.begin().await.unwrap();
    sqlx::query("SELECT id FROM users WHERE id=$1 FOR UPDATE")
        .bind(target_id)
        .fetch_one(&mut *blocker)
        .await
        .unwrap();
    let task_pool = pool.clone();
    let task_targets = targets.clone();
    let task = tokio::spawn(async move {
        mutate_admin_accounts_authorized(
            &task_pool,
            actor_id,
            &actor_name,
            0,
            &task_targets,
            AdminAccountMutationAction::Disable,
            "example.test",
        )
        .await
        .unwrap()
    });
    tokio::task::yield_now().await;
    sqlx::query("UPDATE users SET auth_generation=auth_generation+1 WHERE id=$1")
        .bind(actor_id)
        .execute(&pool)
        .await
        .unwrap();
    blocker.rollback().await.unwrap();
    assert_eq!(
        task.await.unwrap(),
        AdminBatchAccountWriteOutcome::Unauthorized
    );
    assert!(
        !sqlx::query_scalar::<_, bool>("SELECT is_disabled FROM users WHERE id=$1")
            .bind(target_id)
            .fetch_one(&pool)
            .await
            .unwrap()
    );
}

#[cfg(any())]
#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn admin_batch_fences_target_delete_recreate_incarnation() {
    let pool = database().await;
    let suffix = Uuid::new_v4().simple().to_string();
    // Make the actor the first row in the batch's UUID lock order. Holding
    // it lets the competing transaction replace the still-unlocked target
    // after command resolution but before the authoritative recheck.
    let low = u64::from_be_bytes(Uuid::new_v4().as_bytes()[..8].try_into().unwrap());
    let actor_id = Uuid::from_u128(low as u128);
    let old_id = Uuid::from_u128((u128::from(u64::MAX) << 64) | low as u128);
    let replacement_id = Uuid::new_v4();
    let actor_name = format!("admin-{}", &suffix[..12]);
    let username = format!("replace-{}", &suffix[..12]);
    insert_account(&pool, actor_id, &actor_name, true).await;
    insert_account(&pool, old_id, &username, false).await;

    let mut blocker = pool.begin().await.unwrap();
    sqlx::query("SELECT id FROM users WHERE id=$1 FOR UPDATE")
        .bind(actor_id)
        .fetch_one(&mut *blocker)
        .await
        .unwrap();
    let task_pool = pool.clone();
    let task_actor = actor_name.clone();
    let task_username = username.clone();
    let task = tokio::spawn(async move {
        mutate_admin_accounts_authorized(
            &task_pool,
            actor_id,
            &task_actor,
            0,
            &[AdminAccountMutationTarget {
                id: old_id,
                username: task_username,
                exact_full_jid: None,
            }],
            AdminAccountMutationAction::Disable,
            "example.test",
        )
        .await
        .unwrap()
    });
    tokio::task::yield_now().await;
    sqlx::query("DELETE FROM users WHERE id=$1")
        .bind(old_id)
        .execute(&pool)
        .await
        .unwrap();
    insert_account(&pool, replacement_id, &username, false).await;
    blocker.rollback().await.unwrap();
    let outcome = task.await.unwrap();
    assert_eq!(outcome, AdminBatchAccountWriteOutcome::TargetChanged);
    assert!(
        !sqlx::query_scalar::<_, bool>("SELECT is_disabled FROM users WHERE id=$1")
            .bind(replacement_id)
            .fetch_one(&pool)
            .await
            .unwrap()
    );
}

#[cfg(any())]
#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn admin_batch_mid_request_failure_rolls_back_every_target_and_audit() {
    let pool = database().await;
    let suffix = Uuid::new_v4().simple().to_string();
    let actor_id = Uuid::new_v4();
    let actor_name = format!("admin-{}", &suffix[..12]);
    insert_account(&pool, actor_id, &actor_name, true).await;
    let mut targets = Vec::new();
    for index in 0..2 {
        let id = Uuid::new_v4();
        let username = format!("rollback-{index}-{}", &suffix[..10]);
        insert_account(&pool, id, &username, false).await;
        targets.push(AdminAccountMutationTarget {
            id,
            username,
            exact_full_jid: None,
        });
    }
    assert!(mutate_admin_accounts_authorized_with_failure_after(
        &pool,
        actor_id,
        &actor_name,
        0,
        &targets,
        AdminAccountMutationAction::Disable,
        "example.test",
        1,
    )
    .await
    .is_err());
    let disabled: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE id=ANY($1) AND is_disabled")
            .bind(targets.iter().map(|target| target.id).collect::<Vec<_>>())
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(disabled, 0);
    let audits: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit_log
             WHERE actor_id=$1 AND action='admin.user.update'",
    )
    .bind(actor_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(audits, 0);
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn admin_command_same_request_retry_replays_one_terminal_result() {
    let pool = database().await;
    let suffix = Uuid::new_v4().simple().to_string();
    let actor_id = Uuid::new_v4();
    let actor_name = format!("admin-{}", &suffix[..12]);
    insert_account(&pool, actor_id, &actor_name, true).await;
    let owner = format!("{actor_name}@example.test/console");
    let node = "http://jabber.org/protocol/admin#get-registered-users-list";
    let bearer =
        create_admin_command_session(&pool, actor_id, &owner, "example.test", 0, node, "form")
            .await
            .unwrap()
            .unwrap();
    let digest = sha2::Sha256::digest(b"same-request").to_vec();
    let claim = match begin_admin_command_execution(
        &pool,
        bearer.as_str(),
        actor_id,
        &owner,
        0,
        node,
        &digest,
    )
    .await
    .unwrap()
    {
        AdminCommandExecutionState::Started(claim) => claim,
        other => panic!("unexpected execution outcome: {other:?}"),
    };
    let payload = "<x xmlns='jabber:x:data' type='result'/>";
    assert!(complete_admin_command_read_execution(
        &pool,
        claim.token.as_str(),
        actor_id,
        &actor_name,
        0,
        node,
        &digest,
        payload,
    )
    .await
    .unwrap());
    assert_eq!(
        begin_admin_command_execution(&pool, bearer.as_str(), actor_id, &owner, 0, node, &digest,)
            .await
            .unwrap(),
        AdminCommandExecutionState::Completed(payload.to_owned())
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM audit_log
                 WHERE actor_id=$1 AND action='admin.command.read' AND target=$2",
        )
        .bind(actor_id)
        .bind(node)
        .fetch_one(&pool)
        .await
        .unwrap(),
        1
    );
}
