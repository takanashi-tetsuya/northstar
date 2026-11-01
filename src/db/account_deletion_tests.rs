use northstar_workflows::account_deletion::*;
use uuid::Uuid;

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn deletion_recovery_is_delayed_single_owner_and_cascading() {
    let url = std::env::var("TEST_DATABASE_URL")
        .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(8)
        .connect(&url)
        .await
        .unwrap();
    crate::db::migrate(&pool).await.unwrap();
    let username = format!("delete-recovery-{}", Uuid::new_v4());
    let user = northstar_auth_postgres::users::create_user(
        &pool,
        &username,
        "recovery-passphrase",
        false,
        true,
        4096,
        false,
    )
    .await
    .unwrap();
    // A personal-message identity is intentionally retained when its MAM
    // projection expires, but must not outlive the account that owns its
    // actor scope.  Exercise the audited XEP-0077 path rather than the
    // test-only direct DELETE path in users.rs.
    let account_jid = format!("{username}@example.test");
    let archive_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO message_archive
         (id,owner_id,peer_jid,peer_full_jid,stanza,encrypted)
         VALUES($1,$2,'peer@example.test','peer@example.test',
                '<message xmlns=\"jabber:client\"/>',FALSE)",
    )
    .bind(archive_id)
    .bind(user.id)
    .execute(&pool)
    .await
    .unwrap();
    let admission_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO personal_message_admissions
         (id,identity_kind,actor_scope_raw,actor_scope,target_scope,identity_value,
          identity_digest,payload_key_id,payload_mac,sender_archive_id)
         VALUES($1,'local-origin',$2,$2,'peer@example.test','delete-recovery',$3,
                'AAAAAAAAAAAAAAAA',$4,$5)",
    )
    .bind(admission_id)
    .bind(&account_jid)
    .bind(vec![0x61_u8; 32])
    .bind(vec![0x62_u8; 32])
    .bind(archive_id)
    .execute(&pool)
    .await
    .unwrap();
    assert!(
        northstar_workflows::account_lifecycle::begin_account_deletion_quiesce(&pool, user.id)
            .await
            .unwrap()
    );
    assert!(claim_account_deletion_jobs(&pool, 8, 60)
        .await
        .unwrap()
        .is_empty());

    sqlx::query(
        "UPDATE account_deletion_requests SET recovery_after=clock_timestamp()-INTERVAL '1 second' WHERE user_id=$1",
    )
    .bind(user.id)
    .execute(&pool)
    .await
    .unwrap();
    let left = claim_account_deletion_jobs(&pool, 8, 60);
    let right = claim_account_deletion_jobs(&pool, 8, 60);
    let (left, right) = tokio::join!(left, right);
    let mut claimed = left.unwrap();
    claimed.extend(right.unwrap());
    assert_eq!(claimed.len(), 1);
    let job = claimed.pop().unwrap();
    assert_eq!(job.user_id, user.id);
    assert_eq!(job.username, username);

    let wrong = AccountDeletionJob::from_lease(
        job.user_id,
        job.username.clone(),
        Uuid::new_v4(),
        job.attempts(),
    );
    assert!(
        !release_account_deletion_job(&pool, &wrong, "injected-failure")
            .await
            .unwrap()
    );
    assert!(
        release_account_deletion_job(&pool, &job, "injected-failure")
            .await
            .unwrap()
    );

    northstar_workflows::account_lifecycle::delete_user_with_roster_audited(
        &crate::db::roster::RootRosterEffects,
        &pool,
        user.id,
        "example.test",
        serde_json::json!({"source":"test"}),
    )
    .await
    .unwrap()
    .unwrap();
    let remaining: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM account_deletion_requests WHERE user_id=$1")
            .bind(user.id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(remaining, 0);
    let retained_admissions: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM personal_message_admissions WHERE id=$1")
            .bind(admission_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(retained_admissions, 0);
}
