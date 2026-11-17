use northstar_session_postgres::replay::*;
use uuid::Uuid;

#[tokio::test]
#[ignore = "requires the ordinary-role random schema and TEST_DATABASE_URL"]
async fn replay_replacement_preserves_other_resources_and_rejects_stale_tokens() {
    let pool = crate::support::operation_mutation_pool().await;
    let user = Uuid::from_u128(0x573_2301);
    let old_token = Uuid::from_u128(0x573_2302);
    let replacement_token = Uuid::from_u128(0x573_2303);
    let other_token = Uuid::from_u128(0x573_2304);
    sqlx::query(
        "INSERT INTO users(id,username,password_hash) VALUES($1,'replay-fence','test-only')",
    )
    .bind(user)
    .execute(&pool)
    .await
    .unwrap();
    let acquire = |resource: &'static str, token| {
        acquire_offline_replay_lease(&pool, user, resource, token, None, 75)
    };
    let OfflineReplayLeaseAcquire::Acquired(old) = acquire("phone", old_token).await.unwrap()
    else {
        panic!("first resource was not acquired");
    };
    let OfflineReplayLeaseAcquire::Acquired(other) = acquire("desktop", other_token).await.unwrap()
    else {
        panic!("independent resource was not acquired");
    };
    assert!(matches!(
        acquire("phone", replacement_token).await.unwrap(),
        OfflineReplayLeaseAcquire::BusyUntil(_)
    ));
    let duration: f64 = sqlx::query_scalar(
        "SELECT EXTRACT(EPOCH FROM expires_at-acquired_at)::float8
         FROM offline_replay_leases WHERE recipient_id=$1 AND resource='phone'",
    )
    .bind(user)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(duration, 75.0, "minimum owner lease");
    assert!(
        acquire_offline_replay_lease(&pool, user, "short", old_token, None, 74)
            .await
            .is_err()
    );

    sqlx::query("UPDATE offline_replay_leases SET acquired_at=renewed_at-INTERVAL '2 minutes',renewed_at=renewed_at-INTERVAL '2 minutes',expires_at=renewed_at-INTERVAL '1 second' WHERE recipient_id=$1 AND resource='phone'")
        .bind(user).execute(&pool).await.unwrap();
    let OfflineReplayLeaseAcquire::Acquired(replacement) =
        acquire("phone", replacement_token).await.unwrap()
    else {
        panic!("expired resource was not replaced");
    };
    let page = Uuid::from_u128(0x573_2305);
    let message = Uuid::from_u128(0x573_2306);
    sqlx::query("INSERT INTO offline_messages(id,recipient_id,sender_jid,stanza,encrypted,delivery_claim_id,delivery_claim_expires_at) VALUES($1,$2,'peer@remote.test','<message/>',FALSE,$3,clock_timestamp()+INTERVAL '90 seconds')")
        .bind(message).bind(user).bind(page).execute(&pool).await.unwrap();
    assert!(
        matches!(
            claim_offline_replay_page(
                &pool,
                &old,
                30,
                "replay-fence@example.test",
                "replay-fence@example.test/phone",
                None,
                false,
                75
            )
            .await
            .unwrap(),
            OfflineReplayPageOutcome::LeaseLost
        ),
        "stale owner cannot claim"
    );
    assert!(
        !renew_offline_replay_before_send(&pool, &old, page, &[message], 75)
            .await
            .unwrap(),
        "stale owner cannot renew even a valid page suffix"
    );
    assert!(
        renew_offline_replay_before_send(&pool, &replacement, page, &[message], 75)
            .await
            .unwrap(),
        "current owner renews that same page suffix"
    );
    assert!(
        release_untransferred_offline_claims(&pool, user, Uuid::from_u128(0x573_2307), &[message])
            .await
            .is_err(),
        "stale page token cannot release the replacement suffix"
    );
    assert!(
        !release_offline_replay_lease(&pool, &old).await.unwrap(),
        "stale owner cannot release"
    );
    let mut observer = pool.acquire().await.unwrap();
    let owners: Vec<(String, Uuid)> = sqlx::query_as(
        "SELECT resource,owner_token FROM offline_replay_leases WHERE recipient_id=$1 ORDER BY resource",
    ).bind(user).fetch_all(&mut *observer).await.unwrap();
    assert_eq!(
        owners,
        vec![
            ("desktop".to_owned(), other_token),
            ("phone".to_owned(), replacement_token)
        ]
    );
    let preserved: Uuid =
        sqlx::query_scalar("SELECT delivery_claim_id FROM offline_messages WHERE id=$1")
            .bind(message)
            .fetch_one(&mut *observer)
            .await
            .unwrap();
    assert_eq!(preserved, page, "replacement page claim remains intact");
    drop(observer);

    let mut invalid = pool.begin().await.unwrap();
    assert!(sqlx::query("UPDATE offline_replay_leases SET resource='renamed' WHERE recipient_id=$1 AND resource='phone'")
        .bind(user).execute(&mut *invalid).await.is_err(), "resource identity is immutable");
    invalid.rollback().await.unwrap();
    assert!(release_offline_replay_lease(&pool, &replacement)
        .await
        .unwrap());
    assert!(release_offline_replay_lease(&pool, &other).await.unwrap());
    sqlx::query("DELETE FROM users WHERE id=$1")
        .bind(user)
        .execute(&pool)
        .await
        .unwrap();
    pool.close().await;
}
