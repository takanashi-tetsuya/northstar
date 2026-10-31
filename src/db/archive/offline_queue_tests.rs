//! Offline queue and message deduplication tests.

use super::*;
use crate::db;
use northstar_abuse_policy::{AbuseConfig, MessageDedupeCandidate, MessageDedupeIdentity};
use std::sync::Arc;
use tokio::sync::Barrier;

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn concurrent_writers_reject_new_message_instead_of_evicting_old_history() {
    let url = std::env::var("TEST_DATABASE_URL")
        .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(8)
        .connect(&url)
        .await
        .unwrap();
    db::migrate(&pool).await.unwrap();
    let user_id = Uuid::new_v4();
    sqlx::query("INSERT INTO users (id, username, password_hash) VALUES ($1, $2, 'test')")
        .bind(user_id)
        .bind(format!("offline-{}", &user_id.simple().to_string()[..12]))
        .execute(&pool)
        .await
        .unwrap();
    let barrier = Arc::new(Barrier::new(3));
    let mut tasks = Vec::new();
    for id in ["one", "two"] {
        let pool = pool.clone();
        let barrier = Arc::clone(&barrier);
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            store_offline(
                &pool,
                user_id,
                "sender@example.test/Phone",
                &format!("<message id='{id}'/>"),
                true,
                OfflineStorePolicy {
                    max_messages: 1,
                    max_bytes: 1024,
                    ttl_days: 30,
                    mam_backed: false,
                },
            )
            .await
            .unwrap()
        }));
    }
    barrier.wait().await;
    let outcomes = futures::future::join_all(tasks)
        .await
        .into_iter()
        .map(|result| result.unwrap())
        .collect::<Vec<_>>();
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| **outcome == OfflineStoreOutcome::Stored)
            .count(),
        1
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| **outcome == OfflineStoreOutcome::QuotaExceeded)
            .count(),
        1
    );
    assert_eq!(offline_message_count(&pool, user_id).await.unwrap(), 1);
    sqlx::query("DELETE FROM users WHERE id=$1")
        .bind(user_id)
        .execute(&pool)
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn offline_dedupe_rotation_grace_capacity_and_cleanup_are_bounded() {
    let url = std::env::var("TEST_DATABASE_URL")
        .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(8)
        .connect(&url)
        .await
        .unwrap();
    db::migrate(&pool).await.unwrap();
    let marker = Uuid::new_v4();
    let user_id = Uuid::new_v4();
    sqlx::query("INSERT INTO users (id, username, password_hash) VALUES ($1, $2, 'test')")
        .bind(user_id)
        .bind(format!("dedupe-{}", &marker.simple().to_string()[..12]))
        .execute(&pool)
        .await
        .unwrap();
    let policy = OfflineStorePolicy {
        max_messages: 10_000,
        max_bytes: 64 * 1_048_576,
        ttl_days: 365,
        mam_backed: false,
    };
    let old_mac = vec![0x11; 32];
    let new_mac = vec![0x22; 32];
    let digest = sha2::Sha256::digest(format!("offline:{marker}").as_bytes()).to_vec();
    let old_identity = MessageDedupeIdentity {
        identity_digest: digest.clone(),
        candidates: vec![MessageDedupeCandidate {
            key_id: "old-key".to_owned(),
            payload_mac: old_mac.clone(),
        }],
    };
    assert_eq!(
        store_offline_idempotent(
            &pool,
            user_id,
            "alice@example.test/Phone",
            "<message id='dedupe-one'/>",
            true,
            policy,
            Some(&old_identity),
        )
        .await
        .unwrap(),
        OfflineStoreOutcome::Stored
    );

    // During the rolling overlap, old-only nodes still coexist. The old
    // key therefore remains primary for fresh writes while the new
    // authenticator is carried as the secondary candidate.
    let rotated_identity = MessageDedupeIdentity {
        identity_digest: digest.clone(),
        candidates: vec![
            MessageDedupeCandidate {
                key_id: "old-key".to_owned(),
                payload_mac: old_mac,
            },
            MessageDedupeCandidate {
                key_id: "new-key".to_owned(),
                payload_mac: new_mac,
            },
        ],
    };
    assert_eq!(
        store_offline_idempotent(
            &pool,
            user_id,
            "alice@example.test/Phone",
            "<message id='dedupe-one'/>",
            true,
            policy,
            Some(&rotated_identity),
        )
        .await
        .unwrap(),
        OfflineStoreOutcome::Replay
    );
    let conflicting_identity = MessageDedupeIdentity {
        identity_digest: digest.clone(),
        candidates: vec![MessageDedupeCandidate {
            key_id: "old-key".to_owned(),
            payload_mac: vec![0x33; 32],
        }],
    };
    assert!(store_offline_idempotent(
        &pool,
        user_id,
        "alice@example.test/Phone",
        "<message id='changed'/>",
        true,
        policy,
        Some(&conflicting_identity),
    )
    .await
    .unwrap_err()
    .to_string()
    .contains("conflicting offline message identity"));
    assert_eq!(offline_message_count(&pool, user_id).await.unwrap(), 1);

    let (tx, mut rx) = tokio::sync::mpsc::channel(2);
    let tx = crate::xmpp::outbound::OutboundSender::new(tx);
    assert_eq!(
        deliver_offline(&pool, user_id, 365, &tx, None)
            .await
            .unwrap(),
        1
    );
    drop(tx);
    let delivered = rx.recv().await.unwrap();
    crate::db::replay::acknowledge_durable_delivery(&pool, delivered.c2s_delivery().unwrap())
        .await
        .unwrap();
    assert_eq!(delivered.stanza, "<message id='dedupe-one'/>");
    assert!(rx.recv().await.is_none());
    assert_eq!(offline_message_count(&pool, user_id).await.unwrap(), 0);
    let remaining_grace_seconds: f64 = sqlx::query_scalar(
        "SELECT EXTRACT(EPOCH FROM (expires_at-clock_timestamp()))::float8
               FROM offline_message_admissions WHERE identity_digest=$1",
    )
    .bind(&digest)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(
        (30.0 * 86_400.0 - 30.0..=30.0 * 86_400.0).contains(&remaining_grace_seconds),
        "post-delivery replay grace was not bounded to 30 days: {remaining_grace_seconds}"
    );
    assert_eq!(
        store_offline_idempotent(
            &pool,
            user_id,
            "alice@example.test/Phone",
            "<message id='dedupe-one'/>",
            true,
            policy,
            Some(&rotated_identity),
        )
        .await
        .unwrap(),
        OfflineStoreOutcome::Replay
    );
    assert_eq!(offline_message_count(&pool, user_id).await.unwrap(), 0);

    // Fill the recipient limit with compact detached tombstones. The
    // rejected business insert must not leak an offline row or capacity
    // reservation; deleting the fixture immediately restores service.
    let fixture_shard = 63_i16;
    let existing_for_user: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM offline_message_admissions WHERE recipient_id=$1")
            .bind(user_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    let fixture_count = MAX_OFFLINE_DEDUPE_PER_RECIPIENT - existing_for_user;
    let mut fixture_tx = pool.begin().await.unwrap();
    sqlx::query(
        "UPDATE offline_message_admission_capacity
                SET active_records=active_records+$2 WHERE shard=$1",
    )
    .bind(fixture_shard)
    .bind(i32::try_from(fixture_count).unwrap())
    .execute(&mut *fixture_tx)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO offline_message_admissions
             (identity_digest,payload_key_id,recipient_id,capacity_shard,payload_mac,expires_at)
             SELECT decode(md5('offline-fixture:' || $1 || value::text) ||
                           md5('offline-fixture-key:' || $1 || value::text),'hex'),
                    'recipient-fixture',$2,$3,
                    decode(md5('offline-payload:' || $1 || value::text) ||
                           md5('offline-mac:' || $1 || value::text),'hex'),
                    clock_timestamp()+INTERVAL '30 days'
               FROM generate_series(1,$4::integer) AS value",
    )
    .bind(marker.simple().to_string())
    .bind(user_id)
    .bind(fixture_shard)
    .bind(i32::try_from(fixture_count).unwrap())
    .execute(&mut *fixture_tx)
    .await
    .unwrap();
    fixture_tx.commit().await.unwrap();
    let overflow_digest = sha2::Sha256::digest(format!("overflow:{marker}").as_bytes()).to_vec();
    let overflow_identity = MessageDedupeIdentity {
        identity_digest: overflow_digest,
        candidates: vec![MessageDedupeCandidate {
            key_id: "new-key".to_owned(),
            payload_mac: vec![0x44; 32],
        }],
    };
    assert_eq!(
        store_offline_idempotent(
            &pool,
            user_id,
            "alice@example.test/Phone",
            "<message id='recipient-overflow'/>",
            true,
            policy,
            Some(&overflow_identity),
        )
        .await
        .unwrap(),
        OfflineStoreOutcome::QuotaExceeded
    );
    assert_eq!(offline_message_count(&pool, user_id).await.unwrap(), 0);
    sqlx::query("DELETE FROM offline_message_admissions WHERE payload_key_id='recipient-fixture'")
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(
        store_offline_idempotent(
            &pool,
            user_id,
            "alice@example.test/Phone",
            "<message id='recipient-overflow'/>",
            true,
            policy,
            Some(&overflow_identity),
        )
        .await
        .unwrap(),
        OfflineStoreOutcome::Stored
    );

    // A full target shard is a hard global bound. Its rejection rolls
    // back the queue row, and the trigger-backed counter equals physical
    // rows again after restoring the fixture.
    let global_digest = sha2::Sha256::digest(format!("global:{marker}").as_bytes()).to_vec();
    let global_shard = i16::from(global_digest[0] % OFFLINE_DEDUPE_CAPACITY_SHARDS);
    let actual_shard_count: i32 = sqlx::query_scalar(
        "SELECT COUNT(*)::integer FROM offline_message_admissions WHERE capacity_shard=$1",
    )
    .bind(global_shard)
    .fetch_one(&pool)
    .await
    .unwrap();
    sqlx::query("UPDATE offline_message_admission_capacity SET active_records=$2 WHERE shard=$1")
        .bind(global_shard)
        .bind(MAX_OFFLINE_DEDUPE_PER_SHARD)
        .execute(&pool)
        .await
        .unwrap();
    let global_identity = MessageDedupeIdentity {
        identity_digest: global_digest,
        candidates: vec![MessageDedupeCandidate {
            key_id: "new-key".to_owned(),
            payload_mac: vec![0x55; 32],
        }],
    };
    assert_eq!(
        store_offline_idempotent(
            &pool,
            user_id,
            "alice@example.test/Phone",
            "<message id='global-overflow'/>",
            true,
            policy,
            Some(&global_identity),
        )
        .await
        .unwrap(),
        OfflineStoreOutcome::QuotaExceeded
    );
    assert_eq!(offline_message_count(&pool, user_id).await.unwrap(), 1);
    sqlx::query("UPDATE offline_message_admission_capacity SET active_records=$2 WHERE shard=$1")
        .bind(global_shard)
        .bind(actual_shard_count)
        .execute(&pool)
        .await
        .unwrap();

    // Background cleanup is bounded to one batch and the DELETE trigger
    // releases every slot transactionally.
    let cleanup_count = 1_001_i32;
    let cleanup_shard = 62_i16;
    let mut cleanup_tx = pool.begin().await.unwrap();
    sqlx::query(
        "UPDATE offline_message_admission_capacity
                SET active_records=active_records+$2 WHERE shard=$1",
    )
    .bind(cleanup_shard)
    .bind(cleanup_count)
    .execute(&mut *cleanup_tx)
    .await
    .unwrap();
    sqlx::query(
             "INSERT INTO offline_message_admissions
             (identity_digest,payload_key_id,recipient_id,capacity_shard,payload_mac,created_at,expires_at)
             SELECT decode(md5('offline-expired:' || $1 || value::text) ||
                           md5('offline-expired-key:' || $1 || value::text),'hex'),
                    'cleanup-expired',$2,$3,
                    decode(md5('offline-expired-payload:' || $1 || value::text) ||
                           md5('offline-expired-mac:' || $1 || value::text),'hex'),
                    clock_timestamp()-INTERVAL '2 seconds',
                    clock_timestamp()-INTERVAL '1 second'
               FROM generate_series(1,$4::integer) AS value",
        )
        .bind(marker.simple().to_string())
        .bind(user_id)
        .bind(cleanup_shard)
        .bind(cleanup_count)
        .execute(&mut *cleanup_tx)
        .await
        .unwrap();
    cleanup_tx.commit().await.unwrap();
    let guard = crate::db::abuse_effects::persistent_guard(
        AbuseConfig {
            base_work_factor: 2,
            max_work_factor: 4_096,
            window: Duration::from_secs(60),
            cooldown_step: Duration::from_secs(60),
            max_wait: Duration::from_secs(8),
            message_free_burst: 60,
            approximate_max_device_seconds: 8,
        },
        pool.clone(),
        Some(b"offline-cleanup-test-key-at-least-32-bytes"),
        None,
    );
    guard.cleanup_challenges().await.unwrap();
    assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM offline_message_admissions WHERE payload_key_id='cleanup-expired'",
            )
            .fetch_one(&pool)
            .await
            .unwrap(),
            1
        );
    guard.cleanup_challenges().await.unwrap();
    assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM offline_message_admissions WHERE payload_key_id='cleanup-expired'",
            )
            .fetch_one(&pool)
            .await
            .unwrap(),
            0
        );
    let counters_match: bool = sqlx::query_scalar(
        "SELECT NOT EXISTS(
                 SELECT 1 FROM offline_message_admission_capacity capacity
                  WHERE capacity.active_records <> (
                    SELECT COUNT(*)::integer FROM offline_message_admissions admission
                     WHERE admission.capacity_shard=capacity.shard
                  )
             )",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(counters_match);

    sqlx::query("DELETE FROM users WHERE id=$1")
        .bind(user_id)
        .execute(&pool)
        .await
        .unwrap();
    pool.close().await;
}
