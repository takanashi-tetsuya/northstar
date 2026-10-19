//! Storage cleanup, queue snapshot and claim lifecycle tests.

use super::*;

#[test]
fn s3_same_key_cleanup_uses_the_exact_stage_version() {
    assert_eq!(
        cleanup_object_version(
            "s3",
            "objects/id/attempt",
            None,
            Some("objects/id/attempt"),
            Some("version-7"),
        )
        .as_deref(),
        Some("version-7")
    );
    assert_eq!(
        cleanup_object_version(
            "local",
            "id",
            None,
            Some("staging/id/attempt"),
            Some("ignored-stage-version"),
        ),
        None
    );
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn upload_queue_snapshot_reads_committed_changes_on_the_same_backend() {
    let url = std::env::var("TEST_DATABASE_URL").expect("set TEST_DATABASE_URL");
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .unwrap();
    db::migrate(&pool).await.unwrap();
    validate_upload_capacity_policy(
        &pool,
        TEST_UPLOAD_PENDING_LIMIT,
        TEST_UPLOAD_RETAINED_FILES_LIMIT,
        TEST_UPLOAD_RETAINED_BYTES_LIMIT,
    )
    .await
    .unwrap();
    sqlx::query("CREATE TEMP TABLE upload_storage_capacity_ledger(singleton bool)")
        .execute(&pool)
        .await
        .unwrap();
    let before = upload_queue_metrics(&pool).await.unwrap();
    let user_id = insert_user(&pool).await;
    let token = b"snapshot-current-data";
    let slot_id = create_upload_slot(
        &pool,
        UploadReservation {
            user_id,
            filename: "snapshot.bin",
            content_type: "application/octet-stream",
            size: 4,
            token_hash: token,
            max_files_per_user: 100,
            max_bytes_per_user: 1_000,
            storage_backend: "local",
        },
    )
    .await
    .unwrap()
    .unwrap();
    let lease = match claim_upload_slot(&pool, slot_id, token, 90).await.unwrap() {
        UploadClaimOutcome::Acquired(lease) => lease,
        other => panic!("unexpected upload claim outcome: {other:?}"),
    };
    let claimed = upload_queue_metrics(&pool).await.unwrap();
    assert_eq!(
        claimed.cleanup_obligation_debt,
        before.cleanup_obligation_debt + 1
    );
    assert!(release_upload_claim(&pool, slot_id, lease.claim_token)
        .await
        .unwrap());
    let released = upload_queue_metrics(&pool).await.unwrap();
    assert_eq!(
        released.cleanup_obligation_debt,
        before.cleanup_obligation_debt
    );
    assert_eq!(
        released.storage_jobs_pending,
        before.storage_jobs_pending + 1
    );
    sqlx::query("DELETE FROM upload_storage_jobs WHERE object_id=$1")
        .bind(slot_id)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM users WHERE id=$1")
        .bind(user_id)
        .execute(&pool)
        .await
        .unwrap();
    pool.close().await;
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn upload_claim_is_atomic_and_cleanup_is_retryable() {
    let url = std::env::var("TEST_DATABASE_URL")
        .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(16)
        .connect(&url)
        .await
        .unwrap();
    db::migrate(&pool).await.unwrap();
    // Production binds this durable deployment authority in AppState
    // before opening any listener. Mirror that startup boundary here: an
    // unbound policy intentionally rejects every new cleanup obligation.
    validate_upload_capacity_policy(
        &pool,
        TEST_UPLOAD_PENDING_LIMIT,
        TEST_UPLOAD_RETAINED_FILES_LIMIT,
        TEST_UPLOAD_RETAINED_BYTES_LIMIT,
    )
    .await
    .unwrap();

    let user_id = insert_user(&pool).await;
    let token_hash = b"concurrent-test-token-hash".to_vec();
    let slot_id = create_upload_slot(
        &pool,
        UploadReservation {
            user_id,
            filename: "concurrent.bin",
            content_type: "application/octet-stream",
            size: 4,
            token_hash: &token_hash,
            max_files_per_user: 100,
            max_bytes_per_user: 1_000,
            storage_backend: "local",
        },
    )
    .await
    .unwrap()
    .unwrap();
    assert!(matches!(
        claim_upload_slot(&pool, slot_id, b"wrong-token", 90)
            .await
            .unwrap(),
        UploadClaimOutcome::Rejected
    ));

    let competitors = 12;
    let barrier = Arc::new(Barrier::new(competitors + 1));
    let mut tasks = Vec::with_capacity(competitors);
    for _ in 0..competitors {
        let pool = pool.clone();
        let barrier = barrier.clone();
        let token_hash = token_hash.clone();
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            match claim_upload_slot(&pool, slot_id, &token_hash, 90)
                .await
                .unwrap()
            {
                UploadClaimOutcome::Acquired(lease) => Some(lease),
                _ => None,
            }
        }));
    }
    barrier.wait().await;
    let mut winners = Vec::new();
    for task in tasks {
        if let Some(lease) = task.await.unwrap() {
            winners.push(lease);
        }
    }
    assert_eq!(
        winners.len(),
        1,
        "exactly one concurrent PUT may claim a slot"
    );
    assert!(uploaded_file(&pool, slot_id).await.unwrap().is_none());
    let before_forgery: (i64, i64) = sqlx::query_as(
        "SELECT pending_jobs,cleanup_obligation_debt
             FROM upload_storage_capacity_ledger WHERE singleton",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    let forged_stage = format!("staging/{slot_id}/{}", winners[0].claim_token);
    let forged_error = sqlx::query(
        "INSERT INTO upload_cleanup_queue(
                 object_id,storage_backend,object_key,stage_key,storage_attempt,
                 expected_size,storage_fence,slot_delete_projection)
             VALUES($1,'local',$1::text,$3,$2,4,$4,TRUE)",
    )
    .bind(slot_id)
    .bind(winners[0].claim_token)
    .bind(&forged_stage)
    .bind(winners[0].storage_fence)
    .execute(&pool)
    .await
    .unwrap_err();
    assert!(
        matches!(&forged_error,sqlx::Error::Database(error)
                if error.code().as_deref()==Some("42501")),
        "direct writers must not forge slot-delete provenance: {forged_error}"
    );
    let after_forgery: (i64, i64) = sqlx::query_as(
        "SELECT pending_jobs,cleanup_obligation_debt
             FROM upload_storage_capacity_ledger WHERE singleton",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(after_forgery, before_forgery);

    // A mandatory retry-cleanup projection temporarily converts the
    // slot's debt. If cleanup completes before a replacement writer is
    // admitted, the DELETE trigger must hand that obligation back to the
    // still-live writing slot instead of leaving an unaccounted locator.
    sqlx::query(
        "INSERT INTO upload_storage_jobs(
                 object_id,storage_attempt,action,storage_backend,stage_key,
                 storage_fence,expected_size)
             VALUES($1,$2,'delete_stage','local',$3,$4,4)",
    )
    .bind(slot_id)
    .bind(winners[0].claim_token)
    .bind(&forged_stage)
    .bind(winners[0].storage_fence)
    .execute(&pool)
    .await
    .unwrap();
    let converted: (i64, i64, bool) = sqlx::query_as(
        "SELECT ledger.pending_jobs,ledger.cleanup_obligation_debt,
                    slot.storage_cleanup_debt_reserved
               FROM upload_storage_capacity_ledger ledger
               JOIN upload_slots slot ON slot.id=$1
              WHERE ledger.singleton",
    )
    .bind(slot_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        (converted.0, converted.1),
        (before_forgery.0 + 1, before_forgery.1 - 1)
    );
    assert!(!converted.2);
    sqlx::query(
        "DELETE FROM upload_storage_jobs
             WHERE object_id=$1 AND storage_attempt=$2 AND action='delete_stage'",
    )
    .bind(slot_id)
    .bind(winners[0].claim_token)
    .execute(&pool)
    .await
    .unwrap();
    let rearmed: (i64, i64, bool) = sqlx::query_as(
        "SELECT ledger.pending_jobs,ledger.cleanup_obligation_debt,
                    slot.storage_cleanup_debt_reserved
               FROM upload_storage_capacity_ledger ledger
               JOIN upload_slots slot ON slot.id=$1
              WHERE ledger.singleton",
    )
    .bind(slot_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!((rearmed.0, rearmed.1), before_forgery);
    assert!(rearmed.2);
    assert!(release_upload_claim(&pool, slot_id, winners[0].claim_token)
        .await
        .unwrap());
    let lease = match claim_upload_slot(&pool, slot_id, &token_hash, 90)
        .await
        .unwrap()
    {
        UploadClaimOutcome::Acquired(lease) => lease,
        other => panic!("unexpected upload claim outcome: {other:?}"),
    };
    let digest = [9_u8; 32];
    assert!(
        complete_upload(&pool, slot_id, lease.claim_token, &digest, 3_600)
            .await
            .unwrap()
    );
    assert!(uploaded_file(&pool, slot_id).await.unwrap().is_some());
    let expiry = sqlx::query(
        "SELECT EXTRACT(EPOCH FROM (put_expires_at-clock_timestamp()))::bigint AS put_seconds,
                    EXTRACT(EPOCH FROM (expires_at-clock_timestamp()))::bigint AS object_seconds
             FROM upload_slots WHERE id=$1",
    )
    .bind(slot_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    let put_seconds: i64 = expiry.get("put_seconds");
    let object_seconds: i64 = expiry.get("object_seconds");
    assert!((295..=300).contains(&put_seconds));
    assert!((3_590..=3_600).contains(&object_seconds));
    assert!(matches!(
        claim_upload_slot(&pool, slot_id, &token_hash, 90)
            .await
            .unwrap(),
        UploadClaimOutcome::Replay { content_sha256, .. } if content_sha256 == digest
    ));
    assert!(!release_upload_claim(&pool, slot_id, lease.claim_token)
        .await
        .unwrap());
    assert!(record_upload_replay(&pool, slot_id, &token_hash, &digest)
        .await
        .unwrap());
    assert!(
        !record_upload_replay(&pool, slot_id, &token_hash, &[8_u8; 32])
            .await
            .unwrap()
    );
    let replay_count: i64 = sqlx::query_scalar("SELECT replay_count FROM upload_slots WHERE id=$1")
        .bind(slot_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(replay_count, 1);
    for expected_count in 2..=3_i64 {
        assert!(matches!(
            claim_upload_slot(&pool, slot_id, &token_hash, 90)
                .await
                .unwrap(),
            UploadClaimOutcome::Replay { content_sha256, .. } if content_sha256 == digest
        ));
        assert!(record_upload_replay(&pool, slot_id, &token_hash, &digest)
            .await
            .unwrap());
        let count: i64 = sqlx::query_scalar("SELECT replay_count FROM upload_slots WHERE id=$1")
            .bind(slot_id)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count, expected_count);
    }
    assert!(matches!(
        claim_upload_slot(&pool, slot_id, &token_hash, 90)
            .await
            .unwrap(),
        UploadClaimOutcome::Rejected
    ));

    let legacy = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO upload_slots
             (id,user_id,filename,content_type,size,token_hash,expires_at,put_expires_at)
             VALUES($1,$2,'legacy.bin','application/octet-stream',4,$3,
                    clock_timestamp()+INTERVAL '1 hour',
                    clock_timestamp()+INTERVAL '5 minutes')",
    )
    .bind(legacy)
    .bind(user_id)
    .bind(b"legacy-token")
    .execute(&pool)
    .await
    .unwrap();
    // Materialize a schema-valid pre-digest legacy object through UPDATE,
    // so the cleanup-debt trigger reserves its eventual deletion exactly
    // as the 0091 backfill does. It remains unclaimable without a digest.
    sqlx::query(
        "UPDATE upload_slots
             SET uploaded=TRUE,storage_state='legacy_committed',
                 storage_object_key=id::text,storage_size=size
             WHERE id=$1",
    )
    .bind(legacy)
    .execute(&pool)
    .await
    .unwrap();
    assert!(matches!(
        claim_upload_slot(&pool, legacy, b"legacy-token", 90)
            .await
            .unwrap(),
        UploadClaimOutcome::Rejected
    ));

    let exhausted = create_upload_slot(
        &pool,
        UploadReservation {
            user_id,
            filename: "attempts.bin",
            content_type: "application/octet-stream",
            size: 4,
            token_hash: b"attempt-token",
            max_files_per_user: 100,
            max_bytes_per_user: 1_000,
            storage_backend: "local",
        },
    )
    .await
    .unwrap()
    .unwrap();
    for _ in 0..MAX_UPLOAD_ATTEMPTS {
        let lease = match claim_upload_slot(&pool, exhausted, b"attempt-token", 90)
            .await
            .unwrap()
        {
            UploadClaimOutcome::Acquired(lease) => lease,
            other => panic!("unexpected bounded-attempt outcome: {other:?}"),
        };
        assert!(release_upload_claim(&pool, exhausted, lease.claim_token)
            .await
            .unwrap());
    }
    assert!(matches!(
        claim_upload_slot(&pool, exhausted, b"attempt-token", 90)
            .await
            .unwrap(),
        UploadClaimOutcome::Rejected
    ));

    let fenced = create_upload_slot(
        &pool,
        UploadReservation {
            user_id,
            filename: "fenced.bin",
            content_type: "application/octet-stream",
            size: 4,
            token_hash: b"fenced-token",
            max_files_per_user: 100,
            max_bytes_per_user: 1_000,
            storage_backend: "local",
        },
    )
    .await
    .unwrap()
    .unwrap();
    let stale = match claim_upload_slot(&pool, fenced, b"fenced-token", 90)
        .await
        .unwrap()
    {
        UploadClaimOutcome::Acquired(lease) => lease,
        other => panic!("unexpected first fenced claim: {other:?}"),
    };
    assert!(matches!(
        claim_upload_slot(&pool, fenced, b"fenced-token", 90)
            .await
            .unwrap(),
        UploadClaimOutcome::InProgress { .. }
    ));
    sqlx::query(
        "UPDATE upload_slots SET claim_expires_at=clock_timestamp()-INTERVAL '1 second'
             WHERE id=$1",
    )
    .bind(fenced)
    .execute(&pool)
    .await
    .unwrap();
    let replacement = match claim_upload_slot(&pool, fenced, b"fenced-token", 90)
        .await
        .unwrap()
    {
        UploadClaimOutcome::Acquired(lease) => lease,
        other => panic!("unexpected replacement claim: {other:?}"),
    };
    assert_ne!(stale.claim_token, replacement.claim_token);
    assert_eq!(
        renew_upload_claim(&pool, fenced, stale.claim_token, 90)
            .await
            .unwrap(),
        UploadRenewOutcome::Lost
    );
    assert!(!release_upload_claim(&pool, fenced, stale.claim_token)
        .await
        .unwrap());
    assert!(
        !complete_upload(&pool, fenced, stale.claim_token, &[1_u8; 32], 3_600,)
            .await
            .unwrap()
    );
    assert!(
        complete_upload(&pool, fenced, replacement.claim_token, &[2_u8; 32], 3_600,)
            .await
            .unwrap()
    );

    let authorized_deletable = create_upload_slot(
        &pool,
        UploadReservation {
            user_id,
            filename: "authorized-delete.bin",
            content_type: "application/octet-stream",
            size: 7,
            token_hash: b"authorized-delete-token",
            max_files_per_user: 100,
            max_bytes_per_user: 1_000,
            storage_backend: "local",
        },
    )
    .await
    .unwrap()
    .unwrap();
    let live_session = db::create_api_session(&pool, user_id, 1).await.unwrap();
    assert_eq!(
        queue_user_upload_delete_authorized(
            &pool,
            user_id,
            0,
            &live_session,
            authorized_deletable,
            Uuid::new_v4(),
        )
        .await
        .unwrap(),
        UserUploadDeleteOutcome::Accepted
    );

    let stale_deletable = create_upload_slot(
        &pool,
        UploadReservation {
            user_id,
            filename: "stale-delete.bin",
            content_type: "application/octet-stream",
            size: 7,
            token_hash: b"stale-delete-token",
            max_files_per_user: 100,
            max_bytes_per_user: 1_000,
            storage_backend: "local",
        },
    )
    .await
    .unwrap()
    .unwrap();
    let stale_session = db::create_api_session(&pool, user_id, 1).await.unwrap();
    let mut logout = pool.begin().await.unwrap();
    assert!(
        db::delete_api_session_audited_in_tx(&mut logout, &stale_session, Uuid::new_v4(),)
            .await
            .unwrap()
    );
    logout.commit().await.unwrap();
    assert_eq!(
        queue_user_upload_delete_authorized(
            &pool,
            user_id,
            0,
            &stale_session,
            stale_deletable,
            Uuid::new_v4(),
        )
        .await
        .unwrap(),
        UserUploadDeleteOutcome::Unauthorized
    );
    assert!(sqlx::query("SELECT 1 FROM upload_slots WHERE id=$1")
        .bind(stale_deletable)
        .fetch_optional(&pool)
        .await
        .unwrap()
        .is_some());

    let deletable = create_upload_slot(
        &pool,
        UploadReservation {
            user_id,
            filename: "delete-me.bin",
            content_type: "application/octet-stream",
            size: 7,
            token_hash: b"delete-token",
            max_files_per_user: 100,
            max_bytes_per_user: 1_000,
            storage_backend: "local",
        },
    )
    .await
    .unwrap()
    .unwrap();
    let other_user = insert_user(&pool).await;
    assert!(
        !queue_user_upload_delete(&pool, other_user, deletable, Uuid::new_v4())
            .await
            .unwrap()
    );
    let delete_request = Uuid::new_v4();
    assert!(
        queue_user_upload_delete(&pool, user_id, deletable, delete_request)
            .await
            .unwrap()
    );
    assert!(
        !queue_user_upload_delete(&pool, user_id, deletable, Uuid::new_v4())
            .await
            .unwrap()
    );
    let delete_projection: (i64, i64) = sqlx::query_as(
        "SELECT
                 (SELECT COUNT(*) FROM upload_cleanup_queue WHERE object_id=$1),
                 (SELECT COUNT(*) FROM audit_log
                   WHERE actor_id=$2 AND action='user.upload.delete'
                     AND target=$1::text AND request_id=$3)",
    )
    .bind(deletable)
    .bind(user_id)
    .bind(delete_request)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(delete_projection, (0, 1));
    assert!(sqlx::query("SELECT 1 FROM upload_slots WHERE id=$1")
        .bind(deletable)
        .fetch_optional(&pool)
        .await
        .unwrap()
        .is_none());

    let expired = create_upload_slot(
        &pool,
        UploadReservation {
            user_id,
            filename: "expired.bin",
            content_type: "application/octet-stream",
            size: 1,
            token_hash: b"expired",
            max_files_per_user: 100,
            max_bytes_per_user: 1_000,
            storage_backend: "local",
        },
    )
    .await
    .unwrap()
    .unwrap();
    let active_expired = create_upload_slot(
        &pool,
        UploadReservation {
            user_id,
            filename: "active.bin",
            content_type: "application/octet-stream",
            size: 1,
            token_hash: b"active",
            max_files_per_user: 100,
            max_bytes_per_user: 1_000,
            storage_backend: "local",
        },
    )
    .await
    .unwrap()
    .unwrap();
    let abandoned = create_upload_slot(
        &pool,
        UploadReservation {
            user_id,
            filename: "abandoned.bin",
            content_type: "application/octet-stream",
            size: 1,
            token_hash: b"abandoned",
            max_files_per_user: 100,
            max_bytes_per_user: 1_000,
            storage_backend: "local",
        },
    )
    .await
    .unwrap()
    .unwrap();
    let active_claim = Uuid::new_v4();
    let abandoned_claim = Uuid::new_v4();
    let active_stage = format!("staging/{active_expired}/{active_claim}");
    let active_object = format!("objects/{active_expired}/{active_claim}");
    let abandoned_stage = format!("staging/{abandoned}/{abandoned_claim}");
    let abandoned_object = format!("objects/{abandoned}/{abandoned_claim}");
    sqlx::query(
        "UPDATE upload_slots
             SET expires_at = CASE
                 WHEN id = $1 THEN NOW() - INTERVAL '1 minute'
                 WHEN id = $2 THEN NOW() - INTERVAL '1 minute'
                 WHEN id = $3 THEN NOW() - INTERVAL '10 minutes'
                 ELSE expires_at
             END,
             uploading = id IN ($2, $3),
             claim_token = CASE
                 WHEN id = $2 THEN $4
                 WHEN id = $3 THEN $5
                 ELSE NULL
             END,
             claim_expires_at = CASE
                 WHEN id = $2 THEN clock_timestamp() + INTERVAL '1 minute'
                 WHEN id = $3 THEN clock_timestamp() - INTERVAL '9 minutes'
                 ELSE NULL
             END,
             storage_state = CASE WHEN id IN ($2,$3) THEN 'writing' ELSE 'reserved' END,
             storage_attempt = CASE WHEN id=$2 THEN $4 WHEN id=$3 THEN $5 ELSE NULL END,
             storage_stage_key = CASE WHEN id=$2 THEN $6 WHEN id=$3 THEN $8 ELSE NULL END,
             storage_object_key = CASE WHEN id=$2 THEN $7 WHEN id=$3 THEN $9 ELSE NULL END,
             storage_fence = CASE WHEN id IN ($2,$3) THEN storage_fence+1 ELSE storage_fence END
             WHERE id IN ($1, $2, $3)",
    )
    .bind(expired)
    .bind(active_expired)
    .bind(abandoned)
    .bind(active_claim)
    .bind(abandoned_claim)
    .bind(active_stage)
    .bind(active_object)
    .bind(abandoned_stage)
    .bind(abandoned_object)
    .execute(&pool)
    .await
    .unwrap();
    assert!(matches!(
        claim_upload_slot(&pool, expired, b"expired", 90)
            .await
            .unwrap(),
        UploadClaimOutcome::Rejected
    ));

    let candidates = cleanup_expired_upload_slots(&pool).await.unwrap();
    assert!(candidates.contains(&expired));
    assert!(candidates.contains(&abandoned));
    assert!(!candidates.contains(&active_expired));
    assert!(sqlx::query("SELECT 1 FROM upload_slots WHERE id=$1")
        .bind(expired)
        .fetch_optional(&pool)
        .await
        .unwrap()
        .is_none());
    let abandoned_quiet_period: bool = sqlx::query_scalar(
        "SELECT available_at>clock_timestamp()
             FROM upload_cleanup_queue WHERE object_id=$1",
    )
    .bind(abandoned)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(
        abandoned_quiet_period,
        "an expired in-flight writer keeps a durable delayed tombstone"
    );
    // Advance only this fixture past the external-I/O quiet period. The
    // worker must then be able to claim and complete the same tombstone.
    sqlx::query(
        "UPDATE upload_cleanup_queue SET available_at=clock_timestamp()
             WHERE object_id=$1",
    )
    .bind(abandoned)
    .execute(&pool)
    .await
    .unwrap();
    let cleanup = queued_upload_cleanup(&pool).await.unwrap();
    let abandoned_job = cleanup
        .iter()
        .find(|job| job.object_id == abandoned)
        .expect("abandoned upload has durable cleanup work");
    assert!(complete_queued_upload_cleanup(
        &pool,
        abandoned_job.object_id,
        abandoned_job.claim_token,
    )
    .await
    .unwrap());
    let active_still_exists: bool = sqlx::query("SELECT id FROM upload_slots WHERE id = $1")
        .bind(active_expired)
        .fetch_optional(&pool)
        .await
        .unwrap()
        .is_some();
    assert!(active_still_exists);

    let uploaded_still_exists: bool =
        sqlx::query("SELECT uploaded FROM upload_slots WHERE id = $1")
            .bind(slot_id)
            .fetch_one(&pool)
            .await
            .unwrap()
            .get("uploaded");
    assert!(uploaded_still_exists);

    sqlx::query("UPDATE upload_slots SET expires_at = NOW() - INTERVAL '1 second' WHERE id = $1")
        .bind(slot_id)
        .execute(&pool)
        .await
        .unwrap();
    assert!(uploaded_file(&pool, slot_id).await.unwrap().is_none());
    assert!(cleanup_expired_upload_slots(&pool)
        .await
        .unwrap()
        .contains(&slot_id));
    let cleanup = queued_upload_cleanup(&pool).await.unwrap();
    let uploaded_job = cleanup
        .iter()
        .find(|job| job.object_id == slot_id)
        .expect("uploaded object has durable cleanup work");
    assert!(complete_queued_upload_cleanup(
        &pool,
        uploaded_job.object_id,
        uploaded_job.claim_token,
    )
    .await
    .unwrap());

    let cascade_states: Vec<String> = sqlx::query_scalar(
        "SELECT storage_state FROM upload_slots
             WHERE id=ANY($1) ORDER BY storage_state",
    )
    .bind([active_expired, fenced, legacy])
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(
        cascade_states,
        ["committed", "legacy_committed", "writing"],
        "account cascade fixture must cover every locator lifecycle"
    );
    let before_rollback: (i64, i64, i64, i64) = sqlx::query_as(
        "SELECT pending_jobs,cleanup_obligation_debt,
                    storage_jobs_pending,cleanup_jobs_pending
             FROM upload_storage_capacity_ledger WHERE singleton",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    let mut rolled_back_delete = pool.begin().await.unwrap();
    sqlx::query("DELETE FROM users WHERE id=$1")
        .bind(user_id)
        .execute(&mut *rolled_back_delete)
        .await
        .unwrap();
    rolled_back_delete.rollback().await.unwrap();
    let after_rollback: (i64, i64, i64, i64) = sqlx::query_as(
        "SELECT pending_jobs,cleanup_obligation_debt,
                    storage_jobs_pending,cleanup_jobs_pending
             FROM upload_storage_capacity_ledger WHERE singleton",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(after_rollback, before_rollback);

    sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user_id)
        .execute(&pool)
        .await
        .unwrap();
    let cascade_projection: (i64, i64, i64, i64, i64, i64, i64) = sqlx::query_as(
        "SELECT ledger.pending_jobs,ledger.cleanup_obligation_debt,
                    ledger.storage_jobs_pending,ledger.cleanup_jobs_pending,
                    (SELECT COUNT(*) FROM upload_storage_jobs),
                    (SELECT COUNT(*) FROM upload_cleanup_queue),
                    (SELECT COUNT(*) FROM upload_slots WHERE user_id=$1)
             FROM upload_storage_capacity_ledger ledger WHERE singleton",
    )
    .bind(user_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        cascade_projection.0,
        cascade_projection.4 + cascade_projection.5
    );
    assert_eq!(cascade_projection.1, 0);
    assert_eq!(cascade_projection.2, cascade_projection.4);
    assert_eq!(cascade_projection.3, cascade_projection.5);
    assert_eq!(cascade_projection.6, 0);
}
