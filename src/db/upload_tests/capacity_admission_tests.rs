//! Capacity admission, reservation and release tests across upload and account mutations.

use super::*;

#[test]
fn admission_and_account_delete_share_capacity_then_user_lock_order() {
    #[derive(Debug, Eq, PartialEq)]
    enum LockClass {
        CapacityLedger,
        User,
    }
    let admission = [LockClass::CapacityLedger, LockClass::User];
    let account_delete = [LockClass::CapacityLedger, LockClass::User];
    assert_eq!(admission, account_delete);
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn upload_cascade_converts_reserved_debt_at_the_hard_limit() {
    let url = std::env::var("TEST_DATABASE_URL")
        .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(16)
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
    let baseline: (i64, i64) = sqlx::query_as(
        "SELECT pending_jobs,cleanup_obligation_debt
             FROM upload_storage_capacity_ledger WHERE singleton",
    )
    .fetch_one(&pool)
    .await
    .unwrap();

    let mut tx = pool.begin().await.unwrap();
    let user_id = Uuid::new_v4();
    let username = format!("upload-cascade-{}", &user_id.simple().to_string()[..12]);
    sqlx::query(
        "INSERT INTO users(id,username,password_hash,is_admin)
             VALUES($1,$2,'test-only',FALSE)",
    )
    .bind(user_id)
    .bind(username)
    .execute(&mut *tx)
    .await
    .unwrap();
    let slot_id = Uuid::new_v4();
    let attempt = Uuid::new_v4();
    let stage_key = format!("staging/{slot_id}/{attempt}");
    sqlx::query(
        "INSERT INTO upload_slots(
                 id,user_id,filename,content_type,size,token_hash,
                 expires_at,put_expires_at)
             VALUES($1,$2,'cascade.bin','application/octet-stream',1,$3,
                    clock_timestamp()+INTERVAL '1 hour',
                    clock_timestamp()+INTERVAL '5 minutes')",
    )
    .bind(slot_id)
    .bind(user_id)
    .bind(b"cascade-token")
    .execute(&mut *tx)
    .await
    .unwrap();
    sqlx::query(
        "UPDATE upload_slots
             SET uploading=TRUE,claim_token=$2,
                 claim_expires_at=clock_timestamp()+INTERVAL '1 minute',
                 storage_state='writing',storage_attempt=$2,
                 storage_stage_key=$3,storage_object_key=id::text,
                 storage_fence=storage_fence+1
             WHERE id=$1",
    )
    .bind(slot_id)
    .bind(attempt)
    .bind(&stage_key)
    .execute(&mut *tx)
    .await
    .unwrap();
    let before_fill: (i64, i64) = sqlx::query_as(
        "SELECT pending_jobs,cleanup_obligation_debt
             FROM upload_storage_capacity_ledger WHERE singleton",
    )
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    assert_eq!(before_fill.1, baseline.1 + 1);
    let fill_count = TEST_UPLOAD_PENDING_LIMIT - before_fill.0 - before_fill.1;
    assert!(
        fill_count > 0,
        "test fixture unexpectedly starts over capacity"
    );
    for _ in 0..fill_count {
        let object_id = Uuid::new_v4();
        let filler_attempt = Uuid::new_v4();
        let filler_stage = format!("staging/{object_id}/{filler_attempt}");
        sqlx::query(
            "INSERT INTO upload_storage_jobs(
                     object_id,storage_attempt,action,storage_backend,
                     stage_key,storage_fence,expected_size)
                 VALUES($1,$2,'delete_stage','local',$3,0,1)",
        )
        .bind(object_id)
        .bind(filler_attempt)
        .bind(filler_stage)
        .execute(&mut *tx)
        .await
        .unwrap();
    }
    let at_limit: (i64, i64) = sqlx::query_as(
        "SELECT pending_jobs,cleanup_obligation_debt
             FROM upload_storage_capacity_ledger WHERE singleton",
    )
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    assert_eq!(at_limit.0 + at_limit.1, TEST_UPLOAD_PENDING_LIMIT);

    sqlx::query("DELETE FROM users WHERE id=$1")
        .bind(user_id)
        .execute(&mut *tx)
        .await
        .unwrap();
    let converted: (i64, i64) = sqlx::query_as(
        "SELECT pending_jobs,cleanup_obligation_debt
             FROM upload_storage_capacity_ledger WHERE singleton",
    )
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    assert_eq!(converted.0, at_limit.0 + 1);
    assert_eq!(converted.1, at_limit.1 - 1);
    assert_eq!(converted.0 + converted.1, TEST_UPLOAD_PENDING_LIMIT);
    assert!(sqlx::query_scalar::<_, bool>(
        "SELECT slot_delete_projection FROM upload_cleanup_queue
             WHERE object_id=$1 AND storage_attempt=$2
               AND object_key=$1::text AND stage_key=$3",
    )
    .bind(slot_id)
    .bind(attempt)
    .bind(&stage_key)
    .fetch_one(&mut *tx)
    .await
    .unwrap());

    let extra_id = Uuid::new_v4();
    let extra_attempt = Uuid::new_v4();
    let extra_stage = format!("staging/{extra_id}/{extra_attempt}");
    let capacity_error = sqlx::query(
        "INSERT INTO upload_storage_jobs(
                 object_id,storage_attempt,action,storage_backend,
                 stage_key,storage_fence,expected_size)
             VALUES($1,$2,'delete_stage','local',$3,0,1)",
    )
    .bind(extra_id)
    .bind(extra_attempt)
    .bind(extra_stage)
    .execute(&mut *tx)
    .await
    .unwrap_err();
    assert!(
        matches!(&capacity_error,sqlx::Error::Database(error)
                if error.code().as_deref()==Some("53300")),
        "fresh recovery admission must fail at the hard limit: {capacity_error}"
    );
    tx.rollback().await.unwrap();
    let after_rollback: (i64, i64) = sqlx::query_as(
        "SELECT pending_jobs,cleanup_obligation_debt
             FROM upload_storage_capacity_ledger WHERE singleton",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(after_rollback, baseline);
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn upload_recovery_capacity_counts_every_locator_and_releases_last_owner() {
    let url = std::env::var("TEST_DATABASE_URL")
        .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(16)
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
    let baseline: (i64, i64, i64, i64, i64, i64, bool) = sqlx::query_as(
        "SELECT retained_files,retained_bytes,
                    recovery_retained_files,recovery_retained_bytes,
                    pending_jobs,cleanup_obligation_debt,recovery_overcommit_draining
               FROM upload_storage_capacity_ledger WHERE singleton",
    )
    .fetch_one(&pool)
    .await
    .unwrap();

    // Eight failed attempts for one object are eight possible physical
    // stages, even though the logical object owner remains exactly one.
    let object_id = Uuid::new_v4();
    let attempt_size = 25_i64 * 1024 * 1024;
    let mut attempts = Vec::new();
    for _ in 0..MAX_UPLOAD_ATTEMPTS {
        let attempt = Uuid::new_v4();
        let stage = format!("staging/{object_id}/{attempt}");
        sqlx::query(
            "INSERT INTO upload_storage_jobs(
                     object_id,storage_attempt,action,storage_backend,
                     stage_key,storage_fence,expected_size)
                 VALUES($1,$2,'delete_stage','local',$3,0,$4)",
        )
        .bind(object_id)
        .bind(attempt)
        .bind(stage)
        .bind(attempt_size)
        .execute(&pool)
        .await
        .unwrap();
        attempts.push(attempt);
    }
    let after_attempts: (i64, i64, i64, i64) = sqlx::query_as(
        "SELECT retained_files,retained_bytes,
                    recovery_retained_files,recovery_retained_bytes
               FROM upload_storage_capacity_ledger WHERE singleton",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(after_attempts.0, baseline.0 + 1);
    assert_eq!(after_attempts.1, baseline.1 + attempt_size);
    assert_eq!(after_attempts.2, baseline.2 + MAX_UPLOAD_ATTEMPTS);
    assert_eq!(
        after_attempts.3,
        baseline.3 + MAX_UPLOAD_ATTEMPTS * attempt_size
    );

    // Dead-lettering retains the exact physical obligation. It is not a
    // release event and cannot manufacture capacity for another upload.
    sqlx::query(
        "UPDATE upload_storage_jobs SET dead_lettered_at=clock_timestamp()
             WHERE object_id=$1 AND storage_attempt=$2 AND action='delete_stage'",
    )
    .bind(object_id)
    .bind(attempts[0])
    .execute(&pool)
    .await
    .unwrap();
    let after_dead_letter: (i64, i64) = sqlx::query_as(
        "SELECT recovery_retained_files,recovery_retained_bytes
               FROM upload_storage_capacity_ledger WHERE singleton",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(after_dead_letter, (after_attempts.2, after_attempts.3));

    // A local cleanup tombstone names a distinct object and stage: two
    // physical locator units. Since jobs already own the logical object,
    // inserting it must not add a second logical retained unit.
    let stage = format!("staging/{object_id}/{}", attempts[0]);
    sqlx::query(
        "INSERT INTO upload_cleanup_queue(
                 object_id,storage_backend,object_key,stage_key,storage_attempt,
                 expected_size,storage_fence)
             VALUES($1,'local',$1::text,$2,$3,$4,0)",
    )
    .bind(object_id)
    .bind(&stage)
    .bind(attempts[0])
    .bind(attempt_size)
    .execute(&pool)
    .await
    .unwrap();
    let with_cleanup: (i64, i64, i64) = sqlx::query_as(
        "SELECT retained_files,recovery_retained_files,recovery_retained_bytes
               FROM upload_storage_capacity_ledger WHERE singleton",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(with_cleanup.0, baseline.0 + 1);
    assert_eq!(with_cleanup.1, baseline.2 + MAX_UPLOAD_ATTEMPTS + 2);
    assert_eq!(
        with_cleanup.2,
        baseline.3 + (MAX_UPLOAD_ATTEMPTS + 2) * attempt_size
    );

    // Complete cleanup first and storage attempts in reverse order. The
    // logical retained unit stays until the final projection disappears.
    sqlx::query("DELETE FROM upload_cleanup_queue WHERE object_id=$1")
        .bind(object_id)
        .execute(&pool)
        .await
        .unwrap();
    for (index, attempt) in attempts.iter().rev().enumerate() {
        sqlx::query(
            "DELETE FROM upload_storage_jobs
                 WHERE object_id=$1 AND storage_attempt=$2 AND action='delete_stage'",
        )
        .bind(object_id)
        .bind(attempt)
        .execute(&pool)
        .await
        .unwrap();
        let logical: i64 = sqlx::query_scalar(
            "SELECT retained_files FROM upload_storage_capacity_ledger WHERE singleton",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(
            logical,
            baseline.0 + if index + 1 < attempts.len() { 1 } else { 0 },
            "only the last physical projection may release logical ownership"
        );
    }

    // Reverse admission/completion order on another object, and verify an
    // S3 same-key tombstone with the same exact version counts once.
    let reverse_id = Uuid::new_v4();
    let reverse_attempt = Uuid::new_v4();
    let reverse_stage = format!("staging/{reverse_id}/{reverse_attempt}");
    sqlx::query(
        "INSERT INTO upload_cleanup_queue(
                 object_id,storage_backend,object_key,stage_key,storage_attempt,
                 expected_size,storage_fence)
             VALUES($1,'local',$1::text,$2,$3,$4,0)",
    )
    .bind(reverse_id)
    .bind(&reverse_stage)
    .bind(reverse_attempt)
    .bind(attempt_size)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO upload_storage_jobs(
                 object_id,storage_attempt,action,storage_backend,
                 stage_key,storage_fence,expected_size)
             VALUES($1,$2,'delete_stage','local',$3,0,$4)",
    )
    .bind(reverse_id)
    .bind(reverse_attempt)
    .bind(&reverse_stage)
    .bind(attempt_size)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query("DELETE FROM upload_storage_jobs WHERE object_id=$1")
        .bind(reverse_id)
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT retained_files FROM upload_storage_capacity_ledger WHERE singleton"
        )
        .fetch_one(&pool)
        .await
        .unwrap(),
        baseline.0 + 1
    );
    sqlx::query("DELETE FROM upload_cleanup_queue WHERE object_id=$1")
        .bind(reverse_id)
        .execute(&pool)
        .await
        .unwrap();

    let s3_id = Uuid::new_v4();
    let s3_attempt = Uuid::new_v4();
    let s3_key = format!("objects/{s3_id}/{s3_attempt}");
    sqlx::query(
        "INSERT INTO upload_cleanup_queue(
                 object_id,storage_backend,object_key,object_version,
                 stage_key,stage_version,storage_attempt,expected_size,storage_fence)
             VALUES($1,'s3',$2,'version-1',$2,'version-1',$3,$4,0)",
    )
    .bind(s3_id)
    .bind(s3_key)
    .bind(s3_attempt)
    .bind(attempt_size)
    .execute(&pool)
    .await
    .unwrap();
    let s3_recovery_files: i64 = sqlx::query_scalar(
        "SELECT recovery_retained_files FROM upload_storage_capacity_ledger WHERE singleton",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(s3_recovery_files, baseline.2 + 1);
    sqlx::query("DELETE FROM upload_cleanup_queue WHERE object_id=$1")
        .bind(s3_id)
        .execute(&pool)
        .await
        .unwrap();

    // A promotion which appears after cleanup selection is a normal
    // quiescence race. Deferring releases the lease and restores attempts;
    // while the promotion exists the candidate query does not reclaim it.
    let quiet_id = Uuid::new_v4();
    let quiet_attempt = Uuid::new_v4();
    let quiet_stage = format!("staging/{quiet_id}/{quiet_attempt}");
    let quiet_digest = vec![7_u8; 32];
    sqlx::query(
        "INSERT INTO upload_cleanup_queue(
                 object_id,storage_backend,object_key,stage_key,storage_attempt,
                 expected_size,expected_sha256,storage_fence,available_at)
             VALUES($1,'local',$1::text,$2,$3,$4,$5,7,
                    clock_timestamp()-INTERVAL '100 years')",
    )
    .bind(quiet_id)
    .bind(&quiet_stage)
    .bind(quiet_attempt)
    .bind(attempt_size)
    .bind(&quiet_digest)
    .execute(&pool)
    .await
    .unwrap();
    let first_claim = queued_upload_cleanup(&pool)
        .await
        .unwrap()
        .into_iter()
        .find(|job| job.object_id == quiet_id)
        .expect("quiescence fixture cleanup claim");
    sqlx::query(
        "INSERT INTO upload_storage_jobs(
                 object_id,storage_attempt,action,storage_backend,
                 stage_key,object_key,expected_size,expected_sha256,storage_fence)
             VALUES($1,$2,'promote','local',$3,$1::text,$4,$5,7)",
    )
    .bind(quiet_id)
    .bind(quiet_attempt)
    .bind(&quiet_stage)
    .bind(attempt_size)
    .bind(&quiet_digest)
    .execute(&pool)
    .await
    .unwrap();
    assert!(
        !upload_cleanup_generation_is_quiescent(&pool, quiet_id, first_claim.claim_token, 7,)
            .await
            .unwrap()
    );
    assert!(
        defer_queued_upload_cleanup(&pool, quiet_id, first_claim.claim_token)
            .await
            .unwrap()
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT attempts FROM upload_cleanup_queue WHERE object_id=$1"
        )
        .bind(quiet_id)
        .fetch_one(&pool)
        .await
        .unwrap(),
        0
    );
    assert!(
        queued_upload_cleanup(&pool)
            .await
            .unwrap()
            .iter()
            .all(|job| job.object_id != quiet_id),
        "an exact promotion must keep cleanup out of the claimed batch"
    );
    sqlx::query("DELETE FROM upload_storage_jobs WHERE object_id=$1")
        .bind(quiet_id)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query(
        "UPDATE upload_cleanup_queue
             SET available_at=clock_timestamp()-INTERVAL '100 years'
             WHERE object_id=$1",
    )
    .bind(quiet_id)
    .execute(&pool)
    .await
    .unwrap();
    let final_claim = queued_upload_cleanup(&pool)
        .await
        .unwrap()
        .into_iter()
        .find(|job| job.object_id == quiet_id)
        .expect("cleanup becomes claimable after promotion completion");
    assert!(
        complete_queued_upload_cleanup(&pool, quiet_id, final_claim.claim_token,)
            .await
            .unwrap()
    );

    // Mandatory recovery projections remain insertable above the byte
    // ceiling, enter draining, and block a fresh reservation. This models
    // eight maximum-size failed attempts without losing cleanup authority.
    let capacity_id = Uuid::new_v4();
    let capacity_size = TEST_UPLOAD_RETAINED_BYTES_LIMIT / MAX_UPLOAD_ATTEMPTS;
    for _ in 0..MAX_UPLOAD_ATTEMPTS {
        let attempt = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO upload_storage_jobs(
                     object_id,storage_attempt,action,storage_backend,
                     stage_key,storage_fence,expected_size)
                 VALUES($1,$2,'delete_stage','local',$3,0,$4)",
        )
        .bind(capacity_id)
        .bind(attempt)
        .bind(format!("staging/{capacity_id}/{attempt}"))
        .bind(capacity_size)
        .execute(&pool)
        .await
        .unwrap();
    }
    assert!(sqlx::query_scalar::<_, bool>(
        "SELECT recovery_overcommit_draining
               FROM upload_storage_capacity_ledger WHERE singleton",
    )
    .fetch_one(&pool)
    .await
    .unwrap());
    let user_id = insert_user(&pool).await;
    assert!(
        create_upload_slot(
            &pool,
            UploadReservation {
                user_id,
                filename: "blocked-by-recovery.bin",
                content_type: "application/octet-stream",
                size: 1,
                token_hash: b"recovery-capacity",
                max_files_per_user: 10,
                max_bytes_per_user: 10,
                storage_backend: "local",
            },
        )
        .await
        .unwrap()
        .is_none(),
        "physical recovery debt must block fresh upload admission"
    );
    sqlx::query("DELETE FROM upload_storage_jobs WHERE object_id=$1")
        .bind(capacity_id)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM users WHERE id=$1")
        .bind(user_id)
        .execute(&pool)
        .await
        .unwrap();

    let final_ledger: (i64, i64, i64, i64, i64, i64, bool) = sqlx::query_as(
        "SELECT retained_files,retained_bytes,
                    recovery_retained_files,recovery_retained_bytes,
                    pending_jobs,cleanup_obligation_debt,recovery_overcommit_draining
               FROM upload_storage_capacity_ledger WHERE singleton",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(final_ledger, baseline);
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn account_delete_and_upload_mutations_share_retryable_ledger_first_order() {
    let url = std::env::var("TEST_DATABASE_URL")
        .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(8)
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
    let user_id = insert_user(&pool).await;
    let token = b"lock-order-token";
    let slot_id = create_upload_slot(
        &pool,
        UploadReservation {
            user_id,
            filename: "lock-order.bin",
            content_type: "application/octet-stream",
            size: 1,
            token_hash: token,
            max_files_per_user: 10,
            max_bytes_per_user: 10,
            storage_backend: "local",
        },
    )
    .await
    .unwrap()
    .unwrap();
    let active_lease = match claim_upload_slot(&pool, slot_id, token, 90).await.unwrap() {
        UploadClaimOutcome::Acquired(lease) => lease,
        other => panic!("unexpected initial upload claim outcome: {other:?}"),
    };

    // Model the prefix of account deletion: global ledger, then user.
    // Claim's SQL capability has a NOWAIT ledger admission; ordinary lease
    // renewal does not touch capacity authority. Generic capacity paths
    // and implicit trigger accounting must return SQLSTATE 55P03 without
    // waiting behind this owner.
    let mut account_tx = pool.begin().await.unwrap();
    sqlx::query("SELECT singleton FROM upload_storage_capacity_ledger WHERE singleton FOR UPDATE")
        .fetch_one(&mut *account_tx)
        .await
        .unwrap();
    sqlx::query("SELECT id FROM users WHERE id=$1 FOR UPDATE")
        .bind(user_id)
        .fetch_one(&mut *account_tx)
        .await
        .unwrap();
    assert!(matches!(
        claim_upload_slot(&pool, slot_id, token, 90).await.unwrap(),
        UploadClaimOutcome::InProgress { .. }
    ));
    assert_eq!(
        renew_upload_claim(&pool, slot_id, active_lease.claim_token, 90)
            .await
            .unwrap(),
        UploadRenewOutcome::Renewed,
        "a healthy lease renewal must remain independent of unrelated capacity work"
    );
    let queue_error = queue_user_upload_delete(&pool, user_id, slot_id, Uuid::new_v4())
        .await
        .unwrap_err();
    assert!(queue_error
        .to_string()
        .contains("upload storage capacity busy; retry"));
    let trigger_error = tokio::time::timeout(
        Duration::from_secs(1),
        sqlx::query(
            "INSERT INTO upload_cleanup_queue(
                     object_id,storage_backend,object_key,expected_size,storage_fence)
                 VALUES($1,'local',$1::text,1,0)",
        )
        .bind(Uuid::new_v4())
        .execute(&pool),
    )
    .await
    .expect("implicit cleanup accounting must reject a held ledger promptly")
    .unwrap_err();
    assert!(
        is_retryable_upload_capacity_lock(&trigger_error),
        "implicit upload cleanup accounting must expose SQLSTATE 55P03: {trigger_error}"
    );
    let completion_error = tokio::time::timeout(
        Duration::from_secs(1),
        complete_queued_upload_cleanup(&pool, Uuid::new_v4(), Uuid::new_v4()),
    )
    .await
    .expect("cleanup completion must reject ledger contention without waiting for the outer test")
    .unwrap_err();
    assert!(
            completion_error
                .chain()
                .filter_map(|cause| cause.downcast_ref::<sqlx::Error>())
                .any(is_retryable_upload_capacity_lock),
            "generic cleanup completion must preserve SQLSTATE 55P03 for central retry mapping: {completion_error:#}"
        );
    account_tx.rollback().await.unwrap();

    // A committed replay cannot establish another cleanup obligation: it
    // must remain available while unrelated work holds the singleton.
    let replay_digest = [7_u8; 32];
    assert!(complete_upload(
        &pool,
        slot_id,
        active_lease.claim_token,
        &replay_digest,
        600,
    )
    .await
    .unwrap());
    let mut healthy_tx = pool.begin().await.unwrap();
    sqlx::query("SELECT singleton FROM upload_storage_capacity_ledger WHERE singleton FOR UPDATE")
        .fetch_one(&mut *healthy_tx)
        .await
        .unwrap();
    assert!(
        tokio::time::timeout(
            Duration::from_secs(1),
            record_upload_replay(&pool, slot_id, token, &replay_digest),
        )
        .await
        .expect("committed replay must not wait for unrelated capacity authority")
        .unwrap(),
        "committed replay must retain normal dedupe accounting"
    );
    healthy_tx.rollback().await.unwrap();

    // `reserve_slot` takes ledger then user internally. Both acquisitions
    // are SQL NOWAIT, so user-row contention preserves the established
    // unavailable result and releases the singleton with no Rust-side
    // timeout or pre-acquisition.
    let mut user_tx = pool.begin().await.unwrap();
    sqlx::query("SELECT id FROM users WHERE id=$1 FOR UPDATE")
        .bind(user_id)
        .fetch_one(&mut *user_tx)
        .await
        .unwrap();
    let reservation = tokio::time::timeout(
        Duration::from_secs(1),
        create_upload_slot(
            &pool,
            UploadReservation {
                user_id,
                filename: "user-row-contention.bin",
                content_type: "application/octet-stream",
                size: 1,
                token_hash: b"user-row-contention",
                max_files_per_user: 10,
                max_bytes_per_user: 10,
                storage_backend: "local",
            },
        ),
    )
    .await
    .expect("reservation must not retain the ledger behind a user-row lock")
    .unwrap();
    assert!(reservation.is_none());
    sqlx::query(
        "SELECT singleton FROM upload_storage_capacity_ledger WHERE singleton FOR UPDATE NOWAIT",
    )
    .fetch_one(&pool)
    .await
    .expect("reservation contention must release the global ledger");
    user_tx.rollback().await.unwrap();

    // The same requirement applies to the sole debt-creating claim
    // transition: its SQL capability uses NOWAIT for both the ledger and
    // target slot, returning the established retry result without holding
    // the capability transaction behind either owner.
    let contention_slot = create_upload_slot(
        &pool,
        UploadReservation {
            user_id,
            filename: "slot-row-contention.bin",
            content_type: "application/octet-stream",
            size: 1,
            token_hash: b"slot-row-contention",
            max_files_per_user: 10,
            max_bytes_per_user: 10,
            storage_backend: "local",
        },
    )
    .await
    .unwrap()
    .unwrap();
    let mut slot_tx = pool.begin().await.unwrap();
    sqlx::query("SELECT id FROM upload_slots WHERE id=$1 FOR UPDATE")
        .bind(contention_slot)
        .fetch_one(&mut *slot_tx)
        .await
        .unwrap();
    let claim = tokio::time::timeout(
        Duration::from_secs(1),
        claim_upload_slot(&pool, contention_slot, b"slot-row-contention", 90),
    )
    .await
    .expect("claim must not retain the ledger behind a slot-row lock")
    .unwrap();
    assert!(matches!(
        claim,
        UploadClaimOutcome::InProgress {
            retry_after_seconds: 1
        }
    ));
    sqlx::query(
        "SELECT singleton FROM upload_storage_capacity_ledger WHERE singleton FOR UPDATE NOWAIT",
    )
    .fetch_one(&pool)
    .await
    .expect("claim contention must release the global ledger");
    slot_tx.rollback().await.unwrap();

    // Reverse pressure: a cleanup owner holds ledger then its queue row.
    // Account deletion must surface the SQL-native 55P03 before it locks
    // the user and can form a cycle.
    let cleanup_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO upload_cleanup_queue(
                 object_id,storage_backend,object_key,expected_size,storage_fence)
             VALUES($1,'local',$1::text,1,0)",
    )
    .bind(cleanup_id)
    .execute(&pool)
    .await
    .unwrap();
    let mut cleanup_tx = pool.begin().await.unwrap();
    sqlx::query("SELECT singleton FROM upload_storage_capacity_ledger WHERE singleton FOR UPDATE")
        .fetch_one(&mut *cleanup_tx)
        .await
        .unwrap();
    sqlx::query("SELECT object_id FROM upload_cleanup_queue WHERE object_id=$1 FOR UPDATE")
        .bind(cleanup_id)
        .fetch_one(&mut *cleanup_tx)
        .await
        .unwrap();
    let delete_error = crate::db::users::delete_user_with_roster(&pool, user_id, "example.test")
        .await
        .unwrap_err();
    assert!(delete_error
        .to_string()
        .contains("upload storage capacity busy; retry account deletion"));
    cleanup_tx.rollback().await.unwrap();

    sqlx::query("DELETE FROM upload_cleanup_queue WHERE object_id=$1")
        .bind(cleanup_id)
        .execute(&pool)
        .await
        .unwrap();
    assert!(
        crate::db::users::delete_user_with_roster(&pool, user_id, "example.test",)
            .await
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn typed_upload_admission_results_release_capacity_lock_from_outer_transaction() {
    let url = std::env::var("TEST_DATABASE_URL")
        .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(8)
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
    let user_id = insert_user(&pool).await;

    // Reserve obtains the ledger before it attempts the owner row.  Hold
    // that owner on one connection, retain the caller transaction after
    // its typed `false`, and prove another connection can still acquire
    // the ledger before either transaction completes.
    let mut owner_tx = pool.begin().await.unwrap();
    sqlx::query("SELECT id FROM users WHERE id=$1 FOR UPDATE")
        .bind(user_id)
        .fetch_one(&mut *owner_tx)
        .await
        .unwrap();
    let mut reserve_outer_tx = pool.begin().await.unwrap();
    let reserved: bool = sqlx::query_scalar(
        "SELECT northstar_upload_reserve_slot(
                 $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12
             )",
    )
    .bind(Uuid::new_v4())
    .bind(user_id)
    .bind("outer-transaction-reserve.bin")
    .bind("application/octet-stream")
    .bind(1_i64)
    .bind(b"outer-transaction-reserve".as_slice())
    .bind(10_i64)
    .bind(10_i64)
    .bind("local")
    .bind(TEST_UPLOAD_RETAINED_FILES_LIMIT)
    .bind(TEST_UPLOAD_RETAINED_BYTES_LIMIT)
    .bind(TEST_UPLOAD_PENDING_LIMIT)
    .fetch_one(&mut *reserve_outer_tx)
    .await
    .unwrap();
    assert!(
        !reserved,
        "owner-row NOWAIT contention must retain the established typed false result"
    );
    sqlx::query(
        "SELECT singleton FROM upload_storage_capacity_ledger
             WHERE singleton FOR UPDATE NOWAIT",
    )
    .fetch_one(&pool)
    .await
    .expect("typed reserve false must not retain the ledger in its outer transaction");
    reserve_outer_tx.rollback().await.unwrap();
    owner_tx.rollback().await.unwrap();

    // The same savepoint rollback is required for an ordinary quota
    // refusal, where the capacity and owner rows were both acquired but
    // no reservation was admitted.
    let slot_id = create_upload_slot(
        &pool,
        UploadReservation {
            user_id,
            filename: "outer-transaction-claim.bin",
            content_type: "application/octet-stream",
            size: 1,
            token_hash: b"outer-transaction-claim",
            max_files_per_user: 10,
            max_bytes_per_user: 10,
            storage_backend: "local",
        },
    )
    .await
    .unwrap()
    .unwrap();
    let mut reserve_quota_outer_tx = pool.begin().await.unwrap();
    let quota_reserved: bool = sqlx::query_scalar(
        "SELECT northstar_upload_reserve_slot(
                 $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12
             )",
    )
    .bind(Uuid::new_v4())
    .bind(user_id)
    .bind("outer-transaction-quota.bin")
    .bind("application/octet-stream")
    .bind(1_i64)
    .bind(b"outer-transaction-quota".as_slice())
    .bind(1_i64)
    .bind(10_i64)
    .bind("local")
    .bind(TEST_UPLOAD_RETAINED_FILES_LIMIT)
    .bind(TEST_UPLOAD_RETAINED_BYTES_LIMIT)
    .bind(TEST_UPLOAD_PENDING_LIMIT)
    .fetch_one(&mut *reserve_quota_outer_tx)
    .await
    .unwrap();
    assert!(
        !quota_reserved,
        "quota refusal must retain the established typed false result"
    );
    sqlx::query(
        "SELECT singleton FROM upload_storage_capacity_ledger
             WHERE singleton FOR UPDATE NOWAIT",
    )
    .fetch_one(&pool)
    .await
    .expect("ordinary reserve false must not retain the ledger in its outer transaction");
    reserve_quota_outer_tx.rollback().await.unwrap();

    // Claim follows the same ledger-then-slot order.  The slot owner and
    // caller remain open while a third pooled connection verifies that the
    // typed `in_progress` response rolled the capacity lock back.
    let mut slot_tx = pool.begin().await.unwrap();
    sqlx::query("SELECT id FROM upload_slots WHERE id=$1 FOR UPDATE")
        .bind(slot_id)
        .fetch_one(&mut *slot_tx)
        .await
        .unwrap();
    let mut claim_outer_tx = pool.begin().await.unwrap();
    let claim_outcome: String = sqlx::query_scalar(
        "SELECT outcome
               FROM northstar_upload_claim_slot($1,$2,$3,$4,$5)",
    )
    .bind(slot_id)
    .bind(b"outer-transaction-claim".as_slice())
    .bind(90_i64)
    .bind(MAX_UPLOAD_ATTEMPTS)
    .bind(MAX_UPLOAD_REPLAYS)
    .fetch_one(&mut *claim_outer_tx)
    .await
    .unwrap();
    assert_eq!(claim_outcome, "in_progress");
    sqlx::query(
        "SELECT singleton FROM upload_storage_capacity_ledger
             WHERE singleton FOR UPDATE NOWAIT",
    )
    .fetch_one(&pool)
    .await
    .expect("typed claim in_progress must not retain the ledger in its outer transaction");
    claim_outer_tx.rollback().await.unwrap();
    slot_tx.rollback().await.unwrap();

    // Finally, verify the ordinary live-lease `in_progress` result.  It
    // is not a lock conflict, but it must take the same rollback path
    // rather than keeping the global authority for the caller's outer
    // transaction.
    let active_lease = match claim_upload_slot(&pool, slot_id, b"outer-transaction-claim", 90)
        .await
        .unwrap()
    {
        UploadClaimOutcome::Acquired(lease) => lease,
        other => panic!("unexpected initial claim outcome: {other:?}"),
    };
    let mut live_claim_outer_tx = pool.begin().await.unwrap();
    let live_claim_outcome: String = sqlx::query_scalar(
        "SELECT outcome
               FROM northstar_upload_claim_slot($1,$2,$3,$4,$5)",
    )
    .bind(slot_id)
    .bind(b"outer-transaction-claim".as_slice())
    .bind(90_i64)
    .bind(MAX_UPLOAD_ATTEMPTS)
    .bind(MAX_UPLOAD_REPLAYS)
    .fetch_one(&mut *live_claim_outer_tx)
    .await
    .unwrap();
    assert_eq!(live_claim_outcome, "in_progress");
    sqlx::query(
        "SELECT singleton FROM upload_storage_capacity_ledger
             WHERE singleton FOR UPDATE NOWAIT",
    )
    .fetch_one(&pool)
    .await
    .expect("ordinary claim in_progress must not retain the ledger in its outer transaction");
    live_claim_outer_tx.rollback().await.unwrap();
    assert!(
        release_upload_claim(&pool, slot_id, active_lease.claim_token)
            .await
            .unwrap()
    );
}

#[tokio::test]
#[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
async fn upload_quota_reservation_is_serialized_and_expiry_releases_capacity() {
    let url = std::env::var("TEST_DATABASE_URL")
        .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(16)
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
    let user_id = insert_user(&pool).await;

    let competitors = 12;
    let barrier = Arc::new(Barrier::new(competitors + 1));
    let mut tasks = Vec::with_capacity(competitors);
    for attempt in 0..competitors {
        let pool = pool.clone();
        let barrier = barrier.clone();
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            create_upload_slot(
                &pool,
                UploadReservation {
                    user_id,
                    filename: &format!("quota-{attempt}.bin"),
                    content_type: "application/octet-stream",
                    size: 6,
                    token_hash: format!("token-{attempt}").as_bytes(),
                    max_files_per_user: 100,
                    max_bytes_per_user: 10,
                    storage_backend: "local",
                },
            )
            .await
            .unwrap()
        }));
    }
    barrier.wait().await;
    let mut winners = Vec::new();
    for task in tasks {
        if let Some(id) = task.await.unwrap() {
            winners.push(id);
        }
    }
    assert_eq!(
        winners.len(),
        1,
        "quota check and reservation must be atomic"
    );
    assert!(
        create_upload_slot(
            &pool,
            UploadReservation {
                user_id,
                filename: "blocked.bin",
                content_type: "application/octet-stream",
                size: 4,
                token_hash: b"blocked",
                max_files_per_user: 1,
                max_bytes_per_user: 100,
                storage_backend: "local",
            },
        )
        .await
        .unwrap()
        .is_none(),
        "an active reservation consumes the file-count quota",
    );

    sqlx::query("UPDATE upload_slots SET expires_at=NOW()-INTERVAL '1 second' WHERE id=$1")
        .bind(winners[0])
        .execute(&pool)
        .await
        .unwrap();
    assert!(
        create_upload_slot(
            &pool,
            UploadReservation {
                user_id,
                filename: "released.bin",
                content_type: "application/octet-stream",
                size: 10,
                token_hash: b"released",
                max_files_per_user: 1,
                max_bytes_per_user: 10,
                storage_backend: "local",
            },
        )
        .await
        .unwrap()
        .is_none(),
        "expired rows continue consuming physical quota until durable cleanup completes",
    );

    sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user_id)
        .execute(&pool)
        .await
        .unwrap();
}
