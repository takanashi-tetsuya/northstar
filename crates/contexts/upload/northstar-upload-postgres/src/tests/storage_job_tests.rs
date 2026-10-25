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
    northstar_postgres::MIGRATOR.run(&pool).await.unwrap();
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
