use super::{
    audit_upload_capacity_authority, claim_upload_slot, cleanup_object_version,
    complete_queued_upload_cleanup, create_upload_slot, defer_queued_upload_cleanup,
    queued_upload_cleanup, reconcile_upload_capacity_ledger, release_upload_claim,
    upload_cleanup_generation_is_quiescent, upload_queue_metrics, validate_upload_capacity_policy,
    UploadCapacityAuthorityAudit, UploadCapacityReconciliation, UploadClaimOutcome,
    UploadReservation, MAX_UPLOAD_ATTEMPTS, MAX_UPLOAD_REPLAYS, TEST_UPLOAD_PENDING_LIMIT,
    TEST_UPLOAD_RETAINED_BYTES_LIMIT, TEST_UPLOAD_RETAINED_FILES_LIMIT,
};
use sqlx::PgPool;
use std::sync::Arc;
use tokio::sync::Barrier;
use uuid::Uuid;

#[path = "tests/capacity_admission_tests.rs"]
mod capacity_admission;
#[path = "tests/capacity_authority_tests.rs"]
mod capacity_authority;
#[path = "tests/source_contract_tests.rs"]
mod source_contracts;
#[path = "tests/storage_job_tests.rs"]
mod storage_jobs;

async fn insert_user(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    let username = format!("upload-{}", &id.simple().to_string()[..16]);
    sqlx::query(
        "INSERT INTO users (id, username, password_hash, is_admin)
             VALUES ($1, $2, 'test-only', FALSE)",
    )
    .bind(id)
    .bind(username)
    .execute(pool)
    .await
    .unwrap();
    id
}
