use super::{
    audit_upload_capacity_authority, claim_upload_slot, cleanup_expired_upload_slots,
    cleanup_object_version, complete_queued_upload_cleanup, complete_upload, create_upload_slot,
    defer_queued_upload_cleanup, is_retryable_upload_capacity_lock, queue_user_upload_delete,
    queue_user_upload_delete_authorized, queued_upload_cleanup, reconcile_upload_capacity_ledger,
    record_upload_replay, release_upload_claim, renew_upload_claim,
    upload_cleanup_generation_is_quiescent, upload_queue_metrics, uploaded_file,
    validate_upload_capacity_policy, UploadCapacityAuthorityAudit, UploadCapacityReconciliation,
    UploadClaimOutcome, UploadRenewOutcome, UploadReservation, UserUploadDeleteOutcome,
    MAX_UPLOAD_ATTEMPTS, MAX_UPLOAD_REPLAYS, TEST_UPLOAD_PENDING_LIMIT,
    TEST_UPLOAD_RETAINED_BYTES_LIMIT, TEST_UPLOAD_RETAINED_FILES_LIMIT,
};
use crate::db;
use sqlx::{PgPool, Row};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Barrier;
use uuid::Uuid;

#[path = "upload_tests/capacity_admission_tests.rs"]
mod capacity_admission;
#[path = "upload_tests/capacity_authority_tests.rs"]
mod capacity_authority;
#[path = "upload_tests/source_contract_tests.rs"]
mod source_contracts;
#[path = "upload_tests/storage_job_tests.rs"]
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
