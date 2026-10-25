//! PostgreSQL adapter of the upload context: slots and claims, stage and promotion lifecycle, user
//! deletion, storage and cleanup jobs, the capacity authority audit, and the maintenance repository
//! the upload worker uses.

#![forbid(unsafe_code)]

use anyhow::Result;
use sqlx::{PgPool, Row};
#[cfg(any(test, feature = "test-support"))]
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

use northstar_upload_application::service::{PromotionClaim, UploadLifecycleRepository};
pub use northstar_upload_application::service::{
    UploadClaimOutcome, UploadLease, UploadRenewOutcome, UploadSlot, UploadStageProjection,
    UserUploadDeleteOutcome,
};

mod capacity_audit;
mod deletion;
mod lifecycle;
mod slots;
mod storage_jobs;

pub mod maintenance;

pub use self::capacity_audit::*;
pub use self::deletion::*;
pub use self::lifecycle::*;
pub use self::slots::*;
pub use self::storage_jobs::*;

#[derive(Clone)]
pub struct PostgresUploadRepository {
    pool: PgPool,
}

impl PostgresUploadRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

impl northstar_upload_application::UploadRepository for PostgresUploadRepository {
    type Error = anyhow::Error;

    async fn reserve_slot(
        &self,
        request: &northstar_upload_application::UploadSlotRequest<'_>,
        token_hash: &[u8],
    ) -> Result<Option<Uuid>> {
        let size = i64::try_from(request.size)
            .map_err(|_| anyhow::anyhow!("upload reservation exceeds PostgreSQL BIGINT"))?;
        create_upload_slot_bounded(
            &self.pool,
            UploadReservation {
                user_id: request.user_id,
                filename: request.filename,
                content_type: request.content_type,
                size,
                token_hash,
                max_files_per_user: request.max_files_per_user,
                max_bytes_per_user: request.max_bytes_per_user,
                storage_backend: request.storage_backend,
            },
            request.max_retained_files,
            request.max_retained_bytes,
            request.max_pending_jobs,
        )
        .await
    }
}

impl UploadLifecycleRepository for PostgresUploadRepository {
    async fn claim_slot(
        &self,
        id: Uuid,
        token_hash: &[u8],
        lease_seconds: i64,
    ) -> Result<UploadClaimOutcome> {
        claim_upload_slot(&self.pool, id, token_hash, lease_seconds).await
    }

    async fn record_replay(
        &self,
        id: Uuid,
        token_hash: &[u8],
        content_sha256: &[u8; 32],
    ) -> Result<bool> {
        record_upload_replay(&self.pool, id, token_hash, content_sha256).await
    }

    async fn renew_claim(
        &self,
        id: Uuid,
        claim_token: Uuid,
        lease_seconds: i64,
    ) -> Result<UploadRenewOutcome> {
        renew_upload_claim(&self.pool, id, claim_token, lease_seconds).await
    }

    async fn release_claim(&self, id: Uuid, claim_token: Uuid) -> Result<bool> {
        release_upload_claim(&self.pool, id, claim_token).await
    }

    async fn record_stage(&self, projection: UploadStageProjection<'_>) -> Result<bool> {
        record_upload_stage(&self.pool, projection).await
    }

    async fn claim_promotion(
        &self,
        id: Uuid,
        storage_attempt: Uuid,
        storage_fence: i64,
    ) -> Result<Option<Uuid>> {
        claim_upload_promotion_job(&self.pool, id, storage_attempt, storage_fence).await
    }

    async fn begin_promotion(&self, claim: PromotionClaim) -> Result<bool> {
        begin_upload_promotion(
            &self.pool,
            claim.id,
            claim.storage_attempt,
            claim.storage_fence,
            claim.promotion_claim_token,
        )
        .await
    }

    async fn retire_promotion(&self, claim: PromotionClaim) -> Result<bool> {
        retire_upload_promotion_for_cleanup(
            &self.pool,
            claim.id,
            claim.storage_attempt,
            claim.storage_fence,
            claim.promotion_claim_token,
        )
        .await
    }

    async fn defer_promotion(&self, claim: PromotionClaim) -> Result<bool> {
        defer_upload_promotion_job(
            &self.pool,
            claim.id,
            claim.storage_attempt,
            claim.storage_fence,
            claim.promotion_claim_token,
        )
        .await
    }

    async fn complete_promotion(&self, projection: PromotedUploadProjection<'_>) -> Result<bool> {
        complete_promoted_upload(&self.pool, projection).await
    }

    async fn attempt_committed(&self, identity: CommittedUploadIdentity<'_>) -> Result<bool> {
        upload_attempt_is_committed(&self.pool, identity).await
    }

    async fn public_file(&self, id: Uuid) -> Result<Option<UploadSlot>> {
        uploaded_file(&self.pool, id).await
    }

    async fn delete_authorized(
        &self,
        user_id: Uuid,
        auth_generation: i64,
        session_token: &str,
        id: Uuid,
        request_id: Uuid,
    ) -> Result<UserUploadDeleteOutcome> {
        queue_user_upload_delete_authorized(
            &self.pool,
            user_id,
            auth_generation,
            session_token,
            id,
            request_id,
        )
        .await
    }
}

pub const MAX_UPLOAD_ATTEMPTS: i64 = 8;
const MAX_UPLOAD_REPLAYS: i64 = 3;
const UPLOAD_HEALTH_COUNT_SATURATION: i64 = 1001;
#[cfg(any(test, feature = "test-support"))]
pub const TEST_UPLOAD_PENDING_LIMIT: i64 = 128;
#[cfg(any(test, feature = "test-support"))]
pub const TEST_UPLOAD_RETAINED_FILES_LIMIT: i64 = 10_000;
#[cfg(any(test, feature = "test-support"))]
pub const TEST_UPLOAD_RETAINED_BYTES_LIMIT: i64 = 1024 * 1024 * 1024;

pub use northstar_upload_application::maintenance::CommittedUploadIdentity;
pub use northstar_upload_application::maintenance::PromotedUploadProjection;
pub use northstar_upload_application::maintenance::UploadAuthorityProbe;

/// Lightweight catalog proof for the upload-capacity enforcement boundary.
///
/// Unlike the fact reconciliation below, this check does not scan upload
/// rows. It is safe to run frequently and detects a disabled/misattached
/// trigger, changed routine authority, owner drift, public EXECUTE grant, or
/// deployment-policy change before a later write can silently corrupt the
/// trigger-maintained ledger.
pub use northstar_upload_application::maintenance::UploadCapacityAuthorityAudit;
/// Low-frequency proof that the trigger-maintained O(1) capacity authority
/// still equals a statement-consistent projection of the underlying facts.
/// Hot admission must never perform these scans; the supervised upload worker
/// uses them only as an integrity alarm and deliberately does not rewrite the
/// authority automatically.
pub use northstar_upload_application::maintenance::UploadCapacityReconciliation;
pub use northstar_upload_application::maintenance::UploadCleanupJob;
pub use northstar_upload_application::maintenance::UploadQueueMetrics;
pub use northstar_upload_application::maintenance::UploadStorageJob;

pub use northstar_upload_application::maintenance::UploadScrubJob;

/// Production source of this module: the file itself followed by each
/// production child module file, so source-contract tests keep reading the
/// whole module after code moves between them. The children are listed in
/// the order their code had in the former single file, because some
/// contracts split the source on a marker that occurs in more than one child.
/// `module_source_lists_every_child_module` keeps this list in step with the
/// non-test `mod` declarations above.
#[cfg(any(test, feature = "test-support"))]
const MODULE_SOURCE: &[(&str, &str)] = &[
    ("upload", include_str!("lib.rs")),
    ("slots", include_str!("slots.rs")),
    ("lifecycle", include_str!("lifecycle.rs")),
    ("capacity_audit", include_str!("capacity_audit.rs")),
    ("storage_jobs", include_str!("storage_jobs.rs")),
    ("deletion", include_str!("deletion.rs")),
];

#[cfg(any(test, feature = "test-support"))]
pub fn module_source() -> String {
    MODULE_SOURCE
        .iter()
        .map(|(_, text)| *text)
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod module_source_tests;
