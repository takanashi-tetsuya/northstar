//! PostgreSQL adapter for the upload reconciliation worker.
use crate::{db, services::upload_maintenance::*};
use anyhow::Result;
use sqlx::PgPool;
use uuid::Uuid;
#[derive(Clone)]
pub(crate) struct PostgresUploadMaintenanceRepository {
    pool: PgPool,
}
impl PostgresUploadMaintenanceRepository {
    pub(crate) fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}
impl UploadMaintenanceRepository for PostgresUploadMaintenanceRepository {
    #[allow(clippy::too_many_arguments)]
    async fn upload_storage_authority_matches(
        &self,
        backend: &str,
        namespace_sha256: &[u8; 32],
        namespace_generation: i64,
        capacity_policy_generation: i64,
        pending_limit: i64,
        retained_files_limit: i64,
        retained_bytes_limit: i64,
    ) -> Result<UploadAuthorityProbe> {
        db::upload_storage_authority_matches(
            &self.pool,
            backend,
            namespace_sha256,
            namespace_generation,
            capacity_policy_generation,
            pending_limit,
            retained_files_limit,
            retained_bytes_limit,
        )
        .await
    }
    async fn audit_upload_capacity_authority(
        &self,
        pending_limit: i64,
        retained_files_limit: i64,
        retained_bytes_limit: i64,
    ) -> Result<UploadCapacityAuthorityAudit> {
        db::audit_upload_capacity_authority(
            &self.pool,
            pending_limit,
            retained_files_limit,
            retained_bytes_limit,
        )
        .await
    }
    async fn reconcile_upload_capacity_ledger(&self) -> Result<UploadCapacityReconciliation> {
        db::reconcile_upload_capacity_ledger(&self.pool).await
    }
    async fn cleanup_expired_upload_slots(&self) -> Result<Vec<Uuid>> {
        db::cleanup_expired_upload_slots(&self.pool).await
    }
    async fn claim_upload_storage_jobs(&self) -> Result<Vec<UploadStorageJob>> {
        db::claim_upload_storage_jobs(&self.pool).await
    }
    async fn defer_upload_storage_job(&self, id: i64, claim_token: Uuid) -> Result<bool> {
        db::defer_upload_storage_job(&self.pool, id, claim_token).await
    }
    async fn fail_upload_storage_job(
        &self,
        id: i64,
        claim_token: Uuid,
        error: &str,
    ) -> Result<bool> {
        db::fail_upload_storage_job(&self.pool, id, claim_token, error).await
    }
    async fn queued_upload_cleanup(&self) -> Result<Vec<UploadCleanupJob>> {
        db::queued_upload_cleanup(&self.pool).await
    }
    async fn defer_queued_upload_cleanup(&self, id: Uuid, claim_token: Uuid) -> Result<bool> {
        db::defer_queued_upload_cleanup(&self.pool, id, claim_token).await
    }
    async fn fail_queued_upload_cleanup(
        &self,
        id: Uuid,
        claim_token: Uuid,
        error: &str,
    ) -> Result<bool> {
        db::fail_queued_upload_cleanup(&self.pool, id, claim_token, error).await
    }
    async fn claim_upload_scrub_jobs(&self) -> Result<Vec<UploadScrubJob>> {
        db::claim_upload_scrub_jobs(&self.pool).await
    }
    async fn complete_upload_scrub(&self, id: Uuid, claim: Uuid) -> Result<bool> {
        db::complete_upload_scrub(&self.pool, id, claim).await
    }
    async fn defer_upload_scrub(&self, id: Uuid, claim: Uuid) -> Result<bool> {
        db::defer_upload_scrub(&self.pool, id, claim).await
    }
    async fn fail_upload_scrub(&self, id: Uuid, claim: Uuid) -> Result<bool> {
        db::fail_upload_scrub(&self.pool, id, claim).await
    }
    async fn upload_queue_metrics(&self) -> Result<UploadQueueMetrics> {
        db::upload_queue_metrics(&self.pool).await
    }
    async fn begin_upload_promotion(
        &self,
        id: Uuid,
        claim_token: Uuid,
        storage_fence: i64,
        promotion_claim_token: Uuid,
    ) -> Result<bool> {
        db::begin_upload_promotion(
            &self.pool,
            id,
            claim_token,
            storage_fence,
            promotion_claim_token,
        )
        .await
    }
    async fn upload_attempt_is_committed(
        &self,
        identity: CommittedUploadIdentity<'_>,
    ) -> Result<bool> {
        db::upload_attempt_is_committed(&self.pool, identity).await
    }
    async fn complete_upload_storage_job(&self, id: i64, claim_token: Uuid) -> Result<bool> {
        db::complete_upload_storage_job(&self.pool, id, claim_token).await
    }
    async fn retire_upload_promotion_for_cleanup(
        &self,
        id: Uuid,
        storage_attempt: Uuid,
        storage_fence: i64,
        promotion_claim_token: Uuid,
    ) -> Result<bool> {
        db::retire_upload_promotion_for_cleanup(
            &self.pool,
            id,
            storage_attempt,
            storage_fence,
            promotion_claim_token,
        )
        .await
    }
    async fn complete_promoted_upload(
        &self,
        projection: PromotedUploadProjection<'_>,
    ) -> Result<bool> {
        db::complete_promoted_upload(&self.pool, projection).await
    }
    async fn confirm_upload_stage_absence(
        &self,
        id: i64,
        claim_token: Uuid,
        removed_now: bool,
        quiet_seconds: i64,
    ) -> Result<bool> {
        db::confirm_upload_stage_absence(&self.pool, id, claim_token, removed_now, quiet_seconds)
            .await
    }
    async fn upload_cleanup_generation_is_quiescent(
        &self,
        id: Uuid,
        claim_token: Uuid,
        storage_fence: i64,
    ) -> Result<bool> {
        db::upload_cleanup_generation_is_quiescent(&self.pool, id, claim_token, storage_fence).await
    }
    async fn confirm_upload_cleanup_absence(
        &self,
        id: Uuid,
        claim_token: Uuid,
        removed_now: bool,
        quiet_seconds: i64,
    ) -> Result<bool> {
        db::confirm_upload_cleanup_absence(&self.pool, id, claim_token, removed_now, quiet_seconds)
            .await
    }
    async fn complete_queued_upload_cleanup(&self, id: Uuid, claim_token: Uuid) -> Result<bool> {
        db::complete_queued_upload_cleanup(&self.pool, id, claim_token).await
    }
}
