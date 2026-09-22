//! Fenced upload reconciliation, integrity observations and durable cleanup jobs.
use anyhow::Result;
use uuid::Uuid;

#[derive(Clone, Debug)]
pub struct UploadCleanupJob {
    pub object_id: Uuid,
    pub storage_backend: String,
    pub object_key: String,
    pub object_version: Option<String>,
    pub stage_key: Option<String>,
    pub stage_version: Option<String>,
    pub storage_attempt: Option<Uuid>,
    pub storage_fence: i64,
    pub claim_token: Uuid,
}
#[derive(Clone, Debug)]
pub struct UploadStorageJob {
    pub id: i64,
    pub object_id: Uuid,
    pub storage_attempt: Uuid,
    pub action: String,
    pub storage_backend: String,
    pub stage_key: Option<String>,
    pub stage_version: Option<String>,
    pub object_key: Option<String>,
    pub object_version: Option<String>,
    pub expected_size: Option<i64>,
    pub expected_sha256: Option<[u8; 32]>,
    pub storage_fence: i64,
    pub claim_token: Uuid,
}
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct UploadQueueMetrics {
    pub storage_jobs_pending: u64,
    pub cleanup_jobs_pending: u64,
    pub cleanup_obligation_debt: u64,
    pub configured_pending_limit: u64,
    pub legacy_overcommit_draining: u64,
    pub recovery_retained_files: u64,
    pub recovery_retained_bytes: u64,
    pub recovery_overcommit_draining: u64,
    pub oldest_pending_age_seconds: u64,
    /// Saturates at 1001; 1001 means at least 1001, not an exact count.
    pub dead_letter_jobs_capped: u64,
    /// Saturates at 1001; 1001 means at least 1001, not an exact count.
    pub scrub_failures_capped: u64,
    pub scrub_due_capped: u64,
    pub scrub_oldest_overdue_seconds: u64,
    pub cleanup_obligations_due_capped: u64,
    pub cleanup_oldest_overdue_seconds: u64,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UploadCapacityReconciliation {
    pub ledger_retained_files: i64,
    pub fact_retained_files: i64,
    pub ledger_retained_bytes: i64,
    pub fact_retained_bytes: i64,
    pub ledger_pending_jobs: i64,
    pub fact_pending_jobs: i64,
    pub ledger_storage_jobs_pending: i64,
    pub fact_storage_jobs_pending: i64,
    pub ledger_cleanup_jobs_pending: i64,
    pub fact_cleanup_jobs_pending: i64,
    pub ledger_cleanup_obligation_debt: i64,
    pub fact_cleanup_obligation_debt: i64,
    pub ledger_recovery_retained_files: i64,
    pub fact_recovery_retained_files: i64,
    pub ledger_recovery_retained_bytes: i64,
    pub fact_recovery_retained_bytes: i64,
    pub ledger_legacy_overcommit_draining: bool,
    pub fact_legacy_overcommit_draining: bool,
    pub ledger_recovery_overcommit_draining: bool,
    pub fact_recovery_overcommit_draining: bool,
    pub projection_size_conflicts: i64,
}
impl UploadCapacityReconciliation {
    pub fn mismatch_count(self) -> u64 {
        let pairs = [
            (self.ledger_retained_files, self.fact_retained_files),
            (self.ledger_retained_bytes, self.fact_retained_bytes),
            (self.ledger_pending_jobs, self.fact_pending_jobs),
            (
                self.ledger_storage_jobs_pending,
                self.fact_storage_jobs_pending,
            ),
            (
                self.ledger_cleanup_jobs_pending,
                self.fact_cleanup_jobs_pending,
            ),
            (
                self.ledger_cleanup_obligation_debt,
                self.fact_cleanup_obligation_debt,
            ),
            (
                self.ledger_recovery_retained_files,
                self.fact_recovery_retained_files,
            ),
            (
                self.ledger_recovery_retained_bytes,
                self.fact_recovery_retained_bytes,
            ),
        ];
        let counter_mismatches = pairs
            .into_iter()
            .filter(|(ledger, fact)| ledger != fact)
            .count() as u64;
        counter_mismatches
            .saturating_add(u64::from(
                self.ledger_legacy_overcommit_draining != self.fact_legacy_overcommit_draining,
            ))
            .saturating_add(u64::from(
                self.ledger_recovery_overcommit_draining != self.fact_recovery_overcommit_draining,
            ))
            .saturating_add(self.projection_size_conflicts.max(0) as u64)
    }
}
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct UploadCapacityAuthorityAudit {
    pub relation_owner_violations: i64,
    pub relation_acl_violations: i64,
    pub function_authority_violations: i64,
    pub trigger_authority_violations: i64,
    pub policy_binding_violations: i64,
}
impl UploadCapacityAuthorityAudit {
    pub fn violation_count(self) -> u64 {
        [
            self.relation_owner_violations,
            self.relation_acl_violations,
            self.function_authority_violations,
            self.trigger_authority_violations,
            self.policy_binding_violations,
        ]
        .into_iter()
        .map(|violations| violations.max(0) as u64)
        .fold(0_u64, u64::saturating_add)
    }
}
#[derive(Debug)]
pub struct UploadScrubJob {
    pub object_id: Uuid,
    pub storage_attempt: Uuid,
    pub object_key: String,
    pub object_version: Option<String>,
    pub expected_size: u64,
    pub expected_sha256: [u8; 32],
    pub claim_token: Uuid,
}
pub struct PromotedUploadProjection<'a> {
    pub id: Uuid,
    pub claim_token: Uuid,
    pub promotion_claim_token: Uuid,
    pub storage_backend: &'a str,
    pub object_key: &'a str,
    pub object_version: Option<&'a str>,
    pub content_sha256: &'a [u8; 32],
    pub size: u64,
    pub retention_seconds: u64,
    pub storage_fence: i64,
}
pub struct CommittedUploadIdentity<'a> {
    pub id: Uuid,
    pub storage_attempt: Uuid,
    pub storage_backend: &'a str,
    pub object_key: &'a str,
    pub object_version: Option<&'a str>,
    pub content_sha256: &'a [u8; 32],
    pub size: u64,
    pub storage_fence: i64,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UploadAuthorityProbe {
    pub namespace_matches: bool,
    pub capacity_matches: bool,
    pub recovery_draining: bool,
}
pub(crate) trait UploadMaintenanceRepository: Send + Sync {
    #[allow(clippy::too_many_arguments)]
    fn upload_storage_authority_matches(
        &self,
        backend: &str,
        namespace_sha256: &[u8; 32],
        namespace_generation: i64,
        capacity_policy_generation: i64,
        pending_limit: i64,
        retained_files_limit: i64,
        retained_bytes_limit: i64,
    ) -> impl std::future::Future<Output = Result<UploadAuthorityProbe>> + Send;
    fn audit_upload_capacity_authority(
        &self,
        pending_limit: i64,
        retained_files_limit: i64,
        retained_bytes_limit: i64,
    ) -> impl std::future::Future<Output = Result<UploadCapacityAuthorityAudit>> + Send;
    fn reconcile_upload_capacity_ledger(
        &self,
    ) -> impl std::future::Future<Output = Result<UploadCapacityReconciliation>> + Send;
    fn cleanup_expired_upload_slots(
        &self,
    ) -> impl std::future::Future<Output = Result<Vec<Uuid>>> + Send;
    fn claim_upload_storage_jobs(
        &self,
    ) -> impl std::future::Future<Output = Result<Vec<UploadStorageJob>>> + Send;
    fn defer_upload_storage_job(
        &self,
        id: i64,
        claim_token: Uuid,
    ) -> impl std::future::Future<Output = Result<bool>> + Send;
    fn fail_upload_storage_job(
        &self,
        id: i64,
        claim_token: Uuid,
        error: &str,
    ) -> impl std::future::Future<Output = Result<bool>> + Send;
    fn queued_upload_cleanup(
        &self,
    ) -> impl std::future::Future<Output = Result<Vec<UploadCleanupJob>>> + Send;
    fn defer_queued_upload_cleanup(
        &self,
        id: Uuid,
        claim_token: Uuid,
    ) -> impl std::future::Future<Output = Result<bool>> + Send;
    fn fail_queued_upload_cleanup(
        &self,
        id: Uuid,
        claim_token: Uuid,
        error: &str,
    ) -> impl std::future::Future<Output = Result<bool>> + Send;
    fn claim_upload_scrub_jobs(
        &self,
    ) -> impl std::future::Future<Output = Result<Vec<UploadScrubJob>>> + Send;
    fn complete_upload_scrub(
        &self,
        id: Uuid,
        claim: Uuid,
    ) -> impl std::future::Future<Output = Result<bool>> + Send;
    fn defer_upload_scrub(
        &self,
        id: Uuid,
        claim: Uuid,
    ) -> impl std::future::Future<Output = Result<bool>> + Send;
    fn fail_upload_scrub(
        &self,
        id: Uuid,
        claim: Uuid,
    ) -> impl std::future::Future<Output = Result<bool>> + Send;
    fn upload_queue_metrics(
        &self,
    ) -> impl std::future::Future<Output = Result<UploadQueueMetrics>> + Send;
    fn begin_upload_promotion(
        &self,
        id: Uuid,
        claim_token: Uuid,
        storage_fence: i64,
        promotion_claim_token: Uuid,
    ) -> impl std::future::Future<Output = Result<bool>> + Send;
    fn upload_attempt_is_committed(
        &self,
        identity: CommittedUploadIdentity<'_>,
    ) -> impl std::future::Future<Output = Result<bool>> + Send;
    fn complete_upload_storage_job(
        &self,
        id: i64,
        claim_token: Uuid,
    ) -> impl std::future::Future<Output = Result<bool>> + Send;
    fn retire_upload_promotion_for_cleanup(
        &self,
        id: Uuid,
        storage_attempt: Uuid,
        storage_fence: i64,
        promotion_claim_token: Uuid,
    ) -> impl std::future::Future<Output = Result<bool>> + Send;
    fn complete_promoted_upload(
        &self,
        projection: PromotedUploadProjection<'_>,
    ) -> impl std::future::Future<Output = Result<bool>> + Send;
    fn confirm_upload_stage_absence(
        &self,
        id: i64,
        claim_token: Uuid,
        removed_now: bool,
        quiet_seconds: i64,
    ) -> impl std::future::Future<Output = Result<bool>> + Send;
    fn upload_cleanup_generation_is_quiescent(
        &self,
        id: Uuid,
        claim_token: Uuid,
        storage_fence: i64,
    ) -> impl std::future::Future<Output = Result<bool>> + Send;
    fn confirm_upload_cleanup_absence(
        &self,
        id: Uuid,
        claim_token: Uuid,
        removed_now: bool,
        quiet_seconds: i64,
    ) -> impl std::future::Future<Output = Result<bool>> + Send;
    fn complete_queued_upload_cleanup(
        &self,
        id: Uuid,
        claim_token: Uuid,
    ) -> impl std::future::Future<Output = Result<bool>> + Send;
}
