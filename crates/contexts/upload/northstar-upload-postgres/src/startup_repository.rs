//! PostgreSQL adapter for the upload context's startup authority reads.

use anyhow::Result;
use northstar_upload_application::startup::{UploadCapacityLimits, UploadStartupRepository};
use sqlx::PgPool;
use uuid::Uuid;

pub struct PostgresUploadStartupRepository {
    pool: PgPool,
}

impl PostgresUploadStartupRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

impl UploadStartupRepository for PostgresUploadStartupRepository {
    async fn validate_storage_backend(
        &self,
        backend: &str,
        namespace_sha256: &[u8; 32],
    ) -> Result<i64> {
        crate::validate_upload_storage_backend(&self.pool, backend, namespace_sha256).await
    }

    async fn validate_capacity_policy(&self, limits: UploadCapacityLimits) -> Result<(i64, bool)> {
        crate::validate_upload_capacity_policy(
            &self.pool,
            limits.max_pending_jobs,
            limits.max_retained_files,
            limits.max_retained_bytes,
        )
        .await
    }

    async fn audit_capacity_authority(&self, limits: UploadCapacityLimits) -> Result<u64> {
        Ok(crate::audit_upload_capacity_authority(
            &self.pool,
            limits.max_pending_jobs,
            limits.max_retained_files,
            limits.max_retained_bytes,
        )
        .await?
        .violation_count())
    }

    async fn reconcile_capacity_ledger(&self) -> Result<u64> {
        Ok(crate::reconcile_upload_capacity_ledger(&self.pool)
            .await?
            .mismatch_count())
    }

    async fn claim_is_live(&self, object_id: Uuid, claim_token: Uuid) -> Result<bool> {
        crate::upload_claim_is_live(&self.pool, object_id, claim_token).await
    }
}
