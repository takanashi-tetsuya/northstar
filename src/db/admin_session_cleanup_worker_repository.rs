//! PostgreSQL adapter for the administrator session-cleanup worker's exact
//! claim token and worker identity fences.

use crate::db::{self, AdminSessionCleanupLease};
use crate::services::admin_session_cleanup_worker::AdminSessionCleanupRepository;
use anyhow::Result;
use sqlx::PgPool;
use uuid::Uuid;

pub(crate) struct PostgresAdminSessionCleanupRepository {
    pool: PgPool,
}

impl PostgresAdminSessionCleanupRepository {
    pub(crate) fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

impl AdminSessionCleanupRepository for PostgresAdminSessionCleanupRepository {
    async fn claim(
        &self,
        worker_id: Uuid,
        lease_seconds: i32,
    ) -> Result<Option<AdminSessionCleanupLease>> {
        db::claim_admin_session_cleanup(&self.pool, worker_id, lease_seconds).await
    }

    async fn renew(
        &self,
        lease: &AdminSessionCleanupLease,
        worker_id: Uuid,
        lease_seconds: i32,
    ) -> Result<bool> {
        db::renew_admin_session_cleanup(&self.pool, lease, worker_id, lease_seconds).await
    }

    async fn complete(&self, lease: &AdminSessionCleanupLease, worker_id: Uuid) -> Result<bool> {
        db::complete_admin_session_cleanup(&self.pool, lease, worker_id).await
    }

    async fn retry(
        &self,
        lease: &AdminSessionCleanupLease,
        worker_id: Uuid,
        error_code: &'static str,
    ) -> Result<bool> {
        db::retry_admin_session_cleanup(&self.pool, lease, worker_id, error_code).await
    }

    async fn target_current(
        &self,
        lease: &AdminSessionCleanupLease,
        worker_id: Uuid,
    ) -> Result<bool> {
        db::admin_session_cleanup_target_current(&self.pool, lease, worker_id).await
    }
}
