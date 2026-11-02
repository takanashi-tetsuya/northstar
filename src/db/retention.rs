use anyhow::Result;
use chrono::Utc;
use northstar_operations_application::maintenance_repositories::RetentionStore;
use sqlx::PgPool;

#[derive(Clone)]
pub(crate) struct PostgresMaintenanceRepository {
    pool: PgPool,
}

impl PostgresMaintenanceRepository {
    pub(crate) fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

impl northstar_operations_application::maintenance_repositories::RetentionRepository
    for PostgresMaintenanceRepository
{
    async fn purge_resolved_retention_batch(
        &self,
        store: RetentionStore,
        now: chrono::DateTime<Utc>,
        days: i64,
        batch_size: i64,
    ) -> Result<u64> {
        northstar_workflows::retention::purge_resolved_retention_batch(
            &self.pool, store, now, days, batch_size,
        )
        .await
    }
    async fn purge_released_hold_snapshots_batch(&self, days: i64, batch_size: i64) -> Result<u64> {
        northstar_operations_postgres::data_lifecycle::purge_released_hold_snapshots_batch(
            &self.pool, days, batch_size,
        )
        .await
    }
    async fn purge_audit_log_batch(&self, days: i64, batch_size: i64) -> Result<u64> {
        northstar_operations_postgres::data_lifecycle::purge_audit_log_batch(
            &self.pool, days, batch_size,
        )
        .await
    }
    async fn purge_governance_export_leases_batch(
        &self,
        days: i64,
        batch_size: i64,
    ) -> Result<u64> {
        northstar_operations_postgres::data_lifecycle::purge_governance_export_leases_batch(
            &self.pool, days, batch_size,
        )
        .await
    }
    async fn cleanup_omemo_recovery_transfers(&self, batch_size: i64) -> Result<u64> {
        northstar_auth_postgres::omemo_recovery::cleanup_omemo_recovery_transfers(
            &self.pool, batch_size,
        )
        .await
    }
    async fn purge_expired_retraction_intents(&self, batch_size: i64) -> Result<u64> {
        northstar_message_postgres::retraction_intents::purge_expired_retraction_intents(
            &self.pool, batch_size,
        )
        .await
    }
}

impl northstar_operations_application::maintenance_repositories::SubscriptionCleanupRepository
    for PostgresMaintenanceRepository
{
    async fn cleanup_expired_subscriptions(&self, batch_size: i64) -> Result<u64> {
        crate::db::cleanup_expired_subscriptions(&self.pool, batch_size).await
    }
}
