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
        crate::db::cleanup_omemo_recovery_transfers(&self.pool, batch_size).await
    }
    async fn purge_expired_retraction_intents(&self, batch_size: i64) -> Result<u64> {
        crate::db::purge_expired_retraction_intents(&self.pool, batch_size).await
    }
}

impl northstar_operations_application::maintenance_repositories::SubscriptionCleanupRepository
    for PostgresMaintenanceRepository
{
    async fn cleanup_expired_subscriptions(&self, batch_size: i64) -> Result<u64> {
        crate::db::cleanup_expired_subscriptions(&self.pool, batch_size).await
    }
}

/// Remove expired replay evidence only after its durable delivery owners have
/// released it. This repository operation needs no message HMAC capability.
pub(crate) async fn purge_expired_retraction_intents(
    pool: &PgPool,
    batch_size: i64,
) -> Result<u64> {
    anyhow::ensure!(
        (1..=10_000).contains(&batch_size),
        "retraction intent cleanup batch size must be between 1 and 10000"
    );
    Ok(sqlx::query(
        "WITH expired AS MATERIALIZED (
             SELECT id FROM personal_retraction_intents
              WHERE expires_at < clock_timestamp()
                AND s2s_outbox_id IS NULL
                AND c2s_delivery_id IS NULL
              ORDER BY expires_at,id
              LIMIT $1
              FOR UPDATE SKIP LOCKED
         )
         DELETE FROM personal_retraction_intents intent
         USING expired
         WHERE intent.id=expired.id",
    )
    .bind(batch_size)
    .execute(pool)
    .await?
    .rows_affected())
}
