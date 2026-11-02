//! Expiry of the personal retraction replay evidence.

use anyhow::Result;
use sqlx::PgPool;

/// Remove expired replay evidence only after its durable delivery owners have
/// released it. This repository operation needs no message HMAC capability.
pub async fn purge_expired_retraction_intents(pool: &PgPool, batch_size: i64) -> Result<u64> {
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
