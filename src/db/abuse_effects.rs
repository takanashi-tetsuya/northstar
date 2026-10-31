//! The anti-abuse adapter's steps over other contexts' tables.

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use northstar_abuse_postgres::effects::{AbuseEffects, ForeignKeyReferences};
use sqlx::{PgPool, Postgres, Transaction};

pub(crate) struct RootAbuseEffects;

impl AbuseEffects for RootAbuseEffects {
    async fn foreign_key_references(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        key_id: &str,
        now: DateTime<Utc>,
    ) -> Result<ForeignKeyReferences> {
        let (
            offline_admissions,
            personal_message_identities,
            retraction_identities,
            mix_business_identities,
        ): (i64, i64, i64, i64) = sqlx::query_as(
            "SELECT
                 (SELECT COUNT(*)::bigint FROM offline_message_admissions
                   WHERE payload_key_id=$1
                     AND (offline_message_id IS NOT NULL
                          OR expires_at IS NULL OR expires_at > $2)),
                 (SELECT COUNT(*)::bigint FROM personal_message_admissions
                   WHERE payload_key_id=$1),
                  (SELECT COUNT(*)::bigint FROM personal_retraction_intents
                    WHERE semantic_key_id=$1 OR c2s_projection_key_id=$1
                       OR owner_projection_key_id=$1),
                  (SELECT COUNT(*)::bigint FROM mix_business_intents
                    WHERE semantic_key_id=$1 AND expires_at > $2)",
        )
        .bind(key_id)
        .bind(now)
        .fetch_one(&mut **transaction)
        .await
        .context("could not fence active references to the previous anti-abuse key")?;
        Ok(ForeignKeyReferences {
            offline_admissions,
            personal_message_identities,
            retraction_identities,
            mix_business_identities,
        })
    }

    async fn delete_expired_offline_admissions(&self, pool: &PgPool) -> Result<()> {
        sqlx::query(
            "WITH doomed AS (
            SELECT identity_digest FROM offline_message_admissions
            WHERE offline_message_id IS NULL
              AND expires_at IS NOT NULL AND expires_at <= clock_timestamp()
            ORDER BY expires_at,identity_digest
            LIMIT $1 FOR UPDATE SKIP LOCKED
         )
         DELETE FROM offline_message_admissions AS target
         USING doomed WHERE target.identity_digest=doomed.identity_digest",
        )
        .bind(northstar_abuse_policy::MESSAGE_ADMISSION_CLEANUP_BATCH)
        .execute(pool)
        .await?;
        Ok(())
    }
}

/// A guard over the adapter for tests, keeping every durable artifact on the current key.
#[cfg(test)]
pub(crate) fn persistent_guard(
    config: northstar_abuse_policy::AbuseConfig,
    pool: PgPool,
    shared_secret: Option<&[u8]>,
    previous_shared_secret: Option<&[u8]>,
) -> northstar_abuse_application::guard::AbuseGuard {
    northstar_abuse_application::guard::AbuseGuard::new_persistent_for_deployment(
        config,
        std::sync::Arc::new(
            northstar_abuse_postgres::persistence::PostgresAbusePersistence::new(
                pool,
                RootAbuseEffects,
            ),
        ),
        shared_secret,
        previous_shared_secret,
        false,
        Some(DateTime::<Utc>::MAX_UTC),
    )
}
