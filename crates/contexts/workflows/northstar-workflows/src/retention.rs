use anyhow::Result;
use chrono::{DateTime, Duration, Utc};
use sqlx::PgPool;

pub use northstar_operations_application::maintenance_repositories::RetentionStore;

/// `0` deliberately means that automated deletion is disabled. It never
/// means "delete everything now", which keeps a missing/zero configuration
/// from becoming a destructive operation during an upgrade.
pub fn retention_cutoff(now: DateTime<Utc>, retention_days: i64) -> Option<DateTime<Utc>> {
    (retention_days > 0).then(|| now - Duration::days(retention_days))
}

pub fn retention_delete_sql(store: RetentionStore) -> &'static str {
    match store {
        RetentionStore::PersonalMam => {
            "WITH expired AS MATERIALIZED (
                 SELECT archive.id FROM message_archive archive
                 WHERE archive.created_at < $1
                   AND NOT EXISTS (
                       SELECT 1 FROM legal_holds hold
                        WHERE hold.released_at IS NULL AND (
                            EXISTS (SELECT 1 FROM legal_hold_personal_archives link
                                     WHERE link.hold_id=hold.id AND link.archive_id=archive.id)
                            OR EXISTS (SELECT 1 FROM legal_hold_scopes scope_link
                                       WHERE scope_link.hold_id=hold.id
                                         AND scope_link.scope_type='personal_archive_owner'
                                         AND scope_link.subject_id=archive.owner_id)
                        )
                   )
                 ORDER BY archive.created_at, archive.id
                 LIMIT $2
                 FOR UPDATE OF archive SKIP LOCKED
             )
             DELETE FROM message_archive AS archive
             USING expired
             WHERE archive.id = expired.id"
        }
        RetentionStore::MucMam => {
            "WITH expired AS MATERIALIZED (
                 SELECT archive.id FROM muc_messages archive
                 WHERE archive.created_at < $1
                   AND NOT EXISTS (
                       SELECT 1 FROM legal_holds hold
                        WHERE hold.released_at IS NULL AND (
                            EXISTS (SELECT 1 FROM legal_hold_muc_archives link
                                     WHERE link.hold_id=hold.id AND link.message_id=archive.id)
                            OR EXISTS (SELECT 1 FROM legal_hold_scopes scope_link
                                       WHERE scope_link.hold_id=hold.id
                                         AND scope_link.scope_type='muc_archive_room'
                                         AND scope_link.subject_id=archive.room_id)
                        )
                   )
                 ORDER BY archive.created_at, archive.id
                 LIMIT $2
                 FOR UPDATE OF archive SKIP LOCKED
             )
             DELETE FROM muc_messages AS archive
             USING expired
             WHERE archive.id = expired.id"
        }
        RetentionStore::OfflineMessages => {
            "WITH expired AS MATERIALIZED (
                 SELECT message.id FROM offline_messages message
                 WHERE message.created_at < $1
                   AND (message.delivery_claim_id IS NULL
                        OR message.delivery_claim_expires_at<=clock_timestamp())
                   AND NOT EXISTS (
                       SELECT 1 FROM sm_resume_stanzas sm
                        WHERE sm.delivery_message_id=message.id
                   )
                   AND NOT EXISTS (
                       SELECT 1 FROM bosh_delivery_fences bosh
                        WHERE bosh.message_id=message.id
                   )
                   AND NOT EXISTS (
                       SELECT 1 FROM legal_holds hold
                        WHERE hold.released_at IS NULL AND (
                            EXISTS (SELECT 1 FROM legal_hold_offline_messages link
                                     WHERE link.hold_id=hold.id AND link.message_id=message.id)
                            OR EXISTS (SELECT 1 FROM legal_hold_scopes scope_link
                                       WHERE scope_link.hold_id=hold.id
                                         AND scope_link.scope_type='offline_message_recipient'
                                         AND scope_link.subject_id=message.recipient_id)
                        )
                   )
                 ORDER BY message.created_at, message.id
                 LIMIT $2
                 FOR UPDATE OF message SKIP LOCKED
             )
             DELETE FROM offline_messages AS message
             USING expired
             WHERE message.id = expired.id"
        }
        RetentionStore::PersonalDeliveryAdmissions => {
            "WITH expired AS MATERIALIZED (
                 SELECT id FROM personal_message_admissions
                 WHERE sender_archive_id IS NULL
                   AND recipient_archive_id IS NULL
                   AND offline_message_id IS NULL
                   AND s2s_outbox_id IS NULL
                   AND delivery_completed_at IS NOT NULL
                   AND delivery_completed_at < $1
                 ORDER BY delivery_completed_at, id
                 LIMIT $2
                 FOR UPDATE SKIP LOCKED
             )
             DELETE FROM personal_message_admissions AS admission
             USING expired
             WHERE admission.id = expired.id"
        }
    }
}

pub fn resolved_retention_delete_sql(store: RetentionStore) -> Option<&'static str> {
    match store {
        RetentionStore::PersonalMam => Some(
            "WITH expired AS MATERIALIZED (
                 SELECT archive.id
                   FROM message_archive archive
                   LEFT JOIN user_retention_policies policy
                     ON policy.user_id=archive.owner_id
                  WHERE COALESCE(policy.personal_mam_days,NULLIF($2::BIGINT,0)) IS NOT NULL
                    AND archive.created_at < $1-(
                        COALESCE(policy.personal_mam_days,NULLIF($2::BIGINT,0))::BIGINT
                        * INTERVAL '1 day')
                    AND NOT EXISTS (
                        SELECT 1 FROM legal_holds hold
                         WHERE hold.released_at IS NULL AND (
                             EXISTS (SELECT 1 FROM legal_hold_personal_archives link
                                      WHERE link.hold_id=hold.id AND link.archive_id=archive.id)
                             OR EXISTS (SELECT 1 FROM legal_hold_scopes scope_link
                                        WHERE scope_link.hold_id=hold.id
                                          AND scope_link.scope_type='personal_archive_owner'
                                          AND scope_link.subject_id=archive.owner_id)
                         )
                    )
                  ORDER BY archive.created_at,archive.id LIMIT $3
                  FOR UPDATE OF archive SKIP LOCKED
             )
             DELETE FROM message_archive archive USING expired
              WHERE archive.id=expired.id",
        ),
        RetentionStore::MucMam => Some(
            "WITH expired AS MATERIALIZED (
                 SELECT archive.id
                   FROM muc_messages archive
                   LEFT JOIN muc_retention_policies policy
                     ON policy.room_id=archive.room_id
                  WHERE COALESCE(policy.retention_days,NULLIF($2::BIGINT,0)) IS NOT NULL
                    AND archive.created_at < $1-(
                        COALESCE(policy.retention_days,NULLIF($2::BIGINT,0))::BIGINT
                        * INTERVAL '1 day')
                    AND NOT EXISTS (
                        SELECT 1 FROM legal_holds hold
                         WHERE hold.released_at IS NULL AND (
                             EXISTS (SELECT 1 FROM legal_hold_muc_archives link
                                      WHERE link.hold_id=hold.id AND link.message_id=archive.id)
                             OR EXISTS (SELECT 1 FROM legal_hold_scopes scope_link
                                        WHERE scope_link.hold_id=hold.id
                                          AND scope_link.scope_type='muc_archive_room'
                                          AND scope_link.subject_id=archive.room_id)
                         )
                    )
                  ORDER BY archive.created_at,archive.id LIMIT $3
                  FOR UPDATE OF archive SKIP LOCKED
             )
             DELETE FROM muc_messages archive USING expired
              WHERE archive.id=expired.id",
        ),
        RetentionStore::OfflineMessages => Some(
            "WITH expired AS MATERIALIZED (
                 SELECT message.id
                   FROM offline_messages message
                   LEFT JOIN user_retention_policies policy
                     ON policy.user_id=message.recipient_id
                  WHERE COALESCE(policy.offline_message_days,NULLIF($2::BIGINT,0)) IS NOT NULL
                    AND message.created_at < $1-(
                        COALESCE(policy.offline_message_days,NULLIF($2::BIGINT,0))::BIGINT
                        * INTERVAL '1 day')
                    AND (message.delivery_claim_id IS NULL
                         OR message.delivery_claim_expires_at<=clock_timestamp())
                    AND NOT EXISTS (SELECT 1 FROM sm_resume_stanzas sm
                                     WHERE sm.delivery_message_id=message.id)
                    AND NOT EXISTS (SELECT 1 FROM bosh_delivery_fences bosh
                                     WHERE bosh.message_id=message.id)
                    AND NOT EXISTS (
                        SELECT 1 FROM legal_holds hold
                         WHERE hold.released_at IS NULL AND (
                             EXISTS (SELECT 1 FROM legal_hold_offline_messages link
                                      WHERE link.hold_id=hold.id AND link.message_id=message.id)
                             OR EXISTS (SELECT 1 FROM legal_hold_scopes scope_link
                                        WHERE scope_link.hold_id=hold.id
                                          AND scope_link.scope_type='offline_message_recipient'
                                          AND scope_link.subject_id=message.recipient_id)
                         )
                    )
                  ORDER BY message.created_at,message.id LIMIT $3
                  FOR UPDATE OF message SKIP LOCKED
             )
             DELETE FROM offline_messages message USING expired
              WHERE message.id=expired.id",
        ),
        RetentionStore::PersonalDeliveryAdmissions => None,
    }
}

/// Delete at most one chronological batch. Each statement is its own short
/// transaction and uses `FOR UPDATE SKIP LOCKED`, so concurrent nodes or a
/// restarted maintenance worker cannot delete the same row or wait behind a
/// long-running cleanup transaction. The `(created_at, id)` migration indexes
/// prevent an unbounded table scan.
pub async fn purge_retention_batch(
    pool: &PgPool,
    store: RetentionStore,
    cutoff: DateTime<Utc>,
    batch_size: i64,
) -> Result<u64> {
    let batch_size = batch_size.clamp(1, 10_000);
    Ok(sqlx::query(retention_delete_sql(store))
        .bind(cutoff)
        .bind(batch_size)
        .execute(pool)
        .await?
        .rows_affected())
}

/// Resolve an owner/room policy at the same database snapshot that locks and
/// deletes the candidate. `global_days=0` means inherited cleanup is disabled,
/// but an explicit shorter user/room policy remains effective.
pub async fn purge_resolved_retention_batch(
    pool: &PgPool,
    store: RetentionStore,
    now: DateTime<Utc>,
    global_days: i64,
    batch_size: i64,
) -> Result<u64> {
    anyhow::ensure!(
        (0..=36_500).contains(&global_days),
        "invalid retention ceiling"
    );
    if let Some(sql) = resolved_retention_delete_sql(store) {
        return Ok(sqlx::query(sql)
            .bind(now)
            .bind(global_days)
            .bind(batch_size.clamp(1, 10_000))
            .execute(pool)
            .await?
            .rows_affected());
    }
    let Some(cutoff) = retention_cutoff(now, global_days) else {
        return Ok(0);
    };
    purge_retention_batch(pool, store, cutoff, batch_size).await
}
