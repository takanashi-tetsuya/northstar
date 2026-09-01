use anyhow::Result;
use chrono::{DateTime, Duration, Utc};
use sqlx::PgPool;

/// A separately bounded retention source. These are intentionally the only
/// tables touched by automated history cleanup. In particular, reports,
/// appeals, copied report evidence, moderation state, and the audit log are
/// outside this enum and cannot be selected by a retention sweep.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetentionStore {
    PersonalMam,
    MucMam,
    OfflineMessages,
    PersonalDeliveryAdmissions,
}

impl RetentionStore {
    pub fn label(self) -> &'static str {
        match self {
            Self::PersonalMam => "personal_mam",
            Self::MucMam => "muc_mam",
            Self::OfflineMessages => "offline_messages",
            Self::PersonalDeliveryAdmissions => "personal_delivery_admissions",
        }
    }
}

/// `0` deliberately means that automated deletion is disabled. It never
/// means "delete everything now", which keeps a missing/zero configuration
/// from becoming a destructive operation during an upgrade.
pub fn retention_cutoff(now: DateTime<Utc>, retention_days: i64) -> Option<DateTime<Utc>> {
    (retention_days > 0).then(|| now - Duration::days(retention_days))
}

fn retention_delete_sql(store: RetentionStore) -> &'static str {
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

fn resolved_retention_delete_sql(store: RetentionStore) -> Option<&'static str> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db;
    use sha2::{Digest, Sha256};
    use sqlx::Row;
    use std::sync::Arc;
    use tokio::sync::Barrier;
    use uuid::Uuid;

    fn personal_identity<'a>(payload: &str) -> db::PersonalHistoryIdentity<'a> {
        db::PersonalHistoryIdentity {
            kind: "local-origin",
            actor_scope_raw: "sender@example.test",
            actor_scope: "sender@example.test",
            target_scope: "recipient@example.test",
            identity_value: "retention-origin",
            payload_authenticators: crate::abuse::test_personal_message_content_keyring()
                .authenticators(payload.as_bytes()),
            legacy_payload_digest: Sha256::digest(payload.as_bytes()).into(),
        }
    }

    #[test]
    fn zero_disables_cleanup_and_the_cutoff_is_strictly_age_based() {
        let now = Utc::now();
        assert_eq!(retention_cutoff(now, 0), None);
        assert_eq!(retention_cutoff(now, -1), None);
        assert_eq!(retention_cutoff(now, 30), Some(now - Duration::days(30)));
    }

    #[test]
    fn every_cleanup_statement_is_bounded_lock_skipping_and_evidence_safe() {
        for store in [
            RetentionStore::PersonalMam,
            RetentionStore::MucMam,
            RetentionStore::OfflineMessages,
            RetentionStore::PersonalDeliveryAdmissions,
        ] {
            let sql = retention_delete_sql(store);
            assert!(
                sql.contains("ORDER BY archive.created_at, archive.id")
                    || sql.contains("ORDER BY message.created_at, message.id")
                    || sql.contains("ORDER BY delivery_completed_at, id")
            );
            assert!(sql.contains("LIMIT $2"));
            assert!(
                sql.contains("FOR UPDATE SKIP LOCKED")
                    || sql.contains("FOR UPDATE OF archive SKIP LOCKED")
                    || sql.contains("FOR UPDATE OF message SKIP LOCKED")
            );
            assert!(!sql.contains("OFFSET"));
            for protected in [
                "abuse_reports",
                "abuse_report_evidence",
                "abuse_appeals",
                "audit_log",
                "mam_preferences",
            ] {
                assert!(!sql.contains(protected));
            }
            if store == RetentionStore::OfflineMessages {
                assert!(sql.contains("sm_resume_stanzas"));
                assert!(sql.contains("bosh_delivery_fences"));
                assert!(sql.contains("delivery_claim_expires_at"));
                assert!(sql.contains("FOR UPDATE OF message SKIP LOCKED"));
            }
            if store == RetentionStore::PersonalDeliveryAdmissions {
                for projection in [
                    "sender_archive_id IS NULL",
                    "recipient_archive_id IS NULL",
                    "offline_message_id IS NULL",
                    "s2s_outbox_id IS NULL",
                ] {
                    assert!(
                        sql.contains(projection),
                        "admission expiry must wait for projection: {projection}"
                    );
                }
            }
            if store != RetentionStore::PersonalDeliveryAdmissions {
                assert!(sql.contains("legal_holds"));
                assert!(sql.contains("released_at IS NULL"));
            }
        }
    }

    #[test]
    fn resolved_cleanup_uses_subject_policy_and_active_hold_in_one_statement() {
        for store in [
            RetentionStore::PersonalMam,
            RetentionStore::MucMam,
            RetentionStore::OfflineMessages,
        ] {
            let sql = resolved_retention_delete_sql(store).unwrap();
            assert!(sql.contains("COALESCE("));
            assert!(sql.contains("NULLIF($2::BIGINT,0)"));
            assert!(sql.contains("legal_holds"));
            assert!(sql.contains("released_at IS NULL"));
            assert!(sql.contains("FOR UPDATE OF"));
            assert!(sql.contains("SKIP LOCKED"));
            assert!(sql.contains("LIMIT $3"));
        }
    }

    async fn insert_user(pool: &PgPool, prefix: &str) -> Uuid {
        let id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO users (id, username, password_hash, is_admin)
             VALUES ($1, $2, 'retention-test-only', FALSE)",
        )
        .bind(id)
        .bind(format!("{prefix}-{}", &id.simple().to_string()[..12]))
        .execute(pool)
        .await
        .unwrap();
        id
    }

    async fn count(pool: &PgPool, table: &str, owner_column: &str, owner: Uuid) -> i64 {
        let sql = format!("SELECT COUNT(*) FROM {table} WHERE {owner_column}=$1");
        sqlx::query_scalar(&sql)
            .bind(owner)
            .fetch_one(pool)
            .await
            .unwrap()
    }

    #[tokio::test]
    #[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
    async fn bounded_concurrent_cleanup_is_restart_safe_and_preserves_evidence() {
        let url = std::env::var("TEST_DATABASE_URL")
            .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(16)
            .connect(&url)
            .await
            .unwrap();
        db::migrate(&pool).await.unwrap();

        let user = insert_user(&pool, "retention").await;
        let room = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO muc_rooms (id, localpart, owner_id, persistent)
             VALUES ($1, $2, $3, TRUE)",
        )
        .bind(room)
        .bind(format!("retention-{}", &room.simple().to_string()[..12]))
        .bind(user)
        .execute(&pool)
        .await
        .unwrap();

        let cutoff = Utc::now() - Duration::days(30);
        for position in 0..5_i64 {
            let created_at = cutoff - Duration::seconds(position + 1);
            sqlx::query(
                "INSERT INTO message_archive
                 (id, owner_id, peer_jid, peer_full_jid, stanza, encrypted, created_at)
                 VALUES ($1,$2,'peer@example.test','peer@example.test/device',$3,TRUE,$4)",
            )
            .bind(Uuid::new_v4())
            .bind(user)
            .bind(format!("<message id='personal-{position}'/>"))
            .bind(created_at)
            .execute(&pool)
            .await
            .unwrap();
            sqlx::query(
                "INSERT INTO muc_messages
                 (id, room_id, sender_jid, nick, stanza, encrypted, created_at)
                 VALUES ($1,$2,'sender@example.test/device','sender',$3,TRUE,$4)",
            )
            .bind(Uuid::new_v4())
            .bind(room)
            .bind(format!("<message id='muc-{position}'/>"))
            .bind(created_at)
            .execute(&pool)
            .await
            .unwrap();
            sqlx::query(
                "INSERT INTO offline_messages
                 (id, recipient_id, sender_jid, stanza, encrypted, created_at)
                 VALUES ($1,$2,'sender@example.test',$3,TRUE,$4)",
            )
            .bind(Uuid::new_v4())
            .bind(user)
            .bind(format!("<message id='offline-{position}'/>"))
            .bind(created_at)
            .execute(&pool)
            .await
            .unwrap();
        }

        // Exact-cutoff and newer rows are outside the strict `< cutoff`
        // predicate and must survive every sweep.
        for created_at in [cutoff, cutoff + Duration::seconds(1)] {
            sqlx::query(
                "INSERT INTO message_archive
                 (id, owner_id, peer_jid, peer_full_jid, stanza, encrypted, created_at)
                 VALUES ($1,$2,'boundary@example.test','boundary@example.test/device','<message/>',TRUE,$3)",
            )
            .bind(Uuid::new_v4())
            .bind(user)
            .bind(created_at)
            .execute(&pool)
            .await
            .unwrap();
        }

        let report = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO abuse_reports
             (id, reporter_id, reported_jid, category, description, created_at, updated_at)
             VALUES ($1,$2,'reported@example.test','illegal','preserve',$3,$3)",
        )
        .bind(report)
        .bind(user)
        .bind(cutoff - Duration::days(365))
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO abuse_report_evidence
             (id, report_id, sender_jid, body_text, encrypted, position, created_at)
             VALUES ($1,$2,'sender@example.test','copied evidence',TRUE,0,$3)",
        )
        .bind(Uuid::new_v4())
        .bind(report)
        .bind(cutoff - Duration::days(365))
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO mam_preferences (user_id, default_policy, updated_at)
             VALUES ($1,'never',$2)",
        )
        .bind(user)
        .bind(cutoff - Duration::days(365))
        .execute(&pool)
        .await
        .unwrap();

        // Two workers may overlap safely. SKIP LOCKED prevents waiting on or
        // deleting the same batch; a later stateless call represents a worker
        // restart and drains the final expired row without a persisted cursor.
        let barrier = Arc::new(Barrier::new(3));
        let mut tasks = Vec::new();
        for _ in 0..2 {
            let pool = pool.clone();
            let barrier = Arc::clone(&barrier);
            tasks.push(tokio::spawn(async move {
                barrier.wait().await;
                purge_retention_batch(&pool, RetentionStore::PersonalMam, cutoff, 2)
                    .await
                    .unwrap()
            }));
        }
        barrier.wait().await;
        let concurrently_deleted = tasks.remove(0).await.unwrap() + tasks.remove(0).await.unwrap();
        assert_eq!(concurrently_deleted, 4);
        assert_eq!(
            purge_retention_batch(&pool, RetentionStore::PersonalMam, cutoff, 2)
                .await
                .unwrap(),
            1
        );
        assert_eq!(count(&pool, "message_archive", "owner_id", user).await, 2);

        assert_eq!(
            purge_retention_batch(&pool, RetentionStore::MucMam, cutoff, 2)
                .await
                .unwrap(),
            2
        );
        assert_eq!(count(&pool, "muc_messages", "room_id", room).await, 3);
        assert_eq!(
            purge_retention_batch(&pool, RetentionStore::OfflineMessages, cutoff, 10)
                .await
                .unwrap(),
            5
        );
        assert_eq!(
            count(&pool, "offline_messages", "recipient_id", user).await,
            0
        );

        let evidence_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM abuse_report_evidence WHERE report_id=$1")
                .bind(report)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(evidence_count, 1);
        let preference = sqlx::query("SELECT default_policy FROM mam_preferences WHERE user_id=$1")
            .bind(user)
            .fetch_one(&pool)
            .await
            .unwrap()
            .get::<String, _>("default_policy");
        assert_eq!(preference, "never");

        sqlx::query("DELETE FROM muc_rooms WHERE id=$1")
            .bind(room)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM users WHERE id=$1")
            .bind(user)
            .execute(&pool)
            .await
            .unwrap();
    }

    #[tokio::test]
    #[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
    async fn asymmetric_mam_retention_preserves_admission_until_the_last_projection_ends() {
        let url = std::env::var("TEST_DATABASE_URL")
            .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(4)
            .connect(&url)
            .await
            .unwrap();
        db::migrate(&pool).await.unwrap();

        let sender = insert_user(&pool, "admission-retention-sender").await;
        let recipient = insert_user(&pool, "admission-retention-recipient").await;
        let sender_archive_id = Uuid::new_v4();
        let recipient_archive_id = Uuid::new_v4();
        let stanza = "<message id='retention-identity'><origin-id xmlns='urn:xmpp:sid:0' id='retention-origin'/></message>";
        let identity = personal_identity(stanza);
        let writes = [
            db::PersonalArchiveWrite {
                id: sender_archive_id,
                owner_id: sender,
                peer_jid: "recipient@example.test/phone",
                stanza,
                encrypted: true,
                stanza_id: Some("retention-origin"),
            },
            db::PersonalArchiveWrite {
                id: recipient_archive_id,
                owner_id: recipient,
                peer_jid: "sender@example.test/laptop",
                stanza,
                encrypted: true,
                stanza_id: Some("retention-origin"),
            },
        ];
        assert_eq!(
            db::admit_personal_history(&pool, Some(&identity), &writes)
                .await
                .unwrap(),
            db::PersonalHistoryAdmission::Stored(vec![sender_archive_id, recipient_archive_id])
        );
        sqlx::query(
            "UPDATE message_archive
                SET created_at=clock_timestamp()-INTERVAL '31 days'
              WHERE id=ANY($1::UUID[])",
        )
        .bind(vec![sender_archive_id, recipient_archive_id])
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO user_retention_policies(user_id,personal_mam_days)
             VALUES($1,1),($2,365)",
        )
        .bind(sender)
        .bind(recipient)
        .execute(&pool)
        .await
        .unwrap();

        let now = Utc::now();
        assert_eq!(
            purge_resolved_retention_batch(&pool, RetentionStore::PersonalMam, now, 0, 10)
                .await
                .unwrap(),
            1,
            "only the owner with the shorter MAM policy may expire"
        );
        let first_projection_state = sqlx::query_as::<
            _,
            (
                Option<Uuid>,
                Option<Uuid>,
                Option<Uuid>,
                Option<Uuid>,
                Option<DateTime<Utc>>,
            ),
        >(
            "SELECT sender_archive_id,recipient_archive_id,offline_message_id,
                    s2s_outbox_id,delivery_completed_at
               FROM personal_message_admissions
              WHERE identity_value='retention-origin'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(first_projection_state.0, None);
        assert_eq!(first_projection_state.1, Some(recipient_archive_id));
        assert_eq!(first_projection_state.2, None);
        assert_eq!(first_projection_state.3, None);
        assert!(first_projection_state.4.is_some());

        let replay_writes = [
            db::PersonalArchiveWrite {
                id: Uuid::new_v4(),
                ..writes[0].clone()
            },
            db::PersonalArchiveWrite {
                id: Uuid::new_v4(),
                ..writes[1].clone()
            },
        ];
        assert_eq!(
            db::admit_personal_history(&pool, Some(&identity), &replay_writes)
                .await
                .unwrap(),
            db::PersonalHistoryAdmission::Replay(vec![recipient_archive_id]),
            "the surviving recipient projection must keep exact replay suppression alive"
        );
        let changed_identity = personal_identity("<message id='changed-retention-payload'/>");
        assert!(
            db::admit_personal_history(&pool, Some(&changed_identity), &replay_writes)
                .await
                .unwrap_err()
                .to_string()
                .contains("conflicting personal history identity")
        );

        // Prove that finalization refreshes, rather than preserves, an older
        // completion timestamp left by an earlier projection.
        let deliberately_old_completion = now - Duration::days(31);
        sqlx::query(
            "UPDATE personal_message_admissions
                SET delivery_completed_at=$1
              WHERE identity_value='retention-origin'",
        )
        .bind(deliberately_old_completion)
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query("UPDATE user_retention_policies SET personal_mam_days=1 WHERE user_id=$1")
            .bind(recipient)
            .execute(&pool)
            .await
            .unwrap();
        assert_eq!(
            purge_resolved_retention_batch(&pool, RetentionStore::PersonalMam, Utc::now(), 0, 10)
                .await
                .unwrap(),
            1
        );
        let terminal_state = sqlx::query_as::<
            _,
            (
                Option<Uuid>,
                Option<Uuid>,
                Option<Uuid>,
                Option<Uuid>,
                DateTime<Utc>,
            ),
        >(
            "SELECT sender_archive_id,recipient_archive_id,offline_message_id,
                    s2s_outbox_id,delivery_completed_at
               FROM personal_message_admissions
              WHERE identity_value='retention-origin'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(
            (
                terminal_state.0,
                terminal_state.1,
                terminal_state.2,
                terminal_state.3
            ),
            (None, None, None, None)
        );
        assert!(terminal_state.4 > deliberately_old_completion);
        assert_eq!(
            purge_retention_batch(
                &pool,
                RetentionStore::PersonalDeliveryAdmissions,
                terminal_state.4 - Duration::seconds(1),
                10,
            )
            .await
            .unwrap(),
            0,
            "the 30-day grace must begin after the final projection ends"
        );
        assert_eq!(
            db::admit_personal_history(&pool, Some(&identity), &replay_writes)
                .await
                .unwrap(),
            db::PersonalHistoryAdmission::Replay(Vec::new())
        );

        // Simulate the fixed 30-day worker horizon and prove that the keyed
        // identity tombstone is eventually released rather than retained
        // indefinitely.
        sqlx::query(
            "UPDATE personal_message_admissions
                SET delivery_completed_at=clock_timestamp()-INTERVAL '31 days'
              WHERE identity_value='retention-origin'",
        )
        .execute(&pool)
        .await
        .unwrap();
        assert_eq!(
            purge_retention_batch(
                &pool,
                RetentionStore::PersonalDeliveryAdmissions,
                Utc::now() - Duration::days(30),
                10,
            )
            .await
            .unwrap(),
            1
        );
        assert_eq!(
            db::admit_personal_history(&pool, Some(&identity), &replay_writes)
                .await
                .unwrap(),
            db::PersonalHistoryAdmission::Stored(
                replay_writes.iter().map(|write| write.id).collect()
            ),
            "once the bounded tombstone expires, the identity may be admitted again"
        );

        sqlx::query("DELETE FROM personal_message_admissions WHERE identity_value=$1")
            .bind(identity.identity_value)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM users WHERE id=ANY($1::UUID[])")
            .bind(vec![sender, recipient])
            .execute(&pool)
            .await
            .unwrap();
    }

    #[tokio::test]
    #[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
    async fn offline_retention_and_admin_clear_respect_sm_and_bosh_owners() {
        let url = std::env::var("TEST_DATABASE_URL")
            .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(6)
            .connect(&url)
            .await
            .unwrap();
        db::migrate(&pool).await.unwrap();
        let user = insert_user(&pool, "retention-fence").await;
        let username: String = sqlx::query_scalar("SELECT username FROM users WHERE id=$1")
            .bind(user)
            .fetch_one(&pool)
            .await
            .unwrap();
        let cutoff = Utc::now() - Duration::days(30);

        async fn old_message(pool: &PgPool, user: Uuid, marker: &str) -> Uuid {
            let id = Uuid::new_v4();
            sqlx::query(
                "INSERT INTO offline_messages(
                    id,recipient_id,sender_jid,stanza,encrypted,mam_backed,created_at
                 ) VALUES($1,$2,'sender@example.test',$3,FALSE,FALSE,
                          clock_timestamp()-INTERVAL '31 days')",
            )
            .bind(id)
            .bind(user)
            .bind(format!("<message id='{marker}'/>"))
            .execute(pool)
            .await
            .unwrap();
            id
        }

        let unowned = old_message(&pool, user, "unowned").await;
        let bosh_message = old_message(&pool, user, "bosh-owned").await;
        let sm_message = old_message(&pool, user, "sm-owned").await;
        let bosh_session = Uuid::new_v4();
        crate::db::replay::bind_bosh_delivery_response(
            &pool,
            bosh_session,
            41,
            &[crate::outbound::DurableDelivery {
                recipient_id: user,
                message_id: bosh_message,
                claim_id: None,
            }],
            60,
        )
        .await
        .unwrap();

        let sm_connection = Uuid::new_v4();
        let sm_snapshot = crate::db::SmSessionSnapshot {
            inbound_h: 0,
            outbound_h: 1,
            acked_h: 0,
            available: true,
            carbons: false,
            priority: 0,
            blocklist_requested: false,
            roster_requested: false,
            active_privacy_list: None,
            privacy_requested: false,
            peer_ip: "192.0.2.80".parse().unwrap(),
            user_agent_id: None,
            joined_rooms: vec![],
            directed_presence: vec![],
            last_presence: Some("<presence xmlns='jabber:client'/>".to_owned()),
            unacked: vec![crate::outbound::SmUnackedStanza::with_delivery(
                "<message id='sm-owned'/>".to_owned(),
                Some(crate::outbound::DurableDelivery {
                    recipient_id: user,
                    message_id: sm_message,
                    claim_id: None,
                }),
            )],
        };
        let sm_session = crate::db::create_sm_session(
            &pool,
            &[81_u8; 32],
            user,
            0,
            &format!("{username}@example.test/retention"),
            "retention",
            "example.test",
            sm_connection,
            &sm_snapshot,
            300,
            30,
            128,
            10_000,
        )
        .await
        .unwrap();

        assert_eq!(
            purge_retention_batch(&pool, RetentionStore::OfflineMessages, cutoff, 10)
                .await
                .unwrap(),
            1
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM offline_messages WHERE id=ANY($1::UUID[])"
            )
            .bind(vec![unowned, bosh_message, sm_message])
            .fetch_one(&pool)
            .await
            .unwrap(),
            2
        );

        // Admission's foreground TTL cleanup is also a capacity operation;
        // it must count, rather than destroy, transport-owned old rows.
        assert_eq!(
            crate::db::store_offline(
                &pool,
                user,
                "sender@example.test",
                "<message id='new-capacity-probe'/>",
                false,
                crate::db::OfflineStorePolicy {
                    max_messages: 100,
                    max_bytes: 1_000_000,
                    ttl_days: 30,
                    mam_backed: false,
                },
            )
            .await
            .unwrap(),
            crate::db::OfflineStoreOutcome::Stored
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM offline_messages WHERE id=ANY($1::UUID[])"
            )
            .bind(vec![bosh_message, sm_message])
            .fetch_one(&pool)
            .await
            .unwrap(),
            2
        );

        let mut clear = pool.begin().await.unwrap();
        let error = crate::db::clear_offline_messages_in_tx(&mut clear, user, None)
            .await
            .unwrap_err();
        assert!(error
            .downcast_ref::<crate::db::OfflineMessagesTransportOwned>()
            .is_some());
        clear.rollback().await.unwrap();

        crate::db::replay::release_bosh_delivery_fences(&pool, bosh_session)
            .await
            .unwrap();
        crate::db::revoke_sm_session(&pool, sm_session)
            .await
            .unwrap();
        assert_eq!(
            purge_retention_batch(&pool, RetentionStore::OfflineMessages, cutoff, 10)
                .await
                .unwrap(),
            2
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM offline_messages WHERE id=ANY($1::UUID[])"
            )
            .bind(vec![bosh_message, sm_message])
            .fetch_one(&pool)
            .await
            .unwrap(),
            0
        );
        let mut clear = pool.begin().await.unwrap();
        assert_eq!(
            crate::db::clear_offline_messages_in_tx(&mut clear, user, None)
                .await
                .unwrap(),
            1
        );
        clear.commit().await.unwrap();

        sqlx::query("DELETE FROM users WHERE id=$1")
            .bind(user)
            .execute(&pool)
            .await
            .unwrap();
    }
}
