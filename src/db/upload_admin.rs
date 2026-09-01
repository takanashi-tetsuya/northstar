//! Administrator control plane for upload-recovery dead letters.
//!
//! This module intentionally exposes neither object-store locators nor the
//! original worker error through its list projection. A retry is a state
//! transition, never a discard: the durable recovery row and its original
//! `last_error` remain present until the normal fenced worker proves the
//! physical operation complete.

use anyhow::{ensure, Result};
use chrono::{DateTime, Utc};
use sqlx::{Postgres, Row, Transaction};
use uuid::{Uuid, Variant};
use zeroize::Zeroizing;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UploadDeadLetterKind {
    StorageJob,
    Cleanup,
}

impl UploadDeadLetterKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::StorageJob => "storage_job",
            Self::Cleanup => "cleanup",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "storage_job" => Some(Self::StorageJob),
            "cleanup" => Some(Self::Cleanup),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum UploadDeadLetterId {
    StorageJob(i64),
    /// Random administrator-facing recovery handle. This is deliberately not
    /// `upload_cleanup_queue.object_id`, which is also the local object key.
    Cleanup(Uuid),
}

impl UploadDeadLetterId {
    pub fn parse(kind: UploadDeadLetterKind, value: &str) -> Option<Self> {
        match kind {
            UploadDeadLetterKind::StorageJob => value
                .parse::<i64>()
                .ok()
                .filter(|id| *id > 0 && id.to_string() == value)
                .map(Self::StorageJob),
            UploadDeadLetterKind::Cleanup => Uuid::parse_str(value)
                .ok()
                .filter(|id| {
                    !id.is_nil()
                        && id.get_version_num() == 4
                        && id.get_variant() == Variant::RFC4122
                        && id.hyphenated().to_string() == value
                })
                .map(Self::Cleanup),
        }
    }

    pub fn as_api_string(self) -> String {
        match self {
            Self::StorageJob(id) => id.to_string(),
            Self::Cleanup(id) => id.to_string(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UploadDeadLetterBoundary {
    StorageJob(i64),
    Cleanup(Uuid),
}

pub struct UploadDeadLetterRecord {
    pub id: UploadDeadLetterId,
    pub operation: String,
    pub attempts: i64,
    pub dead_lettered_at: DateTime<Utc>,
    pub available_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    /// Never serialize this field directly. The HTTP boundary emits only a
    /// scrubbed, bounded categorical summary.
    pub(crate) last_error: Option<Zeroizing<String>>,
}

pub struct UploadDeadLetterPage {
    pub rows: Vec<UploadDeadLetterRecord>,
    pub next: Option<UploadDeadLetterBoundary>,
    pub database_now: DateTime<Utc>,
}

fn checked_fetch_limit(limit: i64) -> Result<i64> {
    ensure!(
        (1..=100).contains(&limit),
        "upload dead-letter page limit must be between 1 and 100"
    );
    Ok(limit + 1)
}

fn finish_page(
    mut rows: Vec<UploadDeadLetterRecord>,
    limit: i64,
    database_now: DateTime<Utc>,
) -> UploadDeadLetterPage {
    let has_more = rows.len() > limit as usize;
    rows.truncate(limit as usize);
    let next = has_more.then(|| {
        let row = rows
            .last()
            .expect("a dead-letter page with an extra row is nonempty");
        match row.id {
            UploadDeadLetterId::StorageJob(id) => UploadDeadLetterBoundary::StorageJob(id),
            UploadDeadLetterId::Cleanup(id) => UploadDeadLetterBoundary::Cleanup(id),
        }
    });
    UploadDeadLetterPage {
        rows,
        next,
        database_now,
    }
}

/// Read one kind of dead letter with a strict keyset. Keeping the two key
/// spaces separate prevents lossy coercion between the storage queue's
/// BIGSERIAL key and the cleanup queue's random recovery UUID.
pub async fn upload_dead_letters_page_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    kind: UploadDeadLetterKind,
    after: Option<UploadDeadLetterBoundary>,
    limit: i64,
) -> Result<UploadDeadLetterPage> {
    let fetch_limit = checked_fetch_limit(limit)?;
    let database_now = super::api_pages::database_cursor_clock_in_tx(tx).await?;
    let (after_storage_job_id, after_cleanup_recovery_id) = match after {
        None => (None, None),
        Some(UploadDeadLetterBoundary::StorageJob(id))
            if kind == UploadDeadLetterKind::StorageJob =>
        {
            (Some(id), None)
        }
        Some(UploadDeadLetterBoundary::Cleanup(id)) if kind == UploadDeadLetterKind::Cleanup => {
            (None, Some(id))
        }
        Some(UploadDeadLetterBoundary::StorageJob(_)) => {
            anyhow::bail!("storage-job cursor used for cleanup dead letters")
        }
        Some(UploadDeadLetterBoundary::Cleanup(_)) => {
            anyhow::bail!("cleanup cursor used for storage-job dead letters")
        }
    };
    let rows = sqlx::query(
        "SELECT storage_job_id,cleanup_recovery_id,operation,attempts,
                dead_lettered_at,available_at,created_at,error_class
           FROM northstar_upload_dead_letters_page($1,$2,$3,$4)",
    )
    .bind(kind.as_str())
    .bind(after_storage_job_id)
    .bind(after_cleanup_recovery_id)
    .bind(i32::try_from(fetch_limit)?)
    .fetch_all(&mut **tx)
    .await?
    .into_iter()
    .map(|row| {
        let id = match kind {
            UploadDeadLetterKind::StorageJob => {
                UploadDeadLetterId::StorageJob(row.get("storage_job_id"))
            }
            UploadDeadLetterKind::Cleanup => {
                UploadDeadLetterId::Cleanup(row.get("cleanup_recovery_id"))
            }
        };
        UploadDeadLetterRecord {
            id,
            operation: row.get("operation"),
            attempts: row.get("attempts"),
            dead_lettered_at: row.get("dead_lettered_at"),
            available_at: row.get("available_at"),
            created_at: row.get("created_at"),
            // The capability returns only a fixed categorical classification;
            // the protected worker error and every locator stay database-only.
            last_error: row
                .get::<Option<String>, _>("error_class")
                .map(Zeroizing::new),
        }
    })
    .collect();
    Ok(finish_page(rows, limit, database_now))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetryUploadDeadLetter {
    Retried,
    /// Missing, already recovered, and actively leased rows deliberately use
    /// one outcome so the administrative API cannot act as a state oracle.
    Unavailable,
    Unauthorized,
}

/// Requeue one exact dead letter without deleting or retargeting its physical
/// recovery proof. Authorization, row fencing, mutation, audit insertion and
/// the caller's idempotency completion all share the same transaction.
pub async fn retry_upload_dead_letter_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    actor_id: Uuid,
    actor_auth_generation: i64,
    presented_session: &str,
    id: UploadDeadLetterId,
    request_id: Uuid,
) -> Result<RetryUploadDeadLetter> {
    let (kind, storage_job_id, cleanup_recovery_id) = match id {
        UploadDeadLetterId::StorageJob(id) => (UploadDeadLetterKind::StorageJob, Some(id), None),
        UploadDeadLetterId::Cleanup(id) => (UploadDeadLetterKind::Cleanup, None, Some(id)),
    };
    let session_hash = crate::auth::token_hash(presented_session);
    let outcome = sqlx::query_scalar::<_, String>(
        "SELECT northstar_upload_retry_dead_letter($1,$2,$3,$4,$5,$6,$7)",
    )
    .bind(actor_id)
    .bind(actor_auth_generation)
    .bind(session_hash.as_slice())
    .bind(kind.as_str())
    .bind(storage_job_id)
    .bind(cleanup_recovery_id)
    .bind(request_id)
    .fetch_one(&mut **tx)
    .await?;
    match outcome.as_str() {
        "retried" => Ok(RetryUploadDeadLetter::Retried),
        "unavailable" => Ok(RetryUploadDeadLetter::Unavailable),
        "unauthorized" => Ok(RetryUploadDeadLetter::Unauthorized),
        _ => anyhow::bail!("upload dead-letter capability returned an invalid outcome"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;
    use axum::http::StatusCode;
    use sqlx::PgPool;
    use std::collections::HashSet;
    use std::sync::Arc;
    use tokio::sync::Barrier;

    #[test]
    fn kinds_ids_limits_and_error_projection_are_canonical() {
        assert_eq!(
            UploadDeadLetterKind::parse("storage_job"),
            Some(UploadDeadLetterKind::StorageJob)
        );
        assert_eq!(
            UploadDeadLetterKind::parse("cleanup"),
            Some(UploadDeadLetterKind::Cleanup)
        );
        assert!(UploadDeadLetterKind::parse("Storage_Job").is_none());
        assert_eq!(
            UploadDeadLetterId::parse(UploadDeadLetterKind::StorageJob, "42"),
            Some(UploadDeadLetterId::StorageJob(42))
        );
        assert!(UploadDeadLetterId::parse(UploadDeadLetterKind::StorageJob, "0").is_none());
        assert!(UploadDeadLetterId::parse(UploadDeadLetterKind::StorageJob, "01").is_none());
        assert!(UploadDeadLetterId::parse(UploadDeadLetterKind::StorageJob, "+1").is_none());
        assert!(UploadDeadLetterId::parse(UploadDeadLetterKind::StorageJob, " 1").is_none());
        assert_eq!(
            UploadDeadLetterId::parse(UploadDeadLetterKind::StorageJob, "9223372036854775807"),
            Some(UploadDeadLetterId::StorageJob(i64::MAX))
        );
        assert!(
            UploadDeadLetterId::parse(UploadDeadLetterKind::StorageJob, "9223372036854775808")
                .is_none()
        );
        assert!(UploadDeadLetterId::parse(UploadDeadLetterKind::Cleanup, "not-a-uuid").is_none());
        assert!(checked_fetch_limit(1).is_ok());
        assert!(checked_fetch_limit(100).is_ok());
        assert!(checked_fetch_limit(0).is_err());
        assert!(checked_fetch_limit(101).is_err());
        let canonical = Uuid::new_v4();
        assert_eq!(
            UploadDeadLetterId::parse(
                UploadDeadLetterKind::Cleanup,
                &canonical.hyphenated().to_string()
            ),
            Some(UploadDeadLetterId::Cleanup(canonical))
        );
        assert!(UploadDeadLetterId::parse(
            UploadDeadLetterKind::Cleanup,
            &canonical.simple().to_string()
        )
        .is_none());
        assert!(UploadDeadLetterId::parse(
            UploadDeadLetterKind::Cleanup,
            &canonical.hyphenated().to_string().to_ascii_uppercase()
        )
        .is_none());
        assert!(UploadDeadLetterId::parse(
            UploadDeadLetterKind::Cleanup,
            &format!("{{{canonical}}}")
        )
        .is_none());
        assert!(UploadDeadLetterId::parse(
            UploadDeadLetterKind::Cleanup,
            &format!("urn:uuid:{canonical}")
        )
        .is_none());
        assert!(UploadDeadLetterId::parse(
            UploadDeadLetterKind::Cleanup,
            "00000000-0000-0000-0000-000000000000"
        )
        .is_none());
        assert!(UploadDeadLetterId::parse(
            UploadDeadLetterKind::Cleanup,
            "11111111-1111-1111-8111-111111111111"
        )
        .is_none());
        assert!(UploadDeadLetterId::parse(
            UploadDeadLetterKind::Cleanup,
            "11111111-1111-4111-7111-111111111111"
        )
        .is_none());
    }

    async fn insert_user(pool: &PgPool, admin: bool) -> (Uuid, String) {
        let id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO users(id,username,password_hash,is_admin)
             VALUES($1,$2,'test-only',$3)",
        )
        .bind(id)
        .bind(format!("dead-letter-{}", id.simple()))
        .bind(admin)
        .execute(pool)
        .await
        .unwrap();
        let token = crate::db::create_api_session(pool, id, 1).await.unwrap();
        (id, token)
    }

    async fn insert_storage_dead_letter(
        pool: &PgPool,
        claim_expires_at: Option<DateTime<Utc>>,
    ) -> i64 {
        let object_id = Uuid::new_v4();
        sqlx::query_scalar(
            "INSERT INTO upload_storage_jobs(
                 object_id,storage_attempt,action,storage_backend,object_key,
                 expected_size,storage_fence,attempts,dead_lettered_at,last_error,
                 claim_token,claim_expires_at)
             VALUES($1,$2,'delete_object','local',$1::text,1,0,12,
                    clock_timestamp(),'fixture failure',$3,$4)
             RETURNING id",
        )
        .bind(object_id)
        .bind(Uuid::new_v4())
        .bind(claim_expires_at.map(|_| Uuid::new_v4()))
        .bind(claim_expires_at)
        .fetch_one(pool)
        .await
        .unwrap()
    }

    fn retry_idempotency_request<'a>(
        actor_id: Uuid,
        actor_scope: &'a [u8],
        target_scope: &'a [u8],
        key: &'a str,
        auth_generation: i64,
        request_id: Uuid,
    ) -> crate::db::IdempotencyRequest<'a> {
        let base = crate::db::api_request_fingerprint("", b"");
        crate::db::IdempotencyRequest {
            request_id,
            actor_id: Some(actor_id),
            principal_scope: actor_scope,
            capacity_scope: actor_scope,
            target_scope,
            principal_kind: crate::db::ApiPrincipalKind::Admin,
            method: "POST",
            route: "/api/v1/admin/upload-dead-letters/{kind}/{id}/retry",
            idempotency_key: key,
            request_fingerprint:
                crate::api::upload_admin::admin_generation_bound_request_fingerprint(
                    base,
                    auth_generation,
                ),
            ttl_seconds: 86_400,
            lease_seconds: 30,
        }
    }

    #[tokio::test]
    #[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
    async fn postgres_retry_idempotency_replay_target_generation_and_not_found_contract() {
        let url = std::env::var("TEST_DATABASE_URL")
            .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(4)
            .connect(&url)
            .await
            .unwrap();
        crate::db::migrate(&pool).await.unwrap();
        crate::db::validate_upload_capacity_policy(&pool, 10_000, 1_000_000, 1_099_511_627_776)
            .await
            .unwrap();
        let (admin_id, admin_token) = insert_user(&pool, true).await;
        let actor_scope = admin_id.as_bytes();
        let keys = crate::db::ApiControlKeyring::new(
            b"upload-dead-letter-idempotency-test-key-0001",
            None,
        )
        .unwrap();

        let job = insert_storage_dead_letter(&pool, None).await;
        let target = format!("storage_job\0{job}");
        let key = "upload-retry-success-0001";
        let original_request_id = Uuid::new_v4();
        let original = retry_idempotency_request(
            admin_id,
            actor_scope,
            target.as_bytes(),
            key,
            0,
            original_request_id,
        );
        let mut tx = pool.begin().await.unwrap();
        let lease = match crate::db::acquire_idempotency_in_tx(&keys, &mut tx, &original)
            .await
            .unwrap()
        {
            crate::db::IdempotencyAcquire::Acquired(lease) => lease,
            other => panic!("unexpected first idempotency outcome: {other:?}"),
        };
        assert_eq!(
            retry_upload_dead_letter_in_tx(
                &mut tx,
                admin_id,
                0,
                &admin_token,
                UploadDeadLetterId::StorageJob(job),
                lease.request_id,
            )
            .await
            .unwrap(),
            RetryUploadDeadLetter::Retried
        );
        let response_body = format!(r#"{{"kind":"storage_job","id":"{job}","state":"queued"}}"#);
        assert!(crate::db::complete_idempotency_in_tx(
            &keys,
            &mut tx,
            &lease,
            StatusCode::ACCEPTED.as_u16(),
            &crate::api::json_replay_headers(),
            response_body.as_bytes(),
        )
        .await
        .unwrap());
        tx.commit().await.unwrap();

        let replay_request = retry_idempotency_request(
            admin_id,
            actor_scope,
            target.as_bytes(),
            key,
            0,
            Uuid::new_v4(),
        );
        let mut replay_tx = pool.begin().await.unwrap();
        let replay =
            match crate::db::acquire_idempotency_in_tx(&keys, &mut replay_tx, &replay_request)
                .await
                .unwrap()
            {
                crate::db::IdempotencyAcquire::Replay(replay) => replay,
                other => panic!("unexpected replay outcome: {other:?}"),
            };
        replay_tx.commit().await.unwrap();
        let response = crate::api::idempotency_replay_response(replay).unwrap();
        assert_eq!(response.status(), StatusCode::ACCEPTED);
        assert_eq!(
            response
                .headers()
                .get("idempotency-replayed")
                .and_then(|value| value.to_str().ok()),
            Some("true")
        );
        let original_request_id_text = original_request_id.to_string();
        assert_eq!(
            response
                .headers()
                .get("idempotency-original-request-id")
                .and_then(|value| value.to_str().ok()),
            Some(original_request_id_text.as_str())
        );
        assert_eq!(
            to_bytes(response.into_body(), 1024).await.unwrap(),
            response_body.as_bytes()
        );

        let different_target = format!("storage_job\0{}", job.saturating_add(1));
        let target_conflict = retry_idempotency_request(
            admin_id,
            actor_scope,
            different_target.as_bytes(),
            key,
            0,
            Uuid::new_v4(),
        );
        let mut conflict_tx = pool.begin().await.unwrap();
        assert!(matches!(
            crate::db::acquire_idempotency_in_tx(&keys, &mut conflict_tx, &target_conflict)
                .await
                .unwrap(),
            crate::db::IdempotencyAcquire::FingerprintConflict
        ));
        conflict_tx.rollback().await.unwrap();

        let generation_conflict = retry_idempotency_request(
            admin_id,
            actor_scope,
            target.as_bytes(),
            key,
            1,
            Uuid::new_v4(),
        );
        let mut generation_tx = pool.begin().await.unwrap();
        assert!(matches!(
            crate::db::acquire_idempotency_in_tx(&keys, &mut generation_tx, &generation_conflict)
                .await
                .unwrap(),
            crate::db::IdempotencyAcquire::FingerprintConflict
        ));
        generation_tx.rollback().await.unwrap();

        let missing_id = i64::MAX;
        let missing_target = format!("storage_job\0{missing_id}");
        let missing_key = "upload-retry-missing-0001";
        let missing_original_request_id = Uuid::new_v4();
        let missing_request = retry_idempotency_request(
            admin_id,
            actor_scope,
            missing_target.as_bytes(),
            missing_key,
            0,
            missing_original_request_id,
        );
        let mut missing_tx = pool.begin().await.unwrap();
        let missing_lease =
            match crate::db::acquire_idempotency_in_tx(&keys, &mut missing_tx, &missing_request)
                .await
                .unwrap()
            {
                crate::db::IdempotencyAcquire::Acquired(lease) => lease,
                other => panic!("unexpected missing-row admission: {other:?}"),
            };
        assert_eq!(
            retry_upload_dead_letter_in_tx(
                &mut missing_tx,
                admin_id,
                0,
                &admin_token,
                UploadDeadLetterId::StorageJob(missing_id),
                missing_lease.request_id,
            )
            .await
            .unwrap(),
            RetryUploadDeadLetter::Unavailable
        );
        let missing_body = br#"{"error":{"code":"not_found","message":"upload dead-letter entry is unavailable"}}"#;
        assert!(crate::db::complete_idempotency_in_tx(
            &keys,
            &mut missing_tx,
            &missing_lease,
            StatusCode::NOT_FOUND.as_u16(),
            &crate::api::json_replay_headers(),
            missing_body,
        )
        .await
        .unwrap());
        missing_tx.commit().await.unwrap();

        let missing_replay = retry_idempotency_request(
            admin_id,
            actor_scope,
            missing_target.as_bytes(),
            missing_key,
            0,
            Uuid::new_v4(),
        );
        let mut missing_replay_tx = pool.begin().await.unwrap();
        let replay =
            crate::db::acquire_idempotency_in_tx(&keys, &mut missing_replay_tx, &missing_replay)
                .await
                .unwrap();
        let replay = match replay {
            crate::db::IdempotencyAcquire::Replay(replay) => replay,
            other => panic!("unexpected stored-404 replay outcome: {other:?}"),
        };
        missing_replay_tx.commit().await.unwrap();
        let response = crate::api::idempotency_replay_response(replay).unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            response
                .headers()
                .get("idempotency-replayed")
                .and_then(|value| value.to_str().ok()),
            Some("true")
        );
        let missing_original_request_id_text = missing_original_request_id.to_string();
        assert_eq!(
            response
                .headers()
                .get("idempotency-original-request-id")
                .and_then(|value| value.to_str().ok()),
            Some(missing_original_request_id_text.as_str())
        );
        assert_eq!(
            to_bytes(response.into_body(), 1024).await.unwrap().as_ref(),
            missing_body.as_slice()
        );

        let successful_audits: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM audit_log
              WHERE request_id=$1 AND action='admin.upload_dead_letter.retry'",
        )
        .bind(original_request_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(successful_audits, 1);
        pool.close().await;
    }

    #[tokio::test]
    #[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
    async fn postgres_retry_authorization_pagination_concurrency_and_fencing() {
        let url = std::env::var("TEST_DATABASE_URL")
            .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(8)
            .connect(&url)
            .await
            .unwrap();
        crate::db::migrate(&pool).await.unwrap();
        crate::db::validate_upload_capacity_policy(&pool, 10_000, 1_000_000, 1_099_511_627_776)
            .await
            .unwrap();
        let (admin_id, admin_token) = insert_user(&pool, true).await;
        let (user_id, user_token) = insert_user(&pool, false).await;

        let unauthorized_job = insert_storage_dead_letter(&pool, None).await;
        let mut unauthorized_tx = pool.begin().await.unwrap();
        assert_eq!(
            retry_upload_dead_letter_in_tx(
                &mut unauthorized_tx,
                user_id,
                0,
                &user_token,
                UploadDeadLetterId::StorageJob(unauthorized_job),
                Uuid::new_v4(),
            )
            .await
            .unwrap(),
            RetryUploadDeadLetter::Unauthorized
        );
        unauthorized_tx.rollback().await.unwrap();

        let active_claim =
            insert_storage_dead_letter(&pool, Some(Utc::now() + chrono::Duration::minutes(5)))
                .await;
        let mut fenced_tx = pool.begin().await.unwrap();
        assert_eq!(
            retry_upload_dead_letter_in_tx(
                &mut fenced_tx,
                admin_id,
                0,
                &admin_token,
                UploadDeadLetterId::StorageJob(active_claim),
                Uuid::new_v4(),
            )
            .await
            .unwrap(),
            RetryUploadDeadLetter::Unavailable
        );
        fenced_tx.commit().await.unwrap();
        sqlx::query(
            "UPDATE upload_storage_jobs
                SET claim_expires_at=clock_timestamp()-INTERVAL '1 second'
              WHERE id=$1",
        )
        .bind(active_claim)
        .execute(&pool)
        .await
        .unwrap();
        let mut retry_tx = pool.begin().await.unwrap();
        assert_eq!(
            retry_upload_dead_letter_in_tx(
                &mut retry_tx,
                admin_id,
                0,
                &admin_token,
                UploadDeadLetterId::StorageJob(active_claim),
                Uuid::new_v4(),
            )
            .await
            .unwrap(),
            RetryUploadDeadLetter::Retried
        );
        retry_tx.commit().await.unwrap();
        let preserved: (i64, Option<String>, Option<Uuid>) = sqlx::query_as(
            "SELECT attempts,last_error,claim_token
               FROM upload_storage_jobs WHERE id=$1",
        )
        .bind(active_claim)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(preserved, (0, Some("fixture failure".into()), None));

        let raced = insert_storage_dead_letter(&pool, None).await;
        let barrier = Arc::new(Barrier::new(3));
        let mut tasks = Vec::new();
        for _ in 0..2 {
            let pool = pool.clone();
            let barrier = Arc::clone(&barrier);
            let token = admin_token.clone();
            tasks.push(tokio::spawn(async move {
                let mut tx = pool.begin().await.unwrap();
                barrier.wait().await;
                let result = retry_upload_dead_letter_in_tx(
                    &mut tx,
                    admin_id,
                    0,
                    &token,
                    UploadDeadLetterId::StorageJob(raced),
                    Uuid::new_v4(),
                )
                .await
                .unwrap();
                tx.commit().await.unwrap();
                result
            }));
        }
        barrier.wait().await;
        let results = futures::future::join_all(tasks)
            .await
            .into_iter()
            .map(|result| result.unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            results
                .iter()
                .filter(|result| **result == RetryUploadDeadLetter::Retried)
                .count(),
            1
        );
        assert_eq!(
            results
                .iter()
                .filter(|result| **result == RetryUploadDeadLetter::Unavailable)
                .count(),
            1
        );

        let tied: DateTime<Utc> =
            sqlx::query_scalar("SELECT date_trunc('second',clock_timestamp())")
                .fetch_one(&pool)
                .await
                .unwrap();
        let mut fixture_ids = Vec::new();
        for _ in 0..5 {
            let object_id = Uuid::new_v4();
            let recovery_id: Uuid = sqlx::query_scalar(
                "INSERT INTO upload_cleanup_queue(
                     object_id,storage_backend,object_key,expected_size,
                     storage_fence,attempts,dead_lettered_at,last_error)
                 VALUES($1,'local',$1::text,1,0,12,$2,'cleanup fixture')
                 RETURNING recovery_id",
            )
            .bind(object_id)
            .bind(tied)
            .fetch_one(&pool)
            .await
            .unwrap();
            assert_ne!(recovery_id, object_id);
            let recovery_text = recovery_id.hyphenated().to_string();
            assert_eq!(&recovery_text[14..15], "4");
            assert!(matches!(&recovery_text[19..20], "8" | "9" | "a" | "b"));
            fixture_ids.push((object_id, recovery_id));
        }
        let mut page_tx = pool.begin().await.unwrap();
        let first =
            upload_dead_letters_page_in_tx(&mut page_tx, UploadDeadLetterKind::Cleanup, None, 2)
                .await
                .unwrap();
        page_tx.commit().await.unwrap();
        assert_eq!(first.rows.len(), 2);
        let first_ids = first.rows.iter().map(|row| row.id).collect::<HashSet<_>>();
        let mut next_tx = pool.begin().await.unwrap();
        let second = upload_dead_letters_page_in_tx(
            &mut next_tx,
            UploadDeadLetterKind::Cleanup,
            first.next,
            100,
        )
        .await
        .unwrap();
        next_tx.commit().await.unwrap();
        assert!(second.rows.iter().all(|row| !first_ids.contains(&row.id)));
        assert_eq!(first.rows.len() + second.rows.len(), fixture_ids.len());

        let (cleanup_object_id, cleanup_recovery_id) = fixture_ids[0];
        let immutable_error =
            sqlx::query("UPDATE upload_cleanup_queue SET recovery_id=$2 WHERE object_id=$1")
                .bind(cleanup_object_id)
                .bind(Uuid::new_v4())
                .execute(&pool)
                .await
                .unwrap_err();
        assert_eq!(
            immutable_error
                .as_database_error()
                .and_then(|error| error.code().map(|code| code.into_owned()))
                .as_deref(),
            Some("55000")
        );
        let cleanup_request_id = Uuid::new_v4();
        let mut cleanup_retry_tx = pool.begin().await.unwrap();
        assert_eq!(
            retry_upload_dead_letter_in_tx(
                &mut cleanup_retry_tx,
                admin_id,
                0,
                &admin_token,
                UploadDeadLetterId::Cleanup(cleanup_recovery_id),
                cleanup_request_id,
            )
            .await
            .unwrap(),
            RetryUploadDeadLetter::Retried
        );
        cleanup_retry_tx.commit().await.unwrap();
        let cleanup_preserved: (i64, Option<String>, Option<DateTime<Utc>>) = sqlx::query_as(
            "SELECT attempts,last_error,dead_lettered_at
               FROM upload_cleanup_queue WHERE object_id=$1",
        )
        .bind(cleanup_object_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(cleanup_preserved, (0, Some("cleanup fixture".into()), None));
        let (audit_target, audit_details): (String, serde_json::Value) =
            sqlx::query_as("SELECT target,details FROM audit_log WHERE request_id=$1")
                .bind(cleanup_request_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(audit_target, format!("cleanup:{cleanup_recovery_id}"));
        assert!(!audit_target.contains(&cleanup_object_id.to_string()));
        let audit_json = serde_json::to_string(&audit_details).unwrap();
        for forbidden in [
            "last_error_sha256",
            "last_error_bytes",
            "last_error_length",
            "last_error_text",
            "object_id",
            "object_key",
            "stage_key",
            "cleanup fixture",
        ] {
            assert!(!audit_json.contains(forbidden), "audit leaked {forbidden}");
        }

        let audits: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM audit_log
              WHERE actor_id=$1 AND action='admin.upload_dead_letter.retry'",
        )
        .bind(admin_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(audits, 3, "only successful retries create immutable audits");
        pool.close().await;
    }
}
