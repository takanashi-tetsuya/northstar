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
use uuid::Uuid;
use zeroize::Zeroizing;

use northstar_upload_application::admin::{
    UploadDeadLetterBoundary, UploadDeadLetterId, UploadDeadLetterKind, UploadDeadLetterPage,
    UploadDeadLetterRecord,
};

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
    let database_now = northstar_postgres::database_cursor_clock_in_tx(tx).await?;
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
    let session_hash = northstar_auth_core::token_hash(presented_session);
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
}
