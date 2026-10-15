//! Expired slot cleanup and the upload cleanup and storage job queues.

use super::*;

/// Convert expired rows into durable exact-locator deletion work. PostgreSQL
/// metadata remains until the worker has proved both stage and object absent.
pub async fn cleanup_expired_upload_slots(pool: &PgPool) -> Result<Vec<Uuid>> {
    Ok(sqlx::query_scalar::<_, Uuid>(
        "SELECT object_id FROM northstar_upload_admit_expired_cleanup()",
    )
    .fetch_all(pool)
    .await?)
}

pub async fn queued_upload_cleanup(pool: &PgPool) -> Result<Vec<UploadCleanupJob>> {
    let claim_token = Uuid::new_v4();
    let rows = sqlx::query(
        "SELECT object_id,storage_backend,object_key,object_version,
                stage_key,stage_version,storage_attempt,storage_fence,claim_token
           FROM northstar_upload_claim_cleanup($1)",
    )
    .bind(claim_token)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|row| UploadCleanupJob {
            object_id: row.get("object_id"),
            storage_backend: row.get("storage_backend"),
            object_key: row.get("object_key"),
            object_version: row.get("object_version"),
            stage_key: row.get("stage_key"),
            stage_version: row.get("stage_version"),
            storage_attempt: row.get("storage_attempt"),
            storage_fence: row.get("storage_fence"),
            claim_token: row.get("claim_token"),
        })
        .collect())
}

pub async fn complete_queued_upload_cleanup(
    pool: &PgPool,
    id: Uuid,
    claim_token: Uuid,
) -> Result<bool> {
    // The capability's first operation is SQL-native NOWAIT capacity
    // admission. A held ledger returns 55P03 immediately, and central error
    // mapping turns that retryable condition into a 503 rather than waiting
    // behind the cleanup owner.
    Ok(
        sqlx::query_scalar("SELECT northstar_upload_complete_cleanup($1,$2)")
            .bind(id)
            .bind(claim_token)
            .fetch_one(pool)
            .await?,
    )
}

/// A deletion claimant may touch storage only after the durable promotion job
/// for the same attempt/fence has disappeared. This is the external-I/O
/// quiescence barrier used by both HTTP and reconciliation promotion owners.
pub async fn upload_cleanup_generation_is_quiescent(
    pool: &PgPool,
    id: Uuid,
    claim_token: Uuid,
    storage_fence: i64,
) -> Result<bool> {
    Ok(
        sqlx::query_scalar::<_, bool>("SELECT northstar_upload_cleanup_quiescent($1,$2,$3)")
            .bind(id)
            .bind(claim_token)
            .bind(storage_fence)
            .fetch_one(pool)
            .await?,
    )
}

/// Release a cleanup lease when a concurrent exact-generation promotion
/// became visible after candidate selection.  This is scheduling deferral,
/// not a storage failure: return the attempt counter to its pre-claim value so
/// the 24-attempt dead-letter budget is never consumed by normal quiescence.
pub async fn defer_queued_upload_cleanup(
    pool: &PgPool,
    id: Uuid,
    claim_token: Uuid,
) -> Result<bool> {
    Ok(
        sqlx::query_scalar::<_, bool>("SELECT northstar_upload_defer_cleanup($1,$2)")
            .bind(id)
            .bind(claim_token)
            .fetch_one(pool)
            .await?,
    )
}

/// Keep an S3 deletion projection until the exact key has remained absent for
/// a durable quiet period. A timed-out/cancelled multipart completion may
/// become visible after an earlier DELETE/HEAD observed absence. If an object
/// was removed on this pass, restart the quiet period; only two absence
/// observations separated by the interval permit metadata completion.
pub async fn confirm_upload_cleanup_absence(
    pool: &PgPool,
    id: Uuid,
    claim_token: Uuid,
    removed_now: bool,
    quiet_seconds: i64,
) -> Result<bool> {
    anyhow::ensure!(
        (60..=3600).contains(&quiet_seconds),
        "invalid cleanup quiet period"
    );
    Ok(sqlx::query_scalar::<_, bool>(
        "SELECT northstar_upload_confirm_cleanup_absence($1,$2,$3,$4)",
    )
    .bind(id)
    .bind(claim_token)
    .bind(removed_now)
    .bind(quiet_seconds)
    .fetch_one(pool)
    .await?)
}

pub async fn fail_queued_upload_cleanup(
    pool: &PgPool,
    id: Uuid,
    claim_token: Uuid,
    error: &str,
) -> Result<bool> {
    Ok(
        sqlx::query_scalar::<_, bool>("SELECT northstar_upload_fail_cleanup($1,$2,$3)")
            .bind(id)
            .bind(claim_token)
            .bind(error.replace(char::is_control, " "))
            .fetch_one(pool)
            .await?,
    )
}

pub async fn claim_upload_storage_jobs(pool: &PgPool) -> Result<Vec<UploadStorageJob>> {
    let claim = Uuid::new_v4();
    let rows = sqlx::query(
        "SELECT id,object_id,storage_attempt,action,storage_backend,
                stage_key,stage_version,object_key,object_version,
                expected_size,expected_sha256,storage_fence,claim_token
           FROM northstar_upload_claim_storage_jobs($1)",
    )
    .bind(claim)
    .fetch_all(pool)
    .await?;
    rows.into_iter()
        .map(|row| {
            let digest = row
                .get::<Option<Vec<u8>>, _>("expected_sha256")
                .map(|value| {
                    value
                        .try_into()
                        .map_err(|_| anyhow::anyhow!("invalid upload job digest"))
                })
                .transpose()?;
            Ok(UploadStorageJob {
                id: row.get("id"),
                object_id: row.get("object_id"),
                storage_attempt: row.get("storage_attempt"),
                action: row.get("action"),
                storage_backend: row.get("storage_backend"),
                stage_key: row.get("stage_key"),
                stage_version: row.get("stage_version"),
                object_key: row.get("object_key"),
                object_version: row.get("object_version"),
                expected_size: row.get("expected_size"),
                expected_sha256: digest,
                storage_fence: row.get("storage_fence"),
                claim_token: row.get("claim_token"),
            })
        })
        .collect()
}

pub async fn complete_upload_storage_job(
    pool: &PgPool,
    id: i64,
    claim_token: Uuid,
) -> Result<bool> {
    Ok(
        sqlx::query_scalar::<_, bool>("SELECT northstar_upload_complete_storage_job($1,$2)")
            .bind(id)
            .bind(claim_token)
            .fetch_one(pool)
            .await?,
    )
}

pub async fn confirm_upload_stage_absence(
    pool: &PgPool,
    id: i64,
    claim_token: Uuid,
    removed_now: bool,
    quiet_seconds: i64,
) -> Result<bool> {
    anyhow::ensure!(
        (60..=3600).contains(&quiet_seconds),
        "invalid stage quiet period"
    );
    Ok(
        sqlx::query_scalar::<_, bool>("SELECT northstar_upload_confirm_stage_absence($1,$2,$3,$4)")
            .bind(id)
            .bind(claim_token)
            .bind(removed_now)
            .bind(quiet_seconds)
            .fetch_one(pool)
            .await?,
    )
}

pub async fn fail_upload_storage_job(
    pool: &PgPool,
    id: i64,
    claim_token: Uuid,
    error: &str,
) -> Result<bool> {
    Ok(
        sqlx::query_scalar::<_, bool>("SELECT northstar_upload_fail_storage_job($1,$2,$3)")
            .bind(id)
            .bind(claim_token)
            .bind(error.replace(char::is_control, " "))
            .fetch_one(pool)
            .await?,
    )
}

/// Release a storage-job lease without consuming its retry budget. This is
/// used only when the process-wide upload authority gate invalidates an
/// operation; the external I/O result is deliberately treated as unknown and
/// the durable projection remains authoritative for a later healthy worker.
pub async fn defer_upload_storage_job(pool: &PgPool, id: i64, claim_token: Uuid) -> Result<bool> {
    Ok(
        sqlx::query_scalar::<_, bool>("SELECT northstar_upload_defer_storage_job($1,$2)")
            .bind(id)
            .bind(claim_token)
            .fetch_one(pool)
            .await?,
    )
}
