//! Upload slot creation, capacity ledger locking and storage authority validation.

use super::*;

#[cfg(test)]
pub(super) async fn lock_upload_capacity_ledger(
    transaction: &mut Transaction<'_, Postgres>,
) -> Result<()> {
    match sqlx::query_scalar::<_, bool>("SELECT northstar_upload_capacity_lock()")
        .fetch_optional(&mut **transaction)
        .await
    {
        Ok(Some(true)) => Ok(()),
        Ok(Some(false)) | Ok(None) => anyhow::bail!("upload storage capacity authority is missing"),
        Err(sqlx::Error::Database(error)) if error.code().as_deref() == Some("55P03") => {
            anyhow::bail!("upload storage capacity busy; retry")
        }
        Err(error) => Err(error.into()),
    }
}

#[cfg(test)]
pub(super) fn is_retryable_upload_capacity_lock(error: &sqlx::Error) -> bool {
    matches!(error, sqlx::Error::Database(database_error)
        if database_error.code().as_deref()==Some("55P03"))
}

#[cfg(test)]
pub(super) fn cleanup_object_version(
    storage_backend: &str,
    object_key: &str,
    object_version: Option<String>,
    stage_key: Option<&str>,
    stage_version: Option<&str>,
) -> Option<String> {
    if storage_backend == "s3" && stage_key == Some(object_key) {
        object_version.or_else(|| stage_version.map(str::to_owned))
    } else {
        object_version
    }
}

#[derive(Clone, Copy, Debug)]
pub struct UploadReservation<'a> {
    pub user_id: Uuid,
    pub filename: &'a str,
    pub content_type: &'a str,
    pub size: i64,
    pub token_hash: &'a [u8],
    pub max_files_per_user: i64,
    pub max_bytes_per_user: i64,
    pub storage_backend: &'a str,
}

#[cfg(test)]
pub async fn create_upload_slot(
    pool: &PgPool,
    reservation: UploadReservation<'_>,
) -> Result<Option<Uuid>> {
    create_upload_slot_bounded(
        pool,
        reservation,
        TEST_UPLOAD_RETAINED_FILES_LIMIT,
        TEST_UPLOAD_RETAINED_BYTES_LIMIT,
        TEST_UPLOAD_PENDING_LIMIT,
    )
    .await
}

pub async fn create_upload_slot_bounded(
    pool: &PgPool,
    reservation: UploadReservation<'_>,
    max_retained_files: i64,
    max_retained_bytes: i64,
    max_pending_jobs: i64,
) -> Result<Option<Uuid>> {
    let UploadReservation {
        user_id,
        filename,
        content_type,
        size,
        token_hash,
        max_files_per_user,
        max_bytes_per_user,
        storage_backend,
    } = reservation;
    anyhow::ensure!(size > 0, "upload reservation size must be positive");
    anyhow::ensure!(
        matches!(storage_backend, "local" | "s3"),
        "unsupported upload storage backend"
    );
    let id = Uuid::new_v4();
    // Both the ledger and owner-row acquisitions are SQL-native NOWAIT.  The
    // established false result covers either contention case without holding
    // a pool connection behind a lock owner.
    let admitted = sqlx::query_scalar::<_, bool>(
        "SELECT northstar_upload_reserve_slot(
             $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12
         )",
    )
    .bind(id)
    .bind(user_id)
    .bind(filename)
    .bind(content_type)
    .bind(size)
    .bind(token_hash)
    .bind(max_files_per_user)
    .bind(max_bytes_per_user)
    .bind(storage_backend)
    .bind(max_retained_files)
    .bind(max_retained_bytes)
    .bind(max_pending_jobs)
    .fetch_one(pool)
    .await?;
    Ok(admitted.then_some(id))
}

pub async fn validate_upload_storage_backend(
    pool: &PgPool,
    backend: &str,
    namespace_sha256: &[u8; 32],
) -> Result<i64> {
    anyhow::ensure!(matches!(backend, "local" | "s3"), "invalid upload backend");
    sqlx::query_scalar::<_, i64>(
        "SELECT namespace_generation
           FROM northstar_upload_bootstrap_authority($1,$2)",
    )
    .bind(backend)
    .bind(namespace_sha256.as_slice())
    .fetch_one(pool)
    .await
    .map_err(Into::into)
}

/// Refuse to disable uploads while any durable slot or recovery obligation
/// remains. The owner-held function observes all three tables in one snapshot
/// without granting the runtime role direct access to upload records.
pub async fn durable_upload_state_exists(pool: &PgPool) -> Result<bool> {
    Ok(
        sqlx::query_scalar("SELECT northstar_upload_durable_state_exists()")
            .fetch_one(pool)
            .await?,
    )
}

pub async fn validate_upload_capacity_policy(
    pool: &PgPool,
    pending_limit: i64,
    retained_files_limit: i64,
    retained_bytes_limit: i64,
) -> Result<(i64, bool)> {
    let row = sqlx::query(
        "SELECT policy_generation,recovery_draining
           FROM northstar_upload_bind_capacity_policy($1,$2,$3)",
    )
    .bind(pending_limit)
    .bind(retained_files_limit)
    .bind(retained_bytes_limit)
    .fetch_one(pool)
    .await?;
    Ok((
        row.try_get("policy_generation")?,
        row.try_get("recovery_draining")?,
    ))
}

/// Fast fail-closed check used by the security-critical reconciliation worker.
/// The authority row is immutable to the application after first bootstrap.
#[expect(
    clippy::too_many_arguments,
    reason = "the storage and capacity authority tuple is verified atomically by one database function"
)]
pub async fn upload_storage_authority_matches(
    pool: &PgPool,
    backend: &str,
    namespace_sha256: &[u8; 32],
    namespace_generation: i64,
    capacity_policy_generation: i64,
    pending_limit: i64,
    retained_files_limit: i64,
    retained_bytes_limit: i64,
) -> Result<UploadAuthorityProbe> {
    let row = sqlx::query(
        "SELECT namespace_matches,capacity_matches,recovery_draining
           FROM northstar_upload_authority_probe($1,$2,$3,$4,$5,$6,$7)",
    )
    .bind(backend)
    .bind(namespace_sha256.as_slice())
    .bind(namespace_generation)
    .bind(capacity_policy_generation)
    .bind(pending_limit)
    .bind(retained_files_limit)
    .bind(retained_bytes_limit)
    .fetch_one(pool)
    .await?;
    Ok(UploadAuthorityProbe {
        namespace_matches: row.get("namespace_matches"),
        capacity_matches: row.get("capacity_matches"),
        recovery_draining: row.get("recovery_draining"),
    })
}
