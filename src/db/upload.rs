use anyhow::Result;
use sqlx::{PgPool, Row};
#[cfg(test)]
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

const MAX_UPLOAD_ATTEMPTS: i64 = 8;
const MAX_UPLOAD_REPLAYS: i64 = 3;
const UPLOAD_HEALTH_COUNT_SATURATION: i64 = 1001;
#[cfg(test)]
const TEST_UPLOAD_PENDING_LIMIT: i64 = 128;
#[cfg(test)]
const TEST_UPLOAD_RETAINED_FILES_LIMIT: i64 = 10_000;
#[cfg(test)]
const TEST_UPLOAD_RETAINED_BYTES_LIMIT: i64 = 1024 * 1024 * 1024;

#[cfg(test)]
async fn lock_upload_capacity_ledger(transaction: &mut Transaction<'_, Postgres>) -> Result<()> {
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
fn is_retryable_upload_capacity_lock(error: &sqlx::Error) -> bool {
    matches!(error, sqlx::Error::Database(database_error)
        if database_error.code().as_deref()==Some("55P03"))
}

#[cfg(test)]
fn cleanup_object_version(
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

#[derive(Clone, Debug)]
pub struct UploadSlot {
    pub id: Uuid,
    pub content_type: String,
    pub size: i64,
    pub remaining_seconds: u64,
    pub storage_backend: String,
    pub storage_object_key: Option<String>,
    pub storage_object_version: Option<String>,
}

#[derive(Debug)]
pub struct UploadLease {
    pub slot: UploadSlot,
    pub claim_token: Uuid,
    /// Monotonic database fence for this exact attempt. Unlike the renewable
    /// claim expiry, it remains stable throughout staged reconciliation.
    pub storage_fence: i64,
    /// Bounded by PostgreSQL's clock, not the application host clock.
    pub remaining_seconds: u64,
}

#[derive(Debug)]
pub enum UploadClaimOutcome {
    Acquired(UploadLease),
    Replay {
        slot: UploadSlot,
        content_sha256: [u8; 32],
    },
    InProgress {
        retry_after_seconds: u64,
    },
    Rejected,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UploadRenewOutcome {
    Renewed,
    Busy,
    Lost,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UploadAuthorityProbe {
    pub namespace_matches: bool,
    pub capacity_matches: bool,
    pub recovery_draining: bool,
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

pub struct UploadStageProjection<'a> {
    pub id: Uuid,
    pub claim_token: Uuid,
    pub storage_backend: &'a str,
    pub stage_key: &'a str,
    pub stage_version: Option<&'a str>,
    pub object_key: &'a str,
    pub content_sha256: &'a [u8; 32],
    pub size: u64,
    pub storage_fence: i64,
}

pub struct PromotedUploadProjection<'a> {
    pub id: Uuid,
    pub claim_token: Uuid,
    pub promotion_claim_token: Uuid,
    pub storage_backend: &'a str,
    pub object_key: &'a str,
    pub object_version: Option<&'a str>,
    pub content_sha256: &'a [u8; 32],
    pub size: u64,
    pub retention_seconds: u64,
    pub storage_fence: i64,
}

pub struct CommittedUploadIdentity<'a> {
    pub id: Uuid,
    pub storage_attempt: Uuid,
    pub storage_backend: &'a str,
    pub object_key: &'a str,
    pub object_version: Option<&'a str>,
    pub content_sha256: &'a [u8; 32],
    pub size: u64,
    pub storage_fence: i64,
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

/// Atomically claim an upload slot with a renewable fencing token.
///
/// A completed slot returns its authoritative digest so the HTTP layer can
/// consume an authenticated retry and accept it only when the bytes are
/// identical. An expired worker can never renew, complete, or release the
/// replacement worker's lease.
pub async fn claim_upload_slot(
    pool: &PgPool,
    id: Uuid,
    token_hash: &[u8],
    lease_seconds: i64,
) -> Result<UploadClaimOutcome> {
    anyhow::ensure!((15..=300).contains(&lease_seconds), "invalid upload lease");
    // This is the sole runtime transition which can introduce object/stage
    // locators on a debt-free slot. The capability takes both capacity and
    // target-slot locks with SQL-native NOWAIT, returning `in_progress` for
    // either contention case rather than relying on a process timeout.
    let row = sqlx::query(
        "SELECT outcome,id,content_type,size,object_remaining_seconds,
                storage_backend,storage_object_key,storage_object_version,
                content_sha256,claim_token,storage_fence,retry_after_seconds
           FROM northstar_upload_claim_slot($1,$2,$3,$4,$5)",
    )
    .bind(id)
    .bind(token_hash)
    .bind(lease_seconds)
    .bind(MAX_UPLOAD_ATTEMPTS)
    .bind(MAX_UPLOAD_REPLAYS)
    .fetch_one(pool)
    .await?;
    match row.get::<String, _>("outcome").as_str() {
        "rejected" => Ok(UploadClaimOutcome::Rejected),
        "in_progress" => Ok(UploadClaimOutcome::InProgress {
            retry_after_seconds: row
                .get::<Option<i64>, _>("retry_after_seconds")
                .unwrap_or(1)
                .max(1) as u64,
        }),
        "replay" => {
            let digest = row
                .get::<Option<Vec<u8>>, _>("content_sha256")
                .and_then(|value| value.try_into().ok())
                .ok_or_else(|| anyhow::anyhow!("upload replay capability returned bad digest"))?;
            Ok(UploadClaimOutcome::Replay {
                slot: upload_slot_from_row(&row),
                content_sha256: digest,
            })
        }
        "acquired" => Ok(UploadClaimOutcome::Acquired(UploadLease {
            slot: upload_slot_from_row(&row),
            claim_token: row
                .get::<Option<Uuid>, _>("claim_token")
                .ok_or_else(|| anyhow::anyhow!("upload claim capability omitted token"))?,
            storage_fence: row
                .get::<Option<i64>, _>("storage_fence")
                .ok_or_else(|| anyhow::anyhow!("upload claim capability omitted fence"))?,
            remaining_seconds: row
                .get::<Option<i64>, _>("retry_after_seconds")
                .unwrap_or_else(|| row.get::<i64, _>("object_remaining_seconds"))
                .max(0) as u64,
        })),
        _ => anyhow::bail!("upload claim capability returned an invalid outcome"),
    }
}

pub async fn renew_upload_claim(
    pool: &PgPool,
    id: Uuid,
    claim_token: Uuid,
    lease_seconds: i64,
) -> Result<UploadRenewOutcome> {
    anyhow::ensure!((15..=300).contains(&lease_seconds), "invalid upload lease");
    // Renewal updates only the lease fence on an already debt-reserved slot.
    // The database capability deliberately takes that slot with NOWAIT and
    // does *not* touch retained-capacity authority; serializing healthy lease
    // heartbeats on the global ledger would make an unrelated cleanup stall
    // cancel an in-flight upload. Preserve that narrow capability contract.
    let outcome = sqlx::query_scalar::<_, String>("SELECT northstar_upload_renew_claim($1,$2,$3)")
        .bind(id)
        .bind(claim_token)
        .bind(lease_seconds)
        .fetch_one(pool)
        .await?;
    match outcome.as_str() {
        "renewed" => Ok(UploadRenewOutcome::Renewed),
        "busy" => Ok(UploadRenewOutcome::Busy),
        "lost" => Ok(UploadRenewOutcome::Lost),
        _ => anyhow::bail!("upload renew capability returned an invalid outcome"),
    }
}

pub async fn release_upload_claim(pool: &PgPool, id: Uuid, claim_token: Uuid) -> Result<bool> {
    // The SQL capability takes the capacity ledger with NOWAIT before it can
    // create a cleanup projection. Do not add an application timeout around
    // that authoritative admission path.
    Ok(
        sqlx::query_scalar::<_, bool>("SELECT northstar_upload_release_claim($1,$2)")
            .bind(id)
            .bind(claim_token)
            .fetch_one(pool)
            .await?,
    )
}

/// Used by startup recovery before removing a well-formed staging file. This
/// exact token check preserves a live writer owned by another process during a
/// rolling restart while still allowing expired crash remnants to be cleaned.
pub async fn upload_claim_is_live(pool: &PgPool, id: Uuid, claim_token: Uuid) -> Result<bool> {
    Ok(
        sqlx::query_scalar::<_, bool>("SELECT northstar_upload_claim_is_live($1,$2)")
            .bind(id)
            .bind(claim_token)
            .fetch_one(pool)
            .await?,
    )
}

/// Persist the exact stage and its digest before any object-store promotion.
/// The promotion job is admitted in the same transaction, so a process crash
/// after this commit is recovered without listing the bucket.
pub async fn record_upload_stage(
    pool: &PgPool,
    projection: UploadStageProjection<'_>,
) -> Result<bool> {
    let UploadStageProjection {
        id,
        claim_token,
        storage_backend,
        stage_key,
        stage_version,
        object_key,
        content_sha256,
        size,
        storage_fence,
    } = projection;
    let size = i64::try_from(size)?;
    // This capability atomically creates the promotion projection and now
    // performs its capacity admission as SQL-native NOWAIT.
    Ok(sqlx::query_scalar::<_, bool>(
        "SELECT northstar_upload_record_stage($1,$2,$3,$4,$5,$6,$7,$8,$9)",
    )
    .bind(id)
    .bind(claim_token)
    .bind(storage_backend)
    .bind(stage_key)
    .bind(stage_version)
    .bind(object_key)
    .bind(content_sha256.as_slice())
    .bind(size)
    .bind(storage_fence)
    .fetch_one(pool)
    .await?)
}

pub async fn begin_upload_promotion(
    pool: &PgPool,
    id: Uuid,
    claim_token: Uuid,
    storage_fence: i64,
    promotion_claim_token: Uuid,
) -> Result<bool> {
    // A staged promotion already has either reserved cleanup debt or an exact
    // cleanup projection, so this state-only update cannot fire a new debt
    // reservation.  Keep it independent of unrelated capacity work.
    Ok(
        sqlx::query_scalar::<_, bool>("SELECT northstar_upload_begin_promotion($1,$2,$3,$4)")
            .bind(id)
            .bind(claim_token)
            .bind(storage_fence)
            .bind(promotion_claim_token)
            .fetch_one(pool)
            .await?,
    )
}

/// Exclusively own the durable verification/promotion job while the HTTP
/// request performs storage I/O. S3 performs an exact-version readback only;
/// local storage performs its create-only hard link. The lease exceeds the
/// bounded operation timeout used by the worker.
pub async fn claim_upload_promotion_job(
    pool: &PgPool,
    id: Uuid,
    storage_attempt: Uuid,
    storage_fence: i64,
) -> Result<Option<Uuid>> {
    let claim_token = Uuid::new_v4();
    let claimed =
        sqlx::query_scalar::<_, bool>("SELECT northstar_upload_claim_promotion_job($1,$2,$3,$4)")
            .bind(id)
            .bind(storage_attempt)
            .bind(storage_fence)
            .bind(claim_token)
            .fetch_one(pool)
            .await?;
    Ok(claimed.then_some(claim_token))
}

pub async fn defer_upload_promotion_job(
    pool: &PgPool,
    id: Uuid,
    storage_attempt: Uuid,
    storage_fence: i64,
    claim_token: Uuid,
) -> Result<bool> {
    Ok(
        sqlx::query_scalar::<_, bool>("SELECT northstar_upload_defer_promotion_job($1,$2,$3,$4)")
            .bind(id)
            .bind(storage_attempt)
            .bind(storage_fence)
            .bind(claim_token)
            .fetch_one(pool)
            .await?,
    )
}

/// Commit metadata only after the immutable promoted object has been read back
/// and verified. No object-store future is awaited inside this transaction.
pub async fn complete_promoted_upload(
    pool: &PgPool,
    projection: PromotedUploadProjection<'_>,
) -> Result<bool> {
    let PromotedUploadProjection {
        id,
        claim_token,
        promotion_claim_token,
        storage_backend,
        object_key,
        object_version,
        content_sha256,
        size,
        retention_seconds,
        storage_fence,
    } = projection;
    let size = i64::try_from(size)?;
    let retention_seconds = i64::try_from(retention_seconds)?;
    Ok(sqlx::query_scalar::<_, bool>(
        "SELECT northstar_upload_complete_promotion($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)",
    )
    .bind(id)
    .bind(claim_token)
    .bind(promotion_claim_token)
    .bind(storage_backend)
    .bind(object_key)
    .bind(object_version)
    .bind(content_sha256.as_slice())
    .bind(size)
    .bind(retention_seconds)
    .bind(storage_fence)
    .fetch_one(pool)
    .await?)
}

/// Resolve the only benign `complete_promoted_upload` race: another
/// reconciler committed the same immutable attempt and metadata first. This
/// check is deliberately exact; a different fence, digest, key, supplied
/// version or size remains a hard failure. Reconciliation jobs admitted before
/// promotion do not yet know a provider version and may pass `None`; the
/// immutable key/digest/fence tuple then remains authoritative.
pub async fn upload_attempt_is_committed(
    pool: &PgPool,
    identity: CommittedUploadIdentity<'_>,
) -> Result<bool> {
    let CommittedUploadIdentity {
        id,
        storage_attempt,
        storage_backend,
        object_key,
        object_version,
        content_sha256,
        size,
        storage_fence,
    } = identity;
    let size = i64::try_from(size)?;
    Ok(sqlx::query_scalar::<_, bool>(
        "SELECT northstar_upload_attempt_committed($1,$2,$3,$4,$5,$6,$7,$8)",
    )
    .bind(id)
    .bind(storage_attempt)
    .bind(storage_backend)
    .bind(object_key)
    .bind(object_version)
    .bind(content_sha256.as_slice())
    .bind(size)
    .bind(storage_fence)
    .fetch_one(pool)
    .await?)
}

/// Retire an exact promotion job only after a durable deletion projection has
/// fenced the same generation. Callers invoke this after their storage verification has
/// returned (or before starting it), so the delete worker can subsequently
/// prove that no promotion owner remains before touching storage.
pub async fn retire_upload_promotion_for_cleanup(
    pool: &PgPool,
    id: Uuid,
    storage_attempt: Uuid,
    storage_fence: i64,
    promotion_claim_token: Uuid,
) -> Result<bool> {
    Ok(sqlx::query_scalar::<_, bool>(
        "SELECT northstar_upload_retire_promotion_for_cleanup($1,$2,$3,$4)",
    )
    .bind(id)
    .bind(storage_attempt)
    .bind(storage_fence)
    .bind(promotion_claim_token)
    .fetch_one(pool)
    .await?)
}

#[cfg(test)]
pub async fn complete_upload(
    pool: &PgPool,
    id: Uuid,
    claim_token: Uuid,
    content_sha256: &[u8; 32],
    retention_seconds: u64,
) -> Result<bool> {
    let row = sqlx::query(
        "SELECT storage_backend,size,storage_fence FROM upload_slots
         WHERE id=$1 AND storage_attempt=$2",
    )
    .bind(id)
    .bind(claim_token)
    .fetch_optional(pool)
    .await?;
    let Some(row) = row else {
        return Ok(false);
    };
    let backend: String = row.get("storage_backend");
    let size = row.get::<i64, _>("size") as u64;
    let storage_fence: i64 = row.get("storage_fence");
    let object_key = if backend == "local" {
        id.to_string()
    } else {
        format!("objects/{id}/{claim_token}")
    };
    let stage_key = if backend == "s3" {
        object_key.clone()
    } else {
        format!("staging/{id}/{claim_token}")
    };
    if !record_upload_stage(
        pool,
        UploadStageProjection {
            id,
            claim_token,
            storage_backend: &backend,
            stage_key: &stage_key,
            stage_version: None,
            object_key: &object_key,
            content_sha256,
            size,
            storage_fence,
        },
    )
    .await?
    {
        return Ok(false);
    }
    let Some(promotion_claim_token) =
        claim_upload_promotion_job(pool, id, claim_token, storage_fence).await?
    else {
        return Ok(false);
    };
    begin_upload_promotion(pool, id, claim_token, storage_fence, promotion_claim_token).await?;
    complete_promoted_upload(
        pool,
        PromotedUploadProjection {
            id,
            claim_token,
            promotion_claim_token,
            storage_backend: &backend,
            object_key: &object_key,
            object_version: None,
            content_sha256,
            size,
            retention_seconds,
            storage_fence,
        },
    )
    .await
}

pub async fn record_upload_replay(
    pool: &PgPool,
    id: Uuid,
    token_hash: &[u8],
    content_sha256: &[u8; 32],
) -> Result<bool> {
    // A replay only touches a committed row.  Its initial claim already
    // reserved cleanup debt, so the trigger's `NOT OLD...reserved` predicate
    // is false and this hot path must not serialize behind the ledger.
    Ok(
        sqlx::query_scalar::<_, bool>("SELECT northstar_upload_record_replay($1,$2,$3,$4)")
            .bind(id)
            .bind(token_hash)
            .bind(content_sha256.as_slice())
            .bind(MAX_UPLOAD_REPLAYS)
            .fetch_one(pool)
            .await?,
    )
}

pub async fn uploaded_file(pool: &PgPool, id: Uuid) -> Result<Option<UploadSlot>> {
    let row = sqlx::query(
        "SELECT id,content_type,size,storage_backend,storage_object_key,
                storage_object_version,object_remaining_seconds
           FROM northstar_upload_public_file($1)",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;
    Ok(row.as_ref().map(upload_slot_from_row))
}

fn upload_slot_from_row(row: &sqlx::postgres::PgRow) -> UploadSlot {
    UploadSlot {
        id: row.get("id"),
        content_type: row.get("content_type"),
        size: row.get("size"),
        remaining_seconds: row.get::<i64, _>("object_remaining_seconds").max(0) as u64,
        storage_backend: row.get("storage_backend"),
        storage_object_key: row.get("storage_object_key"),
        storage_object_version: row.get("storage_object_version"),
    }
}

#[derive(Clone, Debug)]
pub struct UploadCleanupJob {
    pub object_id: Uuid,
    pub storage_backend: String,
    pub object_key: String,
    pub object_version: Option<String>,
    pub stage_key: Option<String>,
    pub stage_version: Option<String>,
    pub storage_attempt: Option<Uuid>,
    pub storage_fence: i64,
    pub claim_token: Uuid,
}

#[derive(Clone, Debug)]
pub struct UploadStorageJob {
    pub id: i64,
    pub object_id: Uuid,
    pub storage_attempt: Uuid,
    pub action: String,
    pub storage_backend: String,
    pub stage_key: Option<String>,
    pub stage_version: Option<String>,
    pub object_key: Option<String>,
    pub object_version: Option<String>,
    pub expected_size: Option<i64>,
    pub expected_sha256: Option<[u8; 32]>,
    pub storage_fence: i64,
    pub claim_token: Uuid,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct UploadQueueMetrics {
    pub storage_jobs_pending: u64,
    pub cleanup_jobs_pending: u64,
    pub cleanup_obligation_debt: u64,
    pub configured_pending_limit: u64,
    pub legacy_overcommit_draining: u64,
    pub recovery_retained_files: u64,
    pub recovery_retained_bytes: u64,
    pub recovery_overcommit_draining: u64,
    pub oldest_pending_age_seconds: u64,
    /// Saturates at 1001; 1001 means at least 1001, not an exact count.
    pub dead_letter_jobs_capped: u64,
    /// Saturates at 1001; 1001 means at least 1001, not an exact count.
    pub scrub_failures_capped: u64,
    pub scrub_due_capped: u64,
    pub scrub_oldest_overdue_seconds: u64,
    pub cleanup_obligations_due_capped: u64,
    pub cleanup_oldest_overdue_seconds: u64,
}

/// Low-frequency proof that the trigger-maintained O(1) capacity authority
/// still equals a statement-consistent projection of the underlying facts.
/// Hot admission must never perform these scans; the supervised upload worker
/// uses them only as an integrity alarm and deliberately does not rewrite the
/// authority automatically.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UploadCapacityReconciliation {
    pub ledger_retained_files: i64,
    pub fact_retained_files: i64,
    pub ledger_retained_bytes: i64,
    pub fact_retained_bytes: i64,
    pub ledger_pending_jobs: i64,
    pub fact_pending_jobs: i64,
    pub ledger_storage_jobs_pending: i64,
    pub fact_storage_jobs_pending: i64,
    pub ledger_cleanup_jobs_pending: i64,
    pub fact_cleanup_jobs_pending: i64,
    pub ledger_cleanup_obligation_debt: i64,
    pub fact_cleanup_obligation_debt: i64,
    pub ledger_recovery_retained_files: i64,
    pub fact_recovery_retained_files: i64,
    pub ledger_recovery_retained_bytes: i64,
    pub fact_recovery_retained_bytes: i64,
    pub ledger_legacy_overcommit_draining: bool,
    pub fact_legacy_overcommit_draining: bool,
    pub ledger_recovery_overcommit_draining: bool,
    pub fact_recovery_overcommit_draining: bool,
    pub projection_size_conflicts: i64,
}

impl UploadCapacityReconciliation {
    pub fn mismatch_count(self) -> u64 {
        let pairs = [
            (self.ledger_retained_files, self.fact_retained_files),
            (self.ledger_retained_bytes, self.fact_retained_bytes),
            (self.ledger_pending_jobs, self.fact_pending_jobs),
            (
                self.ledger_storage_jobs_pending,
                self.fact_storage_jobs_pending,
            ),
            (
                self.ledger_cleanup_jobs_pending,
                self.fact_cleanup_jobs_pending,
            ),
            (
                self.ledger_cleanup_obligation_debt,
                self.fact_cleanup_obligation_debt,
            ),
            (
                self.ledger_recovery_retained_files,
                self.fact_recovery_retained_files,
            ),
            (
                self.ledger_recovery_retained_bytes,
                self.fact_recovery_retained_bytes,
            ),
        ];
        let counter_mismatches = pairs
            .into_iter()
            .filter(|(ledger, fact)| ledger != fact)
            .count() as u64;
        counter_mismatches
            .saturating_add(u64::from(
                self.ledger_legacy_overcommit_draining != self.fact_legacy_overcommit_draining,
            ))
            .saturating_add(u64::from(
                self.ledger_recovery_overcommit_draining != self.fact_recovery_overcommit_draining,
            ))
            .saturating_add(self.projection_size_conflicts.max(0) as u64)
    }
}

/// Lightweight catalog proof for the upload-capacity enforcement boundary.
///
/// Unlike the fact reconciliation below, this check does not scan upload
/// rows. It is safe to run frequently and detects a disabled/misattached
/// trigger, changed routine authority, owner drift, public EXECUTE grant, or
/// deployment-policy change before a later write can silently corrupt the
/// trigger-maintained ledger.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct UploadCapacityAuthorityAudit {
    pub relation_owner_violations: i64,
    pub relation_acl_violations: i64,
    pub function_authority_violations: i64,
    pub trigger_authority_violations: i64,
    pub policy_binding_violations: i64,
}

impl UploadCapacityAuthorityAudit {
    pub fn violation_count(self) -> u64 {
        [
            self.relation_owner_violations,
            self.relation_acl_violations,
            self.function_authority_violations,
            self.trigger_authority_violations,
            self.policy_binding_violations,
        ]
        .into_iter()
        .map(|violations| violations.max(0) as u64)
        .fold(0_u64, u64::saturating_add)
    }
}

/// Verify the live PostgreSQL authority which makes the O(1) capacity ledger
/// trustworthy. This is intentionally observation-only: a mismatch is
/// evidence to preserve, never permission for the online worker to repair DDL
/// or rewrite counters.
pub async fn audit_upload_capacity_authority(
    pool: &PgPool,
    pending_limit: i64,
    retained_files_limit: i64,
    retained_bytes_limit: i64,
) -> Result<UploadCapacityAuthorityAudit> {
    let mut tx = pool.begin().await?;
    sqlx::query("SET TRANSACTION READ ONLY")
        .execute(&mut *tx)
        .await?;
    sqlx::query("SET LOCAL statement_timeout='5s'")
        .execute(&mut *tx)
        .await?;
    let row = sqlx::query(
        r#"WITH installation AS (
             SELECT pg_catalog.current_schema() AS schema_name
           ), expected_relations(relation_name) AS (
             VALUES ('upload_slots'),('upload_storage_authority'),
                    ('upload_storage_jobs'),('upload_cleanup_queue'),
                    ('upload_storage_capacity_ledger')
           ), relation_state AS (
             SELECT expected.relation_name,relation_row.oid,
                    relation_row.relowner,relation_schema.nspowner
               FROM installation
               CROSS JOIN expected_relations expected
               LEFT JOIN pg_catalog.pg_namespace relation_schema
                 ON relation_schema.nspname=installation.schema_name
               LEFT JOIN pg_catalog.pg_class relation_row
                 ON relation_row.relnamespace=relation_schema.oid
                AND relation_row.relname=expected.relation_name
                AND relation_row.relkind IN ('r','p')
           ), expected_functions(function_name,security_definer) AS (
             VALUES
               ('queue_upload_storage_delete',TRUE),
               ('reserve_upload_cleanup_debt',TRUE),
               ('account_upload_slot_capacity',TRUE),
               ('account_upload_storage_job_capacity',TRUE),
               ('account_upload_cleanup_capacity',TRUE),
               ('guard_upload_capacity_nowait',TRUE),
               ('protect_upload_storage_job_identity',FALSE),
               ('protect_upload_cleanup_identity',FALSE),
               ('protect_upload_capacity_policy',FALSE)
           ), function_state AS (
             SELECT expected.function_name,expected.security_definer,
                    function_row.oid,function_row.proowner,function_row.prosecdef,
                    function_row.prorettype,language_row.lanname,
                    relation_schema.nspowner,
                    COALESCE(function_row.proconfig,ARRAY[]::pg_catalog.text[])=
                      ARRAY[pg_catalog.format(
                        'search_path=pg_catalog, %I, pg_temp',
                        installation.schema_name
                      )]::pg_catalog.text[] AS search_path_exact,
                    CASE WHEN function_row.oid IS NULL THEN FALSE ELSE NOT EXISTS(
                      SELECT 1
                        FROM pg_catalog.aclexplode(COALESCE(
                          function_row.proacl,
                          pg_catalog.acldefault('f',function_row.proowner)
                        )) privilege
                       WHERE privilege.grantee=0
                         AND privilege.privilege_type='EXECUTE'
                    ) END AS public_execute_revoked
               FROM installation
               CROSS JOIN expected_functions expected
               LEFT JOIN pg_catalog.pg_namespace relation_schema
                 ON relation_schema.nspname=installation.schema_name
               LEFT JOIN pg_catalog.pg_proc function_row
                 ON function_row.pronamespace=relation_schema.oid
                AND function_row.proname=expected.function_name
                AND function_row.pronargs=0
               LEFT JOIN pg_catalog.pg_language language_row
                 ON language_row.oid=function_row.prolang
           ), expected_triggers(
                relation_name,trigger_name,function_name,function_signature,trigger_type,
                attachment_count
           ) AS (
             VALUES
               ('upload_slots','upload_storage_delete_queue',
                'queue_upload_storage_delete','queue_upload_storage_delete()',11,1),
               ('upload_slots','upload_slot_cleanup_debt_reserve',
                'reserve_upload_cleanup_debt','reserve_upload_cleanup_debt()',19,1),
               ('upload_slots','upload_slot_capacity_insert',
                'account_upload_slot_capacity','account_upload_slot_capacity()',5,2),
               ('upload_slots','upload_slot_capacity_delete',
                'account_upload_slot_capacity','account_upload_slot_capacity()',9,2),
               ('upload_slots','northstar_upload_capacity_nowait_slots_insert_delete',
                'guard_upload_capacity_nowait','guard_upload_capacity_nowait()',15,4),
               ('upload_slots','northstar_upload_capacity_nowait_slot_locator_update',
                'guard_upload_capacity_nowait','guard_upload_capacity_nowait()',19,4),
               ('upload_storage_jobs','upload_job_capacity_insert',
                'account_upload_storage_job_capacity','account_upload_storage_job_capacity()',5,2),
               ('upload_storage_jobs','upload_job_capacity_delete',
                'account_upload_storage_job_capacity','account_upload_storage_job_capacity()',9,2),
               ('upload_storage_jobs','northstar_upload_capacity_nowait_storage_job_insert_delete',
                'guard_upload_capacity_nowait','guard_upload_capacity_nowait()',15,4),
               ('upload_cleanup_queue','upload_cleanup_capacity_insert',
                'account_upload_cleanup_capacity','account_upload_cleanup_capacity()',5,2),
               ('upload_cleanup_queue','upload_cleanup_capacity_delete',
                'account_upload_cleanup_capacity','account_upload_cleanup_capacity()',9,2),
               ('upload_cleanup_queue','northstar_upload_capacity_nowait_cleanup_insert_delete',
                'guard_upload_capacity_nowait','guard_upload_capacity_nowait()',15,4),
               ('upload_storage_jobs','upload_storage_job_identity_guard',
                'protect_upload_storage_job_identity','protect_upload_storage_job_identity()',19,1),
               ('upload_cleanup_queue','upload_cleanup_identity_guard',
                'protect_upload_cleanup_identity','protect_upload_cleanup_identity()',19,1),
               ('upload_storage_capacity_ledger','upload_capacity_policy_guard',
                'protect_upload_capacity_policy','protect_upload_capacity_policy()',19,1)
           ), trigger_state AS (
             SELECT expected.*,
                    (SELECT pg_catalog.count(*)
                       FROM pg_catalog.pg_trigger trigger_row
                       JOIN pg_catalog.pg_class relation_row
                         ON relation_row.oid=trigger_row.tgrelid
                       JOIN pg_catalog.pg_namespace relation_schema
                         ON relation_schema.oid=relation_row.relnamespace
                       JOIN pg_catalog.pg_proc function_row
                         ON function_row.oid=trigger_row.tgfoid
                       JOIN pg_catalog.pg_namespace function_schema
                         ON function_schema.oid=function_row.pronamespace
                      WHERE relation_schema.nspname=installation.schema_name
                        AND relation_row.relname=expected.relation_name
                        AND trigger_row.tgname=expected.trigger_name
                        AND NOT trigger_row.tgisinternal
                        AND trigger_row.tgenabled IN ('O','A')
                        AND trigger_row.tgqual IS NULL
                        AND trigger_row.tgtype::pg_catalog.int4=
                            expected.trigger_type
                        AND function_schema.nspname=installation.schema_name
                        AND function_row.oid=pg_catalog.to_regprocedure(
                          pg_catalog.format('%I.%s',
                            installation.schema_name,expected.function_signature)
                        )
                        AND function_row.prorettype=
                            'pg_catalog.trigger'::pg_catalog.regtype
                    ) AS exact_matches,
                    (SELECT pg_catalog.count(*)
                       FROM pg_catalog.pg_trigger attachment
                       JOIN pg_catalog.pg_proc attached_function
                         ON attached_function.oid=attachment.tgfoid
                       JOIN pg_catalog.pg_namespace function_schema
                         ON function_schema.oid=attached_function.pronamespace
                      WHERE function_schema.nspname=installation.schema_name
                        AND attached_function.oid=pg_catalog.to_regprocedure(
                          pg_catalog.format('%I.%s',
                            installation.schema_name,expected.function_signature)
                        )
                        AND NOT attachment.tgisinternal
                    ) AS actual_attachments
               FROM installation
               CROSS JOIN expected_triggers expected
           )
           SELECT
             (SELECT pg_catalog.count(*) FILTER (
                       WHERE oid IS NULL
                          OR relowner IS DISTINCT FROM nspowner
                     ) FROM relation_state) AS relation_owner_violations,
             (SELECT pg_catalog.count(*) FILTER (
                       WHERE oid IS NULL OR EXISTS(
                         SELECT 1 FROM pg_catalog.aclexplode(COALESCE(
                           (SELECT relation_acl.relacl
                              FROM pg_catalog.pg_class relation_acl
                             WHERE relation_acl.oid=relation_state.oid),
                           pg_catalog.acldefault('r',relation_state.relowner)
                         )) privilege
                          WHERE privilege.grantee=0
                       )
                     ) FROM relation_state) AS relation_acl_violations,
             ((SELECT pg_catalog.count(*) FILTER (
                       WHERE oid IS NULL
                          OR proowner IS DISTINCT FROM nspowner
                          OR prosecdef IS DISTINCT FROM security_definer
                          OR prorettype IS DISTINCT FROM
                              'pg_catalog.trigger'::pg_catalog.regtype
                          OR lanname IS DISTINCT FROM 'plpgsql'
                          OR NOT search_path_exact
                          OR NOT public_execute_revoked
                     ) FROM function_state)
               +(CASE WHEN northstar_upload_capability_catalog_healthy(
                    (SELECT schema_name FROM installation)
                  ) THEN 0 ELSE 1 END)::pg_catalog.int8)
                AS function_authority_violations,
             (SELECT pg_catalog.count(*) FILTER (
                       WHERE exact_matches<>1
                          OR actual_attachments<>attachment_count
                     ) FROM trigger_state) AS trigger_authority_violations,
             (CASE WHEN northstar_upload_policy_binding_matches($1,$2,$3)
                   THEN 0 ELSE 1 END)::pg_catalog.int8
               AS policy_binding_violations"#,
    )
    .bind(pending_limit)
    .bind(retained_files_limit)
    .bind(retained_bytes_limit)
    .fetch_one(&mut *tx)
    .await?;
    let audit = UploadCapacityAuthorityAudit {
        relation_owner_violations: row.try_get("relation_owner_violations")?,
        relation_acl_violations: row.try_get("relation_acl_violations")?,
        function_authority_violations: row.try_get("function_authority_violations")?,
        trigger_authority_violations: row.try_get("trigger_authority_violations")?,
        policy_binding_violations: row.try_get("policy_binding_violations")?,
    };
    tx.commit().await?;
    Ok(audit)
}

/// Recompute every mutable upload-capacity counter from immutable row facts in
/// one PostgreSQL statement snapshot. A mismatch is evidence of trigger/ACL
/// bypass or corruption and must make readiness unhealthy; automatic repair
/// would erase the evidence and can under-account physical object debt.
pub async fn reconcile_upload_capacity_ledger(
    pool: &PgPool,
) -> Result<UploadCapacityReconciliation> {
    let mut tx = pool.begin().await?;
    sqlx::query("SET TRANSACTION READ ONLY")
        .execute(&mut *tx)
        .await?;
    // This exact fact scan is deliberately low-frequency, but it must still
    // relinquish its pool connection under DDL contention or a pathological
    // plan. The caller treats either timeout as an unsafe ledger and closes
    // readiness/object I/O rather than silently keeping the previous result.
    sqlx::query("SET LOCAL lock_timeout='2s'")
        .execute(&mut *tx)
        .await?;
    sqlx::query("SET LOCAL statement_timeout='15s'")
        .execute(&mut *tx)
        .await?;
    let row = sqlx::query("SELECT * FROM northstar_upload_capacity_reconciliation()")
        .fetch_one(&mut *tx)
        .await?;
    let reconciliation = UploadCapacityReconciliation {
        ledger_retained_files: row.try_get("ledger_retained_files")?,
        fact_retained_files: row.try_get("fact_retained_files")?,
        ledger_retained_bytes: row.try_get("ledger_retained_bytes")?,
        fact_retained_bytes: row.try_get("fact_retained_bytes")?,
        ledger_pending_jobs: row.try_get("ledger_pending_jobs")?,
        fact_pending_jobs: row.try_get("fact_pending_jobs")?,
        ledger_storage_jobs_pending: row.try_get("ledger_storage_jobs_pending")?,
        fact_storage_jobs_pending: row.try_get("fact_storage_jobs_pending")?,
        ledger_cleanup_jobs_pending: row.try_get("ledger_cleanup_jobs_pending")?,
        fact_cleanup_jobs_pending: row.try_get("fact_cleanup_jobs_pending")?,
        ledger_cleanup_obligation_debt: row.try_get("ledger_cleanup_obligation_debt")?,
        fact_cleanup_obligation_debt: row.try_get("fact_cleanup_obligation_debt")?,
        ledger_recovery_retained_files: row.try_get("ledger_recovery_retained_files")?,
        fact_recovery_retained_files: row.try_get("fact_recovery_retained_files")?,
        ledger_recovery_retained_bytes: row.try_get("ledger_recovery_retained_bytes")?,
        fact_recovery_retained_bytes: row.try_get("fact_recovery_retained_bytes")?,
        ledger_legacy_overcommit_draining: row.try_get("ledger_legacy_overcommit_draining")?,
        fact_legacy_overcommit_draining: row.try_get("fact_legacy_overcommit_draining")?,
        ledger_recovery_overcommit_draining: row.try_get("ledger_recovery_overcommit_draining")?,
        fact_recovery_overcommit_draining: row.try_get("fact_recovery_overcommit_draining")?,
        projection_size_conflicts: row.try_get("projection_size_conflicts")?,
    };
    tx.commit().await?;
    Ok(reconciliation)
}

/// Return a bounded snapshot of durable upload work. The two potentially large
/// exceptional populations saturate at 1001. The worker refreshes these
/// gauges; the metrics HTTP handler never queries PostgreSQL.
pub async fn upload_queue_metrics(pool: &PgPool) -> Result<UploadQueueMetrics> {
    let mut tx = pool.begin().await?;
    sqlx::query("SET TRANSACTION READ ONLY")
        .execute(&mut *tx)
        .await?;
    sqlx::query("SET LOCAL lock_timeout='1s'")
        .execute(&mut *tx)
        .await?;
    sqlx::query("SET LOCAL statement_timeout='2s'")
        .execute(&mut *tx)
        .await?;
    let row = sqlx::query("SELECT * FROM northstar_upload_queue_snapshot()")
        .fetch_one(&mut *tx)
        .await?;
    let snapshot = upload_queue_metrics_from_row(&row)?;
    tx.commit().await?;
    Ok(snapshot)
}

fn upload_queue_metrics_from_row(row: &sqlx::postgres::PgRow) -> Result<UploadQueueMetrics> {
    Ok(UploadQueueMetrics {
        storage_jobs_pending: row.try_get::<i64, _>("storage_jobs_pending")?.max(0) as u64,
        cleanup_jobs_pending: row.try_get::<i64, _>("cleanup_jobs_pending")?.max(0) as u64,
        cleanup_obligation_debt: row.try_get::<i64, _>("cleanup_obligation_debt")?.max(0) as u64,
        configured_pending_limit: row.try_get::<i64, _>("configured_pending_limit")?.max(0) as u64,
        legacy_overcommit_draining: u64::from(
            row.try_get::<bool, _>("legacy_overcommit_draining")?,
        ),
        recovery_retained_files: row.try_get::<i64, _>("recovery_retained_files")?.max(0) as u64,
        recovery_retained_bytes: row.try_get::<i64, _>("recovery_retained_bytes")?.max(0) as u64,
        recovery_overcommit_draining: u64::from(
            row.try_get::<bool, _>("recovery_overcommit_draining")?,
        ),
        oldest_pending_age_seconds: row.try_get::<i64, _>("oldest_pending_age_seconds")?.max(0)
            as u64,
        dead_letter_jobs_capped: row
            .try_get::<i64, _>("dead_letter_jobs")?
            .clamp(0, UPLOAD_HEALTH_COUNT_SATURATION) as u64,
        scrub_failures_capped: row
            .try_get::<i64, _>("scrub_failures")?
            .clamp(0, UPLOAD_HEALTH_COUNT_SATURATION) as u64,
        scrub_due_capped: row.try_get::<i64, _>("scrub_due_capped")?.max(0) as u64,
        scrub_oldest_overdue_seconds: row
            .try_get::<i64, _>("scrub_oldest_overdue_seconds")?
            .max(0) as u64,
        cleanup_obligations_due_capped: row
            .try_get::<i64, _>("cleanup_obligations_due_capped")?
            .max(0) as u64,
        cleanup_oldest_overdue_seconds: row
            .try_get::<i64, _>("cleanup_oldest_overdue_seconds")?
            .max(0) as u64,
    })
}

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

/// Remove one owner-controlled upload from the public namespace and enqueue
/// its backing object for idempotent cleanup in the same transaction.  A
/// missing row and a row owned by another account are deliberately
/// indistinguishable to the caller.  The object worker may run after this
/// function returns; on Unix an already-open download remains readable, while
/// stores which cannot delete an open object retry from the durable queue.
#[cfg(test)]
async fn queue_user_upload_delete_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    user_id: Uuid,
    id: Uuid,
    request_id: Uuid,
) -> Result<bool> {
    let row = sqlx::query(
        "SELECT size,uploaded,uploading,storage_backend,storage_object_key,
                storage_object_version,storage_stage_key,storage_stage_version,
                storage_attempt,storage_size,storage_sha256,storage_fence,storage_state,
                storage_cleanup_debt_reserved
         FROM upload_slots
         WHERE id=$1 AND user_id=$2
         FOR UPDATE",
    )
    .bind(id)
    .bind(user_id)
    .fetch_optional(&mut **tx)
    .await?;
    let Some(row) = row else {
        return Ok(false);
    };
    let size: i64 = row.get("size");
    let uploaded: bool = row.get("uploaded");
    let uploading: bool = row.get("uploading");
    let storage_backend: String = row.get("storage_backend");
    let object_key: Option<String> = row.get("storage_object_key");
    let stage_key: Option<String> = row.get("storage_stage_key");
    let cleanup_queued = object_key.is_some() || stage_key.is_some() || uploaded;
    if !cleanup_queued {
        let removed = sqlx::query("DELETE FROM upload_slots WHERE id=$1 AND user_id=$2")
            .bind(id)
            .bind(user_id)
            .execute(&mut **tx)
            .await?
            .rows_affected()
            == 1;
        anyhow::ensure!(
            removed,
            "locked upload reservation disappeared before deletion"
        );
    } else {
        let object_key = object_key
            .or_else(|| uploaded.then(|| id.to_string()))
            .ok_or_else(|| anyhow::anyhow!("upload deletion has a stage but no object key"))?;
        let stage_version: Option<String> = row.get("storage_stage_version");
        let object_version = cleanup_object_version(
            &storage_backend,
            &object_key,
            row.get("storage_object_version"),
            stage_key.as_deref(),
            stage_version.as_deref(),
        );
        let storage_attempt: Option<Uuid> = row.get("storage_attempt");
        let expected_size = row.get::<Option<i64>, _>("storage_size").unwrap_or(size);
        let expected_sha256: Option<Vec<u8>> = row.get("storage_sha256");
        let storage_fence: i64 = row.get("storage_fence");
        let storage_state: String = row.get("storage_state");
        let inserted = sqlx::query(
            "INSERT INTO upload_cleanup_queue(
             object_id,storage_backend,object_key,object_version,
             stage_key,stage_version,storage_attempt,expected_size,expected_sha256,
             storage_fence,available_at
         ) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,
             CASE WHEN $11='writing'
                  THEN clock_timestamp()+INTERVAL '16 minutes'
                  ELSE clock_timestamp() END)
         ON CONFLICT(object_id) DO NOTHING",
        )
        .bind(id)
        .bind(&storage_backend)
        .bind(&object_key)
        .bind(object_version.as_deref())
        .bind(stage_key.as_deref())
        .bind(stage_version.as_deref())
        .bind(storage_attempt)
        .bind(expected_size)
        .bind(expected_sha256.as_deref())
        .bind(storage_fence)
        .bind(&storage_state)
        .execute(&mut **tx)
        .await?
        .rows_affected();
        if inserted == 0 {
            let exact = sqlx::query_scalar::<_, bool>(
                "SELECT EXISTS(
                     SELECT 1 FROM upload_cleanup_queue
                      WHERE object_id=$1 AND storage_backend=$2 AND object_key=$3
                        AND object_version IS NOT DISTINCT FROM $4
                        AND stage_key IS NOT DISTINCT FROM $5
                        AND stage_version IS NOT DISTINCT FROM $6
                        AND storage_attempt IS NOT DISTINCT FROM $7
                        AND expected_size=$8
                        AND expected_sha256 IS NOT DISTINCT FROM $9
                        AND storage_fence=$10 AND NOT slot_delete_projection
                 )",
            )
            .bind(id)
            .bind(&storage_backend)
            .bind(&object_key)
            .bind(object_version.as_deref())
            .bind(stage_key.as_deref())
            .bind(stage_version.as_deref())
            .bind(storage_attempt)
            .bind(expected_size)
            .bind(expected_sha256.as_deref())
            .bind(storage_fence)
            .fetch_one(&mut **tx)
            .await?;
            anyhow::ensure!(
                exact,
                "existing upload cleanup projection has different identity"
            );
            anyhow::ensure!(
                !row.get::<bool, _>("storage_cleanup_debt_reserved"),
                "existing upload cleanup projection did not convert reserved cleanup debt"
            );
        }
        let hidden = sqlx::query(
            "UPDATE upload_slots
         SET storage_state='deleting',uploaded=FALSE,uploading=FALSE,
             claim_token=NULL,claim_expires_at=NULL,
             content_sha256=NULL,completed_at=NULL,
             storage_cleanup_debt_reserved=FALSE,
             expires_at=clock_timestamp(),storage_updated_at=clock_timestamp()
         WHERE id=$1 AND user_id=$2",
        )
        .bind(id)
        .bind(user_id)
        .execute(&mut **tx)
        .await?
        .rows_affected()
            == 1;
        anyhow::ensure!(hidden, "locked upload row disappeared before deletion");
    }
    sqlx::query(
        "INSERT INTO audit_log(actor_id,action,target,details,request_id)
         VALUES($1,'user.upload.delete',$2,$3,$4)",
    )
    .bind(user_id)
    .bind(id.to_string())
    .bind(serde_json::json!({
        "size": size,
        "uploaded": uploaded,
        "uploading": uploading,
        "cleanup_queued": cleanup_queued,
    }))
    .bind(request_id)
    .execute(&mut **tx)
    .await?;
    Ok(true)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UserUploadDeleteOutcome {
    Accepted,
    Unauthorized,
}

/// Authenticate the exact bearer and remove an owner-controlled upload in
/// one transaction. A concurrent logout, password rotation or account
/// disablement must serialize before or after the delete; it cannot land in
/// the former check/use gap.
pub async fn queue_user_upload_delete_authorized(
    pool: &PgPool,
    user_id: Uuid,
    expected_auth_generation: i64,
    presented_session: &str,
    id: Uuid,
    request_id: Uuid,
) -> Result<UserUploadDeleteOutcome> {
    if presented_session.len() != 64
        || !presented_session
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric())
    {
        return Ok(UserUploadDeleteOutcome::Unauthorized);
    }
    let outcome =
        sqlx::query_scalar::<_, String>("SELECT northstar_upload_delete_owned($1,$2,$3,$4,$5)")
            .bind(user_id)
            .bind(expected_auth_generation)
            .bind(crate::auth::token_hash(presented_session))
            .bind(id)
            .bind(request_id)
            .fetch_one(pool)
            .await?;
    match outcome.as_str() {
        "accepted" => Ok(UserUploadDeleteOutcome::Accepted),
        "unauthorized" => Ok(UserUploadDeleteOutcome::Unauthorized),
        _ => anyhow::bail!("upload delete capability returned an invalid outcome"),
    }
}

#[cfg(test)]
pub async fn queue_user_upload_delete(
    pool: &PgPool,
    user_id: Uuid,
    id: Uuid,
    request_id: Uuid,
) -> Result<bool> {
    let mut tx = pool.begin().await?;
    lock_upload_capacity_ledger(&mut tx).await?;
    let deleted = queue_user_upload_delete_in_tx(&mut tx, user_id, id, request_id).await?;
    tx.commit().await?;
    Ok(deleted)
}

#[derive(Debug)]
pub struct UploadScrubJob {
    pub object_id: Uuid,
    pub storage_attempt: Uuid,
    pub object_key: String,
    pub object_version: Option<String>,
    pub expected_size: u64,
    pub expected_sha256: [u8; 32],
    pub claim_token: Uuid,
}

/// Claim a fixed-size manifest scrub batch. The indexed PostgreSQL manifest is
/// authoritative; reconciliation never lists the provider bucket.
pub async fn claim_upload_scrub_jobs(pool: &PgPool) -> Result<Vec<UploadScrubJob>> {
    // Scrub leases only target committed rows, whose initial claim has already
    // reserved cleanup debt.  This update cannot create a new obligation.
    let rows = sqlx::query(
        "SELECT object_id,storage_attempt,object_key,object_version,
                expected_size,expected_sha256,claim_token
           FROM northstar_upload_claim_scrub()",
    )
    .fetch_all(pool)
    .await;
    let rows = rows?;
    rows.into_iter()
        .map(|row| {
            let digest: Vec<u8> = row.get("expected_sha256");
            Ok(UploadScrubJob {
                object_id: row.get("object_id"),
                storage_attempt: row.get("storage_attempt"),
                object_key: row.get("object_key"),
                object_version: row.get("object_version"),
                expected_size: row.get::<i64, _>("expected_size").try_into()?,
                expected_sha256: digest
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("invalid scrub digest"))?,
                claim_token: row.get("claim_token"),
            })
        })
        .collect()
}

pub async fn complete_upload_scrub(pool: &PgPool, id: Uuid, claim: Uuid) -> Result<bool> {
    finish_upload_scrub(pool, id, claim, "complete").await
}

pub async fn fail_upload_scrub(pool: &PgPool, id: Uuid, claim: Uuid) -> Result<bool> {
    finish_upload_scrub(pool, id, claim, "fail").await
}

pub async fn defer_upload_scrub(pool: &PgPool, id: Uuid, claim: Uuid) -> Result<bool> {
    finish_upload_scrub(pool, id, claim, "defer").await
}

async fn finish_upload_scrub(
    pool: &PgPool,
    id: Uuid,
    claim: Uuid,
    outcome: &'static str,
) -> Result<bool> {
    // The claim capability only leases committed rows, so every permitted
    // finish update has pre-existing cleanup debt and cannot invoke the
    // reservation branch of the upload-slot trigger.
    Ok(
        sqlx::query_scalar::<_, bool>("SELECT northstar_upload_finish_scrub($1,$2,$3)")
            .bind(id)
            .bind(claim)
            .bind(outcome)
            .fetch_one(pool)
            .await?,
    )
}

#[cfg(test)]
mod tests {
    use super::{
        audit_upload_capacity_authority, claim_upload_slot, cleanup_expired_upload_slots,
        cleanup_object_version, complete_queued_upload_cleanup, complete_upload,
        create_upload_slot, defer_queued_upload_cleanup, is_retryable_upload_capacity_lock,
        queue_user_upload_delete, queue_user_upload_delete_authorized, queued_upload_cleanup,
        reconcile_upload_capacity_ledger, record_upload_replay, release_upload_claim,
        renew_upload_claim, upload_cleanup_generation_is_quiescent, uploaded_file,
        validate_upload_capacity_policy, UploadCapacityAuthorityAudit,
        UploadCapacityReconciliation, UploadClaimOutcome, UploadRenewOutcome, UploadReservation,
        UserUploadDeleteOutcome, MAX_UPLOAD_ATTEMPTS, MAX_UPLOAD_REPLAYS,
        TEST_UPLOAD_PENDING_LIMIT, TEST_UPLOAD_RETAINED_BYTES_LIMIT,
        TEST_UPLOAD_RETAINED_FILES_LIMIT,
    };
    use crate::db;
    use sqlx::{PgPool, Row};
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::sync::Barrier;
    use uuid::Uuid;

    async fn test_capacity_authority(pool: &PgPool) -> UploadCapacityAuthorityAudit {
        audit_upload_capacity_authority(
            pool,
            TEST_UPLOAD_PENDING_LIMIT,
            TEST_UPLOAD_RETAINED_FILES_LIMIT,
            TEST_UPLOAD_RETAINED_BYTES_LIMIT,
        )
        .await
        .unwrap()
    }

    #[test]
    fn s3_same_key_cleanup_uses_the_exact_stage_version() {
        assert_eq!(
            cleanup_object_version(
                "s3",
                "objects/id/attempt",
                None,
                Some("objects/id/attempt"),
                Some("version-7"),
            )
            .as_deref(),
            Some("version-7")
        );
        assert_eq!(
            cleanup_object_version(
                "local",
                "id",
                None,
                Some("staging/id/attempt"),
                Some("ignored-stage-version"),
            ),
            None
        );
    }

    #[test]
    fn admission_and_account_delete_share_capacity_then_user_lock_order() {
        #[derive(Debug, Eq, PartialEq)]
        enum LockClass {
            CapacityLedger,
            User,
        }
        let admission = [LockClass::CapacityLedger, LockClass::User];
        let account_delete = [LockClass::CapacityLedger, LockClass::User];
        assert_eq!(admission, account_delete);
    }

    #[test]
    fn capacity_reconciliation_counts_each_counter_and_projection_conflict() {
        let consistent = UploadCapacityReconciliation {
            ledger_retained_files: 1,
            fact_retained_files: 1,
            ledger_retained_bytes: 2,
            fact_retained_bytes: 2,
            ledger_pending_jobs: 3,
            fact_pending_jobs: 3,
            ledger_storage_jobs_pending: 1,
            fact_storage_jobs_pending: 1,
            ledger_cleanup_jobs_pending: 2,
            fact_cleanup_jobs_pending: 2,
            ledger_cleanup_obligation_debt: 4,
            fact_cleanup_obligation_debt: 4,
            ledger_recovery_retained_files: 5,
            fact_recovery_retained_files: 5,
            ledger_recovery_retained_bytes: 6,
            fact_recovery_retained_bytes: 6,
            ledger_legacy_overcommit_draining: false,
            fact_legacy_overcommit_draining: false,
            ledger_recovery_overcommit_draining: false,
            fact_recovery_overcommit_draining: false,
            projection_size_conflicts: 0,
        };
        assert_eq!(consistent.mismatch_count(), 0);

        let inconsistent = UploadCapacityReconciliation {
            fact_pending_jobs: 30,
            fact_recovery_retained_bytes: 60,
            fact_legacy_overcommit_draining: true,
            fact_recovery_overcommit_draining: true,
            projection_size_conflicts: 2,
            ..consistent
        };
        assert_eq!(inconsistent.mismatch_count(), 6);
    }

    #[test]
    fn capacity_authority_audit_counts_each_independent_boundary() {
        let clean = UploadCapacityAuthorityAudit::default();
        assert_eq!(clean.violation_count(), 0);
        let drifted = UploadCapacityAuthorityAudit {
            relation_owner_violations: 1,
            relation_acl_violations: 5,
            function_authority_violations: 2,
            trigger_authority_violations: 3,
            policy_binding_violations: 4,
        };
        assert_eq!(drifted.violation_count(), 15);
    }

    #[tokio::test]
    #[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
    async fn capacity_reconciliation_reads_bigint_facts_and_detects_ledger_drift() {
        let url = std::env::var("TEST_DATABASE_URL")
            .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(4)
            .connect(&url)
            .await
            .unwrap();
        db::migrate(&pool).await.unwrap();
        validate_upload_capacity_policy(
            &pool,
            TEST_UPLOAD_PENDING_LIMIT,
            TEST_UPLOAD_RETAINED_FILES_LIMIT,
            TEST_UPLOAD_RETAINED_BYTES_LIMIT,
        )
        .await
        .unwrap();

        let baseline = reconcile_upload_capacity_ledger(&pool).await.unwrap();
        assert_eq!(baseline.mismatch_count(), 0);
        let retained_files: i64 = sqlx::query_scalar(
            "UPDATE upload_storage_capacity_ledger
                SET retained_files=retained_files+1
              WHERE singleton
              RETURNING retained_files-1",
        )
        .fetch_one(&pool)
        .await
        .unwrap();

        let drifted = reconcile_upload_capacity_ledger(&pool).await.unwrap();
        sqlx::query(
            "UPDATE upload_storage_capacity_ledger
                SET retained_files=$1
              WHERE singleton",
        )
        .bind(retained_files)
        .execute(&pool)
        .await
        .unwrap();
        assert_eq!(drifted.ledger_retained_files, retained_files + 1);
        assert_eq!(drifted.fact_retained_files, retained_files);
        assert_eq!(drifted.mismatch_count(), 1);
    }

    #[tokio::test]
    #[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
    async fn capacity_authority_audit_detects_trigger_function_acl_and_policy_drift() {
        let url = std::env::var("TEST_DATABASE_URL")
            .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(4)
            .connect(&url)
            .await
            .unwrap();
        db::migrate(&pool).await.unwrap();
        validate_upload_capacity_policy(
            &pool,
            TEST_UPLOAD_PENDING_LIMIT,
            TEST_UPLOAD_RETAINED_FILES_LIMIT,
            TEST_UPLOAD_RETAINED_BYTES_LIMIT,
        )
        .await
        .unwrap();
        let clean = test_capacity_authority(&pool).await;
        assert_eq!(clean.violation_count(), 0);
        assert_eq!(clean.policy_binding_violations, 0);

        let policy_drift = audit_upload_capacity_authority(
            &pool,
            TEST_UPLOAD_PENDING_LIMIT + 1,
            TEST_UPLOAD_RETAINED_FILES_LIMIT,
            TEST_UPLOAD_RETAINED_BYTES_LIMIT,
        )
        .await
        .unwrap();
        assert_eq!(policy_drift.policy_binding_violations, 1);
        assert_eq!(policy_drift.violation_count(), 1);

        sqlx::query(
            "ALTER TABLE upload_storage_jobs
             DISABLE TRIGGER upload_job_capacity_insert",
        )
        .execute(&pool)
        .await
        .unwrap();
        let disabled = test_capacity_authority(&pool).await;
        sqlx::query(
            "ALTER TABLE upload_storage_jobs
             ENABLE TRIGGER upload_job_capacity_insert",
        )
        .execute(&pool)
        .await
        .unwrap();
        assert!(disabled.trigger_authority_violations > 0);

        sqlx::query("GRANT EXECUTE ON FUNCTION account_upload_storage_job_capacity() TO PUBLIC")
            .execute(&pool)
            .await
            .unwrap();
        let public_execute = test_capacity_authority(&pool).await;
        sqlx::query("REVOKE ALL ON FUNCTION account_upload_storage_job_capacity() FROM PUBLIC")
            .execute(&pool)
            .await
            .unwrap();
        assert!(public_execute.function_authority_violations > 0);

        sqlx::query("ALTER FUNCTION account_upload_storage_job_capacity() SECURITY INVOKER")
            .execute(&pool)
            .await
            .unwrap();
        let invoker = test_capacity_authority(&pool).await;
        sqlx::query("ALTER FUNCTION account_upload_storage_job_capacity() SECURITY DEFINER")
            .execute(&pool)
            .await
            .unwrap();
        assert!(invoker.function_authority_violations > 0);

        let mut unbound = pool.begin().await.unwrap();
        sqlx::query(
            "ALTER TABLE upload_storage_capacity_ledger
             DISABLE TRIGGER upload_capacity_policy_guard",
        )
        .execute(&mut *unbound)
        .await
        .unwrap();
        sqlx::query(
            "UPDATE upload_storage_capacity_ledger
                SET configured_pending_limit=NULL,
                    configured_retained_files_limit=NULL,
                    configured_retained_bytes_limit=NULL
              WHERE singleton",
        )
        .execute(&mut *unbound)
        .await
        .unwrap();
        sqlx::query(
            "ALTER TABLE upload_storage_capacity_ledger
             ENABLE TRIGGER upload_capacity_policy_guard",
        )
        .execute(&mut *unbound)
        .await
        .unwrap();
        let object_id = Uuid::new_v4();
        let storage_attempt = Uuid::new_v4();
        let unbound_error = sqlx::query(
            "INSERT INTO upload_storage_jobs(
                 object_id,storage_attempt,action,storage_backend,stage_key,
                 storage_fence,expected_size
             ) VALUES($1,$2,'delete_stage','local',$3,0,1)",
        )
        .bind(object_id)
        .bind(storage_attempt)
        .bind(format!("staging/{object_id}/{storage_attempt}"))
        .execute(&mut *unbound)
        .await
        .unwrap_err();
        unbound.rollback().await.unwrap();
        assert!(matches!(&unbound_error,sqlx::Error::Database(error)
            if error.code().as_deref()==Some("55000")));
        assert!(unbound_error
            .to_string()
            .contains("capacity policy is not fully bound"));

        let mut unbound_cleanup = pool.begin().await.unwrap();
        sqlx::query(
            "ALTER TABLE upload_storage_capacity_ledger
             DISABLE TRIGGER upload_capacity_policy_guard",
        )
        .execute(&mut *unbound_cleanup)
        .await
        .unwrap();
        sqlx::query(
            "UPDATE upload_storage_capacity_ledger
                SET configured_pending_limit=NULL,
                    configured_retained_files_limit=NULL,
                    configured_retained_bytes_limit=NULL
              WHERE singleton",
        )
        .execute(&mut *unbound_cleanup)
        .await
        .unwrap();
        sqlx::query(
            "ALTER TABLE upload_storage_capacity_ledger
             ENABLE TRIGGER upload_capacity_policy_guard",
        )
        .execute(&mut *unbound_cleanup)
        .await
        .unwrap();
        let cleanup_id = Uuid::new_v4();
        let unbound_cleanup_error = sqlx::query(
            "INSERT INTO upload_cleanup_queue(
                 object_id,storage_backend,object_key,expected_size,storage_fence
             ) VALUES($1,'local',$2,1,0)",
        )
        .bind(cleanup_id)
        .bind(cleanup_id.to_string())
        .execute(&mut *unbound_cleanup)
        .await
        .unwrap_err();
        unbound_cleanup.rollback().await.unwrap();
        assert!(matches!(&unbound_cleanup_error,sqlx::Error::Database(error)
            if error.code().as_deref()==Some("55000")));
        assert!(unbound_cleanup_error
            .to_string()
            .contains("capacity policy is not fully bound"));
        assert_eq!(test_capacity_authority(&pool).await.violation_count(), 0);
    }

    #[tokio::test]
    #[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
    async fn capacity_reconciliation_detects_rows_written_while_trigger_was_bypassed() {
        let url = std::env::var("TEST_DATABASE_URL")
            .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(4)
            .connect(&url)
            .await
            .unwrap();
        db::migrate(&pool).await.unwrap();
        validate_upload_capacity_policy(
            &pool,
            TEST_UPLOAD_PENDING_LIMIT,
            TEST_UPLOAD_RETAINED_FILES_LIMIT,
            TEST_UPLOAD_RETAINED_BYTES_LIMIT,
        )
        .await
        .unwrap();
        let before = reconcile_upload_capacity_ledger(&pool).await.unwrap();
        assert_eq!(before.mismatch_count(), 0);

        let object_id = Uuid::new_v4();
        let storage_attempt = Uuid::new_v4();
        let mut bypass = pool.begin().await.unwrap();
        sqlx::query(
            "ALTER TABLE upload_storage_jobs
             DISABLE TRIGGER upload_job_capacity_insert",
        )
        .execute(&mut *bypass)
        .await
        .unwrap();
        let job_id: i64 = sqlx::query_scalar(
            "INSERT INTO upload_storage_jobs(
                 object_id,storage_attempt,action,storage_backend,stage_key,
                 storage_fence,expected_size
             ) VALUES($1,$2,'delete_stage','local',$3,0,1)
             RETURNING id",
        )
        .bind(object_id)
        .bind(storage_attempt)
        .bind(format!("staging/{object_id}/{storage_attempt}"))
        .fetch_one(&mut *bypass)
        .await
        .unwrap();
        sqlx::query(
            "ALTER TABLE upload_storage_jobs
             ENABLE TRIGGER upload_job_capacity_insert",
        )
        .execute(&mut *bypass)
        .await
        .unwrap();
        bypass.commit().await.unwrap();

        let drifted = reconcile_upload_capacity_ledger(&pool).await.unwrap();
        let mut cleanup = pool.begin().await.unwrap();
        sqlx::query(
            "ALTER TABLE upload_storage_jobs
             DISABLE TRIGGER upload_job_capacity_delete",
        )
        .execute(&mut *cleanup)
        .await
        .unwrap();
        sqlx::query("DELETE FROM upload_storage_jobs WHERE id=$1")
            .bind(job_id)
            .execute(&mut *cleanup)
            .await
            .unwrap();
        sqlx::query(
            "ALTER TABLE upload_storage_jobs
             ENABLE TRIGGER upload_job_capacity_delete",
        )
        .execute(&mut *cleanup)
        .await
        .unwrap();
        cleanup.commit().await.unwrap();

        assert!(drifted.fact_pending_jobs > drifted.ledger_pending_jobs);
        assert!(drifted.fact_storage_jobs_pending > drifted.ledger_storage_jobs_pending);
        assert!(drifted.fact_recovery_retained_files > drifted.ledger_recovery_retained_files);
        assert!(drifted.mismatch_count() >= 4);
        assert_eq!(
            reconcile_upload_capacity_ledger(&pool)
                .await
                .unwrap()
                .mismatch_count(),
            0
        );
    }

    #[test]
    fn cleanup_debt_converts_once_and_survives_every_slot_lifecycle() {
        #[derive(Default, Debug, Eq, PartialEq)]
        struct Ledger {
            pending: u64,
            debt: u64,
        }
        fn locator_first_materializes(ledger: &mut Ledger, reserved: &mut bool) {
            if !*reserved {
                ledger.debt += 1;
                *reserved = true;
            }
        }
        fn enqueue_cleanup(ledger: &mut Ledger, reserved: &mut bool, inserted: bool) {
            if !inserted {
                return;
            }
            ledger.pending += 1;
            if *reserved {
                ledger.debt -= 1;
                *reserved = false;
            }
        }
        fn finish_cleanup(ledger: &mut Ledger) {
            ledger.pending -= 1;
        }

        for _state in [
            "writing",
            "committed",
            "legacy_committed",
            "retention",
            "account-delete",
        ] {
            let mut ledger = Ledger::default();
            let mut reserved = false;
            locator_first_materializes(&mut ledger, &mut reserved);
            locator_first_materializes(&mut ledger, &mut reserved); // replay
            assert_eq!(
                ledger,
                Ledger {
                    pending: 0,
                    debt: 1
                }
            );
            enqueue_cleanup(&mut ledger, &mut reserved, true);
            enqueue_cleanup(&mut ledger, &mut reserved, false); // ON CONFLICT replay
            assert_eq!(
                ledger,
                Ledger {
                    pending: 1,
                    debt: 0
                }
            );
            finish_cleanup(&mut ledger);
            assert_eq!(ledger, Ledger::default());
        }

        // A migration orphan already has a pending projection and therefore
        // backfills no slot debt.
        let orphan = Ledger {
            pending: 1,
            debt: 0,
        };
        assert_eq!(orphan.pending + orphan.debt, 1);

        // Migration backfill reserves one cleanup debt for a legacy committed
        // locator. Exact cleanup admission converts it and confirmed removal
        // releases the sole pending projection.
        let mut legacy_committed = Ledger {
            pending: 0,
            debt: 1,
        };
        let mut legacy_reserved = true;
        enqueue_cleanup(&mut legacy_committed, &mut legacy_reserved, true);
        assert_eq!(
            legacy_committed,
            Ledger {
                pending: 1,
                debt: 0
            }
        );
        finish_cleanup(&mut legacy_committed);
        assert_eq!(legacy_committed, Ledger::default());

        // Staged/promoting deletion is represented by one cleanup row even
        // when local storage has distinct stage/object locators. S3's equal
        // stage/object key is likewise owned and released exactly once.
        for (backend, stage_equals_object) in [("local", false), ("s3", true)] {
            let mut ledger = Ledger {
                pending: 0,
                debt: 1,
            };
            let mut reserved = true;
            enqueue_cleanup(&mut ledger, &mut reserved, true);
            assert_eq!(
                ledger,
                Ledger {
                    pending: 1,
                    debt: 0
                },
                "{backend}"
            );
            assert_eq!(stage_equals_object, backend == "s3");
            finish_cleanup(&mut ledger);
            assert_eq!(ledger, Ledger::default(), "{backend}");
        }

        // A legacy migration may start above both the requested and absolute
        // ceilings. Debt conversion is net-zero and must remain possible;
        // only fresh work is rejected while deletion monotonically drains.
        let requested = 128_u64;
        let absolute = 100_000_u64;
        let mut legacy = Ledger {
            pending: 100_000,
            debt: 7,
        };
        let mut reserved = true;
        let before = legacy.pending + legacy.debt;
        enqueue_cleanup(&mut legacy, &mut reserved, true);
        assert_eq!(legacy.pending + legacy.debt, before);
        assert!(legacy.pending + legacy.debt > requested);
        assert!(legacy.pending + legacy.debt > absolute);
        while legacy.debt > 0 {
            reserved = true;
            enqueue_cleanup(&mut legacy, &mut reserved, true);
            finish_cleanup(&mut legacy);
        }
        while legacy.pending > 0 {
            finish_cleanup(&mut legacy);
        }
        assert_eq!(legacy, Ledger::default());
    }

    #[test]
    fn shared_storage_migration_contains_cleanup_debt_atomicity_guards() {
        let sql = include_str!("../../migrations/0091_shared_upload_storage.sql");
        for required in [
            "storage_cleanup_debt_reserved BOOLEAN NOT NULL DEFAULT FALSE",
            "cleanup_obligation_debt BIGINT NOT NULL CHECK(cleanup_obligation_debt>=0)",
            "legacy_overcommit_draining BOOLEAN NOT NULL DEFAULT FALSE",
            "CREATE TRIGGER upload_slot_cleanup_debt_reserve BEFORE UPDATE ON upload_slots",
            "cleanup_obligation_debt=cleanup_obligation_debt-",
            "AND cleanup_obligation_debt>=CASE WHEN converts_debt THEN 1 ELSE 0 END",
            "pending_jobs+cleanup_obligation_debt+",
            "IF OLD.storage_state='writing'",
            "AND (converts_debt OR (",
            "legacy_overcommit_draining=(pending_jobs-1+cleanup_obligation_debt>",
            "'committed','legacy_committed','deleting'",
        ] {
            assert!(sql.contains(required), "missing debt invariant: {required}");
        }

        // A job insertion converts a reserved obligation in the same ledger
        // UPDATE; there must be no second statement that creates a crash gap.
        let storage_capacity_fn = sql
            .split("CREATE FUNCTION account_upload_storage_job_capacity()")
            .nth(1)
            .and_then(|tail| tail.split("$$ LANGUAGE plpgsql SECURITY DEFINER").next())
            .expect("storage job capacity trigger function");
        assert_eq!(
            storage_capacity_fn
                .matches("cleanup_obligation_debt=cleanup_obligation_debt-")
                .count(),
            1
        );
        assert!(!storage_capacity_fn.contains("TG_TABLE_NAME"));
        let cleanup_capacity_fn = sql
            .split("CREATE FUNCTION account_upload_cleanup_capacity()")
            .nth(1)
            .and_then(|tail| tail.split("$$ LANGUAGE plpgsql SECURITY DEFINER").next())
            .expect("cleanup capacity trigger function");
        assert!(!cleanup_capacity_fn.contains(".action"));
        assert!(!cleanup_capacity_fn.contains("TG_TABLE_NAME"));
        for exact_identity in [
            "storage_backend=NEW.storage_backend",
            "storage_attempt IS NOT DISTINCT FROM NEW.storage_attempt",
            "storage_fence=NEW.storage_fence",
            "storage_stage_version IS NOT DISTINCT FROM NEW.stage_version",
            "storage_object_version IS NOT DISTINCT FROM NEW.object_version",
            "storage_sha256 IS NOT DISTINCT FROM NEW.expected_sha256",
            "COALESCE(storage_size,size)=NEW.expected_size",
        ] {
            assert!(
                sql.contains(exact_identity),
                "missing exact debt authority: {exact_identity}"
            );
        }
        assert_eq!(
            sql.matches("SECURITY DEFINER SET search_path=pg_catalog,pg_temp")
                .count(),
            3
        );
        let lowercase_sql = sql.to_ascii_lowercase();
        for invalid_alias in ["pg_catalog.bigint", "pg_catalog.boolean"] {
            assert!(
                !lowercase_sql.contains(invalid_alias),
                "schema-qualified PostgreSQL aliases do not resolve through pg_type: {invalid_alias}"
            );
        }
        assert_eq!(lowercase_sql.matches("pg_catalog.int8").count(), 1);
        assert_eq!(lowercase_sql.matches("pg_catalog.bool").count(), 2);
        assert!(!sql.contains("SECURITY DEFINER SET search_path=pg_catalog,public"));
        assert!(!sql.contains("SET search_path FROM CURRENT"));
        assert!(!lowercase_sql.contains("public."));
        assert!(sql.contains("migration_schema pg_catalog.text := pg_catalog.current_schema()"));
        assert_eq!(
            sql.matches("SET search_path TO pg_catalog, %I, pg_temp'")
                .count(),
            3
        );
        for secured_function in [
            "offline_upgrade_upload_storage_authority_v1_to_v2(",
            "account_upload_storage_job_capacity()",
            "account_upload_cleanup_capacity()",
        ] {
            assert!(
                sql.contains(&format!("ALTER FUNCTION %I.{secured_function}")),
                "missing fixed schema binding for {secured_function}"
            );
        }
        for rejected_schema in [
            "'pg_catalog','information_schema'",
            "LIKE 'pg_temp_%'",
            "LIKE 'pg_toast_temp_%'",
        ] {
            assert!(sql.contains(rejected_schema));
        }
        for prerequisite in [
            "'upload_slots'",
            "'upload_cleanup_queue'",
            "'upload_cleanup_queue_order_idx'",
        ] {
            assert!(
                sql.contains(&format!(
                    "pg_catalog.to_regclass(pg_catalog.format('%I.%I',target_schema,{prerequisite}))"
                )),
                "migration schema guard is missing {prerequisite}"
            );
        }
        assert!(storage_capacity_fn.contains("UPDATE upload_storage_capacity_ledger"));
        assert!(cleanup_capacity_fn.contains("UPDATE upload_storage_capacity_ledger"));
        assert!(sql.contains(
            "REVOKE INSERT,UPDATE,DELETE ON upload_storage_jobs,upload_cleanup_queue FROM PUBLIC"
        ));

        let authority_position = sql
            .find("CREATE FUNCTION offline_upgrade_upload_storage_authority_v1_to_v2(")
            .expect("offline upload authority function");
        for relation in [
            "CREATE TABLE upload_storage_jobs (",
            "ALTER TABLE upload_cleanup_queue ADD CONSTRAINT upload_cleanup_queue_state_check",
        ] {
            assert!(
                sql.find(relation).expect("offline authority dependency") < authority_position,
                "offline authority function was created before dependency: {relation}"
            );
        }
        let fixed_path_position = sql
            .find("$northstar_upload_function_paths$;")
            .expect("completed SECURITY DEFINER path binding");
        for trigger in [
            "CREATE TRIGGER upload_job_capacity_insert",
            "CREATE TRIGGER upload_job_capacity_delete",
            "CREATE TRIGGER upload_cleanup_capacity_insert",
            "CREATE TRIGGER upload_cleanup_capacity_delete",
        ] {
            assert!(
                sql.find(trigger).expect("capacity trigger") > fixed_path_position,
                "capacity trigger was attached before its function had a fixed schema: {trigger}"
            );
        }

        let cascade_fn = sql
            .split("CREATE FUNCTION queue_upload_storage_delete()")
            .nth(1)
            .and_then(|tail| tail.split("$$ LANGUAGE plpgsql;").next())
            .expect("cascade cleanup trigger function");
        assert!(cascade_fn.contains("IF OLD.storage_state='writing'"));
        assert_eq!(
            cascade_fn
                .matches("INSERT INTO upload_storage_jobs")
                .count(),
            1
        );
        assert_eq!(
            cascade_fn
                .matches("INSERT INTO upload_cleanup_queue")
                .count(),
            1
        );
        assert!(cascade_fn.contains("RETURN OLD;"));
    }

    #[test]
    fn upload_cascade_capacity_requires_explicit_immutable_provenance() {
        let migration = include_str!("../../migrations/0105_upload_cascade_cleanup_capacity.sql");
        for required in [
            "ADD COLUMN slot_delete_projection pg_catalog.bool NOT NULL DEFAULT FALSE",
            "ADD COLUMN recovery_retained_files pg_catalog.int8 NOT NULL DEFAULT 0",
            "ADD COLUMN recovery_retained_bytes pg_catalog.int8 NOT NULL DEFAULT 0",
            "ADD COLUMN configured_retained_files_limit pg_catalog.int8",
            "ADD COLUMN configured_retained_bytes_limit pg_catalog.int8",
            "ADD COLUMN recovery_overcommit_draining pg_catalog.bool NOT NULL DEFAULT FALSE",
            "ALTER TABLE upload_storage_jobs ALTER COLUMN expected_size SET NOT NULL",
            "matching_triggers<>1",
            "trigger_row.tgname='upload_storage_delete_queue'",
            "function_row.proname='queue_upload_storage_delete'",
            "trigger_row.tgenabled IN ('O','A')",
            "trigger_row.tgqual IS NULL",
            "trigger_row.tgtype::pg_catalog.int4=11",
            "'upload_storage_job_identity_guard'",
            "'upload_cleanup_identity_guard'",
            "'upload_capacity_policy_guard'",
            "must have one exact attachment in the installation schema",
            "must have exactly one INSERT and one DELETE attachment",
            "ON CONFLICT(object_id) DO NOTHING",
            "IF OLD.storage_cleanup_debt_reserved THEN",
            "NEW.slot_delete_projection IS DISTINCT FROM OLD.slot_delete_projection",
            "IF pg_catalog.pg_trigger_depth()<=1 THEN",
            "IF NOT converts_debt THEN",
            "IF converts_debt AND NOT NEW.slot_delete_projection THEN",
            "recovery_retained_files=recovery_retained_files+1",
            "recovery_retained_files=recovery_retained_files+locator_units",
            "recovery_retained_files=recovery_retained_files-1",
            "recovery_retained_files=recovery_retained_files-locator_units",
            "hand ownership back to",
            "requested_retained_files_limit pg_catalog.int8",
            "requested_retained_bytes_limit pg_catalog.int8",
            "upload retained-file and retained-byte limits must also be bound",
            "upload storage capacity policy is not fully bound",
            "COALESCE(OLD.storage_object_version,OLD.storage_stage_version)",
            "SECURITY DEFINER",
            "SET search_path TO pg_catalog, %I, pg_temp",
            "REVOKE ALL ON FUNCTION %I.%I() FROM PUBLIC",
            "pg_catalog.count(*)=11",
            "'reserve_upload_cleanup_debt'",
        ] {
            assert!(
                migration.contains(required),
                "missing cascade-capacity invariant: {required}"
            );
        }
        assert_eq!(
            migration
                .matches("ADD COLUMN slot_delete_projection")
                .count(),
            1
        );
        assert_eq!(
            migration
                .matches("NEW.slot_delete_projection IS DISTINCT FROM OLD.slot_delete_projection")
                .count(),
            1
        );
        assert_eq!(
            migration
                .matches("IF pg_catalog.pg_trigger_depth()<=1 THEN")
                .count(),
            1
        );
        let delete_trigger = migration
            .split("CREATE OR REPLACE FUNCTION queue_upload_storage_delete()")
            .nth(1)
            .and_then(|tail| tail.split("$$ LANGUAGE plpgsql;").next())
            .expect("replacement upload delete trigger");
        assert!(delete_trigger.contains("TRUE"));
        assert!(!delete_trigger.contains("INSERT INTO upload_storage_jobs"));
        assert!(!delete_trigger.contains("DO UPDATE SET"));
        assert_eq!(
            delete_trigger
                .matches("GET DIAGNOSTICS inserted_count=ROW_COUNT")
                .count(),
            1
        );
        assert_eq!(delete_trigger.matches("existing upload ").count(), 1);
        assert!(delete_trigger.contains("queue.storage_fence=OLD.storage_fence"));
        assert_eq!(
            migration
                .matches("RAISE EXCEPTION 'upload storage capacity policy is not fully bound'")
                .count(),
            3
        );

        let storage_capacity = migration
            .split("CREATE OR REPLACE FUNCTION account_upload_storage_job_capacity()")
            .nth(1)
            .and_then(|tail| tail.split("$$ LANGUAGE plpgsql;").next())
            .expect("replacement storage-job capacity trigger");
        assert!(!storage_capacity.contains("slot_delete_projection"));
        assert!(storage_capacity.contains("IF NOT policy_bound THEN"));
        assert!(!storage_capacity.contains("AND configured_pending_limit IS NOT NULL"));
        let cleanup_capacity = migration
            .split("CREATE OR REPLACE FUNCTION account_upload_cleanup_capacity()")
            .nth(1)
            .and_then(|tail| tail.split("$$ LANGUAGE plpgsql;").next())
            .expect("replacement cleanup capacity trigger");
        assert!(cleanup_capacity.contains("locator_units"));
        assert!(cleanup_capacity.contains("IF NOT policy_bound THEN"));
        assert!(!cleanup_capacity.contains("AND configured_pending_limit IS NOT NULL"));

        // Deletion has exactly one queue authority. Neither application path
        // may race it by pre-inserting a second cleanup projection.
        for source in [include_str!("users.rs"), include_str!("../pie.rs")] {
            assert!(!source.contains("INSERT INTO upload_cleanup_queue"));
        }
        let account_delete = include_str!("users.rs")
            .split("async fn delete_user_with_roster_inner(")
            .nth(1)
            .and_then(|tail| {
                tail.split("pub(super) async fn delete_user_with_roster_locked_in_transaction(")
                    .next()
            })
            .expect("self-service account deletion implementation");
        let capacity_lock = account_delete
            .find("SELECT northstar_upload_capacity_lock()")
            .expect("account deletion capacity lock");
        let mutation_timeout = account_delete
            .find("SET LOCAL lock_timeout='2s'")
            .expect("account deletion post-admission mutation timeout");
        assert!(
            !account_delete.contains("SET LOCAL lock_timeout='50ms'")
                && capacity_lock < mutation_timeout,
            "account deletion must use SQL-native NOWAIT capacity admission before its normal mutation bound"
        );
        let pie = include_str!("../pie.rs");
        let capacity_lock = pie
            .find("SELECT northstar_upload_capacity_lock()")
            .expect("PIE replacement capacity lock");
        let domain_lock = pie
            .find("pg_advisory_xact_lock(hashtextextended($1, 227))")
            .expect("PIE domain lock");
        let user_lock = pie
            .find("SELECT id,is_admin FROM users WHERE username=$1 FOR UPDATE")
            .expect("PIE user lock");
        assert!(
            !pie.contains("SET LOCAL lock_timeout='50ms'")
                && capacity_lock < domain_lock
                && domain_lock < user_lock,
            "PIE must use SQL-native NOWAIT admission without shortening replacement work"
        );

        let upload_source = include_str!("upload.rs");
        let authority = include_str!("../../migrations/0113_upload_authority_capabilities.sql");
        for capability in [
            "northstar_upload_reserve_slot(",
            "northstar_upload_claim_slot(",
            "northstar_upload_record_stage(",
            "northstar_upload_complete_promotion(",
            "northstar_upload_admit_expired_cleanup(",
            "northstar_upload_delete_owned(",
        ] {
            assert!(
                authority.contains(&format!("CREATE FUNCTION {capability}")),
                "missing owner-held upload capability: {capability}"
            );
        }
        for invariant in [
            "ON CONFLICT(object_id,storage_attempt,action) DO NOTHING",
            "ON CONFLICT(object_id) DO NOTHING",
            "existing upload promotion projection has different identity",
            "existing upload cleanup projection differs or retained debt",
            "REVOKE ALL ON TABLE upload_storage_authority",
        ] {
            assert!(
                authority.contains(invariant),
                "missing upload invariant: {invariant}"
            );
        }
        // `upload_slots.content_type` is VARCHAR(255), while the public
        // capabilities intentionally expose TEXT. PL/pgSQL RETURN QUERY does
        // not apply that conversion implicitly, so every projection must keep
        // an explicit cast or the first PUT fails at runtime.
        assert_eq!(
            authority
                .matches("slot_row.content_type::pg_catalog.text")
                .count(),
            2,
            "upload claim replay/acquire projections must cast VARCHAR to TEXT"
        );
        assert!(
            authority.contains("slot.content_type::pg_catalog.text"),
            "public upload-file projection must cast VARCHAR to TEXT"
        );
        for (function_name, terminator) in [
            (
                "northstar_upload_confirm_cleanup_absence",
                "$northstar_upload_confirm_cleanup_absence$;",
            ),
            (
                "northstar_upload_confirm_stage_absence",
                "$northstar_upload_confirm_stage_absence$;",
            ),
        ] {
            let body = authority
                .split(&format!("CREATE FUNCTION {function_name}("))
                .nth(1)
                .and_then(|tail| tail.split(terminator).next())
                .expect("absence-fence capability");
            assert_eq!(
                body.matches("attempts=GREATEST(attempts-1,0)").count(),
                1,
                "a successful quiet-window observation must preserve retry capacity"
            );
        }
        let authorized_delete = upload_source
            .split("pub async fn queue_user_upload_delete_authorized(")
            .nth(1)
            .and_then(|tail| tail.split("#[cfg(test)]").next())
            .expect("authorized upload-delete implementation");
        let input_validation = authorized_delete
            .find("presented_session.len() != 64")
            .expect("authorized upload-delete bearer validation");
        let session_hash = authorized_delete
            .find("crate::auth::token_hash(presented_session)")
            .expect("authorized upload-delete bearer hashing");
        let capability = authorized_delete
            .find("northstar_upload_delete_owned")
            .expect("authorized upload-delete typed capability");
        assert!(input_validation < capability && capability < session_hash);
    }

    #[test]
    fn upload_capability_lock_scope_matches_cleanup_debt_invariant() {
        let source = include_str!("upload.rs");
        let authority = include_str!("../../migrations/0113_upload_authority_capabilities.sql");
        let nowait = include_str!("../../migrations/0131_upload_capacity_nowait.sql");
        let trigger = nowait
            .split("CREATE OR REPLACE FUNCTION reserve_upload_cleanup_debt()")
            .nth(1)
            .and_then(|tail| {
                tail.split("$northstar_reserve_upload_cleanup_debt$;")
                    .next()
            })
            .expect("cleanup-debt trigger definition");
        for condition in [
            "NOT OLD.storage_cleanup_debt_reserved",
            "(NEW.storage_object_key IS NOT NULL OR NEW.storage_stage_key IS NOT NULL)",
            "NOT EXISTS(",
            "PERFORM northstar_upload_require_capacity_lock()",
        ] {
            assert!(
                trigger.contains(condition),
                "cleanup-debt trigger must retain its precise admission condition: {condition}"
            );
        }
        let capacity_primitive = nowait
            .split("CREATE FUNCTION northstar_upload_require_capacity_lock()")
            .nth(1)
            .and_then(|tail| {
                tail.split("$northstar_upload_require_capacity_lock$;")
                    .next()
            })
            .expect("private SQL-native capacity primitive");
        assert!(capacity_primitive.contains("FOR UPDATE NOWAIT"));
        assert!(capacity_primitive.contains("ERRCODE='55000'"));
        assert!(nowait.contains("CREATE FUNCTION guard_upload_capacity_nowait()"));
        for trigger_name in [
            "northstar_upload_capacity_nowait_slots_insert_delete",
            "northstar_upload_capacity_nowait_slot_locator_update",
            "northstar_upload_capacity_nowait_storage_job_insert_delete",
            "northstar_upload_capacity_nowait_cleanup_insert_delete",
        ] {
            assert!(
                nowait.contains(&format!("CREATE TRIGGER {trigger_name}")),
                "implicit capacity mutator must take the NOWAIT guard first: {trigger_name}"
            );
        }

        let claim_capability = authority
            .split("CREATE FUNCTION northstar_upload_claim_slot(")
            .nth(1)
            .and_then(|tail| tail.split("$northstar_upload_claim_slot$;").next())
            .expect("claim capability definition");
        let capacity_lock = claim_capability
            .find("FROM upload_storage_capacity_ledger")
            .expect("claim capability capacity lock");
        let first_debt_transition = claim_capability
            .find("SET uploading=TRUE,claim_token=new_claim")
            .expect("claim capability writes new attempt locators");
        assert!(
            capacity_lock < first_debt_transition
                && claim_capability.contains("storage_stage_key=new_stage_key")
                && claim_capability.contains("storage_object_key=new_object_key"),
            "only claim may introduce new locators, and it must acquire capacity first"
        );

        // Reservation and claim have no Rust lock-timeout wrapper. Their SQL
        // contracts preserve `false` and `in_progress` for both ledger and
        // later user/slot contention.
        for (name, next) in [
            (
                "create_upload_slot_bounded",
                "pub async fn validate_upload_storage_backend(",
            ),
            ("claim_upload_slot", "pub async fn renew_upload_claim("),
        ] {
            let body = source
                .split(&format!("pub async fn {name}("))
                .nth(1)
                .and_then(|tail| tail.split(next).next())
                .unwrap_or_else(|| panic!("{name} implementation"));
            assert!(
                !body.contains("lock_timeout") && !body.contains("northstar_upload_capacity_lock"),
                "{name} must rely exclusively on its typed SQL NOWAIT capability"
            );
        }

        let reserve = nowait
            .split("CREATE OR REPLACE FUNCTION northstar_upload_reserve_slot(")
            .nth(1)
            .and_then(|tail| tail.split("$northstar_upload_reserve_slot$;").next())
            .expect("replacement reserve capability");
        let reserve_ledger = reserve
            .find("FROM upload_storage_capacity_ledger\n         WHERE singleton FOR UPDATE NOWAIT")
            .expect("reserve capacity acquisition");
        let reserve_owner = reserve
            .find("users WHERE id=requested_user_id FOR UPDATE NOWAIT")
            .expect("reserve owner acquisition");
        let reserve_handler = reserve
            .find("WHEN lock_not_available THEN")
            .expect("reserve subtransaction contention handler");
        assert!(
            reserve_ledger < reserve_owner && reserve_owner < reserve_handler,
            "reserve must place ledger and owner NOWAIT acquisitions in one rollback-capable subtransaction"
        );
        assert!(
            reserve.contains("northstar_upload_reserve_slot_not_admitted")
                && reserve.contains("WHEN SQLSTATE 'P0001' THEN")
                && reserve.contains("GET STACKED DIAGNOSTICS caught_message = MESSAGE_TEXT"),
            "typed false outcomes must abort the capacity-acquiring subtransaction rather than retain its ledger lock"
        );
        let claim = nowait
            .split("CREATE OR REPLACE FUNCTION northstar_upload_claim_slot(")
            .nth(1)
            .and_then(|tail| tail.split("$northstar_upload_claim_slot$;").next())
            .expect("replacement claim capability");
        let claim_ledger = claim
            .find("FROM upload_storage_capacity_ledger\n       WHERE singleton FOR UPDATE NOWAIT")
            .expect("claim capacity acquisition");
        let claim_ledger_lock = claim[claim_ledger..]
            .find("FOR UPDATE NOWAIT;")
            .map(|offset| claim_ledger + offset)
            .expect("claim capacity lock clause");
        let claim_slot = claim[claim_ledger_lock + "FOR UPDATE NOWAIT;".len()..]
            .find("FOR UPDATE NOWAIT;")
            .map(|offset| claim_ledger_lock + "FOR UPDATE NOWAIT;".len() + offset)
            .expect("claim target-slot acquisition");
        let claim_handler = claim
            .find("WHEN lock_not_available THEN")
            .expect("claim subtransaction contention handler");
        assert!(
            claim_ledger < claim_ledger_lock
                && claim_ledger_lock < claim_slot
                && claim_slot < claim_handler,
            "claim must put ledger and slot NOWAIT acquisitions in one rollback-capable subtransaction"
        );
        assert!(
            claim.contains("northstar_upload_claim_slot_not_admitted")
                && claim.contains("WHEN SQLSTATE 'P0001' THEN")
                && claim.contains("RETURN NEXT;\n        RETURN;"),
            "typed claim outcomes must be emitted after rolling back the capacity-acquiring subtransaction"
        );

        // These state-only paths run only after claim established debt (or
        // while an exact same-slot cleanup projection exists).  They must stay
        // independent of unrelated capacity work.
        for (name, next) in [
            ("renew_upload_claim", "pub async fn release_upload_claim("),
            (
                "begin_upload_promotion",
                "pub async fn claim_upload_promotion_job(",
            ),
            ("record_upload_replay", "pub async fn uploaded_file("),
            (
                "claim_upload_scrub_jobs",
                "pub async fn complete_upload_scrub(",
            ),
            ("finish_upload_scrub", "#[cfg(test)]"),
        ] {
            let prefix = if name == "finish_upload_scrub" {
                "async fn"
            } else {
                "pub async fn"
            };
            let body = source
                .split(&format!("{prefix} {name}("))
                .nth(1)
                .and_then(|tail| tail.split(next).next())
                .unwrap_or_else(|| panic!("{name} implementation"));
            assert!(
                !body.contains("lock_timeout") && !body.contains("northstar_upload_capacity_lock"),
                "healthy {name} must not serialize on the global capacity ledger"
            );
        }

        for (function_name, terminator, proof) in [
            (
                "northstar_upload_renew_claim",
                "$northstar_upload_renew_claim$;",
                "storage_cleanup_debt_reserved",
            ),
            (
                "northstar_upload_begin_promotion",
                "$northstar_upload_begin_promotion$;",
                "storage_state IN ('staged','promoting')",
            ),
            (
                "northstar_upload_record_replay",
                "$northstar_upload_record_replay$;",
                "AND uploaded",
            ),
            (
                "northstar_upload_claim_scrub",
                "$northstar_upload_claim_scrub$;",
                "storage_state='committed'",
            ),
            (
                "northstar_upload_finish_scrub",
                "$northstar_upload_finish_scrub$;",
                "storage_scrub_claim_token=requested_claim",
            ),
        ] {
            let body = authority
                .split(&format!("CREATE FUNCTION {function_name}("))
                .nth(1)
                .and_then(|tail| tail.split(terminator).next())
                .unwrap_or_else(|| panic!("{function_name} definition"));
            assert!(
                body.contains(proof),
                "{function_name} must retain its state fence proving no new cleanup debt"
            );
        }

        for (name, next, capability) in [
            (
                "release_upload_claim",
                "/// Used by startup recovery",
                "northstar_upload_release_claim",
            ),
            (
                "record_upload_stage",
                "pub async fn begin_upload_promotion",
                "northstar_upload_record_stage",
            ),
            (
                "complete_promoted_upload",
                "/// Resolve the only benign",
                "northstar_upload_complete_promotion",
            ),
            (
                "retire_upload_promotion_for_cleanup",
                "#[cfg(test)]",
                "northstar_upload_retire_promotion_for_cleanup",
            ),
            (
                "cleanup_expired_upload_slots",
                "pub async fn queued_upload_cleanup",
                "northstar_upload_admit_expired_cleanup",
            ),
            (
                "complete_queued_upload_cleanup",
                "/// A deletion claimant",
                "northstar_upload_complete_cleanup",
            ),
            (
                "complete_upload_storage_job",
                "pub async fn confirm_upload_stage_absence",
                "northstar_upload_complete_storage_job",
            ),
            (
                "queue_user_upload_delete_authorized",
                "#[cfg(test)]",
                "northstar_upload_delete_owned",
            ),
        ] {
            let body = source
                .split(&format!("pub async fn {name}("))
                .nth(1)
                .and_then(|tail| tail.split(next).next())
                .unwrap_or_else(|| panic!("{name} implementation"));
            assert!(
                !body.contains("lock_timeout"),
                "{name} must rely on SQL-native NOWAIT capacity admission"
            );
            let definition = nowait
                .split(&format!("CREATE OR REPLACE FUNCTION {capability}("))
                .nth(1)
                .unwrap_or_else(|| panic!("{capability} migration definition"));
            assert!(
                definition.contains("PERFORM northstar_upload_require_capacity_lock();"),
                "{capability} must acquire the SQL-native capacity primitive first"
            );
        }
        let cleanup_completion = source
            .split("pub async fn complete_queued_upload_cleanup(")
            .nth(1)
            .and_then(|tail| {
                tail.split("pub async fn upload_cleanup_generation_is_quiescent(")
                    .next()
            })
            .expect("upload cleanup completion implementation");
        assert!(
            cleanup_completion.contains("fetch_one(pool)")
                && !cleanup_completion.contains("lock_timeout"),
            "Run70 cleanup completion must expose SQL-native NOWAIT contention"
        );
        // Inspect the production portion only. The test's own literal
        // assertion names must not make a source-wide containment check
        // self-referential.
        let runtime_source = source
            .split("#[cfg(test)]\nmod tests")
            .next()
            .expect("production upload source before its test module");
        assert!(!runtime_source.contains("begin_bounded_upload_admission"));
        assert!(!runtime_source.contains("finish_retryable_upload_capacity_mutation"));
    }

    #[test]
    fn upload_runtime_health_scans_are_bounded_and_timeout_fail_closed() {
        let migration =
            include_str!("../../migrations/0115_upload_runtime_reconciliation_bounds.sql");
        assert!(!migration.contains("public."));
        assert_eq!(migration.matches("LIMIT 1001").count(), 4);
        for invariant in [
            "CREATE INDEX IF NOT EXISTS upload_storage_jobs_dead_idx",
            "CREATE INDEX IF NOT EXISTS upload_cleanup_queue_recovery_dead_idx",
            "CREATE INDEX IF NOT EXISTS upload_slots_storage_scrub_failures_idx",
            "bounded_dead_letters",
            "bounded_scrub_failures",
            "1001 means at least 1001",
            "routine.proowner=migration_owner",
        ] {
            assert!(
                migration.contains(invariant),
                "missing runtime reconciliation bound: {invariant}"
            );
        }
        for invariant in [
            "REVOKE ALL ON FUNCTION %I.northstar_upload_queue_snapshot() FROM PUBLIC CASCADE",
            "WHERE routine.oid=routine_oid)<>1",
            "privilege.grantee<>routine.proowner",
            "privilege.grantor<>routine.proowner",
            "bounded upload queue snapshot has unsafe owner, language, search_path, or non-owner ACL",
        ] {
            assert!(
                migration.contains(invariant),
                "missing fail-closed runtime snapshot ACL guard: {invariant}"
            );
        }

        let source = include_str!("upload.rs");
        let reconciliation = source
            .split("pub async fn reconcile_upload_capacity_ledger(")
            .nth(1)
            .and_then(|tail| tail.split("/// Return a bounded snapshot").next())
            .expect("exact upload reconciliation implementation");
        for bound in [
            "SET TRANSACTION READ ONLY",
            "SET LOCAL lock_timeout='2s'",
            "SET LOCAL statement_timeout='15s'",
        ] {
            assert!(
                reconciliation.contains(bound),
                "missing exact-scan bound: {bound}"
            );
        }
        let snapshot = source
            .split("pub async fn upload_queue_metrics(")
            .nth(1)
            .and_then(|tail| tail.split("fn upload_queue_metrics_from_row").next())
            .expect("bounded upload metrics implementation");
        for bound in [
            "SET TRANSACTION READ ONLY",
            "SET LOCAL lock_timeout='1s'",
            "SET LOCAL statement_timeout='2s'",
        ] {
            assert!(
                snapshot.contains(bound),
                "missing health-scan bound: {bound}"
            );
        }
        let worker = include_str!("../upload_worker.rs");
        assert!(worker.contains("snapshot.dead_letter_jobs_capped"));
        assert!(worker.contains("snapshot.scrub_failures_capped"));
    }

    async fn insert_user(pool: &PgPool) -> Uuid {
        let id = Uuid::new_v4();
        let username = format!("upload-{}", &id.simple().to_string()[..16]);
        sqlx::query(
            "INSERT INTO users (id, username, password_hash, is_admin)
             VALUES ($1, $2, 'test-only', FALSE)",
        )
        .bind(id)
        .bind(username)
        .execute(pool)
        .await
        .unwrap();
        id
    }

    #[tokio::test]
    #[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
    async fn upload_claim_is_atomic_and_cleanup_is_retryable() {
        let url = std::env::var("TEST_DATABASE_URL")
            .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(16)
            .connect(&url)
            .await
            .unwrap();
        db::migrate(&pool).await.unwrap();
        // Production binds this durable deployment authority in AppState
        // before opening any listener. Mirror that startup boundary here: an
        // unbound policy intentionally rejects every new cleanup obligation.
        validate_upload_capacity_policy(
            &pool,
            TEST_UPLOAD_PENDING_LIMIT,
            TEST_UPLOAD_RETAINED_FILES_LIMIT,
            TEST_UPLOAD_RETAINED_BYTES_LIMIT,
        )
        .await
        .unwrap();

        let user_id = insert_user(&pool).await;
        let token_hash = b"concurrent-test-token-hash".to_vec();
        let slot_id = create_upload_slot(
            &pool,
            UploadReservation {
                user_id,
                filename: "concurrent.bin",
                content_type: "application/octet-stream",
                size: 4,
                token_hash: &token_hash,
                max_files_per_user: 100,
                max_bytes_per_user: 1_000,
                storage_backend: "local",
            },
        )
        .await
        .unwrap()
        .unwrap();
        assert!(matches!(
            claim_upload_slot(&pool, slot_id, b"wrong-token", 90)
                .await
                .unwrap(),
            UploadClaimOutcome::Rejected
        ));

        let competitors = 12;
        let barrier = Arc::new(Barrier::new(competitors + 1));
        let mut tasks = Vec::with_capacity(competitors);
        for _ in 0..competitors {
            let pool = pool.clone();
            let barrier = barrier.clone();
            let token_hash = token_hash.clone();
            tasks.push(tokio::spawn(async move {
                barrier.wait().await;
                match claim_upload_slot(&pool, slot_id, &token_hash, 90)
                    .await
                    .unwrap()
                {
                    UploadClaimOutcome::Acquired(lease) => Some(lease),
                    _ => None,
                }
            }));
        }
        barrier.wait().await;
        let mut winners = Vec::new();
        for task in tasks {
            if let Some(lease) = task.await.unwrap() {
                winners.push(lease);
            }
        }
        assert_eq!(
            winners.len(),
            1,
            "exactly one concurrent PUT may claim a slot"
        );
        assert!(uploaded_file(&pool, slot_id).await.unwrap().is_none());
        let before_forgery: (i64, i64) = sqlx::query_as(
            "SELECT pending_jobs,cleanup_obligation_debt
             FROM upload_storage_capacity_ledger WHERE singleton",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        let forged_stage = format!("staging/{slot_id}/{}", winners[0].claim_token);
        let forged_error = sqlx::query(
            "INSERT INTO upload_cleanup_queue(
                 object_id,storage_backend,object_key,stage_key,storage_attempt,
                 expected_size,storage_fence,slot_delete_projection)
             VALUES($1,'local',$1::text,$3,$2,4,$4,TRUE)",
        )
        .bind(slot_id)
        .bind(winners[0].claim_token)
        .bind(&forged_stage)
        .bind(winners[0].storage_fence)
        .execute(&pool)
        .await
        .unwrap_err();
        assert!(
            matches!(&forged_error,sqlx::Error::Database(error)
                if error.code().as_deref()==Some("42501")),
            "direct writers must not forge slot-delete provenance: {forged_error}"
        );
        let after_forgery: (i64, i64) = sqlx::query_as(
            "SELECT pending_jobs,cleanup_obligation_debt
             FROM upload_storage_capacity_ledger WHERE singleton",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(after_forgery, before_forgery);

        // A mandatory retry-cleanup projection temporarily converts the
        // slot's debt. If cleanup completes before a replacement writer is
        // admitted, the DELETE trigger must hand that obligation back to the
        // still-live writing slot instead of leaving an unaccounted locator.
        sqlx::query(
            "INSERT INTO upload_storage_jobs(
                 object_id,storage_attempt,action,storage_backend,stage_key,
                 storage_fence,expected_size)
             VALUES($1,$2,'delete_stage','local',$3,$4,4)",
        )
        .bind(slot_id)
        .bind(winners[0].claim_token)
        .bind(&forged_stage)
        .bind(winners[0].storage_fence)
        .execute(&pool)
        .await
        .unwrap();
        let converted: (i64, i64, bool) = sqlx::query_as(
            "SELECT ledger.pending_jobs,ledger.cleanup_obligation_debt,
                    slot.storage_cleanup_debt_reserved
               FROM upload_storage_capacity_ledger ledger
               JOIN upload_slots slot ON slot.id=$1
              WHERE ledger.singleton",
        )
        .bind(slot_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(
            (converted.0, converted.1),
            (before_forgery.0 + 1, before_forgery.1 - 1)
        );
        assert!(!converted.2);
        sqlx::query(
            "DELETE FROM upload_storage_jobs
             WHERE object_id=$1 AND storage_attempt=$2 AND action='delete_stage'",
        )
        .bind(slot_id)
        .bind(winners[0].claim_token)
        .execute(&pool)
        .await
        .unwrap();
        let rearmed: (i64, i64, bool) = sqlx::query_as(
            "SELECT ledger.pending_jobs,ledger.cleanup_obligation_debt,
                    slot.storage_cleanup_debt_reserved
               FROM upload_storage_capacity_ledger ledger
               JOIN upload_slots slot ON slot.id=$1
              WHERE ledger.singleton",
        )
        .bind(slot_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!((rearmed.0, rearmed.1), before_forgery);
        assert!(rearmed.2);
        assert!(release_upload_claim(&pool, slot_id, winners[0].claim_token)
            .await
            .unwrap());
        let lease = match claim_upload_slot(&pool, slot_id, &token_hash, 90)
            .await
            .unwrap()
        {
            UploadClaimOutcome::Acquired(lease) => lease,
            other => panic!("unexpected upload claim outcome: {other:?}"),
        };
        let digest = [9_u8; 32];
        assert!(
            complete_upload(&pool, slot_id, lease.claim_token, &digest, 3_600)
                .await
                .unwrap()
        );
        assert!(uploaded_file(&pool, slot_id).await.unwrap().is_some());
        let expiry = sqlx::query(
            "SELECT EXTRACT(EPOCH FROM (put_expires_at-clock_timestamp()))::bigint AS put_seconds,
                    EXTRACT(EPOCH FROM (expires_at-clock_timestamp()))::bigint AS object_seconds
             FROM upload_slots WHERE id=$1",
        )
        .bind(slot_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        let put_seconds: i64 = expiry.get("put_seconds");
        let object_seconds: i64 = expiry.get("object_seconds");
        assert!((295..=300).contains(&put_seconds));
        assert!((3_590..=3_600).contains(&object_seconds));
        assert!(matches!(
            claim_upload_slot(&pool, slot_id, &token_hash, 90)
                .await
                .unwrap(),
            UploadClaimOutcome::Replay { content_sha256, .. } if content_sha256 == digest
        ));
        assert!(!release_upload_claim(&pool, slot_id, lease.claim_token)
            .await
            .unwrap());
        assert!(record_upload_replay(&pool, slot_id, &token_hash, &digest)
            .await
            .unwrap());
        assert!(
            !record_upload_replay(&pool, slot_id, &token_hash, &[8_u8; 32])
                .await
                .unwrap()
        );
        let replay_count: i64 =
            sqlx::query_scalar("SELECT replay_count FROM upload_slots WHERE id=$1")
                .bind(slot_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(replay_count, 1);
        for expected_count in 2..=3_i64 {
            assert!(matches!(
                claim_upload_slot(&pool, slot_id, &token_hash, 90)
                    .await
                    .unwrap(),
                UploadClaimOutcome::Replay { content_sha256, .. } if content_sha256 == digest
            ));
            assert!(record_upload_replay(&pool, slot_id, &token_hash, &digest)
                .await
                .unwrap());
            let count: i64 =
                sqlx::query_scalar("SELECT replay_count FROM upload_slots WHERE id=$1")
                    .bind(slot_id)
                    .fetch_one(&pool)
                    .await
                    .unwrap();
            assert_eq!(count, expected_count);
        }
        assert!(matches!(
            claim_upload_slot(&pool, slot_id, &token_hash, 90)
                .await
                .unwrap(),
            UploadClaimOutcome::Rejected
        ));

        let legacy = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO upload_slots
             (id,user_id,filename,content_type,size,token_hash,expires_at,put_expires_at)
             VALUES($1,$2,'legacy.bin','application/octet-stream',4,$3,
                    clock_timestamp()+INTERVAL '1 hour',
                    clock_timestamp()+INTERVAL '5 minutes')",
        )
        .bind(legacy)
        .bind(user_id)
        .bind(b"legacy-token")
        .execute(&pool)
        .await
        .unwrap();
        // Materialize a schema-valid pre-digest legacy object through UPDATE,
        // so the cleanup-debt trigger reserves its eventual deletion exactly
        // as the 0091 backfill does. It remains unclaimable without a digest.
        sqlx::query(
            "UPDATE upload_slots
             SET uploaded=TRUE,storage_state='legacy_committed',
                 storage_object_key=id::text,storage_size=size
             WHERE id=$1",
        )
        .bind(legacy)
        .execute(&pool)
        .await
        .unwrap();
        assert!(matches!(
            claim_upload_slot(&pool, legacy, b"legacy-token", 90)
                .await
                .unwrap(),
            UploadClaimOutcome::Rejected
        ));

        let exhausted = create_upload_slot(
            &pool,
            UploadReservation {
                user_id,
                filename: "attempts.bin",
                content_type: "application/octet-stream",
                size: 4,
                token_hash: b"attempt-token",
                max_files_per_user: 100,
                max_bytes_per_user: 1_000,
                storage_backend: "local",
            },
        )
        .await
        .unwrap()
        .unwrap();
        for _ in 0..MAX_UPLOAD_ATTEMPTS {
            let lease = match claim_upload_slot(&pool, exhausted, b"attempt-token", 90)
                .await
                .unwrap()
            {
                UploadClaimOutcome::Acquired(lease) => lease,
                other => panic!("unexpected bounded-attempt outcome: {other:?}"),
            };
            assert!(release_upload_claim(&pool, exhausted, lease.claim_token)
                .await
                .unwrap());
        }
        assert!(matches!(
            claim_upload_slot(&pool, exhausted, b"attempt-token", 90)
                .await
                .unwrap(),
            UploadClaimOutcome::Rejected
        ));

        let fenced = create_upload_slot(
            &pool,
            UploadReservation {
                user_id,
                filename: "fenced.bin",
                content_type: "application/octet-stream",
                size: 4,
                token_hash: b"fenced-token",
                max_files_per_user: 100,
                max_bytes_per_user: 1_000,
                storage_backend: "local",
            },
        )
        .await
        .unwrap()
        .unwrap();
        let stale = match claim_upload_slot(&pool, fenced, b"fenced-token", 90)
            .await
            .unwrap()
        {
            UploadClaimOutcome::Acquired(lease) => lease,
            other => panic!("unexpected first fenced claim: {other:?}"),
        };
        assert!(matches!(
            claim_upload_slot(&pool, fenced, b"fenced-token", 90)
                .await
                .unwrap(),
            UploadClaimOutcome::InProgress { .. }
        ));
        sqlx::query(
            "UPDATE upload_slots SET claim_expires_at=clock_timestamp()-INTERVAL '1 second'
             WHERE id=$1",
        )
        .bind(fenced)
        .execute(&pool)
        .await
        .unwrap();
        let replacement = match claim_upload_slot(&pool, fenced, b"fenced-token", 90)
            .await
            .unwrap()
        {
            UploadClaimOutcome::Acquired(lease) => lease,
            other => panic!("unexpected replacement claim: {other:?}"),
        };
        assert_ne!(stale.claim_token, replacement.claim_token);
        assert_eq!(
            renew_upload_claim(&pool, fenced, stale.claim_token, 90)
                .await
                .unwrap(),
            UploadRenewOutcome::Lost
        );
        assert!(!release_upload_claim(&pool, fenced, stale.claim_token)
            .await
            .unwrap());
        assert!(
            !complete_upload(&pool, fenced, stale.claim_token, &[1_u8; 32], 3_600,)
                .await
                .unwrap()
        );
        assert!(
            complete_upload(&pool, fenced, replacement.claim_token, &[2_u8; 32], 3_600,)
                .await
                .unwrap()
        );

        let authorized_deletable = create_upload_slot(
            &pool,
            UploadReservation {
                user_id,
                filename: "authorized-delete.bin",
                content_type: "application/octet-stream",
                size: 7,
                token_hash: b"authorized-delete-token",
                max_files_per_user: 100,
                max_bytes_per_user: 1_000,
                storage_backend: "local",
            },
        )
        .await
        .unwrap()
        .unwrap();
        let live_session = db::create_api_session(&pool, user_id, 1).await.unwrap();
        assert_eq!(
            queue_user_upload_delete_authorized(
                &pool,
                user_id,
                0,
                &live_session,
                authorized_deletable,
                Uuid::new_v4(),
            )
            .await
            .unwrap(),
            UserUploadDeleteOutcome::Accepted
        );

        let stale_deletable = create_upload_slot(
            &pool,
            UploadReservation {
                user_id,
                filename: "stale-delete.bin",
                content_type: "application/octet-stream",
                size: 7,
                token_hash: b"stale-delete-token",
                max_files_per_user: 100,
                max_bytes_per_user: 1_000,
                storage_backend: "local",
            },
        )
        .await
        .unwrap()
        .unwrap();
        let stale_session = db::create_api_session(&pool, user_id, 1).await.unwrap();
        let mut logout = pool.begin().await.unwrap();
        assert!(
            db::delete_api_session_audited_in_tx(&mut logout, &stale_session, Uuid::new_v4(),)
                .await
                .unwrap()
        );
        logout.commit().await.unwrap();
        assert_eq!(
            queue_user_upload_delete_authorized(
                &pool,
                user_id,
                0,
                &stale_session,
                stale_deletable,
                Uuid::new_v4(),
            )
            .await
            .unwrap(),
            UserUploadDeleteOutcome::Unauthorized
        );
        assert!(sqlx::query("SELECT 1 FROM upload_slots WHERE id=$1")
            .bind(stale_deletable)
            .fetch_optional(&pool)
            .await
            .unwrap()
            .is_some());

        let deletable = create_upload_slot(
            &pool,
            UploadReservation {
                user_id,
                filename: "delete-me.bin",
                content_type: "application/octet-stream",
                size: 7,
                token_hash: b"delete-token",
                max_files_per_user: 100,
                max_bytes_per_user: 1_000,
                storage_backend: "local",
            },
        )
        .await
        .unwrap()
        .unwrap();
        let other_user = insert_user(&pool).await;
        assert!(
            !queue_user_upload_delete(&pool, other_user, deletable, Uuid::new_v4())
                .await
                .unwrap()
        );
        let delete_request = Uuid::new_v4();
        assert!(
            queue_user_upload_delete(&pool, user_id, deletable, delete_request)
                .await
                .unwrap()
        );
        assert!(
            !queue_user_upload_delete(&pool, user_id, deletable, Uuid::new_v4())
                .await
                .unwrap()
        );
        let delete_projection: (i64, i64) = sqlx::query_as(
            "SELECT
                 (SELECT COUNT(*) FROM upload_cleanup_queue WHERE object_id=$1),
                 (SELECT COUNT(*) FROM audit_log
                   WHERE actor_id=$2 AND action='user.upload.delete'
                     AND target=$1::text AND request_id=$3)",
        )
        .bind(deletable)
        .bind(user_id)
        .bind(delete_request)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(delete_projection, (0, 1));
        assert!(sqlx::query("SELECT 1 FROM upload_slots WHERE id=$1")
            .bind(deletable)
            .fetch_optional(&pool)
            .await
            .unwrap()
            .is_none());

        let expired = create_upload_slot(
            &pool,
            UploadReservation {
                user_id,
                filename: "expired.bin",
                content_type: "application/octet-stream",
                size: 1,
                token_hash: b"expired",
                max_files_per_user: 100,
                max_bytes_per_user: 1_000,
                storage_backend: "local",
            },
        )
        .await
        .unwrap()
        .unwrap();
        let active_expired = create_upload_slot(
            &pool,
            UploadReservation {
                user_id,
                filename: "active.bin",
                content_type: "application/octet-stream",
                size: 1,
                token_hash: b"active",
                max_files_per_user: 100,
                max_bytes_per_user: 1_000,
                storage_backend: "local",
            },
        )
        .await
        .unwrap()
        .unwrap();
        let abandoned = create_upload_slot(
            &pool,
            UploadReservation {
                user_id,
                filename: "abandoned.bin",
                content_type: "application/octet-stream",
                size: 1,
                token_hash: b"abandoned",
                max_files_per_user: 100,
                max_bytes_per_user: 1_000,
                storage_backend: "local",
            },
        )
        .await
        .unwrap()
        .unwrap();
        let active_claim = Uuid::new_v4();
        let abandoned_claim = Uuid::new_v4();
        let active_stage = format!("staging/{active_expired}/{active_claim}");
        let active_object = format!("objects/{active_expired}/{active_claim}");
        let abandoned_stage = format!("staging/{abandoned}/{abandoned_claim}");
        let abandoned_object = format!("objects/{abandoned}/{abandoned_claim}");
        sqlx::query(
            "UPDATE upload_slots
             SET expires_at = CASE
                 WHEN id = $1 THEN NOW() - INTERVAL '1 minute'
                 WHEN id = $2 THEN NOW() - INTERVAL '1 minute'
                 WHEN id = $3 THEN NOW() - INTERVAL '10 minutes'
                 ELSE expires_at
             END,
             uploading = id IN ($2, $3),
             claim_token = CASE
                 WHEN id = $2 THEN $4
                 WHEN id = $3 THEN $5
                 ELSE NULL
             END,
             claim_expires_at = CASE
                 WHEN id = $2 THEN clock_timestamp() + INTERVAL '1 minute'
                 WHEN id = $3 THEN clock_timestamp() - INTERVAL '9 minutes'
                 ELSE NULL
             END,
             storage_state = CASE WHEN id IN ($2,$3) THEN 'writing' ELSE 'reserved' END,
             storage_attempt = CASE WHEN id=$2 THEN $4 WHEN id=$3 THEN $5 ELSE NULL END,
             storage_stage_key = CASE WHEN id=$2 THEN $6 WHEN id=$3 THEN $8 ELSE NULL END,
             storage_object_key = CASE WHEN id=$2 THEN $7 WHEN id=$3 THEN $9 ELSE NULL END,
             storage_fence = CASE WHEN id IN ($2,$3) THEN storage_fence+1 ELSE storage_fence END
             WHERE id IN ($1, $2, $3)",
        )
        .bind(expired)
        .bind(active_expired)
        .bind(abandoned)
        .bind(active_claim)
        .bind(abandoned_claim)
        .bind(active_stage)
        .bind(active_object)
        .bind(abandoned_stage)
        .bind(abandoned_object)
        .execute(&pool)
        .await
        .unwrap();
        assert!(matches!(
            claim_upload_slot(&pool, expired, b"expired", 90)
                .await
                .unwrap(),
            UploadClaimOutcome::Rejected
        ));

        let candidates = cleanup_expired_upload_slots(&pool).await.unwrap();
        assert!(candidates.contains(&expired));
        assert!(candidates.contains(&abandoned));
        assert!(!candidates.contains(&active_expired));
        assert!(sqlx::query("SELECT 1 FROM upload_slots WHERE id=$1")
            .bind(expired)
            .fetch_optional(&pool)
            .await
            .unwrap()
            .is_none());
        let abandoned_quiet_period: bool = sqlx::query_scalar(
            "SELECT available_at>clock_timestamp()
             FROM upload_cleanup_queue WHERE object_id=$1",
        )
        .bind(abandoned)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(
            abandoned_quiet_period,
            "an expired in-flight writer keeps a durable delayed tombstone"
        );
        // Advance only this fixture past the external-I/O quiet period. The
        // worker must then be able to claim and complete the same tombstone.
        sqlx::query(
            "UPDATE upload_cleanup_queue SET available_at=clock_timestamp()
             WHERE object_id=$1",
        )
        .bind(abandoned)
        .execute(&pool)
        .await
        .unwrap();
        let cleanup = queued_upload_cleanup(&pool).await.unwrap();
        let abandoned_job = cleanup
            .iter()
            .find(|job| job.object_id == abandoned)
            .expect("abandoned upload has durable cleanup work");
        assert!(complete_queued_upload_cleanup(
            &pool,
            abandoned_job.object_id,
            abandoned_job.claim_token,
        )
        .await
        .unwrap());
        let active_still_exists: bool = sqlx::query("SELECT id FROM upload_slots WHERE id = $1")
            .bind(active_expired)
            .fetch_optional(&pool)
            .await
            .unwrap()
            .is_some();
        assert!(active_still_exists);

        let uploaded_still_exists: bool =
            sqlx::query("SELECT uploaded FROM upload_slots WHERE id = $1")
                .bind(slot_id)
                .fetch_one(&pool)
                .await
                .unwrap()
                .get("uploaded");
        assert!(uploaded_still_exists);

        sqlx::query(
            "UPDATE upload_slots SET expires_at = NOW() - INTERVAL '1 second' WHERE id = $1",
        )
        .bind(slot_id)
        .execute(&pool)
        .await
        .unwrap();
        assert!(uploaded_file(&pool, slot_id).await.unwrap().is_none());
        assert!(cleanup_expired_upload_slots(&pool)
            .await
            .unwrap()
            .contains(&slot_id));
        let cleanup = queued_upload_cleanup(&pool).await.unwrap();
        let uploaded_job = cleanup
            .iter()
            .find(|job| job.object_id == slot_id)
            .expect("uploaded object has durable cleanup work");
        assert!(complete_queued_upload_cleanup(
            &pool,
            uploaded_job.object_id,
            uploaded_job.claim_token,
        )
        .await
        .unwrap());

        let cascade_states: Vec<String> = sqlx::query_scalar(
            "SELECT storage_state FROM upload_slots
             WHERE id=ANY($1) ORDER BY storage_state",
        )
        .bind([active_expired, fenced, legacy])
        .fetch_all(&pool)
        .await
        .unwrap();
        assert_eq!(
            cascade_states,
            ["committed", "legacy_committed", "writing"],
            "account cascade fixture must cover every locator lifecycle"
        );
        let before_rollback: (i64, i64, i64, i64) = sqlx::query_as(
            "SELECT pending_jobs,cleanup_obligation_debt,
                    storage_jobs_pending,cleanup_jobs_pending
             FROM upload_storage_capacity_ledger WHERE singleton",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        let mut rolled_back_delete = pool.begin().await.unwrap();
        sqlx::query("DELETE FROM users WHERE id=$1")
            .bind(user_id)
            .execute(&mut *rolled_back_delete)
            .await
            .unwrap();
        rolled_back_delete.rollback().await.unwrap();
        let after_rollback: (i64, i64, i64, i64) = sqlx::query_as(
            "SELECT pending_jobs,cleanup_obligation_debt,
                    storage_jobs_pending,cleanup_jobs_pending
             FROM upload_storage_capacity_ledger WHERE singleton",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(after_rollback, before_rollback);

        sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(user_id)
            .execute(&pool)
            .await
            .unwrap();
        let cascade_projection: (i64, i64, i64, i64, i64, i64, i64) = sqlx::query_as(
            "SELECT ledger.pending_jobs,ledger.cleanup_obligation_debt,
                    ledger.storage_jobs_pending,ledger.cleanup_jobs_pending,
                    (SELECT COUNT(*) FROM upload_storage_jobs),
                    (SELECT COUNT(*) FROM upload_cleanup_queue),
                    (SELECT COUNT(*) FROM upload_slots WHERE user_id=$1)
             FROM upload_storage_capacity_ledger ledger WHERE singleton",
        )
        .bind(user_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(
            cascade_projection.0,
            cascade_projection.4 + cascade_projection.5
        );
        assert_eq!(cascade_projection.1, 0);
        assert_eq!(cascade_projection.2, cascade_projection.4);
        assert_eq!(cascade_projection.3, cascade_projection.5);
        assert_eq!(cascade_projection.6, 0);
    }

    #[tokio::test]
    #[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
    async fn upload_cascade_converts_reserved_debt_at_the_hard_limit() {
        let url = std::env::var("TEST_DATABASE_URL")
            .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(16)
            .connect(&url)
            .await
            .unwrap();
        db::migrate(&pool).await.unwrap();
        validate_upload_capacity_policy(
            &pool,
            TEST_UPLOAD_PENDING_LIMIT,
            TEST_UPLOAD_RETAINED_FILES_LIMIT,
            TEST_UPLOAD_RETAINED_BYTES_LIMIT,
        )
        .await
        .unwrap();
        let baseline: (i64, i64) = sqlx::query_as(
            "SELECT pending_jobs,cleanup_obligation_debt
             FROM upload_storage_capacity_ledger WHERE singleton",
        )
        .fetch_one(&pool)
        .await
        .unwrap();

        let mut tx = pool.begin().await.unwrap();
        let user_id = Uuid::new_v4();
        let username = format!("upload-cascade-{}", &user_id.simple().to_string()[..12]);
        sqlx::query(
            "INSERT INTO users(id,username,password_hash,is_admin)
             VALUES($1,$2,'test-only',FALSE)",
        )
        .bind(user_id)
        .bind(username)
        .execute(&mut *tx)
        .await
        .unwrap();
        let slot_id = Uuid::new_v4();
        let attempt = Uuid::new_v4();
        let stage_key = format!("staging/{slot_id}/{attempt}");
        sqlx::query(
            "INSERT INTO upload_slots(
                 id,user_id,filename,content_type,size,token_hash,
                 expires_at,put_expires_at)
             VALUES($1,$2,'cascade.bin','application/octet-stream',1,$3,
                    clock_timestamp()+INTERVAL '1 hour',
                    clock_timestamp()+INTERVAL '5 minutes')",
        )
        .bind(slot_id)
        .bind(user_id)
        .bind(b"cascade-token")
        .execute(&mut *tx)
        .await
        .unwrap();
        sqlx::query(
            "UPDATE upload_slots
             SET uploading=TRUE,claim_token=$2,
                 claim_expires_at=clock_timestamp()+INTERVAL '1 minute',
                 storage_state='writing',storage_attempt=$2,
                 storage_stage_key=$3,storage_object_key=id::text,
                 storage_fence=storage_fence+1
             WHERE id=$1",
        )
        .bind(slot_id)
        .bind(attempt)
        .bind(&stage_key)
        .execute(&mut *tx)
        .await
        .unwrap();
        let before_fill: (i64, i64) = sqlx::query_as(
            "SELECT pending_jobs,cleanup_obligation_debt
             FROM upload_storage_capacity_ledger WHERE singleton",
        )
        .fetch_one(&mut *tx)
        .await
        .unwrap();
        assert_eq!(before_fill.1, baseline.1 + 1);
        let fill_count = TEST_UPLOAD_PENDING_LIMIT - before_fill.0 - before_fill.1;
        assert!(
            fill_count > 0,
            "test fixture unexpectedly starts over capacity"
        );
        for _ in 0..fill_count {
            let object_id = Uuid::new_v4();
            let filler_attempt = Uuid::new_v4();
            let filler_stage = format!("staging/{object_id}/{filler_attempt}");
            sqlx::query(
                "INSERT INTO upload_storage_jobs(
                     object_id,storage_attempt,action,storage_backend,
                     stage_key,storage_fence,expected_size)
                 VALUES($1,$2,'delete_stage','local',$3,0,1)",
            )
            .bind(object_id)
            .bind(filler_attempt)
            .bind(filler_stage)
            .execute(&mut *tx)
            .await
            .unwrap();
        }
        let at_limit: (i64, i64) = sqlx::query_as(
            "SELECT pending_jobs,cleanup_obligation_debt
             FROM upload_storage_capacity_ledger WHERE singleton",
        )
        .fetch_one(&mut *tx)
        .await
        .unwrap();
        assert_eq!(at_limit.0 + at_limit.1, TEST_UPLOAD_PENDING_LIMIT);

        sqlx::query("DELETE FROM users WHERE id=$1")
            .bind(user_id)
            .execute(&mut *tx)
            .await
            .unwrap();
        let converted: (i64, i64) = sqlx::query_as(
            "SELECT pending_jobs,cleanup_obligation_debt
             FROM upload_storage_capacity_ledger WHERE singleton",
        )
        .fetch_one(&mut *tx)
        .await
        .unwrap();
        assert_eq!(converted.0, at_limit.0 + 1);
        assert_eq!(converted.1, at_limit.1 - 1);
        assert_eq!(converted.0 + converted.1, TEST_UPLOAD_PENDING_LIMIT);
        assert!(sqlx::query_scalar::<_, bool>(
            "SELECT slot_delete_projection FROM upload_cleanup_queue
             WHERE object_id=$1 AND storage_attempt=$2
               AND object_key=$1::text AND stage_key=$3",
        )
        .bind(slot_id)
        .bind(attempt)
        .bind(&stage_key)
        .fetch_one(&mut *tx)
        .await
        .unwrap());

        let extra_id = Uuid::new_v4();
        let extra_attempt = Uuid::new_v4();
        let extra_stage = format!("staging/{extra_id}/{extra_attempt}");
        let capacity_error = sqlx::query(
            "INSERT INTO upload_storage_jobs(
                 object_id,storage_attempt,action,storage_backend,
                 stage_key,storage_fence,expected_size)
             VALUES($1,$2,'delete_stage','local',$3,0,1)",
        )
        .bind(extra_id)
        .bind(extra_attempt)
        .bind(extra_stage)
        .execute(&mut *tx)
        .await
        .unwrap_err();
        assert!(
            matches!(&capacity_error,sqlx::Error::Database(error)
                if error.code().as_deref()==Some("53300")),
            "fresh recovery admission must fail at the hard limit: {capacity_error}"
        );
        tx.rollback().await.unwrap();
        let after_rollback: (i64, i64) = sqlx::query_as(
            "SELECT pending_jobs,cleanup_obligation_debt
             FROM upload_storage_capacity_ledger WHERE singleton",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(after_rollback, baseline);
    }

    #[tokio::test]
    #[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
    async fn upload_recovery_capacity_counts_every_locator_and_releases_last_owner() {
        let url = std::env::var("TEST_DATABASE_URL")
            .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(16)
            .connect(&url)
            .await
            .unwrap();
        db::migrate(&pool).await.unwrap();
        validate_upload_capacity_policy(
            &pool,
            TEST_UPLOAD_PENDING_LIMIT,
            TEST_UPLOAD_RETAINED_FILES_LIMIT,
            TEST_UPLOAD_RETAINED_BYTES_LIMIT,
        )
        .await
        .unwrap();
        let baseline: (i64, i64, i64, i64, i64, i64, bool) = sqlx::query_as(
            "SELECT retained_files,retained_bytes,
                    recovery_retained_files,recovery_retained_bytes,
                    pending_jobs,cleanup_obligation_debt,recovery_overcommit_draining
               FROM upload_storage_capacity_ledger WHERE singleton",
        )
        .fetch_one(&pool)
        .await
        .unwrap();

        // Eight failed attempts for one object are eight possible physical
        // stages, even though the logical object owner remains exactly one.
        let object_id = Uuid::new_v4();
        let attempt_size = 25_i64 * 1024 * 1024;
        let mut attempts = Vec::new();
        for _ in 0..MAX_UPLOAD_ATTEMPTS {
            let attempt = Uuid::new_v4();
            let stage = format!("staging/{object_id}/{attempt}");
            sqlx::query(
                "INSERT INTO upload_storage_jobs(
                     object_id,storage_attempt,action,storage_backend,
                     stage_key,storage_fence,expected_size)
                 VALUES($1,$2,'delete_stage','local',$3,0,$4)",
            )
            .bind(object_id)
            .bind(attempt)
            .bind(stage)
            .bind(attempt_size)
            .execute(&pool)
            .await
            .unwrap();
            attempts.push(attempt);
        }
        let after_attempts: (i64, i64, i64, i64) = sqlx::query_as(
            "SELECT retained_files,retained_bytes,
                    recovery_retained_files,recovery_retained_bytes
               FROM upload_storage_capacity_ledger WHERE singleton",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(after_attempts.0, baseline.0 + 1);
        assert_eq!(after_attempts.1, baseline.1 + attempt_size);
        assert_eq!(after_attempts.2, baseline.2 + MAX_UPLOAD_ATTEMPTS);
        assert_eq!(
            after_attempts.3,
            baseline.3 + MAX_UPLOAD_ATTEMPTS * attempt_size
        );

        // Dead-lettering retains the exact physical obligation. It is not a
        // release event and cannot manufacture capacity for another upload.
        sqlx::query(
            "UPDATE upload_storage_jobs SET dead_lettered_at=clock_timestamp()
             WHERE object_id=$1 AND storage_attempt=$2 AND action='delete_stage'",
        )
        .bind(object_id)
        .bind(attempts[0])
        .execute(&pool)
        .await
        .unwrap();
        let after_dead_letter: (i64, i64) = sqlx::query_as(
            "SELECT recovery_retained_files,recovery_retained_bytes
               FROM upload_storage_capacity_ledger WHERE singleton",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(after_dead_letter, (after_attempts.2, after_attempts.3));

        // A local cleanup tombstone names a distinct object and stage: two
        // physical locator units. Since jobs already own the logical object,
        // inserting it must not add a second logical retained unit.
        let stage = format!("staging/{object_id}/{}", attempts[0]);
        sqlx::query(
            "INSERT INTO upload_cleanup_queue(
                 object_id,storage_backend,object_key,stage_key,storage_attempt,
                 expected_size,storage_fence)
             VALUES($1,'local',$1::text,$2,$3,$4,0)",
        )
        .bind(object_id)
        .bind(&stage)
        .bind(attempts[0])
        .bind(attempt_size)
        .execute(&pool)
        .await
        .unwrap();
        let with_cleanup: (i64, i64, i64) = sqlx::query_as(
            "SELECT retained_files,recovery_retained_files,recovery_retained_bytes
               FROM upload_storage_capacity_ledger WHERE singleton",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(with_cleanup.0, baseline.0 + 1);
        assert_eq!(with_cleanup.1, baseline.2 + MAX_UPLOAD_ATTEMPTS + 2);
        assert_eq!(
            with_cleanup.2,
            baseline.3 + (MAX_UPLOAD_ATTEMPTS + 2) * attempt_size
        );

        // Complete cleanup first and storage attempts in reverse order. The
        // logical retained unit stays until the final projection disappears.
        sqlx::query("DELETE FROM upload_cleanup_queue WHERE object_id=$1")
            .bind(object_id)
            .execute(&pool)
            .await
            .unwrap();
        for (index, attempt) in attempts.iter().rev().enumerate() {
            sqlx::query(
                "DELETE FROM upload_storage_jobs
                 WHERE object_id=$1 AND storage_attempt=$2 AND action='delete_stage'",
            )
            .bind(object_id)
            .bind(attempt)
            .execute(&pool)
            .await
            .unwrap();
            let logical: i64 = sqlx::query_scalar(
                "SELECT retained_files FROM upload_storage_capacity_ledger WHERE singleton",
            )
            .fetch_one(&pool)
            .await
            .unwrap();
            assert_eq!(
                logical,
                baseline.0 + if index + 1 < attempts.len() { 1 } else { 0 },
                "only the last physical projection may release logical ownership"
            );
        }

        // Reverse admission/completion order on another object, and verify an
        // S3 same-key tombstone with the same exact version counts once.
        let reverse_id = Uuid::new_v4();
        let reverse_attempt = Uuid::new_v4();
        let reverse_stage = format!("staging/{reverse_id}/{reverse_attempt}");
        sqlx::query(
            "INSERT INTO upload_cleanup_queue(
                 object_id,storage_backend,object_key,stage_key,storage_attempt,
                 expected_size,storage_fence)
             VALUES($1,'local',$1::text,$2,$3,$4,0)",
        )
        .bind(reverse_id)
        .bind(&reverse_stage)
        .bind(reverse_attempt)
        .bind(attempt_size)
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO upload_storage_jobs(
                 object_id,storage_attempt,action,storage_backend,
                 stage_key,storage_fence,expected_size)
             VALUES($1,$2,'delete_stage','local',$3,0,$4)",
        )
        .bind(reverse_id)
        .bind(reverse_attempt)
        .bind(&reverse_stage)
        .bind(attempt_size)
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query("DELETE FROM upload_storage_jobs WHERE object_id=$1")
            .bind(reverse_id)
            .execute(&pool)
            .await
            .unwrap();
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT retained_files FROM upload_storage_capacity_ledger WHERE singleton"
            )
            .fetch_one(&pool)
            .await
            .unwrap(),
            baseline.0 + 1
        );
        sqlx::query("DELETE FROM upload_cleanup_queue WHERE object_id=$1")
            .bind(reverse_id)
            .execute(&pool)
            .await
            .unwrap();

        let s3_id = Uuid::new_v4();
        let s3_attempt = Uuid::new_v4();
        let s3_key = format!("objects/{s3_id}/{s3_attempt}");
        sqlx::query(
            "INSERT INTO upload_cleanup_queue(
                 object_id,storage_backend,object_key,object_version,
                 stage_key,stage_version,storage_attempt,expected_size,storage_fence)
             VALUES($1,'s3',$2,'version-1',$2,'version-1',$3,$4,0)",
        )
        .bind(s3_id)
        .bind(s3_key)
        .bind(s3_attempt)
        .bind(attempt_size)
        .execute(&pool)
        .await
        .unwrap();
        let s3_recovery_files: i64 = sqlx::query_scalar(
            "SELECT recovery_retained_files FROM upload_storage_capacity_ledger WHERE singleton",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(s3_recovery_files, baseline.2 + 1);
        sqlx::query("DELETE FROM upload_cleanup_queue WHERE object_id=$1")
            .bind(s3_id)
            .execute(&pool)
            .await
            .unwrap();

        // A promotion which appears after cleanup selection is a normal
        // quiescence race. Deferring releases the lease and restores attempts;
        // while the promotion exists the candidate query does not reclaim it.
        let quiet_id = Uuid::new_v4();
        let quiet_attempt = Uuid::new_v4();
        let quiet_stage = format!("staging/{quiet_id}/{quiet_attempt}");
        let quiet_digest = vec![7_u8; 32];
        sqlx::query(
            "INSERT INTO upload_cleanup_queue(
                 object_id,storage_backend,object_key,stage_key,storage_attempt,
                 expected_size,expected_sha256,storage_fence,available_at)
             VALUES($1,'local',$1::text,$2,$3,$4,$5,7,
                    clock_timestamp()-INTERVAL '100 years')",
        )
        .bind(quiet_id)
        .bind(&quiet_stage)
        .bind(quiet_attempt)
        .bind(attempt_size)
        .bind(&quiet_digest)
        .execute(&pool)
        .await
        .unwrap();
        let first_claim = queued_upload_cleanup(&pool)
            .await
            .unwrap()
            .into_iter()
            .find(|job| job.object_id == quiet_id)
            .expect("quiescence fixture cleanup claim");
        sqlx::query(
            "INSERT INTO upload_storage_jobs(
                 object_id,storage_attempt,action,storage_backend,
                 stage_key,object_key,expected_size,expected_sha256,storage_fence)
             VALUES($1,$2,'promote','local',$3,$1::text,$4,$5,7)",
        )
        .bind(quiet_id)
        .bind(quiet_attempt)
        .bind(&quiet_stage)
        .bind(attempt_size)
        .bind(&quiet_digest)
        .execute(&pool)
        .await
        .unwrap();
        assert!(!upload_cleanup_generation_is_quiescent(
            &pool,
            quiet_id,
            first_claim.claim_token,
            7,
        )
        .await
        .unwrap());
        assert!(
            defer_queued_upload_cleanup(&pool, quiet_id, first_claim.claim_token)
                .await
                .unwrap()
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT attempts FROM upload_cleanup_queue WHERE object_id=$1"
            )
            .bind(quiet_id)
            .fetch_one(&pool)
            .await
            .unwrap(),
            0
        );
        assert!(
            queued_upload_cleanup(&pool)
                .await
                .unwrap()
                .iter()
                .all(|job| job.object_id != quiet_id),
            "an exact promotion must keep cleanup out of the claimed batch"
        );
        sqlx::query("DELETE FROM upload_storage_jobs WHERE object_id=$1")
            .bind(quiet_id)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query(
            "UPDATE upload_cleanup_queue
             SET available_at=clock_timestamp()-INTERVAL '100 years'
             WHERE object_id=$1",
        )
        .bind(quiet_id)
        .execute(&pool)
        .await
        .unwrap();
        let final_claim = queued_upload_cleanup(&pool)
            .await
            .unwrap()
            .into_iter()
            .find(|job| job.object_id == quiet_id)
            .expect("cleanup becomes claimable after promotion completion");
        assert!(
            complete_queued_upload_cleanup(&pool, quiet_id, final_claim.claim_token,)
                .await
                .unwrap()
        );

        // Mandatory recovery projections remain insertable above the byte
        // ceiling, enter draining, and block a fresh reservation. This models
        // eight maximum-size failed attempts without losing cleanup authority.
        let capacity_id = Uuid::new_v4();
        let capacity_size = TEST_UPLOAD_RETAINED_BYTES_LIMIT / MAX_UPLOAD_ATTEMPTS;
        for _ in 0..MAX_UPLOAD_ATTEMPTS {
            let attempt = Uuid::new_v4();
            sqlx::query(
                "INSERT INTO upload_storage_jobs(
                     object_id,storage_attempt,action,storage_backend,
                     stage_key,storage_fence,expected_size)
                 VALUES($1,$2,'delete_stage','local',$3,0,$4)",
            )
            .bind(capacity_id)
            .bind(attempt)
            .bind(format!("staging/{capacity_id}/{attempt}"))
            .bind(capacity_size)
            .execute(&pool)
            .await
            .unwrap();
        }
        assert!(sqlx::query_scalar::<_, bool>(
            "SELECT recovery_overcommit_draining
               FROM upload_storage_capacity_ledger WHERE singleton",
        )
        .fetch_one(&pool)
        .await
        .unwrap());
        let user_id = insert_user(&pool).await;
        assert!(
            create_upload_slot(
                &pool,
                UploadReservation {
                    user_id,
                    filename: "blocked-by-recovery.bin",
                    content_type: "application/octet-stream",
                    size: 1,
                    token_hash: b"recovery-capacity",
                    max_files_per_user: 10,
                    max_bytes_per_user: 10,
                    storage_backend: "local",
                },
            )
            .await
            .unwrap()
            .is_none(),
            "physical recovery debt must block fresh upload admission"
        );
        sqlx::query("DELETE FROM upload_storage_jobs WHERE object_id=$1")
            .bind(capacity_id)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM users WHERE id=$1")
            .bind(user_id)
            .execute(&pool)
            .await
            .unwrap();

        let final_ledger: (i64, i64, i64, i64, i64, i64, bool) = sqlx::query_as(
            "SELECT retained_files,retained_bytes,
                    recovery_retained_files,recovery_retained_bytes,
                    pending_jobs,cleanup_obligation_debt,recovery_overcommit_draining
               FROM upload_storage_capacity_ledger WHERE singleton",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(final_ledger, baseline);
    }

    #[tokio::test]
    #[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
    async fn upload_capacity_migration_rejects_disabled_or_reused_trigger_authority() {
        let url = std::env::var("TEST_DATABASE_URL")
            .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(2)
            .connect(&url)
            .await
            .unwrap();
        db::migrate(&pool).await.unwrap();
        let migration = include_str!("../../migrations/0105_upload_cascade_cleanup_capacity.sql");
        let marker = "$northstar_upload_delete_trigger_precondition$;";
        let start = migration
            .find("DO $northstar_upload_delete_trigger_precondition$")
            .expect("0105 trigger precondition start");
        let relative_end = migration[start..]
            .find(marker)
            .expect("0105 trigger precondition end");
        let precondition = &migration[start..start + relative_end + marker.len()];

        sqlx::query(
            "ALTER TABLE upload_cleanup_queue
             DISABLE TRIGGER upload_cleanup_identity_guard",
        )
        .execute(&pool)
        .await
        .unwrap();
        let disabled_error = sqlx::query(precondition).execute(&pool).await.unwrap_err();
        sqlx::query(
            "ALTER TABLE upload_cleanup_queue
             ENABLE TRIGGER upload_cleanup_identity_guard",
        )
        .execute(&pool)
        .await
        .unwrap();
        assert!(
            matches!(&disabled_error,sqlx::Error::Database(error)
                if error.code().as_deref()==Some("55000")),
            "disabled identity guard must fail migration preconditions: {disabled_error}"
        );

        sqlx::query(
            "ALTER TABLE upload_storage_jobs
             DISABLE TRIGGER upload_job_capacity_insert",
        )
        .execute(&pool)
        .await
        .unwrap();
        let disabled_capacity_error = sqlx::query(precondition).execute(&pool).await.unwrap_err();
        sqlx::query(
            "ALTER TABLE upload_storage_jobs
             ENABLE TRIGGER upload_job_capacity_insert",
        )
        .execute(&pool)
        .await
        .unwrap();
        assert!(
            matches!(&disabled_capacity_error,sqlx::Error::Database(error)
                if error.code().as_deref()==Some("55000")),
            "disabled capacity trigger must fail migration preconditions: {disabled_capacity_error}"
        );

        sqlx::query("CREATE TABLE upload_cleanup_trigger_probe (LIKE upload_cleanup_queue)")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query(
            "CREATE TRIGGER forged_upload_cleanup_identity_guard
             BEFORE UPDATE ON upload_cleanup_trigger_probe
             FOR EACH ROW EXECUTE FUNCTION protect_upload_cleanup_identity()",
        )
        .execute(&pool)
        .await
        .unwrap();
        let reused_error = sqlx::query(precondition).execute(&pool).await.unwrap_err();
        sqlx::query("DROP TABLE upload_cleanup_trigger_probe")
            .execute(&pool)
            .await
            .unwrap();
        assert!(
            matches!(&reused_error,sqlx::Error::Database(error)
                if error.code().as_deref()==Some("55000")),
            "reusing an identity function OID on another table must fail migration preconditions: {reused_error}"
        );

        sqlx::query("CREATE TABLE upload_job_capacity_trigger_probe (LIKE upload_storage_jobs)")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query(
            "CREATE TRIGGER forged_upload_job_capacity_insert
             AFTER INSERT ON upload_job_capacity_trigger_probe
             FOR EACH ROW EXECUTE FUNCTION account_upload_storage_job_capacity()",
        )
        .execute(&pool)
        .await
        .unwrap();
        let reused_capacity_error = sqlx::query(precondition).execute(&pool).await.unwrap_err();
        sqlx::query("DROP TABLE upload_job_capacity_trigger_probe")
            .execute(&pool)
            .await
            .unwrap();
        assert!(
            matches!(&reused_capacity_error,sqlx::Error::Database(error)
                if error.code().as_deref()==Some("55000")),
            "reusing a capacity function OID on another table must fail migration preconditions: {reused_capacity_error}"
        );
    }

    #[tokio::test]
    #[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
    async fn account_delete_and_upload_mutations_share_retryable_ledger_first_order() {
        let url = std::env::var("TEST_DATABASE_URL")
            .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(8)
            .connect(&url)
            .await
            .unwrap();
        db::migrate(&pool).await.unwrap();
        validate_upload_capacity_policy(
            &pool,
            TEST_UPLOAD_PENDING_LIMIT,
            TEST_UPLOAD_RETAINED_FILES_LIMIT,
            TEST_UPLOAD_RETAINED_BYTES_LIMIT,
        )
        .await
        .unwrap();
        let user_id = insert_user(&pool).await;
        let token = b"lock-order-token";
        let slot_id = create_upload_slot(
            &pool,
            UploadReservation {
                user_id,
                filename: "lock-order.bin",
                content_type: "application/octet-stream",
                size: 1,
                token_hash: token,
                max_files_per_user: 10,
                max_bytes_per_user: 10,
                storage_backend: "local",
            },
        )
        .await
        .unwrap()
        .unwrap();
        let active_lease = match claim_upload_slot(&pool, slot_id, token, 90).await.unwrap() {
            UploadClaimOutcome::Acquired(lease) => lease,
            other => panic!("unexpected initial upload claim outcome: {other:?}"),
        };

        // Model the prefix of account deletion: global ledger, then user.
        // Claim's SQL capability has a NOWAIT ledger admission; ordinary lease
        // renewal does not touch capacity authority. Generic capacity paths
        // and implicit trigger accounting must return SQLSTATE 55P03 without
        // waiting behind this owner.
        let mut account_tx = pool.begin().await.unwrap();
        sqlx::query(
            "SELECT singleton FROM upload_storage_capacity_ledger WHERE singleton FOR UPDATE",
        )
        .fetch_one(&mut *account_tx)
        .await
        .unwrap();
        sqlx::query("SELECT id FROM users WHERE id=$1 FOR UPDATE")
            .bind(user_id)
            .fetch_one(&mut *account_tx)
            .await
            .unwrap();
        assert!(matches!(
            claim_upload_slot(&pool, slot_id, token, 90).await.unwrap(),
            UploadClaimOutcome::InProgress { .. }
        ));
        assert_eq!(
            renew_upload_claim(&pool, slot_id, active_lease.claim_token, 90)
                .await
                .unwrap(),
            UploadRenewOutcome::Renewed,
            "a healthy lease renewal must remain independent of unrelated capacity work"
        );
        let queue_error = queue_user_upload_delete(&pool, user_id, slot_id, Uuid::new_v4())
            .await
            .unwrap_err();
        assert!(queue_error
            .to_string()
            .contains("upload storage capacity busy; retry"));
        let trigger_error = tokio::time::timeout(
            Duration::from_secs(1),
            sqlx::query(
                "INSERT INTO upload_cleanup_queue(
                     object_id,storage_backend,object_key,expected_size,storage_fence)
                 VALUES($1,'local',$1::text,1,0)",
            )
            .bind(Uuid::new_v4())
            .execute(&pool),
        )
        .await
        .expect("implicit cleanup accounting must reject a held ledger promptly")
        .unwrap_err();
        assert!(
            is_retryable_upload_capacity_lock(&trigger_error),
            "implicit upload cleanup accounting must expose SQLSTATE 55P03: {trigger_error}"
        );
        let completion_error = tokio::time::timeout(
            Duration::from_secs(1),
            complete_queued_upload_cleanup(&pool, Uuid::new_v4(), Uuid::new_v4()),
        )
        .await
        .expect(
            "cleanup completion must reject ledger contention without waiting for the outer test",
        )
        .unwrap_err();
        assert!(
            completion_error
                .chain()
                .filter_map(|cause| cause.downcast_ref::<sqlx::Error>())
                .any(is_retryable_upload_capacity_lock),
            "generic cleanup completion must preserve SQLSTATE 55P03 for central retry mapping: {completion_error:#}"
        );
        account_tx.rollback().await.unwrap();

        // A committed replay cannot establish another cleanup obligation: it
        // must remain available while unrelated work holds the singleton.
        let replay_digest = [7_u8; 32];
        assert!(complete_upload(
            &pool,
            slot_id,
            active_lease.claim_token,
            &replay_digest,
            600,
        )
        .await
        .unwrap());
        let mut healthy_tx = pool.begin().await.unwrap();
        sqlx::query(
            "SELECT singleton FROM upload_storage_capacity_ledger WHERE singleton FOR UPDATE",
        )
        .fetch_one(&mut *healthy_tx)
        .await
        .unwrap();
        assert!(
            tokio::time::timeout(
                Duration::from_secs(1),
                record_upload_replay(&pool, slot_id, token, &replay_digest),
            )
            .await
            .expect("committed replay must not wait for unrelated capacity authority")
            .unwrap(),
            "committed replay must retain normal dedupe accounting"
        );
        healthy_tx.rollback().await.unwrap();

        // `reserve_slot` takes ledger then user internally. Both acquisitions
        // are SQL NOWAIT, so user-row contention preserves the established
        // unavailable result and releases the singleton with no Rust-side
        // timeout or pre-acquisition.
        let mut user_tx = pool.begin().await.unwrap();
        sqlx::query("SELECT id FROM users WHERE id=$1 FOR UPDATE")
            .bind(user_id)
            .fetch_one(&mut *user_tx)
            .await
            .unwrap();
        let reservation = tokio::time::timeout(
            Duration::from_secs(1),
            create_upload_slot(
                &pool,
                UploadReservation {
                    user_id,
                    filename: "user-row-contention.bin",
                    content_type: "application/octet-stream",
                    size: 1,
                    token_hash: b"user-row-contention",
                    max_files_per_user: 10,
                    max_bytes_per_user: 10,
                    storage_backend: "local",
                },
            ),
        )
        .await
        .expect("reservation must not retain the ledger behind a user-row lock")
        .unwrap();
        assert!(reservation.is_none());
        sqlx::query(
            "SELECT singleton FROM upload_storage_capacity_ledger WHERE singleton FOR UPDATE NOWAIT",
        )
        .fetch_one(&pool)
        .await
        .expect("reservation contention must release the global ledger");
        user_tx.rollback().await.unwrap();

        // The same requirement applies to the sole debt-creating claim
        // transition: its SQL capability uses NOWAIT for both the ledger and
        // target slot, returning the established retry result without holding
        // the capability transaction behind either owner.
        let contention_slot = create_upload_slot(
            &pool,
            UploadReservation {
                user_id,
                filename: "slot-row-contention.bin",
                content_type: "application/octet-stream",
                size: 1,
                token_hash: b"slot-row-contention",
                max_files_per_user: 10,
                max_bytes_per_user: 10,
                storage_backend: "local",
            },
        )
        .await
        .unwrap()
        .unwrap();
        let mut slot_tx = pool.begin().await.unwrap();
        sqlx::query("SELECT id FROM upload_slots WHERE id=$1 FOR UPDATE")
            .bind(contention_slot)
            .fetch_one(&mut *slot_tx)
            .await
            .unwrap();
        let claim = tokio::time::timeout(
            Duration::from_secs(1),
            claim_upload_slot(&pool, contention_slot, b"slot-row-contention", 90),
        )
        .await
        .expect("claim must not retain the ledger behind a slot-row lock")
        .unwrap();
        assert!(matches!(
            claim,
            UploadClaimOutcome::InProgress {
                retry_after_seconds: 1
            }
        ));
        sqlx::query(
            "SELECT singleton FROM upload_storage_capacity_ledger WHERE singleton FOR UPDATE NOWAIT",
        )
        .fetch_one(&pool)
        .await
        .expect("claim contention must release the global ledger");
        slot_tx.rollback().await.unwrap();

        // Reverse pressure: a cleanup owner holds ledger then its queue row.
        // Account deletion must surface the SQL-native 55P03 before it locks
        // the user and can form a cycle.
        let cleanup_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO upload_cleanup_queue(
                 object_id,storage_backend,object_key,expected_size,storage_fence)
             VALUES($1,'local',$1::text,1,0)",
        )
        .bind(cleanup_id)
        .execute(&pool)
        .await
        .unwrap();
        let mut cleanup_tx = pool.begin().await.unwrap();
        sqlx::query(
            "SELECT singleton FROM upload_storage_capacity_ledger WHERE singleton FOR UPDATE",
        )
        .fetch_one(&mut *cleanup_tx)
        .await
        .unwrap();
        sqlx::query("SELECT object_id FROM upload_cleanup_queue WHERE object_id=$1 FOR UPDATE")
            .bind(cleanup_id)
            .fetch_one(&mut *cleanup_tx)
            .await
            .unwrap();
        let delete_error =
            crate::db::users::delete_user_with_roster(&pool, user_id, "example.test")
                .await
                .unwrap_err();
        assert!(delete_error
            .to_string()
            .contains("upload storage capacity busy; retry account deletion"));
        cleanup_tx.rollback().await.unwrap();

        sqlx::query("DELETE FROM upload_cleanup_queue WHERE object_id=$1")
            .bind(cleanup_id)
            .execute(&pool)
            .await
            .unwrap();
        assert!(
            crate::db::users::delete_user_with_roster(&pool, user_id, "example.test",)
                .await
                .unwrap()
                .is_some()
        );
    }

    #[tokio::test]
    #[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
    async fn typed_upload_admission_results_release_capacity_lock_from_outer_transaction() {
        let url = std::env::var("TEST_DATABASE_URL")
            .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(8)
            .connect(&url)
            .await
            .unwrap();
        db::migrate(&pool).await.unwrap();
        validate_upload_capacity_policy(
            &pool,
            TEST_UPLOAD_PENDING_LIMIT,
            TEST_UPLOAD_RETAINED_FILES_LIMIT,
            TEST_UPLOAD_RETAINED_BYTES_LIMIT,
        )
        .await
        .unwrap();
        let user_id = insert_user(&pool).await;

        // Reserve obtains the ledger before it attempts the owner row.  Hold
        // that owner on one connection, retain the caller transaction after
        // its typed `false`, and prove another connection can still acquire
        // the ledger before either transaction completes.
        let mut owner_tx = pool.begin().await.unwrap();
        sqlx::query("SELECT id FROM users WHERE id=$1 FOR UPDATE")
            .bind(user_id)
            .fetch_one(&mut *owner_tx)
            .await
            .unwrap();
        let mut reserve_outer_tx = pool.begin().await.unwrap();
        let reserved: bool = sqlx::query_scalar(
            "SELECT northstar_upload_reserve_slot(
                 $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12
             )",
        )
        .bind(Uuid::new_v4())
        .bind(user_id)
        .bind("outer-transaction-reserve.bin")
        .bind("application/octet-stream")
        .bind(1_i64)
        .bind(b"outer-transaction-reserve".as_slice())
        .bind(10_i64)
        .bind(10_i64)
        .bind("local")
        .bind(TEST_UPLOAD_RETAINED_FILES_LIMIT)
        .bind(TEST_UPLOAD_RETAINED_BYTES_LIMIT)
        .bind(TEST_UPLOAD_PENDING_LIMIT)
        .fetch_one(&mut *reserve_outer_tx)
        .await
        .unwrap();
        assert!(
            !reserved,
            "owner-row NOWAIT contention must retain the established typed false result"
        );
        sqlx::query(
            "SELECT singleton FROM upload_storage_capacity_ledger
             WHERE singleton FOR UPDATE NOWAIT",
        )
        .fetch_one(&pool)
        .await
        .expect("typed reserve false must not retain the ledger in its outer transaction");
        reserve_outer_tx.rollback().await.unwrap();
        owner_tx.rollback().await.unwrap();

        // The same savepoint rollback is required for an ordinary quota
        // refusal, where the capacity and owner rows were both acquired but
        // no reservation was admitted.
        let slot_id = create_upload_slot(
            &pool,
            UploadReservation {
                user_id,
                filename: "outer-transaction-claim.bin",
                content_type: "application/octet-stream",
                size: 1,
                token_hash: b"outer-transaction-claim",
                max_files_per_user: 10,
                max_bytes_per_user: 10,
                storage_backend: "local",
            },
        )
        .await
        .unwrap()
        .unwrap();
        let mut reserve_quota_outer_tx = pool.begin().await.unwrap();
        let quota_reserved: bool = sqlx::query_scalar(
            "SELECT northstar_upload_reserve_slot(
                 $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12
             )",
        )
        .bind(Uuid::new_v4())
        .bind(user_id)
        .bind("outer-transaction-quota.bin")
        .bind("application/octet-stream")
        .bind(1_i64)
        .bind(b"outer-transaction-quota".as_slice())
        .bind(1_i64)
        .bind(10_i64)
        .bind("local")
        .bind(TEST_UPLOAD_RETAINED_FILES_LIMIT)
        .bind(TEST_UPLOAD_RETAINED_BYTES_LIMIT)
        .bind(TEST_UPLOAD_PENDING_LIMIT)
        .fetch_one(&mut *reserve_quota_outer_tx)
        .await
        .unwrap();
        assert!(
            !quota_reserved,
            "quota refusal must retain the established typed false result"
        );
        sqlx::query(
            "SELECT singleton FROM upload_storage_capacity_ledger
             WHERE singleton FOR UPDATE NOWAIT",
        )
        .fetch_one(&pool)
        .await
        .expect("ordinary reserve false must not retain the ledger in its outer transaction");
        reserve_quota_outer_tx.rollback().await.unwrap();

        // Claim follows the same ledger-then-slot order.  The slot owner and
        // caller remain open while a third pooled connection verifies that the
        // typed `in_progress` response rolled the capacity lock back.
        let mut slot_tx = pool.begin().await.unwrap();
        sqlx::query("SELECT id FROM upload_slots WHERE id=$1 FOR UPDATE")
            .bind(slot_id)
            .fetch_one(&mut *slot_tx)
            .await
            .unwrap();
        let mut claim_outer_tx = pool.begin().await.unwrap();
        let claim_outcome: String = sqlx::query_scalar(
            "SELECT outcome
               FROM northstar_upload_claim_slot($1,$2,$3,$4,$5)",
        )
        .bind(slot_id)
        .bind(b"outer-transaction-claim".as_slice())
        .bind(90_i64)
        .bind(MAX_UPLOAD_ATTEMPTS)
        .bind(MAX_UPLOAD_REPLAYS)
        .fetch_one(&mut *claim_outer_tx)
        .await
        .unwrap();
        assert_eq!(claim_outcome, "in_progress");
        sqlx::query(
            "SELECT singleton FROM upload_storage_capacity_ledger
             WHERE singleton FOR UPDATE NOWAIT",
        )
        .fetch_one(&pool)
        .await
        .expect("typed claim in_progress must not retain the ledger in its outer transaction");
        claim_outer_tx.rollback().await.unwrap();
        slot_tx.rollback().await.unwrap();

        // Finally, verify the ordinary live-lease `in_progress` result.  It
        // is not a lock conflict, but it must take the same rollback path
        // rather than keeping the global authority for the caller's outer
        // transaction.
        let active_lease = match claim_upload_slot(&pool, slot_id, b"outer-transaction-claim", 90)
            .await
            .unwrap()
        {
            UploadClaimOutcome::Acquired(lease) => lease,
            other => panic!("unexpected initial claim outcome: {other:?}"),
        };
        let mut live_claim_outer_tx = pool.begin().await.unwrap();
        let live_claim_outcome: String = sqlx::query_scalar(
            "SELECT outcome
               FROM northstar_upload_claim_slot($1,$2,$3,$4,$5)",
        )
        .bind(slot_id)
        .bind(b"outer-transaction-claim".as_slice())
        .bind(90_i64)
        .bind(MAX_UPLOAD_ATTEMPTS)
        .bind(MAX_UPLOAD_REPLAYS)
        .fetch_one(&mut *live_claim_outer_tx)
        .await
        .unwrap();
        assert_eq!(live_claim_outcome, "in_progress");
        sqlx::query(
            "SELECT singleton FROM upload_storage_capacity_ledger
             WHERE singleton FOR UPDATE NOWAIT",
        )
        .fetch_one(&pool)
        .await
        .expect("ordinary claim in_progress must not retain the ledger in its outer transaction");
        live_claim_outer_tx.rollback().await.unwrap();
        assert!(
            release_upload_claim(&pool, slot_id, active_lease.claim_token)
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    #[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
    async fn upload_quota_reservation_is_serialized_and_expiry_releases_capacity() {
        let url = std::env::var("TEST_DATABASE_URL")
            .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(16)
            .connect(&url)
            .await
            .unwrap();
        db::migrate(&pool).await.unwrap();
        validate_upload_capacity_policy(
            &pool,
            TEST_UPLOAD_PENDING_LIMIT,
            TEST_UPLOAD_RETAINED_FILES_LIMIT,
            TEST_UPLOAD_RETAINED_BYTES_LIMIT,
        )
        .await
        .unwrap();
        let user_id = insert_user(&pool).await;

        let competitors = 12;
        let barrier = Arc::new(Barrier::new(competitors + 1));
        let mut tasks = Vec::with_capacity(competitors);
        for attempt in 0..competitors {
            let pool = pool.clone();
            let barrier = barrier.clone();
            tasks.push(tokio::spawn(async move {
                barrier.wait().await;
                create_upload_slot(
                    &pool,
                    UploadReservation {
                        user_id,
                        filename: &format!("quota-{attempt}.bin"),
                        content_type: "application/octet-stream",
                        size: 6,
                        token_hash: format!("token-{attempt}").as_bytes(),
                        max_files_per_user: 100,
                        max_bytes_per_user: 10,
                        storage_backend: "local",
                    },
                )
                .await
                .unwrap()
            }));
        }
        barrier.wait().await;
        let mut winners = Vec::new();
        for task in tasks {
            if let Some(id) = task.await.unwrap() {
                winners.push(id);
            }
        }
        assert_eq!(
            winners.len(),
            1,
            "quota check and reservation must be atomic"
        );
        assert!(
            create_upload_slot(
                &pool,
                UploadReservation {
                    user_id,
                    filename: "blocked.bin",
                    content_type: "application/octet-stream",
                    size: 4,
                    token_hash: b"blocked",
                    max_files_per_user: 1,
                    max_bytes_per_user: 100,
                    storage_backend: "local",
                },
            )
            .await
            .unwrap()
            .is_none(),
            "an active reservation consumes the file-count quota",
        );

        sqlx::query("UPDATE upload_slots SET expires_at=NOW()-INTERVAL '1 second' WHERE id=$1")
            .bind(winners[0])
            .execute(&pool)
            .await
            .unwrap();
        assert!(
            create_upload_slot(
                &pool,
                UploadReservation {
                    user_id,
                    filename: "released.bin",
                    content_type: "application/octet-stream",
                    size: 10,
                    token_hash: b"released",
                    max_files_per_user: 1,
                    max_bytes_per_user: 10,
                    storage_backend: "local",
                },
            )
            .await
            .unwrap()
            .is_none(),
            "expired rows continue consuming physical quota until durable cleanup completes",
        );

        sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(user_id)
            .execute(&pool)
            .await
            .unwrap();
    }
}
