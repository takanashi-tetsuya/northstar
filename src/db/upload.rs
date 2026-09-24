use anyhow::Result;
use sqlx::{PgPool, Row};
#[cfg(test)]
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

use crate::services::upload::{PromotionClaim, UploadLifecycleRepository};
pub use crate::services::upload::{
    UploadClaimOutcome, UploadLease, UploadRenewOutcome, UploadSlot, UploadStageProjection,
    UserUploadDeleteOutcome,
};

#[derive(Clone)]
pub(crate) struct PostgresUploadRepository {
    pool: PgPool,
}

impl PostgresUploadRepository {
    pub(crate) fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

impl northstar_upload_application::UploadRepository for PostgresUploadRepository {
    type Error = anyhow::Error;

    async fn reserve_slot(
        &self,
        request: &northstar_upload_application::UploadSlotRequest<'_>,
        token_hash: &[u8],
    ) -> Result<Option<Uuid>> {
        let size = i64::try_from(request.size)
            .map_err(|_| anyhow::anyhow!("upload reservation exceeds PostgreSQL BIGINT"))?;
        create_upload_slot_bounded(
            &self.pool,
            UploadReservation {
                user_id: request.user_id,
                filename: request.filename,
                content_type: request.content_type,
                size,
                token_hash,
                max_files_per_user: request.max_files_per_user,
                max_bytes_per_user: request.max_bytes_per_user,
                storage_backend: request.storage_backend,
            },
            request.max_retained_files,
            request.max_retained_bytes,
            request.max_pending_jobs,
        )
        .await
    }
}

impl UploadLifecycleRepository for PostgresUploadRepository {
    async fn claim_slot(
        &self,
        id: Uuid,
        token_hash: &[u8],
        lease_seconds: i64,
    ) -> Result<UploadClaimOutcome> {
        claim_upload_slot(&self.pool, id, token_hash, lease_seconds).await
    }

    async fn record_replay(
        &self,
        id: Uuid,
        token_hash: &[u8],
        content_sha256: &[u8; 32],
    ) -> Result<bool> {
        record_upload_replay(&self.pool, id, token_hash, content_sha256).await
    }

    async fn renew_claim(
        &self,
        id: Uuid,
        claim_token: Uuid,
        lease_seconds: i64,
    ) -> Result<UploadRenewOutcome> {
        renew_upload_claim(&self.pool, id, claim_token, lease_seconds).await
    }

    async fn release_claim(&self, id: Uuid, claim_token: Uuid) -> Result<bool> {
        release_upload_claim(&self.pool, id, claim_token).await
    }

    async fn record_stage(&self, projection: UploadStageProjection<'_>) -> Result<bool> {
        record_upload_stage(&self.pool, projection).await
    }

    async fn claim_promotion(
        &self,
        id: Uuid,
        storage_attempt: Uuid,
        storage_fence: i64,
    ) -> Result<Option<Uuid>> {
        claim_upload_promotion_job(&self.pool, id, storage_attempt, storage_fence).await
    }

    async fn begin_promotion(&self, claim: PromotionClaim) -> Result<bool> {
        begin_upload_promotion(
            &self.pool,
            claim.id,
            claim.storage_attempt,
            claim.storage_fence,
            claim.promotion_claim_token,
        )
        .await
    }

    async fn retire_promotion(&self, claim: PromotionClaim) -> Result<bool> {
        retire_upload_promotion_for_cleanup(
            &self.pool,
            claim.id,
            claim.storage_attempt,
            claim.storage_fence,
            claim.promotion_claim_token,
        )
        .await
    }

    async fn defer_promotion(&self, claim: PromotionClaim) -> Result<bool> {
        defer_upload_promotion_job(
            &self.pool,
            claim.id,
            claim.storage_attempt,
            claim.storage_fence,
            claim.promotion_claim_token,
        )
        .await
    }

    async fn complete_promotion(&self, projection: PromotedUploadProjection<'_>) -> Result<bool> {
        complete_promoted_upload(&self.pool, projection).await
    }

    async fn attempt_committed(&self, identity: CommittedUploadIdentity<'_>) -> Result<bool> {
        upload_attempt_is_committed(&self.pool, identity).await
    }

    async fn public_file(&self, id: Uuid) -> Result<Option<UploadSlot>> {
        uploaded_file(&self.pool, id).await
    }

    async fn delete_authorized(
        &self,
        user_id: Uuid,
        auth_generation: i64,
        session_token: &str,
        id: Uuid,
        request_id: Uuid,
    ) -> Result<UserUploadDeleteOutcome> {
        queue_user_upload_delete_authorized(
            &self.pool,
            user_id,
            auth_generation,
            session_token,
            id,
            request_id,
        )
        .await
    }
}

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

pub use crate::services::upload_maintenance::UploadAuthorityProbe;

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

pub use crate::services::upload_maintenance::PromotedUploadProjection;

pub use crate::services::upload_maintenance::CommittedUploadIdentity;

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

pub use crate::services::upload_maintenance::UploadCleanupJob;

pub use crate::services::upload_maintenance::UploadStorageJob;

pub use crate::services::upload_maintenance::UploadQueueMetrics;

/// Low-frequency proof that the trigger-maintained O(1) capacity authority
/// still equals a statement-consistent projection of the underlying facts.
/// Hot admission must never perform these scans; the supervised upload worker
/// uses them only as an integrity alarm and deliberately does not rewrite the
/// authority automatically.
pub use crate::services::upload_maintenance::UploadCapacityReconciliation;

/// Lightweight catalog proof for the upload-capacity enforcement boundary.
///
/// Unlike the fact reconciliation below, this check does not scan upload
/// rows. It is safe to run frequently and detects a disabled/misattached
/// trigger, changed routine authority, owner drift, public EXECUTE grant, or
/// deployment-policy change before a later write can silently corrupt the
/// trigger-maintained ledger.
pub use crate::services::upload_maintenance::UploadCapacityAuthorityAudit;

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
                'account_upload_storage_job_capacity','account_upload_storage_job_capacity()',11,2),
               ('upload_storage_jobs','northstar_upload_capacity_nowait_storage_job_insert_delete',
                'guard_upload_capacity_nowait','guard_upload_capacity_nowait()',15,4),
               ('upload_cleanup_queue','upload_cleanup_capacity_insert',
                'account_upload_cleanup_capacity','account_upload_cleanup_capacity()',5,2),
               ('upload_cleanup_queue','upload_cleanup_capacity_delete',
                'account_upload_cleanup_capacity','account_upload_cleanup_capacity()',11,2),
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

pub use crate::services::upload_maintenance::UploadScrubJob;

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
#[path = "upload_tests.rs"]
mod tests;
