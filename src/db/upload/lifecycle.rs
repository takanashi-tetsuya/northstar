//! Upload claims, staging, promotion, completion and replay records.

use super::*;

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

pub(super) fn upload_slot_from_row(row: &sqlx::postgres::PgRow) -> UploadSlot {
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
