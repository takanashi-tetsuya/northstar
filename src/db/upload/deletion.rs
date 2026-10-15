//! Owner-requested upload deletion and upload scrub jobs.

use super::*;

/// Remove one owner-controlled upload from the public namespace and enqueue
/// its backing object for idempotent cleanup in the same transaction.  A
/// missing row and a row owned by another account are deliberately
/// indistinguishable to the caller.  The object worker may run after this
/// function returns; on Unix an already-open download remains readable, while
/// stores which cannot delete an open object retry from the durable queue.
#[cfg(test)]
pub(super) async fn queue_user_upload_delete_in_tx(
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

pub(super) async fn finish_upload_scrub(
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
