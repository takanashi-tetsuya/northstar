use axum::body::Body;
use axum::http::header::HeaderValue;
use axum::http::HeaderMap;
use axum::{
    extract::{ConnectInfo, State},
    http::{header, StatusCode},
    response::{IntoResponse, Response},
};
use bytes::Bytes;
use futures::TryStreamExt;
use sha2::{Digest, Sha256};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncReadExt;
use uuid::Uuid;

use crate::auth;
use crate::error::{AppError, Result};
use crate::services::upload::{
    AcquirePromotionOutcome, FinalizePromotionOutcome, PromotedUploadProjection, PromotionClaim,
    UploadClaimOutcome, UploadRenewOutcome, UploadSlot, UploadStageProjection,
    UserUploadDeleteOutcome,
};
use crate::services::upload_safety::UploadIoClass;
use crate::state::{AppState, UploadHttpReadContext};

const UPLOAD_LEASE_SECONDS: i64 = 90;
const UPLOAD_RENEW_SECONDS: u64 = 30;
const UPLOAD_ATTEMPT_MAX_SECONDS: u64 = 15 * 60;
const UPLOAD_PROMOTION_MAX_SECONDS: u64 = 180;

async fn write_with_lease<T>(
    write: impl std::future::Future<Output = T>,
    renew: impl std::future::Future<Output = ()>,
) -> Option<T> {
    // Both futures belong to the request; cancelling it also stops renewal.
    tokio::select! {
        () = renew => None,
        result = write => Some(result),
    }
}

pub async fn upload_put(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    crate::api::ApiPath(id): crate::api::ApiPath<Uuid>,
    headers: HeaderMap,
    body: Body,
) -> Result<Response, AppError> {
    let _operation_timer = state
        .metrics
        .upload_operation_duration_seconds
        .start_timer();
    let client_ip = crate::api::client_ip(peer.ip(), &headers, &state);
    let _request_permit = state.acquire_upload_request(client_ip).ok_or_else(|| {
        AppError::RateLimited(serde_json::json!({
            "message":"too many concurrent upload requests",
            "retry_after_seconds":1
        }))
    })?;
    state
        .upload_safety_gate()
        .permit(UploadIoClass::NewWrite)
        .map_err(|_| AppError::Unavailable("upload storage authority is not ready".into()))?;
    let token = crate::api::bearer_token(&headers)?;
    let token_hash = auth::token_hash(token);
    let content_type = single_header(&headers, header::CONTENT_TYPE)?
        .unwrap_or("application/octet-stream")
        .to_owned();
    let content_length = match single_header(&headers, header::CONTENT_LENGTH)? {
        Some(value) => Some(
            value
                .parse::<u64>()
                .map_err(|_| AppError::BadRequest("invalid Content-Length header".into()))?,
        ),
        None => None,
    };
    validate_upload_framing_headers(&headers)?;
    let claim = state
        .upload_service()
        .claim_slot(id, &token_hash, UPLOAD_LEASE_SECONDS)
        .await?;
    let (slot, lease) = match claim {
        UploadClaimOutcome::Rejected => return Err(AppError::Unauthorized),
        UploadClaimOutcome::InProgress {
            retry_after_seconds,
        } => return upload_in_progress(retry_after_seconds),
        UploadClaimOutcome::Replay {
            slot,
            content_sha256,
        } => {
            validate_upload_metadata(&slot, &content_type, content_length)?;
            let digest = tokio::time::timeout(
                Duration::from_secs(UPLOAD_ATTEMPT_MAX_SECONDS),
                digest_body(body, slot.size as u64),
            )
            .await
            .map_err(|_| AppError::BadRequest("upload attempt timed out".into()))??;
            if digest != content_sha256 {
                return Err(AppError::Conflict(
                    "upload slot already contains different bytes".into(),
                ));
            }
            let stored_digest = stored_object_digest(&state, &slot).await?;
            if stored_digest != content_sha256 {
                return Err(AppError::Internal(anyhow::anyhow!(
                    "stored upload content does not match its committed digest"
                )));
            }
            if !state
                .upload_service()
                .record_replay(slot.id, &token_hash, &digest)
                .await?
            {
                return Err(AppError::IdempotencyReplayInvalidated);
            }
            return created_upload_response(true);
        }
        UploadClaimOutcome::Acquired(lease) => (lease.slot.clone(), lease),
    };
    if let Err(error) = validate_upload_metadata(&slot, &content_type, content_length) {
        release_claim(&state, slot.id, lease.claim_token).await?;
        return Err(error);
    }

    let stream = body.into_data_stream().map_err(std::io::Error::other);
    let async_read = tokio_util::io::StreamReader::new(stream);
    let object_key = slot.id.to_string();
    let attempt_key = lease.claim_token.to_string();
    let renewer = {
        let upload_service = state.upload_service();
        async move {
            let jitter_millis = (lease.claim_token.as_u128() % 41) as u64;
            loop {
                tokio::time::sleep(Duration::from_secs(UPLOAD_RENEW_SECONDS)).await;
                let mut busy_attempt = 0_u32;
                loop {
                    match upload_service
                        .renew_claim(id, lease.claim_token, UPLOAD_LEASE_SECONDS)
                        .await
                    {
                        Ok(UploadRenewOutcome::Renewed) => break,
                        Ok(UploadRenewOutcome::Busy) if busy_attempt < 7 => {
                            let delay = 25_u64
                                .saturating_mul(1_u64 << busy_attempt.min(5))
                                .min(800)
                                .saturating_add(jitter_millis);
                            busy_attempt = busy_attempt.saturating_add(1);
                            tokio::time::sleep(Duration::from_millis(delay)).await;
                        }
                        Ok(UploadRenewOutcome::Busy | UploadRenewOutcome::Lost) => {
                            return;
                        }
                        Err(error) => {
                            tracing::error!(upload_id=%id, ?error, "failed to renew upload lease");
                            return;
                        }
                    }
                }
            }
        }
    };
    let attempt_deadline =
        Duration::from_secs(lease.remaining_seconds.clamp(1, UPLOAD_ATTEMPT_MAX_SECONDS));
    let put = state.upload_store().put(
        &object_key,
        &attempt_key,
        Box::new(async_read),
        slot.size as u64,
    );
    let write_result = write_with_lease(tokio::time::timeout(attempt_deadline, put), renewer).await;
    let mut staged = match write_result {
        Some(Ok(Ok(staged))) => staged,
        Some(Ok(Err(error))) => {
            release_claim_best_effort(&state, slot.id, lease.claim_token).await;
            return if crate::storage::is_upload_safety_error(&error) {
                Err(AppError::Unavailable(
                    "upload storage authority changed; the attempt was quarantined".into(),
                ))
            } else {
                Err(AppError::Internal(error))
            };
        }
        Some(Err(_)) => {
            release_claim(&state, slot.id, lease.claim_token).await?;
            return Err(AppError::BadRequest("upload slot expired".into()));
        }
        None => return upload_in_progress(1),
    };

    if staged.bytes_written() != slot.size as u64 {
        release_claim(&state, slot.id, lease.claim_token).await?;
        return Err(AppError::BadRequest(
            "upload length does not match the reserved slot".into(),
        ));
    }
    let content_sha256 = *staged.sha256().ok_or_else(|| {
        AppError::Internal(anyhow::anyhow!(
            "storage backend accepted exact bytes without an upload digest"
        ))
    })?;
    let stage_is_final_object = staged.stage_key() == staged.object_key();
    if state.upload_store().backend() != slot.storage_backend {
        release_claim_best_effort(&state, slot.id, lease.claim_token).await;
        return Err(AppError::Internal(anyhow::anyhow!(
            "upload slot storage backend differs from this node"
        )));
    }
    // Disarm request-local cleanup before awaiting the database handoff.  A
    // PostgreSQL COMMIT may succeed even when this future is cancelled before
    // its response is observed.  The pre-existing `writing` row already names
    // this exact attempt, so both an uncertain commit and an explicit database
    // error are recovered by the bounded storage worker instead of deleting a
    // stage that a committed promotion job may now own.
    staged.durably_recorded();
    if !state
        .upload_service()
        .record_stage(UploadStageProjection {
            id: slot.id,
            claim_token: lease.claim_token,
            storage_backend: state.upload_store().backend(),
            stage_key: staged.stage_key(),
            stage_version: staged.stage_version(),
            object_key: staged.object_key(),
            content_sha256: &content_sha256,
            size: slot.size as u64,
            storage_fence: lease.storage_fence,
        })
        .await?
    {
        // The stage was disarmed before an uncertain database handoff. For an
        // S3 direct-final key, only a fenced lost-authority/deletion
        // projection may delete it; a concurrent worker may already have
        // committed this same immutable attempt.
        if !stage_is_final_object {
            abort_stage_best_effort(&state, slot.id, lease.claim_token, staged.stage_version())
                .await;
        }
        return upload_in_progress(1);
    }
    let promotion_claim_token = match state
        .upload_service()
        .acquire_promotion(slot.id, lease.claim_token, lease.storage_fence)
        .await?
    {
        AcquirePromotionOutcome::Ready(token) => token,
        AcquirePromotionOutcome::Retired => {
            abort_stage_best_effort(&state, slot.id, lease.claim_token, staged.stage_version())
                .await;
            return Err(AppError::Conflict(
                "upload was deleted before promotion".into(),
            ));
        }
        AcquirePromotionOutcome::Busy => return upload_in_progress(1),
    };
    // No PostgreSQL lock or transaction spans this storage operation. S3 has
    // already written its private attempt key, so this is an exact-version
    // readback only; local storage performs a create-only hard-link promotion.
    let promoted_result = tokio::time::timeout(
        Duration::from_secs(UPLOAD_PROMOTION_MAX_SECONDS),
        state.upload_store().commit(
            &object_key,
            &attempt_key,
            staged.stage_version(),
            slot.size as u64,
            &content_sha256,
        ),
    )
    .await
    .map_err(|_| AppError::Internal(anyhow::anyhow!("upload promotion timed out")))?;
    let promoted = match promoted_result {
        Ok(promoted) => promoted,
        Err(error) if crate::storage::is_upload_safety_error(&error) => {
            state
                .upload_service()
                .defer_promotion(PromotionClaim {
                    id: slot.id,
                    storage_attempt: lease.claim_token,
                    storage_fence: lease.storage_fence,
                    promotion_claim_token,
                })
                .await?;
            return Err(AppError::Unavailable(
                "upload authority changed; promotion was deferred".into(),
            ));
        }
        Err(error) => return Err(AppError::Internal(error)),
    };
    let completion = state
        .upload_service()
        .finalize_promotion(PromotedUploadProjection {
            id: slot.id,
            claim_token: lease.claim_token,
            promotion_claim_token,
            storage_backend: &promoted.backend,
            object_key: &promoted.object_key,
            object_version: promoted.object_version.as_deref(),
            content_sha256: &content_sha256,
            size: promoted.size,
            retention_seconds: state.config.upload_retention_seconds,
            storage_fence: lease.storage_fence,
        })
        .await?;
    match completion {
        FinalizePromotionOutcome::Committed => {}
        FinalizePromotionOutcome::ConcurrentlyCommitted => {
            // A concurrent reconciler committed the same immutable bytes.
        }
        FinalizePromotionOutcome::Retired => {
            abort_stage_best_effort(&state, slot.id, lease.claim_token, staged.stage_version())
                .await;
            return Err(AppError::Conflict(
                "upload was deleted during promotion".into(),
            ));
        }
        FinalizePromotionOutcome::Indeterminate => {
            return Err(AppError::Internal(anyhow::anyhow!(
                "upload storage projection changed before metadata completion"
            )));
        }
    }
    // Local promotion leaves a distinct stage whose durable delete-stage job
    // remains authoritative. For S3 the stage is the committed object itself:
    // a successful or benign duplicate commit must never abort that key.
    if !stage_is_final_object {
        abort_stage_best_effort(&state, slot.id, lease.claim_token, staged.stage_version()).await;
    }
    created_upload_response(false)
}

fn single_header(headers: &HeaderMap, name: header::HeaderName) -> Result<Option<&str>, AppError> {
    let mut values = headers.get_all(&name).iter();
    match (values.next(), values.next()) {
        (None, None) => Ok(None),
        (Some(value), None) => value
            .to_str()
            .map(Some)
            .map_err(|_| AppError::BadRequest(format!("{name} header is invalid"))),
        _ => Err(AppError::BadRequest(format!(
            "exactly one {name} header is allowed"
        ))),
    }
}

fn validate_upload_framing_headers(headers: &HeaderMap) -> Result<(), AppError> {
    if let Some(encoding) = single_header(headers, header::CONTENT_ENCODING)? {
        if !encoding.trim().eq_ignore_ascii_case("identity") {
            return Err(AppError::BadRequest(
                "Content-Encoding must be identity for an upload slot".into(),
            ));
        }
    }
    if single_header(headers, header::CONTENT_RANGE)?.is_some() {
        return Err(AppError::BadRequest(
            "Content-Range is not supported for an upload slot".into(),
        ));
    }
    Ok(())
}

fn validate_upload_metadata(
    slot: &UploadSlot,
    content_type: &str,
    content_length: Option<u64>,
) -> Result<(), AppError> {
    if !content_type.eq_ignore_ascii_case(&slot.content_type) {
        return Err(AppError::BadRequest(
            "upload content type does not match the reserved slot".into(),
        ));
    }
    if content_length.is_some_and(|length| length != slot.size as u64) {
        return Err(AppError::BadRequest(
            "upload length does not match the reserved slot".into(),
        ));
    }
    Ok(())
}

async fn digest_body(body: Body, expected_size: u64) -> Result<[u8; 32], AppError> {
    let mut stream = body.into_data_stream();
    let mut total = 0_u64;
    let mut digest = Sha256::new();
    while let Some(chunk) = stream
        .try_next()
        .await
        .map_err(|error| AppError::BadRequest(format!("could not read upload body: {error}")))?
    {
        total = total
            .checked_add(chunk.len() as u64)
            .ok_or(AppError::PayloadTooLarge)?;
        if total > expected_size {
            return Err(AppError::BadRequest(
                "upload length does not match the reserved slot".into(),
            ));
        }
        digest.update(&chunk);
    }
    if total != expected_size {
        return Err(AppError::BadRequest(
            "upload length does not match the reserved slot".into(),
        ));
    }
    Ok(digest.finalize().into())
}

async fn stored_object_digest(state: &AppState, slot: &UploadSlot) -> Result<[u8; 32], AppError> {
    if state.upload_store().backend() != slot.storage_backend {
        return Err(AppError::Internal(anyhow::anyhow!(
            "committed upload belongs to a different storage backend"
        )));
    }
    let object_key = slot.storage_object_key.as_deref().ok_or_else(|| {
        AppError::Internal(anyhow::anyhow!("committed upload has no object locator"))
    })?;
    let Some(stored) = tokio::time::timeout(
        Duration::from_secs(state.config.upload_download_read_timeout_seconds),
        state
            .upload_store()
            .get(object_key, slot.storage_object_version.as_deref()),
    )
    .await
    .map_err(|_| AppError::Internal(anyhow::anyhow!("upload object lookup timed out")))?
    .map_err(AppError::Internal)?
    else {
        return Err(AppError::Internal(anyhow::anyhow!(
            "committed upload object is missing"
        )));
    };
    if stored.object_version.as_deref() != slot.storage_object_version.as_deref() {
        return Err(AppError::Internal(anyhow::anyhow!(
            "committed upload object version is inconsistent"
        )));
    }
    let mut reader = stored.reader;
    let size = stored.size;
    let expected_size = slot.size as u64;
    if size != expected_size {
        return Err(AppError::Internal(anyhow::anyhow!(
            "committed upload object size is inconsistent"
        )));
    }
    let mut digest = Sha256::new();
    let mut total = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    let total_deadline =
        tokio::time::Instant::now() + Duration::from_secs(state.config.upload_download_max_seconds);
    let idle_timeout = Duration::from_secs(state.config.upload_download_read_timeout_seconds);
    loop {
        let deadline = (tokio::time::Instant::now() + idle_timeout).min(total_deadline);
        let read = tokio::time::timeout_at(deadline, reader.read(&mut buffer))
            .await
            .map_err(|_| {
                AppError::Internal(anyhow::anyhow!(
                    "stored upload digest verification timed out"
                ))
            })?
            .map_err(|error| AppError::Internal(error.into()))?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(read as u64)
            .ok_or_else(|| AppError::Internal(anyhow::anyhow!("stored upload size overflow")))?;
        if total > expected_size {
            return Err(AppError::Internal(anyhow::anyhow!(
                "committed upload object is oversized"
            )));
        }
        digest.update(&buffer[..read]);
    }
    if total != expected_size {
        return Err(AppError::Internal(anyhow::anyhow!(
            "committed upload object is truncated"
        )));
    }
    Ok(digest.finalize().into())
}

fn created_upload_response(replayed: bool) -> Result<Response, AppError> {
    let mut response = Response::builder()
        .status(StatusCode::CREATED)
        .header(header::CACHE_CONTROL, "no-store, max-age=0");
    if replayed {
        response = response.header("idempotency-replayed", "true");
    }
    response
        .body(Body::empty())
        .map_err(|error| AppError::Internal(error.into()))
}

fn upload_in_progress(retry_after_seconds: u64) -> Result<Response, AppError> {
    Response::builder()
        .status(StatusCode::CONFLICT)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::RETRY_AFTER, retry_after_seconds.max(1).to_string())
        .body(Body::from(
            serde_json::to_vec(&serde_json::json!({
                "error": {
                    "code": "upload_in_progress",
                    "message": "an upload for this slot is still in progress"
                }
            }))
            .map_err(|error| AppError::Internal(error.into()))?,
        ))
        .map_err(|error| AppError::Internal(error.into()))
}

pub async fn upload_get(
    State(state): State<UploadHttpReadContext>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    crate::api::ApiPath(id): crate::api::ApiPath<Uuid>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let _operation_timer = state.operation_timer();
    let client_ip =
        super::client_ip_with_trusted_proxies(peer.ip(), &headers, state.trusted_proxies());
    let download_guard = state.acquire_download(client_ip).ok_or_else(|| {
        AppError::RateLimited(serde_json::json!({
            "message":"too many concurrent upload downloads",
            "retry_after_seconds":1
        }))
    })?;
    let Some(slot) = state.public_file(id).await? else {
        return Ok(StatusCode::NOT_FOUND.into_response());
    };
    if state.backend() != slot.storage_backend {
        return Err(AppError::Internal(anyhow::anyhow!(
            "committed upload belongs to a different storage backend"
        )));
    }
    let object_key = slot.storage_object_key.as_deref().ok_or_else(|| {
        AppError::Internal(anyhow::anyhow!("committed upload has no object locator"))
    })?;
    let Some(stored) = tokio::time::timeout(
        state.read_timeout(),
        state.get(object_key, slot.storage_object_version.as_deref()),
    )
    .await
    .map_err(|_| AppError::Internal(anyhow::anyhow!("upload object lookup timed out")))?
    .map_err(AppError::Internal)?
    else {
        return Ok(StatusCode::NOT_FOUND.into_response());
    };
    if stored.object_version.as_deref() != slot.storage_object_version.as_deref() {
        return Err(AppError::Internal(anyhow::anyhow!(
            "stored upload version does not match database metadata"
        )));
    }
    if stored.size as i64 != slot.size {
        return Err(AppError::Internal(anyhow::anyhow!(
            "stored upload size does not match database metadata"
        )));
    }
    let mut response_headers = HeaderMap::new();
    response_headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_str(&slot.content_type)
            .map_err(|error| AppError::Internal(error.into()))?,
    );
    response_headers.insert(
        header::CONTENT_LENGTH,
        HeaderValue::from_str(&stored.size.to_string())
            .map_err(|error| AppError::Internal(error.into()))?,
    );
    let max_age = slot.remaining_seconds;
    response_headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_str(&format!("public, max-age={max_age}, immutable"))
            .map_err(|error| AppError::Internal(error.into()))?,
    );
    response_headers.insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_static("attachment"),
    );
    response_headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    response_headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static("default-src 'none'; sandbox"),
    );

    let read_timeout = state.read_timeout();
    let download_deadline = tokio::time::Instant::now() + state.max_duration();
    // Keep the independent global/IP permit for the entire body lifetime, not
    // merely until this handler returns. Each storage read also has a bounded
    // idle timeout so a stalled origin cannot retain a slot indefinitely.
    let (sender, receiver) = tokio::sync::mpsc::channel::<Result<Bytes, std::io::Error>>(2);
    let mut reader = stored.reader;
    let mut remaining = stored.size;
    tokio::spawn(async move {
        let _download_guard = download_guard;
        while remaining > 0 {
            let mut chunk = vec![0_u8; remaining.min(64 * 1024) as usize];
            let read_deadline = (tokio::time::Instant::now() + read_timeout).min(download_deadline);
            let read = match tokio::time::timeout_at(read_deadline, reader.read(&mut chunk)).await {
                Ok(Ok(read)) if read > 0 => read,
                Ok(Ok(_)) => {
                    let _ = sender.try_send(Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "upload object ended before its committed size",
                    )));
                    return;
                }
                Ok(Err(error)) => {
                    let _ = sender.try_send(Err(error));
                    return;
                }
                Err(_) => return,
            };
            chunk.truncate(read);
            remaining -= read as u64;
            // The same total deadline covers downstream socket backpressure:
            // a full two-chunk channel cannot retain the store reader/permit.
            if tokio::time::timeout_at(download_deadline, sender.send(Ok(Bytes::from(chunk))))
                .await
                .is_err()
            {
                return;
            }
        }
    });
    let stream = futures::stream::unfold(receiver, |mut receiver| async move {
        receiver.recv().await.map(|item| (item, receiver))
    });
    let body = Body::from_stream(stream);

    Ok((response_headers, body).into_response())
}

pub async fn upload_delete(
    State(state): State<Arc<AppState>>,
    axum::Extension(request_id): axum::Extension<crate::api::ApiRequestId>,
    crate::api::ApiPath(id): crate::api::ApiPath<Uuid>,
    headers: HeaderMap,
) -> Result<StatusCode, AppError> {
    let _operation_timer = state
        .metrics
        .upload_operation_duration_seconds
        .start_timer();
    let user = crate::api::current_user(&state, &headers).await?;
    // DELETE is deliberately idempotent and non-enumerating: a missing slot
    // or another user's UUID returns the same 204 while changing no state.
    // An owned row is atomically removed from the public namespace, audited,
    // and queued for retryable object-store cleanup.
    match state
        .upload_service()
        .delete_authorized(
            user.id,
            user.auth_generation,
            user.session_token(),
            id,
            request_id.0,
        )
        .await?
    {
        UserUploadDeleteOutcome::Accepted => Ok(StatusCode::NO_CONTENT),
        UserUploadDeleteOutcome::Unauthorized => Err(AppError::Unauthorized),
    }
}

async fn release_claim(state: &AppState, id: Uuid, claim_token: Uuid) -> Result<(), AppError> {
    if !state
        .upload_service()
        .release_claim(id, claim_token)
        .await?
    {
        tracing::warn!(upload_id = %id, "upload claim was already absent while releasing it");
    }
    Ok(())
}

async fn release_claim_best_effort(state: &AppState, id: Uuid, claim_token: Uuid) {
    if let Err(error) = release_claim(state, id, claim_token).await {
        tracing::error!(upload_id = %id, ?error, "failed to release upload claim");
    }
}

async fn abort_stage_best_effort(
    state: &AppState,
    id: Uuid,
    claim_token: Uuid,
    stage_version: Option<&str>,
) {
    if let Err(error) = tokio::time::timeout(
        Duration::from_secs(UPLOAD_PROMOTION_MAX_SECONDS),
        state
            .upload_store()
            .abort(&id.to_string(), &claim_token.to_string(), stage_version),
    )
    .await
    .map_err(|_| anyhow::anyhow!("upload stage cleanup timed out"))
    .and_then(|result| result)
    {
        tracing::error!(upload_id = %id, ?error, "failed to remove fenced upload stage");
    }
}

#[cfg(test)]
mod tests {
    use super::{validate_upload_framing_headers, write_with_lease};
    use axum::http::{header, HeaderMap, HeaderValue};
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    };
    use std::task::{Context, Poll};

    struct PendingOperation(Arc<AtomicBool>);

    impl Future for PendingOperation {
        type Output = ();
        fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<()> {
            Poll::Pending
        }
    }

    impl Drop for PendingOperation {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    #[tokio::test]
    async fn upload_cancellation_drops_write_and_lease_renewal() {
        let write_dropped = Arc::new(AtomicBool::new(false));
        let renewal_dropped = Arc::new(AtomicBool::new(false));
        let mut request = Box::pin(write_with_lease(
            PendingOperation(write_dropped.clone()),
            PendingOperation(renewal_dropped.clone()),
        ));
        assert!(futures::poll!(&mut request).is_pending());
        drop(request);
        assert!(write_dropped.load(Ordering::SeqCst));
        assert!(renewal_dropped.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn upload_completion_stops_renewal_and_lease_loss_stops_writing() {
        let renewal_dropped = Arc::new(AtomicBool::new(false));
        assert_eq!(
            write_with_lease(async { 42 }, PendingOperation(renewal_dropped.clone())).await,
            Some(42)
        );
        assert!(renewal_dropped.load(Ordering::SeqCst));
        let write_dropped = Arc::new(AtomicBool::new(false));
        assert_eq!(
            write_with_lease(PendingOperation(write_dropped.clone()), async {}).await,
            None
        );
        assert!(write_dropped.load(Ordering::SeqCst));
    }

    #[test]
    fn upload_framing_rejects_ambiguous_encodings_and_ranges() {
        let mut headers = HeaderMap::new();
        assert!(validate_upload_framing_headers(&headers).is_ok());
        headers.insert(
            header::CONTENT_ENCODING,
            HeaderValue::from_static("identity"),
        );
        assert!(validate_upload_framing_headers(&headers).is_ok());

        headers.insert(header::CONTENT_ENCODING, HeaderValue::from_static("gzip"));
        assert!(validate_upload_framing_headers(&headers).is_err());
        headers.clear();
        headers.insert(
            header::CONTENT_RANGE,
            HeaderValue::from_static("bytes 0-3/4"),
        );
        assert!(validate_upload_framing_headers(&headers).is_err());

        headers.clear();
        headers.append(
            header::CONTENT_ENCODING,
            HeaderValue::from_static("identity"),
        );
        headers.append(
            header::CONTENT_ENCODING,
            HeaderValue::from_static("identity"),
        );
        assert!(validate_upload_framing_headers(&headers).is_err());
    }
}
