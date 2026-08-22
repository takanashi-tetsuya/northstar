use axum::body::Body;
use axum::http::header::HeaderValue;
use axum::http::HeaderMap;
use axum::{
    extract::{Path, State},
    http::{header, StatusCode},
    response::{IntoResponse, Response},
};
use futures::TryStreamExt;
use std::sync::Arc;
use uuid::Uuid;

use crate::auth;
use crate::db;
use crate::error::{AppError, Result};
use crate::state::AppState;

pub async fn upload_put(
    State(state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
    body: Body,
) -> Result<StatusCode, AppError> {
    let token = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .ok_or(AppError::Unauthorized)?;
    let slot = db::upload_slot_for_put(&state.pool, id, &auth::token_hash(token))
        .await?
        .ok_or(AppError::Unauthorized)?;
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("application/octet-stream");
    if !content_type.eq_ignore_ascii_case(&slot.content_type) {
        return Err(AppError::BadRequest(
            "upload content type does not match the reserved slot".into(),
        ));
    }

    let stream = body.into_data_stream().map_err(std::io::Error::other);
    let async_read = tokio_util::io::StreamReader::new(stream);
    let bytes_written = state
        .upload_store
        .put(&slot.id.to_string(), Box::new(async_read), slot.size as u64)
        .await
        .map_err(AppError::Internal)?;

    if bytes_written != slot.size as u64 {
        return Err(AppError::BadRequest(
            "upload length does not match the reserved slot".into(),
        ));
    }
    if let Err(error) = db::complete_upload(&state.pool, slot.id).await {
        let _ = state.upload_store.delete(&slot.id.to_string()).await;
        return Err(error.into());
    }
    Ok(StatusCode::CREATED)
}

pub async fn upload_get(
    State(state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
) -> Result<Response, AppError> {
    let Some(slot) = db::uploaded_file(&state.pool, id).await? else {
        return Ok(StatusCode::NOT_FOUND.into_response());
    };
    let Some((reader, size)) = state
        .upload_store
        .get(&slot.id.to_string())
        .await
        .map_err(AppError::Internal)?
    else {
        return Ok(StatusCode::NOT_FOUND.into_response());
    };
    if size as i64 != slot.size {
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
        HeaderValue::from_str(&size.to_string())
            .map_err(|error| AppError::Internal(error.into()))?,
    );
    response_headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=31536000, immutable"),
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

    let stream = tokio_util::io::ReaderStream::new(reader);
    let body = Body::from_stream(stream);

    Ok((response_headers, body).into_response())
}
