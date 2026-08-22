use crate::api::*;
use axum::http::HeaderMap;
use axum::{
    extract::{Query, State},
    Json,
};
use serde_json::json;
use serde_json::Value;
use std::sync::Arc;

use crate::auth;
use crate::db;
use crate::error::{AppError, Result};
use crate::state::AppState;

pub async fn me(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<Value>, AppError> {
    let user = current_user(&state, &headers).await?;
    Ok(Json(
        json!({"id":user.id,"jid":format!("{}@{}",user.username,state.config.domain),"display_name":user.display_name,"is_admin":user.is_admin}),
    ))
}

pub async fn change_password(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<PasswordChange>,
) -> Result<Json<Value>, AppError> {
    let user = current_user(&state, &headers).await?;
    if db::authenticate(
        &state.pool,
        &user.username,
        &body.current_password,
        state.config.scram_iterations,
    )
    .await?
    .is_none()
    {
        return Err(AppError::Unauthorized);
    }
    auth::validate_password(&body.new_password)
        .map_err(|error| AppError::BadRequest(error.to_string()))?;
    db::change_password(
        &state.pool,
        user.id,
        &body.new_password,
        state.config.scram_iterations,
    )
    .await?;
    db::audit(
        &state.pool,
        Some(user.id),
        "user.password.change",
        Some(&user.username),
        json!({}),
    )
    .await?;
    Ok(Json(json!({"changed":true,"sessions_revoked":true})))
}

pub async fn history(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(query): Query<HistoryQuery>,
) -> Result<Json<Value>, AppError> {
    let user = current_user(&state, &headers).await?;
    let rows = db::list_archive(
        &state.pool,
        user.id,
        query.with.as_deref(),
        query.limit.unwrap_or(100),
    )
    .await?;
    let all_end_to_end_encrypted = rows.iter().all(|row| row.encrypted);
    Ok(Json(json!({
        "messages":rows,
        "all_end_to_end_encrypted":all_end_to_end_encrypted,
        "archive_policy":if state.config.require_encrypted_archive {"encrypted_only"} else {"all"}
    })))
}
