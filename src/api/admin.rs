use crate::api::*;
use axum::http::HeaderMap;
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Json,
};
use serde_json::json;
use serde_json::Value;
use std::sync::Arc;
use uuid::Uuid;

use crate::db;
use crate::error::{AppError, Result};
use crate::state::AppState;
use crate::api::models::{NukeRequest, ServerNamePatch, BooleanToggle, SessionView, OfflineMessagesStats, MucRoomView, BroadcastRequest};

pub async fn admin_stats(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<Value>, AppError> {
    let _ = admin(&state, &headers).await?;
    let (users, archived, offline) = db::counts(&state.pool).await?;
    let (rooms, uploads, push_subscriptions) = db::operational_counts(&state.pool).await?;
    let (pending_reports, pending_appeals, active_invitations) =
        db::moderation_counts(&state.pool).await?;
    Ok(Json(json!({
        "users":users, "online_sessions":state.sessions.len(), "archived_stanzas":archived,
        "offline_stanzas":offline, "uptime_seconds":state.started_at.elapsed().as_secs(),
        "archive_policy":if state.config.require_encrypted_archive {"encrypted_only"} else {"all"},
        "rooms":rooms, "room_occupants":state.muc_occupants.len(), "uploaded_files":uploads,
        "push_subscriptions":push_subscriptions, "federation_enabled":state.config.federation_enabled,
        "federation_inbound_connections":state.metrics.federation_inbound_connections_total.load(std::sync::atomic::Ordering::Relaxed),
        "federation_outbound_deliveries":state.metrics.federation_outbound_deliveries_total.load(std::sync::atomic::Ordering::Relaxed),
        "federation_failures":state.metrics.federation_failures_total.load(std::sync::atomic::Ordering::Relaxed),
        "pending_reports":pending_reports, "pending_appeals":pending_appeals,
        "active_invitations":active_invitations,
        "anti_abuse_challenges":state.metrics.anti_abuse_challenges_total.load(std::sync::atomic::Ordering::Relaxed),
        "rate_limited_operations":state.metrics.rate_limited_total.load(std::sync::atomic::Ordering::Relaxed),
        "reports_created":state.metrics.reports_total.load(std::sync::atomic::Ordering::Relaxed),
        "appeals_created":state.metrics.appeals_total.load(std::sync::atomic::Ordering::Relaxed)
    })))
}

pub async fn admin_users(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(page): Query<Page>,
) -> Result<Json<Value>, AppError> {
    let _ = admin(&state, &headers).await?;
    let users = db::list_users(
        &state.pool,
        page.limit.unwrap_or(100).clamp(1, 200),
        page.offset.unwrap_or(0).max(0),
    )
    .await?;
    Ok(Json(json!({"users":users})))
}

pub async fn admin_update_user(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(body): Json<UserPatch>,
) -> Result<Json<Value>, AppError> {
    let actor = admin(&state, &headers).await?;
    if actor.id == id && body.disabled == Some(true) {
        return Err(AppError::BadRequest(
            "an administrator cannot disable their current account".into(),
        ));
    }
    if actor.id == id && body.admin == Some(false) {
        return Err(AppError::BadRequest(
            "an administrator cannot remove their own privileges".into(),
        ));
    }
    let updated = db::set_user_status(&state.pool, id, body.disabled, body.admin).await?;
    if !updated {
        return Err(AppError::BadRequest("user does not exist".into()));
    }
    db::audit(
        &state.pool,
        Some(actor.id),
        "admin.user.update",
        Some(&id.to_string()),
        json!({"disabled":body.disabled,"admin":body.admin}),
    )
    .await?;
    Ok(Json(json!({"updated":true})))
}

pub async fn admin_reports(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<Value>, AppError> {
    let _ = admin(&state, &headers).await?;
    Ok(Json(
        json!({"reports":db::list_reports(&state.pool, None, 200).await?}),
    ))
}

pub async fn admin_update_report(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(body): Json<ModerationPatch>,
) -> Result<Json<Value>, AppError> {
    let actor = admin(&state, &headers).await?;
    if !matches!(
        body.status.as_str(),
        "submitted" | "reviewing" | "actioned" | "rejected" | "closed"
    ) {
        return Err(AppError::BadRequest("invalid report status".into()));
    }
    let resolution = body.resolution.unwrap_or_default();
    if resolution.len() > 8000
        || (matches!(body.status.as_str(), "actioned" | "rejected" | "closed")
            && resolution.trim().is_empty())
    {
        return Err(AppError::BadRequest(
            "a resolution is required when resolving a report".into(),
        ));
    }
    if !db::admin_update_report(&state.pool, id, actor.id, &body.status, resolution.trim()).await? {
        return Err(AppError::BadRequest("report does not exist".into()));
    }
    db::audit(
        &state.pool,
        Some(actor.id),
        "admin.report.update",
        Some(&id.to_string()),
        json!({"status":body.status}),
    )
    .await?;
    Ok(Json(json!({"updated":true})))
}

pub async fn admin_update_appeal(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(body): Json<ModerationPatch>,
) -> Result<Json<Value>, AppError> {
    let actor = admin(&state, &headers).await?;
    if !matches!(
        body.status.as_str(),
        "submitted" | "reviewing" | "upheld" | "denied"
    ) {
        return Err(AppError::BadRequest("invalid appeal status".into()));
    }
    let resolution = body.resolution.unwrap_or_default();
    if resolution.len() > 8000
        || (matches!(body.status.as_str(), "upheld" | "denied") && resolution.trim().is_empty())
    {
        return Err(AppError::BadRequest(
            "a resolution is required when resolving an appeal".into(),
        ));
    }
    if !db::admin_update_appeal(&state.pool, id, actor.id, &body.status, resolution.trim()).await? {
        return Err(AppError::BadRequest("appeal does not exist".into()));
    }
    db::audit(
        &state.pool,
        Some(actor.id),
        "admin.appeal.update",
        Some(&id.to_string()),
        json!({"status":body.status}),
    )
    .await?;
    Ok(Json(json!({"updated":true})))
}

pub async fn admin_tls_reload(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<Value>, AppError> {
    let actor = admin(&state, &headers).await?;
    state.tls.reload().map_err(AppError::Internal)?;
    db::audit(
        &state.pool,
        Some(actor.id),
        "admin.tls.reload",
        None,
        json!({}),
    )
    .await?;
    Ok(Json(json!({"reloaded":true})))
}

pub async fn admin_invitations(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<Value>, AppError> {
    let _ = admin(&state, &headers).await?;
    Ok(Json(
        json!({"invitations":db::list_invitations(&state.pool).await?,"required":state.config.invitation_required}),
    ))
}

pub async fn admin_create_invitation(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<InvitationRequest>,
) -> Result<(StatusCode, Json<Value>), AppError> {
    let actor = admin(&state, &headers).await?;
    let label = body.label.trim();
    if label.is_empty() || label.len() > 128 {
        return Err(AppError::BadRequest("invitation label is invalid".into()));
    }
    let max_uses = body.max_uses.unwrap_or(1);
    if !(1..=100_000).contains(&max_uses) {
        return Err(AppError::BadRequest(
            "invitation max uses is invalid".into(),
        ));
    }
    let expires_at = body
        .expires_in_hours
        .map(|hours| chrono::Utc::now() + chrono::Duration::hours(hours.clamp(1, 8760).into()));
    let (id, token) =
        db::create_invitation(&state.pool, actor.id, label, max_uses, expires_at).await?;
    db::audit(
        &state.pool,
        Some(actor.id),
        "admin.invitation.create",
        Some(&id.to_string()),
        json!({"label":label,"max_uses":max_uses}),
    )
    .await?;
    Ok((
        StatusCode::CREATED,
        Json(json!({"id":id,"token":token,"shown_once":true})),
    ))
}

pub async fn admin_revoke_invitation(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<Value>, AppError> {
    let actor = admin(&state, &headers).await?;
    if !db::revoke_invitation(&state.pool, id).await? {
        return Err(AppError::BadRequest("invitation does not exist".into()));
    }
    db::audit(
        &state.pool,
        Some(actor.id),
        "admin.invitation.revoke",
        Some(&id.to_string()),
        json!({}),
    )
    .await?;
    Ok(Json(json!({"revoked":true})))
}

pub async fn admin_nuke(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<NukeRequest>,
) -> Result<Json<Value>, AppError> {
    let _actor = admin(&state, &headers).await?;
    if body.confirm_phrase != "I understand this will delete all data" {
        return Err(AppError::BadRequest("invalid confirm phrase".into()));
    }
    
    // Nuke database
    db::nuke_everything(&state.pool).await?;
    
    // Clear in-memory state
    state.sessions.clear();
    state.resumable_sessions.clear();
    state.muc_occupants.clear();
    state.s2s_outbound_connections.clear();
    
    // Clear upload directory
    let _ = std::fs::remove_dir_all(&state.config.upload_dir);
    let _ = std::fs::create_dir_all(&state.config.upload_dir);
    
    // Restore bootstrap admin
    db::ensure_bootstrap_admin(&state.pool, &state.config).await?;
    
    Ok(Json(json!({"nuked": true})))
}

pub async fn admin_rename_server(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<ServerNamePatch>,
) -> Result<Json<Value>, AppError> {
    let actor = admin(&state, &headers).await?;
    
    // Modify .env file
    let env_path = std::path::Path::new(".env");
    if env_path.exists() {
        let content = std::fs::read_to_string(env_path).unwrap_or_default();
        let mut lines: Vec<&str> = content.lines().collect();
        let mut found = false;
        let new_line = format!("SERVER_NAME={}", body.server_name.trim());
        for line in &mut lines {
            if line.starts_with("SERVER_NAME=") {
                *line = &new_line;
                found = true;
                break;
            }
        }
        
        let mut new_content = lines.join("\n");
        if !found {
            new_content.push_str("\n");
            new_content.push_str(&new_line);
            new_content.push_str("\n");
        }
        let _ = std::fs::write(env_path, new_content);
    }
    
    db::audit(
        &state.pool,
        Some(actor.id),
        "admin.server.rename",
        None,
        json!({"new_name": body.server_name}),
    )
    .await?;
    
    Ok(Json(json!({"server_name": body.server_name, "message": "Server name updated in .env (requires restart)"})))
}

pub async fn admin_panic_disconnect(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<Value>, AppError> {
    let actor = admin(&state, &headers).await?;
    
    // Drop all online session channels to force disconnects
    let sessions_count = state.sessions.len();
    state.sessions.clear();
    state.resumable_sessions.clear();
    
    db::audit(
        &state.pool,
        Some(actor.id),
        "admin.panic.disconnect",
        None,
        json!({"sessions_dropped": sessions_count}),
    )
    .await?;
    
    Ok(Json(json!({"sessions_dropped": sessions_count, "message": "All users forced offline"})))
}


pub async fn admin_toggle_island_mode(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<BooleanToggle>,
) -> Result<Json<Value>, AppError> {
    let actor = admin(&state, &headers).await?;
    state.island_mode.store(body.enabled, std::sync::atomic::Ordering::Relaxed);
    
    if body.enabled {
        // Disconnect all current outbound S2S federation links
        state.s2s_outbound_connections.clear();
    }
    
    db::audit(
        &state.pool,
        Some(actor.id),
        "admin.island_mode.toggle",
        None,
        json!({"enabled": body.enabled}),
    )
    .await?;
    
    Ok(Json(json!({"island_mode": body.enabled})))
}

pub async fn admin_toggle_registration(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<BooleanToggle>,
) -> Result<Json<Value>, AppError> {
    let actor = admin(&state, &headers).await?;
    state.registration_closed.store(!body.enabled, std::sync::atomic::Ordering::Relaxed);
    
    db::audit(
        &state.pool,
        Some(actor.id),
        "admin.registration.toggle",
        None,
        json!({"open": body.enabled}),
    )
    .await?;
    
    Ok(Json(json!({"open_registration": body.enabled})))
}

pub async fn admin_sessions(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<Vec<SessionView>>, AppError> {
    let _actor = admin(&state, &headers).await?;
    let mut views = Vec::new();
    let now = std::time::Instant::now();
    for entry in state.sessions.iter() {
        let jid = entry.key().clone();
        let session = entry.value();
        views.push(SessionView {
            jid,
            ip: session.ip.map(|ip| ip.to_string()),
            resource: session.resource.clone(),
            connected_duration_seconds: now.saturating_duration_since(session.connected_at).as_secs(),
        });
    }
    Ok(Json(views))
}

pub async fn admin_kick_session(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(jid): Path<String>,
) -> Result<Json<Value>, AppError> {
    let actor = admin(&state, &headers).await?;
    
    // Removing it drops the Sender and breaks the connection loop
    let kicked = state.sessions.remove(&jid).is_some();
    
    if kicked {
        db::audit(
            &state.pool,
            Some(actor.id),
            "admin.session.kick",
            Some(&jid),
            json!({}),
        ).await?;
    }
    
    Ok(Json(json!({"kicked": kicked})))
}

pub async fn admin_offline_messages_stats(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<OfflineMessagesStats>, AppError> {
    let _actor = admin(&state, &headers).await?;
    
    let row: (i64, i64) = sqlx::query_as(
        "SELECT COUNT(*), COALESCE(SUM(LENGTH(stanza)), 0) FROM offline_messages"
    )
    .fetch_one(&state.pool)
    .await?;
    
    Ok(Json(OfflineMessagesStats {
        total_messages: row.0,
        estimated_bytes: row.1,
    }))
}

pub async fn admin_clear_offline_messages(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<Value>, AppError> {
    let actor = admin(&state, &headers).await?;
    
    let _result = sqlx::query("TRUNCATE TABLE offline_messages")
        .execute(&state.pool)
        .await?;
        
    db::audit(
        &state.pool,
        Some(actor.id),
        "admin.offline_messages.clear",
        None,
        json!({}),
    ).await?;
    
    Ok(Json(json!({"cleared": true})))
}

pub async fn admin_muc_rooms(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<Vec<MucRoomView>>, AppError> {
    let _actor = admin(&state, &headers).await?;
    
    let rows = sqlx::query("SELECT localpart, title, created_at, public, persistent, members_only, moderated, non_anonymous FROM muc_rooms ORDER BY created_at DESC")
        .fetch_all(&state.pool)
        .await?;
        
    let mut views = Vec::new();
    for row in rows {
        use sqlx::Row;
        let localpart: String = row.get("localpart");
        let title: Option<String> = row.get("title");
        let created_at: chrono::DateTime<chrono::Utc> = row.get("created_at");
        let public: bool = row.get("public");
        let persistent: bool = row.get("persistent");
        let members_only: bool = row.get("members_only");
        let moderated: bool = row.get("moderated");
        let non_anonymous: bool = row.get("non_anonymous");
        
        let occupants = state.muc_occupants.iter()
            .filter(|occ| occ.room_jid == format!("{}@conference.{}", localpart, state.config.domain))
            .count();
            
        views.push(MucRoomView {
            localpart,
            title,
            created_at,
            public,
            persistent,
            members_only,
            moderated,
            non_anonymous,
            current_occupants: occupants,
        });
    }
    
    Ok(Json(views))
}

pub async fn admin_destroy_muc_room(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(localpart): Path<String>,
) -> Result<Json<Value>, AppError> {
    let actor = admin(&state, &headers).await?;
    
    let result = sqlx::query("DELETE FROM muc_rooms WHERE localpart = $1")
        .bind(&localpart)
        .execute(&state.pool)
        .await?;
        
    if result.rows_affected() > 0 {
        // Drop occupants
        let room_domain = format!("conference.{}", state.config.domain);
        let room_jid = format!("{}@{}", localpart, room_domain);
        state.muc_occupants.retain(|_, occ| occ.room_jid != room_jid);
        
        db::audit(
            &state.pool,
            Some(actor.id),
            "admin.muc_room.destroy",
            Some(&localpart),
            json!({}),
        ).await?;
    }
    
    Ok(Json(json!({"destroyed": result.rows_affected() > 0})))
}

pub async fn admin_broadcast(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<BroadcastRequest>,
) -> Result<Json<Value>, AppError> {
    let actor = admin(&state, &headers).await?;
    
    let message = format!(
        "<message from='{}' type='headline' id='{}'><body>{}</body></message>",
        crate::state::attr_escape(&state.config.domain),
        uuid::Uuid::new_v4(),
        crate::state::attr_escape(&body.message)
    );
    
    let mut sent_count = 0;
    for entry in state.sessions.iter() {
        let session = entry.value();
        if let Ok(_) = session.sender.try_send(message.clone()) {
            sent_count += 1;
        }
    }
    
    db::audit(
        &state.pool,
        Some(actor.id),
        "admin.broadcast",
        None,
        json!({"recipients": sent_count, "length": body.message.len()}),
    ).await?;
    
    Ok(Json(json!({"sent": sent_count})))
}



