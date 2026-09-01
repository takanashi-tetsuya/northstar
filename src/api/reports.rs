use crate::api::*;
use axum::http::HeaderMap;
use axum::{
    extract::{ConnectInfo, State},
    http::StatusCode,
    response::Response,
    Json,
};
use serde_json::json;
use serde_json::Value;
use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;
use uuid::Uuid;

use crate::abuse::{AbuseAction, GuardError, TransactionalGuardOutcome};
use crate::api::idempotency::StoredHttpResponse;
use crate::db;
use crate::error::{AppError, Result};
use crate::state::AppState;

const MAX_DESCRIPTION_CHARS: usize = 4_000;
const MAX_DESCRIPTION_BYTES: usize = MAX_DESCRIPTION_CHARS * 4;
const MAX_EVIDENCE_BODY_CHARS: usize = 8_000;
const MAX_EVIDENCE_BODY_BYTES: usize = MAX_EVIDENCE_BODY_CHARS * 4;
const MAX_CLIENT_MESSAGE_ID_CHARS: usize = 128;
const MAX_CLIENT_MESSAGE_ID_BYTES: usize = MAX_CLIENT_MESSAGE_ID_CHARS * 4;

fn is_bidi_override(character: char) -> bool {
    // Ordinary RTL letters, marks and modern isolate controls remain valid.
    // Only the two directional overrides are rejected because they can make
    // moderation text display in an order different from its stored order.
    matches!(character, '\u{202d}' | '\u{202e}')
}

fn valid_user_text(value: &str, min_chars: usize, max_chars: usize, max_bytes: usize) -> bool {
    let count = value.chars().count();
    (min_chars..=max_chars).contains(&count)
        && value.len() <= max_bytes
        && !value.chars().any(|character| {
            (character.is_control() && !matches!(character, '\t' | '\n' | '\r'))
                || is_bidi_override(character)
        })
}

fn valid_client_message_id(value: &str) -> bool {
    let count = value.chars().count();
    (1..=MAX_CLIENT_MESSAGE_ID_CHARS).contains(&count)
        && value.len() <= MAX_CLIENT_MESSAGE_ID_BYTES
        && !value
            .chars()
            .any(|character| character.is_control() || is_bidi_override(character))
}

pub(crate) fn report_validation_error(body: &ReportRequest) -> Option<&'static str> {
    if crate::jid::canonical_bare_key(body.reported_jid.trim())
        .ok()
        .filter(|jid| jid.contains('@'))
        .is_none()
    {
        return Some("reported JID is invalid");
    }
    if !matches!(
        body.category.as_str(),
        "spam" | "harassment" | "threat" | "impersonation" | "illegal" | "other"
    ) {
        return Some("report category is invalid");
    }
    if body.evidence.is_empty() || body.evidence.len() > 20 {
        return Some("select between 1 and 20 messages as evidence");
    }
    let description = body.description.as_deref().unwrap_or_default().trim();
    if !valid_user_text(description, 0, MAX_DESCRIPTION_CHARS, MAX_DESCRIPTION_BYTES) {
        return Some("report description is invalid");
    }
    let mut archive_ids = HashSet::with_capacity(body.evidence.len());
    for item in &body.evidence {
        if !archive_ids.insert(item.archive_id)
            || !valid_user_text(
                &item.body_text,
                1,
                MAX_EVIDENCE_BODY_CHARS,
                MAX_EVIDENCE_BODY_BYTES,
            )
            || item.body_text.trim().is_empty()
            || item
                .client_message_id
                .as_deref()
                .is_some_and(|id| !valid_client_message_id(id))
        {
            return Some("report evidence is invalid");
        }
    }
    None
}

fn appeal_validation_error(reason: &str) -> Option<&'static str> {
    if valid_user_text(reason, 20, MAX_DESCRIPTION_CHARS, MAX_DESCRIPTION_BYTES) {
        None
    } else {
        Some("appeal reason must be between 20 and 4000 safe Unicode characters")
    }
}

pub(crate) async fn complete_api_error(
    state: &AppState,
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    lease: &db::IdempotencyLease,
    status: StatusCode,
    code: &str,
    message: &str,
) -> Result<Response, AppError> {
    let stored_response = StoredHttpResponse::json(
        status,
        json!({
            "error": {"code": code, "message": message}
        }),
    )?;
    if !stored_response
        .persist_in_tx(state.api_control(), tx, lease)
        .await?
    {
        return Err(AppError::Internal(anyhow::anyhow!(
            "idempotency lease changed while recording an API error"
        )));
    }
    stored_response.build_response()
}

pub(crate) async fn complete_guard_denial(
    state: &AppState,
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    lease: &db::IdempotencyLease,
    error: GuardError,
) -> Result<Response, AppError> {
    let requirement = error.requirement();
    let retry_after = requirement
        .retry_after_seconds
        .max(requirement.hard_wait_seconds);
    let details = json!({
        "message": error.message(),
        "requirement": requirement,
    });
    let mut stored_response = StoredHttpResponse::json(
        StatusCode::TOO_MANY_REQUESTS,
        json!({
            "error": {
                "code": "rate_limited",
                "message": "operation requires proof of work or cooldown",
                "details": details,
            }
        }),
    )?;
    if retry_after > 0 {
        stored_response = stored_response.with_header("retry-after", retry_after.to_string());
    }
    if !stored_response
        .persist_in_tx(state.api_control(), tx, lease)
        .await?
    {
        return Err(AppError::Internal(anyhow::anyhow!(
            "idempotency lease changed while recording a rate-limit denial"
        )));
    }
    stored_response.build_response()
}

pub async fn create_report(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    request: ApiJson<ReportRequest>,
) -> Result<Response, AppError> {
    let user = current_user(&state, &headers).await?;
    let body = &request.value;
    // Semantic failures are intentionally recorded only after the one-use
    // PoW and exact idempotency guard are consumed in the same transaction.
    // This prevents malformed Unicode from becoming a free, unmetered retry
    // path while ensuring PostgreSQL never sees a NUL-containing string.
    let validation_error = report_validation_error(body);
    let description = body
        .description
        .as_deref()
        .unwrap_or_default()
        .trim()
        .to_owned();
    let peer_ip = client_ip(peer.ip(), &headers, &state);
    let (subject, actors) = abuse_identity(AbuseAction::Report, peer_ip, Some(&user));
    let mut tx = state.pool.begin().await?;
    if !db::authorize_user_in_tx(&mut tx, user.id, user.auth_generation, user.session_token())
        .await?
    {
        tx.rollback().await?;
        return Err(AppError::Unauthorized);
    }
    let lease = match db::acquire_idempotency_in_tx(
        state.api_control(),
        &mut tx,
        &request.idempotency(
            Some(user.id),
            user.id.as_bytes(),
            db::ApiPrincipalKind::User,
            "POST",
            "/api/v1/reports",
        ),
    )
    .await?
    {
        db::IdempotencyAcquire::Acquired(lease) => lease,
        db::IdempotencyAcquire::Replay(replay) => {
            tx.commit().await?;
            return idempotency_replay_response(replay);
        }
        db::IdempotencyAcquire::FingerprintConflict | db::IdempotencyAcquire::RotationConflict => {
            tx.rollback().await?;
            return Err(AppError::IdempotencyConflict);
        }
        db::IdempotencyAcquire::ReplayInvalidated => {
            tx.rollback().await?;
            return Err(AppError::IdempotencyReplayInvalidated);
        }
        db::IdempotencyAcquire::Busy {
            retry_after_seconds,
        } => {
            tx.rollback().await?;
            return Err(AppError::IdempotencyBusy {
                retry_after: retry_after_seconds,
            });
        }
        db::IdempotencyAcquire::CapacityLimited {
            retry_after_seconds,
        } => {
            tx.rollback().await?;
            return Err(AppError::TooManyRequests {
                message: "too many retained requests; try again later".into(),
                retry_after: retry_after_seconds,
            });
        }
        db::IdempotencyAcquire::InProgress {
            retry_after_seconds,
        } => {
            tx.rollback().await?;
            return Err(AppError::IdempotencyInProgress {
                retry_after: retry_after_seconds,
            });
        }
    };
    if !lease.guard_verified {
        let pow_intent = body.pow_intent();
        match state
            .abuse
            .verify_or_allow_in_tx_v2(
                &mut tx,
                AbuseAction::Report,
                &subject,
                &actors,
                body.pow.as_ref(),
                &pow_intent,
            )
            .await?
        {
            TransactionalGuardOutcome::Allowed(_) => {
                if !db::mark_idempotency_guard_verified_in_tx(&mut tx, &lease).await? {
                    return Err(AppError::Internal(anyhow::anyhow!(
                        "report idempotency guard lease changed"
                    )));
                }
            }
            TransactionalGuardOutcome::DeniedNeedsCommit(error) => {
                let response = complete_guard_denial(&state, &mut tx, &lease, error).await?;
                tx.commit().await?;
                state
                    .metrics
                    .rate_limited_total
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                return Ok(response);
            }
        }
    }
    if let Some(message) = validation_error {
        let response = complete_api_error(
            &state,
            &mut tx,
            &lease,
            StatusCode::BAD_REQUEST,
            "bad_request",
            message,
        )
        .await?;
        tx.commit().await?;
        return Ok(response);
    }
    let reported_jid = crate::jid::canonical_bare_key(body.reported_jid.trim())
        .expect("validated report JID is canonicalizable");
    let evidence = body
        .evidence
        .iter()
        .map(|item| db::ReportEvidenceInput {
            archive_id: item.archive_id,
            client_message_id: item.client_message_id.clone(),
            body_text: item.body_text.clone(),
        })
        .collect::<Vec<_>>();
    let id = match db::create_report_in_tx(
        &mut tx,
        user.id,
        &reported_jid,
        &body.category,
        &description,
        &evidence,
        Some(lease.request_id),
    )
    .await
    {
        Ok(id) => id,
        Err(db::ReportCreateError::InvalidEvidence(_)) => {
            let response = complete_api_error(
                &state,
                &mut tx,
                &lease,
                StatusCode::BAD_REQUEST,
                "bad_request",
                "report evidence is invalid",
            )
            .await?;
            tx.commit().await?;
            return Ok(response);
        }
        Err(db::ReportCreateError::Internal(error)) => return Err(AppError::Internal(error)),
    };
    let stored_response =
        StoredHttpResponse::json(StatusCode::CREATED, json!({"id":id,"status":"submitted"}))?;
    if !stored_response
        .persist_in_tx(state.api_control(), &mut tx, &lease)
        .await?
    {
        return Err(AppError::Internal(anyhow::anyhow!(
            "report idempotency lease changed"
        )));
    }
    tx.commit().await?;
    state
        .metrics
        .reports_total
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    stored_response.build_response()
}

pub async fn my_reports(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    ApiQuery(query): ApiQuery<ReportPageQuery>,
) -> Result<Json<Value>, AppError> {
    let user = current_user(&state, &headers).await?;
    let limit = pagination::checked_limit(query.limit, 25, 25)?;
    let status = pagination::checked_report_status(query.status.as_deref())?;
    let filter = pagination::one_filter_scope("status", status)?;
    let binding = pagination::pg_binding("reports/own", user.id.as_bytes(), &filter);
    let after = pagination::pg_boundary(&state, query.cursor.as_deref(), &binding).await?;
    let mut read_tx = user.begin_authorized_read(&state).await?;
    let page = db::own_reports_page_in_tx(&mut read_tx, user.id, status, after, limit).await?;
    read_tx.commit().await?;
    let next_cursor = pagination::issue_pg_cursor(&state, &binding, page.next, page.database_now)?;
    Ok(Json(json!({
        "reports":page.rows,
        "limit":limit,
        "next_cursor":next_cursor
    })))
}

pub async fn create_appeal(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    ApiPath(report_id): ApiPath<Uuid>,
    request: ApiJson<AppealRequest>,
) -> Result<Response, AppError> {
    let user = current_user(&state, &headers).await?;
    let body = &request.value;
    let reason = body.reason.trim();
    let validation_error = appeal_validation_error(reason);
    let peer_ip = client_ip(peer.ip(), &headers, &state);
    let (subject, actors) = abuse_identity(AbuseAction::Appeal, peer_ip, Some(&user));
    let mut idempotency = request.idempotency(
        Some(user.id),
        user.id.as_bytes(),
        db::ApiPrincipalKind::User,
        "POST",
        "/api/v1/reports/{id}/appeals",
    );
    idempotency.target_scope = report_id.as_bytes();
    let mut tx = state.pool.begin().await?;
    if !db::authorize_user_in_tx(&mut tx, user.id, user.auth_generation, user.session_token())
        .await?
    {
        tx.rollback().await?;
        return Err(AppError::Unauthorized);
    }
    let lease = match db::acquire_idempotency_in_tx(state.api_control(), &mut tx, &idempotency)
        .await?
    {
        db::IdempotencyAcquire::Acquired(lease) => lease,
        db::IdempotencyAcquire::Replay(replay) => {
            tx.commit().await?;
            return idempotency_replay_response(replay);
        }
        db::IdempotencyAcquire::FingerprintConflict | db::IdempotencyAcquire::RotationConflict => {
            tx.rollback().await?;
            return Err(AppError::IdempotencyConflict);
        }
        db::IdempotencyAcquire::ReplayInvalidated => {
            tx.rollback().await?;
            return Err(AppError::IdempotencyReplayInvalidated);
        }
        db::IdempotencyAcquire::Busy {
            retry_after_seconds,
        } => {
            tx.rollback().await?;
            return Err(AppError::IdempotencyBusy {
                retry_after: retry_after_seconds,
            });
        }
        db::IdempotencyAcquire::CapacityLimited {
            retry_after_seconds,
        } => {
            tx.rollback().await?;
            return Err(AppError::TooManyRequests {
                message: "too many retained requests; try again later".into(),
                retry_after: retry_after_seconds,
            });
        }
        db::IdempotencyAcquire::InProgress {
            retry_after_seconds,
        } => {
            tx.rollback().await?;
            return Err(AppError::IdempotencyInProgress {
                retry_after: retry_after_seconds,
            });
        }
    };
    if !lease.guard_verified {
        let pow_intent = body.pow_intent(report_id);
        match state
            .abuse
            .verify_or_allow_in_tx_v2(
                &mut tx,
                AbuseAction::Appeal,
                &subject,
                &actors,
                body.pow.as_ref(),
                &pow_intent,
            )
            .await?
        {
            TransactionalGuardOutcome::Allowed(_) => {
                if !db::mark_idempotency_guard_verified_in_tx(&mut tx, &lease).await? {
                    return Err(AppError::Internal(anyhow::anyhow!(
                        "appeal idempotency guard lease changed"
                    )));
                }
            }
            TransactionalGuardOutcome::DeniedNeedsCommit(error) => {
                let response = complete_guard_denial(&state, &mut tx, &lease, error).await?;
                tx.commit().await?;
                state
                    .metrics
                    .rate_limited_total
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                return Ok(response);
            }
        }
    }
    if let Some(message) = validation_error {
        let response = complete_api_error(
            &state,
            &mut tx,
            &lease,
            StatusCode::BAD_REQUEST,
            "bad_request",
            message,
        )
        .await?;
        tx.commit().await?;
        return Ok(response);
    }
    let id =
        match db::create_appeal_in_tx(&mut tx, report_id, user.id, reason, Some(lease.request_id))
            .await
        {
            Ok(id) => id,
            Err(error @ db::AppealCreateError::Conflict) => {
                let response = complete_api_error(
                    &state,
                    &mut tx,
                    &lease,
                    StatusCode::CONFLICT,
                    "conflict",
                    &error.to_string(),
                )
                .await?;
                tx.commit().await?;
                return Ok(response);
            }
            Err(db::AppealCreateError::Internal(error)) => return Err(AppError::Internal(error)),
        };
    let stored_response =
        StoredHttpResponse::json(StatusCode::CREATED, json!({"id":id,"status":"submitted"}))?;
    if !stored_response
        .persist_in_tx(state.api_control(), &mut tx, &lease)
        .await?
    {
        return Err(AppError::Internal(anyhow::anyhow!(
            "appeal idempotency lease changed"
        )));
    }
    tx.commit().await?;
    state
        .metrics
        .appeals_total
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    stored_response.build_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_report() -> ReportRequest {
        ReportRequest {
            reported_jid: "peer@example.test".into(),
            category: "spam".into(),
            evidence: vec![EvidenceItem {
                archive_id: Uuid::new_v4(),
                client_message_id: Some("message-1".into()),
                body_text: "A safe multilingual evidence body. 安全な本文。".into(),
            }],
            description: Some("A safe multilingual description. 描述。".into()),
            pow: None,
        }
    }

    #[test]
    fn report_and_appeal_text_reject_every_postgres_nul_boundary() {
        let mut description = valid_report();
        description.description = Some("unsafe\0description".into());
        assert_eq!(
            report_validation_error(&description),
            Some("report description is invalid")
        );

        let mut evidence_body = valid_report();
        evidence_body.evidence[0].body_text = "unsafe\0body".into();
        assert_eq!(
            report_validation_error(&evidence_body),
            Some("report evidence is invalid")
        );

        let mut client_id = valid_report();
        client_id.evidence[0].client_message_id = Some("unsafe\0id".into());
        assert_eq!(
            report_validation_error(&client_id),
            Some("report evidence is invalid")
        );

        assert!(appeal_validation_error("A valid appeal reason for review.").is_none());
        assert!(appeal_validation_error("An unsafe appeal\0 reason for review.").is_some());
    }

    #[test]
    fn text_limits_count_unicode_scalars_and_reject_invisible_controls() {
        assert!(report_validation_error(&valid_report()).is_none());
        assert!(valid_user_text("多言語\ntext", 1, 16, 64));
        assert!(!valid_user_text("unsafe\u{0085}text", 1, 32, 128));
        assert!(!valid_user_text("unsafe\u{202e}text", 1, 32, 128));
        assert!(valid_client_message_id("メッセージ-1"));
        assert!(!valid_client_message_id("message\n1"));
        assert!(valid_user_text(&"界".repeat(4_000), 0, 4_000, 16_000));
        assert!(!valid_user_text(&"界".repeat(4_001), 0, 4_000, 16_000));
    }
}
