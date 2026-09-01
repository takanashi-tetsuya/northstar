//! Narrow administrator API for inspecting and requeuing upload dead letters.

use crate::api::admin::{
    acquire_admin_mutation_in_tx, complete_admin_response, AdminMutationAcquire,
};
use crate::api::cursor::{
    CanonicalScope, CursorBinding, CursorDirection, CursorPosition, CursorValue,
};
use crate::api::{idempotency_replay_response, pagination, ApiAdmin, ApiEmpty, ApiPath, ApiQuery};
use crate::db;
use crate::error::AppError;
use crate::state::AppState;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use axum::Json;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::Arc;
use uuid::Uuid;
use zeroize::Zeroizing;

const DEAD_LETTER_ENDPOINT: &str = "admin/upload-dead-letters";
const DEAD_LETTER_SORT: &str = "id.desc";
const ERROR_SUMMARY_MAX_CHARS: usize = 240;
const ERROR_SUMMARY_MAX_BYTES: usize = 512;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UploadDeadLetterPageQuery {
    pub kind: String,
    pub limit: Option<i64>,
    pub cursor: Option<String>,
}

#[derive(Debug, Serialize)]
struct UploadDeadLetterView {
    kind: &'static str,
    id: String,
    operation: String,
    attempts: i64,
    dead_lettered_at: DateTime<Utc>,
    available_at: DateTime<Utc>,
    created_at: DateTime<Utc>,
    error_summary: Option<String>,
}

fn checked_kind(value: &str) -> Result<db::UploadDeadLetterKind, AppError> {
    db::UploadDeadLetterKind::parse(value)
        .ok_or_else(|| AppError::BadRequest("kind must be exactly storage_job or cleanup".into()))
}

fn require_explicit_idempotency_key(headers: &HeaderMap) -> Result<(), AppError> {
    let mut values = headers.get_all("idempotency-key").iter();
    let Some(value) = values.next() else {
        return Err(AppError::BadRequest(
            "Idempotency-Key is required for upload dead-letter retry".into(),
        ));
    };
    if values.next().is_some() {
        return Err(AppError::BadRequest(
            "exactly one Idempotency-Key header is allowed".into(),
        ));
    }
    let value = value
        .to_str()
        .map_err(|_| AppError::BadRequest("Idempotency-Key is invalid".into()))?;
    if !(8..=200).contains(&value.len()) || !value.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
    {
        return Err(AppError::BadRequest(
            "Idempotency-Key must contain 8 to 200 visible ASCII bytes".into(),
        ));
    }
    Ok(())
}

fn dead_letter_filter(kind: db::UploadDeadLetterKind) -> Result<CanonicalScope, AppError> {
    CanonicalScope::new()
        .field("kind", Some(kind.as_str().as_bytes()))
        .map_err(|error| AppError::Internal(error.into()))
}

fn dead_letter_binding<'a>(actor_id: &'a Uuid, filter: &'a CanonicalScope) -> CursorBinding<'a> {
    CursorBinding {
        endpoint: DEAD_LETTER_ENDPOINT,
        principal_scope: actor_id.as_bytes(),
        filter_scope: filter.as_bytes(),
        sort: DEAD_LETTER_SORT,
        direction: CursorDirection::Forward,
        node_incarnation: Uuid::nil(),
    }
}

fn boundary_from_position(
    kind: db::UploadDeadLetterKind,
    position: CursorPosition,
) -> Result<db::UploadDeadLetterBoundary, AppError> {
    match (kind, position.last.as_slice()) {
        (db::UploadDeadLetterKind::StorageJob, [CursorValue::I64(id)]) if *id > 0 => {
            Ok(db::UploadDeadLetterBoundary::StorageJob(*id))
        }
        (db::UploadDeadLetterKind::Cleanup, [CursorValue::Uuid(id)]) if !id.is_nil() => {
            Ok(db::UploadDeadLetterBoundary::Cleanup(*id))
        }
        _ => Err(AppError::InvalidCursor),
    }
}

async fn dead_letter_boundary(
    state: &AppState,
    token: Option<&str>,
    binding: &CursorBinding<'_>,
    kind: db::UploadDeadLetterKind,
) -> Result<Option<db::UploadDeadLetterBoundary>, AppError> {
    let Some(token) = token else {
        return Ok(None);
    };
    let database_now = db::database_cursor_clock(&state.pool).await?;
    let position = state
        .api_cursor()
        .verify(token, binding, database_now.timestamp())
        .map_err(|_| AppError::InvalidCursor)?;
    boundary_from_position(kind, position).map(Some)
}

fn issue_dead_letter_cursor(
    state: &AppState,
    binding: &CursorBinding<'_>,
    next: Option<db::UploadDeadLetterBoundary>,
    database_now: DateTime<Utc>,
) -> Result<Option<String>, AppError> {
    next.map(|boundary| {
        let last = match boundary {
            db::UploadDeadLetterBoundary::StorageJob(id) => vec![CursorValue::I64(id)],
            db::UploadDeadLetterBoundary::Cleanup(id) => vec![CursorValue::Uuid(id)],
        };
        state
            .api_cursor()
            .issue(
                binding,
                &CursorPosition { last },
                database_now.timestamp(),
                pagination::CURSOR_TTL_SECONDS,
            )
            .map_err(|error| AppError::Internal(error.into()))
    })
    .transpose()
}

fn unsafe_locator_token(token: &str) -> bool {
    let lower = Zeroizing::new(token.to_ascii_lowercase());
    lower.contains("://")
        || lower.contains("objects/")
        || lower.contains("staging/")
        || lower.contains("object_key=")
        || lower.contains("stage_key=")
        || lower.contains("bucket=")
        || lower.contains("token=")
        || lower.contains("secret=")
        || lower.contains("password=")
        || lower.contains("credential=")
        || lower.contains("authorization=")
        || token.starts_with('/')
        || token.starts_with("\\\\")
        || token.contains('\\')
}

fn unsafe_display_character(character: char) -> bool {
    character.is_control()
        || matches!(
            character,
            '\u{061c}'
                | '\u{200e}'
                | '\u{200f}'
                | '\u{202a}'..='\u{202e}'
                | '\u{2066}'..='\u{2069}'
        )
}

fn bounded_text(value: &str, max_chars: usize, max_bytes: usize) -> String {
    let mut output = String::new();
    let mut count = 0_usize;
    let mut truncated = false;
    for character in value.chars() {
        if count == max_chars || output.len() + character.len_utf8() > max_bytes {
            truncated = true;
            break;
        }
        output.push(character);
        count += 1;
    }
    if truncated && count + 3 <= max_chars && output.len() + 3 <= max_bytes {
        output.push_str("...");
    }
    output
}

/// Produce a diagnostic class rather than returning the stored worker error.
/// Classification happens only after control/bidi stripping and likely
/// locator/credential redaction. Operators correlate the fixed class with
/// protected logs by kind, random recovery ID and request ID; no digest of the
/// protected original error crosses the HTTP or audit boundary.
fn safe_error_summary(value: &str) -> String {
    let display_safe = Zeroizing::new(
        value
            .chars()
            .map(|character| {
                if unsafe_display_character(character) {
                    ' '
                } else {
                    character
                }
            })
            .collect::<String>(),
    );
    let redacted = Zeroizing::new(
        display_safe
            .split_whitespace()
            .map(|token| {
                if unsafe_locator_token(token) {
                    "[redacted-locator]"
                } else {
                    token
                }
            })
            .collect::<Vec<_>>()
            .join(" "),
    );
    let normalized = Zeroizing::new(redacted.to_ascii_lowercase());
    let category = if normalized.contains("timed out") || normalized.contains("timeout") {
        "storage operation timed out"
    } else if normalized.contains("permission denied")
        || normalized.contains("access denied")
        || normalized.contains("backend denied")
        || normalized.contains("unauthorized")
        || normalized.contains("forbidden")
    {
        "storage backend denied the operation"
    } else if normalized.contains("checksum")
        || normalized.contains("digest")
        || normalized.contains("integrity")
        || normalized.contains("size mismatch")
    {
        "storage integrity verification failed"
    } else if normalized.contains("not found") || normalized.contains("absent") {
        "storage object was not found"
    } else if normalized.contains("connect")
        || normalized.contains("network")
        || normalized.contains("dns")
        || normalized.contains("unreachable")
    {
        "storage backend connection failed"
    } else if normalized.is_empty() {
        "storage worker reported an unspecified failure"
    } else {
        "storage worker reported a failure"
    };
    bounded_text(
        &format!("{category}; stored details withheld"),
        ERROR_SUMMARY_MAX_CHARS,
        ERROR_SUMMARY_MAX_BYTES,
    )
}

/// Bind an otherwise bodyless administrator retry to the credential
/// generation which authorized it. The outer API-control HMAC keeps this
/// digest opaque in storage. Keeping the actor UUID as principal/capacity
/// scope means reuse of one key after a credential rotation finds the same
/// record and fails with a fingerprint conflict instead of opening a second
/// idempotency namespace.
pub(crate) fn admin_generation_bound_request_fingerprint(
    base: [u8; 32],
    auth_generation: i64,
) -> [u8; 32] {
    let mut material = [0_u8; 40];
    material[..32].copy_from_slice(&base);
    material[32..].copy_from_slice(&auth_generation.to_be_bytes());
    db::api_request_fingerprint(
        "application/vnd.northstar.admin-auth-generation-v1",
        &material,
    )
}

fn view(kind: db::UploadDeadLetterKind, row: db::UploadDeadLetterRecord) -> UploadDeadLetterView {
    let db::UploadDeadLetterRecord {
        id,
        operation,
        attempts,
        dead_lettered_at,
        available_at,
        created_at,
        last_error,
    } = row;
    let error_summary = last_error.as_ref().map(|error| safe_error_summary(error));
    drop(last_error);
    UploadDeadLetterView {
        kind: kind.as_str(),
        id: id.as_api_string(),
        operation,
        attempts,
        dead_lettered_at,
        available_at,
        created_at,
        error_summary,
    }
}

pub async fn admin_upload_dead_letters(
    State(state): State<Arc<AppState>>,
    actor: ApiAdmin,
    ApiQuery(query): ApiQuery<UploadDeadLetterPageQuery>,
) -> Result<Json<serde_json::Value>, AppError> {
    let kind = checked_kind(&query.kind)?;
    let limit = pagination::checked_limit(query.limit, 25, 100)?;
    let filter = dead_letter_filter(kind)?;
    let binding = dead_letter_binding(&actor.id, &filter);
    let after = dead_letter_boundary(&state, query.cursor.as_deref(), &binding, kind).await?;
    let mut tx = actor.begin_authorized_read(&state).await?;
    let page = db::upload_dead_letters_page_in_tx(&mut tx, kind, after, limit).await?;
    tx.commit().await?;
    let next_cursor = issue_dead_letter_cursor(&state, &binding, page.next, page.database_now)?;
    let items = page
        .rows
        .into_iter()
        .map(|row| view(kind, row))
        .collect::<Vec<_>>();
    Ok(Json(json!({
        "kind": kind.as_str(),
        "items": items,
        "limit": limit,
        "next_cursor": next_cursor,
    })))
}

pub async fn admin_retry_upload_dead_letter(
    State(state): State<Arc<AppState>>,
    actor: ApiAdmin,
    ApiPath((kind, id)): ApiPath<(String, String)>,
    headers: HeaderMap,
    request: ApiEmpty,
) -> Result<Response, AppError> {
    require_explicit_idempotency_key(&headers)?;
    let kind = checked_kind(&kind)?;
    let id = db::UploadDeadLetterId::parse(kind, &id)
        .ok_or_else(|| AppError::BadRequest("dead-letter identifier is invalid".into()))?;
    let target_scope = format!("{}\0{}", kind.as_str(), id.as_api_string());
    let mut idempotency = request.idempotency(
        Some(actor.id),
        actor.id.as_bytes(),
        db::ApiPrincipalKind::Admin,
        "POST",
        "/api/v1/admin/upload-dead-letters/{kind}/{id}/retry",
    );
    idempotency.request_fingerprint = admin_generation_bound_request_fingerprint(
        idempotency.request_fingerprint,
        actor.auth_generation,
    );
    // Generation changes conflict under the stable actor scope; unfinished
    // record capacity likewise remains account-wide rather than per generation.
    idempotency.capacity_scope = actor.id.as_bytes();
    idempotency.target_scope = target_scope.as_bytes();

    let mut tx = state.pool.begin().await?;
    let lease = match acquire_admin_mutation_in_tx(&state, &mut tx, &actor, &idempotency).await? {
        AdminMutationAcquire::Acquired(lease) => lease,
        AdminMutationAcquire::Replay(replay) => {
            tx.commit().await?;
            return idempotency_replay_response(replay);
        }
        AdminMutationAcquire::Busy {
            retry_after_seconds,
        } => {
            tx.rollback().await?;
            return Err(AppError::IdempotencyBusy {
                retry_after: retry_after_seconds,
            });
        }
    };

    let outcome = db::retry_upload_dead_letter_in_tx(
        &mut tx,
        actor.id,
        actor.auth_generation,
        actor.session_token(),
        id,
        lease.request_id,
    )
    .await?;
    let (status, body) = match outcome {
        db::RetryUploadDeadLetter::Retried => (
            StatusCode::ACCEPTED,
            json!({"kind":kind.as_str(),"id":id.as_api_string(),"state":"queued"}),
        ),
        db::RetryUploadDeadLetter::Unavailable => (
            StatusCode::NOT_FOUND,
            json!({"error":{"code":"not_found","message":"upload dead-letter entry is unavailable"}}),
        ),
        db::RetryUploadDeadLetter::Unauthorized => return Err(AppError::Forbidden),
    };
    let response = complete_admin_response(&state, &mut tx, &lease, status, body, None).await?;
    tx.commit().await?;
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    #[test]
    fn error_projection_redacts_controls_bidi_and_likely_locators_and_is_bounded() {
        let input = format!(
            "timeout\nfor s3://bucket/private staging/secret \\server\\share \u{202e}{}",
            "界".repeat(400)
        );
        let summary = safe_error_summary(&input);
        assert!(!summary.chars().any(unsafe_display_character));
        assert!(!summary.contains("bucket/private"));
        assert!(!summary.contains("staging/secret"));
        assert!(!summary.contains("server\\share"));
        assert!(summary.contains("timed out"));
        assert!(summary.contains("details withheld"));
        assert!(summary.chars().count() <= ERROR_SUMMARY_MAX_CHARS);
        assert!(summary.len() <= ERROR_SUMMARY_MAX_BYTES);
        assert_ne!(summary, input);
        let bounded = bounded_text(&"界".repeat(400), 17, 32);
        assert!(bounded.chars().count() <= 17);
        assert!(bounded.len() <= 32);
    }

    #[test]
    fn serialized_list_item_never_contains_the_original_error_or_locator_fields() {
        let raw = "access denied for s3://private-bucket/objects/secret";
        let now = Utc::now();
        let item = view(
            db::UploadDeadLetterKind::StorageJob,
            db::UploadDeadLetterRecord {
                id: db::UploadDeadLetterId::StorageJob(17),
                operation: "delete_object".into(),
                attempts: 12,
                dead_lettered_at: now,
                available_at: now,
                created_at: now,
                last_error: Some(zeroize::Zeroizing::new(raw.into())),
            },
        );
        let encoded = serde_json::to_string(&item).unwrap();
        assert!(!encoded.contains(raw));
        assert!(!encoded.contains("private-bucket"));
        assert!(!encoded.contains("object_key"));
        assert!(!encoded.contains("stage_key"));
        assert!(!encoded.contains("sha256"));
        assert!(!encoded.contains("last_error_bytes"));
        assert!(!encoded.contains("last_error_length"));
        assert!(encoded.contains("storage backend denied the operation"));
    }

    #[test]
    fn administrator_generation_changes_the_keyed_request_identity() {
        let base = db::api_request_fingerprint("", b"");
        assert_eq!(
            admin_generation_bound_request_fingerprint(base, 7),
            admin_generation_bound_request_fingerprint(base, 7)
        );
        assert_ne!(
            admin_generation_bound_request_fingerprint(base, 7),
            admin_generation_bound_request_fingerprint(base, 8)
        );
    }

    #[test]
    fn retry_requires_exactly_one_explicit_visible_ascii_key() {
        let mut headers = HeaderMap::new();
        assert!(require_explicit_idempotency_key(&headers).is_err());
        headers.insert(
            "idempotency-key",
            HeaderValue::from_static("retry-key-0001"),
        );
        assert!(require_explicit_idempotency_key(&headers).is_ok());
        headers.append(
            "idempotency-key",
            HeaderValue::from_static("retry-key-0002"),
        );
        assert!(require_explicit_idempotency_key(&headers).is_err());
    }

    #[test]
    fn cursor_position_is_kind_typed_and_fail_closed() {
        let storage = boundary_from_position(
            db::UploadDeadLetterKind::StorageJob,
            CursorPosition {
                last: vec![CursorValue::I64(7)],
            },
        )
        .unwrap();
        assert!(matches!(
            storage,
            db::UploadDeadLetterBoundary::StorageJob(7)
        ));
        assert!(boundary_from_position(
            db::UploadDeadLetterKind::Cleanup,
            CursorPosition {
                last: vec![CursorValue::I64(7)],
            },
        )
        .is_err());
        assert!(boundary_from_position(
            db::UploadDeadLetterKind::StorageJob,
            CursorPosition {
                last: vec![CursorValue::I64(0)],
            },
        )
        .is_err());
    }
}
