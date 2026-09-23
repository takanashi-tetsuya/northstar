use crate::api::*;
use axum::{
    extract::{ConnectInfo, State},
    http::HeaderMap,
    response::Response,
    Json,
};
use serde::Serialize;
use serde_json::json;
use serde_json::Value;
use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;
use uuid::Uuid;

use crate::db;
use crate::error::{AppError, Result};
use crate::state::AppState;

pub async fn me(
    State(state): State<crate::state::ApiQueryContext>,
    headers: HeaderMap,
) -> Result<Json<Value>, AppError> {
    let user = current_user_with_queries(&state, &headers).await?;
    Ok(Json(
        json!({"id":user.id,"jid":format!("{}@{}",user.username,state.domain()),"display_name":user.display_name,"is_admin":user.is_admin}),
    ))
}

pub async fn change_password(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    mut request: ApiJson<PasswordChange>,
) -> Result<Response, AppError> {
    use crate::services::password_change::{PasswordChangeCommand, PasswordChangeResult};

    let presented_session = zeroize::Zeroizing::new(bearer_token(&headers)?.to_owned());
    let pow_intent = request.value.pow_intent();
    let current_password =
        zeroize::Zeroizing::new(std::mem::take(&mut request.value.current_password));
    let new_password = zeroize::Zeroizing::new(std::mem::take(&mut request.value.new_password));
    let peer_ip = client_ip(peer.ip(), &headers, &state);
    let outcome = state
        .password_change_service()
        .execute(PasswordChangeCommand {
            idempotency: request.idempotency(
                None,
                presented_session.as_bytes(),
                db::ApiPrincipalKind::User,
                "PATCH",
                "/api/v1/me/password",
            ),
            presented_session: &presented_session,
            current_password: &current_password,
            new_password: &new_password,
            proof: request.value.pow.as_ref(),
            intent: &pow_intent,
            peer_ip,
        })
        .await?;
    match outcome {
        PasswordChangeResult::Replay(replay) => idempotency_replay_response(replay),
        PasswordChangeResult::Fresh(response) => {
            crate::api::idempotency::stored_api_response(response)
        }
        PasswordChangeResult::RateLimited(response) => {
            state.record_http_rate_limited();
            crate::api::idempotency::stored_api_response(response)
        }
        PasswordChangeResult::Changed(response, account) => {
            state
                .disconnect_account(
                    account.user_id,
                    &format!("{}@{}", account.username, state.config.domain),
                )
                .await;
            crate::api::idempotency::stored_api_response(response)
        }
        PasswordChangeResult::Unauthorized => Err(AppError::Unauthorized),
        PasswordChangeResult::IdempotencyConflict => Err(AppError::IdempotencyConflict),
        PasswordChangeResult::ReplayInvalidated => Err(AppError::IdempotencyReplayInvalidated),
        PasswordChangeResult::Busy(retry_after) => Err(AppError::IdempotencyBusy { retry_after }),
        PasswordChangeResult::CapacityLimited(retry_after) => Err(AppError::TooManyRequests {
            message: "too many retained requests; try again later".into(),
            retry_after,
        }),
        PasswordChangeResult::InProgress(retry_after) => {
            Err(AppError::IdempotencyInProgress { retry_after })
        }
        PasswordChangeResult::LeaseLost => Err(AppError::IdempotencyInProgress { retry_after: 1 }),
        PasswordChangeResult::WorkerOverloaded => Err(AppError::Unavailable(
            "password-change capacity is temporarily exhausted; retry later".into(),
        )),
        PasswordChangeResult::VerifierUnavailable => {
            state.record_http_authentication_backend_failure();
            Err(AppError::Unavailable(
                "password authentication backend is temporarily unavailable; retry later".into(),
            ))
        }
        PasswordChangeResult::PublicationUnavailable => {
            state.record_http_authentication_backend_failure();
            Err(AppError::Unavailable(
                "password-change backend is temporarily unavailable; retry later".into(),
            ))
        }
    }
}

const MAX_HISTORY_RESULTS: i64 = 100;
const MAX_HISTORY_IDS: usize = 100;
const MAX_HISTORY_INDEX: i64 = 1_000_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HistoryQueryMode {
    /// Compatibility mode for the original `with`/`limit`/`cursor` REST API.
    /// Pages and rows are newest-first and `next_cursor` continues backwards.
    Legacy,
    /// Direct REST expression of the shared XEP-0313/XEP-0059 query object.
    Mam,
}

#[derive(Debug)]
struct PreparedHistoryQuery {
    mam: crate::services::mam::MamArchiveQuery,
    mode: HistoryQueryMode,
    flip: bool,
}

#[derive(Serialize)]
struct HistoryMessageView {
    id: Uuid,
    /// Retained compatibility field: always the peer's canonical bare JID.
    peer_jid: String,
    /// Additive field for clients which need resource-specific MAM results.
    peer_full_jid: String,
    stanza: String,
    encrypted: bool,
    stanza_id: Option<String>,
    created_at: chrono::DateTime<chrono::Utc>,
}

impl TryFrom<crate::services::mam::ArchiveRow> for HistoryMessageView {
    type Error = anyhow::Error;

    fn try_from(value: crate::services::mam::ArchiveRow) -> std::result::Result<Self, Self::Error> {
        let peer_jid = crate::jid::canonical_bare_key(&value.peer_jid)?;
        Ok(Self {
            id: value.id,
            peer_jid,
            peer_full_jid: value.peer_jid,
            stanza: value.stanza,
            encrypted: value.encrypted,
            stanza_id: value.stanza_id,
            created_at: value.created_at,
        })
    }
}

fn parse_history_ids(value: Option<&str>) -> Result<Vec<Uuid>, AppError> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    if value.is_empty() {
        return Err(AppError::BadRequest("ids must not be empty".into()));
    }
    let values = value.split(',').collect::<Vec<_>>();
    if values.len() > MAX_HISTORY_IDS || values.iter().any(|value| value.is_empty()) {
        return Err(AppError::BadRequest(format!(
            "ids must contain 1 to {MAX_HISTORY_IDS} comma-separated archive UUIDs"
        )));
    }
    let mut unique = HashSet::with_capacity(values.len());
    let mut ids = Vec::with_capacity(values.len());
    for value in values {
        let id = Uuid::parse_str(value)
            .map_err(|_| AppError::BadRequest("ids contains an invalid archive UUID".into()))?;
        if !unique.insert(id) {
            return Err(AppError::BadRequest(
                "ids contains a duplicate archive UUID".into(),
            ));
        }
        ids.push(id);
    }
    Ok(ids)
}

fn prepare_history_query(query: &HistoryQuery) -> Result<PreparedHistoryQuery, AppError> {
    let with_jid = query
        .r#with
        .as_deref()
        .map(crate::jid::canonicalize)
        .transpose()
        .map_err(|_| AppError::BadRequest("with filter is not a valid JID".into()))?;
    if matches!((query.start, query.end), (Some(start), Some(end)) if start > end) {
        return Err(AppError::BadRequest(
            "start must not be later than end".into(),
        ));
    }
    if query.max.is_some() && query.limit.is_some() {
        return Err(AppError::BadRequest(
            "max and legacy limit are mutually exclusive".into(),
        ));
    }

    let direct_mam = query.start.is_some()
        || query.end.is_some()
        || query.after_id.is_some()
        || query.before_id.is_some()
        || query.ids.is_some()
        || query.page.is_some()
        || query.before.is_some()
        || query.after.is_some()
        || query.index.is_some()
        || query.max.is_some()
        || query.flip.is_some();
    let mode = if direct_mam {
        HistoryQueryMode::Mam
    } else {
        HistoryQueryMode::Legacy
    };
    if mode == HistoryQueryMode::Mam && query.cursor.is_some() {
        return Err(AppError::BadRequest(
            "legacy cursor cannot be combined with MAM controls".into(),
        ));
    }

    let page_controls = usize::from(query.page.is_some())
        + usize::from(query.before.is_some())
        + usize::from(query.after.is_some())
        + usize::from(query.index.is_some());
    if page_controls > 1 {
        return Err(AppError::BadRequest(
            "page, before, after and index are mutually exclusive".into(),
        ));
    }
    let page = if let Some(page) = query.page.as_deref() {
        match page {
            "first" => crate::services::mam::MamRsmPage::First,
            "last" => crate::services::mam::MamRsmPage::Last,
            _ => {
                return Err(AppError::BadRequest("page must be first or last".into()));
            }
        }
    } else if let Some(id) = query.before {
        crate::services::mam::MamRsmPage::Before(id)
    } else if let Some(id) = query.after {
        crate::services::mam::MamRsmPage::After(id)
    } else if let Some(index) = query.index {
        if !(0..=MAX_HISTORY_INDEX).contains(&index) {
            return Err(AppError::BadRequest(format!(
                "index must be between 0 and {MAX_HISTORY_INDEX}"
            )));
        }
        crate::services::mam::MamRsmPage::Index(index)
    } else if mode == HistoryQueryMode::Legacy {
        crate::services::mam::MamRsmPage::Last
    } else {
        crate::services::mam::MamRsmPage::First
    };

    let max = if let Some(max) = query.max {
        if !(0..=MAX_HISTORY_RESULTS).contains(&max) {
            return Err(AppError::BadRequest(format!(
                "max must be between 0 and {MAX_HISTORY_RESULTS}"
            )));
        }
        max
    } else {
        pagination::checked_limit(query.limit, MAX_HISTORY_RESULTS, MAX_HISTORY_RESULTS)?
    };

    Ok(PreparedHistoryQuery {
        mam: crate::services::mam::MamArchiveQuery {
            with_jid,
            start: query.start,
            end: query.end,
            before_id: query.before_id,
            after_id: query.after_id,
            ids: parse_history_ids(query.ids.as_deref())?,
            page,
            max,
        },
        mode,
        // Legacy clients have always received newest-first rows. Direct MAM
        // queries follow chronological XEP order unless flip=true.
        flip: query.flip.unwrap_or(mode == HistoryQueryMode::Legacy),
    })
}

pub async fn history(
    State(state): State<crate::state::ApiQueryContext>,
    headers: HeaderMap,
    ApiQuery(query): ApiQuery<HistoryQuery>,
) -> Result<Json<Value>, AppError> {
    let user = current_user_with_queries(&state, &headers).await?;
    let mut prepared = prepare_history_query(&query)?;

    // Preserve the old opaque, principal/filter-bound cursor without keeping
    // a second archive SQL implementation. Once authenticated, its immutable
    // archive UID becomes the shared MAM RSM `before` cursor; the MAM query
    // revalidates ownership and XEP-0191 visibility in one repeatable snapshot.
    if prepared.mode == HistoryQueryMode::Legacy {
        let filter = pagination::one_filter_scope("with", prepared.mam.with_jid.as_deref())?;
        let binding = pagination::pg_binding("history", user.id.as_bytes(), &filter);
        if let Some(boundary) =
            pagination::pg_boundary(&state, query.cursor.as_deref(), &binding).await?
        {
            prepared.mam.page = crate::services::mam::MamRsmPage::Before(boundary.id);
        }
    }

    let read = state
        .api_query_service()
        .history(user.read_authority(), &prepared.mam)
        .await?
        .ok_or(AppError::Unauthorized)?;
    let database_now = read.database_now;
    let page = read.value.ok_or_else(|| {
        if prepared.mode == HistoryQueryMode::Legacy {
            AppError::InvalidCursor
        } else {
            AppError::NotFound("archive UID is not visible in this query scope".into())
        }
    })?;
    let chronological_first = page.rows.first().map(|row| (row.id, row.created_at));
    let chronological_last = page.rows.last().map(|row| row.id);
    let next_cursor = if prepared.mode == HistoryQueryMode::Legacy && !page.complete {
        let filter = pagination::one_filter_scope("with", prepared.mam.with_jid.as_deref())?;
        let binding = pagination::pg_binding("history", user.id.as_bytes(), &filter);
        pagination::issue_pg_cursor(
            &state,
            &binding,
            chronological_first.map(|(id, created_at)| {
                crate::services::api_queries::PageBoundary { created_at, id }
            }),
            database_now,
        )?
    } else {
        None
    };
    let all_end_to_end_encrypted = page.rows.iter().all(|row| row.encrypted);
    let count = page.total;
    let first_index = page.first_index;
    let complete = page.complete;
    let mut rows = page.rows;
    if prepared.flip {
        rows.reverse();
    }
    let messages = rows
        .into_iter()
        .map(HistoryMessageView::try_from)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(AppError::Internal)?;
    Ok(Json(json!({
        "messages":messages,
        "next_cursor":next_cursor,
        "all_end_to_end_encrypted":all_end_to_end_encrypted,
        "archive_policy":state.archive_policy(),
        "complete":complete,
        "count":count,
        "first_index":first_index,
        "first":chronological_first.map(|(id, _)| id),
        "last":chronological_last,
        "stable":true,
        "order":if prepared.flip {"reverse_chronological"} else {"chronological"},
        "query_mode":match prepared.mode { HistoryQueryMode::Legacy => "legacy", HistoryQueryMode::Mam => "mam" }
    })))
}

#[cfg(test)]
mod history_tests {
    use super::*;
    use chrono::{TimeZone, Utc};

    fn query() -> HistoryQuery {
        HistoryQuery {
            r#with: None,
            start: None,
            end: None,
            after_id: None,
            before_id: None,
            ids: None,
            page: None,
            before: None,
            after: None,
            index: None,
            max: None,
            flip: None,
            limit: None,
            cursor: None,
        }
    }

    #[test]
    fn legacy_history_keeps_newest_first_cursor_contract() {
        let mut input = query();
        input.r#with = Some("Bob@Example.test/Phone".into());
        input.limit = Some(25);
        input.cursor = Some("opaque".into());
        let prepared = prepare_history_query(&input).unwrap();
        assert_eq!(prepared.mode, HistoryQueryMode::Legacy);
        assert_eq!(
            prepared.mam.with_jid.as_deref(),
            Some("bob@example.test/Phone")
        );
        assert_eq!(prepared.mam.page, crate::services::mam::MamRsmPage::Last);
        assert_eq!(prepared.mam.max, 25);
        assert!(prepared.flip);
    }

    #[test]
    fn direct_mam_history_preserves_full_jid_and_all_bounds() {
        let first = Uuid::from_u128(1);
        let second = Uuid::from_u128(2);
        let before = Uuid::from_u128(3);
        let mut input = query();
        input.r#with = Some("bob@example.test/Phone".into());
        input.start = Some(Utc.timestamp_opt(100, 0).unwrap());
        input.end = Some(Utc.timestamp_opt(200, 0).unwrap());
        input.after_id = Some(first);
        input.before_id = Some(second);
        input.ids = Some(format!("{first},{second}"));
        input.before = Some(before);
        input.max = Some(0);
        input.flip = Some(true);
        let prepared = prepare_history_query(&input).unwrap();
        assert_eq!(prepared.mode, HistoryQueryMode::Mam);
        assert_eq!(
            prepared.mam.with_jid.as_deref(),
            Some("bob@example.test/Phone")
        );
        assert_eq!(prepared.mam.after_id, Some(first));
        assert_eq!(prepared.mam.before_id, Some(second));
        assert_eq!(prepared.mam.ids, vec![first, second]);
        assert_eq!(
            prepared.mam.page,
            crate::services::mam::MamRsmPage::Before(before)
        );
        assert_eq!(prepared.mam.max, 0);
        assert!(prepared.flip);
    }

    #[test]
    fn direct_mam_rejects_ambiguous_or_unbounded_controls() {
        let id = Uuid::new_v4();
        let mut ambiguous = query();
        ambiguous.page = Some("last".into());
        ambiguous.after = Some(id);
        assert!(prepare_history_query(&ambiguous).is_err());

        let mut cursor = query();
        cursor.start = Some(Utc.timestamp_opt(100, 0).unwrap());
        cursor.cursor = Some("legacy".into());
        assert!(prepare_history_query(&cursor).is_err());

        let mut duplicate_ids = query();
        duplicate_ids.ids = Some(format!("{id},{id}"));
        assert!(prepare_history_query(&duplicate_ids).is_err());

        let mut reverse_time = query();
        reverse_time.start = Some(Utc.timestamp_opt(200, 0).unwrap());
        reverse_time.end = Some(Utc.timestamp_opt(100, 0).unwrap());
        assert!(prepare_history_query(&reverse_time).is_err());

        let mut large_index = query();
        large_index.index = Some(MAX_HISTORY_INDEX + 1);
        assert!(prepare_history_query(&large_index).is_err());
    }
}
