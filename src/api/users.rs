use crate::api::*;
use axum::{
    body::Body,
    extract::{ConnectInfo, State},
    http::{HeaderMap, StatusCode},
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

use crate::abuse::AbuseAction;
use crate::auth;
use crate::db;
use crate::error::{AppError, Result};
use crate::state::AppState;

/// End a retryable worker lease while retaining any anti-abuse proof marker
/// committed before password verification or publication began.
async fn yield_idempotency_lease_after_retryable_failure(
    state: &AppState,
    lease: &db::IdempotencyLease,
) -> Result<(), AppError> {
    if !db::yield_idempotency_lease(&state.pool, lease).await? {
        return Err(AppError::IdempotencyInProgress { retry_after: 1 });
    }
    Ok(())
}

async fn complete_password_response(
    state: &AppState,
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    lease: &db::IdempotencyLease,
    status: StatusCode,
    body: Value,
) -> Result<Response, AppError> {
    let mut replay_headers = json_replay_headers();
    if status == StatusCode::UNAUTHORIZED {
        replay_headers.insert(
            "www-authenticate".to_owned(),
            "Bearer realm=\"northstar\"".to_owned(),
        );
    }
    let response_body =
        serde_json::to_vec(&body).map_err(|error| AppError::Internal(error.into()))?;
    if !db::complete_idempotency_in_tx(
        state.api_control(),
        tx,
        lease,
        status.as_u16(),
        &replay_headers,
        &response_body,
    )
    .await?
    {
        return Err(AppError::Internal(anyhow::anyhow!(
            "password-change idempotency lease changed"
        )));
    }
    let mut response = Response::builder().status(status);
    for (name, value) in replay_headers {
        response = response.header(name, value);
    }
    response
        .body(Body::from(response_body))
        .map_err(|error| AppError::Internal(error.into()))
}

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
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    mut request: ApiJson<PasswordChange>,
) -> Result<Response, AppError> {
    let presented_session = zeroize::Zeroizing::new(bearer_token(&headers)?.to_owned());
    let invalid_input = request.value.current_password.is_empty()
        || request.value.current_password.len() > 1024
        || auth::validate_password(&request.value.new_password).is_err();
    let pow_intent = request.value.pow_intent();
    let current_password =
        zeroize::Zeroizing::new(std::mem::take(&mut request.value.current_password));
    let new_password = zeroize::Zeroizing::new(std::mem::take(&mut request.value.new_password));
    let body = &request.value;
    let peer_ip = client_ip(peer.ip(), &headers, &state);
    let idempotency = request.idempotency(
        None,
        presented_session.as_bytes(),
        db::ApiPrincipalKind::User,
        "PATCH",
        "/api/v1/me/password",
    );
    let mut replay_tx = state.pool.begin().await?;
    match db::lookup_password_change_replay_in_tx(state.api_control(), &mut replay_tx, &idempotency)
        .await?
    {
        db::IdempotencyReplayLookup::Miss => replay_tx.commit().await?,
        db::IdempotencyReplayLookup::Replay(replay) => {
            replay_tx.commit().await?;
            return idempotency_replay_response(replay);
        }
        db::IdempotencyReplayLookup::FingerprintConflict
        | db::IdempotencyReplayLookup::RotationConflict => {
            replay_tx.rollback().await?;
            return Err(AppError::IdempotencyConflict);
        }
    }

    let mut reserve_tx = state.pool.begin().await?;
    let Some(user) =
        db::password_change_subject_for_token_in_tx(&mut reserve_tx, &presented_session).await?
    else {
        reserve_tx.rollback().await?;
        return Err(AppError::Unauthorized);
    };
    let lease =
        match db::acquire_idempotency_in_tx(state.api_control(), &mut reserve_tx, &idempotency)
            .await?
        {
            db::IdempotencyAcquire::Acquired(lease) => lease,
            db::IdempotencyAcquire::Replay(replay) => {
                reserve_tx.commit().await?;
                return idempotency_replay_response(replay);
            }
            db::IdempotencyAcquire::FingerprintConflict
            | db::IdempotencyAcquire::RotationConflict => {
                reserve_tx.rollback().await?;
                return Err(AppError::IdempotencyConflict);
            }
            db::IdempotencyAcquire::ReplayInvalidated => {
                reserve_tx.rollback().await?;
                return Err(AppError::IdempotencyReplayInvalidated);
            }
            db::IdempotencyAcquire::Busy {
                retry_after_seconds,
            } => {
                reserve_tx.rollback().await?;
                return Err(AppError::IdempotencyBusy {
                    retry_after: retry_after_seconds,
                });
            }
            db::IdempotencyAcquire::CapacityLimited {
                retry_after_seconds,
            } => {
                reserve_tx.rollback().await?;
                return Err(AppError::TooManyRequests {
                    message: "too many retained requests; try again later".into(),
                    retry_after: retry_after_seconds,
                });
            }
            db::IdempotencyAcquire::InProgress {
                retry_after_seconds,
            } => {
                reserve_tx.rollback().await?;
                return Err(AppError::IdempotencyInProgress {
                    retry_after: retry_after_seconds,
                });
            }
        };
    let (subject, actors) = abuse_identity(AbuseAction::PasswordChange, peer_ip, Some(&user));
    if !lease.guard_verified {
        match state
            .abuse
            .verify_or_allow_in_tx_v2(
                &mut reserve_tx,
                AbuseAction::PasswordChange,
                &subject,
                &actors,
                body.pow.as_ref(),
                &pow_intent,
            )
            .await?
        {
            crate::abuse::TransactionalGuardOutcome::Allowed(_) => {
                if !db::mark_idempotency_guard_verified_in_tx(&mut reserve_tx, &lease).await? {
                    return Err(AppError::Internal(anyhow::anyhow!(
                        "password-change guard lease changed"
                    )));
                }
            }
            crate::abuse::TransactionalGuardOutcome::DeniedNeedsCommit(error) => {
                let response = crate::api::reports::complete_guard_denial(
                    &state,
                    &mut reserve_tx,
                    &lease,
                    error,
                )
                .await?;
                reserve_tx.commit().await?;
                state
                    .metrics
                    .rate_limited_total
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                return Ok(response);
            }
        }
    }
    reserve_tx.commit().await?;

    if invalid_input {
        let mut tx = state.pool.begin().await?;
        if !db::resume_idempotency_lease_in_tx(&mut tx, &lease, API_IDEMPOTENCY_LEASE_SECONDS)
            .await?
        {
            tx.rollback().await?;
            return Err(AppError::IdempotencyInProgress { retry_after: 1 });
        }
        if !db::authorize_user_in_tx(&mut tx, user.id, user.auth_generation, &presented_session)
            .await?
        {
            tx.rollback().await?;
            // The bearer is already stale/revoked, so the exact request can
            // never become valid on retry. This is a deterministic rejection,
            // not a transient worker failure.
            db::abandon_idempotency_lease(&state.pool, &lease).await?;
            return Err(AppError::Unauthorized);
        }
        if !db::bind_idempotency_actor_in_tx(&mut tx, &lease, user.id).await? {
            return Err(AppError::Internal(anyhow::anyhow!(
                "password-change idempotency ownership changed"
            )));
        }
        let response = complete_password_response(
            &state,
            &mut tx,
            &lease,
            StatusCode::BAD_REQUEST,
            json!({"error":{"code":"bad_request","message":"password input is invalid"}}),
        )
        .await?;
        tx.commit().await?;
        return Ok(response);
    }

    let mut prework_tx = state.pool.begin().await?;
    if !db::resume_idempotency_lease_in_tx(&mut prework_tx, &lease, API_IDEMPOTENCY_LEASE_SECONDS)
        .await?
    {
        prework_tx.rollback().await?;
        return Err(AppError::IdempotencyInProgress { retry_after: 1 });
    }
    prework_tx.commit().await?;
    let prepared = match db::prepare_password_change(
        user.password_hash(),
        &current_password,
        &new_password,
        state.config.scram_iterations,
        state.config.scram_sha1_enabled,
    )
    .await
    {
        Ok(prepared) => prepared,
        Err(error) if crate::password_work::is_overloaded(&error) => {
            yield_idempotency_lease_after_retryable_failure(&state, &lease).await?;
            return Err(AppError::Unavailable(
                "password-change capacity is temporarily exhausted; retry later".into(),
            ));
        }
        Err(error) => {
            yield_idempotency_lease_after_retryable_failure(&state, &lease).await?;
            state
                .metrics
                .authentication_backend_failures_total
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            tracing::error!(
                integrity_failure = auth::is_password_verifier_integrity_error(&error),
                ?error,
                user_id = %user.id,
                "password-change verifier backend failed"
            );
            return Err(AppError::Unavailable(
                "password authentication backend is temporarily unavailable; retry later".into(),
            ));
        }
    };

    let mut tx = state.pool.begin().await?;
    if !db::resume_idempotency_lease_in_tx(&mut tx, &lease, API_IDEMPOTENCY_LEASE_SECONDS).await? {
        tx.rollback().await?;
        return Err(AppError::IdempotencyInProgress { retry_after: 1 });
    }
    if matches!(prepared, db::PreparedPasswordChange::InvalidCurrentPassword) {
        if !db::authorize_password_change_in_tx(
            &mut tx,
            user.id,
            user.password_hash(),
            user.auth_generation,
            &presented_session,
        )
        .await?
        {
            tx.rollback().await?;
            // Authorization changed after the guard stage. Retrying the same
            // credential-bearing request cannot restore that authorization.
            db::abandon_idempotency_lease(&state.pool, &lease).await?;
            return Err(AppError::Unauthorized);
        }
        if !db::bind_idempotency_actor_in_tx(&mut tx, &lease, user.id).await? {
            return Err(AppError::Internal(anyhow::anyhow!(
                "password-change failure ownership changed"
            )));
        }
        state
            .abuse
            .record_failure_in_tx(&mut tx, AbuseAction::PasswordChange, &actors)
            .await?;
        let response = complete_password_response(
            &state,
            &mut tx,
            &lease,
            StatusCode::UNAUTHORIZED,
            json!({"error":{"code":"unauthorized","message":"authentication required"}}),
        )
        .await?;
        tx.commit().await?;
        return Ok(response);
    }
    if !db::bind_idempotency_actor_in_tx(&mut tx, &lease, user.id).await? {
        return Err(AppError::Internal(anyhow::anyhow!(
            "password-change idempotency ownership changed"
        )));
    }
    let outcome = match db::apply_prepared_password_change_in_tx(
        &mut tx,
        user.id,
        user.password_hash(),
        user.auth_generation,
        &presented_session,
        prepared,
        Some(lease.request_id),
    )
    .await
    {
        Ok(outcome) => outcome,
        Err(error) => {
            tx.rollback().await?;
            yield_idempotency_lease_after_retryable_failure(&state, &lease).await?;
            state
                .metrics
                .authentication_backend_failures_total
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            tracing::error!(
                ?error,
                user_id = %user.id,
                "password-change publication backend failed"
            );
            return Err(AppError::Unavailable(
                "password-change backend is temporarily unavailable; retry later".into(),
            ));
        }
    };
    if outcome != db::PasswordChangeOutcome::Changed {
        tx.rollback().await?;
        // The compare-and-swap observed stale authorization, which is a
        // deterministic rejection for this exact request body and bearer.
        db::abandon_idempotency_lease(&state.pool, &lease).await?;
        return Err(AppError::Unauthorized);
    }
    let response = complete_password_response(
        &state,
        &mut tx,
        &lease,
        StatusCode::OK,
        json!({"changed":true,"sessions_revoked":true}),
    )
    .await?;
    tx.commit().await?;
    state
        .disconnect_account(
            user.id,
            &format!("{}@{}", user.username, state.config.domain),
        )
        .await;
    Ok(response)
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
    mam: db::MamArchiveQuery,
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

impl TryFrom<db::ArchiveRow> for HistoryMessageView {
    type Error = anyhow::Error;

    fn try_from(value: db::ArchiveRow) -> std::result::Result<Self, Self::Error> {
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
            "first" => db::MamRsmPage::First,
            "last" => db::MamRsmPage::Last,
            _ => {
                return Err(AppError::BadRequest("page must be first or last".into()));
            }
        }
    } else if let Some(id) = query.before {
        db::MamRsmPage::Before(id)
    } else if let Some(id) = query.after {
        db::MamRsmPage::After(id)
    } else if let Some(index) = query.index {
        if !(0..=MAX_HISTORY_INDEX).contains(&index) {
            return Err(AppError::BadRequest(format!(
                "index must be between 0 and {MAX_HISTORY_INDEX}"
            )));
        }
        db::MamRsmPage::Index(index)
    } else if mode == HistoryQueryMode::Legacy {
        db::MamRsmPage::Last
    } else {
        db::MamRsmPage::First
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
        mam: db::MamArchiveQuery {
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
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    ApiQuery(query): ApiQuery<HistoryQuery>,
) -> Result<Json<Value>, AppError> {
    let user = current_user(&state, &headers).await?;
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
            prepared.mam.page = db::MamRsmPage::Before(boundary.id);
        }
    }

    let mut read_tx = user.begin_authorized_read(&state).await?;
    let page = db::mam_user_archive_page_in_transaction(&mut read_tx, user.id, &prepared.mam)
        .await?
        .ok_or_else(|| {
            if prepared.mode == HistoryQueryMode::Legacy {
                AppError::InvalidCursor
            } else {
                AppError::NotFound("archive UID is not visible in this query scope".into())
            }
        })?;
    let database_now = db::database_cursor_clock_in_tx(&mut read_tx).await?;
    let chronological_first = page.rows.first().map(|row| (row.id, row.created_at));
    let chronological_last = page.rows.last().map(|row| row.id);
    let next_cursor = if prepared.mode == HistoryQueryMode::Legacy && !page.complete {
        let filter = pagination::one_filter_scope("with", prepared.mam.with_jid.as_deref())?;
        let binding = pagination::pg_binding("history", user.id.as_bytes(), &filter);
        pagination::issue_pg_cursor(
            &state,
            &binding,
            chronological_first.map(|(id, created_at)| db::PageBoundary { created_at, id }),
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
    read_tx.commit().await?;
    Ok(Json(json!({
        "messages":messages,
        "next_cursor":next_cursor,
        "all_end_to_end_encrypted":all_end_to_end_encrypted,
        "archive_policy":if state.config.require_encrypted_archive {"encrypted_only"} else {"all"},
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
        assert_eq!(prepared.mam.page, db::MamRsmPage::Last);
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
        assert_eq!(prepared.mam.page, db::MamRsmPage::Before(before));
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
