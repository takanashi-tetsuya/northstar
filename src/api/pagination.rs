//! Shared REST keyset-pagination policy.

use crate::{db, error::AppError, state::AppState};
use chrono::{DateTime, Utc};
use uuid::Uuid;

use super::cursor::{CanonicalScope, CursorBinding, CursorDirection, CursorPosition, CursorValue};

pub const CURSOR_TTL_SECONDS: i64 = 15 * 60;
pub const PG_SORT: &str = "created_at.id.desc";
pub const SESSION_SORT: &str = "connection_id.desc";

pub fn checked_limit(limit: Option<i64>, default: i64, maximum: i64) -> Result<i64, AppError> {
    let limit = limit.unwrap_or(default);
    if !(1..=maximum).contains(&limit) {
        return Err(AppError::BadRequest(format!(
            "limit must be between 1 and {maximum}"
        )));
    }
    Ok(limit)
}

pub fn checked_report_status(status: Option<&str>) -> Result<Option<&str>, AppError> {
    if status.is_some_and(|value| {
        !matches!(
            value,
            "submitted" | "reviewing" | "actioned" | "rejected" | "closed"
        )
    }) {
        return Err(AppError::BadRequest("status filter is invalid".into()));
    }
    Ok(status)
}

pub fn no_filter_scope() -> CanonicalScope {
    CanonicalScope::new()
}

pub fn one_filter_scope(label: &str, value: Option<&str>) -> Result<CanonicalScope, AppError> {
    CanonicalScope::new()
        .field(label, value.map(str::as_bytes))
        .map_err(|error| AppError::Internal(error.into()))
}

pub fn pg_binding<'a>(
    endpoint: &'a str,
    principal: &'a [u8],
    filter: &'a CanonicalScope,
) -> CursorBinding<'a> {
    CursorBinding {
        endpoint,
        principal_scope: principal,
        filter_scope: filter.as_bytes(),
        sort: PG_SORT,
        direction: CursorDirection::Forward,
        // Durable database pages are deliberately portable across nodes.
        node_incarnation: Uuid::nil(),
    }
}

pub fn session_binding<'a>(
    endpoint: &'a str,
    principal: &'a [u8],
    filter: &'a CanonicalScope,
    node_incarnation: Uuid,
) -> CursorBinding<'a> {
    CursorBinding {
        endpoint,
        principal_scope: principal,
        filter_scope: filter.as_bytes(),
        sort: SESSION_SORT,
        direction: CursorDirection::Forward,
        node_incarnation,
    }
}

pub async fn pg_boundary(
    state: &AppState,
    token: Option<&str>,
    binding: &CursorBinding<'_>,
) -> Result<Option<db::PageBoundary>, AppError> {
    let Some(token) = token else {
        return Ok(None);
    };
    let database_now = db::database_cursor_clock(&state.pool).await?;
    let position = state
        .api_cursor()
        .verify(token, binding, database_now.timestamp())
        .map_err(|_| AppError::InvalidCursor)?;
    let (micros, id) = position
        .descending_timestamp_uuid()
        .map_err(|_| AppError::InvalidCursor)?;
    let created_at =
        DateTime::<Utc>::from_timestamp_micros(micros).ok_or(AppError::InvalidCursor)?;
    Ok(Some(db::PageBoundary { created_at, id }))
}

pub fn issue_pg_cursor(
    state: &AppState,
    binding: &CursorBinding<'_>,
    next: Option<db::PageBoundary>,
    database_now: DateTime<Utc>,
) -> Result<Option<String>, AppError> {
    next.map(|boundary| {
        state
            .api_cursor()
            .issue(
                binding,
                &CursorPosition {
                    last: vec![
                        CursorValue::TimestampMicros(boundary.created_at.timestamp_micros()),
                        CursorValue::Uuid(boundary.id),
                    ],
                },
                database_now.timestamp(),
                CURSOR_TTL_SECONDS,
            )
            .map_err(|error| AppError::Internal(error.into()))
    })
    .transpose()
}

pub async fn session_after(
    state: &AppState,
    token: Option<&str>,
    binding: &CursorBinding<'_>,
) -> Result<Option<Uuid>, AppError> {
    let Some(token) = token else {
        return Ok(None);
    };
    let database_now = db::database_cursor_clock(&state.pool).await?;
    let position = state
        .api_cursor()
        .verify(token, binding, database_now.timestamp())
        .map_err(|_| AppError::InvalidCursor)?;
    match position.last.as_slice() {
        [CursorValue::Uuid(id)] if !id.is_nil() => Ok(Some(*id)),
        _ => Err(AppError::InvalidCursor),
    }
}

pub fn issue_session_cursor(
    state: &AppState,
    binding: &CursorBinding<'_>,
    next: Option<Uuid>,
    database_now: DateTime<Utc>,
) -> Result<Option<String>, AppError> {
    next.map(|id| {
        state
            .api_cursor()
            .issue(
                binding,
                &CursorPosition {
                    last: vec![CursorValue::Uuid(id)],
                },
                database_now.timestamp(),
                CURSOR_TTL_SECONDS,
            )
            .map_err(|error| AppError::Internal(error.into()))
    })
    .transpose()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limits_and_statuses_are_not_clamped_or_normalized() {
        assert_eq!(checked_limit(None, 25, 100).unwrap(), 25);
        assert_eq!(checked_limit(Some(100), 25, 100).unwrap(), 100);
        assert!(checked_limit(Some(0), 25, 100).is_err());
        assert!(checked_limit(Some(101), 25, 100).is_err());
        assert_eq!(
            checked_report_status(Some("reviewing")).unwrap(),
            Some("reviewing")
        );
        assert!(checked_report_status(Some("Reviewing")).is_err());
        assert!(checked_report_status(Some("")).is_err());
    }
}
