use axum::{
    http::{header, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("authentication required")]
    Unauthorized,
    #[error("administrator access required")]
    Forbidden,
    #[error("{0}")]
    BadRequest(String),
    #[error("{0}")]
    NotFound(String),
    #[error("cursor is invalid or expired")]
    InvalidCursor,
    #[error("{0}")]
    Conflict(String),
    #[error("Idempotency-Key was already used for a different request")]
    IdempotencyConflict,
    #[error("an identical idempotent request is still in progress")]
    IdempotencyInProgress { retry_after: u64 },
    #[error("the replayed login session is no longer valid; use a new Idempotency-Key")]
    IdempotencyReplayInvalidated,
    #[error("idempotency admission is busy; try again later")]
    IdempotencyBusy { retry_after: u64 },
    #[error("request body is too large")]
    PayloadTooLarge,
    #[error("rate limited")]
    RateLimited(serde_json::Value),
    #[error("{message}")]
    TooManyRequests { message: String, retry_after: u64 },
    #[error("{0}")]
    Unavailable(String),
    #[error("{0}")]
    OperationDisabled(String),
    #[error(transparent)]
    Internal(anyhow::Error),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, code, message) = match &self {
            Self::Unauthorized => {
                let mut response = (
                    StatusCode::UNAUTHORIZED,
                    Json(
                        json!({ "error": { "code": "unauthorized", "message": self.to_string() } }),
                    ),
                )
                    .into_response();
                response.headers_mut().insert(
                    header::WWW_AUTHENTICATE,
                    HeaderValue::from_static("Bearer realm=\"northstar\""),
                );
                return response;
            }
            Self::Forbidden => (StatusCode::FORBIDDEN, "forbidden", self.to_string()),
            Self::BadRequest(_) => (StatusCode::BAD_REQUEST, "bad_request", self.to_string()),
            Self::NotFound(_) => (StatusCode::NOT_FOUND, "not_found", self.to_string()),
            Self::InvalidCursor => (StatusCode::BAD_REQUEST, "invalid_cursor", self.to_string()),
            Self::Conflict(_) => (StatusCode::CONFLICT, "conflict", self.to_string()),
            Self::IdempotencyConflict => (
                StatusCode::CONFLICT,
                "idempotency_key_conflict",
                self.to_string(),
            ),
            Self::IdempotencyInProgress { retry_after } => {
                let mut response = (
                    StatusCode::CONFLICT,
                    Json(json!({ "error": { "code": "idempotency_in_progress", "message": self.to_string() } })),
                )
                    .into_response();
                if let Ok(value) = HeaderValue::from_str(&retry_after.to_string()) {
                    response.headers_mut().insert(header::RETRY_AFTER, value);
                }
                return response;
            }
            Self::IdempotencyReplayInvalidated => (
                StatusCode::CONFLICT,
                "idempotency_replay_invalidated",
                self.to_string(),
            ),
            Self::IdempotencyBusy { retry_after } => {
                let mut response = (
                    StatusCode::SERVICE_UNAVAILABLE,
                    Json(json!({ "error": { "code": "idempotency_busy", "message": self.to_string() } })),
                )
                    .into_response();
                if let Ok(value) = HeaderValue::from_str(&retry_after.to_string()) {
                    response.headers_mut().insert(header::RETRY_AFTER, value);
                }
                return response;
            }
            Self::PayloadTooLarge => (
                StatusCode::PAYLOAD_TOO_LARGE,
                "payload_too_large",
                self.to_string(),
            ),
            Self::Unavailable(_) => (
                StatusCode::SERVICE_UNAVAILABLE,
                "service_unavailable",
                self.to_string(),
            ),
            Self::OperationDisabled(_) => (
                StatusCode::SERVICE_UNAVAILABLE,
                "operation_disabled",
                self.to_string(),
            ),
            Self::RateLimited(details) => {
                let retry_after = details
                    .pointer("/requirement/retry_after_seconds")
                    .or_else(|| details.get("retry_after_seconds"))
                    .and_then(serde_json::Value::as_u64)
                    .unwrap_or_default()
                    .max(
                        details
                            .pointer("/requirement/hard_wait_seconds")
                            .and_then(serde_json::Value::as_u64)
                            .unwrap_or_default(),
                    );
                let mut response = (
                    StatusCode::TOO_MANY_REQUESTS,
                    Json(json!({ "error": { "code": "rate_limited", "message": "operation requires proof of work or cooldown", "details": details } })),
                ).into_response();
                if retry_after > 0 {
                    if let Ok(value) = HeaderValue::from_str(&retry_after.to_string()) {
                        response.headers_mut().insert(header::RETRY_AFTER, value);
                    }
                }
                return response;
            }
            Self::TooManyRequests {
                message,
                retry_after,
            } => {
                let mut response = (
                    StatusCode::TOO_MANY_REQUESTS,
                    Json(json!({ "error": { "code": "rate_limited", "message": message } })),
                )
                    .into_response();
                if let Ok(value) = HeaderValue::from_str(&retry_after.to_string()) {
                    response.headers_mut().insert(header::RETRY_AFTER, value);
                }
                return response;
            }
            Self::Internal(error) => {
                tracing::error!(?error, "request failed");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    "internal server error".into(),
                )
            }
        };
        (
            status,
            Json(json!({ "error": { "code": code, "message": message } })),
        )
            .into_response()
    }
}

fn retryable_database_sqlstate(code: &str) -> bool {
    // A serialization failure, deadlock, or bounded lock-acquisition failure
    // is a transaction scheduling outcome, not an application fault.
    // Returning the sanitized 503 below tells HTTP callers to retry and
    // avoids exposing PostgreSQL diagnostics.  In particular, PostgreSQL
    // reports NOWAIT/lock_timeout contention as 55P03 (lock_not_available).
    matches!(code, "40001" | "40P01" | "55P03")
}

fn retryable_sqlx_error(error: &sqlx::Error) -> bool {
    error
        .as_database_error()
        .and_then(|error| error.code())
        .is_some_and(|code| retryable_database_sqlstate(code.as_ref()))
}

/// Inspect the complete anyhow causal chain.  Database helpers may need to
/// roll back before returning a bounded lock failure and add operation context
/// while doing so; the original sqlx error remains the source of truth for the
/// HTTP retry classification.
fn retryable_database_error(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause
            .downcast_ref::<sqlx::Error>()
            .is_some_and(retryable_sqlx_error)
    })
}

impl AppError {
    pub(crate) fn from_internal(error: anyhow::Error) -> Self {
        if retryable_database_error(&error) {
            return Self::Unavailable(
                "database operation is temporarily busy; retry the request".into(),
            );
        }
        Self::Internal(error)
    }
}

impl From<anyhow::Error> for AppError {
    fn from(value: anyhow::Error) -> Self {
        Self::from_internal(value)
    }
}

impl From<sqlx::Error> for AppError {
    fn from(value: sqlx::Error) -> Self {
        if retryable_sqlx_error(&value) {
            return Self::Unavailable(
                "database operation is temporarily busy; retry the request".into(),
            );
        }
        Self::Internal(value.into())
    }
}

pub type Result<T, E = AppError> = std::result::Result<T, E>;

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        borrow::Cow,
        error::Error as StdError,
        fmt::{self, Display, Formatter},
    };

    #[derive(Debug)]
    struct TestLockNotAvailable;

    impl Display for TestLockNotAvailable {
        fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
            formatter.write_str("test lock is not available")
        }
    }

    impl StdError for TestLockNotAvailable {}

    impl sqlx::error::DatabaseError for TestLockNotAvailable {
        fn message(&self) -> &str {
            "test lock is not available"
        }

        fn code(&self) -> Option<Cow<'_, str>> {
            Some(Cow::Borrowed("55P03"))
        }

        fn as_error(&self) -> &(dyn StdError + Send + Sync + 'static) {
            self
        }

        fn as_error_mut(&mut self) -> &mut (dyn StdError + Send + Sync + 'static) {
            self
        }

        fn into_error(self: Box<Self>) -> Box<dyn StdError + Send + Sync + 'static> {
            self
        }

        fn kind(&self) -> sqlx::error::ErrorKind {
            sqlx::error::ErrorKind::Other
        }
    }

    #[tokio::test]
    async fn internal_errors_are_not_returned_to_clients() {
        let response =
            AppError::Internal(anyhow::anyhow!("database secret details")).into_response();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = axum::body::to_bytes(response.into_body(), 1024)
            .await
            .unwrap();
        let body = std::str::from_utf8(&body).unwrap();
        assert!(body.contains("internal server error"));
        assert!(!body.contains("database secret details"));
    }

    #[tokio::test]
    async fn invalid_cursor_has_one_typed_non_diagnostic_response() {
        let response = AppError::InvalidCursor.into_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = axum::body::to_bytes(response.into_body(), 1024)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["error"]["code"], "invalid_cursor");
        assert_eq!(body["error"]["message"], "cursor is invalid or expired");
    }

    #[tokio::test]
    async fn resource_not_found_has_a_typed_json_response() {
        let response = AppError::NotFound("operation does not exist".into()).into_response();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let body = axum::body::to_bytes(response.into_body(), 1024)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["error"]["code"], "not_found");
        assert_eq!(body["error"]["message"], "operation does not exist");
    }

    #[tokio::test]
    async fn idempotency_busy_is_a_retryable_service_error() {
        let response = AppError::IdempotencyBusy { retry_after: 1 }.into_response();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            response.headers().get(header::RETRY_AFTER),
            Some(&HeaderValue::from_static("1"))
        );
        let body = axum::body::to_bytes(response.into_body(), 1024)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["error"]["code"], "idempotency_busy");
    }

    #[test]
    fn authentication_and_rate_limit_responses_have_protocol_headers() {
        let unauthorized = AppError::Unauthorized.into_response();
        assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            unauthorized.headers().get(header::WWW_AUTHENTICATE),
            Some(&HeaderValue::from_static("Bearer realm=\"northstar\""))
        );
        assert_eq!(
            AppError::Forbidden.into_response().status(),
            StatusCode::FORBIDDEN
        );
        let limited = AppError::TooManyRequests {
            message: "slow down".into(),
            retry_after: 60,
        }
        .into_response();
        assert_eq!(
            limited.headers().get(header::RETRY_AFTER),
            Some(&HeaderValue::from_static("60"))
        );
        let pow_limited = AppError::RateLimited(json!({
            "requirement": {"retry_after_seconds": 0, "hard_wait_seconds": 15}
        }))
        .into_response();
        assert_eq!(
            pow_limited.headers().get(header::RETRY_AFTER),
            Some(&HeaderValue::from_static("15"))
        );
    }

    #[test]
    fn database_scheduling_conflicts_are_the_only_retryable_sqlstates() {
        assert!(retryable_database_sqlstate("40001"));
        assert!(retryable_database_sqlstate("40P01"));
        assert!(retryable_database_sqlstate("55P03"));
        assert!(!retryable_database_sqlstate("23505"));
        assert!(!retryable_database_sqlstate("42501"));
    }

    #[test]
    fn contextual_lock_not_available_remains_a_retryable_http_error() {
        let error = anyhow::Error::new(sqlx::Error::Database(Box::new(TestLockNotAvailable)))
            .context("upload storage capacity busy; retry upload cleanup completion");
        assert!(matches!(
            AppError::from_internal(error),
            AppError::Unavailable(message)
                if message == "database operation is temporarily busy; retry the request"
        ));
    }
}
