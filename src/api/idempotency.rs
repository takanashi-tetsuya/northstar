use crate::{db, error::AppError, services::api_mutations::StoredApiResponse};
use axum::{body::Body, http::StatusCode, response::Response};
use serde_json::Value;
use uuid::Uuid;

// Compatibility adapter for mutation handlers still owning legacy transactions.
// New repository ports exchange StoredApiResponse directly.
pub(crate) struct StoredHttpResponse {
    inner: StoredApiResponse,
}
impl StoredHttpResponse {
    pub(crate) fn json(status: StatusCode, body: Value) -> Result<Self, AppError> {
        Ok(Self {
            inner: StoredApiResponse::json(status.as_u16(), body)?,
        })
    }
    pub(crate) fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.inner = self.inner.with_header(name, value);
        self
    }
    pub(crate) fn with_optional_replay_resource_id(mut self, id: Option<Uuid>) -> Self {
        self.inner = self.inner.with_optional_replay_resource_id(id);
        self
    }
    pub(crate) async fn persist_in_tx(
        &self,
        keyring: &db::ApiControlKeyring,
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        lease: &db::IdempotencyLease,
    ) -> Result<bool, AppError> {
        Ok(db::api_mutations::persist_response_in_tx(keyring, tx, lease, &self.inner).await?)
    }
    pub(crate) fn build_response(self) -> Result<Response, AppError> {
        stored_api_response(self.inner)
    }
}

pub(crate) fn stored_api_response(stored: StoredApiResponse) -> Result<Response, AppError> {
    let mut response = Response::builder().status(stored.status);
    for (name, value) in stored.headers {
        response = response.header(name, value);
    }
    response
        .body(Body::from(stored.body))
        .map_err(|error| AppError::Internal(error.into()))
}

pub(crate) fn mutation_rejection(
    rejection: crate::services::api_mutations::ApiMutationRejection,
) -> AppError {
    use crate::services::api_mutations::ApiMutationRejection;
    match rejection {
        ApiMutationRejection::Unauthorized => AppError::Unauthorized,
        ApiMutationRejection::Forbidden => AppError::Forbidden,
        ApiMutationRejection::BadRequest(message) => AppError::BadRequest(message.into()),
        ApiMutationRejection::Unavailable(message) => AppError::Unavailable(message),
        ApiMutationRejection::IdempotencyConflict => AppError::IdempotencyConflict,
        ApiMutationRejection::ReplayInvalidated => AppError::IdempotencyReplayInvalidated,
        ApiMutationRejection::Busy { retry_after } => AppError::IdempotencyBusy { retry_after },
        ApiMutationRejection::InProgress { retry_after } => {
            AppError::IdempotencyInProgress { retry_after }
        }
        ApiMutationRejection::CapacityLimited { retry_after } => AppError::TooManyRequests {
            message: "too many retained requests; try again later".into(),
            retry_after,
        },
    }
}
pub(crate) async fn complete_guard_denial(
    state: &crate::state::AppState,
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    lease: &db::IdempotencyLease,
    error: crate::abuse::GuardError,
) -> Result<Response, AppError> {
    let response = crate::services::api_mutations::guard_denial_response(error)?;
    if !db::api_mutations::persist_response_in_tx(state.api_control(), tx, lease, &response).await?
    {
        return Err(AppError::Internal(anyhow::anyhow!(
            "idempotency lease changed while recording a rate-limit denial"
        )));
    }
    stored_api_response(response)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn json_envelope_builds_the_same_cache_safe_representation() {
        let resource_id = Uuid::from_u128(7);
        let stored = StoredHttpResponse::json(
            StatusCode::ACCEPTED,
            serde_json::json!({"operation_id":"example","status":"pending"}),
        )
        .unwrap()
        .with_header("location", "/api/v1/admin/operations/example")
        .with_optional_replay_resource_id(Some(resource_id));

        assert_eq!(stored.inner.status, StatusCode::ACCEPTED.as_u16());
        assert_eq!(stored.inner.replay_resource_id, Some(resource_id));
        assert_eq!(
            stored
                .inner
                .headers
                .get("cache-control")
                .map(String::as_str),
            Some("no-store, max-age=0")
        );
        assert_eq!(
            stored.inner.headers.get("content-type").map(String::as_str),
            Some("application/json")
        );

        let response = stored.build_response().unwrap();
        assert_eq!(response.status(), StatusCode::ACCEPTED);
        assert_eq!(
            response.headers().get("location").unwrap(),
            "/api/v1/admin/operations/example"
        );
        let body = axum::body::to_bytes(response.into_body(), 1_024)
            .await
            .unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&body).unwrap(),
            serde_json::json!({"operation_id":"example","status":"pending"})
        );
    }
}
