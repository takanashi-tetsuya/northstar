use axum::body::Body;
use axum::http::StatusCode;
use axum::response::Response;
use serde_json::Value;
use std::collections::BTreeMap;
use uuid::Uuid;

use crate::api::json_replay_headers;
use crate::db;
use crate::error::AppError;

/// The canonical HTTP representation stored for an idempotent mutation and
/// returned for its first execution. Keeping both paths on the same envelope
/// prevents status, cache policy, content type, body, and resource metadata
/// from drifting between an initial response and a replay.
pub(crate) struct StoredHttpResponse {
    status: StatusCode,
    headers: BTreeMap<String, String>,
    body: Vec<u8>,
    replay_resource_id: Option<Uuid>,
}

impl StoredHttpResponse {
    pub(crate) fn json(status: StatusCode, body: Value) -> Result<Self, AppError> {
        Ok(Self {
            status,
            headers: json_replay_headers(),
            body: serde_json::to_vec(&body).map_err(|error| AppError::Internal(error.into()))?,
            replay_resource_id: None,
        })
    }

    pub(crate) fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.insert(name.into(), value.into());
        self
    }

    pub(crate) fn with_optional_replay_resource_id(
        mut self,
        replay_resource_id: Option<Uuid>,
    ) -> Self {
        self.replay_resource_id = replay_resource_id;
        self
    }

    pub(crate) async fn persist_in_tx(
        &self,
        keyring: &db::ApiControlKeyring,
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        lease: &db::IdempotencyLease,
    ) -> Result<bool, AppError> {
        match self.replay_resource_id {
            Some(resource_id) => {
                self.persist_with_resource_in_tx(keyring, tx, lease, resource_id)
                    .await
            }
            None => Ok(db::complete_idempotency_in_tx(
                keyring,
                tx,
                lease,
                self.status.as_u16(),
                &self.headers,
                &self.body,
            )
            .await?),
        }
    }

    async fn persist_with_resource_in_tx(
        &self,
        keyring: &db::ApiControlKeyring,
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        lease: &db::IdempotencyLease,
        replay_resource_id: Uuid,
    ) -> Result<bool, AppError> {
        Ok(db::complete_idempotency_with_resource_in_tx(
            keyring,
            tx,
            lease,
            self.status.as_u16(),
            &self.headers,
            &self.body,
            Some(replay_resource_id),
        )
        .await?)
    }

    pub(crate) fn build_response(self) -> Result<Response, AppError> {
        let mut response = Response::builder().status(self.status);
        for (name, value) in self.headers {
            response = response.header(name, value);
        }
        response
            .body(Body::from(self.body))
            .map_err(|error| AppError::Internal(error.into()))
    }
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

        assert_eq!(stored.status, StatusCode::ACCEPTED);
        assert_eq!(stored.replay_resource_id, Some(resource_id));
        assert_eq!(
            stored.headers.get("cache-control").map(String::as_str),
            Some("no-store, max-age=0")
        );
        assert_eq!(
            stored.headers.get("content-type").map(String::as_str),
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
