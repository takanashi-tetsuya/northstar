//! REST extractors with a stable, non-diagnostic rejection contract.
//!
//! Axum's native path and query rejections contain useful parser diagnostics,
//! but those diagnostics are an implementation detail and can disclose more
//! about an endpoint's input model than clients need to know.  API handlers
//! should use these wrappers at the HTTP boundary and perform semantic
//! validation after extraction.

use std::ops::Deref;

use axum::{
    extract::{FromRequestParts, Path, Query},
    http::request::Parts,
};
use serde::de::DeserializeOwned;

use crate::error::AppError;

const INVALID_PARAMETERS_MESSAGE: &str = "request parameters are invalid";

fn invalid_parameters() -> AppError {
    AppError::BadRequest(INVALID_PARAMETERS_MESSAGE.into())
}

/// A path-parameter extractor whose rejection never exposes parser details.
#[derive(Clone, Copy, Debug)]
pub struct ApiPath<T>(pub T);

impl<T> Deref for ApiPath<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<S, T> FromRequestParts<S> for ApiPath<T>
where
    S: Send + Sync,
    T: DeserializeOwned + Send,
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        Path::<T>::from_request_parts(parts, state)
            .await
            .map(|Path(value)| Self(value))
            .map_err(|_| invalid_parameters())
    }
}

/// A query-string extractor whose rejection never exposes parser details.
///
/// Input models should use `#[serde(deny_unknown_fields)]`.  Serde then rejects
/// unknown names as well as duplicate scalar fields before the handler runs;
/// this wrapper maps both failures to the same public response.
#[derive(Clone, Copy, Debug)]
pub struct ApiQuery<T>(pub T);

impl<T> Deref for ApiQuery<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<S, T> FromRequestParts<S> for ApiQuery<T>
where
    S: Send + Sync,
    T: DeserializeOwned + Send,
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        Query::<T>::from_request_parts(parts, state)
            .await
            .map(|Query(value)| Self(value))
            .map_err(|_| invalid_parameters())
    }
}

#[cfg(test)]
mod tests {
    use axum::{
        body::{to_bytes, Body},
        http::{Request, StatusCode},
        response::IntoResponse,
    };
    use serde::Deserialize;
    use serde_json::json;
    use uuid::Uuid;

    use super::*;

    #[derive(Debug, Deserialize, PartialEq)]
    #[serde(deny_unknown_fields)]
    struct StrictQuery {
        id: Uuid,
        label: Option<String>,
    }

    async fn query(uri: &str) -> Result<ApiQuery<StrictQuery>, AppError> {
        let (mut parts, _) = Request::builder()
            .uri(uri)
            .body(Body::empty())
            .unwrap()
            .into_parts();
        ApiQuery::from_request_parts(&mut parts, &()).await
    }

    #[tokio::test]
    async fn query_accepts_valid_input_and_supports_accessors() {
        let id = Uuid::new_v4();
        let extracted = query(&format!("/search?id={id}&label=northstar"))
            .await
            .unwrap();
        assert_eq!(extracted.id, id);
        assert_eq!(extracted.label.as_deref(), Some("northstar"));
    }

    #[tokio::test]
    async fn invalid_uuid_unknown_and_duplicate_query_are_indistinguishable() {
        let id = Uuid::new_v4();
        let invalid = vec![
            "/search?id=not-a-uuid".to_owned(),
            format!("/search?id={id}&unknown=value"),
            format!("/search?id={id}&id={id}"),
        ];
        for uri in invalid {
            let error = query(&uri).await.unwrap_err();
            assert!(matches!(
                error,
                AppError::BadRequest(ref message) if message == INVALID_PARAMETERS_MESSAGE
            ));
        }
    }

    #[test]
    fn path_supports_deref() {
        let id = Uuid::new_v4();
        let extracted = ApiPath(id);
        assert_eq!(*extracted, id);
    }

    #[tokio::test]
    async fn path_and_query_rejections_have_one_json_body() {
        let query_rejection = query("/search?id=not-a-uuid").await.unwrap_err();
        let (mut parts, _) = Request::builder()
            .uri("/items/not-a-uuid")
            .body(Body::empty())
            .unwrap()
            .into_parts();
        let path_rejection = ApiPath::<Uuid>::from_request_parts(&mut parts, &())
            .await
            .unwrap_err();

        for rejection in [path_rejection, query_rejection] {
            let response = rejection.into_response();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
            let body = to_bytes(response.into_body(), 1024).await.unwrap();
            let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(
                body,
                json!({
                    "error": {
                        "code": "bad_request",
                        "message": INVALID_PARAMETERS_MESSAGE
                    }
                })
            );
        }
    }
}
