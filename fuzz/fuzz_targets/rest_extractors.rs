#![no_main]

use axum::{
    extract::FromRequestParts,
    http::{Request, StatusCode},
    response::{IntoResponse, Response},
};
use futures::executor::block_on;
use libfuzzer_sys::fuzz_target;
use serde::Deserialize;
use uuid::Uuid;

// `src/api/extract.rs` depends only on the public shape of AppError. Keeping a
// tiny rejection stub lets this target compile and execute the production
// extractor implementation without pulling the database/server graph into the
// libFuzzer process.
mod error {
    use axum::{
        http::StatusCode,
        response::{IntoResponse, Response},
    };

    #[derive(Debug)]
    pub enum AppError {
        BadRequest(String),
    }

    impl IntoResponse for AppError {
        fn into_response(self) -> Response {
            match self {
                Self::BadRequest(message) => (StatusCode::BAD_REQUEST, message).into_response(),
            }
        }
    }
}

#[path = "../../src/api/extract.rs"]
mod extract;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct StrictQuery {
    id: Option<Uuid>,
    cursor: Option<String>,
    limit: Option<u16>,
    enabled: Option<bool>,
}

fuzz_target!(|data: &[u8]| {
    if data.len() > 65_536 {
        return;
    }
    let query = String::from_utf8_lossy(data);
    let Ok(request) = Request::builder()
        .uri(format!("/fuzz?{query}"))
        .body(())
    else {
        return;
    };
    let (mut parts, _) = request.into_parts();
    let result = block_on(extract::ApiQuery::<StrictQuery>::from_request_parts(
        &mut parts,
        &(),
    ));
    match result {
        Ok(value) => {
            let StrictQuery {
                id,
                cursor,
                limit,
                enabled,
            } = value.0;
            let _ = (id, cursor.map(|value| value.len()), limit, enabled);
        }
        Err(error) => {
            let response: Response = error.into_response();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        }
    }

    // An unmatched path has no Axum router capture metadata. This still
    // exercises the production wrapper's non-diagnostic rejection contract.
    let request = Request::builder().uri("/fuzz/not-captured").body(()).unwrap();
    let (mut parts, _) = request.into_parts();
    let path = block_on(extract::ApiPath::<Uuid>::from_request_parts(
        &mut parts,
        &(),
    ));
    if let Err(error) = path {
        assert_eq!(error.into_response().status(), StatusCode::BAD_REQUEST);
    }
});
