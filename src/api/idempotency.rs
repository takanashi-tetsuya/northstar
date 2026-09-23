use crate::{error::AppError, services::api_mutations::StoredApiResponse};
use axum::{body::Body, response::Response};

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
        ApiMutationRejection::Conflict(message) => AppError::Conflict(message),
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
