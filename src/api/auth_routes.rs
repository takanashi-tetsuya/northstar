use crate::api::*;
use axum::body::Body;
use axum::http::HeaderMap;
use axum::{
    extract::{ConnectInfo, Extension, State},
    http::StatusCode,
    response::Response,
    Json,
};
use serde_json::json;
use serde_json::Value;
use std::net::SocketAddr;
use zeroize::Zeroizing;

use crate::abuse::AbuseAction;
use crate::auth;
use crate::db;
use crate::error::{AppError, Result};
use crate::services::challenge_issuance::ChallengeIssueRequest;
use crate::state::{
    api_session_http::ApiSessionHttpContext, http_challenge_endpoint::HttpChallengeEndpointContext,
    http_registration_endpoint::HttpRegistrationEndpointContext, HttpLoginEndpointContext,
};

pub async fn register(
    State(context): State<HttpRegistrationEndpointContext>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    mut request: ApiJson<RegistrationRequest>,
) -> Result<Response, AppError> {
    use crate::services::account::{HttpRegistrationOutcome as Outcome, HttpRegistrationRequest};

    let body = &request.value;
    if body
        .invitation_token
        .as_deref()
        .is_some_and(|token| token.trim().len() > 512)
    {
        return Err(AppError::BadRequest(
            "invitation token is invalid or unavailable".into(),
        ));
    }
    let username = auth::normalize_username(&body.username)
        .map_err(|error| AppError::BadRequest(error.to_string()))?;
    auth::validate_password(&body.password)
        .map_err(|error| AppError::BadRequest(error.to_string()))?;
    let pow_intent = body.pow_intent();
    let password = Zeroizing::new(std::mem::take(&mut request.value.password));
    let body = &request.value;
    let peer_ip =
        super::client_ip_with_trusted_proxies(peer.ip(), &headers, context.trusted_proxies());
    let actors = vec![ip_actor(peer_ip)];
    let principal_scope = format!("registration:{peer_ip}");
    let outcome = context
        .service()
        .register_http(HttpRegistrationRequest {
            idempotency: request.idempotency(
                None,
                principal_scope.as_bytes(),
                db::ApiPrincipalKind::Anonymous,
                "POST",
                "/api/v1/register",
            ),
            username: &username,
            password: &password,
            invitation_token: body.invitation_token.as_deref(),
            proof: body.pow.as_ref(),
            intent: &pow_intent,
            subject: &principal_scope,
            actors: &actors,
            availability: context.availability(),
        })
        .await?;
    match outcome {
        Outcome::Created(body) => {
            context.created();
            json_bytes_response(StatusCode::CREATED, body)
        }
        Outcome::Rejected(body) => json_bytes_response(StatusCode::BAD_REQUEST, body),
        Outcome::Replay(response) => idempotency_replay_response(response),
        Outcome::AbuseDenied(error) => {
            context.abuse_denied();
            Err(rate_limited(error))
        }
        Outcome::CapacityExhausted => {
            context.capacity_exhausted();
            Err(AppError::TooManyRequests {
                message: "deployment account capacity reached".into(),
                retry_after: 3600,
            })
        }
        Outcome::Closed => Err(AppError::Forbidden),
        Outcome::RateLimited => Err(AppError::TooManyRequests {
            message: "registration capacity limit reached; try again later".into(),
            retry_after: 3600,
        }),
        Outcome::PasswordWorkOverloaded => Err(AppError::Unavailable(
            "password registration capacity is temporarily exhausted; retry later".into(),
        )),
        Outcome::InvalidUsername => Err(AppError::BadRequest("username is invalid".into())),
        Outcome::InvitationRejected | Outcome::UsernameTaken => Err(AppError::BadRequest(
            "registration request could not be accepted".into(),
        )),
        Outcome::IdempotencyConflict => Err(AppError::IdempotencyConflict),
        Outcome::ReplayInvalidated => Err(AppError::IdempotencyReplayInvalidated),
        Outcome::Busy(retry_after) => Err(AppError::IdempotencyBusy { retry_after }),
        Outcome::CapacityLimited(retry_after) => Err(AppError::TooManyRequests {
            message: "too many unfinished requests; try again later".into(),
            retry_after,
        }),
        Outcome::InProgress(retry_after) => Err(AppError::IdempotencyInProgress { retry_after }),
        Outcome::LeaseLost => Err(AppError::IdempotencyInProgress { retry_after: 1 }),
    }
}

#[cfg(test)]
fn registration_error(error: db::RegistrationError) -> AppError {
    match error {
        db::RegistrationError::InvalidUsername(_) => {
            AppError::BadRequest("username is invalid".into())
        }
        db::RegistrationError::InvitationRejected | db::RegistrationError::UsernameTaken => {
            AppError::BadRequest("registration request could not be accepted".into())
        }
        db::RegistrationError::Closed => AppError::Forbidden,
        db::RegistrationError::RateLimited => AppError::TooManyRequests {
            message: "registration capacity limit reached; try again later".into(),
            retry_after: 3600,
        },
        db::RegistrationError::CapacityExhausted => AppError::TooManyRequests {
            message: "deployment account capacity reached".into(),
            retry_after: 3600,
        },
        db::RegistrationError::PasswordWorkOverloaded => AppError::Unavailable(
            "password registration capacity is temporarily exhausted; retry later".into(),
        ),
        db::RegistrationError::Internal(error) => AppError::Internal(error),
    }
}

pub async fn login(
    State(context): State<HttpLoginEndpointContext>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    mut request: ApiJson<Credentials>,
) -> Result<Response, AppError> {
    use crate::services::http_login::{HttpLoginOutcome as Outcome, HttpLoginRequest};

    let peer_ip =
        super::client_ip_with_trusted_proxies(peer.ip(), &headers, context.trusted_proxies());
    let login_identity = login_abuse_identity(peer_ip, &request.value.username);
    let (subject, actors) =
        login_identity.unwrap_or_else(|| (String::new(), vec![ip_actor(peer_ip)]));
    let pow_intent = request.value.pow_intent();
    let password = Zeroizing::new(std::mem::take(&mut request.value.password));
    // The service rejects invalid credential bounds before the repository
    // acquires an idempotency lease, preserving the original abuse penalty.
    let capacity_scope = ip_actor(peer_ip);
    let mut idempotency = request.idempotency(
        None,
        subject.as_bytes(),
        db::ApiPrincipalKind::Anonymous,
        "POST",
        "/api/v1/login",
    );
    idempotency.capacity_scope = capacity_scope.as_bytes();
    let outcome = context
        .service()
        .login(HttpLoginRequest {
            idempotency,
            username: &request.value.username,
            password: &password,
            subject: &subject,
            actors: &actors,
            proof: request.value.pow.as_ref(),
            intent: &pow_intent,
        })
        .await?;
    match outcome {
        Outcome::Committed(response) => {
            let status = StatusCode::from_u16(response.status)
                .map_err(|error| AppError::Internal(error.into()))?;
            let mut result = Response::builder().status(status);
            for (name, value) in response.headers {
                result = result.header(name, value);
            }
            result
                .body(Body::from(response.body))
                .map_err(|error| AppError::Internal(error.into()))
        }
        Outcome::Replay(response) => idempotency_replay_response(response),
        Outcome::Unauthorized => Err(AppError::Unauthorized),
        Outcome::AbuseDenied(error) => {
            context.abuse_denied();
            Err(rate_limited(error))
        }
        Outcome::PasswordWorkOverloaded => Err(AppError::Unavailable(
            "password authentication capacity is temporarily exhausted; retry later".into(),
        )),
        Outcome::BackendUnavailable => {
            context.backend_unavailable();
            Err(AppError::Unavailable(
                "password authentication backend is temporarily unavailable; retry later".into(),
            ))
        }
        Outcome::IdempotencyConflict => Err(AppError::IdempotencyConflict),
        Outcome::ReplayInvalidated => Err(AppError::IdempotencyReplayInvalidated),
        Outcome::Busy(retry_after) => Err(AppError::IdempotencyBusy { retry_after }),
        Outcome::CapacityLimited(retry_after) => Err(AppError::TooManyRequests {
            message: "too many unfinished requests; try again later".into(),
            retry_after,
        }),
        Outcome::InProgress(retry_after) => Err(AppError::IdempotencyInProgress { retry_after }),
        Outcome::LeaseLost => Err(AppError::IdempotencyInProgress { retry_after: 1 }),
    }
}

pub async fn logout(
    State(state): State<ApiSessionHttpContext>,
    Extension(ApiRequestId(request_id)): Extension<ApiRequestId>,
    headers: HeaderMap,
) -> Result<Json<Value>, AppError> {
    let token = bearer_token(&headers)?;
    state.logout(token, request_id).await?;
    Ok(Json(json!({"logged_out":true})))
}

pub async fn anti_abuse_challenge(
    State(context): State<HttpChallengeEndpointContext>,
    State(queries): State<crate::state::ApiQueryContext>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<ChallengeRequest>,
) -> Result<Json<Value>, AppError> {
    let action = AbuseAction::parse(&body.action)
        .ok_or_else(|| AppError::BadRequest("unknown anti-abuse action".into()))?;
    let peer_ip =
        super::client_ip_with_trusted_proxies(peer.ip(), &headers, context.trusted_proxies());
    let (subject, actors) = match action {
        AbuseAction::Registration => abuse_identity(action, peer_ip, None),
        AbuseAction::Login => login_abuse_identity(
            peer_ip,
            body.username.as_deref().ok_or_else(|| {
                AppError::BadRequest("username is required for login proof of work".into())
            })?,
        )
        .ok_or_else(|| AppError::BadRequest("login username is invalid".into()))?,
        _ => {
            let user = current_user_with_queries(&queries, &headers).await?;
            let (mut subject, actors) = abuse_identity(action, peer_ip, Some(&user));
            if action == AbuseAction::PasswordChange
                && body
                    .intent
                    .as_ref()
                    .is_some_and(|intent| intent.path == "/xmpp/account-remove")
            {
                subject = format!("account_remove:{}", user.id);
            }
            (subject, actors)
        }
    };
    context.requested();
    let intent = body
        .intent
        .as_ref()
        .map(|requested| crate::abuse::PowIntent::from_request(action, requested))
        .transpose()
        .map_err(|error| AppError::BadRequest(error.to_string()))?;
    let issued = context
        .issue(ChallengeIssueRequest {
            action,
            subject: &subject,
            actors: &actors,
            intent: intent.as_ref(),
        })
        .await;
    let challenge = match issued {
        Ok(challenge) => challenge,
        Err(error) => {
            if let Some(capacity) = error.downcast_ref::<crate::abuse::ChallengeCapacityExceeded>()
            {
                context.capacity_exhausted();
                return Err(AppError::TooManyRequests {
                    message: "proof-of-work challenge capacity reached; try again later".into(),
                    retry_after: capacity.retry_after_seconds(),
                });
            }
            if error
                .downcast_ref::<crate::abuse::LegacyPowV1Disabled>()
                .is_some()
            {
                return Err(AppError::BadRequest(
                    "proof-of-work v2 intent is required; the v1 compatibility window is closed"
                        .into(),
                ));
            }
            return Err(AppError::Internal(error));
        }
    };
    Ok(Json(json!(challenge)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::response::IntoResponse;

    #[tokio::test]
    async fn public_registration_rejections_do_not_enumerate_accounts_or_invitations() {
        let username = registration_error(db::RegistrationError::UsernameTaken).into_response();
        let invitation =
            registration_error(db::RegistrationError::InvitationRejected).into_response();
        assert_eq!(username.status(), invitation.status());
        let username_body = axum::body::to_bytes(username.into_body(), 4096)
            .await
            .unwrap();
        let invitation_body = axum::body::to_bytes(invitation.into_body(), 4096)
            .await
            .unwrap();
        assert_eq!(username_body, invitation_body);
        let body = std::str::from_utf8(&username_body).unwrap();
        assert!(!body.contains("username"));
        assert!(!body.contains("invitation"));
    }

    #[tokio::test]
    async fn password_work_overload_is_a_retryable_service_failure() {
        let response =
            registration_error(db::RegistrationError::PasswordWorkOverloaded).into_response();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["error"]["code"], "service_unavailable");
        assert_ne!(body["error"]["code"], "unauthorized");
    }
}
