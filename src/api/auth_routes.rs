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
use std::sync::Arc;
use zeroize::{Zeroize, Zeroizing};

use crate::abuse::AbuseAction;
use crate::auth;
use crate::db;
use crate::error::{AppError, Result};
use crate::state::AppState;

/// Release a retryable request without deleting a guard marker that may have
/// been committed before the expensive or database-backed work failed.
/// Reacquisition rotates the lease token, so the failed worker remains fenced.
async fn yield_idempotency_lease_after_retryable_failure(
    state: &AppState,
    lease: &db::IdempotencyLease,
) -> Result<(), AppError> {
    if !db::yield_idempotency_lease(&state.pool, lease).await? {
        return Err(AppError::IdempotencyInProgress { retry_after: 1 });
    }
    Ok(())
}

pub async fn register(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    mut request: ApiJson<RegistrationRequest>,
) -> Result<Response, AppError> {
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
    let peer_ip = client_ip(peer.ip(), &headers, &state);
    let actors = vec![ip_actor(peer_ip)];
    let principal_scope = format!("registration:{peer_ip}");
    // Commit the cheap reservation before any PoW or password derivation.
    // Concurrent duplicates now single-flight rather than multiplying CPU
    // work, and the exact request owns the consumed proof across a crash.
    let mut reserve_tx = state.pool.begin().await?;
    let lease = match db::acquire_idempotency_in_tx(
        state.api_control(),
        &mut reserve_tx,
        &request.idempotency(
            None,
            principal_scope.as_bytes(),
            db::ApiPrincipalKind::Anonymous,
            "POST",
            "/api/v1/register",
        ),
    )
    .await?
    {
        db::IdempotencyAcquire::Acquired(lease) => lease,
        db::IdempotencyAcquire::Replay(replay) => {
            reserve_tx.commit().await?;
            return idempotency_replay_response(replay);
        }
        db::IdempotencyAcquire::FingerprintConflict | db::IdempotencyAcquire::RotationConflict => {
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
                message: "too many unfinished requests; try again later".into(),
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
    // A completed request must still replay its original response, which is
    // why these checks follow idempotency acquisition. Keep the new lease and
    // the cheap capacity precheck in one transaction: a database failure rolls
    // the reservation back instead of leaving a 180-second orphan lease. The
    // creation transaction rechecks both policies after password derivation,
    // closing the cross-node race.
    if state.registration_is_closed() {
        if !db::abandon_idempotency_lease_in_tx(&mut reserve_tx, &lease).await? {
            reserve_tx.rollback().await?;
            return Err(AppError::IdempotencyInProgress { retry_after: 1 });
        }
        reserve_tx.commit().await?;
        return Err(AppError::Forbidden);
    }
    if db::registrations_last_hour_in_tx(&mut reserve_tx).await?
        >= i64::from(state.config.registration_rate_per_hour)
    {
        if !db::abandon_idempotency_lease_in_tx(&mut reserve_tx, &lease).await? {
            reserve_tx.rollback().await?;
            return Err(AppError::IdempotencyInProgress { retry_after: 1 });
        }
        reserve_tx.commit().await?;
        return Err(AppError::TooManyRequests {
            message: "registration capacity limit reached; try again later".into(),
            retry_after: 3600,
        });
    }
    reserve_tx.commit().await?;

    // Consume/fence PoW before entering the Argon2/SCRAM worker pool. The
    // idempotency row remembers this exact request's guard result across a
    // crash; concurrent requests from the same actor observe the advanced
    // abuse step before they can multiply password work.
    let mut guard_verified = lease.guard_verified;
    if !guard_verified {
        let mut guard_tx = state.pool.begin().await?;
        if !db::resume_idempotency_lease_in_tx(&mut guard_tx, &lease, API_IDEMPOTENCY_LEASE_SECONDS)
            .await?
        {
            guard_tx.rollback().await?;
            return Err(AppError::IdempotencyInProgress { retry_after: 1 });
        }
        match state
            .abuse
            .verify_or_allow_in_tx_v2(
                &mut guard_tx,
                AbuseAction::Registration,
                &principal_scope,
                &actors,
                body.pow.as_ref(),
                &pow_intent,
            )
            .await?
        {
            crate::abuse::TransactionalGuardOutcome::Allowed(_) => {
                if !db::mark_idempotency_guard_verified_in_tx(&mut guard_tx, &lease).await? {
                    guard_tx.rollback().await?;
                    return Err(AppError::IdempotencyInProgress { retry_after: 1 });
                }
                guard_tx.commit().await?;
                guard_verified = true;
            }
            crate::abuse::TransactionalGuardOutcome::DeniedNeedsCommit(error) => {
                if !db::abandon_idempotency_lease_in_tx(&mut guard_tx, &lease).await? {
                    guard_tx.rollback().await?;
                    return Err(AppError::IdempotencyInProgress { retry_after: 1 });
                }
                guard_tx.commit().await?;
                state
                    .metrics
                    .rate_limited_total
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                return Err(rate_limited(error));
            }
        }
    }
    let prepared = match db::prepare_registration(
        &username,
        &password,
        state.config.scram_iterations,
        state.config.scram_sha1_enabled,
    )
    .await
    {
        Ok(prepared) => prepared,
        Err(error) => {
            // Preserve the already-consumed proof marker but fence this
            // worker. An exact retry may immediately reacquire the request
            // instead of solving PoW twice after transient worker overload.
            yield_idempotency_lease_after_retryable_failure(&state, &lease).await?;
            return Err(registration_error(error));
        }
    };
    let mut tx = state.pool.begin().await?;
    if !db::resume_idempotency_lease_in_tx(&mut tx, &lease, API_IDEMPOTENCY_LEASE_SECONDS).await? {
        tx.rollback().await?;
        return Err(AppError::IdempotencyInProgress { retry_after: 1 });
    }
    let outcome = match db::create_user_with_invitation_guarded_in_tx_v2(
        &mut tx,
        &state.abuse,
        &principal_scope,
        &actors,
        body.pow.as_ref(),
        &pow_intent,
        guard_verified,
        prepared,
        body.invitation_token.as_deref(),
        state.config.invitation_required,
        state.config.registration_rate_per_hour,
        Some(lease.request_id),
    )
    .await
    {
        Ok(outcome) => outcome,
        Err(error) => {
            tx.rollback().await?;
            // The anti-abuse guard was committed before credential
            // publication. Keep that marker while allowing the same request
            // key to reacquire immediately after a transient database error.
            yield_idempotency_lease_after_retryable_failure(&state, &lease).await?;
            return Err(AppError::Internal(error));
        }
    };
    let (user_id, username) = match outcome {
        db::GuardedRegistrationOutcome::Created(mut user) => {
            let identity = (user.id, std::mem::take(&mut user.username));
            user.password_hash.zeroize();
            user.password_hash.clear();
            identity
        }
        db::GuardedRegistrationOutcome::AbuseDenied(error) => {
            if !db::abandon_idempotency_lease_in_tx(&mut tx, &lease).await? {
                tx.rollback().await?;
                return Err(AppError::IdempotencyInProgress { retry_after: 1 });
            }
            tx.commit().await?;
            state
                .metrics
                .rate_limited_total
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return Err(rate_limited(error));
        }
        db::GuardedRegistrationOutcome::Rejected(
            error @ (db::RegistrationError::UsernameTaken
            | db::RegistrationError::InvitationRejected),
        ) => {
            let reason = match error {
                db::RegistrationError::UsernameTaken => "username_unavailable",
                db::RegistrationError::InvitationRejected => "invitation_rejected",
                _ => unreachable!("pattern is restricted above"),
            };
            db::audit_registration_rejection_in_tx(&mut tx, lease.request_id, reason).await?;
            let response_body = registration_rejection_body()?;
            if !db::complete_idempotency_in_tx(
                state.api_control(),
                &mut tx,
                &lease,
                StatusCode::BAD_REQUEST.as_u16(),
                &json_replay_headers(),
                &response_body,
            )
            .await?
            {
                return Err(AppError::Internal(anyhow::anyhow!(
                    "registration rejection idempotency lease changed"
                )));
            }
            tx.commit().await?;
            return json_bytes_response(StatusCode::BAD_REQUEST, response_body);
        }
        db::GuardedRegistrationOutcome::Rejected(db::RegistrationError::CapacityExhausted) => {
            if !db::abandon_idempotency_lease_in_tx(&mut tx, &lease).await? {
                tx.rollback().await?;
                return Err(AppError::IdempotencyInProgress { retry_after: 1 });
            }
            tx.commit().await?;
            state
                .metrics
                .capacity_reservations_rejected_total
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return Err(AppError::TooManyRequests {
                message: "deployment account capacity reached".into(),
                retry_after: 3600,
            });
        }
        db::GuardedRegistrationOutcome::Rejected(error) => {
            if !db::abandon_idempotency_lease_in_tx(&mut tx, &lease).await? {
                tx.rollback().await?;
                return Err(AppError::IdempotencyInProgress { retry_after: 1 });
            }
            tx.commit().await?;
            return Err(registration_error(error));
        }
    };
    if !db::mark_idempotency_guard_verified_in_tx(&mut tx, &lease).await? {
        return Err(AppError::Internal(anyhow::anyhow!(
            "registration idempotency guard marker changed"
        )));
    }
    if !db::bind_idempotency_actor_in_tx(&mut tx, &lease, user_id).await? {
        return Err(AppError::Internal(anyhow::anyhow!(
            "registration idempotency ownership changed"
        )));
    }
    let response_body =
        serde_json::to_vec(&json!({"jid":format!("{}@{}", username, state.config.domain)}))
            .map_err(|error| AppError::Internal(error.into()))?;
    if !db::complete_idempotency_in_tx(
        state.api_control(),
        &mut tx,
        &lease,
        StatusCode::CREATED.as_u16(),
        &json_replay_headers(),
        &response_body,
    )
    .await?
    {
        return Err(AppError::Internal(anyhow::anyhow!(
            "registration idempotency lease changed"
        )));
    }
    tx.commit().await?;
    state
        .metrics
        .registrations_total
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    json_bytes_response(StatusCode::CREATED, response_body)
}

fn registration_rejection_body() -> Result<Vec<u8>, AppError> {
    serde_json::to_vec(&json!({
        "error": {
            "code": "bad_request",
            "message": "registration request could not be accepted"
        }
    }))
    .map_err(|error| AppError::Internal(error.into()))
}

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

fn login_unauthorized_body() -> Result<Vec<u8>, AppError> {
    serde_json::to_vec(&json!({
        "error": {
            "code": "unauthorized",
            "message": "authentication required"
        }
    }))
    .map_err(|error| AppError::Internal(error.into()))
}

fn login_unauthorized_headers() -> std::collections::BTreeMap<String, String> {
    let mut headers = json_replay_headers();
    headers.insert(
        "www-authenticate".to_owned(),
        "Bearer realm=\"northstar\"".to_owned(),
    );
    headers
}

async fn complete_login_failure(
    state: &AppState,
    mut tx: sqlx::Transaction<'_, sqlx::Postgres>,
    lease: &db::IdempotencyLease,
    actors: &[String],
    attempt_already_recorded: bool,
) -> Result<Response, AppError> {
    if !attempt_already_recorded {
        state
            .abuse
            .record_failure_in_tx(&mut tx, AbuseAction::Login, actors)
            .await?;
    }
    if !db::mark_idempotency_guard_verified_in_tx(&mut tx, lease).await? {
        return Err(AppError::IdempotencyInProgress { retry_after: 1 });
    }
    let body = login_unauthorized_body()?;
    let headers = login_unauthorized_headers();
    if !db::complete_idempotency_in_tx(
        state.api_control(),
        &mut tx,
        lease,
        StatusCode::UNAUTHORIZED.as_u16(),
        &headers,
        &body,
    )
    .await?
    {
        return Err(AppError::Internal(anyhow::anyhow!(
            "login failure idempotency lease changed"
        )));
    }
    tx.commit().await?;
    let mut response = Response::builder().status(StatusCode::UNAUTHORIZED);
    for (name, value) in headers {
        response = response.header(name, value);
    }
    response
        .body(Body::from(body))
        .map_err(|error| AppError::Internal(error.into()))
}

pub async fn login(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    mut request: ApiJson<Credentials>,
) -> Result<Response, AppError> {
    let body = &request.value;
    let peer_ip = client_ip(peer.ip(), &headers, &state);
    let login_identity = login_abuse_identity(peer_ip, &body.username);
    let actors = login_identity
        .as_ref()
        .map(|(_, actors)| actors.clone())
        .unwrap_or_else(|| vec![ip_actor(peer_ip)]);

    if body.username.is_empty()
        || body.username.len() > 1024
        || body.password.is_empty()
        || body.password.len() > 1024
    {
        state
            .abuse
            .record_failure(AbuseAction::Login, &actors)
            .await?;
        return Err(AppError::Unauthorized);
    }

    let pow_intent = body.pow_intent();
    let password = Zeroizing::new(std::mem::take(&mut request.value.password));
    let body = &request.value;

    let (subject, actors) = login_identity.expect("validated login abuse identity");
    // Reserve on the canonical, non-secret account scope before PoW and
    // password verification. The request actor remains anonymous and
    // immutable; ownership is bound only after successful authentication.
    let capacity_scope = ip_actor(peer_ip);
    let mut idempotency = request.idempotency(
        None,
        subject.as_bytes(),
        db::ApiPrincipalKind::Anonymous,
        "POST",
        "/api/v1/login",
    );
    idempotency.capacity_scope = capacity_scope.as_bytes();
    let mut reserve_tx = state.pool.begin().await?;
    let (lease, replay) =
        match db::acquire_idempotency_in_tx(state.api_control(), &mut reserve_tx, &idempotency)
            .await?
        {
            db::IdempotencyAcquire::Acquired(lease) => {
                reserve_tx.commit().await?;
                (Some(lease), None)
            }
            db::IdempotencyAcquire::Replay(replay) => {
                reserve_tx.commit().await?;
                (None, Some(replay))
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
                    message: "too many unfinished requests; try again later".into(),
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
    let mut proof_recorded_attempt = false;
    if let Some(lease) = lease.as_ref().filter(|lease| !lease.guard_verified) {
        let mut guard_tx = state.pool.begin().await?;
        if !db::resume_idempotency_lease_in_tx(&mut guard_tx, lease, API_IDEMPOTENCY_LEASE_SECONDS)
            .await?
        {
            guard_tx.rollback().await?;
            return Err(AppError::IdempotencyInProgress { retry_after: 1 });
        }
        let req = state
            .abuse
            .current_requirement_in_tx(&mut guard_tx, AbuseAction::Login, &actors)
            .await?;
        if req.work_factor > 1 || req.retry_after_seconds > 0 {
            if body.pow.is_none() {
                if !db::abandon_idempotency_lease_in_tx(&mut guard_tx, lease).await? {
                    guard_tx.rollback().await?;
                    return Err(AppError::IdempotencyInProgress { retry_after: 1 });
                }
                guard_tx.commit().await?;
                state
                    .metrics
                    .rate_limited_total
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                return Err(rate_limited(GuardError::Required(req)));
            }
            let proof = state
                .abuse
                .verify_or_allow_in_tx_v2(
                    &mut guard_tx,
                    AbuseAction::Login,
                    &subject,
                    &actors,
                    body.pow.as_ref(),
                    &pow_intent,
                )
                .await?;
            match proof {
                crate::abuse::TransactionalGuardOutcome::Allowed(_) => {
                    proof_recorded_attempt = true;
                    if !db::mark_idempotency_guard_verified_in_tx(&mut guard_tx, lease).await? {
                        guard_tx.rollback().await?;
                        return Err(AppError::IdempotencyInProgress { retry_after: 1 });
                    }
                }
                crate::abuse::TransactionalGuardOutcome::DeniedNeedsCommit(error) => {
                    if !db::abandon_idempotency_lease_in_tx(&mut guard_tx, lease).await? {
                        guard_tx.rollback().await?;
                        return Err(AppError::IdempotencyInProgress { retry_after: 1 });
                    }
                    guard_tx.commit().await?;
                    state
                        .metrics
                        .rate_limited_total
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    return Err(rate_limited(error));
                }
            }
        }
        guard_tx.commit().await?;
    }

    let prepared = match db::prepare_login(
        &state.pool,
        &body.username,
        &password,
        state.config.scram_iterations,
        state.config.scram_sha1_enabled,
    )
    .await
    {
        Ok(prepared) => prepared,
        Err(error) if crate::password_work::is_overloaded(&error) => {
            // Overload is not an authentication failure and must not advance
            // failure penalties. Release a newly acquired idempotency lease so
            // the client can retry once capacity is available.
            if let Some(lease) = lease.as_ref() {
                yield_idempotency_lease_after_retryable_failure(&state, lease).await?;
            }
            return Err(AppError::Unavailable(
                "password authentication capacity is temporarily exhausted; retry later".into(),
            ));
        }
        Err(error) if auth::is_password_verifier_integrity_error(&error) => {
            // Do not turn a corrupt stored verifier into an unauthenticated
            // account oracle. prepare_login already performed bounded dummy
            // Argon2 work; retain a high-signal operator metric/log while the
            // public response follows the exact ordinary-login-failure path.
            state
                .metrics
                .authentication_backend_failures_total
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            tracing::error!(
                ?error,
                "REST login stored verifier failed integrity validation"
            );
            None
        }
        Err(error) => {
            if let Some(lease) = lease.as_ref() {
                yield_idempotency_lease_after_retryable_failure(&state, lease).await?;
            }
            state
                .metrics
                .authentication_backend_failures_total
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            tracing::error!(
                integrity_failure = auth::is_password_verifier_integrity_error(&error),
                ?error,
                "REST login verifier backend failed"
            );
            return Err(AppError::Unavailable(
                "password authentication backend is temporarily unavailable; retry later".into(),
            ));
        }
    };
    // A replay never bypasses current credential verification. The database
    // acquisition already checked the original session token, auth epoch,
    // account status, and expiry before decrypting a successful response.
    // Failed replays deliberately perform the real/dummy password work too,
    // but do not advance the abuse step a second time.
    if let Some(replay) = replay {
        return idempotency_replay_response(replay);
    }
    let lease = lease.expect("acquired lease exists when response is not replayed");
    let Some(prepared) = prepared else {
        let mut tx = state.pool.begin().await?;
        if !db::resume_idempotency_lease_in_tx(&mut tx, &lease, API_IDEMPOTENCY_LEASE_SECONDS)
            .await?
        {
            tx.rollback().await?;
            return Err(AppError::IdempotencyInProgress { retry_after: 1 });
        }
        return complete_login_failure(
            &state,
            tx,
            &lease,
            &actors,
            lease.guard_verified || proof_recorded_attempt,
        )
        .await;
    };
    // Retain only response/session identity while the credential-bearing
    // PreparedLogin stays inside the atomic apply call and zeroizes on drop.
    let user_id = prepared.user.id;
    let username = prepared.user.username.clone();
    let is_admin = prepared.user.is_admin;
    let auth_generation = prepared.user.auth_generation;
    let mut tx = state.pool.begin().await?;
    if !db::resume_idempotency_lease_in_tx(&mut tx, &lease, API_IDEMPOTENCY_LEASE_SECONDS).await? {
        tx.rollback().await?;
        return Err(AppError::IdempotencyInProgress { retry_after: 1 });
    }
    let login_applied = match db::apply_prepared_login_in_tx(&mut tx, prepared).await {
        Ok(applied) => applied,
        Err(error) => {
            tx.rollback().await?;
            yield_idempotency_lease_after_retryable_failure(&state, &lease).await?;
            state
                .metrics
                .authentication_backend_failures_total
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            tracing::error!(?error, user_id = %user_id, "REST login publication backend failed");
            return Err(AppError::Unavailable(
                "password authentication backend is temporarily unavailable; retry later".into(),
            ));
        }
    };
    if !login_applied {
        return complete_login_failure(
            &state,
            tx,
            &lease,
            &actors,
            lease.guard_verified || proof_recorded_attempt,
        )
        .await;
    }
    if !db::bind_idempotency_actor_in_tx(&mut tx, &lease, user_id).await? {
        return Err(AppError::Internal(anyhow::anyhow!(
            "login idempotency ownership changed"
        )));
    }
    let created_session = db::create_api_session_in_tx(
        &mut tx,
        user_id,
        state.config.session_ttl_hours,
        Some(lease.request_id),
    )
    .await?;
    if !db::bind_idempotency_session_in_tx(
        &mut tx,
        &lease,
        created_session.id,
        &created_session.token_hash,
        auth_generation,
        created_session.expires_at,
    )
    .await?
    {
        return Err(AppError::Internal(anyhow::anyhow!(
            "login replay session binding changed"
        )));
    }
    let session = SessionResponse {
        token: created_session.token,
        jid: format!("{}@{}", username, state.config.domain),
        is_admin,
    };
    let response_body =
        serde_json::to_vec(&session).map_err(|error| AppError::Internal(error.into()))?;
    if !db::complete_idempotency_in_tx(
        state.api_control(),
        &mut tx,
        &lease,
        StatusCode::OK.as_u16(),
        &json_replay_headers(),
        &response_body,
    )
    .await?
    {
        return Err(AppError::Internal(anyhow::anyhow!(
            "login idempotency lease changed"
        )));
    }
    tx.commit().await?;
    json_bytes_response(StatusCode::OK, response_body)
}

pub async fn logout(
    State(state): State<Arc<AppState>>,
    Extension(ApiRequestId(request_id)): Extension<ApiRequestId>,
    headers: HeaderMap,
) -> Result<Json<Value>, AppError> {
    let token = bearer_token(&headers)?;
    let mut tx = state.pool.begin().await?;
    db::delete_api_session_audited_in_tx(&mut tx, token, request_id).await?;
    tx.commit().await?;
    Ok(Json(json!({"logged_out":true})))
}

pub async fn anti_abuse_challenge(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<ChallengeRequest>,
) -> Result<Json<Value>, AppError> {
    let action = AbuseAction::parse(&body.action)
        .ok_or_else(|| AppError::BadRequest("unknown anti-abuse action".into()))?;
    let peer_ip = client_ip(peer.ip(), &headers, &state);
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
            let user = current_user(&state, &headers).await?;
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
    state
        .metrics
        .anti_abuse_challenges_total
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let issued = match body.intent.as_ref() {
        Some(requested) => {
            let intent = crate::abuse::PowIntent::from_request(action, requested)
                .map_err(|error| AppError::BadRequest(error.to_string()))?;
            state
                .abuse
                .issue_v2(action, &subject, &actors, &intent)
                .await
        }
        None => state.abuse.issue(action, &subject, &actors).await,
    };
    let challenge = match issued {
        Ok(challenge) => challenge,
        Err(error) => {
            if let Some(capacity) = error.downcast_ref::<crate::abuse::ChallengeCapacityExceeded>()
            {
                state
                    .metrics
                    .rate_limited_total
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
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
