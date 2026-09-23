//! Durable REST login: idempotency, abuse admission, verifier work, and
//! session publication. Password work occurs outside SQL transactions.
use crate::{
    abuse::{AbuseAction, AbuseGuard, TransactionalGuardOutcome},
    auth, db,
    services::{
        api_mutations::{json_replay_headers, StoredApiResponse},
        http_login::{
            HttpLoginOutcome, HttpLoginPolicy, HttpLoginRepository, HttpLoginRequest,
            LoginFailureMetrics,
        },
    },
};
use anyhow::{anyhow, Result};
use serde::Serialize;
use sqlx::{PgPool, Postgres, Transaction};
use std::{collections::BTreeMap, sync::Arc};
use zeroize::Zeroize;

#[derive(Clone)]
pub(crate) struct PostgresHttpLoginRepository {
    pool: PgPool,
    abuse: Arc<AbuseGuard>,
    api_control: Arc<db::ApiControlKeyring>,
    policy: HttpLoginPolicy,
    metrics: Arc<dyn LoginFailureMetrics>,
}

impl PostgresHttpLoginRepository {
    pub(crate) fn new(
        pool: PgPool,
        abuse: Arc<AbuseGuard>,
        api_control: Arc<db::ApiControlKeyring>,
        policy: HttpLoginPolicy,
        metrics: Arc<dyn LoginFailureMetrics>,
    ) -> Self {
        Self {
            pool,
            abuse,
            api_control,
            policy,
            metrics,
        }
    }

    async fn yield_lease(&self, lease: &db::IdempotencyLease) -> Result<HttpLoginOutcome> {
        if db::yield_idempotency_lease(&self.pool, lease).await? {
            Ok(HttpLoginOutcome::BackendUnavailable)
        } else {
            Ok(HttpLoginOutcome::LeaseLost)
        }
    }

    async fn complete_failure(
        &self,
        mut tx: Transaction<'_, Postgres>,
        lease: &db::IdempotencyLease,
        actors: &[String],
        attempt_already_recorded: bool,
    ) -> Result<HttpLoginOutcome> {
        if !attempt_already_recorded {
            self.abuse
                .record_failure_in_tx(&mut tx, AbuseAction::Login, actors)
                .await?;
        }
        if !db::mark_idempotency_guard_verified_in_tx(&mut tx, lease).await? {
            return Ok(HttpLoginOutcome::LeaseLost);
        }
        let body = serde_json::to_vec(&serde_json::json!({
            "error": {"code": "unauthorized", "message": "authentication required"}
        }))?;
        let mut headers = json_replay_headers();
        headers.insert(
            "www-authenticate".to_owned(),
            "Bearer realm=\"northstar\"".to_owned(),
        );
        if !db::complete_idempotency_in_tx(&self.api_control, &mut tx, lease, 401, &headers, &body)
            .await?
        {
            return Err(anyhow!("login failure idempotency lease changed"));
        }
        tx.commit().await?;
        Ok(HttpLoginOutcome::Committed(StoredApiResponse {
            status: 401,
            headers,
            body,
            replay_resource_id: None,
        }))
    }
}

#[derive(Serialize)]
struct LoginSessionResponse {
    token: String,
    jid: String,
    is_admin: bool,
}
impl Drop for LoginSessionResponse {
    fn drop(&mut self) {
        self.token.zeroize();
    }
}

impl HttpLoginRepository for PostgresHttpLoginRepository {
    async fn record_invalid_login(&self, actors: &[String]) -> Result<()> {
        self.abuse.record_failure(AbuseAction::Login, actors).await
    }

    async fn login(&self, request: HttpLoginRequest<'_>) -> Result<HttpLoginOutcome> {
        use HttpLoginOutcome as Outcome;
        let mut reserve_tx = self.pool.begin().await?;
        let (lease, replay) = match db::acquire_idempotency_in_tx(
            &self.api_control,
            &mut reserve_tx,
            &request.idempotency,
        )
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
                return Ok(Outcome::IdempotencyConflict);
            }
            db::IdempotencyAcquire::ReplayInvalidated => {
                reserve_tx.rollback().await?;
                return Ok(Outcome::ReplayInvalidated);
            }
            db::IdempotencyAcquire::Busy {
                retry_after_seconds,
            } => {
                reserve_tx.rollback().await?;
                return Ok(Outcome::Busy(retry_after_seconds));
            }
            db::IdempotencyAcquire::CapacityLimited {
                retry_after_seconds,
            } => {
                reserve_tx.rollback().await?;
                return Ok(Outcome::CapacityLimited(retry_after_seconds));
            }
            db::IdempotencyAcquire::InProgress {
                retry_after_seconds,
            } => {
                reserve_tx.rollback().await?;
                return Ok(Outcome::InProgress(retry_after_seconds));
            }
        };

        let mut proof_recorded_attempt = false;
        if let Some(lease) = lease.as_ref().filter(|lease| !lease.guard_verified) {
            let mut guard_tx = self.pool.begin().await?;
            if !db::resume_idempotency_lease_in_tx(
                &mut guard_tx,
                lease,
                request.idempotency.lease_seconds,
            )
            .await?
            {
                guard_tx.rollback().await?;
                return Ok(Outcome::LeaseLost);
            }
            let requirement = self
                .abuse
                .current_requirement_in_tx(&mut guard_tx, AbuseAction::Login, request.actors)
                .await?;
            if requirement.work_factor > 1 || requirement.retry_after_seconds > 0 {
                if request.proof.is_none() {
                    if !db::abandon_idempotency_lease_in_tx(&mut guard_tx, lease).await? {
                        guard_tx.rollback().await?;
                        return Ok(Outcome::LeaseLost);
                    }
                    guard_tx.commit().await?;
                    return Ok(Outcome::AbuseDenied(crate::abuse::GuardError::Required(
                        requirement,
                    )));
                }
                match self
                    .abuse
                    .verify_or_allow_in_tx_v2(
                        &mut guard_tx,
                        AbuseAction::Login,
                        request.subject,
                        request.actors,
                        request.proof,
                        request.intent,
                    )
                    .await?
                {
                    TransactionalGuardOutcome::Allowed(_) => {
                        proof_recorded_attempt = true;
                        if !db::mark_idempotency_guard_verified_in_tx(&mut guard_tx, lease).await? {
                            guard_tx.rollback().await?;
                            return Ok(Outcome::LeaseLost);
                        }
                    }
                    TransactionalGuardOutcome::DeniedNeedsCommit(error) => {
                        if !db::abandon_idempotency_lease_in_tx(&mut guard_tx, lease).await? {
                            guard_tx.rollback().await?;
                            return Ok(Outcome::LeaseLost);
                        }
                        guard_tx.commit().await?;
                        return Ok(Outcome::AbuseDenied(error));
                    }
                }
            }
            guard_tx.commit().await?;
        }

        // The reservation and guard transactions have committed before
        // bounded real/dummy Argon2 work begins.
        let prepared = match db::prepare_login(
            &self.pool,
            request.username,
            request.password,
            self.policy.scram_iterations,
            self.policy.scram_sha1_enabled,
        )
        .await
        {
            Ok(prepared) => prepared,
            Err(error) if crate::password_work::is_overloaded(&error) => {
                if let Some(lease) = lease.as_ref() {
                    if !db::yield_idempotency_lease(&self.pool, lease).await? {
                        return Ok(Outcome::LeaseLost);
                    }
                }
                return Ok(Outcome::PasswordWorkOverloaded);
            }
            Err(error) if auth::is_password_verifier_integrity_error(&error) => {
                self.metrics.record_authentication_backend_failure();
                tracing::error!(
                    ?error,
                    "REST login stored verifier failed integrity validation"
                );
                None
            }
            Err(error) => {
                if let Some(lease) = lease.as_ref() {
                    if !db::yield_idempotency_lease(&self.pool, lease).await? {
                        return Ok(Outcome::LeaseLost);
                    }
                }
                tracing::error!(
                    integrity_failure = auth::is_password_verifier_integrity_error(&error),
                    ?error,
                    "REST login verifier backend failed"
                );
                return Ok(Outcome::BackendUnavailable);
            }
        };
        // Replays still perform current credential verification and never
        // advance the abuse counter twice.
        if let Some(replay) = replay {
            return Ok(Outcome::Replay(replay));
        }
        let lease = lease.expect("acquired lease exists when response is not replayed");
        let Some(prepared) = prepared else {
            let mut tx = self.pool.begin().await?;
            if !db::resume_idempotency_lease_in_tx(
                &mut tx,
                &lease,
                request.idempotency.lease_seconds,
            )
            .await?
            {
                tx.rollback().await?;
                return Ok(Outcome::LeaseLost);
            }
            return self
                .complete_failure(
                    tx,
                    &lease,
                    request.actors,
                    lease.guard_verified || proof_recorded_attempt,
                )
                .await;
        };
        let user_id = prepared.user.id;
        let username = prepared.user.username.clone();
        let is_admin = prepared.user.is_admin;
        let auth_generation = prepared.user.auth_generation;
        let mut tx = self.pool.begin().await?;
        if !db::resume_idempotency_lease_in_tx(&mut tx, &lease, request.idempotency.lease_seconds)
            .await?
        {
            tx.rollback().await?;
            return Ok(Outcome::LeaseLost);
        }
        let login_applied = match db::apply_prepared_login_in_tx(&mut tx, prepared).await {
            Ok(applied) => applied,
            Err(error) => {
                tx.rollback().await?;
                let yielded = self.yield_lease(&lease).await?;
                if matches!(yielded, Outcome::LeaseLost) {
                    return Ok(yielded);
                }
                tracing::error!(?error, user_id = %user_id, "REST login publication backend failed");
                return Ok(Outcome::BackendUnavailable);
            }
        };
        if !login_applied {
            return self
                .complete_failure(
                    tx,
                    &lease,
                    request.actors,
                    lease.guard_verified || proof_recorded_attempt,
                )
                .await;
        }
        if !db::bind_idempotency_actor_in_tx(&mut tx, &lease, user_id).await? {
            return Err(anyhow!("login idempotency ownership changed"));
        }
        let created_session = db::create_api_session_in_tx(
            &mut tx,
            user_id,
            self.policy.session_ttl_hours,
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
            return Err(anyhow!("login replay session binding changed"));
        }
        let session = LoginSessionResponse {
            token: created_session.token,
            jid: format!("{}@{}", username, self.policy.domain),
            is_admin,
        };
        let body = serde_json::to_vec(&session)?;
        let headers: BTreeMap<String, String> = json_replay_headers();
        if !db::complete_idempotency_in_tx(&self.api_control, &mut tx, &lease, 200, &headers, &body)
            .await?
        {
            return Err(anyhow!("login idempotency lease changed"));
        }
        tx.commit().await?;
        Ok(Outcome::Committed(StoredApiResponse {
            status: 200,
            headers,
            body,
            replay_resource_id: None,
        }))
    }
}
