//! Atomic account registration, credential mutation and deletion persistence.
use crate::{abuse::AbuseGuard, db, services::account::*};
use anyhow::{Context, Result};
use sqlx::PgPool;
use std::sync::Arc;
use uuid::Uuid;
use zeroize::Zeroize;

#[derive(Clone)]
pub(crate) struct PostgresAccountRepository {
    pool: PgPool,
    domain: String,
    abuse: Arc<AbuseGuard>,
    api_control: Option<Arc<db::ApiControlKeyring>>,
}
impl PostgresAccountRepository {
    pub(crate) fn new(pool: PgPool, domain: String, abuse: Arc<AbuseGuard>) -> Self {
        Self {
            pool,
            domain,
            abuse,
            api_control: None,
        }
    }

    pub(crate) fn with_api_control(mut self, api_control: Arc<db::ApiControlKeyring>) -> Self {
        self.api_control = Some(api_control);
        self
    }

    async fn yield_http_registration_lease(&self, lease: &db::IdempotencyLease) -> Result<bool> {
        db::yield_idempotency_lease(&self.pool, lease).await
    }
}
impl AccountRepository for PostgresAccountRepository {
    async fn register_http(
        &self,
        request: HttpRegistrationRequest<'_>,
        policy: AccountPolicy,
    ) -> Result<HttpRegistrationOutcome> {
        use HttpRegistrationOutcome as Outcome;

        let keyring = self
            .api_control
            .as_ref()
            .context("HTTP registration API control keyring is missing")?;
        let mut reservation = self.pool.begin().await?;
        let lease =
            match db::acquire_idempotency_in_tx(keyring, &mut reservation, &request.idempotency)
                .await?
            {
                db::IdempotencyAcquire::Acquired(lease) => lease,
                db::IdempotencyAcquire::Replay(replay) => {
                    reservation.commit().await?;
                    return Ok(Outcome::Replay(replay));
                }
                db::IdempotencyAcquire::FingerprintConflict
                | db::IdempotencyAcquire::RotationConflict => {
                    reservation.rollback().await?;
                    return Ok(Outcome::IdempotencyConflict);
                }
                db::IdempotencyAcquire::ReplayInvalidated => {
                    reservation.rollback().await?;
                    return Ok(Outcome::ReplayInvalidated);
                }
                db::IdempotencyAcquire::Busy {
                    retry_after_seconds,
                } => {
                    reservation.rollback().await?;
                    return Ok(Outcome::Busy(retry_after_seconds));
                }
                db::IdempotencyAcquire::CapacityLimited {
                    retry_after_seconds,
                } => {
                    reservation.rollback().await?;
                    return Ok(Outcome::CapacityLimited(retry_after_seconds));
                }
                db::IdempotencyAcquire::InProgress {
                    retry_after_seconds,
                } => {
                    reservation.rollback().await?;
                    return Ok(Outcome::InProgress(retry_after_seconds));
                }
            };

        // A replay precedes policy checks. For a fresh lease, abandon and
        // commit the cheap reservation together with the policy decision.
        let closed = request.availability.is_closed();
        let rate_limited = if closed {
            false
        } else {
            db::registrations_last_hour_in_tx(&mut reservation).await?
                >= i64::from(policy.registration_rate_per_hour)
        };
        if closed || rate_limited {
            if !db::abandon_idempotency_lease_in_tx(&mut reservation, &lease).await? {
                reservation.rollback().await?;
                return Ok(Outcome::LeaseLost);
            }
            reservation.commit().await?;
            return Ok(if closed {
                Outcome::Closed
            } else {
                Outcome::RateLimited
            });
        }
        reservation.commit().await?;

        if !lease.guard_verified {
            match self
                .verify_registration_guard(RegistrationGuardRequest {
                    lease: RegistrationGuardLease {
                        record_id: lease.record_id,
                        lease_token: lease.lease_token(),
                    },
                    lease_seconds: request.idempotency.lease_seconds,
                    subject: request.subject,
                    actors: request.actors,
                    proof: request.proof,
                    intent: request.intent,
                })
                .await?
            {
                RegistrationGuardOutcome::Verified => {}
                RegistrationGuardOutcome::Denied(error) => return Ok(Outcome::AbuseDenied(error)),
                RegistrationGuardOutcome::LeaseLost => return Ok(Outcome::LeaseLost),
            }
        }

        // No transaction spans password work. The committed guard marker
        // allows an exact retry to skip already-consumed proof after a worker
        // or database failure, while the rotated lease fences the old worker.
        let prepared = match db::prepare_registration(
            request.username,
            request.password,
            policy.scram_iterations,
            policy.scram_sha1_enabled,
        )
        .await
        {
            Ok(prepared) => prepared,
            Err(error) => {
                if !self.yield_http_registration_lease(&lease).await? {
                    return Ok(Outcome::LeaseLost);
                }
                return match error {
                    db::RegistrationError::InvalidUsername(_) => Ok(Outcome::InvalidUsername),
                    db::RegistrationError::PasswordWorkOverloaded => {
                        Ok(Outcome::PasswordWorkOverloaded)
                    }
                    db::RegistrationError::Internal(error) => Err(error),
                    other => Err(anyhow::anyhow!(other)
                        .context("registration preparation returned an impossible outcome")),
                };
            }
        };

        let mut publication = self.pool.begin().await?;
        if !db::resume_idempotency_lease_in_tx(
            &mut publication,
            &lease,
            request.idempotency.lease_seconds,
        )
        .await?
        {
            publication.rollback().await?;
            return Ok(Outcome::LeaseLost);
        }
        let outcome = db::create_user_with_invitation_guarded_in_tx_v2(
            &mut publication,
            &self.abuse,
            request.subject,
            request.actors,
            request.proof,
            request.intent,
            true,
            prepared,
            request.invitation_token,
            request.availability.requires_invitation(),
            policy.registration_rate_per_hour,
            Some(lease.request_id),
        )
        .await;
        let outcome = match outcome {
            Ok(outcome) => outcome,
            Err(error) => {
                publication.rollback().await?;
                if !self.yield_http_registration_lease(&lease).await? {
                    return Ok(Outcome::LeaseLost);
                }
                return Err(error).context("guarded HTTP registration failed");
            }
        };
        match outcome {
            db::GuardedRegistrationOutcome::Created(mut user) => {
                let username = std::mem::take(&mut user.username);
                let user_id = user.id;
                user.password_hash.zeroize();
                user.password_hash.clear();
                anyhow::ensure!(
                    db::mark_idempotency_guard_verified_in_tx(&mut publication, &lease).await?,
                    "registration idempotency guard marker changed"
                );
                anyhow::ensure!(
                    db::bind_idempotency_actor_in_tx(&mut publication, &lease, user_id).await?,
                    "registration idempotency ownership changed"
                );
                let body = serde_json::to_vec(&serde_json::json!({
                    "jid": format!("{}@{}", username, self.domain)
                }))?;
                anyhow::ensure!(
                    db::complete_idempotency_in_tx(
                        keyring,
                        &mut publication,
                        &lease,
                        201,
                        &crate::services::api_mutations::json_replay_headers(),
                        &body,
                    )
                    .await?,
                    "registration idempotency lease changed"
                );
                publication.commit().await?;
                Ok(Outcome::Created(body))
            }
            db::GuardedRegistrationOutcome::AbuseDenied(error) => {
                if !db::abandon_idempotency_lease_in_tx(&mut publication, &lease).await? {
                    publication.rollback().await?;
                    return Ok(Outcome::LeaseLost);
                }
                publication.commit().await?;
                Ok(Outcome::AbuseDenied(error))
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
                db::audit_registration_rejection_in_tx(&mut publication, lease.request_id, reason)
                    .await?;
                let body = serde_json::to_vec(&serde_json::json!({
                    "error": {
                        "code": "bad_request",
                        "message": "registration request could not be accepted"
                    }
                }))?;
                anyhow::ensure!(
                    db::complete_idempotency_in_tx(
                        keyring,
                        &mut publication,
                        &lease,
                        400,
                        &crate::services::api_mutations::json_replay_headers(),
                        &body,
                    )
                    .await?,
                    "registration rejection idempotency lease changed"
                );
                publication.commit().await?;
                Ok(Outcome::Rejected(body))
            }
            db::GuardedRegistrationOutcome::Rejected(error) => {
                if !db::abandon_idempotency_lease_in_tx(&mut publication, &lease).await? {
                    publication.rollback().await?;
                    return Ok(Outcome::LeaseLost);
                }
                publication.commit().await?;
                match error {
                    db::RegistrationError::CapacityExhausted => Ok(Outcome::CapacityExhausted),
                    db::RegistrationError::Closed => Ok(Outcome::Closed),
                    db::RegistrationError::RateLimited => Ok(Outcome::RateLimited),
                    db::RegistrationError::PasswordWorkOverloaded => {
                        Ok(Outcome::PasswordWorkOverloaded)
                    }
                    db::RegistrationError::InvalidUsername(_) => Ok(Outcome::InvalidUsername),
                    db::RegistrationError::InvitationRejected => Ok(Outcome::InvitationRejected),
                    db::RegistrationError::UsernameTaken => Ok(Outcome::UsernameTaken),
                    db::RegistrationError::Internal(error) => Err(error),
                }
            }
        }
    }

    async fn verify_registration_guard(
        &self,
        request: RegistrationGuardRequest<'_>,
    ) -> Result<RegistrationGuardOutcome> {
        let mut transaction = self.pool.begin().await?;
        if !db::api_control::resume_idempotency_lease_fence_in_tx(
            &mut transaction,
            request.lease.record_id,
            request.lease.lease_token,
            request.lease_seconds,
        )
        .await?
        {
            transaction.rollback().await?;
            return Ok(RegistrationGuardOutcome::LeaseLost);
        }
        let outcome = self
            .abuse
            .verify_or_allow_in_tx_v2(
                &mut transaction,
                crate::abuse::AbuseAction::Registration,
                request.subject,
                request.actors,
                request.proof,
                request.intent,
            )
            .await?;
        match outcome {
            crate::abuse::TransactionalGuardOutcome::Allowed(_) => {
                if !db::api_control::mark_idempotency_guard_verified_fence_in_tx(
                    &mut transaction,
                    request.lease.record_id,
                    request.lease.lease_token,
                )
                .await?
                {
                    transaction.rollback().await?;
                    return Ok(RegistrationGuardOutcome::LeaseLost);
                }
                transaction.commit().await?;
                Ok(RegistrationGuardOutcome::Verified)
            }
            crate::abuse::TransactionalGuardOutcome::DeniedNeedsCommit(error) => {
                if !db::api_control::abandon_idempotency_lease_fence_in_tx(
                    &mut transaction,
                    request.lease.record_id,
                    request.lease.lease_token,
                )
                .await?
                {
                    transaction.rollback().await?;
                    return Ok(RegistrationGuardOutcome::LeaseLost);
                }
                transaction.commit().await?;
                Ok(RegistrationGuardOutcome::Denied(error))
            }
        }
    }

    async fn register(
        &self,
        request: RegistrationRequest<'_>,
        policy: AccountPolicy,
        password_work: crate::password_work::PasswordWorkReservation,
    ) -> Result<RegistrationOutcome> {
        let mut transaction = self
            .pool
            .begin()
            .await
            .context("could not begin registration admission")?;
        let admission_outcome = self
            .abuse
            .verify_or_allow_in_tx_v2(
                &mut transaction,
                crate::abuse::AbuseAction::Registration,
                request.subject,
                request.actors,
                request.proof,
                request.intent,
            )
            .await
            .context("registration anti-abuse admission failed")?;
        match admission_outcome {
            crate::abuse::TransactionalGuardOutcome::Allowed(_) => {}
            crate::abuse::TransactionalGuardOutcome::DeniedNeedsCommit(error) => {
                let requirement = error.requirement().clone();
                transaction
                    .commit()
                    .await
                    .context("registration denial commit failed")?;
                return Ok(RegistrationOutcome::AbuseDenied(requirement));
            }
        }

        let prepared = match db::prepare_registration_with_reservation(
            request.username,
            request.password,
            policy.scram_iterations,
            policy.scram_sha1_enabled,
            password_work,
        )
        .await
        {
            Ok(prepared) => prepared,
            Err(db::RegistrationError::InvalidUsername(_)) => {
                if let Err(rollback_error) = transaction.rollback().await {
                    tracing::error!(?rollback_error, "registration rollback failed");
                }
                return Ok(RegistrationOutcome::InvalidUsername);
            }
            Err(db::RegistrationError::PasswordWorkOverloaded) => {
                if let Err(rollback_error) = transaction.rollback().await {
                    tracing::error!(?rollback_error, "registration rollback failed");
                }
                return Ok(RegistrationOutcome::PasswordWorkOverloaded);
            }
            Err(db::RegistrationError::Internal(error)) => {
                if let Err(rollback_error) = transaction.rollback().await {
                    tracing::error!(?rollback_error, "registration rollback failed");
                }
                return Err(error);
            }
            Err(error) => {
                if let Err(rollback_error) = transaction.rollback().await {
                    tracing::error!(?rollback_error, "registration rollback failed");
                }
                return Err(anyhow::anyhow!(error)
                    .context("registration preparation returned an impossible outcome"));
            }
        };
        let outcome = db::create_user_with_invitation_guarded_in_tx_v2(
            &mut transaction,
            &self.abuse,
            request.subject,
            request.actors,
            request.proof,
            request.intent,
            true,
            prepared,
            request.invitation_token,
            policy.invitation_required,
            policy.registration_rate_per_hour,
            None,
        )
        .await;
        let outcome = match outcome {
            Ok(outcome) => outcome,
            Err(error) => {
                if let Err(rollback_error) = transaction.rollback().await {
                    tracing::error!(?rollback_error, "guarded registration rollback failed");
                }
                return Err(error).context("guarded registration failed");
            }
        };
        transaction
            .commit()
            .await
            .context("guarded registration commit failed")?;

        Ok(match outcome {
            db::GuardedRegistrationOutcome::Created(mut user) => {
                let username = std::mem::take(&mut user.username);
                user.password_hash.zeroize();
                user.password_hash.clear();
                RegistrationOutcome::Created(RegistrationAccount { username })
            }
            db::GuardedRegistrationOutcome::AbuseDenied(error) => {
                RegistrationOutcome::AbuseDenied(error.requirement().clone())
            }
            db::GuardedRegistrationOutcome::Rejected(error) => match error {
                db::RegistrationError::InvalidUsername(_) => RegistrationOutcome::InvalidUsername,
                db::RegistrationError::InvitationRejected => {
                    RegistrationOutcome::InvitationRejected
                }
                db::RegistrationError::UsernameTaken => RegistrationOutcome::UsernameTaken,
                db::RegistrationError::RateLimited => RegistrationOutcome::RateLimited,
                db::RegistrationError::CapacityExhausted => RegistrationOutcome::CapacityExhausted,
                db::RegistrationError::PasswordWorkOverloaded => {
                    RegistrationOutcome::PasswordWorkOverloaded
                }
                db::RegistrationError::Closed => RegistrationOutcome::Closed,
                db::RegistrationError::Internal(error) => return Err(error),
            },
        })
    }

    async fn change_password(
        &self,
        request: PasswordChangeRequest<'_>,
        policy: AccountPolicy,
    ) -> Result<PasswordChangeOutcome> {
        match db::change_password_guarded_v2(
            &self.pool,
            &self.abuse,
            request.subject,
            request.actors,
            request.proof,
            request.intent,
            request.user_id,
            request.expected_auth_generation,
            request.password,
            policy.scram_iterations,
            policy.scram_sha1_enabled,
        )
        .await
        {
            Ok(Ok(())) => Ok(PasswordChangeOutcome::Changed),
            Ok(Err(error)) => Ok(PasswordChangeOutcome::AbuseDenied(
                error.requirement().clone(),
            )),
            Err(error) if crate::password_work::is_overloaded(&error) => {
                Ok(PasswordChangeOutcome::PasswordWorkOverloaded)
            }
            Err(error) => Err(error).context("guarded password change failed"),
        }
    }

    async fn quiesce_for_deletion(
        &self,
        request: DeletionQuiesceRequest<'_>,
    ) -> Result<DeletionQuiesceOutcome> {
        match db::begin_account_deletion_quiesce_guarded_v2(
            &self.pool,
            &self.abuse,
            request.subject,
            request.actors,
            request.proof,
            request.intent,
            request.user_id,
            request.expected_auth_generation,
        )
        .await?
        {
            Ok(true) => Ok(DeletionQuiesceOutcome::Quiesced),
            Ok(false) => Ok(DeletionQuiesceOutcome::Missing),
            Err(error) => Ok(DeletionQuiesceOutcome::AbuseDenied(
                error.requirement().clone(),
            )),
        }
    }

    async fn delete_quiesced(&self, user_id: Uuid) -> Result<Option<RemovedAccount>> {
        Ok(db::delete_user_with_roster_audited(
            &self.pool,
            user_id,
            &self.domain,
            serde_json::json!({"source":"xep-0077"}),
        )
        .await?
        .map(|removed| RemovedAccount {
            roster: removed.roster,
            reverse_roster_changes: removed.reverse_roster_changes,
        }))
    }

    async fn claim_deletion_recovery(
        &self,
        limit: i64,
        lease_seconds: i64,
    ) -> Result<Vec<DeletionRecoveryJob>> {
        db::claim_account_deletion_jobs(&self.pool, limit, lease_seconds).await
    }

    async fn release_deletion_recovery(
        &self,
        job: &DeletionRecoveryJob,
        error_code: &str,
    ) -> Result<bool> {
        db::release_account_deletion_job(&self.pool, job, error_code).await
    }
}

#[cfg(test)]
mod registration_guard_tests {
    use super::*;
    use crate::abuse::{AbuseAction, AbuseConfig, PowChallenge, PowIntent, PowProof};
    use crate::services::api_mutations::{
        api_request_fingerprint, ApiPrincipalKind, IdempotencyRequest,
    };
    use base64::Engine as _;
    use ring::rand::{SecureRandom, SystemRandom};
    use sha2::{Digest, Sha256};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    fn test_key() -> String {
        let mut key = [0_u8; 32];
        SystemRandom::new().fill(&mut key).unwrap();
        base64::engine::general_purpose::STANDARD.encode(key)
    }

    fn solve_pow(challenge: &PowChallenge) -> PowProof {
        let target = u64::MAX / challenge.requirement.work_factor.max(1);
        for nonce in 0_u64.. {
            let nonce = nonce.to_string();
            let mut hasher = Sha256::new();
            hasher.update(challenge.prefix.as_bytes());
            hasher.update(nonce.as_bytes());
            let digest = hasher.finalize();
            if u64::from_be_bytes(digest[..8].try_into().unwrap()) <= target {
                return PowProof {
                    challenge_id: challenge.challenge_id,
                    nonce,
                };
            }
        }
        unreachable!()
    }

    async fn register_http_once(
        service: &AccountService<PostgresAccountRepository>,
        availability: &HttpRegistrationAvailability,
        username: &str,
        key: &str,
        request_id: Uuid,
        scope: &str,
        proof: Option<&PowProof>,
    ) -> HttpRegistrationOutcome {
        let password = "correct horse battery staple";
        let body = serde_json::json!({
            "username": username,
            "password": password,
            "invitation_token": null,
        });
        let raw_body = serde_json::to_vec(&serde_json::json!({
            "username": username,
            "password": password,
            "invitation_token": null,
            "pow": proof.map(|proof| serde_json::json!({
                "challenge_id": proof.challenge_id,
                "nonce": proof.nonce,
            })),
        }))
        .unwrap();
        let intent = PowIntent::http_json(AbuseAction::Registration, "/api/v1/register", &body);
        let actors = vec![scope.to_owned()];
        service
            .register_http(HttpRegistrationRequest {
                idempotency: IdempotencyRequest {
                    request_id,
                    actor_id: None,
                    principal_scope: scope.as_bytes(),
                    capacity_scope: scope.as_bytes(),
                    target_scope: b"",
                    principal_kind: ApiPrincipalKind::Anonymous,
                    method: "POST",
                    route: "/api/v1/register",
                    idempotency_key: key,
                    request_fingerprint: api_request_fingerprint("application/json", &raw_body),
                    ttl_seconds: 3_600,
                    lease_seconds: 30,
                },
                username,
                password,
                invitation_token: None,
                proof,
                intent: &intent,
                subject: scope,
                actors: &actors,
                availability: availability.clone(),
            })
            .await
            .unwrap()
    }

    #[tokio::test]
    #[ignore = "requires TEST_DATABASE_URL pointing at an isolated PostgreSQL database"]
    async fn http_registration_replays_exact_created_and_rejected_responses_after_policy_closure() {
        let url = std::env::var("TEST_DATABASE_URL").expect("set TEST_DATABASE_URL");
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(4)
            .connect(&url)
            .await
            .unwrap();
        crate::db::migrate(&pool).await.unwrap();
        crate::db::initialize_admin_runtime_settings(&pool, false, false, false)
            .await
            .unwrap();
        let guard = Arc::new(AbuseGuard::new_persistent(
            AbuseConfig {
                base_work_factor: 2,
                max_work_factor: 64,
                window: Duration::from_secs(60),
                cooldown_step: Duration::from_secs(60),
                max_wait: Duration::from_secs(900),
                message_free_burst: 6,
                approximate_max_device_seconds: 8,
            },
            pool.clone(),
            Some(test_key().as_bytes()),
            None,
        ));
        let api_control =
            Arc::new(crate::db::ApiControlKeyring::new(test_key().as_bytes(), None).unwrap());
        let service = AccountService::new(
            PostgresAccountRepository::new(pool.clone(), "example.test".into(), guard)
                .with_api_control(api_control),
            false,
            1_000_000,
            crate::auth::MIN_SCRAM_ITERATIONS,
            false,
        );
        let closed = Arc::new(AtomicBool::new(false));
        let availability = HttpRegistrationAvailability::new(Arc::clone(&closed), false, false);
        let suffix = Uuid::new_v4().simple().to_string();
        let username = format!("registration-{suffix}");
        let created_key = format!("created-{suffix}");
        let created_id = Uuid::new_v4();
        let created_scope = format!("registration:192.0.2.{}", 40);
        let created = register_http_once(
            &service,
            &availability,
            &username,
            &created_key,
            created_id,
            &created_scope,
            None,
        )
        .await;
        let HttpRegistrationOutcome::Created(created_body) = created else {
            panic!("expected newly created account");
        };
        assert_eq!(
            created_body,
            serde_json::to_vec(&serde_json::json!({"jid": format!("{username}@example.test")}))
                .unwrap()
        );
        closed.store(true, Ordering::Release);
        let replayed = register_http_once(
            &service,
            &availability,
            &username,
            &created_key,
            created_id,
            &created_scope,
            None,
        )
        .await;
        let HttpRegistrationOutcome::Replay(replayed) = replayed else {
            panic!("created response must replay before closure check");
        };
        assert_eq!(replayed.request_id, created_id);
        assert_eq!(replayed.status, 201);
        assert_eq!(
            replayed.headers,
            crate::services::api_mutations::json_replay_headers()
        );
        assert_eq!(replayed.body, created_body);

        closed.store(false, Ordering::Release);
        let rejected_key = format!("rejected-{suffix}");
        let rejected_id = Uuid::new_v4();
        let rejected_scope = "registration:192.0.2.41";
        let rejected = register_http_once(
            &service,
            &availability,
            &username,
            &rejected_key,
            rejected_id,
            rejected_scope,
            None,
        )
        .await;
        let HttpRegistrationOutcome::Rejected(rejected_body) = rejected else {
            panic!("expected deterministic username rejection");
        };
        assert_eq!(
            rejected_body,
            serde_json::to_vec(&serde_json::json!({
                "error": {
                    "code": "bad_request",
                    "message": "registration request could not be accepted"
                }
            }))
            .unwrap()
        );
        closed.store(true, Ordering::Release);
        let replayed = register_http_once(
            &service,
            &availability,
            &username,
            &rejected_key,
            rejected_id,
            rejected_scope,
            None,
        )
        .await;
        let HttpRegistrationOutcome::Replay(replayed) = replayed else {
            panic!("rejection must replay before closure check");
        };
        assert_eq!(replayed.request_id, rejected_id);
        assert_eq!(replayed.status, 400);
        assert_eq!(
            replayed.headers,
            crate::services::api_mutations::json_replay_headers()
        );
        assert_eq!(replayed.body, rejected_body);
        pool.close().await;
    }

    #[tokio::test]
    #[ignore = "requires TEST_DATABASE_URL pointing at an isolated PostgreSQL database"]
    async fn http_registration_overload_preserves_committed_proof_marker_for_exact_retry() {
        let url = std::env::var("TEST_DATABASE_URL").expect("set TEST_DATABASE_URL");
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(4)
            .connect(&url)
            .await
            .unwrap();
        crate::db::migrate(&pool).await.unwrap();
        crate::db::initialize_admin_runtime_settings(&pool, false, false, false)
            .await
            .unwrap();
        let guard = Arc::new(AbuseGuard::new_persistent(
            AbuseConfig {
                base_work_factor: 2,
                max_work_factor: 64,
                window: Duration::from_secs(60),
                cooldown_step: Duration::from_secs(60),
                max_wait: Duration::from_secs(900),
                message_free_burst: 6,
                approximate_max_device_seconds: 8,
            },
            pool.clone(),
            Some(test_key().as_bytes()),
            None,
        ));
        let api_control =
            Arc::new(crate::db::ApiControlKeyring::new(test_key().as_bytes(), None).unwrap());
        let service = AccountService::new(
            PostgresAccountRepository::new(pool.clone(), "example.test".into(), Arc::clone(&guard))
                .with_api_control(api_control),
            false,
            1_000_000,
            crate::auth::MIN_SCRAM_ITERATIONS,
            false,
        );
        let availability =
            HttpRegistrationAvailability::new(Arc::new(AtomicBool::new(false)), false, false);
        let suffix = Uuid::new_v4().simple().to_string();
        let username = format!("retry-{suffix}");
        let key = format!("retry-{suffix}");
        let request_id = Uuid::new_v4();
        let scope = "registration:192.0.2.42";
        let actors = vec![scope.to_owned()];
        let body = serde_json::json!({
            "username": username,
            "password": "correct horse battery staple",
            "invitation_token": null,
        });
        let intent = PowIntent::http_json(AbuseAction::Registration, "/api/v1/register", &body);
        assert!(guard
            .verify_or_allow_v2(AbuseAction::Registration, scope, &actors, None, &intent)
            .await
            .unwrap()
            .is_ok());
        let challenge = guard
            .issue_v2(AbuseAction::Registration, scope, &actors, &intent)
            .await
            .unwrap();
        let proof = solve_pow(&challenge);
        let mut admissions = Vec::new();
        while let Ok(admission) = crate::password_work::admit() {
            admissions.push(admission);
        }
        assert!(!admissions.is_empty());
        let overloaded = register_http_once(
            &service,
            &availability,
            &username,
            &key,
            request_id,
            scope,
            Some(&proof),
        )
        .await;
        assert!(matches!(
            overloaded,
            HttpRegistrationOutcome::PasswordWorkOverloaded
        ));
        let marker: bool = sqlx::query_scalar(
            "SELECT guard_verified_at IS NOT NULL FROM api_idempotency_records WHERE request_id=$1",
        )
        .bind(request_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(
            marker,
            "the pre-hash guard marker must survive worker overload"
        );
        let proof_retained: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM abuse_pow_challenges WHERE id=$1)")
                .bind(proof.challenge_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert!(
            !proof_retained,
            "proof consumption must commit with the marker"
        );
        drop(admissions);
        let retried = register_http_once(
            &service,
            &availability,
            &username,
            &key,
            request_id,
            scope,
            Some(&proof),
        )
        .await;
        assert!(matches!(retried, HttpRegistrationOutcome::Created(_)));
        pool.close().await;
    }

    #[tokio::test]
    #[ignore = "requires TEST_DATABASE_URL pointing at an isolated PostgreSQL database"]
    async fn registration_guard_consumes_v2_proof_with_marker_and_fences_old_worker() {
        let url = std::env::var("TEST_DATABASE_URL").expect("set TEST_DATABASE_URL");
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(4)
            .connect(&url)
            .await
            .unwrap();
        crate::db::migrate(&pool).await.unwrap();
        crate::db::initialize_admin_runtime_settings(&pool, false, false, false)
            .await
            .unwrap();
        let abuse_key = test_key();
        let api_key = test_key();
        let guard = Arc::new(AbuseGuard::new_persistent(
            AbuseConfig {
                base_work_factor: 2,
                max_work_factor: 64,
                window: Duration::from_secs(60),
                cooldown_step: Duration::from_secs(60),
                max_wait: Duration::from_secs(900),
                message_free_burst: 6,
                approximate_max_device_seconds: 8,
            },
            pool.clone(),
            Some(abuse_key.as_bytes()),
            None,
        ));
        let repository =
            PostgresAccountRepository::new(pool.clone(), "example.test".into(), Arc::clone(&guard));
        let keys = crate::db::ApiControlKeyring::new(api_key.as_bytes(), None).unwrap();
        let suffix = Uuid::new_v4().simple().to_string();
        let key = format!("registration-guard-{suffix}");
        let scope = "registration:192.0.2.40";
        let actors = vec!["ip:192.0.2.40".to_owned()];
        let body = serde_json::json!({"username":"alice","password":"test password"});
        let raw_body = serde_json::to_vec(&body).unwrap();
        let intent = PowIntent::http_json(AbuseAction::Registration, "/api/v1/register", &body);
        // Spend the free burst, then issue the exact body-bound v2 proof that
        // the guarded idempotent request must consume.
        assert!(guard
            .verify_or_allow_v2(AbuseAction::Registration, scope, &actors, None, &intent)
            .await
            .unwrap()
            .is_ok());
        let challenge = guard
            .issue_v2(AbuseAction::Registration, scope, &actors, &intent)
            .await
            .unwrap();
        let proof = solve_pow(&challenge);
        let request = IdempotencyRequest {
            request_id: Uuid::new_v4(),
            actor_id: None,
            principal_scope: scope.as_bytes(),
            capacity_scope: actors[0].as_bytes(),
            target_scope: b"",
            principal_kind: ApiPrincipalKind::Anonymous,
            method: "POST",
            route: "/api/v1/register",
            idempotency_key: &key,
            request_fingerprint: api_request_fingerprint("application/json", &raw_body),
            ttl_seconds: 3_600,
            lease_seconds: 30,
        };
        let mut reserve = pool.begin().await.unwrap();
        let lease = match crate::db::acquire_idempotency_in_tx(&keys, &mut reserve, &request)
            .await
            .unwrap()
        {
            crate::db::IdempotencyAcquire::Acquired(lease) => lease,
            other => panic!("expected acquired registration lease, got {other:?}"),
        };
        reserve.commit().await.unwrap();

        let fence = RegistrationGuardLease {
            record_id: lease.record_id,
            lease_token: lease.lease_token(),
        };
        let outcome = repository
            .verify_registration_guard(RegistrationGuardRequest {
                lease: fence,
                lease_seconds: 30,
                subject: scope,
                actors: &actors,
                proof: Some(&proof),
                intent: &intent,
            })
            .await
            .unwrap();
        assert!(matches!(outcome, RegistrationGuardOutcome::Verified));
        let marker: bool = sqlx::query_scalar(
            "SELECT guard_verified_at IS NOT NULL FROM api_idempotency_records WHERE id=$1",
        )
        .bind(lease.record_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(marker);
        let proof_retained: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM abuse_pow_challenges WHERE id=$1)")
                .bind(proof.challenge_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert!(
            !proof_retained,
            "proof must be consumed with the guard marker"
        );

        assert!(crate::db::yield_idempotency_lease(&pool, &lease)
            .await
            .unwrap());
        let mut takeover = pool.begin().await.unwrap();
        let replacement = match crate::db::acquire_idempotency_in_tx(&keys, &mut takeover, &request)
            .await
            .unwrap()
        {
            crate::db::IdempotencyAcquire::Acquired(lease) => lease,
            other => panic!("expected guard-verified takeover, got {other:?}"),
        };
        assert!(replacement.guard_verified);
        takeover.commit().await.unwrap();

        // A fresh valid proof makes the stale-owner check observable: the
        // old worker must neither consume it nor advance actor state.
        let fresh_challenge = guard
            .issue_v2(AbuseAction::Registration, scope, &actors, &intent)
            .await
            .unwrap();
        let fresh_proof = solve_pow(&fresh_challenge);
        let events_before: i64 = sqlx::query_scalar(
            "SELECT COALESCE(SUM(cardinality(event_times)),0)::BIGINT FROM abuse_actor_states",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(matches!(
            repository
                .verify_registration_guard(RegistrationGuardRequest {
                    lease: fence,
                    lease_seconds: 30,
                    subject: scope,
                    actors: &actors,
                    proof: Some(&fresh_proof),
                    intent: &intent,
                })
                .await
                .unwrap(),
            RegistrationGuardOutcome::LeaseLost
        ));
        let fresh_retained: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM abuse_pow_challenges WHERE id=$1)")
                .bind(fresh_proof.challenge_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert!(
            fresh_retained,
            "stale worker must not consume a fresh proof"
        );
        let events_after: i64 = sqlx::query_scalar(
            "SELECT COALESCE(SUM(cardinality(event_times)),0)::BIGINT FROM abuse_actor_states",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(events_after, events_before);
        let (active_token, active_marker): (Uuid, bool) = sqlx::query_as(
            "SELECT lease_token,guard_verified_at IS NOT NULL FROM api_idempotency_records WHERE id=$1",
        )
        .bind(replacement.record_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(active_token, replacement.lease_token());
        assert!(active_marker);

        // Reusing the consumed proof for another request must commit a
        // denial, remove only that request's lease, and leave the replacement
        // lease available to its rightful worker.
        let denied_key = format!("registration-guard-denied-{suffix}");
        let denied_request = IdempotencyRequest {
            request_id: Uuid::new_v4(),
            actor_id: None,
            principal_scope: scope.as_bytes(),
            capacity_scope: actors[0].as_bytes(),
            target_scope: b"",
            principal_kind: ApiPrincipalKind::Anonymous,
            method: "POST",
            route: "/api/v1/register",
            idempotency_key: &denied_key,
            request_fingerprint: api_request_fingerprint("application/json", &raw_body),
            ttl_seconds: 3_600,
            lease_seconds: 30,
        };
        let mut reserve_denied = pool.begin().await.unwrap();
        let denied_lease =
            match crate::db::acquire_idempotency_in_tx(&keys, &mut reserve_denied, &denied_request)
                .await
                .unwrap()
            {
                crate::db::IdempotencyAcquire::Acquired(lease) => lease,
                other => panic!("expected second registration lease, got {other:?}"),
            };
        reserve_denied.commit().await.unwrap();
        assert!(matches!(
            repository
                .verify_registration_guard(RegistrationGuardRequest {
                    lease: RegistrationGuardLease {
                        record_id: denied_lease.record_id,
                        lease_token: denied_lease.lease_token(),
                    },
                    lease_seconds: 30,
                    subject: scope,
                    actors: &actors,
                    proof: Some(&proof),
                    intent: &intent,
                })
                .await
                .unwrap(),
            RegistrationGuardOutcome::Denied(crate::abuse::GuardError::Invalid(..))
        ));
        let retained: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM api_idempotency_records WHERE id=$1")
                .bind(denied_lease.record_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(retained, 0);
        let (surviving_token, surviving_marker): (Uuid, bool) = sqlx::query_as(
            "SELECT lease_token,guard_verified_at IS NOT NULL FROM api_idempotency_records WHERE id=$1",
        )
        .bind(replacement.record_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(surviving_token, replacement.lease_token());
        assert!(surviving_marker);
        pool.close().await;
    }
}
