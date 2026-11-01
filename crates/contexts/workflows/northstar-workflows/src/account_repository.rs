//! Atomic account registration, credential mutation and deletion persistence.
use crate::account_lifecycle::AccountDeletionEffects;
use anyhow::{Context, Result};
use northstar_abuse_application::guard::AbuseGuard;
use northstar_auth_application::account::*;
use sqlx::PgPool;
use std::sync::Arc;
use uuid::Uuid;
use zeroize::Zeroize;

#[derive(Clone)]
pub struct PostgresAccountRepository<E> {
    pool: PgPool,
    domain: String,
    abuse: Arc<AbuseGuard>,
    api_control: Option<Arc<northstar_operations_postgres::api_control::ApiControlKeyring>>,
    effects: E,
}
impl<E> PostgresAccountRepository<E> {
    pub fn new(pool: PgPool, domain: String, abuse: Arc<AbuseGuard>, effects: E) -> Self {
        Self {
            pool,
            domain,
            abuse,
            api_control: None,
            effects,
        }
    }

    pub fn with_api_control(
        mut self,
        api_control: Arc<northstar_operations_postgres::api_control::ApiControlKeyring>,
    ) -> Self {
        self.api_control = Some(api_control);
        self
    }

    async fn yield_http_registration_lease(
        &self,
        lease: &northstar_operations_postgres::api_control::IdempotencyLease,
    ) -> Result<bool> {
        northstar_operations_postgres::api_control::yield_idempotency_lease(&self.pool, lease).await
    }
}
impl<E: AccountDeletionEffects> AccountRepository for PostgresAccountRepository<E> {
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
        let lease = match northstar_operations_postgres::api_control::acquire_idempotency_in_tx(
            keyring,
            &mut reservation,
            &request.idempotency,
        )
        .await?
        {
            northstar_operations_postgres::api_control::IdempotencyAcquire::Acquired(lease) => {
                lease
            }
            northstar_operations_postgres::api_control::IdempotencyAcquire::Replay(replay) => {
                reservation.commit().await?;
                return Ok(Outcome::Replay(replay));
            }
            northstar_operations_postgres::api_control::IdempotencyAcquire::FingerprintConflict
            | northstar_operations_postgres::api_control::IdempotencyAcquire::RotationConflict => {
                reservation.rollback().await?;
                return Ok(Outcome::IdempotencyConflict);
            }
            northstar_operations_postgres::api_control::IdempotencyAcquire::ReplayInvalidated => {
                reservation.rollback().await?;
                return Ok(Outcome::ReplayInvalidated);
            }
            northstar_operations_postgres::api_control::IdempotencyAcquire::Busy {
                retry_after_seconds,
            } => {
                reservation.rollback().await?;
                return Ok(Outcome::Busy(retry_after_seconds));
            }
            northstar_operations_postgres::api_control::IdempotencyAcquire::CapacityLimited {
                retry_after_seconds,
            } => {
                reservation.rollback().await?;
                return Ok(Outcome::CapacityLimited(retry_after_seconds));
            }
            northstar_operations_postgres::api_control::IdempotencyAcquire::InProgress {
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
            northstar_auth_postgres::users::registrations_last_hour_in_tx(&mut reservation).await?
                >= i64::from(policy.registration_rate_per_hour)
        };
        if closed || rate_limited {
            if !northstar_operations_postgres::api_control::abandon_idempotency_lease_in_tx(
                &mut reservation,
                &lease,
            )
            .await?
            {
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
        let prepared = match northstar_auth_postgres::users::prepare_registration(
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
                    northstar_auth_postgres::users::RegistrationError::InvalidUsername(_) => {
                        Ok(Outcome::InvalidUsername)
                    }
                    northstar_auth_postgres::users::RegistrationError::PasswordWorkOverloaded => {
                        Ok(Outcome::PasswordWorkOverloaded)
                    }
                    northstar_auth_postgres::users::RegistrationError::Internal(error) => {
                        Err(error)
                    }
                    other => Err(anyhow::anyhow!(other)
                        .context("registration preparation returned an impossible outcome")),
                };
            }
        };

        let mut publication = self.pool.begin().await?;
        if !northstar_operations_postgres::api_control::resume_idempotency_lease_in_tx(
            &mut publication,
            &lease,
            request.idempotency.lease_seconds,
        )
        .await?
        {
            publication.rollback().await?;
            return Ok(Outcome::LeaseLost);
        }
        let outcome = crate::account_lifecycle::create_user_with_invitation_guarded_in_tx_v2(
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
            crate::account_lifecycle::GuardedRegistrationOutcome::Created(mut user) => {
                let username = std::mem::take(&mut user.username);
                let user_id = user.id;
                user.password_hash.zeroize();
                user.password_hash.clear();
                anyhow::ensure!(
                    northstar_operations_postgres::api_control::mark_idempotency_guard_verified_in_tx(&mut publication, &lease).await?,
                    "registration idempotency guard marker changed"
                );
                anyhow::ensure!(
                    northstar_operations_postgres::api_control::bind_idempotency_actor_in_tx(
                        &mut publication,
                        &lease,
                        user_id
                    )
                    .await?,
                    "registration idempotency ownership changed"
                );
                let body = serde_json::to_vec(&serde_json::json!({
                    "jid": format!("{}@{}", username, self.domain)
                }))?;
                anyhow::ensure!(
                    northstar_operations_postgres::api_control::complete_idempotency_in_tx(
                        keyring,
                        &mut publication,
                        &lease,
                        201,
                        &northstar_operations_core::api_mutations::json_replay_headers(),
                        &body,
                    )
                    .await?,
                    "registration idempotency lease changed"
                );
                publication.commit().await?;
                Ok(Outcome::Created(body))
            }
            crate::account_lifecycle::GuardedRegistrationOutcome::AbuseDenied(error) => {
                if !northstar_operations_postgres::api_control::abandon_idempotency_lease_in_tx(
                    &mut publication,
                    &lease,
                )
                .await?
                {
                    publication.rollback().await?;
                    return Ok(Outcome::LeaseLost);
                }
                publication.commit().await?;
                Ok(Outcome::AbuseDenied(error))
            }
            crate::account_lifecycle::GuardedRegistrationOutcome::Rejected(
                error @ (northstar_auth_postgres::users::RegistrationError::UsernameTaken
                | northstar_auth_postgres::users::RegistrationError::InvitationRejected),
            ) => {
                let reason = match error {
                    northstar_auth_postgres::users::RegistrationError::UsernameTaken => {
                        "username_unavailable"
                    }
                    northstar_auth_postgres::users::RegistrationError::InvitationRejected => {
                        "invitation_rejected"
                    }
                    _ => unreachable!("pattern is restricted above"),
                };
                northstar_auth_postgres::users::audit_registration_rejection_in_tx(
                    &mut publication,
                    lease.request_id,
                    reason,
                )
                .await?;
                let body = serde_json::to_vec(&serde_json::json!({
                    "error": {
                        "code": "bad_request",
                        "message": "registration request could not be accepted"
                    }
                }))?;
                anyhow::ensure!(
                    northstar_operations_postgres::api_control::complete_idempotency_in_tx(
                        keyring,
                        &mut publication,
                        &lease,
                        400,
                        &northstar_operations_core::api_mutations::json_replay_headers(),
                        &body,
                    )
                    .await?,
                    "registration rejection idempotency lease changed"
                );
                publication.commit().await?;
                Ok(Outcome::Rejected(body))
            }
            crate::account_lifecycle::GuardedRegistrationOutcome::Rejected(error) => {
                if !northstar_operations_postgres::api_control::abandon_idempotency_lease_in_tx(
                    &mut publication,
                    &lease,
                )
                .await?
                {
                    publication.rollback().await?;
                    return Ok(Outcome::LeaseLost);
                }
                publication.commit().await?;
                match error {
                    northstar_auth_postgres::users::RegistrationError::CapacityExhausted => {
                        Ok(Outcome::CapacityExhausted)
                    }
                    northstar_auth_postgres::users::RegistrationError::Closed => {
                        Ok(Outcome::Closed)
                    }
                    northstar_auth_postgres::users::RegistrationError::RateLimited => {
                        Ok(Outcome::RateLimited)
                    }
                    northstar_auth_postgres::users::RegistrationError::PasswordWorkOverloaded => {
                        Ok(Outcome::PasswordWorkOverloaded)
                    }
                    northstar_auth_postgres::users::RegistrationError::InvalidUsername(_) => {
                        Ok(Outcome::InvalidUsername)
                    }
                    northstar_auth_postgres::users::RegistrationError::InvitationRejected => {
                        Ok(Outcome::InvitationRejected)
                    }
                    northstar_auth_postgres::users::RegistrationError::UsernameTaken => {
                        Ok(Outcome::UsernameTaken)
                    }
                    northstar_auth_postgres::users::RegistrationError::Internal(error) => {
                        Err(error)
                    }
                }
            }
        }
    }

    async fn verify_registration_guard(
        &self,
        request: RegistrationGuardRequest<'_>,
    ) -> Result<RegistrationGuardOutcome> {
        let mut transaction = self.pool.begin().await?;
        if !northstar_operations_postgres::api_control::resume_idempotency_lease_fence_in_tx(
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
        let outcome = northstar_abuse_postgres::transaction::verify_in_tx(
            &mut transaction,
            &self.abuse,
            northstar_abuse_policy::AbuseAction::Registration,
            request.subject,
            request.actors,
            request.proof,
            Some(request.intent),
        )
        .await?;
        match outcome {
            northstar_abuse_application::guard::TransactionalGuardOutcome::Allowed => {
                if !northstar_operations_postgres::api_control::mark_idempotency_guard_verified_fence_in_tx(
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
            northstar_abuse_application::guard::TransactionalGuardOutcome::DeniedNeedsCommit(
                error,
            ) => {
                if !northstar_operations_postgres::api_control::abandon_idempotency_lease_fence_in_tx(
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
        password_work: northstar_security::password_work::PasswordWorkReservation,
    ) -> Result<RegistrationOutcome> {
        let mut transaction = self
            .pool
            .begin()
            .await
            .context("could not begin registration admission")?;
        let admission_outcome = northstar_abuse_postgres::transaction::verify_in_tx(
            &mut transaction,
            &self.abuse,
            northstar_abuse_policy::AbuseAction::Registration,
            request.subject,
            request.actors,
            request.proof,
            Some(request.intent),
        )
        .await
        .context("registration anti-abuse admission failed")?;
        match admission_outcome {
            northstar_abuse_application::guard::TransactionalGuardOutcome::Allowed => {}
            northstar_abuse_application::guard::TransactionalGuardOutcome::DeniedNeedsCommit(
                error,
            ) => {
                let requirement = error.requirement().clone();
                transaction
                    .commit()
                    .await
                    .context("registration denial commit failed")?;
                return Ok(RegistrationOutcome::AbuseDenied(requirement));
            }
        }

        let prepared = match northstar_auth_postgres::users::prepare_registration_with_reservation(
            request.username,
            request.password,
            policy.scram_iterations,
            policy.scram_sha1_enabled,
            password_work,
        )
        .await
        {
            Ok(prepared) => prepared,
            Err(northstar_auth_postgres::users::RegistrationError::InvalidUsername(_)) => {
                if let Err(rollback_error) = transaction.rollback().await {
                    tracing::error!(?rollback_error, "registration rollback failed");
                }
                return Ok(RegistrationOutcome::InvalidUsername);
            }
            Err(northstar_auth_postgres::users::RegistrationError::PasswordWorkOverloaded) => {
                if let Err(rollback_error) = transaction.rollback().await {
                    tracing::error!(?rollback_error, "registration rollback failed");
                }
                return Ok(RegistrationOutcome::PasswordWorkOverloaded);
            }
            Err(northstar_auth_postgres::users::RegistrationError::Internal(error)) => {
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
        let outcome = crate::account_lifecycle::create_user_with_invitation_guarded_in_tx_v2(
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
            crate::account_lifecycle::GuardedRegistrationOutcome::Created(mut user) => {
                let username = std::mem::take(&mut user.username);
                user.password_hash.zeroize();
                user.password_hash.clear();
                RegistrationOutcome::Created(RegistrationAccount { username })
            }
            crate::account_lifecycle::GuardedRegistrationOutcome::AbuseDenied(error) => {
                RegistrationOutcome::AbuseDenied(error.requirement().clone())
            }
            crate::account_lifecycle::GuardedRegistrationOutcome::Rejected(error) => match error {
                northstar_auth_postgres::users::RegistrationError::InvalidUsername(_) => {
                    RegistrationOutcome::InvalidUsername
                }
                northstar_auth_postgres::users::RegistrationError::InvitationRejected => {
                    RegistrationOutcome::InvitationRejected
                }
                northstar_auth_postgres::users::RegistrationError::UsernameTaken => {
                    RegistrationOutcome::UsernameTaken
                }
                northstar_auth_postgres::users::RegistrationError::RateLimited => {
                    RegistrationOutcome::RateLimited
                }
                northstar_auth_postgres::users::RegistrationError::CapacityExhausted => {
                    RegistrationOutcome::CapacityExhausted
                }
                northstar_auth_postgres::users::RegistrationError::PasswordWorkOverloaded => {
                    RegistrationOutcome::PasswordWorkOverloaded
                }
                northstar_auth_postgres::users::RegistrationError::Closed => {
                    RegistrationOutcome::Closed
                }
                northstar_auth_postgres::users::RegistrationError::Internal(error) => {
                    return Err(error)
                }
            },
        })
    }

    async fn change_password(
        &self,
        request: PasswordChangeRequest<'_>,
        policy: AccountPolicy,
    ) -> Result<PasswordChangeOutcome> {
        match crate::account_lifecycle::change_password_guarded_v2(
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
            Err(error) if northstar_security::password_work::is_overloaded(&error) => {
                Ok(PasswordChangeOutcome::PasswordWorkOverloaded)
            }
            Err(error) => Err(error).context("guarded password change failed"),
        }
    }

    async fn quiesce_for_deletion(
        &self,
        request: DeletionQuiesceRequest<'_>,
    ) -> Result<DeletionQuiesceOutcome> {
        match crate::account_lifecycle::begin_account_deletion_quiesce_guarded_v2(
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
        Ok(crate::account_lifecycle::delete_user_with_roster_audited(
            &self.effects,
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
        crate::account_deletion::claim_account_deletion_jobs(&self.pool, limit, lease_seconds).await
    }

    async fn release_deletion_recovery(
        &self,
        job: &DeletionRecoveryJob,
        error_code: &str,
    ) -> Result<bool> {
        crate::account_deletion::release_account_deletion_job(&self.pool, job, error_code).await
    }
}
