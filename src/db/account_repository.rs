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
}
impl PostgresAccountRepository {
    pub(crate) fn new(pool: PgPool, domain: String, abuse: Arc<AbuseGuard>) -> Self {
        Self {
            pool,
            domain,
            abuse,
        }
    }
}
impl AccountRepository for PostgresAccountRepository {
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
