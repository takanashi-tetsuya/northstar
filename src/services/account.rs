//! Account lifecycle application service.
//!
//! XEP-0077 handlers validate and render XML. This boundary owns password
//! derivation and the PostgreSQL transactions that consume PoW challenges,
//! invitations, account capacity, credential changes and account deletion.
//! Keeping those effects together prevents a stanza handler from committing
//! only part of an account mutation or from retaining a general-purpose pool.

use crate::{
    abuse::{AbuseGuard, PowIntent, PowProof, WorkRequirement},
    db,
};
use anyhow::{Context, Result};
use sqlx::PgPool;
use uuid::Uuid;
use zeroize::Zeroize;

#[derive(Clone, Copy)]
struct AccountPolicy {
    invitation_required: bool,
    registration_rate_per_hour: u32,
    scram_iterations: u32,
    scram_sha1_enabled: bool,
}

#[derive(Debug)]
pub(crate) enum RegistrationOutcome {
    Created(RegistrationAccount),
    AbuseDenied(WorkRequirement),
    InvalidUsername,
    InvitationRejected,
    UsernameTaken,
    RateLimited,
    CapacityExhausted,
    PasswordWorkOverloaded,
    Closed,
}

#[derive(Debug)]
pub(crate) struct RegistrationAccount {
    pub(crate) username: String,
}

#[derive(Debug)]
pub(crate) enum PasswordChangeOutcome {
    Changed,
    AbuseDenied(WorkRequirement),
    PasswordWorkOverloaded,
}

#[derive(Debug)]
pub(crate) enum DeletionQuiesceOutcome {
    Quiesced,
    Missing,
    AbuseDenied(WorkRequirement),
}

pub(crate) type RemovedRosterItem = (String, Option<String>, String, Option<String>);

#[derive(Debug)]
pub(crate) struct RemovedAccount {
    pub(crate) roster: Vec<RemovedRosterItem>,
    pub(crate) reverse_roster_changes: Vec<(Uuid, String, db::RosterChange)>,
}

#[derive(Clone, Debug)]
pub(crate) struct DeletionRecoveryJob {
    pub(crate) user_id: Uuid,
    pub(crate) username: String,
    authority: db::AccountDeletionJob,
}

pub(crate) struct RegistrationRequest<'a> {
    pub(crate) username: &'a str,
    pub(crate) password: &'a str,
    pub(crate) invitation_token: Option<&'a str>,
    pub(crate) proof: Option<&'a PowProof>,
    pub(crate) intent: &'a PowIntent,
    pub(crate) subject: &'a str,
    pub(crate) actors: &'a [String],
}

pub(crate) struct PasswordChangeRequest<'a> {
    pub(crate) subject: &'a str,
    pub(crate) actors: &'a [String],
    pub(crate) proof: Option<&'a PowProof>,
    pub(crate) intent: &'a PowIntent,
    pub(crate) user_id: Uuid,
    pub(crate) expected_auth_generation: i64,
    pub(crate) password: &'a str,
}

pub(crate) struct DeletionQuiesceRequest<'a> {
    pub(crate) subject: &'a str,
    pub(crate) actors: &'a [String],
    pub(crate) proof: Option<&'a PowProof>,
    pub(crate) intent: &'a PowIntent,
    pub(crate) user_id: Uuid,
    pub(crate) expected_auth_generation: i64,
}

#[derive(Clone)]
pub(crate) struct AccountService {
    pool: PgPool,
    domain: String,
    policy: AccountPolicy,
}

impl AccountService {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        pool: PgPool,
        domain: String,
        invitation_required: bool,
        registration_rate_per_hour: u32,
        scram_iterations: u32,
        scram_sha1_enabled: bool,
    ) -> Self {
        Self {
            pool,
            domain,
            policy: AccountPolicy {
                invitation_required,
                registration_rate_per_hour,
                scram_iterations,
                scram_sha1_enabled,
            },
        }
    }

    pub(crate) async fn register(
        &self,
        abuse: &AbuseGuard,
        request: RegistrationRequest<'_>,
    ) -> Result<RegistrationOutcome> {
        // Reserve bounded CPU capacity before borrowing a database connection.
        // The expensive work runs only after the body-bound v2 guard succeeds,
        // but proof consumption, actor advancement, invitation consumption,
        // credential creation and the account row remain one transaction. A
        // crash therefore rolls the proof back instead of burning it.
        let password_work = match crate::password_work::reserve().await {
            Ok(password_work) => password_work,
            Err(error) if error.is_overloaded() => {
                return Ok(RegistrationOutcome::PasswordWorkOverloaded)
            }
            Err(error) => return Err(anyhow::Error::new(error)),
        };
        let mut transaction = self
            .pool
            .begin()
            .await
            .context("could not begin registration admission")?;
        let admission_outcome = abuse
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
            self.policy.scram_iterations,
            self.policy.scram_sha1_enabled,
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
            abuse,
            request.subject,
            request.actors,
            request.proof,
            request.intent,
            true,
            prepared,
            request.invitation_token,
            self.policy.invitation_required,
            self.policy.registration_rate_per_hour,
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

    pub(crate) async fn change_password(
        &self,
        abuse: &AbuseGuard,
        request: PasswordChangeRequest<'_>,
    ) -> Result<PasswordChangeOutcome> {
        match db::change_password_guarded_v2(
            &self.pool,
            abuse,
            request.subject,
            request.actors,
            request.proof,
            request.intent,
            request.user_id,
            request.expected_auth_generation,
            request.password,
            self.policy.scram_iterations,
            self.policy.scram_sha1_enabled,
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

    pub(crate) async fn quiesce_for_deletion(
        &self,
        abuse: &AbuseGuard,
        request: DeletionQuiesceRequest<'_>,
    ) -> Result<DeletionQuiesceOutcome> {
        match db::begin_account_deletion_quiesce_guarded_v2(
            &self.pool,
            abuse,
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

    pub(crate) async fn delete_quiesced(&self, user_id: Uuid) -> Result<Option<RemovedAccount>> {
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

    pub(crate) async fn claim_deletion_recovery(
        &self,
        limit: i64,
        lease_seconds: i64,
    ) -> Result<Vec<DeletionRecoveryJob>> {
        Ok(
            db::claim_account_deletion_jobs(&self.pool, limit, lease_seconds)
                .await?
                .into_iter()
                .map(|authority| DeletionRecoveryJob {
                    user_id: authority.user_id,
                    username: authority.username.clone(),
                    authority,
                })
                .collect(),
        )
    }

    pub(crate) async fn release_deletion_recovery(
        &self,
        job: &DeletionRecoveryJob,
        error_code: &str,
    ) -> Result<bool> {
        db::release_account_deletion_job(&self.pool, &job.authority, error_code).await
    }
}
