//! Ordered bearer, idempotency, proof and credential authority for REST
//! password changes. No transaction or credential-bearing subject escapes.

use anyhow::{Context, Result};
use northstar_abuse_application::guard::{AbuseGuard, TransactionalGuardOutcome};
use northstar_abuse_policy::AbuseAction;
use northstar_auth_application::password_change::{
    DisconnectedAccount, PasswordChangeCommand, PasswordChangePolicy, PasswordChangeRepository,
    PasswordChangeResult,
};
use northstar_operations_core::api_mutations;
use northstar_operations_core::api_mutations::StoredApiResponse;
use sqlx::{PgPool, Postgres, Transaction};
use std::sync::Arc;

#[derive(Clone)]
pub struct PostgresPasswordChangeRepository {
    pool: PgPool,
    api_control: Arc<northstar_operations_postgres::api_control::ApiControlKeyring>,
    abuse: Arc<AbuseGuard>,
}

impl PostgresPasswordChangeRepository {
    pub fn new(
        pool: PgPool,
        api_control: Arc<northstar_operations_postgres::api_control::ApiControlKeyring>,
        abuse: Arc<AbuseGuard>,
    ) -> Self {
        Self {
            pool,
            api_control,
            abuse,
        }
    }

    async fn yield_lease(
        &self,
        lease: &northstar_operations_postgres::api_control::IdempotencyLease,
    ) -> Result<bool> {
        northstar_operations_postgres::api_control::yield_idempotency_lease(&self.pool, lease).await
    }

    async fn complete_response(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        lease: &northstar_operations_postgres::api_control::IdempotencyLease,
        mut response: StoredApiResponse,
    ) -> Result<StoredApiResponse> {
        if response.status == 401 {
            response.headers.insert(
                "www-authenticate".to_owned(),
                "Bearer realm=\"northstar\"".to_owned(),
            );
        }
        anyhow::ensure!(
            northstar_operations_postgres::api_mutations::persist_response_in_tx(
                &self.api_control,
                tx,
                lease,
                &response
            )
            .await?,
            "password-change idempotency lease changed"
        );
        Ok(response)
    }
}

impl PasswordChangeRepository for PostgresPasswordChangeRepository {
    async fn execute(
        &self,
        command: PasswordChangeCommand<'_>,
        policy: PasswordChangePolicy,
        invalid_input: bool,
    ) -> Result<PasswordChangeResult> {
        use PasswordChangeResult as Outcome;

        // A completed password change revoked the presented bearer. Replay
        // lookup must precede new bearer authorization and take no row lock.
        let mut replay_tx = self.pool.begin().await?;
        match northstar_operations_postgres::api_control::lookup_password_change_replay_in_tx(
            &self.api_control,
            &mut replay_tx,
            &command.idempotency,
        )
        .await?
        {
            northstar_operations_postgres::api_control::IdempotencyReplayLookup::Miss => replay_tx.commit().await?,
            northstar_operations_postgres::api_control::IdempotencyReplayLookup::Replay(replay) => {
                replay_tx.commit().await?;
                return Ok(Outcome::Replay(replay));
            }
            northstar_operations_postgres::api_control::IdempotencyReplayLookup::FingerprintConflict
            | northstar_operations_postgres::api_control::IdempotencyReplayLookup::RotationConflict => {
                replay_tx.rollback().await?;
                return Ok(Outcome::IdempotencyConflict);
            }
        }

        let mut reserve_tx = self.pool.begin().await?;
        let Some(user) = northstar_auth_postgres::users::password_change_subject_for_token_in_tx(
            &mut reserve_tx,
            command.presented_session,
        )
        .await?
        else {
            reserve_tx.rollback().await?;
            return Ok(Outcome::Unauthorized);
        };
        let lease = match northstar_operations_postgres::api_control::acquire_idempotency_in_tx(
            &self.api_control,
            &mut reserve_tx,
            &command.idempotency,
        )
        .await?
        {
            northstar_operations_postgres::api_control::IdempotencyAcquire::Acquired(lease) => {
                lease
            }
            northstar_operations_postgres::api_control::IdempotencyAcquire::Replay(replay) => {
                reserve_tx.commit().await?;
                return Ok(Outcome::Replay(replay));
            }
            northstar_operations_postgres::api_control::IdempotencyAcquire::FingerprintConflict
            | northstar_operations_postgres::api_control::IdempotencyAcquire::RotationConflict => {
                reserve_tx.rollback().await?;
                return Ok(Outcome::IdempotencyConflict);
            }
            northstar_operations_postgres::api_control::IdempotencyAcquire::ReplayInvalidated => {
                reserve_tx.rollback().await?;
                return Ok(Outcome::ReplayInvalidated);
            }
            northstar_operations_postgres::api_control::IdempotencyAcquire::Busy {
                retry_after_seconds,
            } => {
                reserve_tx.rollback().await?;
                return Ok(Outcome::Busy(retry_after_seconds));
            }
            northstar_operations_postgres::api_control::IdempotencyAcquire::CapacityLimited {
                retry_after_seconds,
            } => {
                reserve_tx.rollback().await?;
                return Ok(Outcome::CapacityLimited(retry_after_seconds));
            }
            northstar_operations_postgres::api_control::IdempotencyAcquire::InProgress {
                retry_after_seconds,
            } => {
                reserve_tx.rollback().await?;
                return Ok(Outcome::InProgress(retry_after_seconds));
            }
        };
        let subject = format!("{}:{}", AbuseAction::PasswordChange.as_str(), user.id);
        let actors = vec![
            format!("ip:{}", command.peer_ip),
            format!("user:{}", user.id),
            format!("behavior:{}", user.id),
        ];
        if !lease.guard_verified {
            match northstar_abuse_postgres::transaction::verify_in_tx(
                &mut reserve_tx,
                &self.abuse,
                AbuseAction::PasswordChange,
                &subject,
                &actors,
                command.proof,
                Some(command.intent),
            )
            .await?
            {
                TransactionalGuardOutcome::Allowed => {
                    anyhow::ensure!(
                        northstar_operations_postgres::api_control::mark_idempotency_guard_verified_in_tx(&mut reserve_tx, &lease).await?,
                        "password-change guard lease changed"
                    );
                }
                TransactionalGuardOutcome::DeniedNeedsCommit(error) => {
                    let response = api_mutations::guard_denial_response(error)?;
                    anyhow::ensure!(
                        northstar_operations_postgres::api_mutations::persist_response_in_tx(
                            &self.api_control,
                            &mut reserve_tx,
                            &lease,
                            &response,
                        )
                        .await?,
                        "idempotency lease changed while recording a rate-limit denial"
                    );
                    reserve_tx.commit().await?;
                    return Ok(Outcome::RateLimited(response));
                }
            }
        }
        reserve_tx.commit().await?;

        if invalid_input {
            let mut tx = self.pool.begin().await?;
            if !northstar_operations_postgres::api_control::resume_idempotency_lease_in_tx(
                &mut tx,
                &lease,
                command.idempotency.lease_seconds,
            )
            .await?
            {
                tx.rollback().await?;
                return Ok(Outcome::LeaseLost);
            }
            if !northstar_auth_postgres::users::authorize_user_in_tx(
                &mut tx,
                user.id,
                user.auth_generation,
                command.presented_session,
            )
            .await?
            {
                tx.rollback().await?;
                northstar_operations_postgres::api_control::abandon_idempotency_lease(
                    &self.pool, &lease,
                )
                .await?;
                return Ok(Outcome::Unauthorized);
            }
            anyhow::ensure!(
                northstar_operations_postgres::api_control::bind_idempotency_actor_in_tx(
                    &mut tx, &lease, user.id
                )
                .await?,
                "password-change idempotency ownership changed"
            );
            let response = self
                .complete_response(
                    &mut tx,
                    &lease,
                    api_mutations::error_response(400, "bad_request", "password input is invalid")?,
                )
                .await?;
            tx.commit().await?;
            return Ok(Outcome::Fresh(response));
        }

        let mut prework_tx = self.pool.begin().await?;
        if !northstar_operations_postgres::api_control::resume_idempotency_lease_in_tx(
            &mut prework_tx,
            &lease,
            command.idempotency.lease_seconds,
        )
        .await?
        {
            prework_tx.rollback().await?;
            return Ok(Outcome::LeaseLost);
        }
        prework_tx.commit().await?;
        let prepared = match northstar_auth_postgres::users::prepare_password_change(
            user.password_hash(),
            command.current_password,
            command.new_password,
            policy.scram_iterations,
            policy.scram_sha1_enabled,
        )
        .await
        {
            Ok(prepared) => prepared,
            Err(error) if northstar_security::password_work::is_overloaded(&error) => {
                if !self.yield_lease(&lease).await? {
                    return Ok(Outcome::LeaseLost);
                }
                return Ok(Outcome::WorkerOverloaded);
            }
            Err(error) => {
                if !self.yield_lease(&lease).await? {
                    return Ok(Outcome::LeaseLost);
                }
                tracing::error!(
                    integrity_failure = northstar_auth_core::is_password_verifier_integrity_error(&error),
                    ?error,
                    user_id = %user.id,
                    "password-change verifier backend failed"
                );
                return Ok(Outcome::VerifierUnavailable);
            }
        };

        let mut tx = self.pool.begin().await?;
        if !northstar_operations_postgres::api_control::resume_idempotency_lease_in_tx(
            &mut tx,
            &lease,
            command.idempotency.lease_seconds,
        )
        .await?
        {
            tx.rollback().await?;
            return Ok(Outcome::LeaseLost);
        }
        if matches!(
            prepared,
            northstar_auth_postgres::users::PreparedPasswordChange::InvalidCurrentPassword
        ) {
            if !northstar_auth_postgres::users::authorize_password_change_in_tx(
                &mut tx,
                user.id,
                user.password_hash(),
                user.auth_generation,
                command.presented_session,
            )
            .await?
            {
                tx.rollback().await?;
                northstar_operations_postgres::api_control::abandon_idempotency_lease(
                    &self.pool, &lease,
                )
                .await?;
                return Ok(Outcome::Unauthorized);
            }
            anyhow::ensure!(
                northstar_operations_postgres::api_control::bind_idempotency_actor_in_tx(
                    &mut tx, &lease, user.id
                )
                .await?,
                "password-change failure ownership changed"
            );
            northstar_abuse_postgres::transaction::record_failure_in_tx(
                &mut tx,
                &self.abuse,
                AbuseAction::PasswordChange,
                &actors,
            )
            .await?;
            let response = self
                .complete_response(
                    &mut tx,
                    &lease,
                    api_mutations::error_response(401, "unauthorized", "authentication required")?,
                )
                .await?;
            tx.commit().await?;
            return Ok(Outcome::Fresh(response));
        }
        anyhow::ensure!(
            northstar_operations_postgres::api_control::bind_idempotency_actor_in_tx(
                &mut tx, &lease, user.id
            )
            .await?,
            "password-change idempotency ownership changed"
        );
        let outcome = match northstar_auth_postgres::users::apply_prepared_password_change_in_tx(
            &mut tx,
            user.id,
            user.password_hash(),
            user.auth_generation,
            command.presented_session,
            prepared,
            Some(lease.request_id),
        )
        .await
        {
            Ok(outcome) => outcome,
            Err(error) => {
                tx.rollback().await?;
                if !self.yield_lease(&lease).await? {
                    return Ok(Outcome::LeaseLost);
                }
                tracing::error!(?error, user_id = %user.id, "password-change publication backend failed");
                return Ok(Outcome::PublicationUnavailable);
            }
        };
        if outcome != northstar_auth_postgres::users::PasswordChangeOutcome::Changed {
            tx.rollback().await?;
            northstar_operations_postgres::api_control::abandon_idempotency_lease(
                &self.pool, &lease,
            )
            .await?;
            return Ok(Outcome::Unauthorized);
        }
        let response = self
            .complete_response(
                &mut tx,
                &lease,
                StoredApiResponse::json(
                    200,
                    serde_json::json!({"changed":true,"sessions_revoked":true}),
                )?,
            )
            .await
            .context("could not store password-change success response")?;
        tx.commit().await?;
        Ok(Outcome::Changed(
            response,
            DisconnectedAccount {
                user_id: user.id,
                username: user.username.clone(),
            },
        ))
    }
}
