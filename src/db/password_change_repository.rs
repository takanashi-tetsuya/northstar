//! Ordered bearer, idempotency, proof and credential authority for REST
//! password changes. No transaction or credential-bearing subject escapes.

use crate::{
    abuse::{AbuseAction, AbuseGuard, TransactionalGuardOutcome},
    db,
    services::{
        api_mutations::{self, StoredApiResponse},
        password_change::{
            DisconnectedAccount, PasswordChangeCommand, PasswordChangePolicy,
            PasswordChangeRepository, PasswordChangeResult,
        },
    },
};
use anyhow::{Context, Result};
use sqlx::{PgPool, Postgres, Transaction};
use std::sync::Arc;

#[derive(Clone)]
pub(crate) struct PostgresPasswordChangeRepository {
    pool: PgPool,
    api_control: Arc<db::ApiControlKeyring>,
    abuse: Arc<AbuseGuard>,
}

impl PostgresPasswordChangeRepository {
    pub(crate) fn new(
        pool: PgPool,
        api_control: Arc<db::ApiControlKeyring>,
        abuse: Arc<AbuseGuard>,
    ) -> Self {
        Self {
            pool,
            api_control,
            abuse,
        }
    }

    async fn yield_lease(&self, lease: &db::IdempotencyLease) -> Result<bool> {
        db::yield_idempotency_lease(&self.pool, lease).await
    }

    async fn complete_response(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        lease: &db::IdempotencyLease,
        mut response: StoredApiResponse,
    ) -> Result<StoredApiResponse> {
        if response.status == 401 {
            response.headers.insert(
                "www-authenticate".to_owned(),
                "Bearer realm=\"northstar\"".to_owned(),
            );
        }
        anyhow::ensure!(
            db::api_mutations::persist_response_in_tx(&self.api_control, tx, lease, &response)
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
        match db::lookup_password_change_replay_in_tx(
            &self.api_control,
            &mut replay_tx,
            &command.idempotency,
        )
        .await?
        {
            db::IdempotencyReplayLookup::Miss => replay_tx.commit().await?,
            db::IdempotencyReplayLookup::Replay(replay) => {
                replay_tx.commit().await?;
                return Ok(Outcome::Replay(replay));
            }
            db::IdempotencyReplayLookup::FingerprintConflict
            | db::IdempotencyReplayLookup::RotationConflict => {
                replay_tx.rollback().await?;
                return Ok(Outcome::IdempotencyConflict);
            }
        }

        let mut reserve_tx = self.pool.begin().await?;
        let Some(user) =
            db::password_change_subject_for_token_in_tx(&mut reserve_tx, command.presented_session)
                .await?
        else {
            reserve_tx.rollback().await?;
            return Ok(Outcome::Unauthorized);
        };
        let lease = match db::acquire_idempotency_in_tx(
            &self.api_control,
            &mut reserve_tx,
            &command.idempotency,
        )
        .await?
        {
            db::IdempotencyAcquire::Acquired(lease) => lease,
            db::IdempotencyAcquire::Replay(replay) => {
                reserve_tx.commit().await?;
                return Ok(Outcome::Replay(replay));
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
        let subject = format!("{}:{}", AbuseAction::PasswordChange.as_str(), user.id);
        let actors = vec![
            format!("ip:{}", command.peer_ip),
            format!("user:{}", user.id),
            format!("behavior:{}", user.id),
        ];
        if !lease.guard_verified {
            match self
                .abuse
                .verify_or_allow_in_tx_v2(
                    &mut reserve_tx,
                    AbuseAction::PasswordChange,
                    &subject,
                    &actors,
                    command.proof,
                    command.intent,
                )
                .await?
            {
                TransactionalGuardOutcome::Allowed => {
                    anyhow::ensure!(
                        db::mark_idempotency_guard_verified_in_tx(&mut reserve_tx, &lease).await?,
                        "password-change guard lease changed"
                    );
                }
                TransactionalGuardOutcome::DeniedNeedsCommit(error) => {
                    let response = api_mutations::guard_denial_response(error)?;
                    anyhow::ensure!(
                        db::api_mutations::persist_response_in_tx(
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
            if !db::resume_idempotency_lease_in_tx(
                &mut tx,
                &lease,
                command.idempotency.lease_seconds,
            )
            .await?
            {
                tx.rollback().await?;
                return Ok(Outcome::LeaseLost);
            }
            if !db::authorize_user_in_tx(
                &mut tx,
                user.id,
                user.auth_generation,
                command.presented_session,
            )
            .await?
            {
                tx.rollback().await?;
                db::abandon_idempotency_lease(&self.pool, &lease).await?;
                return Ok(Outcome::Unauthorized);
            }
            anyhow::ensure!(
                db::bind_idempotency_actor_in_tx(&mut tx, &lease, user.id).await?,
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
        if !db::resume_idempotency_lease_in_tx(
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
        let prepared = match db::prepare_password_change(
            user.password_hash(),
            command.current_password,
            command.new_password,
            policy.scram_iterations,
            policy.scram_sha1_enabled,
        )
        .await
        {
            Ok(prepared) => prepared,
            Err(error) if crate::password_work::is_overloaded(&error) => {
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
                    integrity_failure = crate::auth::is_password_verifier_integrity_error(&error),
                    ?error,
                    user_id = %user.id,
                    "password-change verifier backend failed"
                );
                return Ok(Outcome::VerifierUnavailable);
            }
        };

        let mut tx = self.pool.begin().await?;
        if !db::resume_idempotency_lease_in_tx(&mut tx, &lease, command.idempotency.lease_seconds)
            .await?
        {
            tx.rollback().await?;
            return Ok(Outcome::LeaseLost);
        }
        if matches!(prepared, db::PreparedPasswordChange::InvalidCurrentPassword) {
            if !db::authorize_password_change_in_tx(
                &mut tx,
                user.id,
                user.password_hash(),
                user.auth_generation,
                command.presented_session,
            )
            .await?
            {
                tx.rollback().await?;
                db::abandon_idempotency_lease(&self.pool, &lease).await?;
                return Ok(Outcome::Unauthorized);
            }
            anyhow::ensure!(
                db::bind_idempotency_actor_in_tx(&mut tx, &lease, user.id).await?,
                "password-change failure ownership changed"
            );
            self.abuse
                .record_failure_in_tx(&mut tx, AbuseAction::PasswordChange, &actors)
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
            db::bind_idempotency_actor_in_tx(&mut tx, &lease, user.id).await?,
            "password-change idempotency ownership changed"
        );
        let outcome = match db::apply_prepared_password_change_in_tx(
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
        if outcome != db::PasswordChangeOutcome::Changed {
            tx.rollback().await?;
            db::abandon_idempotency_lease(&self.pool, &lease).await?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        abuse::{AbuseConfig, PowIntent},
        services::{
            api_mutations::{api_request_fingerprint, ApiPrincipalKind, IdempotencyRequest},
            password_change::PasswordChangeService,
        },
    };
    use std::{net::IpAddr, time::Duration};
    use uuid::Uuid;

    async fn run_change(
        service: &PasswordChangeService<PostgresPasswordChangeRepository>,
        token: &str,
        key: &str,
        request_id: Uuid,
        current_password: &str,
        new_password: &str,
    ) -> PasswordChangeResult {
        let body = serde_json::json!({
            "current_password": current_password,
            "new_password": new_password,
        });
        let bytes = serde_json::to_vec(&body).unwrap();
        let intent = PowIntent::http_json_method(
            AbuseAction::PasswordChange,
            "PATCH",
            "/api/v1/me/password",
            &body,
        );
        service
            .execute(PasswordChangeCommand {
                idempotency: IdempotencyRequest {
                    request_id,
                    actor_id: None,
                    principal_scope: token.as_bytes(),
                    capacity_scope: token.as_bytes(),
                    target_scope: b"",
                    principal_kind: ApiPrincipalKind::User,
                    method: "PATCH",
                    route: "/api/v1/me/password",
                    idempotency_key: key,
                    request_fingerprint: api_request_fingerprint("application/json", &bytes),
                    ttl_seconds: 3_600,
                    lease_seconds: 180,
                },
                presented_session: token,
                current_password,
                new_password,
                proof: None,
                intent: &intent,
                peer_ip: IpAddr::from([192, 0, 2, 50]),
            })
            .await
            .unwrap()
    }

    #[tokio::test]
    #[ignore = "requires TEST_DATABASE_URL pointing at an isolated PostgreSQL database"]
    async fn password_change_replays_committed_response_after_bearer_revocation() {
        let url = std::env::var("TEST_DATABASE_URL").expect("set TEST_DATABASE_URL");
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(8)
            .connect(&url)
            .await
            .unwrap();
        crate::db::migrate(&pool).await.unwrap();
        let suffix = Uuid::new_v4().simple().to_string();
        let user = db::create_user(
            &pool,
            &format!("password{}", &suffix[..10]),
            "password-before-change",
            false,
            true,
            crate::auth::MIN_SCRAM_ITERATIONS,
            false,
        )
        .await
        .unwrap();
        let token = db::create_api_session(&pool, user.id, 1).await.unwrap();
        let keyring = Arc::new(
            db::ApiControlKeyring::new(b"password-service-test-control-key-00001", None).unwrap(),
        );
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
            Some(b"password-service-test-abuse-key-000001"),
            None,
        ));
        let service = PasswordChangeService::new(
            PostgresPasswordChangeRepository::new(pool.clone(), keyring, guard),
            crate::auth::MIN_SCRAM_ITERATIONS,
            false,
        );
        let key = format!("password-{suffix}");
        let request_id = Uuid::new_v4();
        let changed = run_change(
            &service,
            &token,
            &key,
            request_id,
            "password-before-change",
            "password-after-change",
        )
        .await;
        let PasswordChangeResult::Changed(response, account) = changed else {
            panic!("expected a committed password change");
        };
        assert_eq!(account.user_id, user.id);
        assert_eq!(response.status, 200);
        assert_eq!(response.headers, api_mutations::json_replay_headers());
        assert_eq!(
            response.body,
            br#"{"changed":true,"sessions_revoked":true}"#
        );
        assert!(db::user_for_token(&pool, &token).await.unwrap().is_none());

        let replay = run_change(
            &service,
            &token,
            &key,
            request_id,
            "password-before-change",
            "password-after-change",
        )
        .await;
        let PasswordChangeResult::Replay(replay) = replay else {
            panic!("exact response must replay after the bearer was revoked");
        };
        assert_eq!(replay.request_id, request_id);
        assert_eq!(replay.status, response.status);
        assert_eq!(replay.headers, response.headers);
        assert_eq!(replay.body, response.body);
        let new_key = format!("other-{suffix}");
        let unauthorized = run_change(
            &service,
            &token,
            &new_key,
            Uuid::new_v4(),
            "password-after-change",
            "another-new-password",
        )
        .await;
        assert!(matches!(unauthorized, PasswordChangeResult::Unauthorized));
        pool.close().await;
    }
}
