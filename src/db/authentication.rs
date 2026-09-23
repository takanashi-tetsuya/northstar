//! Credential reads and atomic SASL/FAST generation, token and binding fences.
use crate::{auth, db, services::authentication::*};
use northstar_archive_core::ArchiveBoundary;
use sqlx::{PgPool, Row};
use std::{future::Future, sync::Arc};
use uuid::Uuid;
use zeroize::Zeroizing;

const LOGIN_EPOCH_STAGE_TTL_SECONDS: u64 = 120;

#[derive(Clone)]
pub(crate) struct PostgresAuthenticationRepository {
    pool: PgPool,
    fast_token_secret: Arc<Zeroizing<Vec<u8>>>,
}
impl PostgresAuthenticationRepository {
    pub(crate) fn new(pool: PgPool, fast_token_secret: Arc<Zeroizing<Vec<u8>>>) -> Self {
        Self {
            pool,
            fast_token_secret,
        }
    }
    pub(crate) async fn authenticate_plain_with_hook<F, Fut>(
        &self,
        username: &str,
        password: &str,
        policy: AuthenticationPolicy,
        after_password_verified: F,
    ) -> AuthenticationResult<AuthenticatedAccount>
    where
        F: FnOnce(AuthenticationFence) -> Fut,
        Fut: Future<Output = ()>,
    {
        let prepared = match db::prepare_login(
            &self.pool,
            username,
            password,
            policy.scram_iterations,
            policy.scram_sha1_enabled,
        )
        .await
        {
            Ok(Some(prepared)) => prepared,
            Ok(None) => return self.classify_unknown_username(username).await,
            Err(error) if auth::is_password_verifier_integrity_error(&error) => {
                // Keep the integrity fault observable to operators without
                // exposing a distinct SASL result for the affected account.
                // prepare_login has already paid the bounded dummy-Argon2
                // cost, so the wire result and gross work profile match an
                // ordinary credential failure.
                tracing::error!(
                    ?error,
                    "stored password verifier failed integrity validation"
                );
                return self.classify_unknown_username(username).await;
            }
            Err(error) => return AuthenticationResult::BackendFailure(error),
        };
        let fence = AuthenticationFence {
            user_id: prepared.user.id,
            auth_generation: prepared.user.auth_generation,
        };
        // Copy only session identity/status fields. Do not duplicate the
        // reusable Argon2 verifier held by PreparedLogin.
        let authenticated_user = sanitized_user(&prepared.user);
        after_password_verified(fence).await;
        let mut transaction = match self.pool.begin().await {
            Ok(transaction) => transaction,
            Err(error) => return AuthenticationResult::BackendFailure(error.into()),
        };
        match db::apply_prepared_login_in_tx(&mut transaction, prepared).await {
            Ok(true) => {
                if let Err(error) = transaction.commit().await {
                    return AuthenticationResult::BackendFailure(error.into());
                }
                AuthenticationResult::Authenticated(authenticated_user)
            }
            Ok(false) => {
                let classification = self
                    .classify_exact_account_state_in_transaction(&mut transaction, fence)
                    .await;
                let rollback = transaction.rollback().await;
                match (classification, rollback) {
                    (AuthenticationResult::Authenticated(()), Ok(())) => {
                        AuthenticationResult::UnknownCredentials
                    }
                    (AuthenticationResult::UnknownCredentials, Ok(())) => {
                        AuthenticationResult::UnknownCredentials
                    }
                    (AuthenticationResult::Disabled, Ok(())) => AuthenticationResult::Disabled,
                    (AuthenticationResult::StaleGeneration, Ok(())) => {
                        AuthenticationResult::StaleGeneration
                    }
                    (AuthenticationResult::ExpiredCredentials, Ok(())) => {
                        AuthenticationResult::ExpiredCredentials
                    }
                    (AuthenticationResult::ReplayedCredentials, Ok(())) => {
                        AuthenticationResult::ReplayedCredentials
                    }
                    (AuthenticationResult::IntegrityFailure, Ok(())) => {
                        AuthenticationResult::IntegrityFailure
                    }
                    (AuthenticationResult::BackendFailure(error), Ok(())) => {
                        AuthenticationResult::BackendFailure(error)
                    }
                    (_, Err(error)) => AuthenticationResult::BackendFailure(error.into()),
                }
            }
            Err(error) => AuthenticationResult::BackendFailure(error),
        }
    }
    pub(crate) async fn bind2_archive_boundaries_with_hook<F, Fut>(
        &self,
        user_id: Uuid,
        expected_auth_generation: i64,
        after_account_locked: F,
    ) -> AuthenticationResult<(Option<ArchiveBoundary>, Option<ArchiveBoundary>)>
    where
        F: FnOnce(AuthenticationFence) -> Fut,
        Fut: Future<Output = ()>,
    {
        // Declare the isolation level in the BEGIN statement so the preflight
        // cannot run a separate statement before PostgreSQL applies it.
        let mut transaction = match self
            .pool
            .begin_with("BEGIN ISOLATION LEVEL REPEATABLE READ")
            .await
        {
            Ok(transaction) => transaction,
            Err(error) => return AuthenticationResult::BackendFailure(error.into()),
        };
        let state =
            sqlx::query("SELECT auth_generation,is_disabled FROM users WHERE id=$1 FOR SHARE")
                .bind(user_id)
                .fetch_optional(&mut *transaction)
                .await;
        let row = match state {
            Ok(Some(row)) => row,
            Ok(None) => {
                let _ = transaction.rollback().await;
                return AuthenticationResult::StaleGeneration;
            }
            Err(error) => return AuthenticationResult::BackendFailure(error.into()),
        };
        let auth_generation = match row.try_get::<i64, _>("auth_generation") {
            Ok(value) => value,
            Err(error) => return AuthenticationResult::BackendFailure(error.into()),
        };
        let is_disabled = match row.try_get::<bool, _>("is_disabled") {
            Ok(value) => value,
            Err(error) => return AuthenticationResult::BackendFailure(error.into()),
        };
        if is_disabled || auth_generation != expected_auth_generation {
            let _ = transaction.rollback().await;
            return if is_disabled {
                AuthenticationResult::Disabled
            } else {
                AuthenticationResult::StaleGeneration
            };
        }
        after_account_locked(AuthenticationFence {
            user_id,
            auth_generation,
        })
        .await;
        let boundaries =
            match db::archive_boundaries_visible_in_transaction(&mut transaction, user_id).await {
                Ok(boundaries) => boundaries,
                Err(error) => return AuthenticationResult::BackendFailure(error),
            };
        match transaction.commit().await {
            Ok(()) => AuthenticationResult::Authenticated(boundaries),
            Err(error) => AuthenticationResult::BackendFailure(error.into()),
        }
    }
    pub(crate) async fn authenticate_fast_with_hook<F, Fut>(
        &self,
        request: FastProofRequest<'_>,
        after_account_locked: F,
    ) -> AuthenticationResult<FastAuthenticationSuccess>
    where
        F: FnOnce(AuthenticationFence) -> Fut,
        Fut: Future<Output = ()>,
    {
        let username = match auth::normalize_username(request.username) {
            Ok(username) => username,
            Err(_) => return AuthenticationResult::UnknownCredentials,
        };
        let mut transaction = match self.pool.begin().await {
            Ok(transaction) => transaction,
            Err(error) => return AuthenticationResult::BackendFailure(error.into()),
        };
        let user = match load_sanitized_user_by_username_in_transaction(&mut transaction, &username)
            .await
        {
            Ok(Some(user)) if user.is_disabled => {
                let _ = transaction.rollback().await;
                return AuthenticationResult::Disabled;
            }
            Ok(Some(user)) => user.account,
            Ok(None) => {
                let _ = transaction.rollback().await;
                return AuthenticationResult::UnknownCredentials;
            }
            Err(error) => return AuthenticationResult::BackendFailure(error),
        };
        after_account_locked(AuthenticationFence {
            user_id: user.id,
            auth_generation: user.auth_generation,
        })
        .await;
        let verified = db::authenticate_fast_token_in_transaction(
            &mut transaction,
            self.fast_token_secret.as_slice(),
            db::FastAuthenticationRequest {
                user_id: user.id,
                device_id: request.device_id,
                mechanism: request.mechanism,
                counter: request.counter,
                initiator_proof: request.initiator_proof,
                channel_binding: request.channel_binding,
                invalidate: request.invalidate,
                rotate_within_days: request.rotate_within_days,
            },
            user.auth_generation,
        )
        .await;
        let verified = match verified {
            Ok(db::FastAuthentication::Success(verified)) => verified,
            Ok(db::FastAuthentication::CredentialsExpired) => {
                let _ = transaction.rollback().await;
                return AuthenticationResult::ExpiredCredentials;
            }
            Ok(db::FastAuthentication::Invalid) => {
                let _ = transaction.rollback().await;
                return AuthenticationResult::UnknownCredentials;
            }
            Ok(db::FastAuthentication::Replayed) => {
                let _ = transaction.rollback().await;
                return AuthenticationResult::ReplayedCredentials;
            }
            Ok(db::FastAuthentication::IntegrityFailure) => {
                let _ = transaction.rollback().await;
                return AuthenticationResult::IntegrityFailure;
            }
            Err(error) => return AuthenticationResult::BackendFailure(error),
        };
        let db::AuthenticatedFastToken {
            token,
            should_rotate,
            id,
            was_new,
            auth_generation,
            strong_auth_at,
            chain_expires_at,
        } = verified;
        if let Err(error) = transaction.commit().await {
            return AuthenticationResult::BackendFailure(error.into());
        }
        let responder = Zeroizing::new(auth::fast_proof(&token, true, request.channel_binding));
        AuthenticationResult::Authenticated(FastAuthenticationSuccess::new(
            user,
            responder,
            should_rotate,
            id,
            was_new,
            auth_generation,
            strong_auth_at,
            chain_expires_at,
        ))
    }
    async fn classify_unknown_username<T>(&self, username: &str) -> AuthenticationResult<T> {
        let username = match auth::normalize_username(username) {
            Ok(username) => username,
            Err(_) => return AuthenticationResult::UnknownCredentials,
        };
        match sqlx::query("SELECT is_disabled FROM users WHERE username=$1")
            .bind(username)
            .fetch_optional(&self.pool)
            .await
        {
            Ok(Some(row)) => match row.try_get::<bool, _>("is_disabled") {
                Ok(true) => AuthenticationResult::Disabled,
                Ok(false) => AuthenticationResult::UnknownCredentials,
                Err(error) => AuthenticationResult::BackendFailure(error.into()),
            },
            Ok(None) => AuthenticationResult::UnknownCredentials,
            Err(error) => AuthenticationResult::BackendFailure(error.into()),
        }
    }
    async fn classify_exact_account_state_in_transaction(
        &self,
        transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        fence: AuthenticationFence,
    ) -> AuthenticationResult<()> {
        match sqlx::query("SELECT auth_generation,is_disabled FROM users WHERE id=$1")
            .bind(fence.user_id)
            .fetch_optional(&mut **transaction)
            .await
        {
            Ok(Some(row)) => {
                let auth_generation = match row.try_get::<i64, _>("auth_generation") {
                    Ok(value) => value,
                    Err(error) => return AuthenticationResult::BackendFailure(error.into()),
                };
                let is_disabled = match row.try_get::<bool, _>("is_disabled") {
                    Ok(value) => value,
                    Err(error) => return AuthenticationResult::BackendFailure(error.into()),
                };
                if is_disabled {
                    AuthenticationResult::Disabled
                } else if auth_generation != fence.auth_generation {
                    AuthenticationResult::StaleGeneration
                } else {
                    AuthenticationResult::Authenticated(())
                }
            }
            Ok(None) => AuthenticationResult::StaleGeneration,
            Err(error) => AuthenticationResult::BackendFailure(error.into()),
        }
    }
}
impl AuthenticationRepository for PostgresAuthenticationRepository {
    async fn scram_credentials(
        &self,
        username: &str,
        algorithm: auth::ScramAlgorithm,
    ) -> AuthenticationResult<ScramCredentialSet> {
        let query = match algorithm {
            auth::ScramAlgorithm::Sha256 => {
                "SELECT id,auth_generation,is_disabled,
                        scram_sha256_salt AS salt,
                        scram_sha256_iterations AS iterations,
                        scram_sha256_stored_key AS stored_key,
                        scram_sha256_server_key AS server_key
                   FROM users WHERE username=$1"
            }
            auth::ScramAlgorithm::Sha1 => {
                "SELECT id,auth_generation,is_disabled,
                        scram_sha1_salt AS salt,
                        scram_sha1_iterations AS iterations,
                        scram_sha1_stored_key AS stored_key,
                        scram_sha1_server_key AS server_key
                   FROM users WHERE username=$1"
            }
        };
        let row = match sqlx::query(query)
            .bind(username)
            .fetch_optional(&self.pool)
            .await
        {
            Ok(Some(row)) => row,
            Ok(None) => return AuthenticationResult::UnknownCredentials,
            Err(error) => return AuthenticationResult::BackendFailure(error.into()),
        };
        let disabled = match row.try_get::<bool, _>("is_disabled") {
            Ok(disabled) => disabled,
            Err(error) => return AuthenticationResult::BackendFailure(error.into()),
        };
        if disabled {
            return AuthenticationResult::Disabled;
        }
        let values = (
            row.try_get::<Option<Vec<u8>>, _>("salt")
                .map(|value| value.map(Zeroizing::new)),
            row.try_get::<Option<i32>, _>("iterations"),
            row.try_get::<Option<Vec<u8>>, _>("stored_key")
                .map(|value| value.map(Zeroizing::new)),
            row.try_get::<Option<Vec<u8>>, _>("server_key")
                .map(|value| value.map(Zeroizing::new)),
        );
        let (mut salt, iterations, mut stored_key, mut server_key) = match values {
            (Ok(Some(salt)), Ok(Some(iterations)), Ok(Some(stored_key)), Ok(Some(server_key))) => {
                (salt, iterations, stored_key, server_key)
            }
            (Ok(None), Ok(None), Ok(None), Ok(None)) => {
                return AuthenticationResult::UnknownCredentials;
            }
            (Err(error), _, _, _)
            | (_, Err(error), _, _)
            | (_, _, Err(error), _)
            | (_, _, _, Err(error)) => {
                return AuthenticationResult::BackendFailure(error.into());
            }
            _ => {
                return AuthenticationResult::BackendFailure(anyhow::anyhow!(
                    "stored SCRAM verifier is incomplete"
                ));
            }
        };
        let iterations = match u32::try_from(iterations) {
            Ok(iterations)
                if (auth::MIN_SCRAM_ITERATIONS..=auth::MAX_SCRAM_ITERATIONS)
                    .contains(&iterations)
                    && !salt.is_empty()
                    && stored_key.len() == algorithm.key_len()
                    && server_key.len() == algorithm.key_len() =>
            {
                iterations
            }
            _ => {
                return AuthenticationResult::BackendFailure(anyhow::anyhow!(
                    "stored SCRAM verifier is invalid"
                ));
            }
        };
        let fence = match (
            row.try_get::<Uuid, _>("id"),
            row.try_get::<i64, _>("auth_generation"),
        ) {
            (Ok(user_id), Ok(auth_generation)) => AuthenticationFence {
                user_id,
                auth_generation,
            },
            (Err(error), _) | (_, Err(error)) => {
                return AuthenticationResult::BackendFailure(error.into());
            }
        };
        AuthenticationResult::Authenticated(ScramCredentialSet::from_verifier(
            fence,
            std::mem::take(&mut *salt),
            iterations,
            std::mem::take(&mut *stored_key),
            std::mem::take(&mut *server_key),
        ))
    }
    async fn authenticate_plain(
        &self,
        username: &str,
        password: &str,
        policy: AuthenticationPolicy,
    ) -> AuthenticationResult<AuthenticatedAccount> {
        self.authenticate_plain_with_hook(username, password, policy, |_| async {})
            .await
    }
    async fn account_by_id(&self, user_id: Uuid) -> anyhow::Result<Option<LoadedAccount>> {
        load_sanitized_user_by_id(&self.pool, user_id).await
    }
    async fn account_by_username(&self, username: &str) -> anyhow::Result<Option<LoadedAccount>> {
        load_sanitized_user_by_username(&self.pool, username).await
    }
    async fn generation_state(&self, fence: AuthenticationFence) -> AuthenticationResult<()> {
        let mut transaction = match self.pool.begin().await {
            Ok(transaction) => transaction,
            Err(error) => return AuthenticationResult::BackendFailure(error.into()),
        };
        let result = self
            .classify_exact_account_state_in_transaction(&mut transaction, fence)
            .await;
        match transaction.rollback().await {
            Ok(()) => result,
            Err(error) => AuthenticationResult::BackendFailure(error.into()),
        }
    }
    async fn bind2_archive_boundaries(
        &self,
        user_id: Uuid,
        expected_auth_generation: i64,
    ) -> AuthenticationResult<(Option<ArchiveBoundary>, Option<ArchiveBoundary>)> {
        self.bind2_archive_boundaries_with_hook(user_id, expected_auth_generation, |_| async {})
            .await
    }
    async fn authenticate_fast(
        &self,
        request: FastProofRequest<'_>,
    ) -> AuthenticationResult<FastAuthenticationSuccess> {
        self.authenticate_fast_with_hook(request, |_| async {})
            .await
    }
    async fn commit_fast_with_login_epoch(
        &self,
        user_id: Uuid,
        expected_auth_generation: i64,
        plan: &FastCommitPlan,
        device_id: Option<Uuid>,
        connection_id: Uuid,
    ) -> AuthenticationResult<CredentialCommitReceipt> {
        let db_plan = db::FastCommitPlan::from(plan);
        let mut tx =
            match db::lock_auth_generation(&self.pool, user_id, expected_auth_generation).await {
                Ok(Some(tx)) => tx,
                Ok(None) => return AuthenticationResult::ExpiredCredentials,
                Err(error) => return AuthenticationResult::BackendFailure(error),
            };
        let staged = match stage_login_epoch_in_transaction(
            &mut tx,
            user_id,
            device_id,
            expected_auth_generation,
            connection_id,
        )
        .await
        {
            Ok(staged) => staged,
            Err(error) => return AuthenticationResult::BackendFailure(error),
        };
        let issued = match db::commit_fast_state_in_transaction(
            &mut tx,
            self.fast_token_secret.as_slice(),
            user_id,
            expected_auth_generation,
            &db_plan,
        )
        .await
        {
            Ok(db::FastCommitOutcome::Committed(issued)) => issued,
            Ok(db::FastCommitOutcome::CredentialsExpired) => {
                let _ = tx.rollback().await;
                return AuthenticationResult::ExpiredCredentials;
            }
            Err(error) => return AuthenticationResult::BackendFailure(error),
        };
        match tx.commit().await {
            Ok(()) => AuthenticationResult::Authenticated(CredentialCommitReceipt::new(
                issued.map(IssuedFastToken::from),
                staged,
                None,
            )),
            Err(error) => AuthenticationResult::BackendFailure(error.into()),
        }
    }
    async fn publish_credential_commit(
        &self,
        receipt: &CredentialCommitReceipt,
    ) -> AuthenticationResult<Option<i64>> {
        if receipt.staged_login_epoch().is_none() && receipt.binding_publication().is_none() {
            return AuthenticationResult::Authenticated(None);
        }
        let mut tx = match self.pool.begin().await {
            Ok(tx) => tx,
            Err(error) => return AuthenticationResult::BackendFailure(error.into()),
        };
        // Take the user/generation and operation locks before capacity rows,
        // matching phase-two finalization. If the binding transfer fails, the
        // epoch publication and claim consumption roll back with it.
        let published_epoch = if let Some(stage) = receipt.staged_login_epoch() {
            match db::publish_user_agent_login_epoch_in_transaction(
                &mut tx,
                stage.operation_id,
                stage.connection_id,
                stage.user_id,
                stage.device_id,
                stage.auth_generation,
                receipt.binding_publication().is_some(),
            )
            .await
            {
                Ok(Some(epoch)) => Some(epoch),
                Ok(None) => {
                    let _ = tx.rollback().await;
                    return AuthenticationResult::ExpiredCredentials;
                }
                Err(error) => return AuthenticationResult::BackendFailure(error),
            }
        } else {
            None
        };
        if let Some(binding) = receipt.binding_publication() {
            match db::publish_binding_live_session_in_transaction(
                &mut tx,
                binding.connection_id,
                binding.user_id,
                &binding.full_jid,
                binding.lease_seconds,
            )
            .await
            {
                Ok(true) => {}
                Ok(false) => {
                    let _ = tx.rollback().await;
                    return AuthenticationResult::ExpiredCredentials;
                }
                Err(error) => return AuthenticationResult::BackendFailure(error),
            }
        }
        match tx.commit().await {
            Ok(()) => AuthenticationResult::Authenticated(published_epoch),
            Err(error) => AuthenticationResult::BackendFailure(error.into()),
        }
    }
}
pub(crate) async fn stage_login_epoch_in_transaction(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    user_id: Uuid,
    device_id: Option<Uuid>,
    auth_generation: i64,
    connection_id: Uuid,
) -> anyhow::Result<Option<StagedLoginEpoch>> {
    let Some(device_id) = device_id else {
        return Ok(None);
    };
    let operation_id = Uuid::new_v4();
    let Some(epoch) = db::stage_user_agent_login_epoch_in_transaction(
        tx,
        user_id,
        device_id,
        auth_generation,
        connection_id,
        operation_id,
        LOGIN_EPOCH_STAGE_TTL_SECONDS,
    )
    .await?
    else {
        return Ok(None);
    };
    Ok(Some(StagedLoginEpoch {
        operation_id,
        connection_id,
        user_id,
        device_id,
        auth_generation,
        epoch,
    }))
}
async fn load_sanitized_user_by_username(
    pool: &PgPool,
    username: &str,
) -> anyhow::Result<Option<LoadedAccount>> {
    let row = sqlx::query(
        "SELECT id,username,is_disabled,auth_generation
           FROM users WHERE username=$1",
    )
    .bind(username)
    .fetch_optional(pool)
    .await?;
    row.as_ref().map(sanitized_user_from_row).transpose()
}

async fn load_sanitized_user_by_id(
    pool: &PgPool,
    user_id: Uuid,
) -> anyhow::Result<Option<LoadedAccount>> {
    let row = sqlx::query(
        "SELECT id,username,is_disabled,auth_generation
           FROM users WHERE id=$1",
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await?;
    row.as_ref().map(sanitized_user_from_row).transpose()
}

async fn load_sanitized_user_by_username_in_transaction(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    username: &str,
) -> anyhow::Result<Option<LoadedAccount>> {
    let row = sqlx::query(
        "SELECT id,username,is_disabled,auth_generation
           FROM users WHERE username=$1 FOR SHARE",
    )
    .bind(username)
    .fetch_optional(&mut **transaction)
    .await?;
    row.as_ref().map(sanitized_user_from_row).transpose()
}

fn sanitized_user_from_row(row: &sqlx::postgres::PgRow) -> anyhow::Result<LoadedAccount> {
    Ok(LoadedAccount {
        account: AuthenticatedAccount {
            id: row.try_get("id")?,
            username: row.try_get("username")?,
            auth_generation: row.try_get("auth_generation")?,
        },
        is_disabled: row.try_get("is_disabled")?,
    })
}

fn sanitized_user(user: &db::User) -> AuthenticatedAccount {
    AuthenticatedAccount {
        id: user.id,
        username: user.username.clone(),
        auth_generation: user.auth_generation,
    }
}

impl From<db::IssuedFastToken> for IssuedFastToken {
    fn from(issued: db::IssuedFastToken) -> Self {
        Self {
            token: issued.token,
            expires_at: issued.expires_at,
        }
    }
}
impl From<db::FastTokenIssue> for FastTokenIssue {
    fn from(issue: db::FastTokenIssue) -> Self {
        Self {
            device_id: issue.device_id,
            mechanism: issue.mechanism,
            ttl_days: issue.ttl_days,
            strong_reauth_max_days: issue.strong_reauth_max_days,
            inherited_chain: issue.inherited_chain,
        }
    }
}
impl From<FastTokenIssue> for db::FastTokenIssue {
    fn from(issue: FastTokenIssue) -> Self {
        Self {
            device_id: issue.device_id,
            mechanism: issue.mechanism,
            ttl_days: issue.ttl_days,
            strong_reauth_max_days: issue.strong_reauth_max_days,
            inherited_chain: issue.inherited_chain,
        }
    }
}
impl From<&FastTokenIssue> for db::FastTokenIssue {
    fn from(issue: &FastTokenIssue) -> Self {
        Self {
            device_id: issue.device_id,
            mechanism: issue.mechanism.clone(),
            ttl_days: issue.ttl_days,
            strong_reauth_max_days: issue.strong_reauth_max_days,
            inherited_chain: issue.inherited_chain,
        }
    }
}
impl From<db::FastCommitPlan> for FastCommitPlan {
    fn from(plan: db::FastCommitPlan) -> Self {
        Self {
            token_id: plan.token_id,
            token_was_new: plan.token_was_new,
            invalidate: plan.invalidate,
            issue: plan.issue.map(Into::into),
        }
    }
}
impl From<FastCommitPlan> for db::FastCommitPlan {
    fn from(plan: FastCommitPlan) -> Self {
        Self {
            token_id: plan.token_id,
            token_was_new: plan.token_was_new,
            invalidate: plan.invalidate,
            issue: plan.issue.map(Into::into),
        }
    }
}
impl From<&FastCommitPlan> for db::FastCommitPlan {
    fn from(plan: &FastCommitPlan) -> Self {
        Self {
            token_id: plan.token_id,
            token_was_new: plan.token_was_new,
            invalidate: plan.invalidate,
            issue: plan.issue.as_ref().map(Into::into),
        }
    }
}
