//! Database and credential boundary for legacy SASL, SASL2 and XEP-0484.
//!
//! Protocol handlers keep the wire state machine, but never receive a
//! PostgreSQL capability or the FAST derivation secret. Every successful
//! identity is fenced to an exact account UUID and credential generation.

use crate::{auth, db};
use sqlx::{PgPool, Row};
use std::future::Future;
use std::sync::Arc;
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct AuthenticationFence {
    pub(crate) user_id: Uuid,
    pub(crate) auth_generation: i64,
}

/// Least-authority identity installed into an authenticated XMPP session.
/// Reusable password/SCRAM verifier material is structurally absent rather
/// than copied and blanked after crossing the service boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AuthenticatedAccount {
    pub(crate) id: Uuid,
    pub(crate) username: String,
    pub(crate) auth_generation: i64,
}

struct LoadedAccount {
    account: AuthenticatedAccount,
    is_disabled: bool,
}

#[derive(Debug)]
pub(crate) enum AuthenticationResult<T> {
    Authenticated(T),
    UnknownCredentials,
    Disabled,
    StaleGeneration,
    ExpiredCredentials,
    ReplayedCredentials,
    IntegrityFailure,
    BackendFailure(anyhow::Error),
}

/// SCRAM verifier material exists only between the bounded database read and
/// transfer into the per-connection mechanism. Both owners zeroize it.
pub(crate) struct ScramCredentialSet {
    fence: AuthenticationFence,
    salt: Vec<u8>,
    iterations: u32,
    stored_key: Vec<u8>,
    server_key: Vec<u8>,
}

impl std::fmt::Debug for ScramCredentialSet {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ScramCredentialSet")
            .field("fence", &self.fence)
            .field("iterations", &self.iterations)
            .field("salt_bytes", &self.salt.len())
            .field("stored_key_bytes", &self.stored_key.len())
            .field("server_key_bytes", &self.server_key.len())
            .finish()
    }
}

impl Drop for ScramCredentialSet {
    fn drop(&mut self) {
        self.salt.zeroize();
        self.stored_key.zeroize();
        self.server_key.zeroize();
    }
}

impl ScramCredentialSet {
    #[cfg(test)]
    fn fence(&self) -> AuthenticationFence {
        self.fence
    }

    pub(crate) fn into_mechanism_parts(
        mut self,
    ) -> (AuthenticationFence, Vec<u8>, u32, Vec<u8>, Vec<u8>) {
        (
            self.fence,
            std::mem::take(&mut self.salt),
            self.iterations,
            std::mem::take(&mut self.stored_key),
            std::mem::take(&mut self.server_key),
        )
    }
}

pub(crate) struct FastProofRequest<'a> {
    pub(crate) username: &'a str,
    pub(crate) device_id: Uuid,
    pub(crate) mechanism: &'a str,
    pub(crate) counter: Option<i64>,
    pub(crate) initiator_proof: &'a [u8],
    pub(crate) channel_binding: &'a [u8],
    pub(crate) invalidate: bool,
    pub(crate) rotate_within_days: i64,
}

pub(crate) struct FastAuthenticationSuccess {
    user: AuthenticatedAccount,
    responder: Zeroizing<Vec<u8>>,
    should_rotate: bool,
    token_id: Uuid,
    token_was_new: bool,
    auth_generation: i64,
    strong_auth_at: chrono::DateTime<chrono::Utc>,
    chain_expires_at: chrono::DateTime<chrono::Utc>,
}

impl FastAuthenticationSuccess {
    #[allow(clippy::type_complexity)]
    pub(crate) fn into_parts(
        self,
    ) -> (
        AuthenticatedAccount,
        Zeroizing<Vec<u8>>,
        bool,
        Uuid,
        bool,
        i64,
        chrono::DateTime<chrono::Utc>,
        chrono::DateTime<chrono::Utc>,
    ) {
        let Self {
            user,
            responder,
            should_rotate,
            token_id,
            token_was_new,
            auth_generation,
            strong_auth_at,
            chain_expires_at,
        } = self;
        (
            user,
            responder,
            should_rotate,
            token_id,
            token_was_new,
            auth_generation,
            strong_auth_at,
            chain_expires_at,
        )
    }
}

pub(crate) struct IssuedFastToken {
    pub(crate) token: Zeroizing<String>,
    pub(crate) expires_at: chrono::DateTime<chrono::Utc>,
}

impl std::fmt::Debug for IssuedFastToken {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("IssuedFastToken")
            .field("token", &"[REDACTED]")
            .field("expires_at", &self.expires_at)
            .finish()
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

const LOGIN_EPOCH_STAGE_TTL_SECONDS: u64 = 120;

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) struct StagedLoginEpoch {
    pub(crate) operation_id: Uuid,
    pub(crate) connection_id: Uuid,
    pub(crate) user_id: Uuid,
    pub(crate) device_id: Uuid,
    pub(crate) auth_generation: i64,
    pub(crate) epoch: i64,
}

impl std::fmt::Debug for StagedLoginEpoch {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("StagedLoginEpoch")
            .field("operation_id", &self.operation_id)
            .field("connection_id", &self.connection_id)
            .field("user_id", &self.user_id)
            .field("device_id", &self.device_id)
            .field("auth_generation", &self.auth_generation)
            .field("epoch", &self.epoch)
            .finish()
    }
}

/// Durable proof that FAST side effects committed. The issued bearer can be
/// consumed exactly once for the SASL2 success XML; the staged login epoch is
/// published only by the transport-success callback.
pub(crate) struct CredentialCommitReceipt {
    issued_fast: Option<IssuedFastToken>,
    staged_login_epoch: Option<StagedLoginEpoch>,
    binding_publication: Option<BindingPublication>,
}

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct BindingPublication {
    pub(crate) connection_id: Uuid,
    pub(crate) user_id: Uuid,
    pub(crate) full_jid: String,
    pub(crate) lease_seconds: u64,
}

impl std::fmt::Debug for BindingPublication {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BindingPublication")
            .field("connection_id", &self.connection_id)
            .field("user_id", &self.user_id)
            .field("full_jid", &self.full_jid)
            .field("lease_seconds", &self.lease_seconds)
            .finish()
    }
}

impl std::fmt::Debug for CredentialCommitReceipt {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CredentialCommitReceipt")
            .field(
                "issued_fast",
                &self.issued_fast.as_ref().map(|_| "[REDACTED]"),
            )
            .field("staged_login_epoch", &self.staged_login_epoch)
            .field("binding_publication", &self.binding_publication)
            .finish()
    }
}

impl CredentialCommitReceipt {
    pub(crate) fn new(
        issued_fast: Option<IssuedFastToken>,
        staged_login_epoch: Option<StagedLoginEpoch>,
        binding_publication: Option<BindingPublication>,
    ) -> Self {
        Self {
            issued_fast,
            staged_login_epoch,
            binding_publication,
        }
    }

    pub(crate) fn take_issued_fast(&mut self) -> Option<IssuedFastToken> {
        self.issued_fast.take()
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct FastTokenIssue {
    pub(crate) device_id: Uuid,
    pub(crate) mechanism: String,
    pub(crate) ttl_days: i64,
    pub(crate) strong_reauth_max_days: i64,
    pub(crate) inherited_chain:
        Option<(chrono::DateTime<chrono::Utc>, chrono::DateTime<chrono::Utc>)>,
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

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct FastCommitPlan {
    pub(crate) token_id: Option<Uuid>,
    pub(crate) token_was_new: bool,
    pub(crate) invalidate: bool,
    pub(crate) issue: Option<FastTokenIssue>,
}

#[cfg(test)]
impl FastCommitPlan {
    pub(crate) fn to_db(&self) -> db::FastCommitPlan {
        self.into()
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

#[derive(Clone)]
pub(crate) struct AuthenticationService {
    pool: PgPool,
    fast_token_secret: Arc<Zeroizing<Vec<u8>>>,
    dummy_scram_secret: Arc<Zeroizing<Vec<u8>>>,
    scram_iterations: u32,
    dummy_scram_iteration_profiles: Arc<[u32]>,
    scram_sha1_enabled: bool,
}

impl AuthenticationService {
    #[cfg(test)]
    pub(crate) fn new(
        pool: PgPool,
        fast_token_secret: Arc<Zeroizing<Vec<u8>>>,
        dummy_scram_secret: Arc<Zeroizing<Vec<u8>>>,
        scram_iterations: u32,
        scram_sha1_enabled: bool,
    ) -> Self {
        Self::new_with_dummy_scram_iteration_profiles(
            pool,
            fast_token_secret,
            dummy_scram_secret,
            scram_iterations,
            vec![auth::MIN_SCRAM_ITERATIONS, scram_iterations],
            scram_sha1_enabled,
        )
    }

    pub(crate) fn new_with_dummy_scram_iteration_profiles(
        pool: PgPool,
        fast_token_secret: Arc<Zeroizing<Vec<u8>>>,
        dummy_scram_secret: Arc<Zeroizing<Vec<u8>>>,
        scram_iterations: u32,
        mut dummy_scram_iteration_profiles: Vec<u32>,
        scram_sha1_enabled: bool,
    ) -> Self {
        dummy_scram_iteration_profiles.sort_unstable();
        dummy_scram_iteration_profiles.dedup();
        assert!(
            !dummy_scram_iteration_profiles.is_empty()
                && dummy_scram_iteration_profiles.iter().all(|iterations| {
                    (auth::MIN_SCRAM_ITERATIONS..=auth::MAX_SCRAM_ITERATIONS).contains(iterations)
                }),
            "dummy SCRAM iteration profiles are validated at startup"
        );
        Self {
            pool,
            fast_token_secret,
            dummy_scram_secret,
            scram_iterations,
            dummy_scram_iteration_profiles: Arc::from(
                dummy_scram_iteration_profiles.into_boxed_slice(),
            ),
            scram_sha1_enabled,
        }
    }

    /// Return deployment-keyed dummy SCRAM material for an unknown or
    /// disabled account. Keeping selection and derivation behind this service
    /// prevents protocol handlers from ever receiving the master secret.
    pub(crate) fn dummy_scram_credentials(
        &self,
        username: &str,
        algorithm: auth::ScramAlgorithm,
    ) -> (Vec<u8>, u32, Vec<u8>, Vec<u8>) {
        let iterations = auth::dummy_scram_iterations(
            self.dummy_scram_secret.as_slice(),
            username,
            algorithm,
            &self.dummy_scram_iteration_profiles,
        );
        let (salt, stored_key, server_key) = auth::dummy_scram_credentials(
            self.dummy_scram_secret.as_slice(),
            username,
            algorithm,
            iterations,
        );
        (salt, iterations, stored_key, server_key)
    }

    pub(crate) async fn scram_credentials(
        &self,
        username: &str,
        algorithm: auth::ScramAlgorithm,
    ) -> AuthenticationResult<ScramCredentialSet> {
        if algorithm == auth::ScramAlgorithm::Sha1 && !self.scram_sha1_enabled {
            return AuthenticationResult::UnknownCredentials;
        }
        let username = match auth::normalize_username(username) {
            Ok(username) => username,
            Err(_) => return AuthenticationResult::UnknownCredentials,
        };
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
        AuthenticationResult::Authenticated(ScramCredentialSet {
            fence,
            salt: std::mem::take(&mut *salt),
            iterations,
            stored_key: std::mem::take(&mut *stored_key),
            server_key: std::mem::take(&mut *server_key),
        })
    }

    pub(crate) async fn authenticate_plain(
        &self,
        username: &str,
        password: &str,
    ) -> AuthenticationResult<AuthenticatedAccount> {
        self.authenticate_plain_with_hook(username, password, |_| async {})
            .await
    }

    async fn authenticate_plain_with_hook<F, Fut>(
        &self,
        username: &str,
        password: &str,
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
            self.scram_iterations,
            self.scram_sha1_enabled,
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

    pub(crate) async fn complete_scram(
        &self,
        username: &str,
        fence: Option<AuthenticationFence>,
    ) -> AuthenticationResult<AuthenticatedAccount> {
        let Some(fence) = fence else {
            return AuthenticationResult::UnknownCredentials;
        };
        let username = match auth::normalize_username(username) {
            Ok(username) => username,
            Err(_) => return AuthenticationResult::UnknownCredentials,
        };
        match load_sanitized_user_by_id(&self.pool, fence.user_id).await {
            Ok(Some(user)) if user.is_disabled => AuthenticationResult::Disabled,
            Ok(Some(user))
                if user.account.username != username
                    || user.account.auth_generation != fence.auth_generation =>
            {
                AuthenticationResult::StaleGeneration
            }
            Ok(Some(user)) => AuthenticationResult::Authenticated(user.account),
            Ok(None) => AuthenticationResult::StaleGeneration,
            Err(error) => AuthenticationResult::BackendFailure(error),
        }
    }

    pub(crate) async fn authenticate_external(
        &self,
        username: &str,
    ) -> AuthenticationResult<AuthenticatedAccount> {
        let username = match auth::normalize_username(username) {
            Ok(username) => username,
            Err(_) => return AuthenticationResult::UnknownCredentials,
        };
        match load_sanitized_user_by_username(&self.pool, &username).await {
            Ok(Some(user)) if user.is_disabled => AuthenticationResult::Disabled,
            Ok(Some(user)) => AuthenticationResult::Authenticated(user.account),
            Ok(None) => AuthenticationResult::UnknownCredentials,
            Err(error) => AuthenticationResult::BackendFailure(error),
        }
    }

    pub(crate) async fn revalidate_generation(
        &self,
        user_id: Uuid,
        expected_auth_generation: i64,
    ) -> AuthenticationResult<()> {
        self.classify_exact_account_state(AuthenticationFence {
            user_id,
            auth_generation: expected_auth_generation,
        })
        .await
    }

    pub(crate) async fn bind2_archive_boundaries(
        &self,
        user_id: Uuid,
        expected_auth_generation: i64,
    ) -> AuthenticationResult<(Option<db::ArchiveBoundary>, Option<db::ArchiveBoundary>)> {
        self.bind2_archive_boundaries_with_hook(user_id, expected_auth_generation, |_| async {})
            .await
    }

    async fn bind2_archive_boundaries_with_hook<F, Fut>(
        &self,
        user_id: Uuid,
        expected_auth_generation: i64,
        after_account_locked: F,
    ) -> AuthenticationResult<(Option<db::ArchiveBoundary>, Option<db::ArchiveBoundary>)>
    where
        F: FnOnce(AuthenticationFence) -> Fut,
        Fut: Future<Output = ()>,
    {
        let mut transaction = match self.pool.begin().await {
            Ok(transaction) => transaction,
            Err(error) => return AuthenticationResult::BackendFailure(error.into()),
        };
        if let Err(error) = sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
            .execute(&mut *transaction)
            .await
        {
            return AuthenticationResult::BackendFailure(error.into());
        }
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

    pub(crate) async fn authenticate_fast(
        &self,
        request: FastProofRequest<'_>,
    ) -> AuthenticationResult<FastAuthenticationSuccess> {
        self.authenticate_fast_with_hook(request, |_| async {})
            .await
    }

    async fn authenticate_fast_with_hook<F, Fut>(
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
        AuthenticationResult::Authenticated(FastAuthenticationSuccess {
            user,
            responder,
            should_rotate,
            token_id: id,
            token_was_new: was_new,
            auth_generation,
            strong_auth_at,
            chain_expires_at,
        })
    }

    pub(crate) async fn commit_fast_with_login_epoch(
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

    pub(crate) async fn publish_credential_commit(
        &self,
        receipt: &CredentialCommitReceipt,
    ) -> AuthenticationResult<Option<i64>> {
        if receipt.staged_login_epoch.is_none() && receipt.binding_publication.is_none() {
            return AuthenticationResult::Authenticated(None);
        }
        let mut tx = match self.pool.begin().await {
            Ok(tx) => tx,
            Err(error) => return AuthenticationResult::BackendFailure(error.into()),
        };
        // Take the user/generation and operation locks before capacity rows,
        // matching phase-two finalization. If the binding transfer fails, the
        // epoch publication and claim consumption roll back with it.
        let published_epoch = if let Some(stage) = receipt.staged_login_epoch {
            match db::publish_user_agent_login_epoch_in_transaction(
                &mut tx,
                stage.operation_id,
                stage.connection_id,
                stage.user_id,
                stage.device_id,
                stage.auth_generation,
                receipt.binding_publication.is_some(),
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
        if let Some(binding) = receipt.binding_publication.as_ref() {
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

    async fn classify_exact_account_state(
        &self,
        fence: AuthenticationFence,
    ) -> AuthenticationResult<()> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::sync::oneshot;

    #[tokio::test]
    async fn dummy_scram_identity_is_independent_from_fast_key_rotation() {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://unused:unused@127.0.0.1/unused")
            .unwrap();
        let make_service = |fast_byte, dummy_byte| {
            AuthenticationService::new(
                pool.clone(),
                Arc::new(Zeroizing::new(vec![fast_byte; 32])),
                Arc::new(Zeroizing::new(vec![dummy_byte; 32])),
                auth::MIN_SCRAM_ITERATIONS,
                false,
            )
        };
        let before = make_service(0x11, 0xa5)
            .dummy_scram_credentials("missing-account", auth::ScramAlgorithm::Sha256);
        let after_fast_rotation = make_service(0x22, 0xa5)
            .dummy_scram_credentials("missing-account", auth::ScramAlgorithm::Sha256);
        let after_dummy_rotation = make_service(0x22, 0xa6)
            .dummy_scram_credentials("missing-account", auth::ScramAlgorithm::Sha256);
        assert_eq!(before, after_fast_rotation);
        assert_ne!(before, after_dummy_rotation);
    }

    async fn isolated_pool() -> PgPool {
        let url = std::env::var("TEST_DATABASE_URL")
            .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(4)
            .acquire_timeout(Duration::from_secs(60))
            .connect(&url)
            .await
            .unwrap();
        let schema: String = sqlx::query_scalar("SELECT current_schema()")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert!(
            schema.starts_with("northstar_authentication_it_") && schema.len() <= 63,
            "authentication DB test refuses non-isolated schema {schema}"
        );
        eprintln!("isolated_schema={schema}");
        crate::db::migrate(&pool).await.unwrap();
        pool
    }

    async fn create_account(pool: &PgPool, username: &str, password: &str) -> (Uuid, i64) {
        let mut user = db::create_user(
            pool,
            username,
            password,
            false,
            false,
            auth::MIN_SCRAM_ITERATIONS,
            false,
        )
        .await
        .unwrap();
        let identity = (user.id, user.auth_generation);
        user.password_hash.zeroize();
        user.password_hash.clear();
        identity
    }

    async fn reserve_test_live_session(
        pool: &PgPool,
        connection_id: Uuid,
        user_id: Uuid,
        auth_generation: i64,
        full_jid: &str,
    ) {
        let mut tx = db::lock_auth_generation(pool, user_id, auth_generation)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            db::reserve_live_session_in_transaction(
                &mut tx,
                connection_id,
                user_id,
                full_jid,
                120,
                false,
            )
            .await
            .unwrap(),
            db::LiveSessionReservation::Reserved
        );
        tx.commit().await.unwrap();
    }

    #[tokio::test]
    #[ignore = "requires TEST_DATABASE_URL; creates and removes a random isolated schema"]
    async fn authentication_service_fences_all_credential_and_inline_state_transitions() {
        let pool = isolated_pool().await;
        let fast_secret = Arc::new(Zeroizing::new(vec![0x5a; 32]));
        let service = AuthenticationService::new(
            pool.clone(),
            Arc::clone(&fast_secret),
            Arc::new(Zeroizing::new(vec![0xa5; 32])),
            auth::MIN_SCRAM_ITERATIONS,
            false,
        );

        let alice = format!("auth-alice-{}", &Uuid::new_v4().simple().to_string()[..10]);
        let (alice_id, _) = create_account(&pool, &alice, "old correct horse battery").await;
        let prepared_debug = db::prepare_login(
            &pool,
            &alice,
            "old correct horse battery",
            auth::MIN_SCRAM_ITERATIONS,
            false,
        )
        .await
        .unwrap()
        .expect("valid password must prepare a login");
        let prepared_debug_text = format!("{prepared_debug:?}");
        assert!(prepared_debug_text.contains("[REDACTED]"));
        assert!(!prepared_debug_text.contains("$argon2"));
        assert!(!prepared_debug_text.contains("old correct horse battery"));
        drop(prepared_debug);
        let plain_user = match service
            .authenticate_plain(&alice, "old correct horse battery")
            .await
        {
            AuthenticationResult::Authenticated(user) => user,
            _ => panic!("valid PLAIN credentials were rejected"),
        };
        assert_eq!(plain_user.id, alice_id);

        // Compatibility-off accounts never gain a SHA-1 verifier, and the
        // AuthenticationService cannot retrieve one even if the protocol asks.
        type OptionalSha1VerifierColumns = (
            Option<Vec<u8>>,
            Option<i32>,
            Option<Vec<u8>>,
            Option<Vec<u8>>,
        );
        let sha1_columns: OptionalSha1VerifierColumns = sqlx::query_as(
            "SELECT scram_sha1_salt,scram_sha1_iterations,
                        scram_sha1_stored_key,scram_sha1_server_key
                   FROM users WHERE id=$1",
        )
        .bind(alice_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(matches!(sha1_columns, (None, None, None, None)));
        assert!(matches!(
            service
                .scram_credentials(&alice, auth::ScramAlgorithm::Sha1)
                .await,
            AuthenticationResult::UnknownCredentials
        ));

        // A completed SCRAM proof remains tied to the UUID/generation whose
        // verifier produced it. Deleting and recreating the same username must
        // not let that proof authenticate the replacement account.
        let old_scram_fence = match service
            .scram_credentials(&alice, auth::ScramAlgorithm::Sha256)
            .await
        {
            AuthenticationResult::Authenticated(credentials) => credentials.fence(),
            _ => panic!("SCRAM-SHA-256 verifier was unavailable"),
        };
        sqlx::query("DELETE FROM users WHERE id=$1")
            .bind(alice_id)
            .execute(&pool)
            .await
            .unwrap();
        let (replacement_id, _) =
            create_account(&pool, &alice, "replacement correct horse battery").await;
        assert_ne!(replacement_id, old_scram_fence.user_id);
        assert!(matches!(
            service.complete_scram(&alice, Some(old_scram_fence)).await,
            AuthenticationResult::StaleGeneration
        ));

        // Password verification happens outside a database transaction, then
        // apply_prepared_login rechecks UUID/hash/generation under lock. Force
        // a rotation in that window and prove the old password cannot commit.
        let bob = format!("auth-bob-{}", &Uuid::new_v4().simple().to_string()[..10]);
        let (bob_id, _) = create_account(&pool, &bob, "bob old correct horse battery").await;
        let (verified_tx, verified_rx) = oneshot::channel();
        let (release_tx, release_rx) = oneshot::channel();
        let plain_service = service.clone();
        let plain_username = bob.clone();
        let plain_attempt = tokio::spawn(async move {
            plain_service
                .authenticate_plain_with_hook(
                    &plain_username,
                    "bob old correct horse battery",
                    move |fence| async move {
                        verified_tx.send(fence).unwrap();
                        release_rx.await.unwrap();
                    },
                )
                .await
        });
        let prepared_fence = verified_rx.await.unwrap();
        assert_eq!(prepared_fence.user_id, bob_id);
        db::change_password(
            &pool,
            bob_id,
            "bob new correct horse battery",
            auth::MIN_SCRAM_ITERATIONS,
            false,
        )
        .await
        .unwrap();
        release_tx.send(()).unwrap();
        assert!(matches!(
            plain_attempt.await.unwrap(),
            AuthenticationResult::StaleGeneration
        ));
        let bob_session = match service
            .authenticate_plain(&bob, "bob new correct horse battery")
            .await
        {
            AuthenticationResult::Authenticated(user) => user,
            _ => panic!("rotated PLAIN credential was rejected"),
        };
        assert_eq!(bob_session.id, bob_id);

        // Disabling an account in the same post-verification window is
        // distinguished internally while remaining a generic wire failure.
        let carol = format!("auth-carol-{}", &Uuid::new_v4().simple().to_string()[..10]);
        let (carol_id, _) = create_account(&pool, &carol, "carol correct horse battery").await;
        let (verified_tx, verified_rx) = oneshot::channel();
        let (release_tx, release_rx) = oneshot::channel();
        let disabled_service = service.clone();
        let disabled_username = carol.clone();
        let disabled_attempt = tokio::spawn(async move {
            disabled_service
                .authenticate_plain_with_hook(
                    &disabled_username,
                    "carol correct horse battery",
                    move |fence| async move {
                        verified_tx.send(fence).unwrap();
                        release_rx.await.unwrap();
                    },
                )
                .await
        });
        verified_rx.await.unwrap();
        sqlx::query(
            "UPDATE users SET is_disabled=TRUE,auth_generation=auth_generation+1 WHERE id=$1",
        )
        .bind(carol_id)
        .execute(&pool)
        .await
        .unwrap();
        release_tx.send(()).unwrap();
        assert!(matches!(
            disabled_attempt.await.unwrap(),
            AuthenticationResult::Disabled
        ));

        // Bind 2 locks the exact generation and reads privacy-filtered MAM
        // boundaries inside that same RR transaction. A concurrent generation
        // update cannot commit in the former check/read gap.
        let bob_generation: i64 =
            sqlx::query_scalar("SELECT auth_generation FROM users WHERE id=$1")
                .bind(bob_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        let (locked_tx, locked_rx) = oneshot::channel();
        let (release_tx, release_rx) = oneshot::channel();
        let boundary_service = service.clone();
        let boundary_attempt = tokio::spawn(async move {
            boundary_service
                .bind2_archive_boundaries_with_hook(
                    bob_id,
                    bob_generation,
                    move |fence| async move {
                        locked_tx.send(fence).unwrap();
                        release_rx.await.unwrap();
                    },
                )
                .await
        });
        locked_rx.await.unwrap();
        let update_pool = pool.clone();
        let mut generation_update = tokio::spawn(async move {
            sqlx::query("UPDATE users SET auth_generation=auth_generation+1 WHERE id=$1")
                .bind(bob_id)
                .execute(&update_pool)
                .await
                .unwrap();
        });
        assert!(
            tokio::time::timeout(Duration::from_millis(100), &mut generation_update)
                .await
                .is_err()
        );
        release_tx.send(()).unwrap();
        assert!(matches!(
            boundary_attempt.await.unwrap(),
            AuthenticationResult::Authenticated((None, None))
        ));
        generation_update.await.unwrap();

        // FAST account status and one-time proof consumption use one user-row
        // lock and transaction. A later generation update is serialized after
        // proof commit and is caught by the downstream generation fence.
        let dave = format!("auth-dave-{}", &Uuid::new_v4().simple().to_string()[..10]);
        let (dave_id, dave_generation) =
            create_account(&pool, &dave, "dave correct horse battery").await;
        let device_id = Uuid::new_v4();
        let issued = db::issue_fast_token(
            &pool,
            fast_secret.as_slice(),
            dave_id,
            device_id,
            "HT-SHA-256-NONE",
            dave_generation,
            30,
            90,
            None,
        )
        .await
        .unwrap();
        let token = Zeroizing::new(issued.token);
        let proof = Zeroizing::new(auth::fast_proof(&token, false, &[]));
        let (locked_tx, locked_rx) = oneshot::channel();
        let (release_tx, release_rx) = oneshot::channel();
        let fast_service = service.clone();
        let fast_username = dave.clone();
        let fast_attempt = tokio::spawn(async move {
            fast_service
                .authenticate_fast_with_hook(
                    FastProofRequest {
                        username: &fast_username,
                        device_id,
                        mechanism: "HT-SHA-256-NONE",
                        counter: None,
                        initiator_proof: &proof,
                        channel_binding: &[],
                        invalidate: false,
                        rotate_within_days: 7,
                    },
                    move |fence| async move {
                        locked_tx.send(fence).unwrap();
                        release_rx.await.unwrap();
                    },
                )
                .await
        });
        locked_rx.await.unwrap();
        let update_pool = pool.clone();
        let mut generation_update = tokio::spawn(async move {
            sqlx::query("UPDATE users SET auth_generation=auth_generation+1 WHERE id=$1")
                .bind(dave_id)
                .execute(&update_pool)
                .await
                .unwrap();
        });
        assert!(
            tokio::time::timeout(Duration::from_millis(100), &mut generation_update)
                .await
                .is_err()
        );
        release_tx.send(()).unwrap();
        let fast_success = match fast_attempt.await.unwrap() {
            AuthenticationResult::Authenticated(success) => success,
            _ => panic!("valid FAST proof was rejected"),
        };
        let (fast_user, responder, _, _, _, authenticated_generation, _, _) =
            fast_success.into_parts();
        assert_eq!(fast_user.id, dave_id);
        assert_eq!(authenticated_generation, dave_generation);
        assert_eq!(responder.len(), 32);
        generation_update.await.unwrap();
        assert!(matches!(
            service
                .revalidate_generation(dave_id, authenticated_generation)
                .await,
            AuthenticationResult::StaleGeneration
        ));

        // A backend outage is never collapsed into UnknownCredentials.
        pool.close().await;
        assert!(matches!(
            service.authenticate_external(&dave).await,
            AuthenticationResult::BackendFailure(_)
        ));
    }

    #[test]
    fn fast_service_dto_conversions_keep_secrets_move_only() {
        let now = chrono::Utc::now();
        let later = now + chrono::Duration::days(30);
        let device_id = Uuid::new_v4();
        let token_id = Uuid::new_v4();

        let db_issued = db::IssuedFastToken {
            token: Zeroizing::new("secret-fast-token-value".to_string()),
            expires_at: later,
        };
        let round_trip_issued = IssuedFastToken::from(db_issued);
        assert_eq!(round_trip_issued.token.as_str(), "secret-fast-token-value");
        assert_eq!(round_trip_issued.expires_at, later);

        let service_issue = FastTokenIssue {
            device_id,
            mechanism: "HT-SHA-256-NONE".to_string(),
            ttl_days: 30,
            strong_reauth_max_days: 90,
            inherited_chain: Some((now, later)),
        };
        let db_issue = db::FastTokenIssue::from(&service_issue);
        assert_eq!(db_issue.device_id, device_id);
        assert_eq!(db_issue.mechanism, "HT-SHA-256-NONE");
        assert_eq!(db_issue.ttl_days, 30);
        assert_eq!(db_issue.strong_reauth_max_days, 90);
        assert_eq!(db_issue.inherited_chain, Some((now, later)));

        let round_trip_issue = FastTokenIssue::from(db_issue);
        assert_eq!(round_trip_issue, service_issue);

        let service_plan = FastCommitPlan {
            token_id: Some(token_id),
            token_was_new: true,
            invalidate: true,
            issue: Some(service_issue),
        };
        let db_plan = service_plan.to_db();
        assert_eq!(db_plan.token_id, Some(token_id));
        assert!(db_plan.token_was_new);
        assert!(db_plan.invalidate);
        assert!(db_plan.issue.is_some());

        let round_trip_plan = FastCommitPlan::from(db_plan);
        assert_eq!(round_trip_plan, service_plan);
    }

    #[test]
    fn issued_fast_token_redacts_secret_in_debug_format() {
        let issued = IssuedFastToken {
            token: Zeroizing::new("super-sensitive-token-data-12345".to_string()),
            expires_at: chrono::Utc::now(),
        };
        let debug_str = format!("{issued:?}");
        assert!(debug_str.contains("[REDACTED]"));
        assert!(!debug_str.contains("super-sensitive-token-data-12345"));
    }

    #[tokio::test]
    #[ignore = "requires TEST_DATABASE_URL; creates and removes a random isolated schema"]
    async fn login_epoch_publication_is_fenced_invisible_and_atomic_with_binding() {
        let pool = isolated_pool().await;
        db::reconcile_deployment_capacity(
            &pool,
            db::DeploymentCapacityConfiguration {
                epoch: 1,
                accounts: 8,
                muc_rooms: 8,
                muc_rooms_per_owner: 4,
                live_sessions: 8,
                sessions_per_account: 8,
                resumable_sessions: 8,
            },
        )
        .await
        .unwrap();
        let username = format!("epoch-{}", &Uuid::new_v4().simple().to_string()[..10]);
        let (user_id, auth_generation) =
            create_account(&pool, &username, "epoch correct horse battery").await;
        let service = AuthenticationService::new(
            pool.clone(),
            Arc::new(Zeroizing::new(vec![0x61; 32])),
            Arc::new(Zeroizing::new(vec![0xa6; 32])),
            auth::MIN_SCRAM_ITERATIONS,
            false,
        );
        let device_id = Uuid::new_v4();
        let connection_id = Uuid::new_v4();
        let full_jid = format!("{username}@example.test/device");

        let mut tx = db::lock_auth_generation(&pool, user_id, auth_generation)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            db::reserve_live_session_in_transaction(
                &mut tx,
                connection_id,
                user_id,
                &full_jid,
                120,
                false,
            )
            .await
            .unwrap(),
            db::LiveSessionReservation::Reserved
        );
        let staged = stage_login_epoch_in_transaction(
            &mut tx,
            user_id,
            Some(device_id),
            auth_generation,
            connection_id,
        )
        .await
        .unwrap()
        .unwrap();
        tx.commit().await.unwrap();

        // Phase two is durable, but maintenance must still observe no new
        // device epoch before the transport-success continuation runs.
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM user_agent_login_epochs
                  WHERE user_id=$1 AND device_id=$2",
            )
            .bind(user_id)
            .bind(device_id)
            .fetch_one(&pool)
            .await
            .unwrap(),
            0
        );
        let wrong_fence = CredentialCommitReceipt::new(
            None,
            Some(StagedLoginEpoch {
                connection_id: Uuid::new_v4(),
                ..staged
            }),
            None,
        );
        assert!(matches!(
            service.publish_credential_commit(&wrong_fence).await,
            AuthenticationResult::ExpiredCredentials
        ));
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM user_agent_login_epoch_stages
                  WHERE operation_id=$1",
            )
            .bind(staged.operation_id)
            .fetch_one(&pool)
            .await
            .unwrap(),
            1,
            "a mismatched publication fence must not consume the stage"
        );

        let receipt = CredentialCommitReceipt::new(
            None,
            Some(staged),
            Some(BindingPublication {
                connection_id,
                user_id,
                full_jid: full_jid.clone(),
                lease_seconds: 120,
            }),
        );
        assert!(matches!(
            service.publish_credential_commit(&receipt).await,
            AuthenticationResult::Authenticated(Some(1))
        ));
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT epoch FROM user_agent_login_epochs
                  WHERE user_id=$1 AND device_id=$2",
            )
            .bind(user_id)
            .bind(device_id)
            .fetch_one(&pool)
            .await
            .unwrap(),
            1
        );
        assert!(db::release_live_session(&pool, connection_id)
            .await
            .unwrap());

        // Make the stage provisionally eligible with a durable replacement
        // claim whose old SM stream does not exist. Epoch SQL executes first,
        // then binding publication rejects it; the enclosing transaction must
        // leave the published epoch unchanged and retain the stage for TTL
        // cleanup rather than exposing a partial device replacement.
        let failed_connection = Uuid::new_v4();
        let failed_full_jid = format!("{username}@example.test/failure");
        let failed_stage = {
            let mut tx = db::lock_auth_generation(&pool, user_id, auth_generation)
                .await
                .unwrap()
                .unwrap();
            let stage = stage_login_epoch_in_transaction(
                &mut tx,
                user_id,
                Some(device_id),
                auth_generation,
                failed_connection,
            )
            .await
            .unwrap()
            .unwrap();
            sqlx::query(
                "INSERT INTO deployment_session_binding_claims
                 (connection_id,user_id,full_jid,replaced_connection_id,expires_at)
                 VALUES($1,$2,$3,$4,clock_timestamp()+INTERVAL '2 minutes')",
            )
            .bind(failed_connection)
            .bind(user_id)
            .bind(&failed_full_jid)
            .bind(Uuid::new_v4())
            .execute(&mut *tx)
            .await
            .unwrap();
            tx.commit().await.unwrap();
            stage
        };
        let failed_receipt = CredentialCommitReceipt::new(
            None,
            Some(failed_stage),
            Some(BindingPublication {
                connection_id: failed_connection,
                user_id,
                full_jid: failed_full_jid,
                lease_seconds: 120,
            }),
        );
        assert!(matches!(
            service.publish_credential_commit(&failed_receipt).await,
            AuthenticationResult::ExpiredCredentials
        ));
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT epoch FROM user_agent_login_epochs
                  WHERE user_id=$1 AND device_id=$2",
            )
            .bind(user_id)
            .bind(device_id)
            .fetch_one(&pool)
            .await
            .unwrap(),
            1
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM user_agent_login_epoch_stages
                  WHERE operation_id=$1",
            )
            .bind(failed_stage.operation_id)
            .fetch_one(&pool)
            .await
            .unwrap(),
            1
        );
        sqlx::query(
            "UPDATE user_agent_login_epoch_stages
                SET expires_at=clock_timestamp()-INTERVAL '1 second'
              WHERE operation_id=$1",
        )
        .bind(failed_stage.operation_id)
        .execute(&pool)
        .await
        .unwrap();
        assert_eq!(
            db::cleanup_expired_user_agent_login_epoch_stages(&pool, 10)
                .await
                .unwrap(),
            1
        );
        assert!(db::release_live_session(&pool, failed_connection)
            .await
            .unwrap());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "requires TEST_DATABASE_URL; creates and removes a random isolated schema"]
    async fn publication_lease_lock_blocks_reserve_release_and_expiry_cleanup() {
        let pool = isolated_pool().await;
        db::reconcile_deployment_capacity(
            &pool,
            db::DeploymentCapacityConfiguration {
                epoch: 1,
                accounts: 8,
                muc_rooms: 8,
                muc_rooms_per_owner: 4,
                live_sessions: 8,
                sessions_per_account: 8,
                resumable_sessions: 8,
            },
        )
        .await
        .unwrap();
        let username = format!("lease-lock-{}", &Uuid::new_v4().simple().to_string()[..10]);
        let (user_id, auth_generation) =
            create_account(&pool, &username, "lease lock correct horse").await;
        let full_jid = format!("{username}@example.test/device");
        let first_connection = Uuid::new_v4();
        reserve_test_live_session(&pool, first_connection, user_id, auth_generation, &full_jid)
            .await;

        // The publication-side exact lookup owns both the per-JID advisory
        // barrier and the lease row lock. A concurrent reservation for the
        // same full JID cannot pass the barrier or invert lease/claim order.
        let mut publication = db::lock_auth_generation(&pool, user_id, auth_generation)
            .await
            .unwrap()
            .unwrap();
        assert!(db::publish_binding_live_session_in_transaction(
            &mut publication,
            first_connection,
            user_id,
            &full_jid,
            120,
        )
        .await
        .unwrap());
        let reserve_pool = pool.clone();
        let reserve_jid = full_jid.clone();
        let competing_connection = Uuid::new_v4();
        let (reserve_started_tx, reserve_started_rx) = tokio::sync::oneshot::channel();
        let reserve_task = tokio::spawn(async move {
            let mut tx = reserve_pool.begin().await.unwrap();
            let _ = reserve_started_tx.send(());
            let outcome = db::reserve_live_session_in_transaction(
                &mut tx,
                competing_connection,
                user_id,
                &reserve_jid,
                120,
                false,
            )
            .await;
            tx.rollback().await.unwrap();
            outcome
        });
        reserve_started_rx.await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(
            !reserve_task.is_finished(),
            "same-JID reservation bypassed publication advisory/lease locks"
        );
        publication.commit().await.unwrap();
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), reserve_task)
                .await
                .expect("same-JID reservation remained deadlocked after publication commit")
                .unwrap()
                .unwrap(),
            db::LiveSessionReservation::Conflict
        );

        // An exact release must likewise wait for the row lock. This is the
        // former EXISTS/delete TOCTOU between authentication publication SQL
        // and commit.
        let mut publication = db::lock_auth_generation(&pool, user_id, auth_generation)
            .await
            .unwrap()
            .unwrap();
        assert!(db::publish_binding_live_session_in_transaction(
            &mut publication,
            first_connection,
            user_id,
            &full_jid,
            120,
        )
        .await
        .unwrap());
        let release_pool = pool.clone();
        let (release_started_tx, release_started_rx) = tokio::sync::oneshot::channel();
        let release_task = tokio::spawn(async move {
            let _ = release_started_tx.send(());
            db::release_live_session(&release_pool, first_connection).await
        });
        release_started_rx.await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(
            !release_task.is_finished(),
            "release deleted a lease locked by authentication publication"
        );
        publication.commit().await.unwrap();
        assert!(tokio::time::timeout(Duration::from_secs(2), release_task)
            .await
            .expect("lease release remained blocked after publication commit")
            .unwrap()
            .unwrap());

        // Expired rows are locked too. Although they cannot authorize an
        // epoch, cleanup cannot delete one between exact revalidation and the
        // caller's rollback/commit decision.
        let expired_connection = Uuid::new_v4();
        reserve_test_live_session(
            &pool,
            expired_connection,
            user_id,
            auth_generation,
            &full_jid,
        )
        .await;
        sqlx::query(
            "UPDATE deployment_session_leases
                SET lease_until=clock_timestamp()-INTERVAL '1 second'
              WHERE connection_id=$1",
        )
        .bind(expired_connection)
        .execute(&pool)
        .await
        .unwrap();
        let mut publication = db::lock_auth_generation(&pool, user_id, auth_generation)
            .await
            .unwrap()
            .unwrap();
        assert!(!db::publish_binding_live_session_in_transaction(
            &mut publication,
            expired_connection,
            user_id,
            &full_jid,
            120,
        )
        .await
        .unwrap());
        let cleanup_pool = pool.clone();
        let (cleanup_started_tx, cleanup_started_rx) = tokio::sync::oneshot::channel();
        let cleanup_task = tokio::spawn(async move {
            let _ = cleanup_started_tx.send(());
            db::cleanup_expired_live_session_leases(&cleanup_pool, 10).await
        });
        cleanup_started_rx.await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(
            !cleanup_task.is_finished(),
            "expiry cleanup deleted a lease locked by publication"
        );
        publication.rollback().await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_secs(2), cleanup_task)
                .await
                .expect("expiry cleanup remained blocked after publication rollback")
                .unwrap()
                .unwrap()
                >= 1
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM deployment_session_leases WHERE connection_id=$1",
            )
            .bind(expired_connection)
            .fetch_one(&pool)
            .await
            .unwrap(),
            0
        );
        sqlx::query("DELETE FROM users WHERE id=$1")
            .bind(user_id)
            .execute(&pool)
            .await
            .unwrap();
    }
}
