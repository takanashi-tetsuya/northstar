//! Database and credential boundary for legacy SASL, SASL2 and XEP-0484.
//!
//! Protocol handlers keep the wire state machine, but never receive a
//! PostgreSQL capability or the FAST derivation secret. Every successful
//! identity is fenced to an exact account UUID and credential generation.

pub(crate) mod publication;

use northstar_archive_core::ArchiveBoundary;
use northstar_auth_core as auth;
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

pub(crate) struct LoadedAccount {
    pub(crate) account: AuthenticatedAccount,
    pub(crate) is_disabled: bool,
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
    pub(crate) fn from_verifier(
        fence: AuthenticationFence,
        salt: Vec<u8>,
        iterations: u32,
        stored_key: Vec<u8>,
        server_key: Vec<u8>,
    ) -> Self {
        Self {
            fence,
            salt,
            iterations,
            stored_key,
            server_key,
        }
    }

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
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        user: AuthenticatedAccount,
        responder: Zeroizing<Vec<u8>>,
        should_rotate: bool,
        token_id: Uuid,
        token_was_new: bool,
        auth_generation: i64,
        strong_auth_at: chrono::DateTime<chrono::Utc>,
        chain_expires_at: chrono::DateTime<chrono::Utc>,
    ) -> Self {
        Self {
            user,
            responder,
            should_rotate,
            token_id,
            token_was_new,
            auth_generation,
            strong_auth_at,
            chain_expires_at,
        }
    }

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
    publication_identity: Uuid,
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
    pub(crate) fn publication_identity(&self) -> Uuid {
        self.publication_identity
    }
    pub(crate) fn staged_login_epoch(&self) -> Option<StagedLoginEpoch> {
        self.staged_login_epoch
    }
    pub(crate) fn binding_publication(&self) -> Option<&BindingPublication> {
        self.binding_publication.as_ref()
    }

    pub(crate) fn new(
        issued_fast: Option<IssuedFastToken>,
        staged_login_epoch: Option<StagedLoginEpoch>,
        binding_publication: Option<BindingPublication>,
    ) -> Self {
        Self {
            publication_identity: Uuid::new_v4(),
            issued_fast,
            staged_login_epoch,
            binding_publication,
        }
    }

    pub(crate) fn take_issued_fast(&mut self) -> Option<IssuedFastToken> {
        self.issued_fast.take()
    }
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

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct FastCommitPlan {
    pub(crate) token_id: Option<Uuid>,
    pub(crate) token_was_new: bool,
    pub(crate) invalidate: bool,
    pub(crate) issue: Option<FastTokenIssue>,
}

#[derive(Clone, Copy)]
pub(crate) struct AuthenticationPolicy {
    pub(crate) scram_iterations: u32,
    pub(crate) scram_sha1_enabled: bool,
}

pub(crate) trait AuthenticationRepository: Send + Sync {
    fn scram_credentials(
        &self,
        username: &str,
        algorithm: auth::ScramAlgorithm,
    ) -> impl std::future::Future<Output = AuthenticationResult<ScramCredentialSet>> + Send;
    fn authenticate_plain(
        &self,
        username: &str,
        password: &str,
        policy: AuthenticationPolicy,
    ) -> impl std::future::Future<Output = AuthenticationResult<AuthenticatedAccount>> + Send;
    fn account_by_id(
        &self,
        user_id: Uuid,
    ) -> impl std::future::Future<Output = anyhow::Result<Option<LoadedAccount>>> + Send;
    fn account_by_username(
        &self,
        username: &str,
    ) -> impl std::future::Future<Output = anyhow::Result<Option<LoadedAccount>>> + Send;
    fn generation_state(
        &self,
        fence: AuthenticationFence,
    ) -> impl std::future::Future<Output = AuthenticationResult<()>> + Send;
    fn bind2_archive_boundaries(
        &self,
        user_id: Uuid,
        expected_auth_generation: i64,
    ) -> impl std::future::Future<
        Output = AuthenticationResult<(Option<ArchiveBoundary>, Option<ArchiveBoundary>)>,
    > + Send;
    fn authenticate_fast(
        &self,
        request: FastProofRequest<'_>,
    ) -> impl std::future::Future<Output = AuthenticationResult<FastAuthenticationSuccess>> + Send;
    fn commit_fast_with_login_epoch(
        &self,
        user_id: Uuid,
        expected_auth_generation: i64,
        plan: &FastCommitPlan,
        device_id: Option<Uuid>,
        connection_id: Uuid,
    ) -> impl std::future::Future<Output = AuthenticationResult<CredentialCommitReceipt>> + Send;
    fn commit_fast_with_login_epoch_observed(
        &self,
        user_id: Uuid,
        expected_auth_generation: i64,
        plan: &FastCommitPlan,
        device_id: Option<Uuid>,
        connection_id: Uuid,
        invocation: &publication::CredentialInvocation<'_>,
    ) -> impl std::future::Future<Output = AuthenticationResult<CredentialCommitReceipt>> + Send;
    fn publish_credential_commit(
        &self,
        receipt: &CredentialCommitReceipt,
    ) -> impl std::future::Future<Output = AuthenticationResult<Option<i64>>> + Send;
    fn publish_credential_commit_observed(
        &self,
        invocation: &publication::Invocation<'_>,
    ) -> impl std::future::Future<Output = AuthenticationResult<Option<i64>>> + Send;
}

#[derive(Clone)]
pub(crate) struct AuthenticationService<R> {
    repository: R,
    dummy_scram_secret: Arc<Zeroizing<Vec<u8>>>,
    scram_iterations: u32,
    dummy_scram_iteration_profiles: Arc<[u32]>,
    scram_sha1_enabled: bool,
}

impl<R: AuthenticationRepository> AuthenticationService<R> {
    #[cfg(test)]
    pub(crate) fn new(
        repository: R,
        dummy_scram_secret: Arc<Zeroizing<Vec<u8>>>,
        scram_iterations: u32,
        scram_sha1_enabled: bool,
    ) -> Self {
        Self::new_with_dummy_scram_iteration_profiles(
            repository,
            dummy_scram_secret,
            scram_iterations,
            vec![auth::MIN_SCRAM_ITERATIONS, scram_iterations],
            scram_sha1_enabled,
        )
    }

    pub(crate) fn new_with_dummy_scram_iteration_profiles(
        repository: R,
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
            repository,
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
        self.repository
            .scram_credentials(&username, algorithm)
            .await
    }

    pub(crate) async fn authenticate_plain(
        &self,
        username: &str,
        password: &str,
    ) -> AuthenticationResult<AuthenticatedAccount> {
        self.repository
            .authenticate_plain(
                username,
                password,
                AuthenticationPolicy {
                    scram_iterations: self.scram_iterations,
                    scram_sha1_enabled: self.scram_sha1_enabled,
                },
            )
            .await
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
        match self.repository.account_by_id(fence.user_id).await {
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
        match self.repository.account_by_username(&username).await {
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
        self.repository
            .generation_state(AuthenticationFence {
                user_id,
                auth_generation: expected_auth_generation,
            })
            .await
    }

    pub(crate) async fn bind2_archive_boundaries(
        &self,
        user_id: Uuid,
        expected_auth_generation: i64,
    ) -> AuthenticationResult<(Option<ArchiveBoundary>, Option<ArchiveBoundary>)> {
        self.repository
            .bind2_archive_boundaries(user_id, expected_auth_generation)
            .await
    }

    pub(crate) async fn authenticate_fast(
        &self,
        request: FastProofRequest<'_>,
    ) -> AuthenticationResult<FastAuthenticationSuccess> {
        self.repository.authenticate_fast(request).await
    }

    pub(crate) async fn commit_fast_with_login_epoch(
        &self,
        user_id: Uuid,
        expected_auth_generation: i64,
        plan: &FastCommitPlan,
        device_id: Option<Uuid>,
        connection_id: Uuid,
    ) -> AuthenticationResult<CredentialCommitReceipt> {
        self.repository
            .commit_fast_with_login_epoch(
                user_id,
                expected_auth_generation,
                plan,
                device_id,
                connection_id,
            )
            .await
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn commit_fast_with_login_epoch_observed(
        &self,
        user_id: Uuid,
        expected_auth_generation: i64,
        plan: &FastCommitPlan,
        device_id: Option<Uuid>,
        connection_id: Uuid,
        prepared: Option<&publication::PreparedCredential>,
    ) -> AuthenticationResult<CredentialCommitReceipt> {
        let Some(prepared) = prepared else {
            return self
                .commit_fast_with_login_epoch(
                    user_id,
                    expected_auth_generation,
                    plan,
                    device_id,
                    connection_id,
                )
                .await;
        };
        let Ok(invocation) = prepared.fast(
            user_id,
            expected_auth_generation,
            plan,
            device_id,
            connection_id,
        ) else {
            return AuthenticationResult::IntegrityFailure;
        };
        let result = self
            .repository
            .commit_fast_with_login_epoch_observed(
                user_id,
                expected_auth_generation,
                plan,
                device_id,
                connection_id,
                &invocation,
            )
            .await;
        invocation.fast_returned(&result);
        result
    }

    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "Returned-receipt compatibility for SQL controls; live transports use observed publication"
        )
    )]
    pub(crate) async fn publish_credential_commit(
        &self,
        receipt: &CredentialCommitReceipt,
    ) -> AuthenticationResult<Option<i64>> {
        if receipt.staged_login_epoch.is_none() && receipt.binding_publication.is_none() {
            return AuthenticationResult::Authenticated(None);
        }
        self.repository.publish_credential_commit(receipt).await
    }

    pub(crate) async fn publish_credential_commit_observed(
        &self,
        invocation: &publication::Invocation<'_>,
    ) -> AuthenticationResult<Option<i64>> {
        if invocation.enter_service().is_err() {
            return AuthenticationResult::IntegrityFailure;
        }
        let receipt = invocation.receipt();
        let result =
            if receipt.staged_login_epoch.is_none() && receipt.binding_publication.is_none() {
                if invocation.not_required().is_err() {
                    AuthenticationResult::IntegrityFailure
                } else {
                    AuthenticationResult::Authenticated(None)
                }
            } else {
                self.repository
                    .publish_credential_commit_observed(invocation)
                    .await
            };
        if !invocation.returned(&result) {
            return AuthenticationResult::IntegrityFailure;
        }
        result
    }
}

#[cfg(test)]
mod tests;
