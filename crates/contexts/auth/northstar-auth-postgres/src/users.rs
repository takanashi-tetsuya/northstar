//! Accounts, API sessions, credentials and user-agent login epochs.

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use northstar_auth_core as auth;
use northstar_config::Config;
use serde::Serialize;
use sqlx::{PgPool, Postgres, Row, Transaction};
use std::collections::HashMap;
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

mod api_sessions;
mod authentication;
mod registration;

pub use self::api_sessions::*;
pub use self::authentication::*;
pub use self::registration::*;
pub use northstar_auth_core::api_session::ApiPrincipal;

#[derive(Debug, thiserror::Error)]
pub enum RegistrationError {
    #[error("username is invalid")]
    InvalidUsername(#[source] anyhow::Error),
    #[error("invitation token is invalid, expired, revoked, or fully used")]
    InvitationRejected,
    #[error("registration is closed")]
    Closed,
    #[error("username is already registered")]
    UsernameTaken,
    #[error("registration capacity limit reached")]
    RateLimited,
    #[error("deployment account capacity reached")]
    CapacityExhausted,
    #[error("password work capacity is temporarily exhausted")]
    PasswordWorkOverloaded,
    #[error("registration backend failed")]
    Internal(#[source] anyhow::Error),
}

#[derive(Debug, thiserror::Error)]
pub enum UserStatusError {
    #[error("user does not exist")]
    NotFound,
    #[error("administrator authorization changed")]
    Unauthorized,
    #[error("an administrator cannot disable or demote the account authorizing this request")]
    SelfMutation,
    #[error("the last enabled administrator cannot be disabled or demoted")]
    LastAdministrator,
    #[error("user status backend failed")]
    Internal(#[source] anyhow::Error),
}

#[derive(Clone, Serialize)]
pub struct User {
    pub id: Uuid,
    pub username: String,
    #[serde(skip_serializing)]
    pub password_hash: Zeroizing<String>,
    #[serde(skip_serializing)]
    pub scram_iterations: Option<u32>,
    #[serde(skip_serializing)]
    pub scram_iteration_floor: u32,
    #[serde(skip_serializing)]
    pub scram_sha1_iterations: Option<u32>,
    #[serde(skip_serializing)]
    pub scram_sha1_iteration_floor: u32,
    pub display_name: Option<String>,
    pub is_admin: bool,
    pub is_disabled: bool,
    #[serde(skip_serializing)]
    pub auth_generation: i64,
    pub created_at: DateTime<Utc>,
    pub last_login_at: Option<DateTime<Utc>>,
}

impl Drop for User {
    fn drop(&mut self) {
        self.password_hash.zeroize();
    }
}

/// Verifier-free identity returned to externally triggered XMPP routing and
/// profile/PubSub lookups. Disabled accounts are excluded by construction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnabledUser {
    pub id: Uuid,
    pub username: String,
    pub display_name: Option<String>,
    pub auth_generation: i64,
}

// A User crosses most protocol and API boundaries, so deriving Debug here
// would make the reusable Argon2 verifier available to any future `?user`
// diagnostic.  Keep useful identity/status diagnostics while making verifier
// material structurally impossible to format by accident.
impl std::fmt::Debug for User {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("User")
            .field("id", &self.id)
            .field("username", &self.username)
            .field("display_name", &self.display_name)
            .field("is_admin", &self.is_admin)
            .field("is_disabled", &self.is_disabled)
            .field("auth_generation", &self.auth_generation)
            .field("created_at", &self.created_at)
            .field("last_login_at", &self.last_login_at)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UserAuthState {
    pub auth_generation: i64,
    pub is_disabled: bool,
}

#[cfg(any(test, feature = "test-support"))]
pub struct ScramCredentials {
    pub salt: Vec<u8>,
    pub iterations: u32,
    pub stored_key: Vec<u8>,
    pub server_key: Vec<u8>,
}

#[cfg(any(test, feature = "test-support"))]
impl std::fmt::Debug for ScramCredentials {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ScramCredentials")
            .field("iterations", &self.iterations)
            .field("salt_bytes", &self.salt.len())
            .field("stored_key_bytes", &self.stored_key.len())
            .field("server_key_bytes", &self.server_key.len())
            .finish()
    }
}

#[cfg(any(test, feature = "test-support"))]
pub async fn get_scram_credentials(
    pool: &PgPool,
    username: &str,
    algorithm: auth::ScramAlgorithm,
) -> Result<Option<ScramCredentials>> {
    let username = auth::normalize_username(username).unwrap_or_default();
    let query = match algorithm {
        auth::ScramAlgorithm::Sha256 => "SELECT scram_sha256_salt AS salt, scram_sha256_iterations AS iterations, scram_sha256_stored_key AS stored_key, scram_sha256_server_key AS server_key FROM users WHERE username = $1 AND NOT is_disabled",
        auth::ScramAlgorithm::Sha1 => "SELECT scram_sha1_salt AS salt, scram_sha1_iterations AS iterations, scram_sha1_stored_key AS stored_key, scram_sha1_server_key AS server_key FROM users WHERE username = $1 AND NOT is_disabled",
    };
    let row = sqlx::query(query)
        .bind(&username)
        .fetch_optional(pool)
        .await?;

    let Some(row) = row else {
        return Ok(None);
    };
    let values = (
        row.get::<Option<Vec<u8>>, _>("salt"),
        row.get::<Option<i32>, _>("iterations"),
        row.get::<Option<Vec<u8>>, _>("stored_key"),
        row.get::<Option<Vec<u8>>, _>("server_key"),
    );
    match values {
        (None, None, None, None) => Ok(None),
        (Some(salt), Some(iterations), Some(stored_key), Some(server_key)) => {
            let iterations =
                u32::try_from(iterations).context("stored SCRAM iteration count is negative")?;
            if !(auth::MIN_SCRAM_ITERATIONS..=auth::MAX_SCRAM_ITERATIONS).contains(&iterations)
                || salt.is_empty()
                || stored_key.len() != algorithm.key_len()
                || server_key.len() != algorithm.key_len()
            {
                anyhow::bail!("stored SCRAM credentials are invalid");
            }
            Ok(Some(ScramCredentials {
                salt,
                iterations,
                stored_key,
                server_key,
            }))
        }
        _ => anyhow::bail!("stored SCRAM credentials are incomplete"),
    }
}

#[cfg(any(test, feature = "test-support"))]
pub async fn create_user_with_invitation(
    pool: &PgPool,
    username: &str,
    password: &str,
    invitation_token: Option<&str>,
    invitation_required: bool,
    registration_rate_per_hour: u32,
    scram_iterations: u32,
) -> std::result::Result<User, RegistrationError> {
    let prepared = prepare_registration(username, password, scram_iterations, true).await?;
    let mut tx = pool
        .begin()
        .await
        .map_err(|error| RegistrationError::Internal(error.into()))?;
    let user = create_user_with_invitation_in_tx(
        &mut tx,
        prepared,
        invitation_token,
        invitation_required,
        registration_rate_per_hour,
        None,
    )
    .await?;
    tx.commit()
        .await
        .map_err(|error| RegistrationError::Internal(error.into()))?;
    Ok(user)
}

#[cfg(any(test, feature = "test-support"))]
pub async fn find_user_by_id(pool: &PgPool, id: Uuid) -> Result<Option<User>> {
    let row = sqlx::query("SELECT * FROM users WHERE id = $1")
        .bind(id)
        .fetch_optional(pool)
        .await?;
    Ok(row.as_ref().map(user_from_row))
}

pub async fn lock_auth_generation<'a>(
    pool: &'a PgPool,
    user_id: Uuid,
    expected_generation: i64,
) -> Result<Option<sqlx::Transaction<'a, sqlx::Postgres>>> {
    lock_auth_generation_observed(pool, user_id, expected_generation, None).await
}

pub async fn lock_auth_generation_observed<'a>(
    pool: &'a PgPool,
    user_id: Uuid,
    expected_generation: i64,
    observation: Option<
        &northstar_auth_application::authentication::publication::CredentialInvocation<'_>,
    >,
) -> Result<Option<sqlx::Transaction<'a, sqlx::Postgres>>> {
    use northstar_auth_application::authentication::publication::{
        credential_error, CredentialInvocation, CredentialRollbackSite,
    };
    let mut tx = CredentialInvocation::begin(observation, pool.begin())
        .await
        .map_err(credential_error)?;
    let eligible = CredentialInvocation::eligibility(
        observation,
        sqlx::query_scalar::<_, bool>("SELECT northstar_lock_auth_generation($1,$2)")
            .bind(user_id)
            .bind(expected_generation)
            .fetch_optional(&mut *tx),
    )
    .await
    .map_err(credential_error)?;
    if eligible != Some(true) {
        CredentialInvocation::rollback(
            observation,
            CredentialRollbackSite::GenerationRefused,
            tx.rollback(),
        )
        .await
        .map_err(credential_error)?;
        return Ok(None);
    }
    if let Some(observation) = observation {
        observation.transaction_returned();
    }
    Ok(Some(tx))
}

/// Allocate a database-serialized installation login epoch. Cluster controls
/// revoke only lower epochs, so a delayed replacement message cannot kill a
/// newer login by the same XEP-0388 user-agent UUID.
#[cfg(any(test, feature = "test-support"))]
pub async fn next_user_agent_login_epoch(
    pool: &PgPool,
    user_id: Uuid,
    device_id: Uuid,
    expected_auth_generation: i64,
) -> Result<Option<i64>> {
    let mut tx = pool.begin().await?;
    let epoch = next_user_agent_login_epoch_in_transaction(
        &mut tx,
        user_id,
        device_id,
        expected_auth_generation,
    )
    .await?;
    if epoch.is_some() {
        tx.commit().await?;
    } else {
        tx.rollback().await?;
    }
    Ok(epoch)
}

#[cfg(any(test, feature = "test-support"))]
pub async fn next_user_agent_login_epoch_in_transaction(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    user_id: Uuid,
    device_id: Uuid,
    expected_auth_generation: i64,
) -> Result<Option<i64>> {
    let eligible = sqlx::query_scalar::<_, bool>(
        "SELECT TRUE FROM users
         WHERE id=$1 AND auth_generation=$2 AND NOT is_disabled FOR SHARE",
    )
    .bind(user_id)
    .bind(expected_auth_generation)
    .fetch_optional(&mut **tx)
    .await?;
    if eligible.is_none() {
        return Ok(None);
    }
    let epoch = sqlx::query_scalar(
        "INSERT INTO user_agent_login_epochs(user_id,device_id,epoch)
         VALUES($1,$2,1)
         ON CONFLICT(user_id,device_id) DO UPDATE
         SET epoch=user_agent_login_epochs.epoch+1,updated_at=clock_timestamp()
         RETURNING epoch",
    )
    .bind(user_id)
    .bind(device_id)
    .fetch_one(&mut **tx)
    .await?;
    // Keep the staged allocator ahead of this legacy/test-only direct
    // publication path. Mixing both helpers must never reuse an epoch.
    sqlx::query(
        "INSERT INTO user_agent_login_epoch_sequences(user_id,device_id,allocated_epoch)
         VALUES($1,$2,$3)
         ON CONFLICT(user_id,device_id) DO UPDATE
         SET allocated_epoch=GREATEST(
                 user_agent_login_epoch_sequences.allocated_epoch,
                 EXCLUDED.allocated_epoch
             ),
             updated_at=clock_timestamp()",
    )
    .bind(user_id)
    .bind(device_id)
    .bind(epoch)
    .execute(&mut **tx)
    .await?;
    Ok(Some(epoch))
}

#[cfg(any(test, feature = "test-support"))]
pub async fn create_api_session(pool: &PgPool, user_id: Uuid, ttl_hours: i64) -> Result<String> {
    let mut tx = pool.begin().await?;
    let session = create_api_session_in_tx(&mut tx, user_id, ttl_hours, None).await?;
    tx.commit().await?;
    Ok(session.token)
}

/// Change a password only if the exact password hash, credential generation,
/// and API bearer observed by the handler are still current. Password and
/// SCRAM derivation happens before the short transaction; the final row locks
/// turn the operation into a compare-and-swap with all bearer revocation and
/// audit writes in the same commit.
#[allow(clippy::too_many_arguments)]
#[cfg(any(test, feature = "test-support"))]
pub async fn change_password_cas(
    pool: &PgPool,
    user_id: Uuid,
    expected_password_hash: &str,
    expected_auth_generation: i64,
    presented_session: &str,
    current_password: &str,
    new_password: &str,
    scram_iterations: u32,
) -> Result<PasswordChangeOutcome> {
    if presented_session.len() != 64
        || !presented_session
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric())
    {
        return Ok(PasswordChangeOutcome::StaleAuthorization);
    }
    let prepared = prepare_password_change(
        expected_password_hash,
        current_password,
        new_password,
        scram_iterations,
        true,
    )
    .await?;
    if matches!(prepared, PreparedPasswordChange::InvalidCurrentPassword) {
        return Ok(PasswordChangeOutcome::InvalidCurrentPassword);
    }
    let mut tx = pool.begin().await?;
    let outcome = apply_prepared_password_change_in_tx(
        &mut tx,
        user_id,
        expected_password_hash,
        expected_auth_generation,
        presented_session,
        prepared,
        None,
    )
    .await?;
    if outcome != PasswordChangeOutcome::Changed {
        tx.rollback().await?;
        return Ok(outcome);
    }
    tx.commit().await?;
    Ok(outcome)
}

#[cfg(any(test, feature = "test-support"))]
pub async fn change_password(
    pool: &PgPool,
    user_id: Uuid,
    new_password: &str,
    scram_iterations: u32,
    scram_sha1_enabled: bool,
) -> Result<()> {
    let password = Zeroizing::new(new_password.to_owned());
    let creds = northstar_security::password_work::run(move || {
        auth::hash_password(&password, true, scram_iterations, scram_sha1_enabled)
    })
    .await
    .map_err(anyhow::Error::from)
    .context("password hashing task failed")?;
    let mut tx = pool.begin().await?;
    let expected_auth_generation =
        sqlx::query_scalar("SELECT auth_generation FROM users WHERE id=$1")
            .bind(user_id)
            .fetch_one(&mut *tx)
            .await?;
    anyhow::ensure!(
        apply_password_credentials_in_tx(&mut tx, user_id, expected_auth_generation, creds).await?,
        "test password-change generation became stale"
    );
    tx.commit().await?;
    Ok(())
}

#[cfg(any(test, feature = "test-support"))]
pub async fn registrations_last_hour(pool: &PgPool) -> Result<i64> {
    Ok(sqlx::query_scalar(
        "SELECT COUNT(*) FROM users WHERE created_at >= NOW() - INTERVAL '1 hour'",
    )
    .fetch_one(pool)
    .await?)
}

/// Production source of this module: the file itself followed by each
/// production child module file, so source-contract tests keep reading the
/// whole module after code moves between them. The children are listed in
/// the order their code had in the former single file, because some
/// contracts split the source on a marker that occurs in more than one child.
/// `module_source_lists_every_child_module` keeps this list in step with the
/// non-test `mod` declarations above.
#[cfg(any(test, feature = "test-support"))]
const MODULE_SOURCE: &[(&str, &str)] = &[
    ("users", include_str!("users.rs")),
    ("api_sessions", include_str!("users/api_sessions.rs")),
    ("registration", include_str!("users/registration.rs")),
    ("authentication", include_str!("users/authentication.rs")),
];

#[cfg(any(test, feature = "test-support"))]
pub fn module_source() -> String {
    MODULE_SOURCE
        .iter()
        .map(|(_, text)| *text)
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
mod module_source_tests;
