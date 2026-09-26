use crate::config::Config;
use crate::{
    abuse::{AbuseAction, AbuseGuard, GuardError, PowProof, TransactionalGuardOutcome},
    auth,
};
use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::Serialize;
use sqlx::{PgPool, Postgres, Row, Transaction};
use std::collections::HashMap;
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

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

pub use crate::services::api_queries::ApiPrincipal;

/// Credential-bearing projection reserved for the password-change endpoint.
/// Its Argon2 verifier is zeroized as soon as the request path releases it.
pub struct PasswordChangeSubject {
    pub principal: ApiPrincipal,
    password_hash: Zeroizing<String>,
}

impl PasswordChangeSubject {
    pub fn password_hash(&self) -> &str {
        self.password_hash.as_str()
    }
}

impl std::ops::Deref for PasswordChangeSubject {
    type Target = ApiPrincipal;

    fn deref(&self) -> &Self::Target {
        &self.principal
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

pub async fn create_user(
    pool: &PgPool,
    username: &str,
    password: &str,
    admin: bool,
    force: bool,
    scram_iterations: u32,
    scram_sha1_enabled: bool,
) -> Result<User> {
    let username = auth::normalize_username(username)?;
    let password = Zeroizing::new(password.to_owned());
    let creds = crate::password_work::run(move || {
        auth::hash_password(&password, !force, scram_iterations, scram_sha1_enabled)
    })
    .await
    .map_err(anyhow::Error::from)
    .context("password hashing task failed")?;
    let user_id = Uuid::new_v4();
    #[cfg(not(test))]
    let row = {
        anyhow::ensure!(
            admin,
            "production create_user is reserved for the empty-database bootstrap administrator"
        );
        let created: bool = sqlx::query_scalar(
            "SELECT northstar_user_create_bootstrap_admin(
                $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)",
        )
        .bind(user_id)
        .bind(&username)
        .bind(&creds.hash)
        .bind(&creds.scram_salt)
        .bind(i32::try_from(creds.scram_iterations)?)
        .bind(&creds.scram_stored_key)
        .bind(&creds.scram_server_key)
        .bind(&creds.scram_sha1_salt)
        .bind(
            creds
                .scram_sha1_stored_key
                .as_ref()
                .map(|_| i32::try_from(creds.scram_iterations))
                .transpose()?,
        )
        .bind(&creds.scram_sha1_stored_key)
        .bind(&creds.scram_sha1_server_key)
        .fetch_one(pool)
        .await
        .context("bootstrap administrator capability failed")?;
        anyhow::ensure!(
            created,
            "bootstrap administrator requires an empty users table"
        );
        sqlx::query("SELECT * FROM users WHERE id=$1")
            .bind(user_id)
            .fetch_one(pool)
            .await?
    };
    #[cfg(test)]
    let row = sqlx::query(
        "INSERT INTO users (id, username, password_hash, is_admin, scram_sha256_salt, scram_sha256_iterations, scram_sha256_stored_key, scram_sha256_server_key, scram_sha1_salt, scram_sha1_iterations, scram_sha1_stored_key, scram_sha1_server_key) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12) RETURNING *",
    )
    .bind(user_id)
    .bind(username)
    .bind(&creds.hash)
    .bind(admin)
    .bind(&creds.scram_salt)
    .bind(creds.scram_iterations as i32)
    .bind(&creds.scram_stored_key)
    .bind(&creds.scram_server_key)
    .bind(&creds.scram_sha1_salt)
    .bind(creds.scram_sha1_stored_key.as_ref().map(|_| creds.scram_iterations as i32))
    .bind(&creds.scram_sha1_stored_key)
    .bind(&creds.scram_sha1_server_key)
    .fetch_one(pool)
    .await
    .context("could not create user")?;
    Ok(user_from_row(&row))
}

#[cfg(test)]
pub struct ScramCredentials {
    pub salt: Vec<u8>,
    pub iterations: u32,
    pub stored_key: Vec<u8>,
    pub server_key: Vec<u8>,
}

#[cfg(test)]
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

#[cfg(test)]
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

/// Remove legacy verifier material when compatibility mode is disabled. This
/// is safe to repeat at every startup and leaves the stronger SHA-256 and
/// Argon2 credentials untouched.
pub async fn clear_scram_sha1_credentials(pool: &PgPool) -> Result<u64> {
    let changed: i64 = sqlx::query_scalar("SELECT northstar_user_clear_scram_sha1()")
        .fetch_one(pool)
        .await
        .context("could not clear disabled SCRAM-SHA-1 verifiers")?;
    u64::try_from(changed).context("SCRAM-SHA-1 cleanup returned a negative row count")
}

/// Load the complete bounded set of SCRAM costs that can appear on the wire.
/// Unknown-account challenges select from this set with a deployment-keyed
/// mapping, preventing a historical iteration count from becoming a trivial
/// account-existence oracle. New/rotated credentials always use the configured
/// profile, which is included even before the first such account exists.
pub async fn scram_iteration_profiles(pool: &PgPool, configured: u32) -> Result<Vec<u32>> {
    anyhow::ensure!(
        (auth::MIN_SCRAM_ITERATIONS..=auth::MAX_SCRAM_ITERATIONS).contains(&configured),
        "configured SCRAM iteration profile is invalid"
    );
    let stored = sqlx::query_scalar::<_, i32>(
        "SELECT DISTINCT iterations FROM (
             SELECT scram_sha256_iterations AS iterations FROM users
             UNION
             SELECT scram_sha1_iterations AS iterations FROM users
             UNION
             SELECT scram_sha256_iteration_floor AS iterations FROM users
             UNION
             SELECT scram_sha1_iteration_floor AS iterations FROM users
         ) profiles
         WHERE iterations IS NOT NULL
         ORDER BY iterations",
    )
    .fetch_all(pool)
    .await
    .context("could not load SCRAM iteration profiles")?;
    // Do not impose a second, artificial cardinality limit here. Every row is
    // already bounded by the account-capacity authority and contributes at
    // most two current values plus two durable floors. Refusing to start at
    // 65 distinct historical costs turned otherwise-valid rolling upgrades
    // into an availability failure; truncating instead would make the omitted
    // profiles an account-enumeration signal.
    let mut profiles = Vec::with_capacity(stored.len() + 2);
    profiles.push(auth::MIN_SCRAM_ITERATIONS);
    profiles.push(configured);
    for stored in stored {
        let stored = u32::try_from(stored).context("stored SCRAM iteration count is negative")?;
        anyhow::ensure!(
            (auth::MIN_SCRAM_ITERATIONS..=auth::MAX_SCRAM_ITERATIONS).contains(&stored),
            "stored SCRAM iteration profile is outside the accepted range"
        );
        profiles.push(stored);
    }
    profiles.sort_unstable();
    profiles.dedup();
    Ok(profiles)
}

#[cfg(test)]
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

pub struct PreparedRegistration {
    username: String,
    credentials: auth::PasswordCredentials,
}

#[derive(Debug)]
pub enum GuardedRegistrationOutcome {
    Created(User),
    AbuseDenied(GuardError),
    Rejected(RegistrationError),
}

pub async fn prepare_registration(
    username: &str,
    password: &str,
    scram_iterations: u32,
    scram_sha1_enabled: bool,
) -> std::result::Result<PreparedRegistration, RegistrationError> {
    let username =
        auth::normalize_username(username).map_err(RegistrationError::InvalidUsername)?;
    let password = Zeroizing::new(password.to_owned());
    let creds = crate::password_work::run(move || {
        auth::hash_password(&password, true, scram_iterations, scram_sha1_enabled)
    })
    .await
    .map_err(|error| {
        if error.is_overloaded() {
            RegistrationError::PasswordWorkOverloaded
        } else {
            RegistrationError::Internal(anyhow::Error::new(error))
        }
    })?;
    Ok(PreparedRegistration {
        username,
        credentials: creds,
    })
}

/// Prepare credentials using CPU capacity reserved before the caller opened
/// its transaction.  XMPP registration uses this variant so invalid PoW is
/// rejected before Argon2 runs while proof consumption and account creation
/// still share one rollback boundary.  Reserving first also caps the number of
/// database connections that can be held during the expensive computation.
pub async fn prepare_registration_with_reservation(
    username: &str,
    password: &str,
    scram_iterations: u32,
    scram_sha1_enabled: bool,
    password_work: crate::password_work::PasswordWorkReservation,
) -> std::result::Result<PreparedRegistration, RegistrationError> {
    let username =
        auth::normalize_username(username).map_err(RegistrationError::InvalidUsername)?;
    let password = Zeroizing::new(password.to_owned());
    let creds = password_work
        .run(move || auth::hash_password(&password, true, scram_iterations, scram_sha1_enabled))
        .await
        .map_err(|error| {
            if error.is_overloaded() {
                RegistrationError::PasswordWorkOverloaded
            } else {
                RegistrationError::Internal(anyhow::Error::new(error))
            }
        })?;
    Ok(PreparedRegistration {
        username,
        credentials: creds,
    })
}

/// Atomically consume the registration proof, advance its actor state and
/// create the account (including invitation consumption, hourly capacity and
/// audit). Most callers prepare password material before entering this short
/// transaction. The XMPP application service instead reserves bounded CPU
/// capacity before opening the transaction and hashes only after the v2 guard
/// succeeds, preserving the same rollback boundary without allowing invalid
/// proofs to consume Argon2 work. Callers must commit every returned outcome;
/// an internal error is returned as `Err` so dropping/rolling back restores the
/// one-use proof and every registration side effect for a safe retry.
/// Body-bound registration entry point used by HTTP and both XMPP registration
/// profiles. The expected intent is reconstructed from the parsed request and
/// is never accepted from the proof envelope.
#[allow(clippy::too_many_arguments)]
pub async fn create_user_with_invitation_guarded_in_tx_v2(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    abuse: &AbuseGuard,
    subject: &str,
    actors: &[String],
    proof: Option<&PowProof>,
    intent: &crate::abuse::PowIntent,
    guard_already_verified: bool,
    prepared: PreparedRegistration,
    invitation_token: Option<&str>,
    invitation_required: bool,
    registration_rate_per_hour: u32,
    request_id: Option<Uuid>,
) -> Result<GuardedRegistrationOutcome> {
    create_user_with_invitation_guarded_in_tx_bound(
        tx,
        abuse,
        subject,
        actors,
        proof,
        intent,
        guard_already_verified,
        prepared,
        invitation_token,
        invitation_required,
        registration_rate_per_hour,
        request_id,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn create_user_with_invitation_guarded_in_tx_bound(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    abuse: &AbuseGuard,
    subject: &str,
    actors: &[String],
    proof: Option<&PowProof>,
    intent: &crate::abuse::PowIntent,
    guard_already_verified: bool,
    prepared: PreparedRegistration,
    invitation_token: Option<&str>,
    invitation_required: bool,
    registration_rate_per_hour: u32,
    request_id: Option<Uuid>,
) -> Result<GuardedRegistrationOutcome> {
    if !guard_already_verified {
        let decision = crate::db::abuse_transaction_repository::verify_in_tx(
            tx,
            abuse,
            AbuseAction::Registration,
            subject,
            actors,
            proof,
            Some(intent),
        )
        .await?;
        match decision {
            TransactionalGuardOutcome::Allowed => {}
            TransactionalGuardOutcome::DeniedNeedsCommit(error) => {
                return Ok(GuardedRegistrationOutcome::AbuseDenied(error));
            }
        }
    }
    match create_user_with_invitation_in_tx(
        tx,
        prepared,
        invitation_token,
        invitation_required,
        registration_rate_per_hour,
        request_id,
    )
    .await
    {
        Ok(user) => Ok(GuardedRegistrationOutcome::Created(user)),
        Err(RegistrationError::Internal(error)) => Err(error),
        Err(error) => Ok(GuardedRegistrationOutcome::Rejected(error)),
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn create_user_with_invitation_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    prepared: PreparedRegistration,
    invitation_token: Option<&str>,
    invitation_required: bool,
    registration_rate_per_hour: u32,
    request_id: Option<Uuid>,
) -> std::result::Result<User, RegistrationError> {
    if invitation_token.is_some_and(|token| token.trim().len() > 512) {
        return Err(RegistrationError::InvitationRejected);
    }
    let PreparedRegistration {
        username,
        credentials: creds,
    } = prepared;
    let invitation_hash = invitation_token
        .filter(|token| !token.trim().is_empty())
        .map(|token| auth::token_hash(token.trim()));
    let user_id = Uuid::new_v4();
    let outcome: String = sqlx::query_scalar(
        "SELECT northstar_user_register(
            $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)",
    )
    .bind(user_id)
    .bind(&username)
    .bind(&creds.hash)
    .bind(&creds.scram_salt)
    .bind(
        i32::try_from(creds.scram_iterations)
            .map_err(|error| RegistrationError::Internal(error.into()))?,
    )
    .bind(&creds.scram_stored_key)
    .bind(&creds.scram_server_key)
    .bind(&creds.scram_sha1_salt)
    .bind(
        creds
            .scram_sha1_stored_key
            .as_ref()
            .map(|_| i32::try_from(creds.scram_iterations))
            .transpose()
            .map_err(|error| RegistrationError::Internal(error.into()))?,
    )
    .bind(&creds.scram_sha1_stored_key)
    .bind(&creds.scram_sha1_server_key)
    .bind(&invitation_hash)
    .bind(invitation_required)
    .bind(
        i32::try_from(registration_rate_per_hour)
            .map_err(|error| RegistrationError::Internal(error.into()))?,
    )
    .bind(request_id)
    .fetch_one(&mut **tx)
    .await
    .map_err(|error| RegistrationError::Internal(error.into()))?;
    match outcome.as_str() {
        "created" => {}
        "closed" => return Err(RegistrationError::Closed),
        "rate_limited" => return Err(RegistrationError::RateLimited),
        "username_taken" => return Err(RegistrationError::UsernameTaken),
        "invitation_rejected" => return Err(RegistrationError::InvitationRejected),
        "capacity_exhausted" => return Err(RegistrationError::CapacityExhausted),
        _ => {
            return Err(RegistrationError::Internal(anyhow::anyhow!(
                "registration capability returned unknown outcome {outcome:?}"
            )))
        }
    }
    let row = sqlx::query("SELECT * FROM users WHERE id=$1")
        .bind(user_id)
        .fetch_one(&mut **tx)
        .await
        .map_err(|error| RegistrationError::Internal(error.into()))?;
    let user = user_from_row(&row);
    Ok(user)
}

pub async fn audit_registration_rejection_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    request_id: Uuid,
    reason: &str,
) -> Result<()> {
    anyhow::ensure!(
        matches!(reason, "username_unavailable" | "invitation_rejected"),
        "invalid registration rejection reason"
    );
    sqlx::query(
        "INSERT INTO audit_log(actor_id,action,target,details,request_id)
         VALUES(NULL,'user.register.reject',NULL,$1,$2)",
    )
    .bind(serde_json::json!({"reason":reason}))
    .bind(request_id)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

pub async fn ensure_bootstrap_admin(pool: &PgPool, config: &Config) -> Result<()> {
    let (Some(username), Some(password)) = (
        config.bootstrap_admin_username.as_deref(),
        config.bootstrap_admin_password.as_deref(),
    ) else {
        return Ok(());
    };
    let username = auth::normalize_username(username)?;
    if let Some(existing) = find_user(pool, &username).await? {
        if !existing.is_admin {
            anyhow::bail!(
                "bootstrap administrator username already belongs to a non-admin account"
            );
        }
        return Ok(());
    }
    create_user(
        pool,
        &username,
        password,
        true,
        false,
        config.scram_iterations,
        config.scram_sha1_enabled,
    )
    .await?;
    tracing::warn!(%username, "created bootstrap administrator; rotate its password immediately");
    Ok(())
}

pub async fn find_user(pool: &PgPool, username: &str) -> Result<Option<User>> {
    // Every account is stored under the RFC 7622/PRECIS canonical localpart.
    // Normalize at the repository boundary as well as at authentication and
    // registration boundaries so legacy protocol call sites cannot make a
    // Unicode account unreachable by applying ASCII-only casing.
    let Ok(username) = auth::normalize_username(username) else {
        return Ok(None);
    };
    let row = sqlx::query("SELECT * FROM users WHERE username = $1")
        .bind(&username)
        .fetch_optional(pool)
        .await?;
    Ok(row.as_ref().map(user_from_row))
}

/// Least-authority local routing lookup. Disabled accounts are deliberately
/// indistinguishable from missing accounts and no password/SCRAM verifier is
/// loaded into the application service performing the route decision.
pub async fn find_enabled_user(pool: &PgPool, username: &str) -> Result<Option<EnabledUser>> {
    let Ok(username) = auth::normalize_username(username) else {
        return Ok(None);
    };
    Ok(sqlx::query(
        "SELECT id,username,display_name,auth_generation
           FROM users WHERE username=$1 AND NOT is_disabled",
    )
    .bind(username)
    .fetch_optional(pool)
    .await?
    .map(|row| EnabledUser {
        id: row.get("id"),
        username: row.get("username"),
        display_name: row.get("display_name"),
        auth_generation: row.get("auth_generation"),
    }))
}

pub async fn find_enabled_user_by_id(pool: &PgPool, id: Uuid) -> Result<Option<EnabledUser>> {
    Ok(sqlx::query(
        "SELECT id,username,display_name,auth_generation
           FROM users WHERE id=$1 AND NOT is_disabled",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?
    .map(|row| EnabledUser {
        id: row.get("id"),
        username: row.get("username"),
        display_name: row.get("display_name"),
        auth_generation: row.get("auth_generation"),
    }))
}

pub async fn enabled_user_id(pool: &PgPool, username: &str) -> Result<Option<Uuid>> {
    Ok(find_enabled_user(pool, username).await?.map(|user| user.id))
}

/// Lock a deterministic set of enabled account incarnations for the lifetime
/// of an application-owned write transaction.  Administrative disable/delete
/// takes an exclusive row lock, so a durable projection either commits before
/// that state change or observes the account as unavailable afterwards.
pub(crate) async fn lock_enabled_users_in_transaction(
    transaction: &mut Transaction<'_, Postgres>,
    user_ids: &[Uuid],
) -> Result<bool> {
    if user_ids.is_empty() {
        return Ok(true);
    }
    let mut user_ids = user_ids.to_vec();
    user_ids.sort_unstable();
    user_ids.dedup();
    let candidates = sqlx::query_as::<_, (Uuid, i64)>(
        "SELECT id,auth_generation FROM users
          WHERE id=ANY($1) AND NOT is_disabled
          ORDER BY id",
    )
    .bind(&user_ids)
    .fetch_all(&mut **transaction)
    .await?;
    if candidates.len() != user_ids.len() {
        return Ok(false);
    }
    for (user_id, generation) in candidates {
        let locked: bool = sqlx::query_scalar("SELECT northstar_lock_auth_generation($1,$2)")
            .bind(user_id)
            .bind(generation)
            .fetch_one(&mut **transaction)
            .await?;
        if !locked {
            return Ok(false);
        }
    }
    Ok(true)
}

#[cfg(test)]
pub async fn find_user_by_id(pool: &PgPool, id: Uuid) -> Result<Option<User>> {
    let row = sqlx::query("SELECT * FROM users WHERE id = $1")
        .bind(id)
        .fetch_optional(pool)
        .await?;
    Ok(row.as_ref().map(user_from_row))
}

/// Fetch credential epochs for a bounded set of live users in one round trip.
/// Missing rows deliberately stay absent so deleted accounts fail closed.
pub async fn auth_states_for_users(
    pool: &PgPool,
    user_ids: &[Uuid],
) -> Result<HashMap<Uuid, UserAuthState>> {
    if user_ids.is_empty() {
        return Ok(HashMap::new());
    }
    let rows = sqlx::query("SELECT id, auth_generation, is_disabled FROM users WHERE id = ANY($1)")
        .bind(user_ids)
        .fetch_all(pool)
        .await?;
    Ok(rows
        .into_iter()
        .map(|row| {
            (
                row.get("id"),
                UserAuthState {
                    auth_generation: row.get("auth_generation"),
                    is_disabled: row.get("is_disabled"),
                },
            )
        })
        .collect())
}

pub async fn lock_auth_generation<'a>(
    pool: &'a PgPool,
    user_id: Uuid,
    expected_generation: i64,
) -> Result<Option<sqlx::Transaction<'a, sqlx::Postgres>>> {
    let mut tx = pool.begin().await?;
    let eligible = sqlx::query_scalar::<_, bool>("SELECT northstar_lock_auth_generation($1,$2)")
        .bind(user_id)
        .bind(expected_generation)
        .fetch_optional(&mut *tx)
        .await?;
    if eligible != Some(true) {
        tx.rollback().await?;
        return Ok(None);
    }
    Ok(Some(tx))
}

/// Allocate a database-serialized installation login epoch. Cluster controls
/// revoke only lower epochs, so a delayed replacement message cannot kill a
/// newer login by the same XEP-0388 user-agent UUID.
#[cfg(test)]
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

#[cfg(test)]
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

/// Allocate, but do not publish, the next XEP-0388 user-agent epoch.
///
/// The returned epoch is invisible to replacement maintenance until
/// `publish_user_agent_login_epoch` consumes the exact operation/connection
/// fence after the terminal authentication frame has been written.
pub async fn stage_user_agent_login_epoch_in_transaction(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    user_id: Uuid,
    device_id: Uuid,
    expected_auth_generation: i64,
    connection_id: Uuid,
    operation_id: Uuid,
    ttl_seconds: u64,
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
    let ttl_seconds =
        i64::try_from(ttl_seconds).context("user-agent login epoch stage TTL is too large")?;
    let epoch: i64 = sqlx::query_scalar(
        "INSERT INTO user_agent_login_epoch_sequences(user_id,device_id,allocated_epoch)
         VALUES(
             $1,$2,
             COALESCE((
                 SELECT epoch FROM user_agent_login_epochs
                  WHERE user_id=$1 AND device_id=$2
             ),0)+1
         )
         ON CONFLICT(user_id,device_id) DO UPDATE
         SET allocated_epoch=user_agent_login_epoch_sequences.allocated_epoch+1,
             updated_at=clock_timestamp()
         RETURNING allocated_epoch",
    )
    .bind(user_id)
    .bind(device_id)
    .fetch_one(&mut **tx)
    .await?;
    sqlx::query(
        "INSERT INTO user_agent_login_epoch_stages
         (operation_id,connection_id,user_id,device_id,auth_generation,epoch,expires_at)
         VALUES($1,$2,$3,$4,$5,$6,
                clock_timestamp()+make_interval(secs=>$7))",
    )
    .bind(operation_id)
    .bind(connection_id)
    .bind(user_id)
    .bind(device_id)
    .bind(expected_auth_generation)
    .bind(epoch)
    .bind(ttl_seconds as f64)
    .execute(&mut **tx)
    .await?;
    Ok(Some(epoch))
}

/// Transactional form used to publish a login epoch and a replacement binding
/// lease in one post-transport commit.
pub(crate) async fn publish_user_agent_login_epoch_in_transaction(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    operation_id: Uuid,
    connection_id: Uuid,
    user_id: Uuid,
    device_id: Uuid,
    expected_auth_generation: i64,
    allow_binding_claim: bool,
) -> Result<Option<i64>> {
    let epoch = sqlx::query_scalar::<_, i64>(
        "SELECT stage.epoch
           FROM user_agent_login_epoch_stages stage
           JOIN users u ON u.id=stage.user_id
          WHERE stage.operation_id=$1 AND stage.connection_id=$2
            AND stage.user_id=$3 AND stage.device_id=$4
            AND stage.auth_generation=$5 AND stage.expires_at>clock_timestamp()
            AND NOT u.is_disabled AND u.auth_generation=stage.auth_generation
            AND (
                EXISTS (
                    SELECT 1 FROM deployment_session_leases lease
                     WHERE lease.connection_id=stage.connection_id
                       AND lease.user_id=stage.user_id
                       AND lease.lease_until>clock_timestamp()
                )
                OR ($6 AND EXISTS (
                    SELECT 1 FROM deployment_session_binding_claims claim
                     WHERE claim.connection_id=stage.connection_id
                       AND claim.user_id=stage.user_id
                       AND claim.expires_at>clock_timestamp()
                ))
            )
          FOR UPDATE OF stage,u",
    )
    .bind(operation_id)
    .bind(connection_id)
    .bind(user_id)
    .bind(device_id)
    .bind(expected_auth_generation)
    .bind(allow_binding_claim)
    .fetch_optional(&mut **tx)
    .await?;
    let Some(epoch) = epoch else {
        return Ok(None);
    };
    sqlx::query(
        "INSERT INTO user_agent_login_epochs(user_id,device_id,epoch)
         VALUES($1,$2,$3)
         ON CONFLICT(user_id,device_id) DO UPDATE
         SET epoch=GREATEST(user_agent_login_epochs.epoch,EXCLUDED.epoch),
             updated_at=clock_timestamp()",
    )
    .bind(user_id)
    .bind(device_id)
    .bind(epoch)
    .execute(&mut **tx)
    .await?;
    let deleted = sqlx::query(
        "DELETE FROM user_agent_login_epoch_stages
          WHERE operation_id=$1 AND connection_id=$2",
    )
    .bind(operation_id)
    .bind(connection_id)
    .execute(&mut **tx)
    .await?
    .rows_affected();
    anyhow::ensure!(
        deleted == 1,
        "staged login epoch publication fence was lost"
    );
    Ok(Some(epoch))
}

pub async fn cleanup_expired_user_agent_login_epoch_stages(
    pool: &PgPool,
    limit: i64,
) -> Result<u64> {
    Ok(sqlx::query(
        "DELETE FROM user_agent_login_epoch_stages WHERE operation_id IN (
             SELECT operation_id FROM user_agent_login_epoch_stages
              WHERE expires_at<=clock_timestamp()
              ORDER BY expires_at,operation_id LIMIT $1
         )",
    )
    .bind(limit.max(1))
    .execute(pool)
    .await?
    .rows_affected())
}

pub async fn user_agent_login_epochs(
    pool: &PgPool,
    agents: &[(Uuid, Uuid)],
) -> Result<HashMap<(Uuid, Uuid), i64>> {
    if agents.is_empty() {
        return Ok(HashMap::new());
    }
    let user_ids = agents.iter().map(|(user, _)| *user).collect::<Vec<_>>();
    let device_ids = agents.iter().map(|(_, device)| *device).collect::<Vec<_>>();
    let rows = sqlx::query(
        "SELECT epoch.user_id,epoch.device_id,epoch.epoch
         FROM user_agent_login_epochs epoch
         JOIN UNNEST($1::UUID[],$2::UUID[]) AS requested(user_id,device_id)
           ON requested.user_id=epoch.user_id AND requested.device_id=epoch.device_id",
    )
    .bind(user_ids)
    .bind(device_ids)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|row| ((row.get("user_id"), row.get("device_id")), row.get("epoch")))
        .collect())
}

struct PreparedScramUpgrade {
    sha256_salt: Vec<u8>,
    sha1_salt: Option<Vec<u8>>,
    sha256_iterations: u32,
    sha1_iterations: Option<u32>,
    sha256_stored_key: Vec<u8>,
    sha256_server_key: Vec<u8>,
    sha1_stored_key: Option<Vec<u8>>,
    sha1_server_key: Option<Vec<u8>>,
}

impl Drop for PreparedScramUpgrade {
    fn drop(&mut self) {
        self.sha256_salt.zeroize();
        self.sha1_salt.zeroize();
        self.sha256_stored_key.zeroize();
        self.sha256_server_key.zeroize();
        self.sha1_stored_key.zeroize();
        self.sha1_server_key.zeroize();
    }
}

pub struct PreparedLogin {
    pub user: User,
    expected_password_hash: Zeroizing<String>,
    scram_upgrade: Option<PreparedScramUpgrade>,
}

impl std::fmt::Debug for PreparedLogin {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PreparedLogin")
            .field("user_id", &self.user.id)
            .field("username", &self.user.username)
            .field("auth_generation", &self.user.auth_generation)
            .field("expected_password_hash", &"[REDACTED]")
            .field("scram_upgrade", &self.scram_upgrade.is_some())
            .finish()
    }
}

impl Drop for PreparedLogin {
    fn drop(&mut self) {
        self.expected_password_hash.zeroize();
        self.user.password_hash.zeroize();
    }
}

fn scram_upgrade_targets(
    stored_sha256: Option<u32>,
    sha256_floor: u32,
    stored_sha1: Option<u32>,
    sha1_floor: u32,
    configured: u32,
    sha1_enabled: bool,
) -> (u32, Option<u32>, bool) {
    let sha256 = stored_sha256
        .unwrap_or(configured)
        .max(configured)
        .max(sha256_floor);
    let sha1 = sha1_enabled.then(|| {
        stored_sha1
            .unwrap_or(configured)
            .max(configured)
            .max(sha1_floor)
    });
    let required = stored_sha256 != Some(sha256) || stored_sha1 != sha1;
    (sha256, sha1, required)
}

pub async fn prepare_login(
    pool: &PgPool,
    username: &str,
    password: &str,
    scram_iterations: u32,
    scram_sha1_enabled: bool,
) -> Result<Option<PreparedLogin>> {
    let Ok(username) = auth::normalize_username(username) else {
        return Ok(None);
    };
    // Bound the whole password-authentication request before its user lookup,
    // not only the Argon2 closure. Otherwise a random-username flood could
    // bypass the retained-work cap while consuming database connections.
    let password_work = crate::password_work::admit()
        .map_err(anyhow::Error::from)
        .context("password authentication admission failed")?;
    let Some(mut user) = find_user(pool, &username).await? else {
        let candidate = Zeroizing::new(password.to_owned());
        password_work
            .run(move || {
                auth::verify_against_dummy_hash(&candidate)
                    .context("dummy Argon2 verifier failed integrity validation")?;
                Ok(())
            })
            .await
            .map_err(anyhow::Error::from)
            .context("dummy password verification task failed")?;
        return Ok(None);
    };
    let stored_password_hash = std::mem::take(&mut user.password_hash);
    let hash = Zeroizing::new(stored_password_hash.as_str().to_owned());
    let candidate = Zeroizing::new(password.to_owned());
    // Treat each SCRAM family independently. The capability currently
    // replaces the complete SCRAM set atomically, so an update re-derives both
    // enabled families, but each keeps the greater of its own stored cost and
    // the configured floor. A SHA-1 compatibility update can therefore never
    // lower a stronger SHA-256 verifier (and vice versa).
    let (sha256_iterations, sha1_iterations, upgrade_required) = scram_upgrade_targets(
        user.scram_iterations,
        user.scram_iteration_floor,
        user.scram_sha1_iterations,
        user.scram_sha1_iteration_floor,
        scram_iterations,
        scram_sha1_enabled,
    );
    let sha256_salt = upgrade_required.then(auth::generate_scram_salt);
    let sha1_salt = (upgrade_required && scram_sha1_enabled).then(auth::generate_scram_salt);
    let is_disabled = user.is_disabled;
    // Verification and an optional SCRAM upgrade share one admission and one
    // blocking closure.  A login cannot consume two queue positions, and a
    // cancellation cannot release the active slot between the two CPU-heavy
    // phases while work is still running.
    let verified = password_work
        .run(move || {
            let password_matches = match auth::verify_password(&hash, &candidate) {
                Ok(password_matches) => password_matches,
                Err(error) => {
                    // A malformed or policy-violating stored verifier is an
                    // operator-visible integrity failure, but it must not be
                    // a cheap remote account oracle. Spend the same bounded
                    // Argon2 work as the unknown-user path before returning
                    // the typed error to the caller. The candidate and both
                    // verifiers remain Zeroizing for every exit path.
                    let _ = auth::verify_against_dummy_hash(&candidate);
                    return Err(anyhow::Error::new(error)
                        .context("stored Argon2 verifier failed integrity validation"));
                }
            };
            if !password_matches || is_disabled {
                return Ok(None);
            }
            let Some(sha256_salt) = sha256_salt else {
                return Ok(Some(None));
            };
            let (sha256_stored_key, sha256_server_key) =
                auth::compute_scram_sha256(&candidate, &sha256_salt, sha256_iterations);
            let sha1 = sha1_salt
                .as_deref()
                .zip(sha1_iterations)
                .map(|(salt, iterations)| auth::compute_scram_sha1(&candidate, salt, iterations));
            let (sha1_stored_key, sha1_server_key) = sha1
                .map(|(stored, server)| (Some(stored), Some(server)))
                .unwrap_or((None, None));
            Ok(Some(Some(PreparedScramUpgrade {
                sha256_salt,
                sha1_salt,
                sha256_iterations,
                sha1_iterations,
                sha256_stored_key,
                sha256_server_key,
                sha1_stored_key,
                sha1_server_key,
            })))
        })
        .await
        .map_err(anyhow::Error::from)
        .context("password verification task failed")?;
    let Some(scram_upgrade) = verified else {
        return Ok(None);
    };
    Ok(Some(PreparedLogin {
        user,
        expected_password_hash: stored_password_hash,
        scram_upgrade,
    }))
}

pub async fn apply_prepared_login_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    prepared: PreparedLogin,
) -> Result<bool> {
    let upgrade = prepared.scram_upgrade.as_ref();
    let iterations = upgrade
        .map(|upgrade| i32::try_from(upgrade.sha256_iterations))
        .transpose()?;
    let sha1_iterations = upgrade
        .and_then(|upgrade| upgrade.sha1_iterations)
        .map(i32::try_from)
        .transpose()?;
    sqlx::query_scalar::<_, bool>(
        "SELECT northstar_user_apply_login(
            $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)",
    )
    .bind(prepared.user.id)
    .bind(prepared.expected_password_hash.as_str())
    .bind(prepared.user.auth_generation)
    .bind(upgrade.map(|upgrade| &upgrade.sha256_salt))
    .bind(iterations)
    .bind(upgrade.map(|upgrade| &upgrade.sha256_stored_key))
    .bind(upgrade.map(|upgrade| &upgrade.sha256_server_key))
    .bind(upgrade.and_then(|upgrade| upgrade.sha1_salt.as_ref()))
    .bind(sha1_iterations)
    .bind(upgrade.and_then(|upgrade| upgrade.sha1_stored_key.as_ref()))
    .bind(upgrade.and_then(|upgrade| upgrade.sha1_server_key.as_ref()))
    .fetch_one(&mut **tx)
    .await
    .context("login publication capability failed")
}

const MAX_API_SESSIONS_PER_USER: i64 = 32;

#[cfg(test)]
pub async fn create_api_session(pool: &PgPool, user_id: Uuid, ttl_hours: i64) -> Result<String> {
    let mut tx = pool.begin().await?;
    let session = create_api_session_in_tx(&mut tx, user_id, ttl_hours, None).await?;
    tx.commit().await?;
    Ok(session.token)
}

pub struct CreatedApiSession {
    pub id: Uuid,
    pub token: String,
    pub token_hash: Vec<u8>,
    pub expires_at: DateTime<Utc>,
}

pub async fn create_api_session_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    user_id: Uuid,
    ttl_hours: i64,
    request_id: Option<Uuid>,
) -> Result<CreatedApiSession> {
    let token = auth::new_session_token();
    let token_hash = auth::token_hash(&token);
    let id = Uuid::new_v4();
    // Serialize session creation per account so concurrent successful logins
    // cannot race past the bounded-session invariant.
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1::text, 0))")
        .bind(user_id)
        .execute(&mut **tx)
        .await?;
    sqlx::query("DELETE FROM api_sessions WHERE user_id = $1 AND expires_at <= NOW()")
        .bind(user_id)
        .execute(&mut **tx)
        .await?;
    // Retain room for this new token before inserting it. PostgreSQL `NOW()`
    // is transaction-scoped, so pruning after insertion could otherwise drop
    // the just-created row when several lock waiters share close timestamps.
    sqlx::query(
        "DELETE FROM api_sessions WHERE user_id = $1 AND id NOT IN (SELECT id FROM api_sessions WHERE user_id = $1 ORDER BY created_at DESC, id DESC LIMIT $2)",
    )
    .bind(user_id)
    .bind(MAX_API_SESSIONS_PER_USER - 1)
    .execute(&mut **tx)
    .await?;
    let expires_at: DateTime<Utc> = sqlx::query_scalar(
        "INSERT INTO api_sessions (id,user_id,token_hash,expires_at)
         VALUES($1,$2,$3,clock_timestamp()+($4*INTERVAL '1 hour'))
         RETURNING expires_at",
    )
    .bind(id)
    .bind(user_id)
    .bind(&token_hash)
    .bind(ttl_hours)
    .fetch_one(&mut **tx)
    .await?;
    if let Some(request_id) = request_id {
        sqlx::query(
            "INSERT INTO audit_log(actor_id,action,target,details,request_id)
             VALUES($1,'user.session.login',$1::text,'{}'::jsonb,$2)",
        )
        .bind(user_id)
        .bind(request_id)
        .execute(&mut **tx)
        .await?;
    }
    Ok(CreatedApiSession {
        id,
        token,
        token_hash,
        expires_at,
    })
}

pub async fn user_for_token(pool: &PgPool, token: &str) -> Result<Option<ApiPrincipal>> {
    if token.len() != 64 || !token.bytes().all(|byte| byte.is_ascii_alphanumeric()) {
        return Ok(None);
    }
    let row = sqlx::query(
        "SELECT u.id,u.username,u.display_name,u.is_admin,u.auth_generation
           FROM users u JOIN api_sessions s ON s.user_id=u.id
          WHERE s.token_hash=$1 AND s.expires_at>clock_timestamp()
            AND NOT u.is_disabled",
    )
    .bind(auth::token_hash(token))
    .fetch_optional(pool)
    .await?;
    Ok(row.as_ref().map(api_principal_from_row))
}

pub async fn user_for_token_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    token: &str,
) -> Result<Option<ApiPrincipal>> {
    if token.len() != 64 || !token.bytes().all(|byte| byte.is_ascii_alphanumeric()) {
        return Ok(None);
    }
    let token_hash = auth::token_hash(token);
    // Discovering the owner is intentionally non-locking.  Every API
    // authorization path then takes row locks in one global order:
    // users -> api_sessions.  Password/status rotations already use that
    // order before deleting sessions.  A single JOIN with two row marks does
    // not make PostgreSQL's executor lock order an application invariant and
    // used to leave a users/session deadlock cycle with concurrent logout.
    let Some(user_id) = sqlx::query_scalar::<_, Uuid>(
        "SELECT user_id FROM api_sessions
         WHERE token_hash=$1 AND expires_at > clock_timestamp()",
    )
    .bind(&token_hash)
    .fetch_optional(&mut **tx)
    .await?
    else {
        return Ok(None);
    };
    let row = sqlx::query(
        "SELECT id,username,display_name,is_admin,auth_generation
           FROM users WHERE id=$1 AND NOT is_disabled FOR SHARE",
    )
    .bind(user_id)
    .fetch_optional(&mut **tx)
    .await?;
    let Some(row) = row else {
        return Ok(None);
    };
    let session_live = sqlx::query_scalar::<_, bool>(
        "SELECT TRUE FROM api_sessions
         WHERE user_id=$1 AND token_hash=$2
           AND expires_at > clock_timestamp()
         FOR SHARE",
    )
    .bind(user_id)
    .bind(&token_hash)
    .fetch_optional(&mut **tx)
    .await?
    .is_some();
    Ok(session_live.then(|| api_principal_from_row(&row)))
}

/// Resolve the exact bearer and load the Argon2 verifier only for a password
/// change. The same users -> api_sessions lock order as ordinary mutation
/// authorization prevents a concurrent revocation/status change from being
/// observed as a valid credential snapshot.
pub async fn password_change_subject_for_token_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    token: &str,
) -> Result<Option<PasswordChangeSubject>> {
    if token.len() != 64 || !token.bytes().all(|byte| byte.is_ascii_alphanumeric()) {
        return Ok(None);
    }
    let token_hash = auth::token_hash(token);
    let Some(user_id) = sqlx::query_scalar::<_, Uuid>(
        "SELECT user_id FROM api_sessions
         WHERE token_hash=$1 AND expires_at>clock_timestamp()",
    )
    .bind(&token_hash)
    .fetch_optional(&mut **tx)
    .await?
    else {
        return Ok(None);
    };
    let row = sqlx::query(
        "SELECT id,username,display_name,is_admin,auth_generation,password_hash
           FROM users WHERE id=$1 AND NOT is_disabled FOR SHARE",
    )
    .bind(user_id)
    .fetch_optional(&mut **tx)
    .await?;
    let Some(row) = row else {
        return Ok(None);
    };
    let session_live = sqlx::query_scalar::<_, bool>(
        "SELECT TRUE FROM api_sessions
         WHERE user_id=$1 AND token_hash=$2
           AND expires_at>clock_timestamp()
         FOR SHARE",
    )
    .bind(user_id)
    .bind(&token_hash)
    .fetch_optional(&mut **tx)
    .await?
    .is_some();
    Ok(session_live.then(|| PasswordChangeSubject {
        principal: api_principal_from_row(&row),
        password_hash: Zeroizing::new(row.get("password_hash")),
    }))
}

pub async fn delete_api_session_audited_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    token: &str,
    request_id: Uuid,
) -> Result<bool> {
    let token_hash = auth::token_hash(token);
    // Resolve without a row mark, then join the same users -> api_sessions
    // lock order as exact-bearer authorization and credential rotation.  The
    // DELETE below rechecks both values, so a concurrent revocation between
    // discovery and locking remains an idempotent no-op.
    let user_id =
        sqlx::query_scalar::<_, Uuid>("SELECT user_id FROM api_sessions WHERE token_hash=$1")
            .bind(&token_hash)
            .fetch_optional(&mut **tx)
            .await?;
    if let Some(user_id) = user_id {
        let user_exists =
            sqlx::query_scalar::<_, bool>("SELECT TRUE FROM users WHERE id=$1 FOR SHARE")
                .bind(user_id)
                .fetch_optional(&mut **tx)
                .await?
                .is_some();
        if !user_exists {
            return Ok(false);
        }
        let deleted = sqlx::query_scalar::<_, Uuid>(
            "DELETE FROM api_sessions
             WHERE token_hash=$1 AND user_id=$2 RETURNING user_id",
        )
        .bind(&token_hash)
        .bind(user_id)
        .fetch_optional(&mut **tx)
        .await?;
        if deleted.is_none() {
            return Ok(false);
        }
        sqlx::query(
            "INSERT INTO audit_log(actor_id,action,target,details,request_id)
             VALUES($1,'user.session.logout',$1::text,'{}'::jsonb,$2)",
        )
        .bind(user_id)
        .bind(request_id)
        .execute(&mut **tx)
        .await?;
        return Ok(true);
    }
    Ok(false)
}

/// Revalidate an administrator at the exact database serialization point of
/// an API mutation.  A user-row check alone is insufficient: a password
/// rotation or explicit logout may already have revoked the bearer which was
/// presented to the HTTP handler.
pub async fn authorize_admin_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    actor_id: Uuid,
    expected_auth_generation: i64,
    presented_session: &str,
) -> Result<bool> {
    if !authorize_user_in_tx(tx, actor_id, expected_auth_generation, presented_session).await? {
        return Ok(false);
    }
    Ok(
        sqlx::query_scalar::<_, bool>("SELECT is_admin FROM users WHERE id=$1 FOR SHARE")
            .bind(actor_id)
            .fetch_one(&mut **tx)
            .await?,
    )
}

/// Revalidate the exact bearer and credential generation observed by a user
/// mutation handler at its database serialization point.
pub async fn authorize_user_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    actor_id: Uuid,
    expected_auth_generation: i64,
    presented_session: &str,
) -> Result<bool> {
    if presented_session.len() != 64
        || !presented_session
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric())
    {
        return Ok(false);
    }
    let actor_live = sqlx::query_scalar::<_, bool>(
        "SELECT TRUE FROM users
         WHERE id=$1 AND auth_generation=$2 AND NOT is_disabled
         FOR SHARE",
    )
    .bind(actor_id)
    .bind(expected_auth_generation)
    .fetch_optional(&mut **tx)
    .await?
    .is_some();
    if !actor_live {
        return Ok(false);
    }
    Ok(sqlx::query_scalar::<_, bool>(
        "SELECT TRUE FROM api_sessions
         WHERE user_id=$1 AND token_hash=$2
           AND expires_at > clock_timestamp()
         FOR SHARE",
    )
    .bind(actor_id)
    .bind(auth::token_hash(presented_session))
    .fetch_optional(&mut **tx)
    .await?
    .is_some())
}

/// Make every durable SM bearer for an authorization-mutated account
/// immediately ineligible for resumption while retaining its presence/MUC
/// snapshot.  The post-commit disconnect path or the expiry maintenance
/// worker can then lease that row and complete unavailable/occupant teardown;
/// deleting it here would irreversibly lose those side effects on a crash.
#[cfg(test)]
pub(super) async fn expire_user_sm_sessions_in_transaction(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    user_id: Uuid,
) -> Result<()> {
    sqlx::query(
        "UPDATE sm_resume_sessions
         SET resumable=FALSE, live_lease_until=clock_timestamp(),
             expires_at=clock_timestamp(), updated_at=clock_timestamp()
         WHERE user_id=$1",
    )
    .bind(user_id)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum PasswordChangeOutcome {
    Changed,
    InvalidCurrentPassword,
    StaleAuthorization,
}

pub enum PreparedPasswordChange {
    InvalidCurrentPassword,
    Ready(auth::PasswordCredentials),
}

pub async fn prepare_password_change(
    expected_password_hash: &str,
    current_password: &str,
    new_password: &str,
    scram_iterations: u32,
    scram_sha1_enabled: bool,
) -> Result<PreparedPasswordChange> {
    let current_hash = Zeroizing::new(expected_password_hash.to_owned());
    let current_candidate = Zeroizing::new(current_password.to_owned());
    let password = Zeroizing::new(new_password.to_owned());
    let prepared = crate::password_work::run(move || {
        if !auth::verify_password(&current_hash, &current_candidate)
            .context("stored Argon2 verifier failed integrity validation")?
        {
            return Ok(PreparedPasswordChange::InvalidCurrentPassword);
        }
        auth::hash_password(&password, true, scram_iterations, scram_sha1_enabled)
            .map(PreparedPasswordChange::Ready)
    })
    .await
    .map_err(anyhow::Error::from)
    .context("password-change preparation task failed")?;
    Ok(prepared)
}

pub async fn authorize_password_change_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    user_id: Uuid,
    expected_password_hash: &str,
    expected_auth_generation: i64,
    presented_session: &str,
) -> Result<bool> {
    if presented_session.len() != 64
        || !presented_session
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric())
    {
        return Ok(false);
    }
    Ok(sqlx::query_scalar::<_, bool>(
        "SELECT TRUE
         FROM users AS actor
         JOIN api_sessions AS session ON session.user_id=actor.id
         WHERE actor.id=$1 AND actor.password_hash=$2
           AND actor.auth_generation=$3 AND NOT actor.is_disabled
           AND session.token_hash=$4
           AND session.expires_at > clock_timestamp()
         FOR UPDATE OF actor,session",
    )
    .bind(user_id)
    .bind(expected_password_hash)
    .bind(expected_auth_generation)
    .bind(auth::token_hash(presented_session))
    .fetch_optional(&mut **tx)
    .await?
    .is_some())
}

#[allow(clippy::too_many_arguments)]
pub async fn apply_prepared_password_change_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    user_id: Uuid,
    expected_password_hash: &str,
    expected_auth_generation: i64,
    presented_session: &str,
    prepared: PreparedPasswordChange,
    request_id: Option<Uuid>,
) -> Result<PasswordChangeOutcome> {
    let PreparedPasswordChange::Ready(creds) = prepared else {
        return Ok(PasswordChangeOutcome::InvalidCurrentPassword);
    };
    let scram_iterations = i32::try_from(creds.scram_iterations)?;
    let sha1_iterations = creds
        .scram_sha1_stored_key
        .as_ref()
        .map(|_| scram_iterations);
    let changed: bool = sqlx::query_scalar(
        "SELECT northstar_user_change_password_api(
            $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)",
    )
    .bind(user_id)
    .bind(expected_password_hash)
    .bind(expected_auth_generation)
    .bind(auth::token_hash(presented_session))
    .bind(&creds.hash)
    .bind(&creds.scram_salt)
    .bind(scram_iterations)
    .bind(&creds.scram_stored_key)
    .bind(&creds.scram_server_key)
    .bind(&creds.scram_sha1_salt)
    .bind(sha1_iterations)
    .bind(&creds.scram_sha1_stored_key)
    .bind(&creds.scram_sha1_server_key)
    .bind(request_id)
    .fetch_one(&mut **tx)
    .await?;
    if !changed {
        return Ok(PasswordChangeOutcome::StaleAuthorization);
    }
    Ok(PasswordChangeOutcome::Changed)
}

/// Change a password only if the exact password hash, credential generation,
/// and API bearer observed by the handler are still current. Password and
/// SCRAM derivation happens before the short transaction; the final row locks
/// turn the operation into a compare-and-swap with all bearer revocation and
/// audit writes in the same commit.
#[allow(clippy::too_many_arguments)]
#[cfg(test)]
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

/// Password rotation for an already-authorized XMPP stream. The XMPP
/// protocol layer owns that stream's credential-generation check; REST uses
/// `change_password_cas` because its bearer must also be locked and compared.
#[allow(clippy::too_many_arguments)]
pub async fn change_password_guarded_v2(
    pool: &PgPool,
    abuse: &AbuseGuard,
    subject: &str,
    actors: &[String],
    proof: Option<&PowProof>,
    intent: &crate::abuse::PowIntent,
    user_id: Uuid,
    expected_auth_generation: i64,
    new_password: &str,
    scram_iterations: u32,
    scram_sha1_enabled: bool,
) -> Result<std::result::Result<(), GuardError>> {
    // Reserve bounded CPU capacity before borrowing a database connection.
    // Proof consumption and the credential write remain one transaction, but
    // password-work queueing can no longer occupy the entire PgPool.
    let password_work = crate::password_work::reserve()
        .await
        .map_err(anyhow::Error::from)
        .context("password-change work admission failed")?;
    let mut tx = pool.begin().await?;
    match crate::db::abuse_transaction_repository::verify_in_tx(
        &mut tx,
        abuse,
        AbuseAction::PasswordChange,
        subject,
        actors,
        proof,
        Some(intent),
    )
    .await?
    {
        TransactionalGuardOutcome::Allowed => {
            // Invalid/missing proofs are rejected before Argon2/SCRAM work.
            // Keep the bounded worker inside this short authoritative
            // transaction so a rollback restores both proof and actor state.
            let password = Zeroizing::new(new_password.to_owned());
            let creds = password_work
                .run(move || {
                    auth::hash_password(&password, true, scram_iterations, scram_sha1_enabled)
                })
                .await
                .map_err(anyhow::Error::from)
                .context("password hashing task failed")?;
            let changed =
                apply_password_credentials_in_tx(&mut tx, user_id, expected_auth_generation, creds)
                    .await?;
            anyhow::ensure!(
                changed,
                "authenticated password-change generation became stale"
            );
            tx.commit().await?;
            Ok(Ok(()))
        }
        TransactionalGuardOutcome::DeniedNeedsCommit(error) => {
            // Challenge consumption and the penalty are intentional denial
            // state and must commit together; no credential write occurs.
            tx.commit().await?;
            Ok(Err(error))
        }
    }
}

#[cfg(test)]
pub async fn change_password(
    pool: &PgPool,
    user_id: Uuid,
    new_password: &str,
    scram_iterations: u32,
    scram_sha1_enabled: bool,
) -> Result<()> {
    let password = Zeroizing::new(new_password.to_owned());
    let creds = crate::password_work::run(move || {
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

async fn apply_password_credentials_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    user_id: Uuid,
    expected_auth_generation: i64,
    creds: auth::PasswordCredentials,
) -> Result<bool> {
    let scram_iterations = i32::try_from(creds.scram_iterations)?;
    let sha1_iterations = creds
        .scram_sha1_stored_key
        .as_ref()
        .map(|_| scram_iterations);
    sqlx::query_scalar(
        "SELECT northstar_user_change_password_stream(
            $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)",
    )
    .bind(user_id)
    .bind(expected_auth_generation)
    .bind(&creds.hash)
    .bind(&creds.scram_salt)
    .bind(scram_iterations)
    .bind(&creds.scram_stored_key)
    .bind(&creds.scram_server_key)
    .bind(&creds.scram_sha1_salt)
    .bind(sha1_iterations)
    .bind(&creds.scram_sha1_stored_key)
    .bind(&creds.scram_sha1_server_key)
    .fetch_one(&mut **tx)
    .await
    .context("stream password-change capability failed")
}

#[cfg(test)]
pub async fn set_user_status(
    pool: &PgPool,
    actor_id: Uuid,
    id: Uuid,
    disabled: Option<bool>,
    admin: Option<bool>,
) -> std::result::Result<(), UserStatusError> {
    let mut tx = pool
        .begin()
        .await
        .map_err(|error| UserStatusError::Internal(error.into()))?;
    // All administrator-role mutations share this transaction lock. It closes
    // the two-admin race where both requests could otherwise demote the other
    // after independently observing an enabled administrator.
    sqlx::query("SELECT pg_advisory_xact_lock(5645368709120101)")
        .execute(&mut *tx)
        .await
        .map_err(|error| UserStatusError::Internal(error.into()))?;
    set_user_status_in_tx(&mut tx, actor_id, id, disabled, admin, false).await?;
    tx.commit()
        .await
        .map_err(|error| UserStatusError::Internal(error.into()))?;
    Ok(())
}

#[cfg(test)]
pub async fn set_user_status_api(
    pool: &PgPool,
    actor_id: Uuid,
    actor_generation: i64,
    presented_session: &str,
    id: Uuid,
    disabled: Option<bool>,
    admin: Option<bool>,
) -> std::result::Result<(), UserStatusError> {
    let mut tx = pool
        .begin()
        .await
        .map_err(|error| UserStatusError::Internal(error.into()))?;
    sqlx::query("SELECT pg_advisory_xact_lock(5645368709120101)")
        .execute(&mut *tx)
        .await
        .map_err(|error| UserStatusError::Internal(error.into()))?;
    if !authorize_admin_in_tx(&mut tx, actor_id, actor_generation, presented_session)
        .await
        .map_err(UserStatusError::Internal)?
    {
        tx.rollback()
            .await
            .map_err(|error| UserStatusError::Internal(error.into()))?;
        return Err(UserStatusError::Unauthorized);
    }
    set_user_status_in_tx(&mut tx, actor_id, id, disabled, admin, true).await?;
    tx.commit()
        .await
        .map_err(|error| UserStatusError::Internal(error.into()))?;
    Ok(())
}

#[cfg(test)]
async fn set_user_status_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    actor_id: Uuid,
    id: Uuid,
    disabled: Option<bool>,
    admin: Option<bool>,
    enforce_api_self_rule: bool,
) -> std::result::Result<(), UserStatusError> {
    if enforce_api_self_rule && actor_id == id && (disabled == Some(true) || admin == Some(false)) {
        return Err(UserStatusError::SelfMutation);
    }
    let target = sqlx::query("SELECT is_admin, is_disabled FROM users WHERE id = $1 FOR UPDATE")
        .bind(id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(|error| UserStatusError::Internal(error.into()))?
        .ok_or(UserStatusError::NotFound)?;
    let was_enabled_admin =
        target.get::<bool, _>("is_admin") && !target.get::<bool, _>("is_disabled");
    let will_be_enabled_admin = admin.unwrap_or_else(|| target.get("is_admin"))
        && !disabled.unwrap_or_else(|| target.get("is_disabled"));
    if was_enabled_admin && !will_be_enabled_admin {
        let enabled_admins: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE is_admin AND NOT is_disabled")
                .fetch_one(&mut **tx)
                .await
                .map_err(|error| UserStatusError::Internal(error.into()))?;
        if enabled_admins <= 1 {
            return Err(UserStatusError::LastAdministrator);
        }
    }
    let result = sqlx::query(
        "UPDATE users
         SET is_disabled=COALESCE($2,is_disabled),
             is_admin=COALESCE($3,is_admin),
             auth_generation=auth_generation + CASE
               WHEN is_disabled IS DISTINCT FROM COALESCE($2,is_disabled)
                 OR is_admin IS DISTINCT FROM COALESCE($3,is_admin)
               THEN 1 ELSE 0 END
         WHERE id=$1",
    )
    .bind(id)
    .bind(disabled)
    .bind(admin)
    .execute(&mut **tx)
    .await
    .map_err(|error| UserStatusError::Internal(error.into()))?;
    let changed = target.get::<bool, _>("is_disabled")
        != disabled.unwrap_or_else(|| target.get("is_disabled"))
        || target.get::<bool, _>("is_admin") != admin.unwrap_or_else(|| target.get("is_admin"));
    if changed {
        expire_user_sm_sessions_in_transaction(tx, id)
            .await
            .map_err(UserStatusError::Internal)?;
        sqlx::query(
            "UPDATE fast_tokens SET revoked_at=NOW() WHERE user_id=$1 AND revoked_at IS NULL",
        )
        .bind(id)
        .execute(&mut **tx)
        .await
        .map_err(|error| UserStatusError::Internal(error.into()))?;
        // A disabled account must not regain old bearer sessions when an
        // administrator later re-enables it.
        sqlx::query("DELETE FROM api_sessions WHERE user_id = $1")
            .bind(id)
            .execute(&mut **tx)
            .await
            .map_err(|error| UserStatusError::Internal(error.into()))?;
    }
    if result.rows_affected() != 1 {
        return Err(UserStatusError::NotFound);
    }
    sqlx::query(
        "INSERT INTO audit_log (actor_id, action, target, details) VALUES ($1, 'admin.user.update', $2, $3)",
    )
    .bind(actor_id)
    .bind(id.to_string())
    .bind(serde_json::json!({"disabled": disabled, "admin": admin}))
    .execute(&mut **tx)
    .await
    .map_err(|error| UserStatusError::Internal(error.into()))?;
    Ok(())
}

pub async fn set_user_status_admin_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    actor_id: Uuid,
    actor_generation: i64,
    presented_session: &str,
    id: Uuid,
    disabled: Option<bool>,
    admin: Option<bool>,
) -> std::result::Result<i64, UserStatusError> {
    let outcome: i64 =
        sqlx::query_scalar("SELECT northstar_user_set_status_api($1,$2,$3,$4,$5,$6)")
            .bind(actor_id)
            .bind(actor_generation)
            .bind(auth::token_hash(presented_session))
            .bind(id)
            .bind(disabled)
            .bind(admin)
            .fetch_one(&mut **tx)
            .await
            .map_err(|error| UserStatusError::Internal(error.into()))?;
    match outcome {
        generation if generation >= 0 => Ok(generation),
        -1 => Err(UserStatusError::NotFound),
        -2 => Err(UserStatusError::Unauthorized),
        -3 => Err(UserStatusError::SelfMutation),
        -4 => Err(UserStatusError::LastAdministrator),
        _ => Err(UserStatusError::Internal(anyhow::anyhow!(
            "account-status capability returned unknown outcome {outcome}"
        ))),
    }
}

/// Replace the complete service-administrator set as one audited mutation.
/// The executing administrator must remain enabled and present in the new
/// set, which prevents both accidental lockout and a stale command session
/// from revoking its own authority mid-transaction.
#[cfg(test)]
pub async fn replace_admins(pool: &PgPool, actor_id: Uuid, admin_ids: &[Uuid]) -> Result<()> {
    anyhow::ensure!(!admin_ids.is_empty(), "administrator list cannot be empty");
    let mut ids = admin_ids.to_vec();
    ids.sort_unstable();
    ids.dedup();
    anyhow::ensure!(
        ids.contains(&actor_id),
        "executing administrator must remain listed"
    );

    let mut tx = pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(5645368709120101)")
        .execute(&mut *tx)
        .await?;
    let eligible: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE id=ANY($1) AND NOT is_disabled")
            .bind(&ids)
            .fetch_one(&mut *tx)
            .await?;
    anyhow::ensure!(
        eligible == ids.len() as i64,
        "administrator list contains an unavailable account"
    );
    let actor_authorized = sqlx::query_scalar::<_, bool>(
        "SELECT TRUE FROM users WHERE id=$1 AND is_admin AND NOT is_disabled FOR SHARE",
    )
    .bind(actor_id)
    .fetch_optional(&mut *tx)
    .await?;
    anyhow::ensure!(
        actor_authorized.is_some(),
        "administrator authorization changed"
    );

    let changed = sqlx::query_scalar::<_, Uuid>(
        "UPDATE users
         SET is_admin=(id=ANY($1)),
             auth_generation=auth_generation+1
         WHERE is_admin IS DISTINCT FROM (id=ANY($1))
         RETURNING id",
    )
    .bind(&ids)
    .fetch_all(&mut *tx)
    .await?;
    if !changed.is_empty() {
        sqlx::query("DELETE FROM api_sessions WHERE user_id=ANY($1)")
            .bind(&changed)
            .execute(&mut *tx)
            .await?;
        sqlx::query(
            "UPDATE sm_resume_sessions
             SET resumable=FALSE, live_lease_until=clock_timestamp(),
                 expires_at=clock_timestamp(), updated_at=clock_timestamp()
             WHERE user_id=ANY($1)",
        )
        .bind(&changed)
        .execute(&mut *tx)
        .await?;
    }
    sqlx::query(
        "INSERT INTO audit_log(actor_id,action,target,details)
         VALUES($1,'admin.list.replace',NULL,$2)",
    )
    .bind(actor_id)
    .bind(serde_json::json!({"admin_ids":ids,"changed_ids":changed}))
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(())
}

/// Terminate every current XMPP login while preserving the account and its
/// password.  Advancing the credential epoch makes the operation safe across
/// nodes and against delayed cluster controls; future password authentication
/// immediately observes the new epoch and may log in again.
#[cfg(test)]
pub async fn end_user_sessions(pool: &PgPool, actor_id: Uuid, user_id: Uuid) -> Result<bool> {
    let mut tx = pool.begin().await?;
    let changed = sqlx::query_scalar::<_, i64>(
        "UPDATE users SET auth_generation=auth_generation+1 WHERE id=$1 RETURNING auth_generation",
    )
    .bind(user_id)
    .fetch_optional(&mut *tx)
    .await?;
    if changed.is_none() {
        tx.rollback().await?;
        return Ok(false);
    }
    expire_user_sm_sessions_in_transaction(&mut tx, user_id).await?;
    sqlx::query("UPDATE fast_tokens SET revoked_at=clock_timestamp() WHERE user_id=$1 AND revoked_at IS NULL")
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        "INSERT INTO audit_log(actor_id,action,target,details)
         VALUES($1,'admin.user.sessions.end',$2,'{}'::jsonb)",
    )
    .bind(actor_id)
    .bind(user_id.to_string())
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(true)
}

/// Consume the exact v2 account-removal proof and establish the durable
/// deletion boundary in the same transaction.  A crash before commit restores
/// the one-use proof; a committed proof always has a disabled account and
/// revoked API/FAST credentials to recover from.
#[allow(clippy::too_many_arguments)]
pub async fn begin_account_deletion_quiesce_guarded_v2(
    pool: &PgPool,
    abuse: &AbuseGuard,
    subject: &str,
    actors: &[String],
    proof: Option<&PowProof>,
    intent: &crate::abuse::PowIntent,
    user_id: Uuid,
    expected_auth_generation: i64,
) -> Result<std::result::Result<bool, GuardError>> {
    let mut transaction = pool.begin().await?;
    match crate::db::abuse_transaction_repository::verify_in_tx(
        &mut transaction,
        abuse,
        AbuseAction::PasswordChange,
        subject,
        actors,
        proof,
        Some(intent),
    )
    .await?
    {
        TransactionalGuardOutcome::Allowed => {
            let found: bool = sqlx::query_scalar("SELECT northstar_user_quiesce_deletion($1,$2)")
                .bind(user_id)
                .bind(expected_auth_generation)
                .fetch_one(&mut *transaction)
                .await?;
            if !found {
                // No protected mutation exists, so do not burn a valid proof.
                transaction.rollback().await?;
                return Ok(Ok(false));
            }
            transaction.commit().await?;
            Ok(Ok(true))
        }
        TransactionalGuardOutcome::DeniedNeedsCommit(error) => {
            // A rejected one-use proof and its penalty are intentional durable
            // denial state; no account mutation was performed.
            transaction.commit().await?;
            Ok(Err(error))
        }
    }
}

#[cfg(test)]
async fn begin_account_deletion_quiesce_in_tx(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    user_id: Uuid,
) -> Result<bool> {
    let disabled =
        sqlx::query_scalar::<_, bool>("SELECT is_disabled FROM users WHERE id=$1 FOR UPDATE")
            .bind(user_id)
            .fetch_optional(&mut **transaction)
            .await?;
    let Some(disabled) = disabled else {
        return Ok(false);
    };
    if !disabled {
        sqlx::query(
            "UPDATE users SET is_disabled=TRUE, auth_generation=auth_generation+1 WHERE id=$1",
        )
        .bind(user_id)
        .execute(&mut **transaction)
        .await?;
    }
    sqlx::query("DELETE FROM api_sessions WHERE user_id=$1")
        .bind(user_id)
        .execute(&mut **transaction)
        .await?;
    sqlx::query(
        "UPDATE fast_tokens SET revoked_at=COALESCE(revoked_at,clock_timestamp()) WHERE user_id=$1",
    )
    .bind(user_id)
    .execute(&mut **transaction)
    .await?;
    sqlx::query(
        "INSERT INTO account_deletion_requests (user_id)
         VALUES ($1)
         ON CONFLICT (user_id) DO NOTHING",
    )
    .bind(user_id)
    .execute(&mut **transaction)
    .await?;
    Ok(true)
}

/// Test-only seam used by durable-SM recovery fixtures. Production callers
/// cannot bypass the guarded v2 proof/quiesce transaction above.
#[cfg(test)]
pub(crate) async fn begin_account_deletion_quiesce(pool: &PgPool, user_id: Uuid) -> Result<bool> {
    let mut transaction = pool.begin().await?;
    let found = begin_account_deletion_quiesce_in_tx(&mut transaction, user_id).await?;
    if !found {
        transaction.rollback().await?;
        return Ok(false);
    }
    transaction.commit().await?;
    Ok(true)
}

pub async fn counts_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
) -> Result<(i64, i64, i64)> {
    let users: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users")
        .fetch_one(&mut **tx)
        .await?;
    let archived: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM message_archive")
        .fetch_one(&mut **tx)
        .await?;
    let offline: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM offline_messages")
        .fetch_one(&mut **tx)
        .await?;
    Ok((users, archived, offline))
}

pub async fn operational_counts_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
) -> Result<(i64, i64, i64)> {
    let rooms = sqlx::query_scalar("SELECT COUNT(*) FROM muc_rooms WHERE destroyed_at IS NULL")
        .fetch_one(&mut **tx)
        .await?;
    let uploads = sqlx::query_scalar("SELECT northstar_upload_public_slot_count()")
        .fetch_one(&mut **tx)
        .await?;
    let push_subscriptions = sqlx::query_scalar("SELECT COUNT(*) FROM push_subscriptions")
        .fetch_one(&mut **tx)
        .await?;
    Ok((rooms, uploads, push_subscriptions))
}

#[cfg(test)]
pub async fn registrations_last_hour(pool: &PgPool) -> Result<i64> {
    Ok(sqlx::query_scalar(
        "SELECT COUNT(*) FROM users WHERE created_at >= NOW() - INTERVAL '1 hour'",
    )
    .fetch_one(pool)
    .await?)
}

pub async fn registrations_last_hour_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
) -> Result<i64> {
    Ok(sqlx::query_scalar(
        "SELECT COUNT(*) FROM users WHERE created_at >= NOW() - INTERVAL '1 hour'",
    )
    .fetch_one(&mut **tx)
    .await?)
}

pub type RemovedRosterItem = (String, Option<String>, String, Option<String>);

#[derive(Debug)]
pub struct RemovedAccount {
    pub roster: Vec<RemovedRosterItem>,
    /// Exact committed roster-version snapshots for affected local contacts.
    pub reverse_roster_changes: Vec<(Uuid, String, super::roster::RosterChange)>,
}

pub(super) struct AdminDeletionFence<'a> {
    pub actor_id: Uuid,
    pub actor_username: &'a str,
    pub actor_generation: i64,
    pub claim_token: &'a str,
    pub node: &'a str,
    pub target_digest: &'a [u8],
    pub complete_command: bool,
    pub result_payload: &'a str,
}

/// Atomically snapshot every presence relationship and permanently remove an
/// account. All involved local user rows are locked in UUID order, while
/// serializable isolation prevents a concurrent roster/FK insertion from
/// slipping in after the XEP-0077 cancellation snapshot. Account-owned state
/// cascades; room ownership and audit actors deliberately become NULL.
#[cfg(test)]
pub async fn delete_user_with_roster(
    pool: &PgPool,
    user_id: Uuid,
    domain: &str,
) -> Result<Option<RemovedAccount>> {
    delete_user_with_roster_inner(pool, user_id, domain, None).await
}

/// XEP-0077 account cancellation with an audit record committed by the same
/// serializable transaction. If either the audit insert or deletion fails,
/// neither side is allowed to survive independently.
pub async fn delete_user_with_roster_audited(
    pool: &PgPool,
    user_id: Uuid,
    domain: &str,
    details: serde_json::Value,
) -> Result<Option<RemovedAccount>> {
    delete_user_with_roster_inner(
        pool,
        user_id,
        domain,
        Some((user_id, "user.account.remove", details)),
    )
    .await
}

async fn delete_user_with_roster_inner(
    pool: &PgPool,
    user_id: Uuid,
    domain: &str,
    audit: Option<(Uuid, &'static str, serde_json::Value)>,
) -> Result<Option<RemovedAccount>> {
    let mut transaction = pool.begin().await?;
    // The account deletion and every local reverse-roster transition must
    // commit as one unit. SERIALIZABLE also turns a roster mutation racing the
    // initial contact discovery into a retryable transaction failure instead
    // of leaving a stale reverse subscription.
    sqlx::query("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE")
        .execute(&mut *transaction)
        .await?;
    // Global storage capacity always precedes every user/account row. Upload
    // cascade triggers update this ledger, so taking it after the user lock
    // would invert create-slot admission and permit a deadlock.
    // The capability is SQL-native NOWAIT as of migration 0131, so capacity
    // contention is an immediate 55P03 rather than an arbitrary short
    // timeout applied to every later account/roster mutation.
    if let Err(error) = sqlx::query("SELECT northstar_upload_capacity_lock()")
        .fetch_one(&mut *transaction)
        .await
    {
        transaction.rollback().await?;
        if matches!(&error, sqlx::Error::Database(db) if db.code().as_deref()==Some("55P03")) {
            return Err(anyhow::Error::from(error)
                .context("upload storage capacity busy; retry account deletion"));
        }
        return Err(error.into());
    }
    // After this transaction owns the ledger, retain the normal bounded
    // mutation budget for its many roster/upload rows. That operational bound
    // no longer controls capacity admission itself.
    sqlx::query("SET LOCAL lock_timeout='2s'")
        .execute(&mut *transaction)
        .await?;
    let local_rows = sqlx::query(
        "SELECT r.contact_jid, u.id, u.username
           FROM roster_items r
           JOIN users u ON u.username = split_part(r.contact_jid, '@', 1)
          WHERE r.owner_id = $1
            AND split_part(r.contact_jid, '@', 2) = $2
            AND position('/' in r.contact_jid) = 0",
    )
    .bind(user_id)
    .bind(domain)
    .fetch_all(&mut *transaction)
    .await?;
    let mut local_contacts = HashMap::new();
    let mut lock_ids = vec![user_id];
    for row in local_rows {
        let contact_jid: String = row.get("contact_jid");
        let contact_id: Uuid = row.get("id");
        let username: String = row.get("username");
        if contact_id != user_id {
            lock_ids.push(contact_id);
            local_contacts.insert(contact_jid, (contact_id, username));
        }
    }
    lock_ids.sort_unstable();
    lock_ids.dedup();
    let locked = sqlx::query_scalar::<_, Uuid>(
        "SELECT id FROM users WHERE id = ANY($1) ORDER BY id FOR UPDATE",
    )
    .bind(&lock_ids)
    .fetch_all(&mut *transaction)
    .await?;
    if !locked.contains(&user_id) {
        transaction.rollback().await?;
        return Ok(None);
    }
    let removed = delete_user_with_roster_locked_in_transaction(
        &mut transaction,
        user_id,
        domain,
        local_contacts,
        audit,
        None,
    )
    .await?;
    transaction.commit().await?;
    Ok(Some(removed))
}

/// Delete one account after the caller has locked the account and every local
/// reverse-roster peer. Keeping this unit transaction-agnostic lets an
/// administrative multi-account command use one SERIALIZABLE transaction for
/// the complete batch instead of committing a successful prefix.
pub(super) async fn delete_user_with_roster_locked_in_transaction(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    user_id: Uuid,
    domain: &str,
    local_contacts: HashMap<String, (Uuid, String)>,
    audit: Option<(Uuid, &'static str, serde_json::Value)>,
    admin_fence: Option<AdminDeletionFence<'_>>,
) -> Result<RemovedAccount> {
    let username: String = sqlx::query_scalar("SELECT username FROM users WHERE id=$1")
        .bind(user_id)
        .fetch_one(&mut **transaction)
        .await?;
    let rows = sqlx::query(
        "SELECT contact_jid, display_name, subscription, ask
           FROM roster_items WHERE owner_id = $1 ORDER BY contact_jid FOR UPDATE",
    )
    .bind(user_id)
    .fetch_all(&mut **transaction)
    .await?;
    let roster: Vec<RemovedRosterItem> = rows
        .iter()
        .map(|row| {
            (
                row.get("contact_jid"),
                row.get("display_name"),
                row.get("subscription"),
                row.get("ask"),
            )
        })
        .collect();
    let account = format!("{username}@{domain}");
    let account = crate::jid::canonicalize_bare(&account)?;
    let mut reverse_roster_changes = Vec::new();
    for (contact, _, subscription, _) in &roster {
        let Some((contact_id, contact_username)) = local_contacts.get(contact) else {
            continue;
        };
        let existing = sqlx::query_scalar::<_, String>(
            "SELECT subscription FROM roster_items WHERE owner_id=$1 AND contact_jid=$2 FOR UPDATE",
        )
        .bind(contact_id)
        .bind(&account)
        .fetch_optional(&mut **transaction)
        .await?;
        let Some(existing) = existing else {
            continue;
        };
        let without_deleted_subscriber = if matches!(subscription.as_str(), "to" | "both") {
            remove_subscription_direction(&existing, "from")
        } else {
            existing.clone()
        };
        let cancelled = if matches!(subscription.as_str(), "from" | "both") {
            remove_subscription_direction(&without_deleted_subscriber, "to")
        } else {
            without_deleted_subscriber
        };
        if cancelled != existing {
            let change = super::roster::update_subscription_in_transaction(
                transaction,
                *contact_id,
                &account,
                &cancelled,
                None,
                None,
            )
            .await?;
            reverse_roster_changes.push((*contact_id, contact_username.clone(), change));
        }
    }
    #[cfg(test)]
    let unaudited_test_delete = audit.is_none();
    if let Some((actor_id, action, details)) = audit {
        sqlx::query(
            "INSERT INTO audit_log (actor_id, action, target, details) VALUES ($1,$2,$3,$4)",
        )
        .bind(actor_id)
        .bind(action)
        .bind(&account)
        .bind(details)
        .execute(&mut **transaction)
        .await?;
    }
    // Generic PubSub stores JIDs because subscribers and co-owners may be
    // federated, so these rows cannot use a direct users(id) foreign key.
    // Account deletion is therefore the ownership boundary for local JIDs.
    // Delete creator-owned and otherwise-ownerless nodes first so all node
    // items, edges and node-scoped rows disappear through their FKs.
    sqlx::query(
        "DELETE FROM pubsub_nodes n
          WHERE n.creator_jid = $1
             OR (EXISTS (
                    SELECT 1 FROM pubsub_affiliations mine
                     WHERE mine.node_id = n.id AND mine.jid = $1
                       AND mine.affiliation = 'owner'
                 ) AND NOT EXISTS (
                    SELECT 1 FROM pubsub_affiliations other
                     WHERE other.node_id = n.id AND other.jid <> $1
                       AND other.affiliation = 'owner'
                 ))",
    )
    .bind(&account)
    .execute(&mut **transaction)
    .await?;
    // Digest rows deliberately are not coupled to a subscription FK because
    // they are a durable delivery queue. Remove them explicitly before the
    // subscription identity is removed, including resource subscriptions.
    sqlx::query("DELETE FROM pubsub_digest_queue WHERE split_part(subscriber_jid, '/', 1) = $1")
        .bind(&account)
        .execute(&mut **transaction)
        .await?;
    sqlx::query("DELETE FROM pubsub_subscriptions WHERE split_part(jid, '/', 1) = $1")
        .bind(&account)
        .execute(&mut **transaction)
        .await?;
    sqlx::query("DELETE FROM pubsub_affiliations WHERE jid = $1")
        .bind(&account)
        .execute(&mut **transaction)
        .await?;
    sqlx::query(
        "UPDATE pubsub_nodes
            SET children_association_whitelist = array_remove(children_association_whitelist, $1),
                updated_at = NOW()
          WHERE $1 = ANY(children_association_whitelist)",
    )
    .bind(&account)
    .execute(&mut **transaction)
    .await?;
    // Admission rows deliberately do not have a users FK: their canonical
    // actor/target scopes may name a remote principal, while their durable
    // archive, C2S, and S2S projections must survive ordinary retention.
    // That projection-preservation rule used to leave a replay tombstone
    // behind when an account's archive cascaded during deletion.  Account
    // deletion is a different authority boundary: remove every admission
    // whose canonical personal-message scope belongs to this account before
    // deleting its projections.  The user row is already exclusively locked,
    // so concurrent durable admissions either commit before this transaction
    // or observe the disabled/deleted account; the surrounding transaction
    // also restores these rows if a later teardown step fails.
    // The scope lookup indexes use a fixed-width domain-separated digest;
    // retain the exact canonical comparison so an MD5 collision cannot erase
    // another principal's admission. Lock IDs in one total order before the
    // delete: two simultaneous account removals for opposite ends of the same
    // conversation then contend/retry rather than lock the same rows in
    // actor-vs-target order.
    let admission_ids = sqlx::query_scalar::<_, Uuid>(
        "SELECT admission.id
           FROM personal_message_admissions admission
          WHERE (
                    pg_catalog.md5('northstar:personal-admission-scope:v1:' || admission.actor_scope)
                      = pg_catalog.md5('northstar:personal-admission-scope:v1:' || $1)
                AND admission.actor_scope=$1
                )
             OR (
                    pg_catalog.md5('northstar:personal-admission-scope:v1:' || admission.target_scope)
                      = pg_catalog.md5('northstar:personal-admission-scope:v1:' || $1)
                AND admission.target_scope=$1
                )
          ORDER BY admission.id
          FOR UPDATE",
    )
    .bind(&account)
    .fetch_all(&mut **transaction)
    .await?;
    if !admission_ids.is_empty() {
        sqlx::query("DELETE FROM personal_message_admissions WHERE id = ANY($1)")
            .bind(&admission_ids)
            .execute(&mut **transaction)
            .await?;
    }
    super::cluster_muc::revoke_cluster_muc_account_in_tx(transaction, user_id, &account).await?;
    let deletion: Result<()> = if let Some(fence) = admin_fence {
        let outcome: String = sqlx::query_scalar(
            "SELECT northstar_admin_command_delete_user(
              $1,$2,$3,$4,$5,$6,$7,$8,$9,$10)",
        )
        .bind(fence.claim_token)
        .bind(fence.actor_id)
        .bind(fence.actor_username)
        .bind(fence.actor_generation)
        .bind(fence.node)
        .bind(fence.target_digest)
        .bind(user_id)
        .bind(&username)
        .bind(fence.complete_command)
        .bind(fence.result_payload)
        .fetch_one(&mut **transaction)
        .await?;
        anyhow::ensure!(
            outcome == "applied",
            "administrative account-delete capability returned {outcome:?}"
        );
        Ok(())
    } else {
        #[cfg(test)]
        if unaudited_test_delete {
            return sqlx::query("DELETE FROM users WHERE id=$1")
                .bind(user_id)
                .execute(&mut **transaction)
                .await
                .map(|_| RemovedAccount {
                    roster,
                    reverse_roster_changes,
                })
                .map_err(Into::into);
        }
        let deleted: bool = sqlx::query_scalar("SELECT northstar_user_delete_quiesced($1,$2)")
            .bind(user_id)
            .bind(&username)
            .fetch_one(&mut **transaction)
            .await?;
        anyhow::ensure!(deleted, "account is not durably quiesced for deletion");
        Ok(())
    };
    deletion?;
    Ok(RemovedAccount {
        roster,
        reverse_roster_changes,
    })
}

fn remove_subscription_direction(current: &str, direction: &str) -> String {
    match (current, direction) {
        ("both", "to") => "from",
        ("both", "from") => "to",
        ("to", "to") | ("from", "from") => "none",
        _ => current,
    }
    .to_owned()
}

fn user_from_row(row: &sqlx::postgres::PgRow) -> User {
    let mut salt = row.get::<Option<Vec<u8>>, _>("scram_sha256_salt");
    let iterations = row
        .get::<Option<i32>, _>("scram_sha256_iterations")
        .and_then(|iterations| u32::try_from(iterations).ok());
    let mut stored_key = row.get::<Option<Vec<u8>>, _>("scram_sha256_stored_key");
    let mut server_key = row.get::<Option<Vec<u8>>, _>("scram_sha256_server_key");
    let scram_iterations = match (
        salt.as_deref(),
        iterations,
        stored_key.as_deref(),
        server_key.as_deref(),
    ) {
        (Some(salt), Some(iterations), Some(stored_key), Some(server_key))
            if !salt.is_empty()
                && (auth::MIN_SCRAM_ITERATIONS..=auth::MAX_SCRAM_ITERATIONS)
                    .contains(&iterations)
                && stored_key.len() == 32
                && server_key.len() == 32 =>
        {
            Some(iterations)
        }
        _ => None,
    };
    salt.zeroize();
    stored_key.zeroize();
    server_key.zeroize();
    let mut sha1_salt = row.get::<Option<Vec<u8>>, _>("scram_sha1_salt");
    let sha1_iterations = row
        .get::<Option<i32>, _>("scram_sha1_iterations")
        .and_then(|iterations| u32::try_from(iterations).ok());
    let mut sha1_stored_key = row.get::<Option<Vec<u8>>, _>("scram_sha1_stored_key");
    let mut sha1_server_key = row.get::<Option<Vec<u8>>, _>("scram_sha1_server_key");
    let scram_sha1_iterations = match (
        sha1_salt.as_deref(),
        sha1_iterations,
        sha1_stored_key.as_deref(),
        sha1_server_key.as_deref(),
    ) {
        (Some(salt), Some(iterations), Some(stored_key), Some(server_key))
            if !salt.is_empty()
                && (auth::MIN_SCRAM_ITERATIONS..=auth::MAX_SCRAM_ITERATIONS)
                    .contains(&iterations)
                && stored_key.len() == auth::ScramAlgorithm::Sha1.key_len()
                && server_key.len() == auth::ScramAlgorithm::Sha1.key_len() =>
        {
            Some(iterations)
        }
        _ => None,
    };
    let scram_iteration_floor = row
        .get::<i32, _>("scram_sha256_iteration_floor")
        .try_into()
        .unwrap_or(auth::MIN_SCRAM_ITERATIONS);
    let scram_sha1_iteration_floor = row
        .get::<i32, _>("scram_sha1_iteration_floor")
        .try_into()
        .unwrap_or(auth::MIN_SCRAM_ITERATIONS);
    sha1_salt.zeroize();
    sha1_stored_key.zeroize();
    sha1_server_key.zeroize();
    User {
        id: row.get("id"),
        username: row.get("username"),
        password_hash: Zeroizing::new(row.get("password_hash")),
        scram_iterations,
        scram_iteration_floor,
        scram_sha1_iterations,
        scram_sha1_iteration_floor,
        display_name: row.get("display_name"),
        is_admin: row.get("is_admin"),
        is_disabled: row.get("is_disabled"),
        auth_generation: row.get("auth_generation"),
        created_at: row.get("created_at"),
        last_login_at: row.get("last_login_at"),
    }
}

fn api_principal_from_row(row: &sqlx::postgres::PgRow) -> ApiPrincipal {
    ApiPrincipal {
        id: row.get("id"),
        username: row.get("username"),
        display_name: row.get("display_name"),
        is_admin: row.get("is_admin"),
        auth_generation: row.get("auth_generation"),
    }
}

pub async fn cleanup_expired_sessions(pool: &sqlx::PgPool) -> anyhow::Result<u64> {
    let res = sqlx::query("DELETE FROM api_sessions WHERE expires_at <= NOW()")
        .execute(pool)
        .await?;
    Ok(res.rows_affected())
}

#[cfg(test)]
#[path = "users_tests.rs"]
mod tests;
