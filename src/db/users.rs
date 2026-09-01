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

/// Verifier-free identity/status projection for REST bearer authorization.
/// Password and SCRAM material is structurally absent, so ordinary API
/// requests cannot accidentally retain reusable credential verifiers.
#[derive(Clone, Debug)]
pub struct ApiPrincipal {
    pub id: Uuid,
    pub username: String,
    pub display_name: Option<String>,
    pub is_admin: bool,
    pub auth_generation: i64,
}

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
        let decision = abuse
            .verify_or_allow_in_tx_v2(
                tx,
                AbuseAction::Registration,
                subject,
                actors,
                proof,
                intent,
            )
            .await?;
        match decision {
            TransactionalGuardOutcome::Allowed(_) => {}
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
    let locked = sqlx::query_scalar::<_, Uuid>(
        "SELECT id FROM users
          WHERE id=ANY($1) AND NOT is_disabled
          ORDER BY id FOR SHARE",
    )
    .bind(&user_ids)
    .fetch_all(&mut **transaction)
    .await?;
    Ok(locked.len() == user_ids.len())
}

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
    let eligible = sqlx::query_scalar::<_, bool>(
        "SELECT TRUE FROM users
         WHERE id=$1 AND auth_generation=$2 AND NOT is_disabled FOR SHARE",
    )
    .bind(user_id)
    .bind(expected_generation)
    .fetch_optional(&mut *tx)
    .await?;
    if eligible.is_none() {
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
    match abuse
        .verify_or_allow_in_tx_v2(
            &mut tx,
            AbuseAction::PasswordChange,
            subject,
            actors,
            proof,
            intent,
        )
        .await?
    {
        TransactionalGuardOutcome::Allowed(_) => {
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
    match abuse
        .verify_or_allow_in_tx_v2(
            &mut transaction,
            AbuseAction::PasswordChange,
            subject,
            actors,
            proof,
            intent,
        )
        .await?
    {
        TransactionalGuardOutcome::Allowed(_) => {
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
    sqlx::query("SET LOCAL lock_timeout='50ms'")
        .execute(&mut *transaction)
        .await?;
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
    // The 50 ms bound above is only the fail-fast admission budget for the
    // global ledger. Once this transaction owns that first lock, keeping the
    // same budget for every roster/upload cascade lock makes a large account
    // practically undeletable under ordinary short-lived contention. Restore
    // the normal bounded mutation budget while preserving ledger-first order.
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
mod tests {
    use super::*;

    #[test]
    fn authentication_verifiers_are_redacted_from_debug_output() {
        let verifier = "$argon2id$verifier-that-must-not-reach-a-log";
        let user = User {
            id: Uuid::nil(),
            username: "alice".to_owned(),
            password_hash: Zeroizing::new(verifier.to_owned()),
            scram_iterations: Some(600_000),
            scram_iteration_floor: 600_000,
            scram_sha1_iterations: None,
            scram_sha1_iteration_floor: auth::MIN_SCRAM_ITERATIONS,
            display_name: None,
            is_admin: false,
            is_disabled: false,
            auth_generation: 3,
            created_at: Utc::now(),
            last_login_at: None,
        };
        let formatted = format!("{user:?}");
        assert!(!formatted.contains(verifier));
        assert!(!formatted.contains("password_hash"));

        let scram_secret = vec![0xa5; 32];
        let credentials = ScramCredentials {
            salt: vec![0x51; 32],
            iterations: 600_000,
            stored_key: scram_secret.clone(),
            server_key: scram_secret,
        };
        let formatted = format!("{credentials:?}");
        assert!(formatted.contains("stored_key_bytes: 32"));
        assert!(!formatted.contains("165"));
    }

    #[test]
    fn scram_family_upgrade_targets_never_lower_existing_costs() {
        let (sha256, sha1, required) = scram_upgrade_targets(
            Some(1_000_000),
            1_000_000,
            None,
            auth::MIN_SCRAM_ITERATIONS,
            600_000,
            true,
        );
        assert_eq!(sha256, 1_000_000);
        assert_eq!(sha1, Some(600_000));
        assert!(required);

        let (sha256, sha1, required) = scram_upgrade_targets(
            Some(600_000),
            600_000,
            Some(1_000_000),
            1_000_000,
            700_000,
            true,
        );
        assert_eq!(sha256, 700_000);
        assert_eq!(sha1, Some(1_000_000));
        assert!(required);

        let (_, sha1, required) = scram_upgrade_targets(
            Some(600_000),
            600_000,
            Some(900_000),
            900_000,
            600_000,
            false,
        );
        assert_eq!(sha1, None);
        assert!(required);
    }

    #[tokio::test]
    #[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
    async fn login_publication_preserves_each_scram_family_across_rolling_configuration() {
        let url = std::env::var("TEST_DATABASE_URL")
            .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(4)
            .connect(&url)
            .await
            .unwrap();
        crate::db::migrate(&pool).await.unwrap();

        let suffix = Uuid::new_v4().simple().to_string();
        let username = format!("rollscram{}", &suffix[..10]);
        let password = "rolling SCRAM configuration password";
        let account = create_user(
            &pool,
            &username,
            password,
            false,
            false,
            auth::MIN_SCRAM_ITERATIONS,
            true,
        )
        .await
        .unwrap();

        // Establish valid but intentionally independent family histories:
        // SHA-256 is already at 10k while compatibility SHA-1 is at 4,096.
        let sha256_salt = auth::generate_scram_salt();
        let (sha256_stored_key, sha256_server_key) =
            auth::compute_scram_sha256(password, &sha256_salt, 10_000);
        sqlx::query(
            "UPDATE users
                SET scram_sha256_salt=$2,scram_sha256_iterations=$3,
                    scram_sha256_stored_key=$4,scram_sha256_server_key=$5
              WHERE id=$1",
        )
        .bind(account.id)
        .bind(sha256_salt)
        .bind(10_000_i32)
        .bind(sha256_stored_key)
        .bind(sha256_server_key)
        .execute(&pool)
        .await
        .unwrap();

        // Both nodes finish password work before either publishes. The newer
        // node raises only SHA-1 to 8k (SHA-256 remains 10k); the older node's
        // otherwise-valid 6k publication must then lose under the row lock.
        let newer = prepare_login(&pool, &username, password, 8_000, true)
            .await
            .unwrap()
            .unwrap();
        let older = prepare_login(&pool, &username, password, 6_000, true)
            .await
            .unwrap()
            .unwrap();
        let mut newer_tx = pool.begin().await.unwrap();
        assert!(apply_prepared_login_in_tx(&mut newer_tx, newer)
            .await
            .unwrap());
        newer_tx.commit().await.unwrap();

        let mut older_tx = pool.begin().await.unwrap();
        let error = apply_prepared_login_in_tx(&mut older_tx, older)
            .await
            .unwrap_err();
        older_tx.rollback().await.unwrap();
        assert!(
            format!("{error:#}").contains("invalid or downgraded SCRAM login upgrade"),
            "{error:#}"
        );
        let iterations: (i32, i32) = sqlx::query_as(
            "SELECT scram_sha256_iterations,scram_sha1_iterations
               FROM users WHERE id=$1",
        )
        .bind(account.id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(iterations, (10_000, 8_000));

        // A compatibility-off node may deliberately clear SHA-1. The durable
        // high-water mark survives, and an older compatibility-on node derives
        // the missing verifier at 8k rather than recreating it at its 6k
        // configured floor.
        clear_scram_sha1_credentials(&pool).await.unwrap();
        let cleared = find_user_by_id(&pool, account.id).await.unwrap().unwrap();
        assert_eq!(cleared.scram_sha1_iterations, None);
        assert_eq!(cleared.scram_sha1_iteration_floor, 8_000);
        let rebuilt = prepare_login(&pool, &username, password, 6_000, true)
            .await
            .unwrap()
            .unwrap();
        let mut rebuild_tx = pool.begin().await.unwrap();
        assert!(apply_prepared_login_in_tx(&mut rebuild_tx, rebuilt)
            .await
            .unwrap());
        rebuild_tx.commit().await.unwrap();
        let rebuilt_iterations: (i32, i32) = sqlx::query_as(
            "SELECT scram_sha256_iterations,scram_sha1_iterations
               FROM users WHERE id=$1",
        )
        .bind(account.id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(rebuilt_iterations, (10_000, 8_000));
    }

    fn solve_pow(challenge: &crate::abuse::PowChallenge) -> crate::abuse::PowProof {
        use sha2::{Digest, Sha256};

        let target = u64::MAX / challenge.requirement.work_factor.max(1);
        for nonce in 0_u64.. {
            let nonce = nonce.to_string();
            let mut hasher = Sha256::new();
            hasher.update(challenge.prefix.as_bytes());
            hasher.update(nonce.as_bytes());
            let digest = hasher.finalize();
            if u64::from_be_bytes(digest[..8].try_into().unwrap()) <= target {
                return crate::abuse::PowProof {
                    challenge_id: challenge.challenge_id,
                    nonce,
                };
            }
        }
        unreachable!()
    }

    #[tokio::test]
    #[ignore = "requires TEST_DATABASE_URL pointing at a disposable random PostgreSQL schema"]
    async fn scram_families_hide_unknown_and_disabled_accounts_but_surface_corruption() {
        let url = std::env::var("TEST_DATABASE_URL")
            .expect("set TEST_DATABASE_URL to a disposable random PostgreSQL schema");
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(4)
            .connect(&url)
            .await
            .unwrap();
        crate::db::migrate(&pool).await.unwrap();
        crate::db::upload::validate_upload_capacity_policy(&pool, 128, 10_000, 1024 * 1024 * 1024)
            .await
            .unwrap();

        let suffix = Uuid::new_v4().simple().to_string();
        let username = format!("scramdb{}", &suffix[..12]);
        let unknown = format!("missing{}", &suffix[..12]);
        let user = create_user(
            &pool,
            &username,
            "independent-scram-family-test-password",
            false,
            false,
            auth::MIN_SCRAM_ITERATIONS,
            true,
        )
        .await
        .unwrap();
        assert_eq!(
            enabled_user_id(&pool, &username).await.unwrap(),
            Some(user.id)
        );
        let enabled = find_enabled_user(&pool, &username).await.unwrap().unwrap();
        assert_eq!(enabled.id, user.id);
        assert_eq!(enabled.username, username);
        assert_eq!(
            find_enabled_user_by_id(&pool, user.id)
                .await
                .unwrap()
                .map(|account| account.id),
            Some(user.id)
        );

        for algorithm in [auth::ScramAlgorithm::Sha256, auth::ScramAlgorithm::Sha1] {
            let credentials = get_scram_credentials(&pool, &username, algorithm)
                .await
                .unwrap()
                .expect("new accounts have both independent SCRAM verifiers");
            assert_eq!(credentials.stored_key.len(), algorithm.key_len());
            assert_eq!(credentials.server_key.len(), algorithm.key_len());
            assert!(!credentials.salt.is_empty());
            assert_eq!(credentials.iterations, auth::MIN_SCRAM_ITERATIONS);
            assert!(get_scram_credentials(&pool, &unknown, algorithm)
                .await
                .unwrap()
                .is_none());
        }

        sqlx::query("UPDATE users SET is_disabled=TRUE WHERE id=$1")
            .bind(user.id)
            .execute(&pool)
            .await
            .unwrap();
        assert!(enabled_user_id(&pool, &username).await.unwrap().is_none());
        assert!(find_enabled_user(&pool, &username).await.unwrap().is_none());
        assert!(find_enabled_user_by_id(&pool, user.id)
            .await
            .unwrap()
            .is_none());
        for algorithm in [auth::ScramAlgorithm::Sha256, auth::ScramAlgorithm::Sha1] {
            assert!(get_scram_credentials(&pool, &username, algorithm)
                .await
                .unwrap()
                .is_none());
        }

        sqlx::query(
            "UPDATE users
                SET is_disabled=FALSE,
                    scram_sha1_server_key=NULL
              WHERE id=$1",
        )
        .bind(user.id)
        .execute(&pool)
        .await
        .unwrap();
        let partial = get_scram_credentials(&pool, &username, auth::ScramAlgorithm::Sha1)
            .await
            .unwrap_err()
            .to_string();
        assert!(partial.contains("incomplete"), "{partial}");

        sqlx::query(
            "UPDATE users
                SET scram_sha1_salt=NULL,scram_sha1_iterations=NULL,
                    scram_sha1_stored_key=NULL,scram_sha1_server_key=NULL
              WHERE id=$1",
        )
        .bind(user.id)
        .execute(&pool)
        .await
        .unwrap();
        assert!(
            get_scram_credentials(&pool, &username, auth::ScramAlgorithm::Sha1)
                .await
                .unwrap()
                .is_none()
        );

        sqlx::query(
            "UPDATE users
                SET scram_sha1_salt=decode(repeat('11',32),'hex'),
                    scram_sha1_iterations=$2,
                    scram_sha1_stored_key=decode(repeat('00',20),'hex'),
                    scram_sha1_server_key=decode(repeat('00',20),'hex'),
                    scram_sha256_stored_key=decode(repeat('00',31),'hex')
              WHERE id=$1",
        )
        .bind(user.id)
        .bind(i32::try_from(auth::MIN_SCRAM_ITERATIONS).unwrap())
        .execute(&pool)
        .await
        .unwrap();
        let invalid = get_scram_credentials(&pool, &username, auth::ScramAlgorithm::Sha256)
            .await
            .unwrap_err()
            .to_string();
        assert!(invalid.contains("invalid"), "{invalid}");
    }

    fn password_idempotency_request<'a>(
        token: &'a str,
        key: &'a str,
        body: &[u8],
    ) -> crate::db::IdempotencyRequest<'a> {
        crate::db::IdempotencyRequest {
            request_id: Uuid::new_v4(),
            actor_id: None,
            principal_scope: token.as_bytes(),
            capacity_scope: token.as_bytes(),
            target_scope: b"",
            principal_kind: crate::db::ApiPrincipalKind::User,
            method: "PATCH",
            route: "/api/v1/me/password",
            idempotency_key: key,
            request_fingerprint: crate::db::api_request_fingerprint("application/json", body),
            ttl_seconds: 3600,
            lease_seconds: 180,
        }
    }

    fn acquired(outcome: crate::db::IdempotencyAcquire) -> crate::db::IdempotencyLease {
        match outcome {
            crate::db::IdempotencyAcquire::Acquired(lease) => lease,
            other => panic!("expected acquired idempotency lease, got {other:?}"),
        }
    }

    #[tokio::test]
    #[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
    async fn concurrent_registration_cannot_exceed_the_global_hourly_limit() {
        let url = std::env::var("TEST_DATABASE_URL")
            .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(8)
            .connect(&url)
            .await
            .unwrap();
        crate::db::migrate(&pool).await.unwrap();
        crate::db::initialize_admin_runtime_settings(&pool, false, false)
            .await
            .unwrap();

        let existing = registrations_last_hour(&pool).await.unwrap();
        let limit = u32::try_from(existing + 2).unwrap();
        let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(5));
        let suffix = Uuid::new_v4().simple().to_string();
        let mut tasks = Vec::new();
        for index in 0..4 {
            let pool = pool.clone();
            let barrier = std::sync::Arc::clone(&barrier);
            let username = format!("r{index}{}", &suffix[..10]);
            tasks.push(tokio::spawn(async move {
                barrier.wait().await;
                create_user_with_invitation(
                    &pool,
                    &username,
                    "registration-test-password",
                    None,
                    false,
                    limit,
                    auth::MIN_SCRAM_ITERATIONS,
                )
                .await
            }));
        }
        barrier.wait().await;

        let mut created = Vec::new();
        let mut limited = 0;
        for task in tasks {
            match task.await.unwrap() {
                Ok(user) => created.push(user.id),
                Err(RegistrationError::RateLimited) => limited += 1,
                Err(error) => panic!("unexpected registration error: {error}"),
            }
        }
        assert_eq!(created.len(), 2);
        assert_eq!(limited, 2);
        assert_eq!(registrations_last_hour(&pool).await.unwrap(), existing + 2);

        sqlx::query("DELETE FROM users WHERE id = ANY($1)")
            .bind(&created)
            .execute(&pool)
            .await
            .unwrap();
    }

    #[tokio::test]
    #[ignore = "requires TEST_DATABASE_URL pointing at a disposable random PostgreSQL schema"]
    async fn guarded_registration_rolls_back_and_replays_proof_invitation_user_and_audit() {
        use crate::abuse::{AbuseConfig, AbuseGuard};
        use std::time::Duration;

        let url = std::env::var("TEST_DATABASE_URL")
            .expect("set TEST_DATABASE_URL to a disposable random PostgreSQL schema");
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(8)
            .connect(&url)
            .await
            .unwrap();
        crate::db::migrate(&pool).await.unwrap();
        crate::db::initialize_admin_runtime_settings(&pool, false, false)
            .await
            .unwrap();

        let guard = AbuseGuard::new_persistent(
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
            Some(b"guarded-registration-test-key-at-least-32-bytes"),
            None,
        );
        let suffix = Uuid::new_v4().simple().to_string();
        let username = format!("atomic{}", &suffix[..12]);
        let replay_username = format!("replay{}", &suffix[..12]);
        let invitation = format!("{}{}", suffix, suffix);
        sqlx::query(
            "INSERT INTO invitation_tokens(id,token_hash,label,max_uses) VALUES($1,$2,'guarded registration',2)",
        )
        .bind(Uuid::new_v4())
        .bind(auth::token_hash(&invitation))
        .execute(&pool)
        .await
        .unwrap();
        let actors = vec![format!("ip:198.51.100.{}", suffix.as_bytes()[0])];
        let subject = format!("registration:{}", actors[0]);
        let registration_password = "guarded-registration-password";
        let intent = crate::abuse::PowIntent::xmpp_registration(
            &username,
            registration_password,
            Some(&invitation),
        );

        // Advance the free burst so the transaction must consume a durable,
        // one-use proof instead of succeeding on an unchallenged first use.
        assert!(guard
            .verify_or_allow_v2(AbuseAction::Registration, &subject, &actors, None, &intent,)
            .await
            .unwrap()
            .is_ok());
        let challenge = guard
            .issue_v2(AbuseAction::Registration, &subject, &actors, &intent)
            .await
            .unwrap();
        let proof = solve_pow(&challenge);
        let initial_audit_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM audit_log WHERE action='user.register'")
                .fetch_one(&pool)
                .await
                .unwrap();

        let prepared = prepare_registration(
            &username,
            registration_password,
            auth::MIN_SCRAM_ITERATIONS,
            false,
        )
        .await
        .unwrap();
        let mut crashed = pool.begin().await.unwrap();
        assert!(matches!(
            create_user_with_invitation_guarded_in_tx_v2(
                &mut crashed,
                &guard,
                &subject,
                &actors,
                Some(&proof),
                &intent,
                false,
                prepared,
                Some(&invitation),
                true,
                u32::MAX,
                None,
            )
            .await
            .unwrap(),
            GuardedRegistrationOutcome::Created(_)
        ));
        crashed.rollback().await.unwrap();

        assert!(find_user(&pool, &username).await.unwrap().is_none());
        assert_eq!(
            sqlx::query_scalar::<_, i32>(
                "SELECT use_count FROM invitation_tokens WHERE token_hash=$1"
            )
            .bind(auth::token_hash(&invitation))
            .fetch_one(&pool)
            .await
            .unwrap(),
            0
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM audit_log WHERE action='user.register'"
            )
            .fetch_one(&pool)
            .await
            .unwrap(),
            initial_audit_count
        );
        assert!(sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM abuse_pow_challenges WHERE id=$1)"
        )
        .bind(proof.challenge_id)
        .fetch_one(&pool)
        .await
        .unwrap());

        let prepared = prepare_registration(
            &username,
            registration_password,
            auth::MIN_SCRAM_ITERATIONS,
            false,
        )
        .await
        .unwrap();
        let mut retry = pool.begin().await.unwrap();
        assert!(matches!(
            create_user_with_invitation_guarded_in_tx_v2(
                &mut retry,
                &guard,
                &subject,
                &actors,
                Some(&proof),
                &intent,
                false,
                prepared,
                Some(&invitation),
                true,
                u32::MAX,
                None,
            )
            .await
            .unwrap(),
            GuardedRegistrationOutcome::Created(_)
        ));
        retry.commit().await.unwrap();

        let replay_prepared = prepare_registration(
            &replay_username,
            registration_password,
            auth::MIN_SCRAM_ITERATIONS,
            false,
        )
        .await
        .unwrap();
        let replay_intent = crate::abuse::PowIntent::xmpp_registration(
            &replay_username,
            registration_password,
            Some(&invitation),
        );
        let mut replay = pool.begin().await.unwrap();
        assert!(matches!(
            create_user_with_invitation_guarded_in_tx_v2(
                &mut replay,
                &guard,
                &subject,
                &actors,
                Some(&proof),
                &replay_intent,
                false,
                replay_prepared,
                Some(&invitation),
                true,
                u32::MAX,
                None,
            )
            .await
            .unwrap(),
            GuardedRegistrationOutcome::AbuseDenied(_)
        ));
        replay.commit().await.unwrap();
        assert!(find_user(&pool, &replay_username).await.unwrap().is_none());
        assert_eq!(
            sqlx::query_scalar::<_, i32>(
                "SELECT use_count FROM invitation_tokens WHERE token_hash=$1"
            )
            .bind(auth::token_hash(&invitation))
            .fetch_one(&pool)
            .await
            .unwrap(),
            1
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM audit_log WHERE action='user.register'"
            )
            .fetch_one(&pool)
            .await
            .unwrap(),
            initial_audit_count + 1
        );
    }

    #[tokio::test]
    #[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
    async fn api_session_cap_and_disable_revocation_are_atomic() {
        let url = std::env::var("TEST_DATABASE_URL")
            .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(8)
            .connect(&url)
            .await
            .unwrap();
        crate::db::migrate(&pool).await.unwrap();
        // A normal restart must treat every already-recorded migration,
        // including 0056, as an idempotent no-op.
        crate::db::migrate(&pool).await.unwrap();

        let suffix = Uuid::new_v4().simple().to_string();
        let actor_id = Uuid::new_v4();
        let second_admin_id = Uuid::new_v4();
        let target_id = Uuid::new_v4();
        for (id, username, is_admin) in [
            (actor_id, format!("a{}", &suffix[..12]), true),
            (second_admin_id, format!("b{}", &suffix[..12]), true),
            (target_id, format!("u{}", &suffix[..12]), false),
        ] {
            sqlx::query(
                "INSERT INTO users (id, username, password_hash, is_admin) VALUES ($1, $2, 'test-only-invalid-hash', $3)",
            )
            .bind(id)
            .bind(username)
            .bind(is_admin)
            .execute(&pool)
            .await
            .unwrap();
        }

        let mut newest_token = String::new();
        for _ in 0..40 {
            newest_token = create_api_session(&pool, target_id, 1).await.unwrap();
        }
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM api_sessions WHERE user_id=$1")
            .bind(target_id)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count, MAX_API_SESSIONS_PER_USER);
        assert!(user_for_token(&pool, &newest_token)
            .await
            .unwrap()
            .is_some());

        set_user_status(&pool, actor_id, target_id, Some(true), None)
            .await
            .unwrap();
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM api_sessions WHERE user_id=$1")
            .bind(target_id)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count, 0);
        assert!(user_for_token(&pool, &newest_token)
            .await
            .unwrap()
            .is_none());

        set_user_status(&pool, actor_id, second_admin_id, None, Some(false))
            .await
            .unwrap();
        assert!(matches!(
            set_user_status(&pool, second_admin_id, actor_id, None, Some(false)).await,
            Err(UserStatusError::LastAdministrator)
        ));

        sqlx::query("DELETE FROM users WHERE id = ANY($1)")
            .bind([actor_id, second_admin_id, target_id])
            .execute(&pool)
            .await
            .unwrap();
    }

    #[tokio::test]
    #[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
    async fn rest_password_cas_and_admin_authorization_are_atomic() {
        let url = std::env::var("TEST_DATABASE_URL")
            .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(8)
            .connect(&url)
            .await
            .unwrap();
        crate::db::migrate(&pool).await.unwrap();

        let suffix = Uuid::new_v4().simple().to_string();
        let admin_a = create_user(
            &pool,
            &format!("aa{}", &suffix[..10]),
            "admin-a-old-password",
            true,
            true,
            auth::MIN_SCRAM_ITERATIONS,
            false,
        )
        .await
        .unwrap();
        let admin_b = create_user(
            &pool,
            &format!("ab{}", &suffix[..10]),
            "admin-b-old-password",
            true,
            true,
            auth::MIN_SCRAM_ITERATIONS,
            false,
        )
        .await
        .unwrap();
        let target = create_user(
            &pool,
            &format!("u{}", &suffix[..10]),
            "target-old-password",
            false,
            true,
            auth::MIN_SCRAM_ITERATIONS,
            false,
        )
        .await
        .unwrap();
        let target_token = create_api_session(&pool, target.id, 1).await.unwrap();
        let fast_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO fast_tokens
             (id,user_id,device_id,mechanism,channel_binding,slot,derivation_nonce,token_hash,
              expires_at,auth_generation,strong_auth_at,chain_expires_at)
             VALUES($1,$2,$3,'HT-SHA-256-NONE','none','current',$4,$5,
                    NOW()+INTERVAL '1 day',$6,NOW(),NOW()+INTERVAL '1 day')",
        )
        .bind(fast_id)
        .bind(target.id)
        .bind(Uuid::new_v4())
        .bind(vec![7_u8; 32])
        .bind(vec![8_u8; 32])
        .bind(target.auth_generation)
        .execute(&pool)
        .await
        .unwrap();
        let sm_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO sm_resume_sessions
             (id,token_hash,user_id,auth_generation,full_jid,resource,connection_id,
              resume_timeout_seconds,peer_ip,live_lease_until,expires_at,resumable)
             VALUES($1,$2,$3,$4,$5,'phone',$6,300,'127.0.0.1',
                    NOW()+INTERVAL '5 minutes',NOW()+INTERVAL '5 minutes',TRUE)",
        )
        .bind(sm_id)
        .bind(vec![9_u8; 32])
        .bind(target.id)
        .bind(target.auth_generation)
        .bind(format!("{}@example.test/phone", target.username))
        .bind(Uuid::new_v4())
        .execute(&pool)
        .await
        .unwrap();

        assert_eq!(
            change_password_cas(
                &pool,
                target.id,
                &target.password_hash,
                target.auth_generation,
                &target_token,
                "target-old-password",
                "target-new-password",
                auth::MIN_SCRAM_ITERATIONS,
            )
            .await
            .unwrap(),
            PasswordChangeOutcome::Changed
        );
        let rotated = find_user_by_id(&pool, target.id).await.unwrap().unwrap();
        assert_eq!(
            rotated.auth_generation,
            target.auth_generation.saturating_add(1)
        );
        assert!(!auth::verify_password(&rotated.password_hash, "target-old-password").unwrap());
        assert!(auth::verify_password(&rotated.password_hash, "target-new-password").unwrap());
        assert!(user_for_token(&pool, &target_token)
            .await
            .unwrap()
            .is_none());
        let fast_revoked: bool =
            sqlx::query_scalar("SELECT revoked_at IS NOT NULL FROM fast_tokens WHERE id=$1")
                .bind(fast_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert!(fast_revoked);
        let sm_expired: bool = sqlx::query_scalar(
            "SELECT NOT resumable AND expires_at <= clock_timestamp()
             FROM sm_resume_sessions WHERE id=$1",
        )
        .bind(sm_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(sm_expired);
        let audit_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM audit_log
             WHERE actor_id=$1 AND action='user.password.change'",
        )
        .bind(target.id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(audit_count, 1);

        // A handler that derived a new password while its observed account
        // generation became stale must not overwrite the newer credential.
        let stale_token = create_api_session(&pool, target.id, 1).await.unwrap();
        sqlx::query("UPDATE users SET auth_generation=auth_generation+1 WHERE id=$1")
            .bind(target.id)
            .execute(&pool)
            .await
            .unwrap();
        assert_eq!(
            change_password_cas(
                &pool,
                target.id,
                &rotated.password_hash,
                rotated.auth_generation,
                &stale_token,
                "target-new-password",
                "stale-write-must-not-win",
                auth::MIN_SCRAM_ITERATIONS,
            )
            .await
            .unwrap(),
            PasswordChangeOutcome::StaleAuthorization
        );
        let after_stale = find_user_by_id(&pool, target.id).await.unwrap().unwrap();
        assert_eq!(after_stale.password_hash, rotated.password_hash);

        let token_a = create_api_session(&pool, admin_a.id, 1).await.unwrap();
        let token_b = create_api_session(&pool, admin_b.id, 1).await.unwrap();
        assert!(matches!(
            set_user_status_api(
                &pool,
                admin_a.id,
                admin_a.auth_generation,
                &token_a,
                admin_a.id,
                Some(true),
                None,
            )
            .await,
            Err(UserStatusError::SelfMutation)
        ));

        // The advisory lock plus in-transaction bearer revalidation means
        // concurrent administrators cannot both demote the other and leave
        // the service without a usable administrator. The winner revokes the
        // loser's bearer before the second transaction authorizes.
        let (demote_b, demote_a) = tokio::join!(
            set_user_status_api(
                &pool,
                admin_a.id,
                admin_a.auth_generation,
                &token_a,
                admin_b.id,
                None,
                Some(false),
            ),
            set_user_status_api(
                &pool,
                admin_b.id,
                admin_b.auth_generation,
                &token_b,
                admin_a.id,
                None,
                Some(false),
            )
        );
        let outcomes = [demote_b, demote_a];
        assert_eq!(outcomes.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(
            outcomes
                .iter()
                .filter(|result| matches!(result, Err(UserStatusError::Unauthorized)))
                .count(),
            1
        );
        let enabled_admins: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE is_admin AND NOT is_disabled")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(enabled_admins, 1);
    }

    #[tokio::test]
    #[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
    async fn rest_password_idempotency_logout_and_lock_order_are_atomic() {
        use crate::abuse::{AbuseAction, AbuseConfig, AbuseGuard, TransactionalGuardOutcome};
        use std::collections::BTreeMap;
        use std::sync::Arc;
        use std::time::Duration;

        let url = std::env::var("TEST_DATABASE_URL")
            .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(12)
            .connect(&url)
            .await
            .unwrap();
        crate::db::migrate(&pool).await.unwrap();
        let suffix = Uuid::new_v4().simple().to_string();
        let user = create_user(
            &pool,
            &format!("pw{}", &suffix[..10]),
            "password-before-change",
            false,
            true,
            auth::MIN_SCRAM_ITERATIONS,
            false,
        )
        .await
        .unwrap();
        let token = create_api_session(&pool, user.id, 1).await.unwrap();
        let keyring = Arc::new(
            crate::db::ApiControlKeyring::new(b"password-api-control-test-key-000001", None)
                .unwrap(),
        );
        let guard = AbuseGuard::new_persistent(
            AbuseConfig {
                base_work_factor: 2,
                max_work_factor: 1024,
                window: Duration::from_secs(60),
                cooldown_step: Duration::from_secs(60),
                max_wait: Duration::from_secs(900),
                message_free_burst: 6,
                approximate_max_device_seconds: 8,
            },
            pool.clone(),
            Some(b"password-abuse-test-key-at-least-32-bytes"),
            None,
        );
        let request_key = "password-change-key-0001".to_owned();
        let request = password_idempotency_request(
            &token,
            &request_key,
            br#"{"current_password":"password-before-change","new_password":"password-after-change"}"#,
        );
        let headers = BTreeMap::from([
            ("cache-control".to_owned(), "no-store, max-age=0".to_owned()),
            ("content-type".to_owned(), "application/json".to_owned()),
        ]);
        let response_body = br#"{"changed":true,"sessions_revoked":true}"#;

        let mut lookup = pool.begin().await.unwrap();
        assert!(matches!(
            crate::db::lookup_password_change_replay_in_tx(&keyring, &mut lookup, &request)
                .await
                .unwrap(),
            crate::db::IdempotencyReplayLookup::Miss
        ));
        lookup.commit().await.unwrap();

        let mut reserve = pool.begin().await.unwrap();
        assert!(user_for_token_in_tx(&mut reserve, &token)
            .await
            .unwrap()
            .is_some());
        let lease = acquired(
            crate::db::acquire_idempotency_in_tx(&keyring, &mut reserve, &request)
                .await
                .unwrap(),
        );
        let actors = vec![format!("user:{}", user.id)];
        assert!(matches!(
            guard
                .verify_or_allow_in_tx(
                    &mut reserve,
                    AbuseAction::PasswordChange,
                    &format!("password_change:{}", user.id),
                    &actors,
                    None,
                )
                .await
                .unwrap(),
            TransactionalGuardOutcome::Allowed(_)
        ));
        assert!(
            crate::db::mark_idempotency_guard_verified_in_tx(&mut reserve, &lease)
                .await
                .unwrap()
        );
        reserve.commit().await.unwrap();

        let mut prework = pool.begin().await.unwrap();
        assert!(
            crate::db::resume_idempotency_lease_in_tx(&mut prework, &lease, 180)
                .await
                .unwrap()
        );
        prework.commit().await.unwrap();
        let prepared = prepare_password_change(
            &user.password_hash,
            "password-before-change",
            "password-after-change",
            auth::MIN_SCRAM_ITERATIONS,
            false,
        )
        .await
        .unwrap();

        // Crash after every database consequence was staged: rollback must
        // restore credentials, sessions, audit and replay state together.
        let mut crashed = pool.begin().await.unwrap();
        assert!(
            crate::db::resume_idempotency_lease_in_tx(&mut crashed, &lease, 180)
                .await
                .unwrap()
        );
        assert!(
            crate::db::bind_idempotency_actor_in_tx(&mut crashed, &lease, user.id)
                .await
                .unwrap()
        );
        assert_eq!(
            apply_prepared_password_change_in_tx(
                &mut crashed,
                user.id,
                &user.password_hash,
                user.auth_generation,
                &token,
                prepared,
                Some(lease.request_id),
            )
            .await
            .unwrap(),
            PasswordChangeOutcome::Changed
        );
        assert!(crate::db::complete_idempotency_in_tx(
            &keyring,
            &mut crashed,
            &lease,
            200,
            &headers,
            response_body,
        )
        .await
        .unwrap());
        crashed.rollback().await.unwrap();
        assert!(user_for_token(&pool, &token).await.unwrap().is_some());
        assert!(auth::verify_password(
            &find_user_by_id(&pool, user.id)
                .await
                .unwrap()
                .unwrap()
                .password_hash,
            "password-before-change"
        )
        .unwrap());

        // Simulate process loss and lease takeover. The committed guard marker
        // survives, but the rolled-back password mutation does not.
        sqlx::query(
            "UPDATE api_idempotency_records
             SET lease_expires_at=clock_timestamp()-INTERVAL '1 second'
             WHERE request_id=$1",
        )
        .bind(lease.request_id)
        .execute(&pool)
        .await
        .unwrap();
        let mut takeover = pool.begin().await.unwrap();
        assert!(user_for_token_in_tx(&mut takeover, &token)
            .await
            .unwrap()
            .is_some());
        let takeover_lease = acquired(
            crate::db::acquire_idempotency_in_tx(&keyring, &mut takeover, &request)
                .await
                .unwrap(),
        );
        assert!(takeover_lease.guard_verified);
        takeover.commit().await.unwrap();
        let retry_prepared = prepare_password_change(
            &user.password_hash,
            "password-before-change",
            "password-after-change",
            auth::MIN_SCRAM_ITERATIONS,
            false,
        )
        .await
        .unwrap();
        let mut final_tx = pool.begin().await.unwrap();
        assert!(
            crate::db::resume_idempotency_lease_in_tx(&mut final_tx, &takeover_lease, 180,)
                .await
                .unwrap()
        );
        assert!(
            crate::db::bind_idempotency_actor_in_tx(&mut final_tx, &takeover_lease, user.id,)
                .await
                .unwrap()
        );
        assert_eq!(
            apply_prepared_password_change_in_tx(
                &mut final_tx,
                user.id,
                &user.password_hash,
                user.auth_generation,
                &token,
                retry_prepared,
                Some(takeover_lease.request_id),
            )
            .await
            .unwrap(),
            PasswordChangeOutcome::Changed
        );
        assert!(crate::db::complete_idempotency_in_tx(
            &keyring,
            &mut final_tx,
            &takeover_lease,
            200,
            &headers,
            response_body,
        )
        .await
        .unwrap());
        final_tx.commit().await.unwrap();
        assert!(user_for_token(&pool, &token).await.unwrap().is_none());
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM audit_log
                 WHERE actor_id=$1 AND action='user.password.change' AND request_id=$2"
            )
            .bind(user.id)
            .bind(takeover_lease.request_id)
            .fetch_one(&pool)
            .await
            .unwrap(),
            1
        );
        let mut replay = pool.begin().await.unwrap();
        match crate::db::lookup_password_change_replay_in_tx(&keyring, &mut replay, &request)
            .await
            .unwrap()
        {
            crate::db::IdempotencyReplayLookup::Replay(response) => {
                assert_eq!(response.status, 200);
                assert_eq!(response.body, response_body);
            }
            other => panic!("expected password response replay, got {other:?}"),
        }
        replay.commit().await.unwrap();

        // A new key cannot use the now-revoked bearer to create a mutation.
        let new_key = "password-change-key-0002".to_owned();
        let new_request = password_idempotency_request(
            &token,
            &new_key,
            br#"{"current_password":"password-after-change","new_password":"another-password"}"#,
        );
        let mut unauthenticated = pool.begin().await.unwrap();
        assert!(user_for_token_in_tx(&mut unauthenticated, &token)
            .await
            .unwrap()
            .is_none());
        unauthenticated.rollback().await.unwrap();
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM api_idempotency_records WHERE route='/api/v1/me/password'"
            )
            .fetch_one(&pool)
            .await
            .unwrap(),
            1
        );
        let mut new_lookup = pool.begin().await.unwrap();
        assert!(matches!(
            crate::db::lookup_password_change_replay_in_tx(
                &keyring,
                &mut new_lookup,
                &new_request,
            )
            .await
            .unwrap(),
            crate::db::IdempotencyReplayLookup::Miss
        ));
        new_lookup.commit().await.unwrap();

        // Logout is naturally idempotent: only the successful DELETE writes
        // its audit row; repeats and random well-formed tokens are identical.
        let logout_user = create_user(
            &pool,
            &format!("lo{}", &suffix[..10]),
            "logout-test-password",
            false,
            true,
            auth::MIN_SCRAM_ITERATIONS,
            false,
        )
        .await
        .unwrap();
        let logout_token = create_api_session(&pool, logout_user.id, 1).await.unwrap();
        let first_logout_request = Uuid::new_v4();
        let mut logout_tx = pool.begin().await.unwrap();
        assert!(delete_api_session_audited_in_tx(
            &mut logout_tx,
            &logout_token,
            first_logout_request,
        )
        .await
        .unwrap());
        logout_tx.commit().await.unwrap();
        let mut repeated_logout = pool.begin().await.unwrap();
        assert!(!delete_api_session_audited_in_tx(
            &mut repeated_logout,
            &logout_token,
            Uuid::new_v4(),
        )
        .await
        .unwrap());
        repeated_logout.commit().await.unwrap();
        let mut random_logout = pool.begin().await.unwrap();
        assert!(!delete_api_session_audited_in_tx(
            &mut random_logout,
            &auth::new_session_token(),
            Uuid::new_v4(),
        )
        .await
        .unwrap());
        random_logout.commit().await.unwrap();
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM audit_log
                 WHERE actor_id=$1 AND action='user.session.logout'"
            )
            .bind(logout_user.id)
            .fetch_one(&pool)
            .await
            .unwrap(),
            1
        );

        // Password and report-style mutations both lock user/session before
        // idempotency. Starting them together must not form the former cycle.
        let lock_user = create_user(
            &pool,
            &format!("lk{}", &suffix[..10]),
            "lock-order-password",
            false,
            true,
            auth::MIN_SCRAM_ITERATIONS,
            false,
        )
        .await
        .unwrap();
        let lock_token = create_api_session(&pool, lock_user.id, 1).await.unwrap();
        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        enum InitialAdmission {
            Acquired,
            Busy,
        }

        let authorization_barrier = Arc::new(tokio::sync::Barrier::new(2));
        let admission_barrier = Arc::new(tokio::sync::Barrier::new(2));
        let rollback_barrier = Arc::new(tokio::sync::Barrier::new(2));
        let password_lock = {
            let pool = pool.clone();
            let keyring = Arc::clone(&keyring);
            let authorization_barrier = Arc::clone(&authorization_barrier);
            let admission_barrier = Arc::clone(&admission_barrier);
            let rollback_barrier = Arc::clone(&rollback_barrier);
            let lock_token = lock_token.clone();
            tokio::spawn(async move {
                let key = "lock-password-key-0001".to_owned();
                let request = password_idempotency_request(&lock_token, &key, b"password-lock");
                let mut tx = pool.begin().await.unwrap();
                sqlx::query("SET LOCAL lock_timeout='2s'")
                    .execute(&mut *tx)
                    .await
                    .unwrap();
                assert!(user_for_token_in_tx(&mut tx, &lock_token)
                    .await
                    .unwrap()
                    .is_some());
                authorization_barrier.wait().await;
                let outcome = crate::db::acquire_idempotency_in_tx(&keyring, &mut tx, &request)
                    .await
                    .unwrap();
                let initial = match outcome {
                    crate::db::IdempotencyAcquire::Acquired(_) => InitialAdmission::Acquired,
                    crate::db::IdempotencyAcquire::Busy {
                        retry_after_seconds: 1,
                    } => InitialAdmission::Busy,
                    other => panic!("unexpected password idempotency outcome: {other:?}"),
                };
                // Keep the winner's singleton row lock until the competing
                // transaction has observed fail-fast Busy. This makes the
                // capacity-lock contract deterministic rather than scheduler
                // dependent.
                admission_barrier.wait().await;
                tx.rollback().await.unwrap();
                rollback_barrier.wait().await;

                if initial == InitialAdmission::Busy {
                    let mut retry = pool.begin().await.unwrap();
                    sqlx::query("SET LOCAL lock_timeout='2s'")
                        .execute(&mut *retry)
                        .await
                        .unwrap();
                    assert!(user_for_token_in_tx(&mut retry, &lock_token)
                        .await
                        .unwrap()
                        .is_some());
                    let retried =
                        crate::db::acquire_idempotency_in_tx(&keyring, &mut retry, &request)
                            .await
                            .unwrap();
                    assert!(
                        matches!(retried, crate::db::IdempotencyAcquire::Acquired(_)),
                        "password Busy admission did not recover: {retried:?}"
                    );
                    retry.rollback().await.unwrap();
                }
                initial
            })
        };
        let report_lock = {
            let pool = pool.clone();
            let keyring = Arc::clone(&keyring);
            let authorization_barrier = Arc::clone(&authorization_barrier);
            let admission_barrier = Arc::clone(&admission_barrier);
            let rollback_barrier = Arc::clone(&rollback_barrier);
            let lock_token = lock_token.clone();
            tokio::spawn(async move {
                let key = "lock-report-key-0001".to_owned();
                let body = crate::db::api_request_fingerprint("application/json", b"report-lock");
                let request = crate::db::IdempotencyRequest {
                    request_id: Uuid::new_v4(),
                    actor_id: Some(lock_user.id),
                    principal_scope: lock_user.id.as_bytes(),
                    capacity_scope: lock_user.id.as_bytes(),
                    target_scope: b"",
                    principal_kind: crate::db::ApiPrincipalKind::User,
                    method: "POST",
                    route: "/api/v1/reports",
                    idempotency_key: &key,
                    request_fingerprint: body,
                    ttl_seconds: 3600,
                    lease_seconds: 180,
                };
                let mut tx = pool.begin().await.unwrap();
                sqlx::query("SET LOCAL lock_timeout='2s'")
                    .execute(&mut *tx)
                    .await
                    .unwrap();
                assert!(authorize_user_in_tx(
                    &mut tx,
                    lock_user.id,
                    lock_user.auth_generation,
                    &lock_token,
                )
                .await
                .unwrap());
                authorization_barrier.wait().await;
                let outcome = crate::db::acquire_idempotency_in_tx(&keyring, &mut tx, &request)
                    .await
                    .unwrap();
                let initial = match outcome {
                    crate::db::IdempotencyAcquire::Acquired(_) => InitialAdmission::Acquired,
                    crate::db::IdempotencyAcquire::Busy {
                        retry_after_seconds: 1,
                    } => InitialAdmission::Busy,
                    other => panic!("unexpected report idempotency outcome: {other:?}"),
                };
                admission_barrier.wait().await;
                tx.rollback().await.unwrap();
                rollback_barrier.wait().await;

                if initial == InitialAdmission::Busy {
                    let mut retry = pool.begin().await.unwrap();
                    sqlx::query("SET LOCAL lock_timeout='2s'")
                        .execute(&mut *retry)
                        .await
                        .unwrap();
                    assert!(authorize_user_in_tx(
                        &mut retry,
                        lock_user.id,
                        lock_user.auth_generation,
                        &lock_token,
                    )
                    .await
                    .unwrap());
                    let retried =
                        crate::db::acquire_idempotency_in_tx(&keyring, &mut retry, &request)
                            .await
                            .unwrap();
                    assert!(
                        matches!(retried, crate::db::IdempotencyAcquire::Acquired(_)),
                        "report Busy admission did not recover: {retried:?}"
                    );
                    retry.rollback().await.unwrap();
                }
                initial
            })
        };
        let (password_initial, report_initial) =
            tokio::time::timeout(Duration::from_secs(5), async {
                (password_lock.await.unwrap(), report_lock.await.unwrap())
            })
            .await
            .expect("password/report lock-order barrier timed out");
        assert!(matches!(
            (password_initial, report_initial),
            (InitialAdmission::Acquired, InitialAdmission::Busy)
                | (InitialAdmission::Busy, InitialAdmission::Acquired)
        ));
        pool.close().await;
    }

    #[tokio::test]
    #[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
    async fn account_deletion_atomically_cancels_local_reverse_rosters() {
        let url = std::env::var("TEST_DATABASE_URL")
            .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(4)
            .connect(&url)
            .await
            .unwrap();
        crate::db::migrate(&pool).await.unwrap();

        let suffix = Uuid::new_v4().simple().to_string();
        let removed_id = Uuid::new_v4();
        let contact_id = Uuid::new_v4();
        let removed_name = format!("d{}", &suffix[..12]);
        let contact_name = format!("c{}", &suffix[..12]);
        for (id, username) in [
            (removed_id, removed_name.as_str()),
            (contact_id, contact_name.as_str()),
        ] {
            sqlx::query("INSERT INTO users(id,username,password_hash) VALUES($1,$2,'test-only')")
                .bind(id)
                .bind(username)
                .execute(&pool)
                .await
                .unwrap();
        }
        let removed_jid = format!("{removed_name}@example.test");
        let contact_jid = format!("{contact_name}@example.test");
        let removed_pubsub_node = Uuid::new_v4();
        let shared_pubsub_node = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO pubsub_nodes(id,node,creator_jid,children_association_whitelist)
             VALUES($1,$2,$3,ARRAY[$3]),($4,$5,$6,ARRAY[$3,$6])",
        )
        .bind(removed_pubsub_node)
        .bind(format!("delete-owned-{suffix}"))
        .bind(&removed_jid)
        .bind(shared_pubsub_node)
        .bind(format!("delete-shared-{suffix}"))
        .bind(&contact_jid)
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO pubsub_affiliations(node_id,jid,affiliation)
             VALUES($1,$2,'owner'),($3,$2,'owner'),($3,$4,'owner')",
        )
        .bind(removed_pubsub_node)
        .bind(&removed_jid)
        .bind(shared_pubsub_node)
        .bind(&contact_jid)
        .execute(&pool)
        .await
        .unwrap();
        let removed_resource = format!("{removed_jid}/phone");
        sqlx::query(
            "INSERT INTO pubsub_subscriptions(node_id,jid,state,subid,digest)
             VALUES($1,$2,'subscribed',$3,TRUE)",
        )
        .bind(shared_pubsub_node)
        .bind(&removed_resource)
        .bind(Uuid::new_v4().to_string())
        .execute(&pool)
        .await
        .unwrap();
        let digest_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO pubsub_digest_queue
             (id,subscription_node_id,subscriber_jid,event_xml,deliver_after)
             VALUES($1,$2,$3,'<event/>',NOW()+INTERVAL '1 hour')",
        )
        .bind(digest_id)
        .bind(shared_pubsub_node)
        .bind(&removed_resource)
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query("INSERT INTO roster_items(owner_id,contact_jid,subscription,groups) VALUES($1,$2,'both','[]'::jsonb),($3,$4,'both','[1]'::jsonb)")
            .bind(removed_id)
            .bind(&contact_jid)
            .bind(contact_id)
            .bind(&removed_jid)
            .execute(&pool)
            .await
            .unwrap();
        let upload_id = Uuid::new_v4();
        let upload_digest = vec![0x42_u8; 32];
        sqlx::query(
            "INSERT INTO upload_slots
             (id,user_id,filename,content_type,size,token_hash,expires_at,put_expires_at)
             VALUES($1,$2,'cipher.bin','application/octet-stream',4,'test-token',
                    NOW()+INTERVAL '1 day',NOW()+INTERVAL '5 minutes')",
        )
        .bind(upload_id)
        .bind(removed_id)
        .execute(&pool)
        .await
        .unwrap();
        // Build a complete current committed projection through UPDATE so the
        // cleanup-debt trigger reserves its cascade obligation exactly as it
        // does for the production finalization path.
        sqlx::query(
            "UPDATE upload_slots
             SET uploaded=TRUE,content_sha256=$2,completed_at=clock_timestamp(),
                 storage_state='committed',storage_object_key=id::text,
                 storage_sha256=$2,storage_size=size
             WHERE id=$1",
        )
        .bind(upload_id)
        .bind(&upload_digest)
        .execute(&pool)
        .await
        .unwrap();

        let api_token = create_api_session(&pool, removed_id, 1).await.unwrap();
        let fast_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO fast_tokens
             (id,user_id,device_id,mechanism,channel_binding,slot,derivation_nonce,token_hash,
              expires_at,auth_generation,strong_auth_at,chain_expires_at)
             VALUES($1,$2,$3,'HT-SHA-256-NONE','none','current',$4,$5,
                    NOW()+INTERVAL '1 day',0,NOW(),NOW()+INTERVAL '1 day')",
        )
        .bind(fast_id)
        .bind(removed_id)
        .bind(Uuid::new_v4())
        .bind(vec![7_u8; 32])
        .bind(vec![8_u8; 32])
        .execute(&pool)
        .await
        .unwrap();
        let sm_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO sm_resume_sessions
             (id,token_hash,user_id,auth_generation,full_jid,resource,connection_id,
              resume_timeout_seconds,peer_ip,live_lease_until,expires_at)
             VALUES($1,$2,$3,0,$4,'phone',$5,300,'127.0.0.1',NOW(),NOW()+INTERVAL '5 minutes')",
        )
        .bind(sm_id)
        .bind(vec![9_u8; 32])
        .bind(removed_id)
        .bind(format!("{removed_jid}/phone"))
        .bind(Uuid::new_v4())
        .execute(&pool)
        .await
        .unwrap();
        let archive_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO message_archive
             (id,owner_id,peer_jid,peer_full_jid,stanza,encrypted)
             VALUES($1,$2,$3,$3,'<message xmlns=\"jabber:client\"/>',FALSE)",
        )
        .bind(archive_id)
        .bind(removed_id)
        .bind(&contact_jid)
        .execute(&pool)
        .await
        .unwrap();
        let admission_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO personal_message_admissions
             (id,identity_kind,actor_scope_raw,actor_scope,target_scope,identity_value,
              identity_digest,payload_key_id,payload_mac,sender_archive_id)
             VALUES($1,'local-origin',$2,$2,$3,'delete-test',$4,'AAAAAAAAAAAAAAAA',$5,$6)",
        )
        .bind(admission_id)
        .bind(&removed_jid)
        .bind(&contact_jid)
        .bind(vec![10_u8; 32])
        .bind(vec![11_u8; 32])
        .bind(archive_id)
        .execute(&pool)
        .await
        .unwrap();

        // Invalid historical group data makes journal materialization fail.
        // The reverse subscription update and user delete must both roll back.
        assert!(delete_user_with_roster(&pool, removed_id, "example.test")
            .await
            .is_err());
        assert!(find_user(&pool, &removed_name).await.unwrap().is_some());
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM pubsub_nodes WHERE id = ANY($1)")
                .bind([removed_pubsub_node, shared_pubsub_node])
                .fetch_one(&pool)
                .await
                .unwrap(),
            2,
            "PubSub cleanup must roll back with a failed account deletion"
        );
        let cleanup_after_rollback: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM upload_cleanup_queue WHERE object_id=$1")
                .bind(upload_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(cleanup_after_rollback, 0);
        let reverse: String = sqlx::query_scalar(
            "SELECT subscription FROM roster_items WHERE owner_id=$1 AND contact_jid=$2",
        )
        .bind(contact_id)
        .bind(&removed_jid)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(reverse, "both");
        assert!(user_for_token(&pool, &api_token).await.unwrap().is_some());
        for (table, id) in [
            ("fast_tokens", fast_id),
            ("sm_resume_sessions", sm_id),
            ("message_archive", archive_id),
            ("personal_message_admissions", admission_id),
        ] {
            let count: i64 =
                sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {table} WHERE id=$1"))
                    .bind(id)
                    .fetch_one(&pool)
                    .await
                    .unwrap();
            assert_eq!(count, 1, "{table} must survive a rolled-back deletion");
        }

        sqlx::query(
            "UPDATE roster_items SET groups='[]'::jsonb WHERE owner_id=$1 AND contact_jid=$2",
        )
        .bind(contact_id)
        .bind(&removed_jid)
        .execute(&pool)
        .await
        .unwrap();
        let removed = delete_user_with_roster(&pool, removed_id, "example.test")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(removed.roster.len(), 1);
        assert_eq!(removed.reverse_roster_changes.len(), 1);
        assert_eq!(removed.reverse_roster_changes[0].0, contact_id);
        assert_eq!(removed.reverse_roster_changes[0].1, contact_name);
        assert_eq!(
            removed.reverse_roster_changes[0].2.subscription.as_deref(),
            Some("none")
        );
        assert!(find_user(&pool, &removed_name).await.unwrap().is_none());
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM pubsub_nodes WHERE id=$1")
                .bind(removed_pubsub_node)
                .fetch_one(&pool)
                .await
                .unwrap(),
            0,
            "creator-owned PubSub node was not deleted"
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM pubsub_nodes WHERE id=$1")
                .bind(shared_pubsub_node)
                .fetch_one(&pool)
                .await
                .unwrap(),
            1,
            "co-owned PubSub node should survive"
        );
        for (table, predicate) in [
            ("pubsub_affiliations", "node_id=$1 AND jid=$2"),
            (
                "pubsub_subscriptions",
                "node_id=$1 AND split_part(jid, '/', 1)=$2",
            ),
            (
                "pubsub_digest_queue",
                "subscription_node_id=$1 AND split_part(subscriber_jid, '/', 1)=$2",
            ),
        ] {
            let count: i64 =
                sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {table} WHERE {predicate}"))
                    .bind(shared_pubsub_node)
                    .bind(&removed_jid)
                    .fetch_one(&pool)
                    .await
                    .unwrap();
            assert_eq!(count, 0, "{table} retained the deleted account");
        }
        let whitelist: Vec<String> = sqlx::query_scalar(
            "SELECT children_association_whitelist FROM pubsub_nodes WHERE id=$1",
        )
        .bind(shared_pubsub_node)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(whitelist.as_slice(), std::slice::from_ref(&contact_jid));
        let cleanup_after_commit: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM upload_cleanup_queue WHERE object_id=$1")
                .bind(upload_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(cleanup_after_commit, 1);
        let reverse: String = sqlx::query_scalar(
            "SELECT subscription FROM roster_items WHERE owner_id=$1 AND contact_jid=$2",
        )
        .bind(contact_id)
        .bind(&removed_jid)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(reverse, "none");
        assert!(user_for_token(&pool, &api_token).await.unwrap().is_none());
        for (table, id) in [
            ("fast_tokens", fast_id),
            ("sm_resume_sessions", sm_id),
            ("message_archive", archive_id),
            ("personal_message_admissions", admission_id),
        ] {
            let count: i64 =
                sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {table} WHERE id=$1"))
                    .bind(id)
                    .fetch_one(&pool)
                    .await
                    .unwrap();
            assert_eq!(count, 0, "{table} must be removed with the account");
        }

        sqlx::query("DELETE FROM users WHERE id=$1")
            .bind(contact_id)
            .execute(&pool)
            .await
            .unwrap();
    }
}
