use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use northstar_abuse_application::guard::{AbuseGuard, TransactionalGuardOutcome};
use northstar_abuse_policy::{AbuseAction, GuardError, PowProof};
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

#[cfg(test)]
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

pub(crate) async fn lock_auth_generation_observed<'a>(
    pool: &'a PgPool,
    user_id: Uuid,
    expected_generation: i64,
    observation: Option<&crate::services::authentication::publication::CredentialInvocation<'_>>,
) -> Result<Option<sqlx::Transaction<'a, sqlx::Postgres>>> {
    use crate::services::authentication::publication::{
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

#[cfg(test)]
pub async fn create_api_session(pool: &PgPool, user_id: Uuid, ttl_hours: i64) -> Result<String> {
    let mut tx = pool.begin().await?;
    let session = create_api_session_in_tx(&mut tx, user_id, ttl_hours, None).await?;
    tx.commit().await?;
    Ok(session.token)
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

#[cfg(test)]
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
    intent: &northstar_abuse_policy::PowIntent,
    user_id: Uuid,
    expected_auth_generation: i64,
) -> Result<std::result::Result<bool, GuardError>> {
    let mut transaction = pool.begin().await?;
    match northstar_abuse_postgres::transaction::verify_in_tx(
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
    let account = northstar_xmpp_types::jid::canonicalize_bare(&account)?;
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

/// Production source of this module: the file itself followed by each
/// production child module file, so source-contract tests keep reading the
/// whole module after code moves between them. The children are listed in
/// the order their code had in the former single file, because some
/// contracts split the source on a marker that occurs in more than one child.
/// `module_source_lists_every_child_module` keeps this list in step with the
/// non-test `mod` declarations above.
#[cfg(test)]
pub(super) const MODULE_SOURCE: &[(&str, &str)] = &[
    ("users", include_str!("users.rs")),
    ("api_sessions", include_str!("users/api_sessions.rs")),
    ("registration", include_str!("users/registration.rs")),
    ("authentication", include_str!("users/authentication.rs")),
];

#[cfg(test)]
pub(super) fn module_source() -> String {
    MODULE_SOURCE
        .iter()
        .map(|(_, text)| *text)
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
#[path = "users_tests.rs"]
mod tests;

#[cfg(test)]
mod module_source_tests;
