//! Resolve account authentication state and persist credentials and login epochs.

use super::*;

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

pub(super) struct PreparedScramUpgrade {
    pub(super) sha256_salt: Vec<u8>,
    pub(super) sha1_salt: Option<Vec<u8>>,
    pub(super) sha256_iterations: u32,
    pub(super) sha1_iterations: Option<u32>,
    pub(super) sha256_stored_key: Vec<u8>,
    pub(super) sha256_server_key: Vec<u8>,
    pub(super) sha1_stored_key: Option<Vec<u8>>,
    pub(super) sha1_server_key: Option<Vec<u8>>,
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
    pub(super) expected_password_hash: Zeroizing<String>,
    pub(super) scram_upgrade: Option<PreparedScramUpgrade>,
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

pub(super) fn scram_upgrade_targets(
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
    let password_work = crate::security::password_work::admit()
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
    let prepared = crate::security::password_work::run(move || {
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
    intent: &crate::security::abuse::PowIntent,
    user_id: Uuid,
    expected_auth_generation: i64,
    new_password: &str,
    scram_iterations: u32,
    scram_sha1_enabled: bool,
) -> Result<std::result::Result<(), GuardError>> {
    // Reserve bounded CPU capacity before borrowing a database connection.
    // Proof consumption and the credential write remain one transaction, but
    // password-work queueing can no longer occupy the entire PgPool.
    let password_work = crate::security::password_work::reserve()
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

pub(super) async fn apply_password_credentials_in_tx(
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

pub(super) fn user_from_row(row: &sqlx::postgres::PgRow) -> User {
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
