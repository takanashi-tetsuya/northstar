//! Prepare and persist bootstrap and invitation-based account registration.

use super::*;

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
    let creds = crate::security::password_work::run(move || {
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

pub struct PreparedRegistration {
    pub(super) username: String,
    pub(super) credentials: auth::PasswordCredentials,
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
    let creds = crate::security::password_work::run(move || {
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
    password_work: crate::security::password_work::PasswordWorkReservation,
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
    intent: &crate::services::abuse::PowIntent,
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
pub(super) async fn create_user_with_invitation_guarded_in_tx_bound(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    abuse: &AbuseGuard,
    subject: &str,
    actors: &[String],
    proof: Option<&PowProof>,
    intent: &crate::services::abuse::PowIntent,
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

pub async fn registrations_last_hour_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
) -> Result<i64> {
    Ok(sqlx::query_scalar(
        "SELECT COUNT(*) FROM users WHERE created_at >= NOW() - INTERVAL '1 hour'",
    )
    .fetch_one(&mut **tx)
    .await?)
}
