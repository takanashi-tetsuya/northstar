use crate::auth;
use crate::config::Config;
use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::Serialize;
use sqlx::PgPool;
use sqlx::Row;
use tokio::sync::Semaphore;
use uuid::Uuid;

static PASSWORD_WORK: Semaphore = Semaphore::const_new(8);

#[derive(Clone, Debug, Serialize)]
pub struct User {
    pub id: Uuid,
    pub username: String,
    #[serde(skip_serializing)]
    pub password_hash: String,
    #[serde(skip_serializing)]
    pub scram_iterations: Option<u32>,
    pub display_name: Option<String>,
    pub is_admin: bool,
    pub is_disabled: bool,
    pub created_at: DateTime<Utc>,
    pub last_login_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize)]
pub struct UserSummary {
    pub id: Uuid,
    pub username: String,
    pub display_name: Option<String>,
    pub is_admin: bool,
    pub is_disabled: bool,
    pub created_at: DateTime<Utc>,
    pub last_login_at: Option<DateTime<Utc>>,
}

pub async fn create_user(
    pool: &PgPool,
    username: &str,
    password: &str,
    admin: bool,
    force: bool,
    scram_iterations: u32,
) -> Result<User> {
    let username = auth::normalize_username(username)?;
    let password = password.to_owned();
    let _permit = PASSWORD_WORK
        .acquire()
        .await
        .context("password worker queue closed")?;
    let creds = tokio::task::spawn_blocking(move || {
        auth::hash_password(&password, !force, scram_iterations)
    })
    .await
    .context("password hashing task failed")??;
    drop(_permit);
    let row = sqlx::query(
        "INSERT INTO users (id, username, password_hash, is_admin, scram_sha256_salt, scram_sha256_iterations, scram_sha256_stored_key, scram_sha256_server_key) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING *",
    )
    .bind(Uuid::new_v4())
    .bind(username)
    .bind(creds.hash)
    .bind(admin)
    .bind(creds.scram_salt)
    .bind(creds.scram_iterations as i32)
    .bind(creds.scram_stored_key)
    .bind(creds.scram_server_key)
    .fetch_one(pool)
    .await
    .context("could not create user")?;
    Ok(user_from_row(&row))
}

pub struct ScramCredentials {
    pub salt: Vec<u8>,
    pub iterations: u32,
    pub stored_key: Vec<u8>,
    pub server_key: Vec<u8>,
}

pub async fn get_scram_credentials(
    pool: &PgPool,
    username: &str,
) -> Result<Option<ScramCredentials>> {
    let username = auth::normalize_username(username).unwrap_or_default();
    let row = sqlx::query(
        "SELECT scram_sha256_salt, scram_sha256_iterations, scram_sha256_stored_key, scram_sha256_server_key FROM users WHERE username = $1 AND NOT is_disabled"
    )
    .bind(&username)
    .fetch_optional(pool)
    .await?;

    let Some(row) = row else {
        return Ok(None);
    };
    let values = (
        row.get::<Option<Vec<u8>>, _>("scram_sha256_salt"),
        row.get::<Option<i32>, _>("scram_sha256_iterations"),
        row.get::<Option<Vec<u8>>, _>("scram_sha256_stored_key"),
        row.get::<Option<Vec<u8>>, _>("scram_sha256_server_key"),
    );
    match values {
        (None, None, None, None) => Ok(None),
        (Some(salt), Some(iterations), Some(stored_key), Some(server_key)) => {
            let iterations =
                u32::try_from(iterations).context("stored SCRAM iteration count is negative")?;
            if !(auth::MIN_SCRAM_ITERATIONS..=auth::MAX_SCRAM_ITERATIONS).contains(&iterations)
                || salt.is_empty()
                || stored_key.len() != 32
                || server_key.len() != 32
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

pub async fn create_user_with_invitation(
    pool: &PgPool,
    username: &str,
    password: &str,
    invitation_token: Option<&str>,
    invitation_required: bool,
    scram_iterations: u32,
) -> Result<User> {
    let username = auth::normalize_username(username)?;
    let password = password.to_owned();
    let _permit = PASSWORD_WORK
        .acquire()
        .await
        .context("password worker queue closed")?;
    let creds =
        tokio::task::spawn_blocking(move || auth::hash_password(&password, true, scram_iterations))
            .await
            .context("password hashing task failed")??;
    drop(_permit);
    let mut tx = pool.begin().await?;
    if let Some(token) = invitation_token.filter(|token| !token.trim().is_empty()) {
        let consumed = sqlx::query(
            "UPDATE invitation_tokens SET use_count = use_count + 1 WHERE token_hash = $1 AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > NOW()) AND use_count < max_uses",
        )
        .bind(auth::token_hash(token.trim()))
        .execute(&mut *tx).await?.rows_affected() == 1;
        if !consumed {
            anyhow::bail!("invitation token is invalid, expired, revoked, or fully used");
        }
    } else if invitation_required {
        anyhow::bail!("a valid invitation token is required");
    }
    let row = sqlx::query(
        "INSERT INTO users (id, username, password_hash, is_admin, scram_sha256_salt, scram_sha256_iterations, scram_sha256_stored_key, scram_sha256_server_key) VALUES ($1, $2, $3, FALSE, $4, $5, $6, $7) RETURNING *",
    )
    .bind(Uuid::new_v4())
    .bind(username)
    .bind(creds.hash)
    .bind(creds.scram_salt)
    .bind(creds.scram_iterations as i32)
    .bind(creds.scram_stored_key)
    .bind(creds.scram_server_key)
    .fetch_one(&mut *tx).await.context("could not create user")?;
    tx.commit().await?;
    Ok(user_from_row(&row))
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
    )
    .await?;
    tracing::warn!(%username, "created bootstrap administrator; rotate its password immediately");
    Ok(())
}

pub async fn find_user(pool: &PgPool, username: &str) -> Result<Option<User>> {
    let row = sqlx::query("SELECT * FROM users WHERE username = $1")
        .bind(username)
        .fetch_optional(pool)
        .await?;
    Ok(row.as_ref().map(user_from_row))
}

pub async fn authenticate(
    pool: &PgPool,
    username: &str,
    password: &str,
    scram_iterations: u32,
) -> Result<Option<User>> {
    let Ok(username) = auth::normalize_username(username) else {
        return Ok(None);
    };
    let Some(user) = find_user(pool, &username).await? else {
        let candidate = password.to_owned();
        let _permit = PASSWORD_WORK
            .acquire()
            .await
            .context("password worker queue closed")?;
        tokio::task::spawn_blocking(move || auth::verify_against_dummy_hash(&candidate))
            .await
            .context("dummy password verification task failed")?;
        return Ok(None);
    };
    let stored_password_hash = user.password_hash.clone();
    let hash = stored_password_hash.clone();
    let candidate = password.to_owned();
    let scram_password = candidate.clone();
    let _permit = PASSWORD_WORK
        .acquire()
        .await
        .context("password worker queue closed")?;
    let valid = tokio::task::spawn_blocking(move || auth::verify_password(&hash, &candidate))
        .await
        .context("password verification task failed")?;
    if user.is_disabled || !valid {
        return Ok(None);
    }
    if user
        .scram_iterations
        .is_none_or(|stored_iterations| stored_iterations < scram_iterations)
    {
        let salt = auth::generate_scram_salt();
        let calculation_salt = salt.clone();
        let (stored_key, server_key) = tokio::task::spawn_blocking(move || {
            auth::compute_scram_sha256(&scram_password, &calculation_salt, scram_iterations)
        })
        .await
        .context("SCRAM credential upgrade task failed")?;
        sqlx::query(
            "UPDATE users SET scram_sha256_salt = $2, scram_sha256_iterations = $3, scram_sha256_stored_key = $4, scram_sha256_server_key = $5 WHERE id = $1 AND password_hash = $6",
        )
        .bind(user.id)
        .bind(salt)
        .bind(scram_iterations as i32)
        .bind(stored_key)
        .bind(server_key)
        .bind(stored_password_hash)
        .execute(pool)
        .await?;
    }
    drop(_permit);
    sqlx::query("UPDATE users SET last_login_at = NOW() WHERE id = $1")
        .bind(user.id)
        .execute(pool)
        .await?;
    Ok(Some(user))
}

pub async fn create_api_session(pool: &PgPool, user_id: Uuid, ttl_hours: i64) -> Result<String> {
    let token = auth::new_session_token();
    let expires_at = Utc::now() + chrono::Duration::hours(ttl_hours);
    sqlx::query(
        "INSERT INTO api_sessions (id, user_id, token_hash, expires_at) VALUES ($1, $2, $3, $4)",
    )
    .bind(Uuid::new_v4())
    .bind(user_id)
    .bind(auth::token_hash(&token))
    .bind(expires_at)
    .execute(pool)
    .await?;
    Ok(token)
}

pub async fn user_for_token(pool: &PgPool, token: &str) -> Result<Option<User>> {
    let row = sqlx::query(
        "SELECT u.* FROM users u JOIN api_sessions s ON s.user_id = u.id WHERE s.token_hash = $1 AND s.expires_at > NOW() AND NOT u.is_disabled",
    )
    .bind(auth::token_hash(token))
    .fetch_optional(pool)
    .await?;
    Ok(row.as_ref().map(user_from_row))
}

pub async fn change_password(
    pool: &PgPool,
    user_id: Uuid,
    new_password: &str,
    scram_iterations: u32,
) -> Result<()> {
    let password = new_password.to_owned();
    let _permit = PASSWORD_WORK
        .acquire()
        .await
        .context("password worker queue closed")?;
    let creds =
        tokio::task::spawn_blocking(move || auth::hash_password(&password, true, scram_iterations))
            .await
            .context("password hashing task failed")??;
    drop(_permit);
    let mut tx = pool.begin().await?;
    sqlx::query("UPDATE users SET password_hash = $2, scram_sha256_salt = $3, scram_sha256_iterations = $4, scram_sha256_stored_key = $5, scram_sha256_server_key = $6 WHERE id = $1")
        .bind(user_id)
        .bind(creds.hash)
        .bind(creds.scram_salt)
        .bind(creds.scram_iterations as i32)
        .bind(creds.scram_stored_key)
        .bind(creds.scram_server_key)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM api_sessions WHERE user_id = $1")
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(())
}

pub async fn list_users(pool: &PgPool, limit: i64, offset: i64) -> Result<Vec<UserSummary>> {
    let rows = sqlx::query("SELECT * FROM users ORDER BY created_at DESC LIMIT $1 OFFSET $2")
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await?;
    Ok(rows
        .iter()
        .map(|r| UserSummary {
            id: r.get("id"),
            username: r.get("username"),
            display_name: r.get("display_name"),
            is_admin: r.get("is_admin"),
            is_disabled: r.get("is_disabled"),
            created_at: r.get("created_at"),
            last_login_at: r.get("last_login_at"),
        })
        .collect())
}

pub async fn set_user_status(
    pool: &PgPool,
    id: Uuid,
    disabled: Option<bool>,
    admin: Option<bool>,
) -> Result<bool> {
    let result = sqlx::query(
        "UPDATE users SET is_disabled = COALESCE($2, is_disabled), is_admin = COALESCE($3, is_admin) WHERE id = $1",
    )
    .bind(id)
    .bind(disabled)
    .bind(admin)
    .execute(pool)
    .await?;
    Ok(result.rows_affected() == 1)
}

pub async fn counts(pool: &PgPool) -> Result<(i64, i64, i64)> {
    let users: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users")
        .fetch_one(pool)
        .await?;
    let archived: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM message_archive")
        .fetch_one(pool)
        .await?;
    let offline: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM offline_messages")
        .fetch_one(pool)
        .await?;
    Ok((users, archived, offline))
}

pub async fn operational_counts(pool: &PgPool) -> Result<(i64, i64, i64)> {
    let rooms = sqlx::query_scalar("SELECT COUNT(*) FROM muc_rooms")
        .fetch_one(pool)
        .await?;
    let uploads = sqlx::query_scalar("SELECT COUNT(*) FROM upload_slots WHERE uploaded")
        .fetch_one(pool)
        .await?;
    let push_subscriptions = sqlx::query_scalar("SELECT COUNT(*) FROM push_subscriptions")
        .fetch_one(pool)
        .await?;
    Ok((rooms, uploads, push_subscriptions))
}

pub async fn registrations_last_hour(pool: &PgPool) -> Result<i64> {
    Ok(sqlx::query_scalar(
        "SELECT COUNT(*) FROM users WHERE created_at >= NOW() - INTERVAL '1 hour'",
    )
    .fetch_one(pool)
    .await?)
}

fn user_from_row(row: &sqlx::postgres::PgRow) -> User {
    let salt = row.get::<Option<Vec<u8>>, _>("scram_sha256_salt");
    let iterations = row
        .get::<Option<i32>, _>("scram_sha256_iterations")
        .and_then(|iterations| u32::try_from(iterations).ok());
    let stored_key = row.get::<Option<Vec<u8>>, _>("scram_sha256_stored_key");
    let server_key = row.get::<Option<Vec<u8>>, _>("scram_sha256_server_key");
    let scram_iterations = match (salt, iterations, stored_key, server_key) {
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
    User {
        id: row.get("id"),
        username: row.get("username"),
        password_hash: row.get("password_hash"),
        scram_iterations,
        display_name: row.get("display_name"),
        is_admin: row.get("is_admin"),
        is_disabled: row.get("is_disabled"),
        created_at: row.get("created_at"),
        last_login_at: row.get("last_login_at"),
    }
}

pub async fn cleanup_expired_sessions(pool: &sqlx::PgPool) -> anyhow::Result<u64> {
    let res = sqlx::query("DELETE FROM api_sessions WHERE expires_at <= NOW()")
        .execute(pool)
        .await?;
    Ok(res.rows_affected())
}
