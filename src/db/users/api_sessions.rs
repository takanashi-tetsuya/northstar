//! Manage API bearer sessions, principal projections and authorized account status changes.

use super::*;

/// Credential-bearing projection reserved for the password-change endpoint.
/// Its Argon2 verifier is zeroized as soon as the request path releases it.
pub struct PasswordChangeSubject {
    pub principal: ApiPrincipal,
    pub(super) password_hash: Zeroizing<String>,
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

pub(super) const MAX_API_SESSIONS_PER_USER: i64 = 32;

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

pub(super) fn api_principal_from_row(row: &sqlx::postgres::PgRow) -> ApiPrincipal {
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
