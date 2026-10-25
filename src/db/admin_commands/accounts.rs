//! Persists authorized account and administrator operations against exact account identities.

use super::*;

pub(super) async fn admin_authorized_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    actor_id: Uuid,
    actor_username: &str,
    actor_generation: i64,
) -> Result<bool> {
    Ok(sqlx::query_scalar::<_, bool>(
        "SELECT TRUE FROM users
         WHERE id=$1 AND username=$2 AND auth_generation=$3
           AND is_admin AND NOT is_disabled FOR SHARE",
    )
    .bind(actor_id)
    .bind(actor_username)
    .bind(actor_generation)
    .fetch_optional(&mut **tx)
    .await?
    .is_some())
}

/// Resolve the exact account incarnations named by an administrative form.
/// Every mutating entry point below compares both UUID and username again
/// after locking, so a delete/recreate race cannot redirect a command to the
/// replacement account.
pub async fn resolve_admin_account_identities(
    pool: &PgPool,
    usernames: &[String],
) -> Result<Option<Vec<AdminAccountIdentity>>> {
    if usernames.is_empty() {
        return Ok(Some(Vec::new()));
    }
    let mut unique = usernames.to_vec();
    unique.sort();
    unique.dedup();
    if unique.len() != usernames.len() {
        return Ok(None);
    }
    let rows = sqlx::query("SELECT id,username FROM users WHERE username=ANY($1)")
        .bind(&unique)
        .fetch_all(pool)
        .await?;
    if rows.len() != unique.len() {
        return Ok(None);
    }
    let by_name = rows
        .into_iter()
        .map(|row| (row.get::<String, _>("username"), row.get::<Uuid, _>("id")))
        .collect::<HashMap<_, _>>();
    Ok(usernames
        .iter()
        .map(|username| {
            by_name
                .get(username)
                .copied()
                .map(|id| AdminAccountIdentity {
                    id,
                    username: username.clone(),
                })
        })
        .collect())
}

#[allow(clippy::too_many_arguments)]
pub async fn create_admin_account_authorized(
    pool: &PgPool,
    fence: AdminCommandFence<'_>,
    username: &str,
    password: &str,
    scram_iterations: u32,
    scram_sha1_enabled: bool,
) -> Result<AdminCreateAccountOutcome> {
    let username = northstar_auth_core::normalize_username(username)?;
    let password = zeroize::Zeroizing::new(password.to_owned());
    let credentials = crate::security::password_work::run(move || {
        northstar_auth_core::hash_password(&password, true, scram_iterations, scram_sha1_enabled)
    })
    .await
    .map_err(anyhow::Error::from)
    .context("password hashing task failed")?;

    let mut tx = pool.begin().await?;
    sqlx::query("SET LOCAL lock_timeout='2s'")
        .execute(&mut *tx)
        .await?;
    sqlx::query("SET LOCAL statement_timeout='15s'")
        .execute(&mut *tx)
        .await?;
    let user_id = Uuid::new_v4();
    let scram_iterations = i32::try_from(credentials.scram_iterations)?;
    let sha1_iterations = credentials
        .scram_sha1_stored_key
        .as_ref()
        .map(|_| scram_iterations);
    let outcome: String = sqlx::query_scalar(
        "SELECT northstar_admin_command_create_user(
            $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)",
    )
    .bind(fence.claim_token)
    .bind(fence.actor_id)
    .bind(fence.actor_username)
    .bind(fence.actor_generation)
    .bind(fence.node)
    .bind(fence.target_digest)
    .bind(user_id)
    .bind(&username)
    .bind(&credentials.hash)
    .bind(&credentials.scram_salt)
    .bind(scram_iterations)
    .bind(&credentials.scram_stored_key)
    .bind(&credentials.scram_server_key)
    .bind(&credentials.scram_sha1_salt)
    .bind(sha1_iterations)
    .bind(&credentials.scram_sha1_stored_key)
    .bind(&credentials.scram_sha1_server_key)
    .bind(fence.result_payload)
    .fetch_one(&mut *tx)
    .await?;
    let outcome = match outcome.as_str() {
        "created" => AdminCreateAccountOutcome::Created,
        "username_taken" => AdminCreateAccountOutcome::UsernameTaken,
        "capacity_exhausted" => AdminCreateAccountOutcome::CapacityExhausted,
        "unauthorized" => AdminCreateAccountOutcome::Unauthorized,
        other => anyhow::bail!("admin create-user capability returned {other:?}"),
    };
    if outcome == AdminCreateAccountOutcome::Created {
        tx.commit().await?;
    } else {
        tx.rollback().await?;
    }
    Ok(outcome)
}

#[allow(clippy::too_many_arguments)]
pub async fn reset_admin_account_password_authorized(
    pool: &PgPool,
    fence: AdminCommandFence<'_>,
    target: &AdminAccountIdentity,
    password: &str,
    scram_iterations: u32,
    scram_sha1_enabled: bool,
    bare_jid: &str,
) -> Result<AdminAccountWriteOutcome> {
    let bare_jid = northstar_xmpp_types::jid::CanonicalJid::parse_bare(bare_jid)?;
    anyhow::ensure!(
        bare_jid.localpart() == Some(target.username.as_str()),
        "password-reset JID does not match the target account"
    );
    let password = zeroize::Zeroizing::new(password.to_owned());
    let credentials = crate::security::password_work::run(move || {
        northstar_auth_core::hash_password(&password, true, scram_iterations, scram_sha1_enabled)
    })
    .await
    .map_err(anyhow::Error::from)
    .context("password hashing task failed")?;
    let mut tx = pool.begin().await?;
    sqlx::query("SET LOCAL lock_timeout='2s'")
        .execute(&mut *tx)
        .await?;
    sqlx::query("SET LOCAL statement_timeout='15s'")
        .execute(&mut *tx)
        .await?;
    let scram_iterations = i32::try_from(credentials.scram_iterations)?;
    let sha1_iterations = credentials
        .scram_sha1_stored_key
        .as_ref()
        .map(|_| scram_iterations);
    let outcome: String = sqlx::query_scalar(
        "SELECT northstar_admin_command_reset_user_password(
            $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19)",
    )
    .bind(fence.claim_token)
    .bind(fence.actor_id)
    .bind(fence.actor_username)
    .bind(fence.actor_generation)
    .bind(fence.node)
    .bind(fence.target_digest)
    .bind(target.id)
    .bind(&target.username)
    .bind(&credentials.hash)
    .bind(&credentials.scram_salt)
    .bind(scram_iterations)
    .bind(&credentials.scram_stored_key)
    .bind(&credentials.scram_server_key)
    .bind(&credentials.scram_sha1_salt)
    .bind(sha1_iterations)
    .bind(&credentials.scram_sha1_stored_key)
    .bind(&credentials.scram_sha1_server_key)
    .bind(bare_jid.to_string())
    .bind(fence.result_payload)
    .fetch_one(&mut *tx)
    .await?;
    let outcome = match outcome.as_str() {
        "applied" => AdminAccountWriteOutcome::Applied,
        "unauthorized" => AdminAccountWriteOutcome::Unauthorized,
        "target_changed" => AdminAccountWriteOutcome::TargetChanged,
        other => anyhow::bail!("admin password-reset capability returned {other:?}"),
    };
    if outcome == AdminAccountWriteOutcome::Applied {
        tx.commit().await?;
    } else {
        tx.rollback().await?;
    }
    Ok(outcome)
}

#[allow(clippy::too_many_arguments)]
pub async fn mutate_admin_accounts_authorized(
    pool: &PgPool,
    fence: AdminCommandFence<'_>,
    targets: &[AdminAccountMutationTarget],
    action: AdminAccountMutationAction,
    domain: &str,
) -> Result<AdminBatchAccountWriteOutcome> {
    mutate_admin_accounts_authorized_inner(pool, fence, targets, action, domain, None).await
}

pub async fn replace_admins_authorized(
    pool: &PgPool,
    fence: AdminCommandFence<'_>,
    expected: &[AdminAccountIdentity],
) -> Result<AdminAccountWriteOutcome> {
    anyhow::ensure!(!expected.is_empty(), "administrator list cannot be empty");
    anyhow::ensure!(expected.len() <= 200, "administrator list is too large");
    let mut ids = expected.iter().map(|target| target.id).collect::<Vec<_>>();
    ids.sort_unstable();
    ids.dedup();
    if ids.len() != expected.len() || !ids.contains(&fence.actor_id) {
        return Ok(AdminAccountWriteOutcome::SelfMutation);
    }
    let mut tx = pool.begin().await?;
    sqlx::query("SET LOCAL lock_timeout='2s'")
        .execute(&mut *tx)
        .await?;
    sqlx::query("SET LOCAL statement_timeout='15s'")
        .execute(&mut *tx)
        .await?;
    let claim_session: Option<Uuid> =
        sqlx::query_scalar("SELECT northstar_admin_command_authorize_claim($1,$2,$3,$4,$5,$6)")
            .bind(fence.claim_token)
            .bind(fence.actor_id)
            .bind(fence.actor_username)
            .bind(fence.actor_generation)
            .bind(fence.node)
            .bind(fence.target_digest)
            .fetch_one(&mut *tx)
            .await?;
    if claim_session.is_none() {
        tx.rollback().await?;
        return Ok(AdminAccountWriteOutcome::Unauthorized);
    }
    sqlx::query("SELECT pg_advisory_xact_lock(5645368709120101)")
        .execute(&mut *tx)
        .await?;
    // Lock both the current and requested administrator sets in one UUID-ordered
    // statement.  A promotion racing this command is therefore either included
    // in this replacement or waits until the replacement has committed; it
    // cannot introduce a row-lock inversion through a stale pre-lock snapshot.
    sqlx::query_scalar::<_, Uuid>(
        "SELECT id FROM users
         WHERE is_admin OR id=ANY($1) OR id=$2
         ORDER BY id FOR UPDATE",
    )
    .bind(&ids)
    .bind(fence.actor_id)
    .fetch_all(&mut *tx)
    .await?;
    if !admin_authorized_in_tx(
        &mut tx,
        fence.actor_id,
        fence.actor_username,
        fence.actor_generation,
    )
    .await?
    {
        tx.rollback().await?;
        return Ok(AdminAccountWriteOutcome::Unauthorized);
    }
    let rows = sqlx::query("SELECT id,username,is_disabled FROM users WHERE id=ANY($1)")
        .bind(&ids)
        .fetch_all(&mut *tx)
        .await?;
    if rows.len() != expected.len() {
        tx.rollback().await?;
        return Ok(AdminAccountWriteOutcome::TargetChanged);
    }
    let exact = rows
        .into_iter()
        .map(|row| {
            (
                row.get::<Uuid, _>("id"),
                (
                    row.get::<String, _>("username"),
                    row.get::<bool, _>("is_disabled"),
                ),
            )
        })
        .collect::<HashMap<_, _>>();
    if expected.iter().any(|target| {
        exact
            .get(&target.id)
            .is_none_or(|(username, disabled)| username != &target.username || *disabled)
    }) {
        tx.rollback().await?;
        return Ok(AdminAccountWriteOutcome::TargetChanged);
    }
    let changed: Option<Vec<Uuid>> =
        sqlx::query_scalar("SELECT northstar_admin_command_replace_users($1,$2,$3,$4,$5,$6,$7,$8)")
            .bind(fence.claim_token)
            .bind(fence.actor_id)
            .bind(fence.actor_username)
            .bind(fence.actor_generation)
            .bind(fence.node)
            .bind(fence.target_digest)
            .bind(&ids)
            .bind(fence.result_payload)
            .fetch_one(&mut *tx)
            .await?;
    if changed.is_none() {
        tx.rollback().await?;
        return Ok(AdminAccountWriteOutcome::Unauthorized);
    }
    tx.commit().await?;
    Ok(AdminAccountWriteOutcome::Applied)
}
