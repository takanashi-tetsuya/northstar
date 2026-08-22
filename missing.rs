pub async fn create_user(
    pool: &PgPool,
    username: &str,
    password: &str,
    admin: bool,
) -> Result<User> {
    let username = auth::normalize_username(username)?;
    let password = password.to_owned();
    let _permit = PASSWORD_WORK
        .acquire()
        .await
        .context("password worker queue closed")?;
    let password_hash = tokio::task::spawn_blocking(move || auth::hash_password(&password))
        .await
        .context("password hashing task failed")??;
    drop(_permit);
    let row = sqlx::query(
        "INSERT INTO users (id, username, password_hash, is_admin) VALUES ($1, $2, $3, $4) RETURNING *",
    )
    .bind(Uuid::new_v4())
    .bind(username)
    .bind(password_hash)
    .bind(admin)
    .fetch_one(pool)
    .await
    .context("could not create user")?;
    Ok(user_from_row(&row))
}

pub async fn create_user_with_invitation(
    pool: &PgPool,
    username: &str,
    password: &str,
    invitation_token: Option<&str>,
    invitation_required: bool,
) -> Result<User> {
    let username = auth::normalize_username(username)?;
    let password = password.to_owned();
    let _permit = PASSWORD_WORK.acquire().await.context("password worker queue closed")?;
    let password_hash = tokio::task::spawn_blocking(move || auth::hash_password(&password))
        .await.context("password hashing task failed")??;
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
        "INSERT INTO users (id, username, password_hash, is_admin) VALUES ($1, $2, $3, FALSE) RETURNING *",
    )
    .bind(Uuid::new_v4()).bind(username).bind(password_hash)
    .fetch_one(&mut *tx).await.context("could not create user")?;
    tx.commit().await?;
    Ok(user_from_row(&row))
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

