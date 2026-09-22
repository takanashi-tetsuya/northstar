use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::Value;
use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

#[derive(sqlx::FromRow, Serialize)]
pub(crate) struct Credential {
    pub id: Uuid,
    pub label: String,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
    #[serde(skip)]
    pub credential: Value,
    #[serde(skip)]
    pub revision: Uuid,
}

pub(crate) async fn credentials(pool: &PgPool, user: Uuid) -> Result<Vec<Credential>> {
    Ok(sqlx::query_as(
        "SELECT id,label,created_at,last_used_at,credential,revision
        FROM webauthn_credentials WHERE user_id=$1 ORDER BY created_at,id LIMIT 10",
    )
    .bind(user)
    .fetch_all(pool)
    .await?)
}

pub(crate) async fn credentials_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    user: Uuid,
) -> Result<Vec<Credential>> {
    Ok(sqlx::query_as(
        "SELECT id,label,created_at,last_used_at,credential,revision
        FROM webauthn_credentials WHERE user_id=$1 ORDER BY created_at,id LIMIT 10",
    )
    .bind(user)
    .fetch_all(&mut **tx)
    .await?)
}

pub(crate) async fn challenge(
    pool: &PgPool,
    user: Uuid,
    generation: i64,
    kind: &str,
    session_hash: Option<&[u8]>,
    state: &Value,
) -> Result<Option<Uuid>> {
    Ok(
        sqlx::query_scalar("SELECT northstar_passkey_challenge($1,$2,$3,$4,$5)")
            .bind(user)
            .bind(generation)
            .bind(kind)
            .bind(session_hash)
            .bind(state)
            .fetch_one(pool)
            .await?,
    )
}

#[derive(sqlx::FromRow)]
pub(crate) struct Challenge {
    pub user_id: Uuid,
    pub auth_generation: i64,
    pub state: Value,
}

pub(crate) async fn consume(
    pool: &PgPool,
    id: Uuid,
    kind: &str,
    session_hash: Option<&[u8]>,
) -> Result<Option<Challenge>> {
    Ok(
        sqlx::query_as("SELECT * FROM northstar_passkey_consume($1,$2,$3)")
            .bind(id)
            .bind(kind)
            .bind(session_hash)
            .fetch_optional(pool)
            .await?,
    )
}

pub(crate) async fn register(
    pool: &PgPool,
    user: Uuid,
    generation: i64,
    session_hash: &[u8],
    credential_id: &[u8],
    credential: &Value,
    label: &str,
) -> Result<Option<Uuid>> {
    Ok(
        sqlx::query_scalar("SELECT northstar_passkey_register($1,$2,$3,$4,$5,$6)")
            .bind(user)
            .bind(generation)
            .bind(session_hash)
            .bind(credential_id)
            .bind(credential)
            .bind(label)
            .fetch_one(pool)
            .await?,
    )
}

pub(crate) async fn accept(
    tx: &mut Transaction<'_, Postgres>,
    user: Uuid,
    generation: i64,
    id: Uuid,
    revision: Uuid,
    credential: &Value,
    counter: u32,
) -> Result<bool> {
    Ok(
        sqlx::query_scalar("SELECT northstar_passkey_accept($1,$2,$3,$4,$5,$6)")
            .bind(user)
            .bind(generation)
            .bind(id)
            .bind(revision)
            .bind(credential)
            .bind(i64::from(counter))
            .fetch_one(&mut **tx)
            .await?,
    )
}

pub(crate) async fn remove(
    pool: &PgPool,
    user: Uuid,
    generation: i64,
    session_hash: &[u8],
    id: Uuid,
) -> Result<Option<i64>> {
    Ok(
        sqlx::query_scalar("SELECT northstar_passkey_remove($1,$2,$3,$4)")
            .bind(user)
            .bind(generation)
            .bind(session_hash)
            .bind(id)
            .fetch_one(pool)
            .await?,
    )
}

use crate::services::passkeys::{
    PasskeyAccount, PasskeyActor, PasskeyLoginCommit, PasskeyLoginSession, PasskeyRepository,
    StoredChallenge, StoredCredential,
};
use std::sync::Arc;
use zeroize::Zeroizing;

pub(crate) struct PostgresPasskeyRepository {
    pool: PgPool,
    fast_token_secret: Arc<Zeroizing<Vec<u8>>>,
}

impl PostgresPasskeyRepository {
    pub(crate) fn new(pool: PgPool, fast_token_secret: Arc<Zeroizing<Vec<u8>>>) -> Self {
        Self {
            pool,
            fast_token_secret,
        }
    }
}

impl From<Credential> for StoredCredential {
    fn from(key: Credential) -> Self {
        Self {
            id: key.id,
            label: key.label,
            created_at: key.created_at,
            last_used_at: key.last_used_at,
            credential: key.credential,
            revision: key.revision,
        }
    }
}

impl PasskeyRepository for PostgresPasskeyRepository {
    async fn account(&self, username: &str) -> Result<Option<PasskeyAccount>> {
        Ok(super::find_enabled_user(&self.pool, username)
            .await?
            .map(|user| PasskeyAccount {
                id: user.id,
                auth_generation: user.auth_generation,
            }))
    }

    async fn credentials(&self, user_id: Uuid) -> Result<Vec<StoredCredential>> {
        Ok(credentials(&self.pool, user_id)
            .await?
            .into_iter()
            .map(Into::into)
            .collect())
    }

    async fn authorized_credentials(
        &self,
        actor: &PasskeyActor<'_>,
    ) -> Result<Option<Vec<StoredCredential>>> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
            .execute(&mut *tx)
            .await?;
        if !super::authorize_user_in_tx(
            &mut tx,
            actor.id,
            actor.auth_generation,
            actor.session_token,
        )
        .await?
        {
            tx.rollback().await?;
            return Ok(None);
        }
        let keys = credentials_in_tx(&mut tx, actor.id).await?;
        tx.commit().await?;
        Ok(Some(keys.into_iter().map(Into::into).collect()))
    }

    async fn verify_password(
        &self,
        actor: &PasskeyActor<'_>,
        password: &str,
        iterations: u32,
        sha1: bool,
    ) -> Result<bool> {
        Ok(
            super::prepare_login(&self.pool, actor.username, password, iterations, sha1)
                .await?
                .is_some_and(|login| {
                    login.user.id == actor.id && login.user.auth_generation == actor.auth_generation
                }),
        )
    }

    async fn challenge(
        &self,
        user: Uuid,
        generation: i64,
        kind: &str,
        session_hash: Option<&[u8]>,
        state: &Value,
    ) -> Result<Option<Uuid>> {
        challenge(&self.pool, user, generation, kind, session_hash, state).await
    }

    async fn consume(
        &self,
        id: Uuid,
        kind: &str,
        session_hash: Option<&[u8]>,
    ) -> Result<Option<StoredChallenge>> {
        Ok(consume(&self.pool, id, kind, session_hash)
            .await?
            .map(|challenge| StoredChallenge {
                user_id: challenge.user_id,
                auth_generation: challenge.auth_generation,
                state: challenge.state,
            }))
    }

    async fn register(
        &self,
        actor: &PasskeyActor<'_>,
        credential_id: &[u8],
        credential: &Value,
        label: &str,
    ) -> Result<Option<Uuid>> {
        register(
            &self.pool,
            actor.id,
            actor.auth_generation,
            &crate::auth::token_hash(actor.session_token),
            credential_id,
            credential,
            label,
        )
        .await
    }

    async fn complete_login(
        &self,
        command: PasskeyLoginCommit<'_>,
    ) -> Result<Option<PasskeyLoginSession>> {
        let mut tx = self.pool.begin().await?;
        if !accept(
            &mut tx,
            command.user_id,
            command.auth_generation,
            command.credential_id,
            command.credential_revision,
            command.credential,
            command.counter,
        )
        .await?
        {
            tx.rollback().await?;
            return Ok(None);
        }
        let fast = super::issue_fast_token_in_transaction(
            &mut tx,
            &self.fast_token_secret,
            command.user_id,
            command.device_id,
            "HT-SHA-256-NONE",
            command.auth_generation,
            command.fast_token_ttl_days,
            command.fast_strong_reauth_max_days,
            None,
        )
        .await?;
        let session = super::create_api_session_in_tx(
            &mut tx,
            command.user_id,
            command.session_ttl_hours,
            None,
        )
        .await?;
        let Some(user) = super::user_for_token_in_tx(&mut tx, &session.token).await? else {
            tx.rollback().await?;
            return Ok(None);
        };
        tx.commit().await?;
        Ok(Some(PasskeyLoginSession {
            token: Zeroizing::new(session.token),
            username: user.username,
            is_admin: user.is_admin,
            fast_token: fast.token,
            fast_expires_at: fast.expires_at,
        }))
    }

    async fn remove(&self, actor: &PasskeyActor<'_>, id: Uuid) -> Result<Option<i64>> {
        remove(
            &self.pool,
            actor.id,
            actor.auth_generation,
            &crate::auth::token_hash(actor.session_token),
            id,
        )
        .await
    }
}

#[cfg(test)]
#[path = "passkeys_test.rs"]
mod tests;
