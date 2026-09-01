use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Postgres, Row, Transaction};
use subtle::ConstantTimeEq;
use uuid::Uuid;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OmemoRecoveryTransfer {
    pub id: Uuid,
    pub user_id: Uuid,
    pub generation: i64,
    pub source_device_id: i64,
    pub package_sha256: Option<[u8; 32]>,
    pub state: String,
    pub consumer_commitment: Option<[u8; 32]>,
    pub consumed_auth_generation: Option<i64>,
    pub created_at: DateTime<Utc>,
    pub prepared_at: Option<DateTime<Utc>>,
    pub consumed_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub expires_at: DateTime<Utc>,
    pub expired: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OmemoRecoveryAuthority {
    pub next_generation: i64,
    pub latest_consumed_generation: i64,
    pub latest_consumed_transfer_id: Option<Uuid>,
    pub latest_consumer_commitment: Option<[u8; 32]>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OmemoRecoveryPollStatus {
    pub generation: i64,
    pub state: String,
}

const CONSUMER_COMMITMENT_DOMAIN: &[u8] = b"Northstar OMEMO recovery consumer v1\0";
const SOURCE_POLL_DOMAIN: &[u8] = b"Northstar OMEMO recovery source poll v1\0";

fn recovery_secret_digest(
    purpose: &[u8],
    canonical_account: &str,
    transfer_id: Uuid,
    secret: &[u8; 32],
) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(purpose);
    digest.update(canonical_account.as_bytes());
    digest.update([0]);
    digest.update(transfer_id.as_bytes());
    digest.update(secret);
    digest.finalize().into()
}

pub fn omemo_recovery_consumer_commitment(
    canonical_account: &str,
    transfer_id: Uuid,
    consumer_secret: &[u8; 32],
) -> [u8; 32] {
    recovery_secret_digest(
        CONSUMER_COMMITMENT_DOMAIN,
        canonical_account,
        transfer_id,
        consumer_secret,
    )
}

fn omemo_recovery_poll_secret_hash(
    canonical_account: &str,
    transfer_id: Uuid,
    poll_secret: &[u8; 32],
) -> [u8; 32] {
    recovery_secret_digest(
        SOURCE_POLL_DOMAIN,
        canonical_account,
        transfer_id,
        poll_secret,
    )
}

fn secret_digest_matches(stored: &[u8], expected: &[u8; 32]) -> bool {
    stored.len() == 32 && bool::from(stored.ct_eq(expected.as_slice()))
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PrepareOmemoRecovery {
    Prepared(OmemoRecoveryTransfer),
    Replay(OmemoRecoveryTransfer),
    Conflict,
    Unauthorized,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SealOmemoRecovery {
    Sealed(OmemoRecoveryTransfer),
    Replay(OmemoRecoveryTransfer),
    Missing,
    Expired,
    Conflict,
    Unauthorized,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConsumeOmemoRecovery {
    Consumed(OmemoRecoveryTransfer),
    Replay(OmemoRecoveryTransfer),
    Missing,
    Expired,
    Conflict,
    Unauthorized,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RevokeOmemoRecovery {
    Revoked,
    Replay,
    Missing,
    Conflict,
    Unauthorized,
}

fn transfer_from_row(row: &sqlx::postgres::PgRow) -> Result<OmemoRecoveryTransfer> {
    let digest = row
        .try_get::<Option<Vec<u8>>, _>("package_sha256")?
        .map(|value| {
            value
                .try_into()
                .map_err(|_| anyhow::anyhow!("stored OMEMO recovery digest has invalid length"))
        })
        .transpose()?;
    let consumer_commitment = row
        .try_get::<Option<Vec<u8>>, _>("consumer_commitment")?
        .map(|value| {
            value.try_into().map_err(|_| {
                anyhow::anyhow!("stored OMEMO recovery consumer commitment has invalid length")
            })
        })
        .transpose()?;
    Ok(OmemoRecoveryTransfer {
        id: row.try_get("id")?,
        user_id: row.try_get("user_id")?,
        generation: row.try_get("generation")?,
        source_device_id: row.try_get("source_device_id")?,
        package_sha256: digest,
        state: row.try_get("state")?,
        consumer_commitment,
        consumed_auth_generation: row.try_get("consumed_auth_generation")?,
        created_at: row.try_get("created_at")?,
        prepared_at: row.try_get("prepared_at")?,
        consumed_at: row.try_get("consumed_at")?,
        revoked_at: row.try_get("revoked_at")?,
        expires_at: row.try_get("expires_at")?,
        expired: row.try_get("expired")?,
    })
}

const TRANSFER_COLUMNS: &str =
    "id,user_id,generation,source_device_id,package_sha256,state,consumer_commitment,\
     consumed_auth_generation,\
     created_at,prepared_at,consumed_at,revoked_at,expires_at,\
     (expires_at<=clock_timestamp()) AS expired";

async fn transfer_for_update(
    tx: &mut Transaction<'_, Postgres>,
    user_id: Uuid,
    transfer_id: Uuid,
) -> Result<Option<OmemoRecoveryTransfer>> {
    let query = format!(
        "SELECT {TRANSFER_COLUMNS} FROM omemo_recovery_transfers \
         WHERE id=$1 AND user_id=$2 FOR UPDATE"
    );
    sqlx::query(&query)
        .bind(transfer_id)
        .bind(user_id)
        .fetch_optional(&mut **tx)
        .await?
        .map(|row| transfer_from_row(&row))
        .transpose()
}

/// Revalidate and exclusively serialize an authenticated recovery mutation at
/// its database commit boundary.  A handler-level bearer lookup is not enough:
/// logout or a password/authorization rotation may commit while the request is
/// waiting for another recovery row lock.
async fn authorize_recovery_mutation(
    tx: &mut Transaction<'_, Postgres>,
    user_id: Uuid,
    expected_auth_generation: i64,
    presented_session: &str,
) -> Result<bool> {
    if expected_auth_generation < 0
        || presented_session.len() != 64
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
         WHERE actor.id=$1 AND actor.auth_generation=$2
           AND NOT actor.is_disabled
           AND session.token_hash=$3
           AND session.expires_at > clock_timestamp()
         FOR UPDATE OF actor,session",
    )
    .bind(user_id)
    .bind(expected_auth_generation)
    .bind(crate::auth::token_hash(presented_session))
    .fetch_optional(&mut **tx)
    .await?
    .is_some())
}

async fn audit_transfer_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    user_id: Uuid,
    transfer_id: Uuid,
    action: &str,
    details: serde_json::Value,
) -> Result<()> {
    sqlx::query("INSERT INTO audit_log(actor_id,action,target,details) VALUES($1,$2,$3,$4)")
        .bind(user_id)
        .bind(action)
        .bind(transfer_id.to_string())
        .bind(details)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

pub struct PrepareOmemoRecoveryRequest<'a> {
    pub user_id: Uuid,
    pub canonical_account: &'a str,
    pub expected_auth_generation: i64,
    pub presented_session: &'a str,
    pub transfer_id: Uuid,
    pub source_device_id: i64,
    pub poll_secret: &'a [u8; 32],
}

pub async fn prepare_omemo_recovery_transfer(
    pool: &PgPool,
    request: PrepareOmemoRecoveryRequest<'_>,
) -> Result<PrepareOmemoRecovery> {
    let PrepareOmemoRecoveryRequest {
        user_id,
        canonical_account,
        expected_auth_generation,
        presented_session,
        transfer_id,
        source_device_id,
        poll_secret,
    } = request;
    anyhow::ensure!(
        (1..=2_147_483_647).contains(&source_device_id),
        "OMEMO recovery source device ID is invalid"
    );
    let poll_secret_hash =
        omemo_recovery_poll_secret_hash(canonical_account, transfer_id, poll_secret);
    let mut tx = pool.begin().await?;
    if !authorize_recovery_mutation(
        &mut tx,
        user_id,
        expected_auth_generation,
        presented_session,
    )
    .await?
    {
        tx.rollback().await?;
        return Ok(PrepareOmemoRecovery::Unauthorized);
    }
    let mut advisory_bytes = [0_u8; 8];
    advisory_bytes.copy_from_slice(&transfer_id.as_bytes()[..8]);
    let advisory_key = i64::from_be_bytes(advisory_bytes);
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(advisory_key)
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        "INSERT INTO omemo_recovery_counters(user_id,next_generation) VALUES($1,1) \
         ON CONFLICT (user_id) DO NOTHING",
    )
    .bind(user_id)
    .execute(&mut *tx)
    .await?;
    let next_generation: i64 = sqlx::query_scalar(
        "SELECT next_generation FROM omemo_recovery_counters \
         WHERE user_id=$1 FOR UPDATE",
    )
    .bind(user_id)
    .fetch_one(&mut *tx)
    .await?;

    // Recheck after taking the per-account generation lock. Two uncertain
    // HTTP retries with the same transfer UUID must never allocate twice.
    let any_existing = sqlx::query(&format!(
        "SELECT {TRANSFER_COLUMNS} FROM omemo_recovery_transfers WHERE id=$1"
    ))
    .bind(transfer_id)
    .fetch_optional(&mut *tx)
    .await?;
    if let Some(row) = any_existing {
        let existing = transfer_from_row(&row)?;
        if existing.user_id == user_id
            && existing.expired
            && matches!(existing.state.as_str(), "preparing" | "prepared")
        {
            revoke_expired_in_tx(&mut tx, transfer_id, user_id).await?;
            tx.commit().await?;
            return Ok(PrepareOmemoRecovery::Conflict);
        }
        let poll_hash = if existing.user_id == user_id {
            sqlx::query_scalar::<_, Vec<u8>>(
                "SELECT secret_hash FROM omemo_recovery_poll_capabilities \
                 WHERE transfer_id=$1 AND user_id=$2",
            )
            .bind(transfer_id)
            .bind(user_id)
            .fetch_optional(&mut *tx)
            .await?
        } else {
            None
        };
        tx.commit().await?;
        return if existing.user_id == user_id
            && existing.source_device_id == source_device_id
            && poll_hash
                .as_deref()
                .is_some_and(|stored| secret_digest_matches(stored, &poll_secret_hash))
        {
            Ok(PrepareOmemoRecovery::Replay(existing))
        } else {
            Ok(PrepareOmemoRecovery::Conflict)
        };
    }

    sqlx::query(
        "UPDATE omemo_recovery_transfers SET state='revoked',\
                revoked_at=clock_timestamp() \
         WHERE user_id=$1 AND state IN ('preparing','prepared') \
           AND expires_at<=clock_timestamp()",
    )
    .bind(user_id)
    .execute(&mut *tx)
    .await?;

    let active_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM omemo_recovery_transfers \
         WHERE user_id=$1 AND state IN ('preparing','prepared'))",
    )
    .bind(user_id)
    .fetch_one(&mut *tx)
    .await?;
    if active_exists {
        tx.commit().await?;
        return Ok(PrepareOmemoRecovery::Conflict);
    }

    anyhow::ensure!(
        next_generation < 9_007_199_254_740_991_i64,
        "OMEMO recovery generation is exhausted"
    );
    sqlx::query(
        "UPDATE omemo_recovery_counters SET next_generation=next_generation+1,\
                updated_at=clock_timestamp() WHERE user_id=$1",
    )
    .bind(user_id)
    .execute(&mut *tx)
    .await?;
    // The high-water fence lives in omemo_recovery_counters, so old terminal
    // request rows may be compacted without allowing rollback. Keeping the
    // newest 63 plus the new active row bounds storage per account even if an
    // authenticated client repeatedly allocates and revokes transfers.
    sqlx::query(
        "DELETE FROM omemo_recovery_transfers WHERE id IN (\
             SELECT id FROM omemo_recovery_transfers \
              WHERE user_id=$1 AND state IN ('consumed','revoked') \
              ORDER BY generation DESC OFFSET 63)",
    )
    .bind(user_id)
    .execute(&mut *tx)
    .await?;
    let row = sqlx::query(&format!(
        "INSERT INTO omemo_recovery_transfers(\
             id,user_id,generation,source_device_id,state,expires_at) \
         VALUES($1,$2,$3,$4,'preparing',\
                clock_timestamp()+INTERVAL '7 days') \
         RETURNING {TRANSFER_COLUMNS}"
    ))
    .bind(transfer_id)
    .bind(user_id)
    .bind(next_generation)
    .bind(source_device_id)
    .fetch_one(&mut *tx)
    .await?;
    let transfer = transfer_from_row(&row)?;
    sqlx::query(
        "INSERT INTO omemo_recovery_poll_capabilities(\
             transfer_id,user_id,secret_hash,expires_at) \
         VALUES($1,$2,$3,$4+INTERVAL '1 day')",
    )
    .bind(transfer_id)
    .bind(user_id)
    .bind(poll_secret_hash.as_slice())
    .bind(transfer.expires_at)
    .execute(&mut *tx)
    .await?;
    audit_transfer_in_tx(
        &mut tx,
        user_id,
        transfer_id,
        "user.omemo_recovery.prepare",
        serde_json::json!({
            "generation": transfer.generation,
            "source_device_id": source_device_id,
        }),
    )
    .await?;
    tx.commit().await?;
    Ok(PrepareOmemoRecovery::Prepared(transfer))
}

async fn revoke_expired_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    transfer_id: Uuid,
    user_id: Uuid,
) -> Result<()> {
    sqlx::query(
        "UPDATE omemo_recovery_transfers SET state='revoked',\
                revoked_at=clock_timestamp() \
         WHERE id=$1 AND user_id=$2 AND state IN ('preparing','prepared') \
           AND expires_at<=clock_timestamp()",
    )
    .bind(transfer_id)
    .bind(user_id)
    .execute(&mut **tx)
    .await?;
    sqlx::query(
        "UPDATE omemo_recovery_poll_capabilities \
         SET expires_at=LEAST(expires_at,clock_timestamp()+INTERVAL '24 hours') \
         WHERE transfer_id=$1 AND user_id=$2",
    )
    .bind(transfer_id)
    .bind(user_id)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

pub async fn seal_omemo_recovery_transfer(
    pool: &PgPool,
    user_id: Uuid,
    expected_auth_generation: i64,
    presented_session: &str,
    transfer_id: Uuid,
    package_sha256: &[u8; 32],
) -> Result<SealOmemoRecovery> {
    let mut tx = pool.begin().await?;
    if !authorize_recovery_mutation(
        &mut tx,
        user_id,
        expected_auth_generation,
        presented_session,
    )
    .await?
    {
        tx.rollback().await?;
        return Ok(SealOmemoRecovery::Unauthorized);
    }
    let Some(existing) = transfer_for_update(&mut tx, user_id, transfer_id).await? else {
        tx.rollback().await?;
        return Ok(SealOmemoRecovery::Missing);
    };
    if existing.expired && matches!(existing.state.as_str(), "preparing" | "prepared") {
        revoke_expired_in_tx(&mut tx, transfer_id, user_id).await?;
        tx.commit().await?;
        return Ok(SealOmemoRecovery::Expired);
    }
    if existing.state == "prepared" && existing.package_sha256 == Some(*package_sha256) {
        tx.commit().await?;
        return Ok(SealOmemoRecovery::Replay(existing));
    }
    if existing.state != "preparing" || existing.package_sha256.is_some() {
        tx.rollback().await?;
        return Ok(SealOmemoRecovery::Conflict);
    }
    let row = sqlx::query(&format!(
        "UPDATE omemo_recovery_transfers SET state='prepared',package_sha256=$3,\
                prepared_at=clock_timestamp() \
         WHERE id=$1 AND user_id=$2 RETURNING {TRANSFER_COLUMNS}"
    ))
    .bind(transfer_id)
    .bind(user_id)
    .bind(package_sha256.as_slice())
    .fetch_one(&mut *tx)
    .await?;
    let transfer = transfer_from_row(&row)?;
    audit_transfer_in_tx(
        &mut tx,
        user_id,
        transfer_id,
        "user.omemo_recovery.seal",
        serde_json::json!({"generation": transfer.generation}),
    )
    .await?;
    tx.commit().await?;
    Ok(SealOmemoRecovery::Sealed(transfer))
}

pub struct ConsumeOmemoRecoveryRequest<'a> {
    pub user_id: Uuid,
    pub canonical_account: &'a str,
    pub expected_auth_generation: i64,
    pub presented_session: &'a str,
    pub transfer_id: Uuid,
    pub consumer_secret: &'a [u8; 32],
    pub package_sha256: &'a [u8; 32],
}

pub async fn consume_omemo_recovery_transfer(
    pool: &PgPool,
    request: ConsumeOmemoRecoveryRequest<'_>,
) -> Result<ConsumeOmemoRecovery> {
    let ConsumeOmemoRecoveryRequest {
        user_id,
        canonical_account,
        expected_auth_generation,
        presented_session,
        transfer_id,
        consumer_secret,
        package_sha256,
    } = request;
    let mut tx = pool.begin().await?;
    if !authorize_recovery_mutation(
        &mut tx,
        user_id,
        expected_auth_generation,
        presented_session,
    )
    .await?
    {
        tx.rollback().await?;
        return Ok(ConsumeOmemoRecovery::Unauthorized);
    }
    // Compute the proof only after the exact bearer and account generation are
    // locked.  The raw 256-bit secret is never bound to SQL or persisted.
    let consumer_commitment =
        omemo_recovery_consumer_commitment(canonical_account, transfer_id, consumer_secret);
    // Account authority is always locked before an individual transfer. This
    // is the same order used by prepare and prevents a newer generation from
    // racing the durable consumed high-water fence.
    let authority = sqlx::query(
        "SELECT next_generation,latest_consumed_generation \
         FROM omemo_recovery_counters WHERE user_id=$1 FOR UPDATE",
    )
    .bind(user_id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(authority) = authority else {
        tx.rollback().await?;
        return Ok(ConsumeOmemoRecovery::Missing);
    };
    let Some(existing) = transfer_for_update(&mut tx, user_id, transfer_id).await? else {
        tx.rollback().await?;
        return Ok(ConsumeOmemoRecovery::Missing);
    };
    if existing.expired && matches!(existing.state.as_str(), "preparing" | "prepared") {
        revoke_expired_in_tx(&mut tx, transfer_id, user_id).await?;
        tx.commit().await?;
        return Ok(ConsumeOmemoRecovery::Expired);
    }
    if existing.state == "consumed"
        && existing.consumer_commitment.as_ref().is_some_and(|stored| {
            bool::from(stored.as_slice().ct_eq(consumer_commitment.as_slice()))
        })
        && existing.package_sha256 == Some(*package_sha256)
        && existing.consumed_auth_generation.is_some()
    {
        tx.commit().await?;
        return Ok(ConsumeOmemoRecovery::Replay(existing));
    }
    if existing.state != "prepared" || existing.package_sha256 != Some(*package_sha256) {
        tx.rollback().await?;
        return Ok(ConsumeOmemoRecovery::Conflict);
    }
    let latest_consumed_generation: i64 = authority.try_get("latest_consumed_generation")?;
    let next_generation: i64 = authority.try_get("next_generation")?;
    if existing.generation <= latest_consumed_generation || existing.generation >= next_generation {
        tx.rollback().await?;
        return Ok(ConsumeOmemoRecovery::Conflict);
    }
    let newer: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM omemo_recovery_transfers \
         WHERE user_id=$1 AND generation>$2)",
    )
    .bind(user_id)
    .bind(existing.generation)
    .fetch_one(&mut *tx)
    .await?;
    if newer {
        tx.rollback().await?;
        return Ok(ConsumeOmemoRecovery::Conflict);
    }
    anyhow::ensure!(
        expected_auth_generation < i64::MAX,
        "OMEMO recovery authorization generation is exhausted"
    );
    let consumed_auth_generation: Option<i64> =
        sqlx::query_scalar("SELECT northstar_user_consume_recovery_generation($1,$2,$3)")
            .bind(user_id)
            .bind(expected_auth_generation)
            .bind(crate::auth::token_hash(presented_session))
            .fetch_one(&mut *tx)
            .await?;
    let consumed_auth_generation = consumed_auth_generation
        .context("OMEMO recovery authorization changed after its locked validation")?;
    // The transfer of a live Double Ratchet state is an authorization
    // boundary, not merely a UI hint.  Make every bearer authenticated before
    // this commit ineligible in the same transaction as the one-consumer
    // fence.  Rows are retained for post-commit presence/MUC teardown.
    sqlx::query(
        "UPDATE fast_tokens SET revoked_at=clock_timestamp()
         WHERE user_id=$1 AND revoked_at IS NULL",
    )
    .bind(user_id)
    .execute(&mut *tx)
    .await?;
    sqlx::query("DELETE FROM api_sessions WHERE user_id=$1")
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query_scalar::<_, i64>("SELECT northstar_sm_expire_before_generation($1,$2)")
        .bind(user_id)
        .bind(consumed_auth_generation)
        .fetch_one(&mut *tx)
        .await?;
    let row = sqlx::query(&format!(
        "UPDATE omemo_recovery_transfers SET state='consumed',consumer_commitment=$3,\
                consumed_auth_generation=$4,consumed_at=clock_timestamp() \
         WHERE id=$1 AND user_id=$2 RETURNING {TRANSFER_COLUMNS}"
    ))
    .bind(transfer_id)
    .bind(user_id)
    .bind(consumer_commitment.as_slice())
    .bind(consumed_auth_generation)
    .fetch_one(&mut *tx)
    .await?;
    let transfer = transfer_from_row(&row)?;
    let advanced = sqlx::query(
        "UPDATE omemo_recovery_counters SET \
             latest_consumed_generation=$2,latest_consumed_transfer_id=$3,\
             latest_consumer_commitment=$4,latest_consumed_auth_generation=$5,\
             updated_at=clock_timestamp() \
         WHERE user_id=$1 AND latest_consumed_generation<$2",
    )
    .bind(user_id)
    .bind(transfer.generation)
    .bind(transfer.id)
    .bind(consumer_commitment.as_slice())
    .bind(consumed_auth_generation)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    anyhow::ensure!(
        advanced == 1,
        "OMEMO recovery authority high-water fence did not advance"
    );
    sqlx::query(
        "UPDATE omemo_recovery_poll_capabilities \
         SET expires_at=LEAST(expires_at,clock_timestamp()+INTERVAL '24 hours') \
         WHERE transfer_id=$1 AND user_id=$2",
    )
    .bind(transfer_id)
    .bind(user_id)
    .execute(&mut *tx)
    .await?;
    audit_transfer_in_tx(
        &mut tx,
        user_id,
        transfer_id,
        "user.omemo_recovery.consume",
        serde_json::json!({
            "generation": transfer.generation,
            "consumed_auth_generation": consumed_auth_generation,
        }),
    )
    .await?;
    tx.commit().await?;
    Ok(ConsumeOmemoRecovery::Consumed(transfer))
}

pub async fn omemo_recovery_authority(
    pool: &PgPool,
    user_id: Uuid,
) -> Result<OmemoRecoveryAuthority> {
    let row = sqlx::query(
        "SELECT next_generation,latest_consumed_generation,\
                latest_consumed_transfer_id,latest_consumer_commitment \
         FROM omemo_recovery_counters WHERE user_id=$1",
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await?;
    let Some(row) = row else {
        return Ok(OmemoRecoveryAuthority {
            next_generation: 1,
            latest_consumed_generation: 0,
            latest_consumed_transfer_id: None,
            latest_consumer_commitment: None,
        });
    };
    Ok(OmemoRecoveryAuthority {
        next_generation: row.try_get("next_generation")?,
        latest_consumed_generation: row.try_get("latest_consumed_generation")?,
        latest_consumed_transfer_id: row.try_get("latest_consumed_transfer_id")?,
        latest_consumer_commitment: row
            .try_get::<Option<Vec<u8>>, _>("latest_consumer_commitment")?
            .map(|value| {
                value.try_into().map_err(|_| {
                    anyhow::anyhow!("stored OMEMO recovery authority commitment has invalid length")
                })
            })
            .transpose()?,
    })
}

/// Resolve the source's read-only completion capability without accepting an
/// ordinary API bearer.  A consume rotates that bearer in the same transaction
/// as the terminal fence, so tying this observation to the old session would
/// make an uncertain HTTP result unrecoverable.  The response deliberately
/// contains only the state and monotonic generation.
pub async fn poll_omemo_recovery_transfer(
    pool: &PgPool,
    server_domain: &str,
    transfer_id: Uuid,
    poll_secret: &[u8; 32],
) -> Result<Option<OmemoRecoveryPollStatus>> {
    let mut tx = pool.begin().await?;
    sqlx::query("SET LOCAL statement_timeout = '1500ms'")
        .execute(&mut *tx)
        .await?;
    let row = sqlx::query(
        "SELECT actor.username,transfer.user_id,transfer.generation,transfer.state,\
                transfer.expires_at AS transfer_expires_at,capability.secret_hash \
         FROM omemo_recovery_poll_capabilities AS capability \
         JOIN omemo_recovery_transfers AS transfer ON transfer.id=capability.transfer_id \
         JOIN users AS actor ON actor.id=transfer.user_id \
         WHERE capability.transfer_id=$1 \
           AND capability.expires_at>clock_timestamp()",
    )
    .bind(transfer_id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(row) = row else {
        return Ok(None);
    };
    let username: String = row.try_get("username")?;
    let canonical_account = format!("{username}@{server_domain}");
    let expected = omemo_recovery_poll_secret_hash(&canonical_account, transfer_id, poll_secret);
    let stored: Vec<u8> = row.try_get("secret_hash")?;
    if !secret_digest_matches(&stored, &expected) {
        return Ok(None);
    }
    let mut state: String = row.try_get("state")?;
    let transfer_expires_at: DateTime<Utc> = row.try_get("transfer_expires_at")?;
    if matches!(state.as_str(), "preparing" | "prepared") && transfer_expires_at <= Utc::now() {
        state = "expired".to_owned();
    }
    let result = OmemoRecoveryPollStatus {
        generation: row.try_get("generation")?,
        state,
    };
    tx.commit().await?;
    Ok(Some(result))
}

pub async fn omemo_recovery_transfer(
    pool: &PgPool,
    user_id: Uuid,
    transfer_id: Uuid,
) -> Result<Option<OmemoRecoveryTransfer>> {
    let row = sqlx::query(&format!(
        "SELECT {TRANSFER_COLUMNS} FROM omemo_recovery_transfers \
         WHERE id=$1 AND user_id=$2"
    ))
    .bind(transfer_id)
    .bind(user_id)
    .fetch_optional(pool)
    .await?;
    row.map(|row| transfer_from_row(&row)).transpose()
}

pub async fn revoke_omemo_recovery_transfer(
    pool: &PgPool,
    user_id: Uuid,
    expected_auth_generation: i64,
    presented_session: &str,
    transfer_id: Uuid,
) -> Result<RevokeOmemoRecovery> {
    let mut tx = pool.begin().await?;
    if !authorize_recovery_mutation(
        &mut tx,
        user_id,
        expected_auth_generation,
        presented_session,
    )
    .await?
    {
        tx.rollback().await?;
        return Ok(RevokeOmemoRecovery::Unauthorized);
    }
    let Some(existing) = transfer_for_update(&mut tx, user_id, transfer_id).await? else {
        tx.rollback().await?;
        return Ok(RevokeOmemoRecovery::Missing);
    };
    let outcome = match existing.state.as_str() {
        "revoked" => RevokeOmemoRecovery::Replay,
        "preparing" | "prepared" => {
            sqlx::query(
                "UPDATE omemo_recovery_transfers SET state='revoked',\
                        revoked_at=clock_timestamp() WHERE id=$1 AND user_id=$2",
            )
            .bind(transfer_id)
            .bind(user_id)
            .execute(&mut *tx)
            .await?;
            sqlx::query(
                "UPDATE omemo_recovery_poll_capabilities \
                 SET expires_at=LEAST(expires_at,clock_timestamp()+INTERVAL '24 hours') \
                 WHERE transfer_id=$1 AND user_id=$2",
            )
            .bind(transfer_id)
            .bind(user_id)
            .execute(&mut *tx)
            .await?;
            audit_transfer_in_tx(
                &mut tx,
                user_id,
                transfer_id,
                "user.omemo_recovery.revoke",
                serde_json::json!({"generation": existing.generation}),
            )
            .await?;
            RevokeOmemoRecovery::Revoked
        }
        _ => RevokeOmemoRecovery::Conflict,
    };
    tx.commit().await?;
    Ok(outcome)
}

pub async fn cleanup_omemo_recovery_transfers(pool: &PgPool, limit: i64) -> Result<u64> {
    anyhow::ensure!(
        (1..=10_000).contains(&limit),
        "invalid OMEMO recovery cleanup limit"
    );
    let mut tx = pool.begin().await?;
    let deleted_capabilities = sqlx::query(
        "DELETE FROM omemo_recovery_poll_capabilities WHERE transfer_id IN (\
             SELECT transfer_id FROM omemo_recovery_poll_capabilities \
              WHERE expires_at<=clock_timestamp() ORDER BY expires_at,transfer_id \
              FOR UPDATE SKIP LOCKED LIMIT $1)",
    )
    .bind(limit)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    let after_capabilities =
        limit.saturating_sub(i64::try_from(deleted_capabilities).unwrap_or(limit));
    let expired = if after_capabilities > 0 {
        sqlx::query(
            "WITH candidates AS (\
             SELECT id FROM omemo_recovery_transfers \
              WHERE state IN ('preparing','prepared') \
                AND expires_at<=clock_timestamp() \
              ORDER BY expires_at,id FOR UPDATE SKIP LOCKED LIMIT $1) \
         UPDATE omemo_recovery_transfers transfer SET state='revoked',\
                revoked_at=clock_timestamp() FROM candidates \
          WHERE transfer.id=candidates.id",
        )
        .bind(after_capabilities)
        .execute(&mut *tx)
        .await?
        .rows_affected()
    } else {
        0
    };
    let consumed_budget = deleted_capabilities.saturating_add(expired);
    let remaining = limit.saturating_sub(i64::try_from(consumed_budget).unwrap_or(limit));
    let deleted = if remaining > 0 {
        sqlx::query(
            "DELETE FROM omemo_recovery_transfers WHERE id IN (\
                 SELECT id FROM omemo_recovery_transfers \
                  WHERE state IN ('consumed','revoked') \
                    AND COALESCE(consumed_at,revoked_at,created_at) \
                        < clock_timestamp()-INTERVAL '30 days' \
                  ORDER BY COALESCE(consumed_at,revoked_at,created_at),id \
                  FOR UPDATE SKIP LOCKED LIMIT $1)",
        )
        .bind(remaining)
        .execute(&mut *tx)
        .await?
        .rows_affected()
    } else {
        0
    };
    tx.commit()
        .await
        .context("could not commit OMEMO recovery cleanup")?;
    Ok(deleted_capabilities
        .saturating_add(expired)
        .saturating_add(deleted))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn consumer_commitment_matches_browser_vector() {
        let transfer_id = Uuid::parse_str("018f47bb-2f50-7cc3-9a8c-bf68c988c131").unwrap();
        let commitment =
            omemo_recovery_consumer_commitment("alice@example.org", transfer_id, &[0x5a_u8; 32]);
        assert_eq!(
            commitment
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>(),
            "4b5b22fa2705912b121f4f33c0b2633552f051d9bd1fb3980c8a4b5a6c7c85a3"
        );
    }

    #[test]
    fn migration_keeps_secrets_out_and_fences_terminal_rows() {
        let migration = include_str!("../../migrations/0093_omemo_recovery_transfer.sql");
        assert!(migration.contains("package_sha256 BYTEA"));
        assert!(migration.contains("terminal OMEMO recovery transfer is immutable"));
        assert!(migration.contains("CREATE UNIQUE INDEX omemo_recovery_transfers_one_active_idx"));
        assert!(migration.contains("latest_consumed_generation BIGINT NOT NULL"));
        assert!(migration.contains("OMEMO recovery consumer fence is immutable"));
        assert!(migration.contains("omemo_recovery_poll_capabilities"));
        assert!(migration.contains("consumer_commitment BYTEA"));
        for forbidden_column in [
            "passphrase text",
            "private_key bytea",
            "derived_key bytea",
            "plaintext bytea",
            "consumer_secret bytea",
            "poll_secret bytea",
        ] {
            assert!(!migration.to_ascii_lowercase().contains(forbidden_column));
        }
    }

    #[tokio::test]
    #[ignore = "requires TEST_DATABASE_URL; exercises one-time generation/seal/consume/replay fencing"]
    async fn postgres_omemo_recovery_transfer_is_monotonic_and_single_consumer() {
        let Some(url) = std::env::var("TEST_DATABASE_URL").ok() else {
            return;
        };
        let pool = PgPool::connect(&url).await.unwrap();
        crate::db::migrate(&pool).await.unwrap();
        let username = format!("omemo-recovery-{}", Uuid::new_v4().simple());
        let user = crate::db::create_user(
            &pool,
            &username,
            "test password 123",
            false,
            false,
            4_096,
            false,
        )
        .await
        .unwrap();
        let token = crate::db::create_api_session(&pool, user.id, 1)
            .await
            .unwrap();
        let first_id = Uuid::new_v4();
        let canonical_account = format!("{}@localhost", user.username);
        let first_poll_secret = [3_u8; 32];
        let first = prepare_omemo_recovery_transfer(
            &pool,
            PrepareOmemoRecoveryRequest {
                user_id: user.id,
                canonical_account: &canonical_account,
                expected_auth_generation: user.auth_generation,
                presented_session: &token,
                transfer_id: first_id,
                source_device_id: 7,
                poll_secret: &first_poll_secret,
            },
        )
        .await
        .unwrap();
        let PrepareOmemoRecovery::Prepared(first) = first else {
            panic!("first transfer was not prepared")
        };
        assert!(matches!(
            prepare_omemo_recovery_transfer(
                &pool,
                PrepareOmemoRecoveryRequest {
                    user_id: user.id,
                    canonical_account: &canonical_account,
                    expected_auth_generation: user.auth_generation,
                    presented_session: &token,
                    transfer_id: first_id,
                    source_device_id: 7,
                    poll_secret: &first_poll_secret,
                },
            )
            .await
            .unwrap(),
            PrepareOmemoRecovery::Replay(_)
        ));
        let digest = [9_u8; 32];
        assert!(matches!(
            seal_omemo_recovery_transfer(
                &pool,
                user.id,
                user.auth_generation,
                &token,
                first_id,
                &digest,
            )
            .await
            .unwrap(),
            SealOmemoRecovery::Sealed(_)
        ));
        let consumer_secret = [7_u8; 32];
        let consumer_commitment =
            omemo_recovery_consumer_commitment(&canonical_account, first_id, &consumer_secret);
        assert!(matches!(
            consume_omemo_recovery_transfer(
                &pool,
                ConsumeOmemoRecoveryRequest {
                    user_id: user.id,
                    canonical_account: &canonical_account,
                    expected_auth_generation: user.auth_generation,
                    presented_session: &token,
                    transfer_id: first_id,
                    consumer_secret: &consumer_secret,
                    package_sha256: &digest,
                },
            )
            .await
            .unwrap(),
            ConsumeOmemoRecovery::Consumed(_)
        ));
        let rotated = crate::db::find_user_by_id(&pool, user.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(rotated.auth_generation, user.auth_generation + 1);
        let replay_token = crate::db::create_api_session(&pool, user.id, 1)
            .await
            .unwrap();
        assert!(matches!(
            consume_omemo_recovery_transfer(
                &pool,
                ConsumeOmemoRecoveryRequest {
                    user_id: user.id,
                    canonical_account: &canonical_account,
                    expected_auth_generation: rotated.auth_generation,
                    presented_session: &replay_token,
                    transfer_id: first_id,
                    consumer_secret: &consumer_secret,
                    package_sha256: &digest,
                },
            )
            .await
            .unwrap(),
            ConsumeOmemoRecovery::Replay(_)
        ));
        let authority = omemo_recovery_authority(&pool, user.id).await.unwrap();
        assert_eq!(authority.latest_consumed_generation, first.generation);
        assert_eq!(authority.latest_consumed_transfer_id, Some(first_id));
        assert_eq!(
            authority.latest_consumer_commitment,
            Some(consumer_commitment)
        );
        assert_eq!(
            poll_omemo_recovery_transfer(&pool, "localhost", first_id, &first_poll_secret)
                .await
                .unwrap()
                .unwrap()
                .state,
            "consumed"
        );
        assert!(matches!(
            consume_omemo_recovery_transfer(
                &pool,
                ConsumeOmemoRecoveryRequest {
                    user_id: user.id,
                    canonical_account: &canonical_account,
                    expected_auth_generation: rotated.auth_generation,
                    presented_session: &replay_token,
                    transfer_id: first_id,
                    consumer_secret: &[8_u8; 32],
                    package_sha256: &digest,
                },
            )
            .await
            .unwrap(),
            ConsumeOmemoRecovery::Conflict
        ));
        let second = prepare_omemo_recovery_transfer(
            &pool,
            PrepareOmemoRecoveryRequest {
                user_id: user.id,
                canonical_account: &canonical_account,
                expected_auth_generation: rotated.auth_generation,
                presented_session: &replay_token,
                transfer_id: Uuid::new_v4(),
                source_device_id: 7,
                poll_secret: &[4_u8; 32],
            },
        )
        .await
        .unwrap();
        let PrepareOmemoRecovery::Prepared(second) = second else {
            panic!("second transfer was not prepared")
        };
        assert_eq!(second.generation, first.generation + 1);
        sqlx::query("DELETE FROM users WHERE id=$1")
            .bind(user.id)
            .execute(&pool)
            .await
            .unwrap();
    }
}
