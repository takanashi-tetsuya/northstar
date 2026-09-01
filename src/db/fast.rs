use crate::auth;
use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use rand::RngCore;
use sqlx::{PgPool, Postgres, Row, Transaction};
use uuid::Uuid;
use zeroize::Zeroizing;

pub struct IssuedFastToken {
    pub token: Zeroizing<String>,
    pub expires_at: DateTime<Utc>,
}

impl std::fmt::Debug for IssuedFastToken {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("IssuedFastToken")
            .field("token", &"[REDACTED]")
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

#[derive(Clone, Debug)]
pub struct FastTokenIssue {
    pub device_id: Uuid,
    pub mechanism: String,
    pub ttl_days: i64,
    pub strong_reauth_max_days: i64,
    pub inherited_chain: Option<(DateTime<Utc>, DateTime<Utc>)>,
}

#[derive(Clone, Debug, Default)]
pub struct FastCommitPlan {
    pub token_id: Option<Uuid>,
    pub token_was_new: bool,
    pub invalidate: bool,
    pub issue: Option<FastTokenIssue>,
}

#[derive(Debug)]
pub enum FastCommitOutcome {
    Committed(Option<IssuedFastToken>),
    CredentialsExpired,
}

pub struct AuthenticatedFastToken {
    pub token: Zeroizing<String>,
    pub should_rotate: bool,
    pub id: Uuid,
    pub was_new: bool,
    pub auth_generation: i64,
    pub strong_auth_at: DateTime<Utc>,
    pub chain_expires_at: DateTime<Utc>,
}

impl std::fmt::Debug for AuthenticatedFastToken {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AuthenticatedFastToken")
            .field("token", &"[REDACTED]")
            .field("should_rotate", &self.should_rotate)
            .field("id", &"[REDACTED]")
            .field("was_new", &self.was_new)
            .field("auth_generation", &self.auth_generation)
            .field("strong_auth_at", &self.strong_auth_at)
            .field("chain_expires_at", &self.chain_expires_at)
            .finish()
    }
}

#[derive(Debug)]
pub enum FastAuthentication {
    Success(AuthenticatedFastToken),
    CredentialsExpired,
    Invalid,
    Replayed,
    /// Candidate rows existed, but none could be reproduced with the active
    /// derivation key. This is an operator-key mismatch or durable corruption,
    /// never an ordinary bad credential.
    IntegrityFailure,
}

/// All client-controlled inputs needed for one atomic FAST proof attempt.
/// Grouping them avoids positional argument mistakes between the mechanism,
/// channel binding, proof, counter, and post-authentication rotation policy.
pub struct FastAuthenticationRequest<'a> {
    pub user_id: Uuid,
    pub device_id: Uuid,
    pub mechanism: &'a str,
    pub counter: Option<i64>,
    pub initiator_proof: &'a [u8],
    pub channel_binding: &'a [u8],
    pub invalidate: bool,
    pub rotate_within_days: i64,
}

struct FastTokenRow {
    id: Uuid,
    user_id: Uuid,
    device_id: Uuid,
    mechanism: String,
    channel_binding: String,
    slot: String,
    nonce: Vec<u8>,
    token_hash: Vec<u8>,
    should_rotate: bool,
    auth_generation: i64,
    strong_auth_at: DateTime<Utc>,
    chain_expires_at: DateTime<Utc>,
}

fn row_from_pg(row: &sqlx::postgres::PgRow) -> FastTokenRow {
    FastTokenRow {
        id: row.get("id"),
        user_id: row.get("user_id"),
        device_id: row.get("device_id"),
        mechanism: row.get("mechanism"),
        channel_binding: row.get("channel_binding"),
        slot: row.get("slot"),
        nonce: row.get("derivation_nonce"),
        token_hash: row.get("token_hash"),
        should_rotate: row.get("should_rotate"),
        auth_generation: row.get("auth_generation"),
        strong_auth_at: row.get("strong_auth_at"),
        chain_expires_at: row.get("chain_expires_at"),
    }
}

fn derived_token(master_key: &[u8], row: &FastTokenRow) -> Result<Zeroizing<String>> {
    Ok(Zeroizing::new(auth::derive_fast_token(
        master_key,
        row.id,
        row.user_id,
        row.device_id,
        &row.mechanism,
        &row.nonce,
    )?))
}

/// Installs a pending token while retaining the current token.  This is the
/// two-slot rotation rule from XEP-0484: the old credential is invalidated
/// only once the client proves possession of the replacement.
#[allow(clippy::too_many_arguments)]
#[cfg(test)]
pub async fn issue_fast_token(
    pool: &PgPool,
    master_key: &[u8],
    user_id: Uuid,
    device_id: Uuid,
    mechanism: &str,
    expected_auth_generation: i64,
    ttl_days: i64,
    strong_reauth_max_days: i64,
    inherited_chain: Option<(DateTime<Utc>, DateTime<Utc>)>,
) -> Result<IssuedFastToken> {
    let mut tx = pool.begin().await?;
    let issued = issue_fast_token_in_transaction(
        &mut tx,
        master_key,
        user_id,
        device_id,
        mechanism,
        expected_auth_generation,
        ttl_days,
        strong_reauth_max_days,
        inherited_chain,
    )
    .await?;
    tx.commit().await?;
    Ok(issued)
}

#[allow(clippy::too_many_arguments)]
pub async fn issue_fast_token_in_transaction(
    tx: &mut Transaction<'_, Postgres>,
    master_key: &[u8],
    user_id: Uuid,
    device_id: Uuid,
    mechanism: &str,
    expected_auth_generation: i64,
    ttl_days: i64,
    strong_reauth_max_days: i64,
    inherited_chain: Option<(DateTime<Utc>, DateTime<Utc>)>,
) -> Result<IssuedFastToken> {
    let channel_binding =
        auth::fast_channel_binding_name(mechanism).context("unsupported FAST mechanism")?;
    let id = Uuid::new_v4();
    let mut nonce = vec![0_u8; 32];
    rand::thread_rng().fill_bytes(&mut nonce);
    let token = Zeroizing::new(auth::derive_fast_token(
        master_key, id, user_id, device_id, mechanism, &nonce,
    )?);
    let token_hash = auth::token_hash(&token);
    let ttl_days =
        i32::try_from(ttl_days).context("FAST token lifetime does not fit PostgreSQL")?;
    let strong_reauth_max_days = i32::try_from(strong_reauth_max_days)
        .context("FAST strong-auth lifetime does not fit PostgreSQL")?;
    // Serialize token issuance with password rotation and account disablement.
    // Both mutation paths lock the user row before touching fast_tokens.
    let eligible = sqlx::query_scalar::<_, DateTime<Utc>>(
        "SELECT clock_timestamp() FROM users
         WHERE id=$1 AND auth_generation=$2 AND NOT is_disabled FOR SHARE",
    )
    .bind(user_id)
    .bind(expected_auth_generation)
    .fetch_optional(&mut **tx)
    .await?;
    let now = eligible.context("FAST account credentials changed")?;
    let (strong_auth_at, chain_expires_at) = inherited_chain.unwrap_or_else(|| {
        (
            now,
            now + chrono::Duration::days(i64::from(strong_reauth_max_days)),
        )
    });
    anyhow::ensure!(
        strong_auth_at <= now && chain_expires_at > now,
        "FAST strong-auth chain expired"
    );
    let expires_at: DateTime<Utc> = sqlx::query_scalar(
        "INSERT INTO fast_tokens
         (id, user_id, device_id, mechanism, channel_binding, slot,
          derivation_nonce, token_hash, last_counter, auth_generation,
          strong_auth_at, chain_expires_at, expires_at)
         VALUES ($1,$2,$3,$4,$5,'new',$6,$7,-1,$8,$9,$10,
                 LEAST($10, clock_timestamp() + make_interval(days => $11)))
         ON CONFLICT (user_id, device_id, slot) DO UPDATE SET
          id = EXCLUDED.id, channel_binding = EXCLUDED.channel_binding,
          mechanism = EXCLUDED.mechanism,
          derivation_nonce = EXCLUDED.derivation_nonce,
          token_hash = EXCLUDED.token_hash, last_counter = -1,
          auth_generation = EXCLUDED.auth_generation,
          strong_auth_at = EXCLUDED.strong_auth_at,
          chain_expires_at = EXCLUDED.chain_expires_at,
          expires_at = EXCLUDED.expires_at, created_at = clock_timestamp(),
          used_at = NULL, revoked_at = NULL
         RETURNING expires_at",
    )
    .bind(id)
    .bind(user_id)
    .bind(device_id)
    .bind(mechanism)
    .bind(channel_binding)
    .bind(nonce)
    .bind(token_hash)
    .bind(expected_auth_generation)
    .bind(strong_auth_at)
    .bind(chain_expires_at)
    .bind(ttl_days)
    .fetch_one(&mut **tx)
    .await
    .context("could not persist pending FAST token")?;
    Ok(IssuedFastToken { token, expires_at })
}

async fn select_candidates(
    tx: &mut Transaction<'_, Postgres>,
    user_id: Uuid,
    device_id: Uuid,
    mechanism: &str,
    auth_generation: i64,
    rotate_within_days: i64,
) -> Result<Vec<FastTokenRow>> {
    let rotate_within_days = i32::try_from(rotate_within_days)
        .context("FAST rotation window does not fit PostgreSQL")?;
    let rows = sqlx::query(
        "SELECT id,user_id,device_id,mechanism,channel_binding,slot,derivation_nonce,token_hash,
                auth_generation,strong_auth_at,chain_expires_at,expires_at,
                expires_at <= clock_timestamp() + make_interval(days => $4) AS should_rotate
         FROM fast_tokens
         WHERE user_id=$1 AND device_id=$2 AND mechanism=$3
           AND auth_generation=$5 AND chain_expires_at > clock_timestamp()
           AND revoked_at IS NULL AND expires_at > clock_timestamp()
         ORDER BY CASE slot WHEN 'new' THEN 0 ELSE 1 END
         FOR UPDATE",
    )
    .bind(user_id)
    .bind(device_id)
    .bind(mechanism)
    .bind(rotate_within_days)
    .bind(auth_generation)
    .fetch_all(&mut **tx)
    .await?;
    Ok(rows.iter().map(row_from_pg).collect())
}

/// Atomically verifies an HT proof and advances the replay counter.  Reusing
/// a counter, including in two concurrent sessions, can succeed at most once
/// because candidate rows are locked until commit.
#[cfg(test)]
pub async fn authenticate_fast_token(
    pool: &PgPool,
    master_key: &[u8],
    request: FastAuthenticationRequest<'_>,
) -> Result<FastAuthentication> {
    let user_id = request.user_id;
    let mut tx = pool.begin().await?;
    // Lock order is user row then token row, matching password/status changes.
    // It closes the boundary where a token could authenticate concurrently
    // with a committed credential rotation or account disablement.
    let account_generation = sqlx::query_scalar::<_, i64>(
        "SELECT auth_generation FROM users WHERE id=$1 AND NOT is_disabled FOR SHARE",
    )
    .bind(user_id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(account_generation) = account_generation else {
        tx.rollback().await?;
        return Ok(FastAuthentication::CredentialsExpired);
    };
    let result =
        authenticate_fast_token_in_transaction(&mut tx, master_key, request, account_generation)
            .await?;
    if matches!(&result, FastAuthentication::Success(_)) {
        tx.commit().await?;
    } else {
        tx.rollback().await?;
    }
    Ok(result)
}

/// Verify and consume one FAST proof inside a caller-owned transaction.
///
/// The caller must first lock the matching enabled `users` row and pass the
/// generation read from that same row.  This lets AuthenticationService return
/// a sanitized account DTO from exactly the transaction which consumes the
/// one-time proof counter, rather than performing a racy username lookup before
/// or after token verification.
pub(crate) async fn authenticate_fast_token_in_transaction(
    tx: &mut Transaction<'_, Postgres>,
    master_key: &[u8],
    request: FastAuthenticationRequest<'_>,
    account_generation: i64,
) -> Result<FastAuthentication> {
    let FastAuthenticationRequest {
        user_id,
        device_id,
        mechanism,
        counter,
        initiator_proof,
        channel_binding,
        invalidate,
        rotate_within_days,
    } = request;
    if counter.is_some_and(|counter| counter < 0) || !auth::is_fast_mechanism(mechanism) {
        return Ok(FastAuthentication::Invalid);
    }
    let candidates = select_candidates(
        tx,
        user_id,
        device_id,
        mechanism,
        account_generation,
        rotate_within_days,
    )
    .await?;
    if candidates.is_empty() {
        return Ok(FastAuthentication::CredentialsExpired);
    }
    let mut selected = None;
    let mut derivation_integrity_failure = false;
    for row in candidates {
        if auth::fast_channel_binding_name(&row.mechanism) != Some(row.channel_binding.as_str()) {
            derivation_integrity_failure = true;
            continue;
        }
        let token = derived_token(master_key, &row)?;
        // The stored digest detects an operator key mismatch or database
        // corruption before the HMAC credential is evaluated.
        if !auth::constant_time_bytes_eq(&auth::token_hash(&token), &row.token_hash) {
            derivation_integrity_failure = true;
            continue;
        }
        if selected.is_none()
            && auth::verify_fast_proof(&token, false, channel_binding, initiator_proof)
        {
            selected = Some((row, token));
        }
    }
    // Fail closed if any active candidate row cannot be reproduced. In a
    // two-slot rotation, accepting the other slot would hide corruption or an
    // operator-key mismatch and could advance/invalidate credential state.
    if derivation_integrity_failure {
        return Ok(FastAuthentication::IntegrityFailure);
    }
    let Some((row, token)) = selected else {
        return Ok(FastAuthentication::Invalid);
    };

    let advanced = sqlx::query(
        "UPDATE fast_tokens
            SET last_counter = CASE
                    WHEN $2::BIGINT IS NULL THEN last_counter + 1
                    ELSE $2
                END,
                used_at=clock_timestamp()
          WHERE id=$1
            AND revoked_at IS NULL
            AND expires_at > clock_timestamp()
            AND (($2::BIGINT IS NULL AND last_counter < 9223372036854775807)
                 OR ($2::BIGINT IS NOT NULL AND last_counter < $2))",
    )
    .bind(row.id)
    .bind(counter)
    .execute(&mut **tx)
    .await?
    .rows_affected()
        == 1;
    if !advanced {
        return Ok(FastAuthentication::Replayed);
    }

    Ok(FastAuthentication::Success(AuthenticatedFastToken {
        token,
        should_rotate: !invalidate && row.should_rotate,
        id: row.id,
        was_new: row.slot == "new",
        auth_generation: row.auth_generation,
        strong_auth_at: row.strong_auth_at,
        chain_expires_at: row.chain_expires_at,
    }))
}

/// Applies rotation/invalidation only after all SASL2 inline operations have
/// succeeded. The replay counter is deliberately consumed earlier, but a Bind
/// 2 backend failure cannot revoke the client's last usable token.
#[cfg(test)]
pub async fn finalize_fast_token(
    pool: &PgPool,
    token_id: Uuid,
    was_new: bool,
    invalidate: bool,
    expected_auth_generation: i64,
) -> Result<bool> {
    let mut tx = pool.begin().await?;
    let finalized = finalize_fast_token_in_transaction(
        &mut tx,
        token_id,
        was_new,
        invalidate,
        expected_auth_generation,
    )
    .await?;
    if !finalized {
        tx.rollback().await?;
        return Ok(false);
    }
    tx.commit().await?;
    Ok(true)
}

pub async fn finalize_fast_token_in_transaction(
    tx: &mut Transaction<'_, Postgres>,
    token_id: Uuid,
    was_new: bool,
    invalidate: bool,
    expected_auth_generation: i64,
) -> Result<bool> {
    let row = sqlx::query(
        "SELECT token.user_id,token.device_id
         FROM fast_tokens token
         JOIN users ON users.id=token.user_id
         WHERE token.id=$1 AND token.revoked_at IS NULL
           AND token.expires_at > clock_timestamp()
           AND token.chain_expires_at > clock_timestamp()
           AND token.auth_generation=$2
           AND users.auth_generation=$2 AND NOT users.is_disabled
         FOR UPDATE OF token,users",
    )
    .bind(token_id)
    .bind(expected_auth_generation)
    .fetch_optional(&mut **tx)
    .await?;
    let Some(row) = row else {
        return Ok(false);
    };
    if was_new {
        let user_id: Uuid = row.get("user_id");
        let device_id: Uuid = row.get("device_id");
        sqlx::query(
            "DELETE FROM fast_tokens
             WHERE user_id=$1 AND device_id=$2
               AND slot='current' AND id<>$3",
        )
        .bind(user_id)
        .bind(device_id)
        .bind(token_id)
        .execute(&mut **tx)
        .await?;
        sqlx::query("UPDATE fast_tokens SET slot='current' WHERE id=$1")
            .bind(token_id)
            .execute(&mut **tx)
            .await?;
    }
    if invalidate {
        sqlx::query("UPDATE fast_tokens SET revoked_at=NOW() WHERE id=$1")
            .bind(token_id)
            .execute(&mut **tx)
            .await?;
    }
    Ok(true)
}

/// Applies FAST promotion/invalidation and replacement issuance in the
/// caller's short finalization transaction. Bind 2 stages a non-routable
/// cluster route first, then revalidates its durable lease in that transaction,
/// so a failed publication cannot leave a promoted, revoked, or newly-issued
/// credential behind without holding a database lock across Redis I/O.
pub async fn commit_fast_state_in_transaction(
    tx: &mut Transaction<'_, Postgres>,
    master_key: &[u8],
    user_id: Uuid,
    expected_auth_generation: i64,
    plan: &FastCommitPlan,
) -> Result<FastCommitOutcome> {
    if let Some(token_id) = plan.token_id {
        if !finalize_fast_token_in_transaction(
            tx,
            token_id,
            plan.token_was_new,
            plan.invalidate,
            expected_auth_generation,
        )
        .await?
        {
            return Ok(FastCommitOutcome::CredentialsExpired);
        }
    }
    let issued = if let Some(issue) = plan.issue.as_ref() {
        Some(
            issue_fast_token_in_transaction(
                tx,
                master_key,
                user_id,
                issue.device_id,
                &issue.mechanism,
                expected_auth_generation,
                issue.ttl_days,
                issue.strong_reauth_max_days,
                issue.inherited_chain,
            )
            .await?,
        )
    } else {
        None
    };
    Ok(FastCommitOutcome::Committed(issued))
}

/// Commit every credential-side effect of a successful, unbound SASL2
/// authentication as one PostgreSQL unit.  In particular, a FAST token must
/// never be promoted, revoked, or issued if allocation of the XEP-0388
/// user-agent login epoch fails (and vice versa): SASL2 failures leave the
/// stream and session state unchanged.
#[cfg(test)]
pub async fn commit_fast_state_with_login_epoch(
    pool: &PgPool,
    master_key: &[u8],
    user_id: Uuid,
    expected_auth_generation: i64,
    plan: &FastCommitPlan,
    device_id: Option<Uuid>,
) -> Result<Option<(Option<IssuedFastToken>, Option<i64>)>> {
    let Some(mut tx) =
        crate::db::lock_auth_generation(pool, user_id, expected_auth_generation).await?
    else {
        return Ok(None);
    };
    let login_epoch = if let Some(device_id) = device_id {
        let Some(epoch) = crate::db::next_user_agent_login_epoch_in_transaction(
            &mut tx,
            user_id,
            device_id,
            expected_auth_generation,
        )
        .await?
        else {
            tx.rollback().await?;
            return Ok(None);
        };
        Some(epoch)
    } else {
        None
    };
    let issued = match commit_fast_state_in_transaction(
        &mut tx,
        master_key,
        user_id,
        expected_auth_generation,
        plan,
    )
    .await?
    {
        FastCommitOutcome::Committed(issued) => issued,
        FastCommitOutcome::CredentialsExpired => {
            tx.rollback().await?;
            return Ok(None);
        }
    };
    tx.commit().await?;
    Ok(Some((issued, login_epoch)))
}

pub async fn cleanup_fast_tokens(pool: &PgPool) -> Result<u64> {
    Ok(sqlx::query(
        "DELETE FROM fast_tokens WHERE id IN (
             SELECT id FROM fast_tokens
             WHERE expires_at <= NOW()
                OR chain_expires_at <= NOW()
                OR revoked_at < NOW() - INTERVAL '7 days'
             ORDER BY COALESCE(revoked_at, expires_at), id
             LIMIT 1000
         )",
    )
    .execute(pool)
    .await?
    .rows_affected())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fast_credentials_are_redacted_from_debug_output() {
        let secret = "fast-secret-that-must-never-reach-a-log";
        let issued = IssuedFastToken {
            token: Zeroizing::new(secret.to_owned()),
            expires_at: Utc::now(),
        };
        let authenticated = AuthenticatedFastToken {
            token: Zeroizing::new(secret.to_owned()),
            should_rotate: false,
            id: Uuid::nil(),
            was_new: false,
            auth_generation: 7,
            strong_auth_at: Utc::now(),
            chain_expires_at: Utc::now(),
        };
        for formatted in [format!("{issued:?}"), format!("{authenticated:?}")] {
            assert!(formatted.contains("[REDACTED]"));
            assert!(!formatted.contains(secret));
        }
    }

    #[test]
    fn derived_token_is_bound_to_device_and_mechanism() {
        let key = [7_u8; 32];
        let token_id = Uuid::nil();
        let user = Uuid::from_u128(1);
        let device_a = Uuid::from_u128(2);
        let device_b = Uuid::from_u128(3);
        let nonce = [9_u8; 32];
        let a = auth::derive_fast_token(&key, token_id, user, device_a, "HT-SHA-256-ENDP", &nonce)
            .unwrap();
        let b = auth::derive_fast_token(&key, token_id, user, device_b, "HT-SHA-256-ENDP", &nonce)
            .unwrap();
        let downgraded =
            auth::derive_fast_token(&key, token_id, user, device_a, "HT-SHA-256-NONE", &nonce)
                .unwrap();
        assert_ne!(a, b);
        assert_ne!(a, downgraded);
    }

    #[tokio::test]
    #[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
    async fn durable_fast_tokens_support_optional_counts_replay_and_status_revocation() {
        let url = std::env::var("TEST_DATABASE_URL")
            .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(8)
            .connect(&url)
            .await
            .unwrap();
        crate::db::migrate(&pool).await.unwrap();

        let user_id = Uuid::new_v4();
        let admin_id = Uuid::new_v4();
        for (id, prefix, admin) in [(user_id, "fast", false), (admin_id, "admin", true)] {
            sqlx::query(
                "INSERT INTO users(id,username,password_hash,is_admin) VALUES($1,$2,'test-only',$3)",
            )
            .bind(id)
            .bind(format!("{prefix}-{}", &id.simple().to_string()[..10]))
            .bind(admin)
            .execute(&pool)
            .await
            .unwrap();
        }
        let device_id = Uuid::new_v4();
        let master = [0x51_u8; 32];
        let issued = issue_fast_token(
            &pool,
            &master,
            user_id,
            device_id,
            "HT-SHA-256-NONE",
            0,
            30,
            90,
            None,
        )
        .await
        .unwrap();
        let proof = auth::fast_proof(&issued.token, false, &[]);
        let authenticate = |counter| FastAuthenticationRequest {
            user_id,
            device_id,
            mechanism: "HT-SHA-256-NONE",
            counter,
            initiator_proof: &proof,
            channel_binding: &[],
            invalidate: false,
            rotate_within_days: 7,
        };

        // The bearer is installation-bound. Reusing an otherwise valid proof
        // under a different XEP-0388 user-agent UUID cannot discover or use
        // the credential.
        assert!(matches!(
            authenticate_fast_token(
                &pool,
                &master,
                FastAuthenticationRequest {
                    user_id,
                    device_id: Uuid::new_v4(),
                    mechanism: "HT-SHA-256-NONE",
                    counter: None,
                    initiator_proof: &proof,
                    channel_binding: &[],
                    invalidate: false,
                    rotate_within_days: 7,
                },
            )
            .await
            .unwrap(),
            FastAuthentication::CredentialsExpired
        ));

        // Non-0RTT clients are conforming without a count and may reuse the
        // current token. PostgreSQL still advances a private use counter.
        assert!(matches!(
            authenticate_fast_token(&pool, &master, authenticate(None))
                .await
                .unwrap(),
            FastAuthentication::Success(_)
        ));
        assert!(matches!(
            authenticate_fast_token(&pool, &master, authenticate(None))
                .await
                .unwrap(),
            FastAuthentication::Success(_)
        ));

        assert!(matches!(
            authenticate_fast_token(&pool, &master, authenticate(Some(9)))
                .await
                .unwrap(),
            FastAuthentication::Success(_)
        ));
        assert!(matches!(
            authenticate_fast_token(&pool, &master, authenticate(Some(9)))
                .await
                .unwrap(),
            FastAuthentication::Replayed
        ));

        // A concurrent duplicate counter succeeds at most once across pools
        // and therefore across Northstar processes.
        let first_pool = pool.clone();
        let second_pool = pool.clone();
        let first_master = master;
        let second_master = master;
        let first_proof = proof.clone();
        let second_proof = proof.clone();
        let first = tokio::spawn(async move {
            authenticate_fast_token(
                &first_pool,
                &first_master,
                FastAuthenticationRequest {
                    user_id,
                    device_id,
                    mechanism: "HT-SHA-256-NONE",
                    counter: Some(10),
                    initiator_proof: &first_proof,
                    channel_binding: &[],
                    invalidate: false,
                    rotate_within_days: 7,
                },
            )
            .await
            .unwrap()
        });
        let second = tokio::spawn(async move {
            authenticate_fast_token(
                &second_pool,
                &second_master,
                FastAuthenticationRequest {
                    user_id,
                    device_id,
                    mechanism: "HT-SHA-256-NONE",
                    counter: Some(10),
                    initiator_proof: &second_proof,
                    channel_binding: &[],
                    invalidate: false,
                    rotate_within_days: 7,
                },
            )
            .await
            .unwrap()
        });
        let outcomes = [first.await.unwrap(), second.await.unwrap()];
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| matches!(outcome, FastAuthentication::Success(_)))
                .count(),
            1
        );

        // Expiry is enforced from PostgreSQL rather than process memory, so
        // it survives restarts and is shared by every frontend instance.
        let expired_device = Uuid::new_v4();
        let expired = issue_fast_token(
            &pool,
            &master,
            user_id,
            expired_device,
            "HT-SHA-256-NONE",
            0,
            30,
            90,
            None,
        )
        .await
        .unwrap();
        sqlx::query(
            "UPDATE fast_tokens
             SET strong_auth_at=clock_timestamp()-INTERVAL '2 seconds',
                 expires_at=clock_timestamp()-INTERVAL '1 second'
             WHERE user_id=$1 AND device_id=$2",
        )
        .bind(user_id)
        .bind(expired_device)
        .execute(&pool)
        .await
        .unwrap();
        let expired_proof = auth::fast_proof(&expired.token, false, &[]);
        let restarted_pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(2)
            .connect(&url)
            .await
            .unwrap();
        assert!(matches!(
            authenticate_fast_token(
                &restarted_pool,
                &master,
                FastAuthenticationRequest {
                    user_id,
                    device_id: expired_device,
                    mechanism: "HT-SHA-256-NONE",
                    counter: None,
                    initiator_proof: &expired_proof,
                    channel_binding: &[],
                    invalidate: false,
                    rotate_within_days: 7,
                },
            )
            .await
            .unwrap(),
            FastAuthentication::CredentialsExpired
        ));

        let rotating_device = Uuid::new_v4();
        let rotating = issue_fast_token(
            &pool,
            &master,
            user_id,
            rotating_device,
            "HT-SHA-256-NONE",
            0,
            30,
            90,
            None,
        )
        .await
        .unwrap();
        let rotating_proof = auth::fast_proof(&rotating.token, false, &[]);
        let rotating_verified = match authenticate_fast_token(
            &restarted_pool,
            &master,
            FastAuthenticationRequest {
                user_id,
                device_id: rotating_device,
                mechanism: "HT-SHA-256-NONE",
                counter: Some(1),
                initiator_proof: &rotating_proof,
                channel_binding: &[],
                invalidate: true,
                rotate_within_days: 31,
            },
        )
        .await
        .unwrap()
        {
            FastAuthentication::Success(verified) => verified,
            other => panic!("expected restart-safe FAST success, got {other:?}"),
        };
        // Invalidation suppresses automatic rotation even inside the
        // rotation window and takes effect only when success is committed.
        assert!(!rotating_verified.should_rotate);
        assert!(finalize_fast_token(
            &restarted_pool,
            rotating_verified.id,
            rotating_verified.was_new,
            true,
            rotating_verified.auth_generation,
        )
        .await
        .unwrap());
        assert!(matches!(
            authenticate_fast_token(
                &pool,
                &master,
                FastAuthenticationRequest {
                    user_id,
                    device_id: rotating_device,
                    mechanism: "HT-SHA-256-NONE",
                    counter: Some(2),
                    initiator_proof: &rotating_proof,
                    channel_binding: &[],
                    invalidate: false,
                    rotate_within_days: 31,
                },
            )
            .await
            .unwrap(),
            FastAuthentication::CredentialsExpired
        ));

        let replacement_device = Uuid::new_v4();
        let current = issue_fast_token(
            &pool,
            &master,
            user_id,
            replacement_device,
            "HT-SHA-256-NONE",
            0,
            30,
            90,
            None,
        )
        .await
        .unwrap();
        let current_proof = auth::fast_proof(&current.token, false, &[]);
        let current_verified = match authenticate_fast_token(
            &restarted_pool,
            &master,
            FastAuthenticationRequest {
                user_id,
                device_id: replacement_device,
                mechanism: "HT-SHA-256-NONE",
                counter: Some(1),
                initiator_proof: &current_proof,
                channel_binding: &[],
                invalidate: false,
                rotate_within_days: 31,
            },
        )
        .await
        .unwrap()
        {
            FastAuthentication::Success(verified) => verified,
            other => panic!("expected rotation-eligible FAST success, got {other:?}"),
        };
        assert!(current_verified.should_rotate);
        let replacement_plan = FastCommitPlan {
            token_id: Some(current_verified.id),
            token_was_new: current_verified.was_new,
            invalidate: false,
            issue: Some(FastTokenIssue {
                device_id: replacement_device,
                mechanism: "HT-SHA-256-NONE".to_owned(),
                ttl_days: 30,
                strong_reauth_max_days: 90,
                inherited_chain: Some((
                    current_verified.strong_auth_at,
                    current_verified.chain_expires_at,
                )),
            }),
        };
        let (replacement, _) = commit_fast_state_with_login_epoch(
            &restarted_pool,
            &master,
            user_id,
            current_verified.auth_generation,
            &replacement_plan,
            None,
        )
        .await
        .unwrap()
        .expect("rotation generation must remain current");
        let replacement = replacement.expect("rotation must issue a pending replacement");
        let slots: Vec<String> = sqlx::query_scalar(
            "SELECT slot FROM fast_tokens WHERE user_id=$1 AND device_id=$2 ORDER BY slot",
        )
        .bind(user_id)
        .bind(replacement_device)
        .fetch_all(&pool)
        .await
        .unwrap();
        assert_eq!(slots, vec!["current".to_owned(), "new".to_owned()]);
        let replacement_proof = auth::fast_proof(&replacement.token, false, &[]);
        let replacement_verified = match authenticate_fast_token(
            &pool,
            &master,
            FastAuthenticationRequest {
                user_id,
                device_id: replacement_device,
                mechanism: "HT-SHA-256-NONE",
                counter: Some(1),
                initiator_proof: &replacement_proof,
                channel_binding: &[],
                invalidate: false,
                rotate_within_days: 7,
            },
        )
        .await
        .unwrap()
        {
            FastAuthentication::Success(verified) => verified,
            other => panic!("expected pending FAST replacement success, got {other:?}"),
        };
        assert!(replacement_verified.was_new);
        assert!(finalize_fast_token(
            &pool,
            replacement_verified.id,
            true,
            false,
            replacement_verified.auth_generation,
        )
        .await
        .unwrap());
        let remaining_ids: Vec<Uuid> = sqlx::query_scalar(
            "SELECT id FROM fast_tokens WHERE user_id=$1 AND device_id=$2 ORDER BY id",
        )
        .bind(user_id)
        .bind(replacement_device)
        .fetch_all(&pool)
        .await
        .unwrap();
        assert_eq!(remaining_ids, vec![replacement_verified.id]);
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| matches!(outcome, FastAuthentication::Replayed))
                .count(),
            1
        );

        // Two slots are global to a client installation, rather than two per
        // mechanism. Promotion across mechanisms preserves the original
        // strong-authentication deadline.
        let original = match authenticate_fast_token(&pool, &master, authenticate(Some(11)))
            .await
            .unwrap()
        {
            FastAuthentication::Success(verified) => verified,
            other => panic!("expected FAST success, got {other:?}"),
        };
        assert!(finalize_fast_token(
            &pool,
            original.id,
            original.was_new,
            false,
            original.auth_generation,
        )
        .await
        .unwrap());
        let endpoint = issue_fast_token(
            &pool,
            &master,
            user_id,
            device_id,
            "HT-SHA-256-ENDP",
            original.auth_generation,
            30,
            90,
            Some((original.strong_auth_at, original.chain_expires_at)),
        )
        .await
        .unwrap();
        let slots: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM fast_tokens
             WHERE user_id=$1 AND device_id=$2 AND revoked_at IS NULL",
        )
        .bind(user_id)
        .bind(device_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(slots, 2);
        let endpoint_binding = b"endpoint-binding";
        let endpoint_proof = auth::fast_proof(&endpoint.token, false, endpoint_binding);
        let promoted = match authenticate_fast_token(
            &pool,
            &master,
            FastAuthenticationRequest {
                user_id,
                device_id,
                mechanism: "HT-SHA-256-ENDP",
                counter: Some(1),
                initiator_proof: &endpoint_proof,
                channel_binding: endpoint_binding,
                invalidate: false,
                rotate_within_days: 7,
            },
        )
        .await
        .unwrap()
        {
            FastAuthentication::Success(verified) => verified,
            other => panic!("expected promoted FAST success, got {other:?}"),
        };
        assert_eq!(promoted.chain_expires_at, original.chain_expires_at);
        assert!(finalize_fast_token(
            &pool,
            promoted.id,
            promoted.was_new,
            false,
            promoted.auth_generation,
        )
        .await
        .unwrap());
        let remaining: (i64, String) = sqlx::query_as(
            "SELECT COUNT(*)::BIGINT, MIN(mechanism) FROM fast_tokens
             WHERE user_id=$1 AND device_id=$2 AND revoked_at IS NULL",
        )
        .bind(user_id)
        .bind(device_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(remaining, (1, "HT-SHA-256-ENDP".to_owned()));

        let epoch_device = Uuid::new_v4();
        let mut tasks = Vec::new();
        for _ in 0..16 {
            let pool = pool.clone();
            tasks.push(tokio::spawn(async move {
                crate::db::next_user_agent_login_epoch(&pool, user_id, epoch_device, 0)
                    .await
                    .unwrap()
                    .unwrap()
            }));
        }
        let mut epochs = Vec::new();
        for task in tasks {
            epochs.push(task.await.unwrap());
        }
        epochs.sort_unstable();
        assert_eq!(epochs, (1..=16).collect::<Vec<_>>());

        crate::db::set_user_status(&pool, admin_id, user_id, Some(true), None)
            .await
            .unwrap();
        assert!(matches!(
            authenticate_fast_token(&pool, &master, authenticate(None))
                .await
                .unwrap(),
            FastAuthentication::CredentialsExpired
        ));
        assert!(issue_fast_token(
            &pool,
            &master,
            user_id,
            device_id,
            "HT-SHA-256-NONE",
            1,
            30,
            90,
            None,
        )
        .await
        .is_err());
        assert_eq!(
            crate::db::next_user_agent_login_epoch(&pool, user_id, epoch_device, 1)
                .await
                .unwrap(),
            None
        );
    }

    #[tokio::test]
    #[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
    async fn fast_derivation_integrity_failures_are_side_effect_free() {
        let url = std::env::var("TEST_DATABASE_URL")
            .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(4)
            .connect(&url)
            .await
            .unwrap();
        crate::db::migrate(&pool).await.unwrap();
        let user_id = Uuid::new_v4();
        let device_id = Uuid::new_v4();
        sqlx::query("INSERT INTO users(id,username,password_hash) VALUES($1,$2,'test-only')")
            .bind(user_id)
            .bind(format!("fast-integrity-{}", user_id.simple()))
            .execute(&pool)
            .await
            .unwrap();
        let master = [0x83_u8; 32];
        let wrong_master = [0x84_u8; 32];
        let issued = issue_fast_token(
            &pool,
            &master,
            user_id,
            device_id,
            "HT-SHA-256-NONE",
            0,
            30,
            90,
            None,
        )
        .await
        .unwrap();
        let proof = auth::fast_proof(&issued.token, false, &[]);
        assert!(matches!(
            authenticate_fast_token(
                &pool,
                &wrong_master,
                FastAuthenticationRequest {
                    user_id,
                    device_id,
                    mechanism: "HT-SHA-256-NONE",
                    counter: Some(41),
                    initiator_proof: &proof,
                    channel_binding: &[],
                    // Even an integrity failure carrying an invalidate request
                    // must not revoke the durable credential.
                    invalidate: true,
                    rotate_within_days: 7,
                },
            )
            .await
            .unwrap(),
            FastAuthentication::IntegrityFailure
        ));
        let unchanged_after_wrong_key: (i64, bool, bool) = sqlx::query_as(
            "SELECT last_counter,used_at IS NULL,revoked_at IS NULL
               FROM fast_tokens WHERE user_id=$1 AND device_id=$2",
        )
        .bind(user_id)
        .bind(device_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(unchanged_after_wrong_key, (-1, true, true));

        sqlx::query("UPDATE fast_tokens SET token_hash=$3 WHERE user_id=$1 AND device_id=$2")
            .bind(user_id)
            .bind(device_id)
            .bind(vec![0_u8; 32])
            .execute(&pool)
            .await
            .unwrap();
        assert!(matches!(
            authenticate_fast_token(
                &pool,
                &master,
                FastAuthenticationRequest {
                    user_id,
                    device_id,
                    mechanism: "HT-SHA-256-NONE",
                    counter: Some(41),
                    initiator_proof: &proof,
                    channel_binding: &[],
                    invalidate: true,
                    rotate_within_days: 7,
                },
            )
            .await
            .unwrap(),
            FastAuthentication::IntegrityFailure
        ));
        let unchanged_after_tamper: (i64, bool, bool) = sqlx::query_as(
            "SELECT last_counter,used_at IS NULL,revoked_at IS NULL
               FROM fast_tokens WHERE user_id=$1 AND device_id=$2",
        )
        .bind(user_id)
        .bind(device_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(unchanged_after_tamper, (-1, true, true));
    }

    #[tokio::test]
    #[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
    async fn bind2_fast_side_effects_rollback_with_route_sql_and_commit_failures() {
        let url = std::env::var("TEST_DATABASE_URL")
            .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(4)
            .connect(&url)
            .await
            .unwrap();
        crate::db::migrate(&pool).await.unwrap();

        let user_id = Uuid::new_v4();
        let device_id = Uuid::new_v4();
        sqlx::query("INSERT INTO users(id,username,password_hash) VALUES($1,$2,'test-only')")
            .bind(user_id)
            .bind(format!(
                "atomic-fast-{}",
                &user_id.simple().to_string()[..10]
            ))
            .execute(&pool)
            .await
            .unwrap();
        let master = [0x73_u8; 32];
        let original = issue_fast_token(
            &pool,
            &master,
            user_id,
            device_id,
            "HT-SHA-256-NONE",
            0,
            30,
            90,
            None,
        )
        .await
        .unwrap();
        let proof = auth::fast_proof(&original.token, false, &[]);
        let verified = match authenticate_fast_token(
            &pool,
            &master,
            FastAuthenticationRequest {
                user_id,
                device_id,
                mechanism: "HT-SHA-256-NONE",
                counter: Some(1),
                initiator_proof: &proof,
                channel_binding: &[],
                invalidate: false,
                rotate_within_days: 7,
            },
        )
        .await
        .unwrap()
        {
            FastAuthentication::Success(verified) => verified,
            other => panic!("expected FAST success, got {other:?}"),
        };
        let plan = FastCommitPlan {
            token_id: Some(verified.id),
            token_was_new: verified.was_new,
            invalidate: false,
            issue: Some(FastTokenIssue {
                device_id,
                mechanism: "HT-SHA-256-ENDP".to_owned(),
                ttl_days: 30,
                strong_reauth_max_days: 90,
                inherited_chain: Some((verified.strong_auth_at, verified.chain_expires_at)),
            }),
        };

        // This is the exact transaction shape used by Bind 2. A route
        // conflict/Redis failure rolls it back before the pending route is
        // removed, so neither the installation epoch nor FAST slots change.
        let mut tx = crate::db::lock_auth_generation(&pool, user_id, 0)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            crate::db::next_user_agent_login_epoch_in_transaction(&mut tx, user_id, device_id, 0)
                .await
                .unwrap(),
            Some(1)
        );
        assert!(matches!(
            commit_fast_state_in_transaction(&mut tx, &master, user_id, 0, &plan)
                .await
                .unwrap(),
            FastCommitOutcome::Committed(Some(_))
        ));
        tx.rollback().await.unwrap();
        assert_bind_side_effects_absent(&pool, user_id, device_id, verified.id).await;

        // Exercise the production unbound-SASL2 helper. A late issuance
        // error occurs after both epoch allocation and promotion SQL have
        // run; dropping its transaction must leak neither side effect.
        let mut invalid_plan = plan.clone();
        invalid_plan.issue.as_mut().unwrap().mechanism = "unsupported".to_owned();
        assert!(commit_fast_state_with_login_epoch(
            &pool,
            &master,
            user_id,
            0,
            &invalid_plan,
            Some(device_id),
        )
        .await
        .is_err());
        assert_bind_side_effects_absent(&pool, user_id, device_id, verified.id).await;

        // Force a real commit-time PostgreSQL failure with a deferred FK.
        // The FAST/epoch writes share that transaction and must roll back.
        sqlx::query("CREATE TABLE IF NOT EXISTS test_fast_commit_parent(id BIGINT PRIMARY KEY)")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS test_fast_commit_child(
               id BIGINT PRIMARY KEY,
               parent_id BIGINT REFERENCES test_fast_commit_parent(id)
                 DEFERRABLE INITIALLY DEFERRED
             )",
        )
        .execute(&pool)
        .await
        .unwrap();
        let mut tx = crate::db::lock_auth_generation(&pool, user_id, 0)
            .await
            .unwrap()
            .unwrap();
        crate::db::next_user_agent_login_epoch_in_transaction(&mut tx, user_id, device_id, 0)
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(
            commit_fast_state_in_transaction(&mut tx, &master, user_id, 0, &plan)
                .await
                .unwrap(),
            FastCommitOutcome::Committed(Some(_))
        ));
        sqlx::query("INSERT INTO test_fast_commit_child(id,parent_id) VALUES(1,999999)")
            .execute(&mut *tx)
            .await
            .unwrap();
        assert!(tx.commit().await.is_err());
        assert_bind_side_effects_absent(&pool, user_id, device_id, verified.id).await;
    }

    async fn assert_bind_side_effects_absent(
        pool: &PgPool,
        user_id: Uuid,
        device_id: Uuid,
        original_id: Uuid,
    ) {
        let rows: Vec<(Uuid, String, String)> = sqlx::query_as(
            "SELECT id,slot,mechanism FROM fast_tokens
             WHERE user_id=$1 AND device_id=$2 ORDER BY slot,id",
        )
        .bind(user_id)
        .bind(device_id)
        .fetch_all(pool)
        .await
        .unwrap();
        assert_eq!(
            rows,
            vec![(original_id, "new".to_owned(), "HT-SHA-256-NONE".to_owned())]
        );
        let epoch: Option<i64> = sqlx::query_scalar(
            "SELECT epoch FROM user_agent_login_epochs WHERE user_id=$1 AND device_id=$2",
        )
        .bind(user_id)
        .bind(device_id)
        .fetch_optional(pool)
        .await
        .unwrap();
        assert_eq!(epoch, None);
    }
}
