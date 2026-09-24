pub use crate::services::api_mutations::{
    api_request_fingerprint, ApiPrincipalKind, IdempotencyRequest, IdempotentResponse,
};
use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use rand::RngCore;
use ring::aead;
use sha2::{Digest, Sha256};
use sqlx::{Postgres, Row, Transaction};
use std::collections::BTreeMap;
use std::fmt::Write as _;
use subtle::ConstantTimeEq;
use uuid::Uuid;
use zeroize::Zeroize;

type HmacSha256 = Hmac<Sha256>;

const MAX_IDEMPOTENCY_KEY_BYTES: usize = 200;
const MAX_REPLAY_BODY_BYTES: usize = 1024 * 1024;
const MAX_REPLAY_HEADERS_BYTES: usize = 8 * 1024;
const MAX_STARTED_PER_PRINCIPAL: i64 = 32;
const MAX_RECORDS_PER_PRINCIPAL: i64 = 128;
const MAX_GLOBAL_RECORDS: i64 = 100_000;
const STARTED_TTL_SECONDS: i64 = 5 * 60;
const ALLOWED_REPLAY_HEADERS: &[&str] = &[
    "cache-control",
    "content-type",
    "etag",
    "location",
    "retry-after",
    "www-authenticate",
];

struct ApiControlKey {
    id: String,
    scope_hmac: [u8; 32],
    fingerprint_hmac: [u8; 32],
    replay_aead: [u8; 32],
}

impl Drop for ApiControlKey {
    fn drop(&mut self) {
        self.scope_hmac.zeroize();
        self.fingerprint_hmac.zeroize();
        self.replay_aead.zeroize();
    }
}

/// Process keyring for REST idempotency scope digests and encrypted response
/// replay. Only opaque key identifiers and HMAC outputs reach PostgreSQL.
pub struct ApiControlKeyring {
    current: ApiControlKey,
    previous: Option<ApiControlKey>,
}

impl ApiControlKeyring {
    pub fn new(current: &[u8], previous: Option<&[u8]>) -> Result<Self> {
        anyhow::ensure!(
            (32..=4096).contains(&current.len()) && !current.contains(&0),
            "API control secret must contain 32 to 4096 bytes without NUL"
        );
        let current = ApiControlKey::derive(current)?;
        let previous = previous
            .map(|secret| {
                anyhow::ensure!(
                    (32..=4096).contains(&secret.len()) && !secret.contains(&0),
                    "previous API control secret must contain 32 to 4096 bytes without NUL"
                );
                ApiControlKey::derive(secret)
            })
            .transpose()?;
        if previous
            .as_ref()
            .is_some_and(|previous| previous.id == current.id)
        {
            anyhow::bail!("current and previous API control secrets must differ");
        }
        Ok(Self { current, previous })
    }

    fn scope_hashes(&self, request: &IdempotencyRequest<'_>) -> ([u8; 32], Option<[u8; 32]>) {
        (
            self.current.scope_hash(request),
            self.previous.as_ref().map(|key| key.scope_hash(request)),
        )
    }

    fn principal_hashes(&self, request: &IdempotencyRequest<'_>) -> ([u8; 32], Option<[u8; 32]>) {
        (
            self.current.principal_hash(request),
            self.previous
                .as_ref()
                .map(|key| key.principal_hash(request)),
        )
    }

    fn request_fingerprints(
        &self,
        request: &IdempotencyRequest<'_>,
    ) -> ([u8; 32], Option<[u8; 32]>) {
        (
            self.current.request_fingerprint(request),
            self.previous
                .as_ref()
                .map(|key| key.request_fingerprint(request)),
        )
    }

    fn key(&self, id: &str) -> Option<&ApiControlKey> {
        if self.current.id == id {
            Some(&self.current)
        } else {
            self.previous.as_ref().filter(|key| key.id == id)
        }
    }
}

impl ApiControlKey {
    fn derive(secret: &[u8]) -> Result<Self> {
        let scope_hmac = derive_subkey(secret, b"northstar/api-control/scope-hmac/v1")?;
        let fingerprint_hmac =
            derive_subkey(secret, b"northstar/api-control/request-fingerprint/v1")?;
        let replay_aead = derive_subkey(secret, b"northstar/api-control/replay-aead/v1")?;
        let digest = Sha256::digest(
            [
                b"northstar/api-control/key-id/v1\0".as_slice(),
                scope_hmac.as_slice(),
            ]
            .concat(),
        );
        let mut id = String::with_capacity(16);
        for byte in &digest[..8] {
            write!(&mut id, "{byte:02x}").expect("writing to String cannot fail");
        }
        Ok(Self {
            id,
            scope_hmac,
            fingerprint_hmac,
            replay_aead,
        })
    }

    fn scope_hash(&self, request: &IdempotencyRequest<'_>) -> [u8; 32] {
        let mut mac = HmacSha256::new_from_slice(&self.scope_hmac)
            .expect("HMAC-SHA-256 accepts a 32-byte key");
        for field in [
            request.principal_kind.as_str().as_bytes(),
            request.principal_scope,
            request.method.as_bytes(),
            request.route.as_bytes(),
            request.idempotency_key.as_bytes(),
        ] {
            mac.update(&(field.len() as u64).to_be_bytes());
            mac.update(field);
        }
        mac.finalize().into_bytes().into()
    }

    fn principal_hash(&self, request: &IdempotencyRequest<'_>) -> [u8; 32] {
        let mut mac = HmacSha256::new_from_slice(&self.scope_hmac)
            .expect("HMAC-SHA-256 accepts a 32-byte key");
        for field in [
            b"principal-capacity-v1".as_slice(),
            request.principal_kind.as_str().as_bytes(),
            request.capacity_scope,
        ] {
            mac.update(&(field.len() as u64).to_be_bytes());
            mac.update(field);
        }
        mac.finalize().into_bytes().into()
    }

    fn request_fingerprint(&self, request: &IdempotencyRequest<'_>) -> [u8; 32] {
        let mut mac = HmacSha256::new_from_slice(&self.fingerprint_hmac)
            .expect("HMAC-SHA-256 accepts a 32-byte key");
        for field in [
            b"request-fingerprint-v1".as_slice(),
            request.route.as_bytes(),
            request.target_scope,
            request.request_fingerprint.as_slice(),
        ] {
            mac.update(&(field.len() as u64).to_be_bytes());
            mac.update(field);
        }
        mac.finalize().into_bytes().into()
    }
}

fn derive_subkey(secret: &[u8], label: &[u8]) -> Result<[u8; 32]> {
    let mut mac = HmacSha256::new_from_slice(secret).context("invalid API control HMAC key")?;
    mac.update(label);
    Ok(mac.finalize().into_bytes().into())
}

#[derive(Debug)]
pub struct IdempotencyLease {
    pub record_id: Uuid,
    pub request_id: Uuid,
    /// True only when the exact request fingerprint previously satisfied its
    /// anti-abuse gate. This survives a worker crash so a consumed PoW nonce
    /// is not demanded a second time, while a merely reserved request can
    /// never bypass the gate after its lease is recovered.
    pub guard_verified: bool,
    completion_ttl_seconds: i64,
    lease_token: Uuid,
    scope_hash: [u8; 32],
    request_fingerprint: [u8; 32],
}

impl IdempotencyLease {
    pub(crate) fn lease_token(&self) -> Uuid {
        self.lease_token
    }
}

#[derive(Debug)]
pub enum IdempotencyAcquire {
    Acquired(IdempotencyLease),
    Replay(IdempotentResponse),
    FingerprintConflict,
    RotationConflict,
    ReplayInvalidated,
    Busy { retry_after_seconds: u64 },
    CapacityLimited { retry_after_seconds: u64 },
    InProgress { retry_after_seconds: u64 },
}

#[derive(Debug)]
pub enum IdempotencyReplayLookup {
    Miss,
    Replay(IdempotentResponse),
    FingerprintConflict,
    RotationConflict,
}

/// Read-only fast path for the password-change success response. A completed
/// response must remain replayable after that very operation revoked the
/// presented bearer. This query deliberately takes no row/global-capacity
/// lock and never inserts: on a miss, the handler starts a new transaction in
/// the global mutation order (user/session -> idempotency -> abuse).
pub async fn lookup_password_change_replay_in_tx(
    keyring: &ApiControlKeyring,
    tx: &mut Transaction<'_, Postgres>,
    request: &IdempotencyRequest<'_>,
) -> Result<IdempotencyReplayLookup> {
    validate_request(request)?;
    anyhow::ensure!(
        request.route == "/api/v1/me/password",
        "password replay lookup used for another route"
    );
    let (current_scope, previous_scope) = keyring.scope_hashes(request);
    let (current_fingerprint, previous_fingerprint) = keyring.request_fingerprints(request);
    let rows = sqlx::query(
        "SELECT * FROM api_idempotency_records
         WHERE state='completed'
           AND (scope_hash=$1 OR ($2::bytea IS NOT NULL AND scope_hash=$2))
         ORDER BY created_at,id",
    )
    .bind(current_scope.as_slice())
    .bind(previous_scope.as_ref().map(<[u8; 32]>::as_slice))
    .fetch_all(&mut **tx)
    .await?;
    if rows.is_empty() {
        return Ok(IdempotencyReplayLookup::Miss);
    }
    if rows.len() != 1 {
        return Ok(IdempotencyReplayLookup::RotationConflict);
    }
    let row = &rows[0];
    let stored_fingerprint: Vec<u8> = row.get("request_fingerprint");
    let matches = stored_fingerprint.len() == 32
        && (bool::from(
            stored_fingerprint
                .as_slice()
                .ct_eq(current_fingerprint.as_slice()),
        ) || previous_fingerprint.as_ref().is_some_and(|previous| {
            bool::from(stored_fingerprint.as_slice().ct_eq(previous.as_slice()))
        }));
    if !matches
        || row.get::<String, _>("method") != request.method
        || row.get::<String, _>("route") != request.route
        || row.get::<String, _>("principal_kind") != request.principal_kind.as_str()
        || row.get::<Option<Uuid>, _>("request_actor_id") != request.actor_id
    {
        return Ok(IdempotencyReplayLookup::FingerprintConflict);
    }
    let id: Uuid = row.get("id");
    let request_id: Uuid = row.get("request_id");
    let scope_hash: Vec<u8> = row.get("scope_hash");
    let scope_hash: [u8; 32] = scope_hash
        .as_slice()
        .try_into()
        .context("stored password replay scope hash has invalid length")?;
    let stored_fingerprint: [u8; 32] = stored_fingerprint
        .as_slice()
        .try_into()
        .context("stored password replay fingerprint has invalid length")?;
    let status = u16::try_from(row.get::<i16, _>("response_status"))
        .context("stored password replay response status is invalid")?;
    let key_id: String = row.get("response_key_id");
    let key = keyring
        .key(&key_id)
        .context("password replay key is no longer configured")?;
    let nonce: Vec<u8> = row.get("response_nonce");
    let nonce: [u8; 12] = nonce
        .as_slice()
        .try_into()
        .context("stored password replay nonce has invalid length")?;
    let mut envelope: Vec<u8> = row.get("response_ciphertext");
    open_replay(
        key,
        nonce,
        replay_aad(id, &scope_hash, &stored_fingerprint, status),
        &mut envelope,
    )?;
    let (headers, body) = decode_replay_envelope(&envelope)?;
    Ok(IdempotencyReplayLookup::Replay(IdempotentResponse {
        request_id,
        status,
        headers,
        body,
    }))
}

pub async fn acquire_idempotency_in_tx(
    keyring: &ApiControlKeyring,
    tx: &mut Transaction<'_, Postgres>,
    request: &IdempotencyRequest<'_>,
) -> Result<IdempotencyAcquire> {
    validate_request(request)?;
    let (current_scope_hash_array, previous_scope_hash) = keyring.scope_hashes(request);
    let (current_principal_hash_array, previous_principal_hash) = keyring.principal_hashes(request);
    let (current_request_fingerprint, previous_request_fingerprint) =
        keyring.request_fingerprints(request);
    let current_scope_hash = current_scope_hash_array.to_vec();
    let previous_scope_hash = previous_scope_hash.map(|hash| hash.to_vec());
    let current_principal_hash = current_principal_hash_array.to_vec();
    let previous_principal_hash = previous_principal_hash.map(|hash| hash.to_vec());

    // This singleton row is the cross-process admission lock. Never wait for
    // it while holding a pooled connection: a burst of idempotent requests
    // must not fill the pool with lock waiters and starve unrelated work.
    // The caller rolls its reservation transaction back immediately on Busy.
    let capacity_lock: Option<i64> = sqlx::query_scalar(
        "SELECT active_records FROM api_idempotency_capacity
         WHERE singleton=TRUE FOR UPDATE SKIP LOCKED",
    )
    .fetch_optional(&mut **tx)
    .await?;
    if capacity_lock.is_none() {
        // A skipped row is ordinary contention, while a missing singleton is
        // loss of the trigger-maintained authority boundary and must fail
        // hard. This MVCC visibility probe does not wait for a row lock.
        let authority_exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(
                 SELECT 1 FROM api_idempotency_capacity WHERE singleton=TRUE
             )",
        )
        .fetch_one(&mut **tx)
        .await?;
        anyhow::ensure!(
            authority_exists,
            "API idempotency capacity authority row is missing"
        );
        return Ok(IdempotencyAcquire::Busy {
            retry_after_seconds: 1,
        });
    }

    sqlx::query(
        "DELETE FROM api_idempotency_records
         WHERE expires_at <= clock_timestamp()
           AND (scope_hash=$1 OR ($2::bytea IS NOT NULL AND scope_hash=$2))",
    )
    .bind(&current_scope_hash)
    .bind(previous_scope_hash.as_deref())
    .execute(&mut **tx)
    .await?;
    sqlx::query(
        "DELETE FROM api_idempotency_records
         WHERE state='started' AND expires_at <= clock_timestamp()
           AND (principal_hash=$1 OR ($2::bytea IS NOT NULL AND principal_hash=$2))",
    )
    .bind(&current_principal_hash)
    .bind(previous_principal_hash.as_deref())
    .execute(&mut **tx)
    .await?;

    let mut rows =
        existing_records(tx, &current_scope_hash, previous_scope_hash.as_deref()).await?;
    if rows.len() > 1 {
        return Ok(IdempotencyAcquire::RotationConflict);
    }
    let row = if let Some(row) = rows.pop() {
        row
    } else {
        let unfinished: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM api_idempotency_records
             WHERE state='started' AND expires_at > clock_timestamp()
               AND (principal_hash=$1 OR ($2::bytea IS NOT NULL AND principal_hash=$2))
               AND ($3::uuid IS NOT NULL OR ownership_actor_id IS NULL)",
        )
        .bind(&current_principal_hash)
        .bind(previous_principal_hash.as_deref())
        .bind(request.actor_id)
        .fetch_one(&mut **tx)
        .await?;
        if unfinished >= MAX_STARTED_PER_PRINCIPAL {
            return Ok(IdempotencyAcquire::CapacityLimited {
                retry_after_seconds: 30,
            });
        }
        let principal_records: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM api_idempotency_records
             WHERE expires_at > clock_timestamp()
               AND (principal_hash=$1 OR ($2::bytea IS NOT NULL AND principal_hash=$2))
               AND ($3::uuid IS NOT NULL OR ownership_actor_id IS NULL)",
        )
        .bind(&current_principal_hash)
        .bind(previous_principal_hash.as_deref())
        .bind(request.actor_id)
        .fetch_one(&mut **tx)
        .await?;
        let global_records: i64 = sqlx::query_scalar(
            "SELECT active_records FROM api_idempotency_capacity WHERE singleton=TRUE",
        )
        .fetch_one(&mut **tx)
        .await?;
        if principal_records >= MAX_RECORDS_PER_PRINCIPAL || global_records >= MAX_GLOBAL_RECORDS {
            return Ok(IdempotencyAcquire::CapacityLimited {
                retry_after_seconds: 60,
            });
        }
        let id = Uuid::new_v4();
        let request_id = request.request_id;
        let lease_token = Uuid::new_v4();
        let inserted = sqlx::query(
            "INSERT INTO api_idempotency_records
             (id,scope_hash,principal_hash,scope_key_id,request_actor_id,ownership_actor_id,principal_kind,method,route,
              request_fingerprint,request_id,state,lease_token,lease_expires_at,expires_at)
             VALUES($1,$2,$3,$4,$5,$5,$6,$7,$8,$9,$10,'started',$11,
                    clock_timestamp()+($12*INTERVAL '1 second'),
                    clock_timestamp()+(LEAST($13,$14)*INTERVAL '1 second'))
             ON CONFLICT(scope_hash) DO NOTHING
             RETURNING *",
        )
        .bind(id)
        .bind(&current_scope_hash)
        .bind(&current_principal_hash)
        .bind(&keyring.current.id)
        .bind(request.actor_id)
        .bind(request.principal_kind.as_str())
        .bind(request.method)
        .bind(request.route)
        .bind(current_request_fingerprint.as_slice())
        .bind(request_id)
        .bind(lease_token)
        .bind(request.lease_seconds)
        .bind(request.ttl_seconds)
        .bind(STARTED_TTL_SECONDS)
        .fetch_optional(&mut **tx)
        .await?;
        if inserted.is_some() {
            return Ok(IdempotencyAcquire::Acquired(IdempotencyLease {
                record_id: id,
                request_id,
                guard_verified: false,
                completion_ttl_seconds: request.ttl_seconds,
                lease_token,
                scope_hash: current_scope_hash_array,
                request_fingerprint: current_request_fingerprint,
            }));
        }
        let mut rows = existing_records(tx, &current_scope_hash, None).await?;
        anyhow::ensure!(rows.len() == 1, "idempotency conflict row disappeared");
        rows.pop().expect("length checked")
    };

    existing_record_result(
        keyring,
        tx,
        request,
        ExistingRecordHashes {
            current_scope: &current_scope_hash_array,
            current_principal: &current_principal_hash_array,
            current_fingerprint: &current_request_fingerprint,
            previous_fingerprint: previous_request_fingerprint.as_ref(),
        },
        row,
    )
    .await
}

async fn existing_records(
    tx: &mut Transaction<'_, Postgres>,
    current_scope_hash: &[u8],
    previous_scope_hash: Option<&[u8]>,
) -> Result<Vec<sqlx::postgres::PgRow>> {
    Ok(sqlx::query(
        "SELECT * FROM api_idempotency_records
         WHERE scope_hash=$1 OR ($2::bytea IS NOT NULL AND scope_hash=$2)
         ORDER BY created_at,id
         FOR UPDATE",
    )
    .bind(current_scope_hash)
    .bind(previous_scope_hash)
    .fetch_all(&mut **tx)
    .await?)
}

struct ExistingRecordHashes<'a> {
    current_scope: &'a [u8; 32],
    current_principal: &'a [u8; 32],
    current_fingerprint: &'a [u8; 32],
    previous_fingerprint: Option<&'a [u8; 32]>,
}

async fn existing_record_result(
    keyring: &ApiControlKeyring,
    tx: &mut Transaction<'_, Postgres>,
    request: &IdempotencyRequest<'_>,
    hashes: ExistingRecordHashes<'_>,
    row: sqlx::postgres::PgRow,
) -> Result<IdempotencyAcquire> {
    let stored_fingerprint: Vec<u8> = row.get("request_fingerprint");
    let fingerprint_matches = stored_fingerprint.len() == 32
        && (bool::from(
            stored_fingerprint
                .as_slice()
                .ct_eq(hashes.current_fingerprint.as_slice()),
        ) || hashes.previous_fingerprint.is_some_and(|previous| {
            bool::from(stored_fingerprint.as_slice().ct_eq(previous.as_slice()))
        }));
    if !fingerprint_matches
        || row.get::<String, _>("method") != request.method
        || row.get::<String, _>("route") != request.route
        || row.get::<String, _>("principal_kind") != request.principal_kind.as_str()
        || row.get::<Option<Uuid>, _>("request_actor_id") != request.actor_id
    {
        return Ok(IdempotencyAcquire::FingerprintConflict);
    }
    let id: Uuid = row.get("id");
    let request_id: Uuid = row.get("request_id");
    let scope_hash: Vec<u8> = row.get("scope_hash");
    let scope_hash: [u8; 32] = scope_hash
        .as_slice()
        .try_into()
        .context("stored idempotency scope hash has invalid length")?;
    let stored_fingerprint: [u8; 32] = stored_fingerprint
        .as_slice()
        .try_into()
        .context("stored keyed request fingerprint has invalid length")?;
    let needs_rotation = !bool::from(scope_hash.ct_eq(hashes.current_scope))
        || !bool::from(stored_fingerprint.ct_eq(hashes.current_fingerprint));
    if row.get::<String, _>("state") == "completed" {
        let status = u16::try_from(row.get::<i16, _>("response_status"))
            .context("stored idempotency response status is invalid")?;
        if request.route == "/api/v1/admin/invitations" && request.method == "POST" {
            let invitation_id: Option<Uuid> = row.get("replay_resource_id");
            let replayable = if let Some(invitation_id) = invitation_id {
                sqlx::query_scalar::<_, bool>(
                    "SELECT TRUE FROM invitation_tokens
                     WHERE id=$1 AND revoked_at IS NULL
                       AND (expires_at IS NULL OR expires_at > clock_timestamp())
                       AND use_count < max_uses
                     FOR SHARE",
                )
                .bind(invitation_id)
                .fetch_optional(&mut **tx)
                .await?
                .is_some()
            } else {
                false
            };
            if !replayable {
                return Ok(IdempotencyAcquire::ReplayInvalidated);
            }
        }
        if row.get::<String, _>("route") == "/api/v1/login" && status == 200 {
            let replay_session_id: Option<Uuid> = row.get("replay_session_id");
            let replay_session_token_hash: Option<Vec<u8>> = row.get("replay_session_token_hash");
            let replay_auth_generation: Option<i64> = row.get("replay_auth_generation");
            let replay_session_expires_at: Option<DateTime<Utc>> =
                row.get("replay_session_expires_at");
            let valid = match (
                replay_session_id,
                replay_session_token_hash,
                replay_auth_generation,
                replay_session_expires_at,
            ) {
                (Some(session_id), Some(token_hash), Some(generation), Some(expires_at))
                    if token_hash.len() == 32 =>
                {
                    let ownership_actor_id: Option<Uuid> = row.get("ownership_actor_id");
                    sqlx::query_scalar::<_, bool>(
                        "SELECT EXISTS(
                            SELECT 1 FROM api_sessions AS session
                            JOIN users AS actor ON actor.id=session.user_id
                            WHERE session.id=$1 AND session.token_hash=$2
                              AND session.expires_at=$3
                              AND session.expires_at > clock_timestamp()
                              AND actor.id=$4 AND actor.auth_generation=$5
                              AND NOT actor.is_disabled
                         )",
                    )
                    .bind(session_id)
                    .bind(token_hash)
                    .bind(expires_at)
                    .bind(ownership_actor_id)
                    .bind(generation)
                    .fetch_one(&mut **tx)
                    .await?
                }
                _ => false,
            };
            if !valid {
                return Ok(IdempotencyAcquire::ReplayInvalidated);
            }
        }
        anyhow::ensure!(
            row.get::<String, _>("route") != "/api/v1/login" || matches!(status, 200 | 401),
            "stored login replay status is invalid"
        );
        let key_id: String = row.get("response_key_id");
        let key = keyring
            .key(&key_id)
            .context("idempotency replay key is no longer configured")?;
        let nonce: Vec<u8> = row.get("response_nonce");
        let nonce: [u8; 12] = nonce
            .as_slice()
            .try_into()
            .context("stored idempotency replay nonce has invalid length")?;
        let mut encrypted_envelope: Vec<u8> = row.get("response_ciphertext");
        open_replay(
            key,
            nonce,
            replay_aad(id, &scope_hash, &stored_fingerprint, status),
            &mut encrypted_envelope,
        )?;
        let (headers, body) = decode_replay_envelope(&encrypted_envelope)?;
        if needs_rotation {
            let mut replacement_nonce = [0_u8; 12];
            rand::thread_rng().fill_bytes(&mut replacement_nonce);
            let mut replacement_ciphertext = encrypted_envelope;
            seal_replay(
                &keyring.current,
                replacement_nonce,
                replay_aad(id, hashes.current_scope, hashes.current_fingerprint, status),
                &mut replacement_ciphertext,
            )?;
            let updated = sqlx::query(
                "UPDATE api_idempotency_records
                 SET scope_hash=$2,principal_hash=$3,request_fingerprint=$4,
                     scope_key_id=$5,response_key_id=$5,
                     response_nonce=$6,response_ciphertext=$7,updated_at=clock_timestamp()
                 WHERE id=$1 AND scope_hash=$8 AND request_fingerprint=$9
                   AND state='completed'",
            )
            .bind(id)
            .bind(hashes.current_scope.as_slice())
            .bind(hashes.current_principal.as_slice())
            .bind(hashes.current_fingerprint.as_slice())
            .bind(&keyring.current.id)
            .bind(replacement_nonce.as_slice())
            .bind(replacement_ciphertext)
            .bind(scope_hash.as_slice())
            .bind(stored_fingerprint.as_slice())
            .execute(&mut **tx)
            .await;
            match updated {
                Ok(result) if result.rows_affected() == 1 => {}
                Ok(_) => return Ok(IdempotencyAcquire::RotationConflict),
                Err(error)
                    if error
                        .as_database_error()
                        .is_some_and(|error| error.code().as_deref() == Some("23505")) =>
                {
                    return Ok(IdempotencyAcquire::RotationConflict)
                }
                Err(error) => return Err(error.into()),
            }
        }
        return Ok(IdempotencyAcquire::Replay(IdempotentResponse {
            request_id,
            status,
            headers,
            body,
        }));
    }

    let lease_expires_at: DateTime<Utc> = row.get("lease_expires_at");
    let now: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(&mut **tx)
        .await?;
    if lease_expires_at > now {
        return Ok(IdempotencyAcquire::InProgress {
            retry_after_seconds: u64::try_from((lease_expires_at - now).num_seconds().max(1))
                .unwrap_or(1),
        });
    }
    let lease_token = Uuid::new_v4();
    let changed = sqlx::query(
        "UPDATE api_idempotency_records
         SET lease_token=$2,lease_expires_at=clock_timestamp()+($3*INTERVAL '1 second'),
             scope_hash=$4,principal_hash=$5,request_fingerprint=$6,scope_key_id=$7,
             attempts=attempts+1,updated_at=clock_timestamp()
         WHERE id=$1 AND state='started' AND lease_expires_at <= clock_timestamp()
           AND attempts < 1000",
    )
    .bind(id)
    .bind(lease_token)
    .bind(request.lease_seconds)
    .bind(hashes.current_scope.as_slice())
    .bind(hashes.current_principal.as_slice())
    .bind(hashes.current_fingerprint.as_slice())
    .bind(&keyring.current.id)
    .execute(&mut **tx)
    .await?
    .rows_affected();
    anyhow::ensure!(changed == 1, "idempotency lease could not be recovered");
    Ok(IdempotencyAcquire::Acquired(IdempotencyLease {
        record_id: id,
        request_id,
        guard_verified: row
            .get::<Option<DateTime<Utc>>, _>("guard_verified_at")
            .is_some(),
        completion_ttl_seconds: request.ttl_seconds,
        lease_token,
        scope_hash: *hashes.current_scope,
        request_fingerprint: *hashes.current_fingerprint,
    }))
}

/// Renew a reservation immediately before entering its mutation transaction.
/// The exact lease token fences a recovered worker from committing after a
/// retry has taken ownership.
pub async fn resume_idempotency_lease_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    lease: &IdempotencyLease,
    lease_seconds: i64,
) -> Result<bool> {
    resume_idempotency_lease_fence_in_tx(tx, lease.record_id, lease.lease_token, lease_seconds)
        .await
}

pub(crate) async fn resume_idempotency_lease_fence_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    record_id: Uuid,
    lease_token: Uuid,
    lease_seconds: i64,
) -> Result<bool> {
    anyhow::ensure!((5..=300).contains(&lease_seconds), "invalid lease duration");
    Ok(sqlx::query(
        "UPDATE api_idempotency_records
         SET lease_expires_at=clock_timestamp()+($3*INTERVAL '1 second'),
             updated_at=clock_timestamp()
         WHERE id=$1 AND state='started' AND lease_token=$2
           AND lease_expires_at > clock_timestamp()",
    )
    .bind(record_id)
    .bind(lease_token)
    .bind(lease_seconds)
    .execute(&mut **tx)
    .await?
    .rows_affected()
        == 1)
}

/// Persist that the exact request body passed its anti-abuse gate. Persistent
/// one-use proof consumption and this marker must be in the same PostgreSQL
/// transaction as the protected mutation (or its durable replay response).
pub async fn mark_idempotency_guard_verified_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    lease: &IdempotencyLease,
) -> Result<bool> {
    mark_idempotency_guard_verified_fence_in_tx(tx, lease.record_id, lease.lease_token).await
}

pub(crate) async fn mark_idempotency_guard_verified_fence_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    record_id: Uuid,
    lease_token: Uuid,
) -> Result<bool> {
    Ok(sqlx::query(
        "UPDATE api_idempotency_records
         SET guard_verified_at=COALESCE(guard_verified_at,clock_timestamp()),
             updated_at=clock_timestamp()
         WHERE id=$1 AND state='started' AND lease_token=$2
           AND lease_expires_at > clock_timestamp()",
    )
    .bind(record_id)
    .bind(lease_token)
    .execute(&mut **tx)
    .await?
    .rows_affected()
        == 1)
}

/// Release an uncommitted reservation after a deterministic rejection. The
/// lease token prevents an old worker from deleting a recovered request.
pub async fn abandon_idempotency_lease(
    pool: &sqlx::PgPool,
    lease: &IdempotencyLease,
) -> Result<bool> {
    Ok(sqlx::query(
        "DELETE FROM api_idempotency_records
         WHERE id=$1 AND state='started' AND lease_token=$2",
    )
    .bind(lease.record_id)
    .bind(lease.lease_token)
    .execute(pool)
    .await?
    .rows_affected()
        == 1)
}

/// Yield an unfinished request lease without erasing a committed anti-abuse
/// marker. This is used when bounded expensive work is temporarily
/// unavailable after the exact request already consumed its one-use proof.
/// A retry can immediately take a fresh fenced lease, while the old worker's
/// token can no longer resume or commit the request.
pub async fn yield_idempotency_lease(
    pool: &sqlx::PgPool,
    lease: &IdempotencyLease,
) -> Result<bool> {
    Ok(sqlx::query(
        "UPDATE api_idempotency_records
         SET lease_expires_at=clock_timestamp(),updated_at=clock_timestamp()
         WHERE id=$1 AND state='started' AND lease_token=$2
           AND lease_expires_at > clock_timestamp()",
    )
    .bind(lease.record_id)
    .bind(lease.lease_token)
    .execute(pool)
    .await?
    .rows_affected()
        == 1)
}

/// Transactional counterpart used when a deterministic anti-abuse denial has
/// already changed one-use challenge or penalty state. Deleting the lease and
/// committing the denial together makes an exact retry unambiguous; backend
/// failures roll both changes back.
pub async fn abandon_idempotency_lease_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    lease: &IdempotencyLease,
) -> Result<bool> {
    abandon_idempotency_lease_fence_in_tx(tx, lease.record_id, lease.lease_token).await
}

pub(crate) async fn abandon_idempotency_lease_fence_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    record_id: Uuid,
    lease_token: Uuid,
) -> Result<bool> {
    Ok(sqlx::query(
        "DELETE FROM api_idempotency_records
         WHERE id=$1 AND state='started' AND lease_token=$2",
    )
    .bind(record_id)
    .bind(lease_token)
    .execute(&mut **tx)
    .await?
    .rows_affected()
        == 1)
}

pub async fn bind_idempotency_session_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    lease: &IdempotencyLease,
    session_id: Uuid,
    token_hash: &[u8],
    auth_generation: i64,
    session_expires_at: DateTime<Utc>,
) -> Result<bool> {
    anyhow::ensure!(token_hash.len() == 32, "invalid session token digest");
    anyhow::ensure!(auth_generation >= 0, "invalid authentication generation");
    Ok(sqlx::query(
        "UPDATE api_idempotency_records
         SET replay_session_id=$3,replay_session_token_hash=$4,
             replay_auth_generation=$5,replay_session_expires_at=$6,
             expires_at=LEAST(expires_at,$6),updated_at=clock_timestamp()
         WHERE id=$1 AND state='started' AND lease_token=$2
           AND ownership_actor_id IS NOT NULL
           AND replay_session_id IS NULL",
    )
    .bind(lease.record_id)
    .bind(lease.lease_token)
    .bind(session_id)
    .bind(token_hash)
    .bind(auth_generation)
    .bind(session_expires_at)
    .execute(&mut **tx)
    .await?
    .rows_affected()
        == 1)
}

pub async fn complete_idempotency_in_tx(
    keyring: &ApiControlKeyring,
    tx: &mut Transaction<'_, Postgres>,
    lease: &IdempotencyLease,
    status: u16,
    headers: &BTreeMap<String, String>,
    body: &[u8],
) -> Result<bool> {
    complete_idempotency_with_resource_in_tx(keyring, tx, lease, status, headers, body, None).await
}

pub async fn complete_idempotency_with_resource_in_tx(
    keyring: &ApiControlKeyring,
    tx: &mut Transaction<'_, Postgres>,
    lease: &IdempotencyLease,
    status: u16,
    headers: &BTreeMap<String, String>,
    body: &[u8],
    replay_resource_id: Option<Uuid>,
) -> Result<bool> {
    anyhow::ensure!(
        (100..=599).contains(&status),
        "invalid HTTP response status"
    );
    validate_replay_headers(headers)?;
    anyhow::ensure!(
        body.len() <= MAX_REPLAY_BODY_BYTES,
        "replay response exceeds the database bound"
    );
    let mut nonce = [0_u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce);
    let mut ciphertext = encode_replay_envelope(headers, body)?;
    seal_replay(
        &keyring.current,
        nonce,
        replay_aad(
            lease.record_id,
            &lease.scope_hash,
            &lease.request_fingerprint,
            status,
        ),
        &mut ciphertext,
    )?;
    let replay_ttl_seconds = if status >= 400 {
        lease.completion_ttl_seconds.min(STARTED_TTL_SECONDS)
    } else {
        lease.completion_ttl_seconds
    };
    let completed = sqlx::query(
        "UPDATE api_idempotency_records
         SET state='completed',lease_token=NULL,lease_expires_at=NULL,
             response_status=$3,response_key_id=$4,
             response_nonce=$5,response_ciphertext=$6,
             replay_resource_id=$8,
             expires_at=LEAST(
                 clock_timestamp()+($7*INTERVAL '1 second'),
                 COALESCE(replay_session_expires_at,'infinity'::timestamptz),
                 COALESCE(
                     (SELECT expires_at FROM invitation_tokens WHERE id=$8),
                     'infinity'::timestamptz
                 )
             ),
             completed_at=clock_timestamp(),updated_at=clock_timestamp()
         WHERE id=$1 AND state='started' AND lease_token=$2",
    )
    .bind(lease.record_id)
    .bind(lease.lease_token)
    .bind(i16::try_from(status).expect("HTTP status fits i16"))
    .bind(&keyring.current.id)
    .bind(nonce.as_slice())
    .bind(ciphertext)
    .bind(replay_ttl_seconds)
    .bind(replay_resource_id)
    .execute(&mut **tx)
    .await?
    .rows_affected()
        == 1;
    Ok(completed)
}

pub async fn bind_idempotency_actor_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    lease: &IdempotencyLease,
    actor_id: Uuid,
) -> Result<bool> {
    Ok(sqlx::query(
        "UPDATE api_idempotency_records SET ownership_actor_id=$3,updated_at=clock_timestamp()
         WHERE id=$1 AND state='started' AND lease_token=$2 AND ownership_actor_id IS NULL",
    )
    .bind(lease.record_id)
    .bind(lease.lease_token)
    .bind(actor_id)
    .execute(&mut **tx)
    .await?
    .rows_affected()
        == 1)
}

pub async fn cleanup_expired_idempotency(pool: &sqlx::PgPool, limit: i64) -> Result<u64> {
    anyhow::ensure!((1..=10_000).contains(&limit), "cleanup limit is invalid");
    let result = sqlx::query(
        "DELETE FROM api_idempotency_records WHERE id IN (
            SELECT id FROM api_idempotency_records
            WHERE expires_at <= clock_timestamp()
            ORDER BY expires_at,id LIMIT $1 FOR UPDATE SKIP LOCKED
         )",
    )
    .bind(limit)
    .execute(pool)
    .await?;
    Ok(result.rows_affected())
}

fn validate_replay_headers(headers: &BTreeMap<String, String>) -> Result<()> {
    for (name, value) in headers {
        anyhow::ensure!(
            name == &name.to_ascii_lowercase()
                && ALLOWED_REPLAY_HEADERS.binary_search(&name.as_str()).is_ok(),
            "response header is not safe for idempotent replay"
        );
        anyhow::ensure!(
            value.len() <= 2048
                && !value
                    .bytes()
                    .any(|byte| byte.is_ascii_control() && byte != b'\t'),
            "response header value is invalid"
        );
    }
    anyhow::ensure!(
        serde_json::to_vec(headers)?.len() <= MAX_REPLAY_HEADERS_BYTES,
        "replay headers exceed the database bound"
    );
    Ok(())
}

fn encode_replay_envelope(headers: &BTreeMap<String, String>, body: &[u8]) -> Result<Vec<u8>> {
    validate_replay_headers(headers)?;
    let header_bytes = serde_json::to_vec(headers)?;
    let header_len = u32::try_from(header_bytes.len()).context("replay headers are too large")?;
    let mut envelope = Vec::with_capacity(4 + header_bytes.len() + body.len());
    envelope.extend_from_slice(&header_len.to_be_bytes());
    envelope.extend_from_slice(&header_bytes);
    envelope.extend_from_slice(body);
    Ok(envelope)
}

fn decode_replay_envelope(envelope: &[u8]) -> Result<(BTreeMap<String, String>, Vec<u8>)> {
    anyhow::ensure!(
        envelope.len() >= 4,
        "idempotency replay envelope is truncated"
    );
    let header_len = u32::from_be_bytes(
        envelope[..4]
            .try_into()
            .expect("four-byte slice has fixed length"),
    ) as usize;
    anyhow::ensure!(
        header_len <= MAX_REPLAY_HEADERS_BYTES && 4 + header_len <= envelope.len(),
        "idempotency replay header envelope is invalid"
    );
    let headers: BTreeMap<String, String> = serde_json::from_slice(&envelope[4..4 + header_len])?;
    validate_replay_headers(&headers)?;
    let body = envelope[4 + header_len..].to_vec();
    anyhow::ensure!(
        body.len() <= MAX_REPLAY_BODY_BYTES,
        "idempotency replay body exceeds the database bound"
    );
    Ok((headers, body))
}

fn validate_request(request: &IdempotencyRequest<'_>) -> Result<()> {
    anyhow::ensure!(
        matches!(request.method, "POST" | "PUT" | "PATCH" | "DELETE"),
        "idempotency is only valid for mutation methods"
    );
    anyhow::ensure!(
        !request.route.is_empty()
            && request.route.len() <= 512
            && request.route.starts_with('/')
            && !request.route.contains('?')
            && !request.route.chars().any(char::is_control),
        "idempotency route must be a canonical path template"
    );
    anyhow::ensure!(
        !request.principal_scope.is_empty() && request.principal_scope.len() <= 1024,
        "idempotency principal scope is invalid"
    );
    anyhow::ensure!(
        !request.capacity_scope.is_empty() && request.capacity_scope.len() <= 1024,
        "idempotency capacity scope is invalid"
    );
    anyhow::ensure!(
        request.target_scope.len() <= 1024,
        "idempotency target scope is invalid"
    );
    anyhow::ensure!(
        (8..=MAX_IDEMPOTENCY_KEY_BYTES).contains(&request.idempotency_key.len())
            && request
                .idempotency_key
                .bytes()
                .all(|byte| (0x21..=0x7e).contains(&byte)),
        "Idempotency-Key must contain 8 to 200 visible ASCII bytes"
    );
    anyhow::ensure!(
        (60..=86_400).contains(&request.ttl_seconds),
        "idempotency TTL must be between 60 and 86400 seconds"
    );
    anyhow::ensure!(
        (5..=300).contains(&request.lease_seconds),
        "idempotency lease must be between 5 and 300 seconds"
    );
    Ok(())
}

fn replay_aad(
    record_id: Uuid,
    scope_hash: &[u8; 32],
    request_fingerprint: &[u8; 32],
    status: u16,
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(16 + 32 + 32 + 2 + 33);
    aad.extend_from_slice(b"northstar/api-control/replay/v1\0");
    aad.extend_from_slice(record_id.as_bytes());
    aad.extend_from_slice(scope_hash);
    aad.extend_from_slice(request_fingerprint);
    aad.extend_from_slice(&status.to_be_bytes());
    aad
}

fn seal_replay(
    key: &ApiControlKey,
    nonce: [u8; 12],
    aad: Vec<u8>,
    body: &mut Vec<u8>,
) -> Result<()> {
    let key = aead::UnboundKey::new(&aead::AES_256_GCM, &key.replay_aead)
        .map(aead::LessSafeKey::new)
        .map_err(|_| anyhow::anyhow!("could not initialize replay AEAD"))?;
    key.seal_in_place_append_tag(
        aead::Nonce::assume_unique_for_key(nonce),
        aead::Aad::from(aad),
        body,
    )
    .map_err(|_| anyhow::anyhow!("could not encrypt idempotency replay"))?;
    Ok(())
}

fn open_replay(
    key: &ApiControlKey,
    nonce: [u8; 12],
    aad: Vec<u8>,
    body: &mut Vec<u8>,
) -> Result<()> {
    let key = aead::UnboundKey::new(&aead::AES_256_GCM, &key.replay_aead)
        .map(aead::LessSafeKey::new)
        .map_err(|_| anyhow::anyhow!("could not initialize replay AEAD"))?;
    let plaintext = key
        .open_in_place(
            aead::Nonce::assume_unique_for_key(nonce),
            aead::Aad::from(aad),
            body,
        )
        .map_err(|_| anyhow::anyhow!("idempotency replay authentication failed"))?;
    let plaintext_len = plaintext.len();
    body.truncate(plaintext_len);
    Ok(())
}

#[cfg(test)]
#[path = "api_control_tests.rs"]
mod tests;
