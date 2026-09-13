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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApiPrincipalKind {
    Anonymous,
    User,
    #[allow(dead_code)]
    Admin,
    #[allow(dead_code)]
    Upload,
}

impl ApiPrincipalKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Anonymous => "anonymous",
            Self::User => "user",
            Self::Admin => "admin",
            Self::Upload => "upload",
        }
    }
}

pub struct IdempotencyRequest<'a> {
    pub request_id: Uuid,
    pub actor_id: Option<Uuid>,
    /// Canonical request-scoped identity. It is HMACed and never persisted.
    pub principal_scope: &'a [u8],
    /// Coarser abuse boundary used only to cap unfinished reservations.
    pub capacity_scope: &'a [u8],
    /// Canonical path/object identity. Raw identifiers are never persisted;
    /// a keyed digest is compared under the idempotency scope instead.
    pub target_scope: &'a [u8],
    pub principal_kind: ApiPrincipalKind,
    pub method: &'a str,
    /// Canonical route template, never a raw URI or query string.
    pub route: &'a str,
    pub idempotency_key: &'a str,
    pub request_fingerprint: [u8; 32],
    pub ttl_seconds: i64,
    pub lease_seconds: i64,
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

#[derive(Debug, Eq, PartialEq)]
pub struct IdempotentResponse {
    pub request_id: Uuid,
    pub status: u16,
    pub headers: BTreeMap<String, String>,
    pub body: Vec<u8>,
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

/// Hash the exact media type and bytes consumed by a mutation handler. HTTP
/// code must call this before deserializing so semantically different JSON
/// encodings cannot be silently substituted under one idempotency key.
pub fn api_request_fingerprint(content_type: &str, body: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update((content_type.len() as u64).to_be_bytes());
    hash.update(content_type.as_bytes());
    hash.update((body.len() as u64).to_be_bytes());
    hash.update(body);
    hash.finalize().into()
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
    anyhow::ensure!((5..=300).contains(&lease_seconds), "invalid lease duration");
    Ok(sqlx::query(
        "UPDATE api_idempotency_records
         SET lease_expires_at=clock_timestamp()+($3*INTERVAL '1 second'),
             updated_at=clock_timestamp()
         WHERE id=$1 AND state='started' AND lease_token=$2
           AND lease_expires_at > clock_timestamp()",
    )
    .bind(lease.record_id)
    .bind(lease.lease_token)
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
    Ok(sqlx::query(
        "UPDATE api_idempotency_records
         SET guard_verified_at=COALESCE(guard_verified_at,clock_timestamp()),
             updated_at=clock_timestamp()
         WHERE id=$1 AND state='started' AND lease_token=$2
           AND lease_expires_at > clock_timestamp()",
    )
    .bind(lease.record_id)
    .bind(lease.lease_token)
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
    Ok(sqlx::query(
        "DELETE FROM api_idempotency_records
         WHERE id=$1 AND state='started' AND lease_token=$2",
    )
    .bind(lease.record_id)
    .bind(lease.lease_token)
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
mod tests {
    use super::*;

    fn request<'a>(key: &'a str, body: &[u8]) -> IdempotencyRequest<'a> {
        IdempotencyRequest {
            request_id: Uuid::new_v4(),
            actor_id: Some(Uuid::nil()),
            principal_scope: b"user:00000000-0000-0000-0000-000000000000",
            capacity_scope: b"user:00000000-0000-0000-0000-000000000000",
            target_scope: b"",
            principal_kind: ApiPrincipalKind::User,
            method: "POST",
            route: "/api/v1/example",
            idempotency_key: key,
            request_fingerprint: api_request_fingerprint("application/json", body),
            ttl_seconds: 3600,
            lease_seconds: 30,
        }
    }

    fn admin_request<'a>(
        actor_id: &'a Uuid,
        key: &'a str,
        target_scope: &'a [u8],
        method: &'a str,
        route: &'a str,
        body: &[u8],
    ) -> IdempotencyRequest<'a> {
        IdempotencyRequest {
            request_id: Uuid::new_v4(),
            actor_id: Some(*actor_id),
            principal_scope: actor_id.as_bytes(),
            capacity_scope: actor_id.as_bytes(),
            target_scope,
            principal_kind: ApiPrincipalKind::Admin,
            method,
            route,
            idempotency_key: key,
            request_fingerprint: api_request_fingerprint("application/json", body),
            ttl_seconds: 3600,
            lease_seconds: 30,
        }
    }

    fn acquired(outcome: IdempotencyAcquire) -> IdempotencyLease {
        match outcome {
            IdempotencyAcquire::Acquired(lease) => lease,
            other => panic!("expected a new idempotency lease, got {other:?}"),
        }
    }

    #[test]
    fn scope_and_keyed_fingerprint_bind_request_without_persisting_raw_identity() {
        let keys = ApiControlKeyring::new(b"0123456789abcdef0123456789abcdef", None).unwrap();
        let first = request("request-key-0001", br#"{"value":1}"#);
        let second = request("request-key-0002", br#"{"value":1}"#);
        let first_hash = keys.scope_hashes(&first).0;
        assert_ne!(first_hash, keys.scope_hashes(&second).0);

        let mut other_route = request("request-key-0001", br#"{"value":1}"#);
        other_route.route = "/api/v1/other";
        assert_ne!(first_hash, keys.scope_hashes(&other_route).0);

        let first_fingerprint = keys.request_fingerprints(&first).0;
        assert_ne!(first_fingerprint, first.request_fingerprint);
        let different_body = request("request-key-0001", br#"{"value":2}"#);
        assert_ne!(
            first_fingerprint,
            keys.request_fingerprints(&different_body).0
        );
        let mut different_target = request("request-key-0001", br#"{"value":1}"#);
        different_target.target_scope = b"report:00000000-0000-0000-0000-000000000001";
        assert_eq!(first_hash, keys.scope_hashes(&different_target).0);
        assert_ne!(
            first_fingerprint,
            keys.request_fingerprints(&different_target).0
        );
    }

    #[test]
    fn replay_aead_detects_ciphertext_and_context_tampering() {
        let keys = ApiControlKeyring::new(b"0123456789abcdef0123456789abcdef", None).unwrap();
        let id = Uuid::new_v4();
        let scope = [1_u8; 32];
        let fingerprint = [2_u8; 32];
        let nonce = [3_u8; 12];
        let aad = replay_aad(id, &scope, &fingerprint, 201);
        let mut ciphertext = br#"{"token":"secret"}"#.to_vec();
        seal_replay(&keys.current, nonce, aad.clone(), &mut ciphertext).unwrap();
        assert!(!String::from_utf8_lossy(&ciphertext).contains("secret"));
        let mut valid = ciphertext.clone();
        open_replay(&keys.current, nonce, aad, &mut valid).unwrap();
        assert_eq!(valid, br#"{"token":"secret"}"#);

        ciphertext[0] ^= 1;
        assert!(open_replay(
            &keys.current,
            nonce,
            replay_aad(id, &scope, &fingerprint, 201),
            &mut ciphertext,
        )
        .is_err());
    }

    #[tokio::test]
    #[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
    async fn capacity_lock_contention_fails_fast_without_starving_pool() {
        use std::sync::Arc;
        use std::time::Duration;
        use tokio::sync::Barrier;

        let url = std::env::var("TEST_DATABASE_URL")
            .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(4)
            .connect(&url)
            .await
            .unwrap();
        crate::db::migrate(&pool).await.unwrap();

        let keys =
            Arc::new(ApiControlKeyring::new(b"capacity-lock-test-secret-000000001", None).unwrap());
        let mut holder = pool.begin().await.unwrap();
        let _: i64 = sqlx::query_scalar(
            "SELECT active_records FROM api_idempotency_capacity
             WHERE singleton=TRUE FOR UPDATE",
        )
        .fetch_one(&mut *holder)
        .await
        .unwrap();

        // The holder plus these three transactions occupy all four pool
        // connections before they race the singleton. With a blocking
        // `FOR UPDATE`, an unrelated query could never obtain a connection.
        let ready = Arc::new(Barrier::new(4));
        let contender = |number: u8| {
            let pool = pool.clone();
            let keys = Arc::clone(&keys);
            let ready = Arc::clone(&ready);
            tokio::spawn(async move {
                let key = format!("capacity-busy-key-{number:04}");
                let body = format!(r#"{{"contender":{number}}}"#);
                let mut request = request(&key, body.as_bytes());
                request.actor_id = None;
                request.principal_kind = ApiPrincipalKind::Anonymous;
                request.principal_scope = b"capacity-lock-test:anonymous";
                request.capacity_scope = b"capacity-lock-test:anonymous";
                let mut tx = pool.begin().await.unwrap();
                ready.wait().await;
                let retry_after = match acquire_idempotency_in_tx(&keys, &mut tx, &request)
                    .await
                    .unwrap()
                {
                    IdempotencyAcquire::Busy {
                        retry_after_seconds,
                    } => retry_after_seconds,
                    other => panic!("expected busy capacity admission, got {other:?}"),
                };
                // Production callers have the same explicit rollback branch;
                // the connection must return to the pool before any retry.
                tx.rollback().await.unwrap();
                retry_after
            })
        };
        let first = contender(1);
        let second = contender(2);
        let third = contender(3);
        ready.wait().await;

        let unrelated: i32 = tokio::time::timeout(
            Duration::from_secs(2),
            sqlx::query_scalar("SELECT 1").fetch_one(&pool),
        )
        .await
        .expect("idempotency lock waiters starved an unrelated pool query")
        .unwrap();
        assert_eq!(unrelated, 1);

        let (first, second, third) = tokio::time::timeout(Duration::from_secs(2), async {
            tokio::join!(first, second, third)
        })
        .await
        .expect("busy idempotency admissions did not return promptly");
        assert_eq!(first.unwrap(), 1);
        assert_eq!(second.unwrap(), 1);
        assert_eq!(third.unwrap(), 1);
        holder.rollback().await.unwrap();

        let mut recovered = pool.begin().await.unwrap();
        let mut recovered_request = request("capacity-recovered-key", br#"{"recovered":true}"#);
        recovered_request.actor_id = None;
        recovered_request.principal_kind = ApiPrincipalKind::Anonymous;
        recovered_request.principal_scope = b"capacity-lock-test:anonymous";
        recovered_request.capacity_scope = b"capacity-lock-test:anonymous";
        assert!(matches!(
            acquire_idempotency_in_tx(&keys, &mut recovered, &recovered_request)
                .await
                .unwrap(),
            IdempotencyAcquire::Acquired(_)
        ));
        recovered.rollback().await.unwrap();

        let mut missing_authority = pool.begin().await.unwrap();
        sqlx::query("DELETE FROM api_idempotency_capacity WHERE singleton=TRUE")
            .execute(&mut *missing_authority)
            .await
            .unwrap();
        let mut missing_request = request("capacity-missing-key", br#"{"missing":true}"#);
        missing_request.actor_id = None;
        missing_request.principal_kind = ApiPrincipalKind::Anonymous;
        missing_request.principal_scope = b"capacity-lock-test:anonymous";
        missing_request.capacity_scope = b"capacity-lock-test:anonymous";
        let error = acquire_idempotency_in_tx(&keys, &mut missing_authority, &missing_request)
            .await
            .expect_err("a missing capacity authority row must fail closed");
        assert!(
            error
                .to_string()
                .contains("API idempotency capacity authority row is missing"),
            "unexpected missing-authority error: {error:#}"
        );
        missing_authority.rollback().await.unwrap();
    }

    #[tokio::test]
    #[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
    async fn failed_login_penalty_and_replay_are_one_transaction() {
        use crate::abuse::{AbuseAction, AbuseConfig, AbuseGuard};
        use std::time::Duration;

        let url = std::env::var("TEST_DATABASE_URL")
            .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(4)
            .connect(&url)
            .await
            .unwrap();
        crate::db::migrate(&pool).await.unwrap();

        let keys = ApiControlKeyring::new(b"login-idempotency-secret-0000000001", None).unwrap();
        let guard = AbuseGuard::new_persistent(
            AbuseConfig {
                base_work_factor: 2,
                max_work_factor: 1_000_000,
                window: Duration::from_secs(300),
                cooldown_step: Duration::from_secs(60),
                max_wait: Duration::from_secs(8),
                message_free_burst: 5,
                approximate_max_device_seconds: 8,
            },
            pool.clone(),
            Some(b"login-abuse-state-secret-00000000001"),
            None,
        );
        let raw_body = br#"{"username":"missing","password":"wrong"}"#;
        let request = IdempotencyRequest {
            request_id: Uuid::new_v4(),
            actor_id: None,
            principal_scope: b"login:missing",
            capacity_scope: b"ip:192.0.2.7",
            target_scope: b"",
            principal_kind: ApiPrincipalKind::Anonymous,
            method: "POST",
            route: "/api/v1/login",
            idempotency_key: "failed-login-key-0001",
            request_fingerprint: api_request_fingerprint("application/json", raw_body),
            ttl_seconds: 3600,
            lease_seconds: 30,
        };
        let actors = vec!["ip:192.0.2.7".to_owned(), "account:missing".to_owned()];

        let mut reserve_tx = pool.begin().await.unwrap();
        let lease = acquired(
            acquire_idempotency_in_tx(&keys, &mut reserve_tx, &request)
                .await
                .unwrap(),
        );
        reserve_tx.commit().await.unwrap();

        // A backend failure after recording the penalty but before commit must
        // leave neither a penalty nor a terminal replay behind. The original
        // lease remains retryable with the same fencing token.
        let mut failed_tx = pool.begin().await.unwrap();
        assert!(resume_idempotency_lease_in_tx(&mut failed_tx, &lease, 30)
            .await
            .unwrap());
        guard
            .record_failure_in_tx(&mut failed_tx, AbuseAction::Login, &actors)
            .await
            .unwrap();
        assert!(
            mark_idempotency_guard_verified_in_tx(&mut failed_tx, &lease)
                .await
                .unwrap()
        );
        let mut headers = BTreeMap::new();
        headers.insert("content-type".to_owned(), "application/json".to_owned());
        headers.insert(
            "www-authenticate".to_owned(),
            "Bearer realm=\"northstar\"".to_owned(),
        );
        let body = br#"{"error":{"code":"unauthorized","message":"authentication required"}}"#;
        assert!(
            complete_idempotency_in_tx(&keys, &mut failed_tx, &lease, 401, &headers, body,)
                .await
                .unwrap()
        );
        failed_tx.rollback().await.unwrap();

        let (state, guard_verified): (String, bool) = sqlx::query_as(
            "SELECT state,guard_verified_at IS NOT NULL FROM api_idempotency_records WHERE id=$1",
        )
        .bind(lease.record_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(state, "started");
        assert!(!guard_verified);
        let rolled_back_events: i64 = sqlx::query_scalar(
            "SELECT COALESCE(SUM(cardinality(event_times)),0)::bigint FROM abuse_actor_states",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(rolled_back_events, 0);

        let mut retry_tx = pool.begin().await.unwrap();
        assert!(resume_idempotency_lease_in_tx(&mut retry_tx, &lease, 30)
            .await
            .unwrap());
        guard
            .record_failure_in_tx(&mut retry_tx, AbuseAction::Login, &actors)
            .await
            .unwrap();
        assert!(mark_idempotency_guard_verified_in_tx(&mut retry_tx, &lease)
            .await
            .unwrap());
        assert!(
            complete_idempotency_in_tx(&keys, &mut retry_tx, &lease, 401, &headers, body,)
                .await
                .unwrap()
        );
        retry_tx.commit().await.unwrap();

        let committed_events: i64 = sqlx::query_scalar(
            "SELECT COALESCE(SUM(cardinality(event_times)),0)::bigint FROM abuse_actor_states",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        // Login records both the account identity and the shared source-IP
        // signal. They are distinct bounded actor states, each advanced once.
        assert_eq!(committed_events, 2);
        let mut replay_tx = pool.begin().await.unwrap();
        let replay = match acquire_idempotency_in_tx(&keys, &mut replay_tx, &request)
            .await
            .unwrap()
        {
            IdempotencyAcquire::Replay(replay) => replay,
            other => panic!("expected terminal failed-login replay, got {other:?}"),
        };
        replay_tx.commit().await.unwrap();
        assert_eq!(replay.status, 401);
        assert_eq!(replay.headers, headers);
        assert_eq!(replay.body, body);
        let replay_events: i64 = sqlx::query_scalar(
            "SELECT COALESCE(SUM(cardinality(event_times)),0)::bigint FROM abuse_actor_states",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(replay_events, 2);

        pool.close().await;
    }

    #[tokio::test]
    #[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
    async fn yielded_lease_preserves_guard_marker_and_fences_old_worker() {
        let url = std::env::var("TEST_DATABASE_URL")
            .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(4)
            .connect(&url)
            .await
            .unwrap();
        crate::db::migrate(&pool).await.unwrap();

        let keys = ApiControlKeyring::new(b"yield-idempotency-key-00000000001", None).unwrap();
        let raw_body = br#"{"username":"yield-test","password":"not-persisted"}"#;
        let request = IdempotencyRequest {
            request_id: Uuid::new_v4(),
            actor_id: None,
            principal_scope: b"registration:192.0.2.40",
            capacity_scope: b"ip:192.0.2.40",
            target_scope: b"",
            principal_kind: ApiPrincipalKind::Anonymous,
            method: "POST",
            route: "/api/v1/register",
            idempotency_key: "yielded-registration-work-0001",
            request_fingerprint: api_request_fingerprint("application/json", raw_body),
            ttl_seconds: 3_600,
            lease_seconds: 30,
        };
        let mut reserve = pool.begin().await.unwrap();
        let lease = acquired(
            acquire_idempotency_in_tx(&keys, &mut reserve, &request)
                .await
                .unwrap(),
        );
        assert!(mark_idempotency_guard_verified_in_tx(&mut reserve, &lease)
            .await
            .unwrap());
        reserve.commit().await.unwrap();

        assert!(yield_idempotency_lease(&pool, &lease).await.unwrap());
        let mut stale = pool.begin().await.unwrap();
        assert!(!resume_idempotency_lease_in_tx(&mut stale, &lease, 30)
            .await
            .unwrap());
        stale.rollback().await.unwrap();

        let mut takeover = pool.begin().await.unwrap();
        let replacement = acquired(
            acquire_idempotency_in_tx(&keys, &mut takeover, &request)
                .await
                .unwrap(),
        );
        assert!(replacement.guard_verified);
        assert_ne!(replacement.lease_token(), lease.lease_token());
        takeover.rollback().await.unwrap();
    }

    #[tokio::test]
    #[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
    async fn postgres_idempotency_is_atomic_rotatable_and_tamper_evident() {
        let url = std::env::var("TEST_DATABASE_URL")
            .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(8)
            .connect(&url)
            .await
            .unwrap();
        crate::db::migrate(&pool).await.unwrap();
        crate::db::migrate(&pool).await.unwrap();
        let actor_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO users(id,username,password_hash) VALUES($1,$2,'test-only-invalid')",
        )
        .bind(actor_id)
        .bind(format!("api{}", &Uuid::new_v4().simple().to_string()[..12]))
        .execute(&pool)
        .await
        .unwrap();

        let old_secret = b"old-api-control-secret-000000000001";
        let new_secret = b"new-api-control-secret-000000000002";
        let old_keys = ApiControlKeyring::new(old_secret, None).unwrap();
        let raw_request = br#"{"username":"alice","password":"not-a-database-verifier"}"#;
        let fingerprint = api_request_fingerprint("application/json", raw_request);
        let make_request = |key: &'static str| IdempotencyRequest {
            request_id: Uuid::new_v4(),
            actor_id: Some(actor_id),
            principal_scope: actor_id.as_bytes(),
            capacity_scope: actor_id.as_bytes(),
            target_scope: b"",
            principal_kind: ApiPrincipalKind::Admin,
            method: "POST",
            route: "/api/v1/admin/example",
            idempotency_key: key,
            request_fingerprint: fingerprint,
            ttl_seconds: 3600,
            lease_seconds: 30,
        };

        // The idempotency reservation is part of the caller's transaction;
        // rolling the mutation back must not leave a phantom in-progress key.
        let mut rollback_tx = pool.begin().await.unwrap();
        assert!(matches!(
            acquire_idempotency_in_tx(
                &old_keys,
                &mut rollback_tx,
                &make_request("rollback-key-0001")
            )
            .await
            .unwrap(),
            IdempotencyAcquire::Acquired(_)
        ));
        rollback_tx.rollback().await.unwrap();
        let rollback_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM api_idempotency_records WHERE request_actor_id=$1",
        )
        .bind(actor_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(rollback_count, 0);

        let mut tx = pool.begin().await.unwrap();
        let lease =
            match acquire_idempotency_in_tx(&old_keys, &mut tx, &make_request("rotation-key-0001"))
                .await
                .unwrap()
            {
                IdempotencyAcquire::Acquired(lease) => lease,
                other => panic!("unexpected first acquire: {other:?}"),
            };
        let mut headers = BTreeMap::new();
        headers.insert("content-type".to_owned(), "application/json".to_owned());
        let response = br#"{"token":"only-visible-after-aead"}"#;
        assert!(
            complete_idempotency_in_tx(&old_keys, &mut tx, &lease, 201, &headers, response,)
                .await
                .unwrap()
        );
        tx.commit().await.unwrap();

        let raw_key_stored: bool = sqlx::query_scalar(
            "SELECT EXISTS(
                SELECT 1 FROM api_idempotency_records
                WHERE position($1::bytea in scope_hash) > 0
                   OR position($1::bytea in response_ciphertext) > 0
             )",
        )
        .bind(b"rotation-key-0001".as_slice())
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(!raw_key_stored);
        let plaintext_stored: bool = sqlx::query_scalar(
            "SELECT EXISTS(
                SELECT 1 FROM api_idempotency_records
                WHERE position($1::bytea in response_ciphertext) > 0
             )",
        )
        .bind(b"only-visible-after-aead".as_slice())
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(!plaintext_stored);
        let raw_fingerprint_stored: bool = sqlx::query_scalar(
            "SELECT EXISTS(
                SELECT 1 FROM api_idempotency_records
                WHERE request_fingerprint=$1
             )",
        )
        .bind(fingerprint.as_slice())
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(!raw_fingerprint_stored);

        // A rotating process recognizes the old scope HMAC, authenticates the
        // old replay, then atomically rewrites both scope and response under
        // the current key before returning it.
        let rotating_keys = ApiControlKeyring::new(new_secret, Some(old_secret)).unwrap();
        let mut rotate_tx = pool.begin().await.unwrap();
        let replay = match acquire_idempotency_in_tx(
            &rotating_keys,
            &mut rotate_tx,
            &make_request("rotation-key-0001"),
        )
        .await
        .unwrap()
        {
            IdempotencyAcquire::Replay(replay) => replay,
            other => panic!("unexpected rotating acquire: {other:?}"),
        };
        assert_eq!(replay.status, 201);
        assert_eq!(replay.headers, headers);
        assert_eq!(replay.body, response);
        rotate_tx.commit().await.unwrap();
        let (scope_key_id, response_key_id): (String, String) = sqlx::query_as(
            "SELECT scope_key_id,response_key_id FROM api_idempotency_records
             WHERE id=$1",
        )
        .bind(lease.record_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(scope_key_id, rotating_keys.current.id);
        assert_eq!(response_key_id, rotating_keys.current.id);
        let rotated_fingerprint: Vec<u8> = sqlx::query_scalar(
            "SELECT request_fingerprint FROM api_idempotency_records WHERE id=$1",
        )
        .bind(lease.record_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(
            rotated_fingerprint,
            rotating_keys
                .request_fingerprints(&make_request("rotation-key-0001"))
                .0
        );

        // Once rebound, removing the previous key cannot turn the same raw key
        // into a new mutation.
        let new_keys = ApiControlKeyring::new(new_secret, None).unwrap();
        let mut replay_tx = pool.begin().await.unwrap();
        assert!(matches!(
            acquire_idempotency_in_tx(
                &new_keys,
                &mut replay_tx,
                &make_request("rotation-key-0001")
            )
            .await
            .unwrap(),
            IdempotencyAcquire::Replay(_)
        ));
        replay_tx.commit().await.unwrap();

        let conflict_request = IdempotencyRequest {
            request_fingerprint: api_request_fingerprint(
                "application/json",
                br#"{"action":"different"}"#,
            ),
            ..make_request("rotation-key-0001")
        };
        let mut conflict_tx = pool.begin().await.unwrap();
        assert!(matches!(
            acquire_idempotency_in_tx(&new_keys, &mut conflict_tx, &conflict_request)
                .await
                .unwrap(),
            IdempotencyAcquire::FingerprintConflict
        ));
        conflict_tx.rollback().await.unwrap();

        let target_conflict_request = IdempotencyRequest {
            target_scope: b"report:00000000-0000-0000-0000-000000000001",
            ..make_request("rotation-key-0001")
        };
        let mut target_conflict_tx = pool.begin().await.unwrap();
        assert!(matches!(
            acquire_idempotency_in_tx(&new_keys, &mut target_conflict_tx, &target_conflict_request)
                .await
                .unwrap(),
            IdempotencyAcquire::FingerprintConflict
        ));
        target_conflict_tx.rollback().await.unwrap();

        // If an incorrectly staged rotation already created both HMAC rows,
        // fail closed instead of choosing either mutation/replay implicitly.
        for keys in [&old_keys, &new_keys] {
            let mut double_tx = pool.begin().await.unwrap();
            let double_lease = match acquire_idempotency_in_tx(
                keys,
                &mut double_tx,
                &make_request("double-row-key-0001"),
            )
            .await
            .unwrap()
            {
                IdempotencyAcquire::Acquired(lease) => lease,
                other => panic!("unexpected double-row setup: {other:?}"),
            };
            assert!(complete_idempotency_in_tx(
                keys,
                &mut double_tx,
                &double_lease,
                200,
                &headers,
                br#"{"ok":true}"#,
            )
            .await
            .unwrap());
            double_tx.commit().await.unwrap();
        }
        let mut double_tx = pool.begin().await.unwrap();
        assert!(matches!(
            acquire_idempotency_in_tx(
                &rotating_keys,
                &mut double_tx,
                &make_request("double-row-key-0001")
            )
            .await
            .unwrap(),
            IdempotencyAcquire::RotationConflict
        ));
        double_tx.rollback().await.unwrap();

        // Any database-side change to the encrypted headers/body bundle is
        // detected before a replay is returned.
        sqlx::query(
            "UPDATE api_idempotency_records
             SET response_ciphertext=set_byte(response_ciphertext,0,
                 get_byte(response_ciphertext,0) # 1)
             WHERE id=$1",
        )
        .bind(lease.record_id)
        .execute(&pool)
        .await
        .unwrap();
        let mut tamper_tx = pool.begin().await.unwrap();
        assert!(acquire_idempotency_in_tx(
            &new_keys,
            &mut tamper_tx,
            &make_request("rotation-key-0001")
        )
        .await
        .is_err());
        tamper_tx.rollback().await.unwrap();

        // Anonymous callers cannot fill PostgreSQL with random 24-hour
        // reservations. Distinct account scopes share the coarser capacity
        // scope, are serialized, and expire after five minutes unless they
        // complete.
        let capacity_scope = b"ip:198.51.100.44";
        for index in 0..MAX_STARTED_PER_PRINCIPAL {
            let key = format!("capacity-key-{index:04}");
            let principal = format!("login:198.51.100.44:account-{index}");
            let capacity_request = IdempotencyRequest {
                request_id: Uuid::new_v4(),
                actor_id: None,
                principal_scope: principal.as_bytes(),
                capacity_scope,
                target_scope: b"",
                principal_kind: ApiPrincipalKind::Anonymous,
                method: "POST",
                route: "/api/v1/login",
                idempotency_key: &key,
                request_fingerprint: fingerprint,
                ttl_seconds: 3600,
                lease_seconds: 180,
            };
            let mut capacity_tx = pool.begin().await.unwrap();
            assert!(matches!(
                acquire_idempotency_in_tx(&new_keys, &mut capacity_tx, &capacity_request)
                    .await
                    .unwrap(),
                IdempotencyAcquire::Acquired(_)
            ));
            capacity_tx.commit().await.unwrap();
        }
        let overflow_key = "capacity-overflow-key";
        let overflow_request = IdempotencyRequest {
            request_id: Uuid::new_v4(),
            actor_id: None,
            principal_scope: b"login:198.51.100.44:overflow",
            capacity_scope,
            target_scope: b"",
            principal_kind: ApiPrincipalKind::Anonymous,
            method: "POST",
            route: "/api/v1/login",
            idempotency_key: overflow_key,
            request_fingerprint: fingerprint,
            ttl_seconds: 3600,
            lease_seconds: 180,
        };
        let mut overflow_tx = pool.begin().await.unwrap();
        assert!(matches!(
            acquire_idempotency_in_tx(&new_keys, &mut overflow_tx, &overflow_request)
                .await
                .unwrap(),
            IdempotencyAcquire::CapacityLimited { .. }
        ));
        overflow_tx.rollback().await.unwrap();
        let maximum_started_lifetime: f64 = sqlx::query_scalar(
            "SELECT MAX(EXTRACT(EPOCH FROM (expires_at-created_at)))::double precision
             FROM api_idempotency_records WHERE state='started'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(maximum_started_lifetime <= 301.0);

        sqlx::query(
            "UPDATE api_idempotency_records
             SET created_at=clock_timestamp()-INTERVAL '10 minutes',
                 expires_at=clock_timestamp()-INTERVAL '1 second'
             WHERE state='started' AND ownership_actor_id IS NULL",
        )
        .execute(&pool)
        .await
        .unwrap();
        cleanup_expired_idempotency(&pool, 10_000).await.unwrap();

        // Successful anonymous registration/login records are rebound to an
        // authenticated owner and must not exhaust a shared-NAT IP quota.
        // They remain globally bounded and login sessions retain their own
        // independent 32-session account bound.
        for index in 0..1000 {
            let key = format!("owned-success-{index:04}");
            let principal = format!("registration:203.0.113.9:account-{index}");
            let owned_request = IdempotencyRequest {
                request_id: Uuid::new_v4(),
                actor_id: None,
                principal_scope: principal.as_bytes(),
                capacity_scope: b"ip:203.0.113.9",
                target_scope: b"",
                principal_kind: ApiPrincipalKind::Anonymous,
                method: "POST",
                route: "/api/v1/register",
                idempotency_key: &key,
                request_fingerprint: fingerprint,
                ttl_seconds: 3600,
                lease_seconds: 180,
            };
            let mut owned_tx = pool.begin().await.unwrap();
            let owned_lease =
                match acquire_idempotency_in_tx(&new_keys, &mut owned_tx, &owned_request)
                    .await
                    .unwrap()
                {
                    IdempotencyAcquire::Acquired(lease) => lease,
                    other => panic!("shared NAT success {index} was rejected: {other:?}"),
                };
            assert!(
                bind_idempotency_actor_in_tx(&mut owned_tx, &owned_lease, actor_id)
                    .await
                    .unwrap()
            );
            assert!(complete_idempotency_in_tx(
                &new_keys,
                &mut owned_tx,
                &owned_lease,
                201,
                &headers,
                br#"{"created":true}"#,
            )
            .await
            .unwrap());
            owned_tx.commit().await.unwrap();
        }

        // Completed public rejections stay replayable for only minutes and
        // still count against the anonymous principal's total hard bound.
        for index in 0..MAX_RECORDS_PER_PRINCIPAL {
            let key = format!("rejected-request-{index:04}");
            let rejected_request = IdempotencyRequest {
                request_id: Uuid::new_v4(),
                actor_id: None,
                principal_scope: b"registration:203.0.113.10",
                capacity_scope: b"ip:203.0.113.10",
                target_scope: b"",
                principal_kind: ApiPrincipalKind::Anonymous,
                method: "POST",
                route: "/api/v1/register",
                idempotency_key: &key,
                request_fingerprint: fingerprint,
                ttl_seconds: 3600,
                lease_seconds: 180,
            };
            let mut rejected_tx = pool.begin().await.unwrap();
            let rejected_lease =
                match acquire_idempotency_in_tx(&new_keys, &mut rejected_tx, &rejected_request)
                    .await
                    .unwrap()
                {
                    IdempotencyAcquire::Acquired(lease) => lease,
                    other => panic!("rejection setup {index} failed: {other:?}"),
                };
            assert!(complete_idempotency_in_tx(
                &new_keys,
                &mut rejected_tx,
                &rejected_lease,
                400,
                &headers,
                br#"{"rejected":true}"#,
            )
            .await
            .unwrap());
            rejected_tx.commit().await.unwrap();
        }
        let rejected_overflow_key = "rejected-request-overflow";
        let rejected_overflow = IdempotencyRequest {
            request_id: Uuid::new_v4(),
            actor_id: None,
            principal_scope: b"registration:203.0.113.10",
            capacity_scope: b"ip:203.0.113.10",
            target_scope: b"",
            principal_kind: ApiPrincipalKind::Anonymous,
            method: "POST",
            route: "/api/v1/register",
            idempotency_key: rejected_overflow_key,
            request_fingerprint: fingerprint,
            ttl_seconds: 3600,
            lease_seconds: 180,
        };
        let mut rejected_overflow_tx = pool.begin().await.unwrap();
        assert!(matches!(
            acquire_idempotency_in_tx(&new_keys, &mut rejected_overflow_tx, &rejected_overflow)
                .await
                .unwrap(),
            IdempotencyAcquire::CapacityLimited { .. }
        ));
        rejected_overflow_tx.rollback().await.unwrap();
        let maximum_rejection_lifetime: f64 = sqlx::query_scalar(
            "SELECT MAX(EXTRACT(EPOCH FROM (expires_at-completed_at)))::double precision
             FROM api_idempotency_records WHERE response_status >= 400",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(maximum_rejection_lifetime <= 301.0);

        let actual_records: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM api_idempotency_records")
                .fetch_one(&pool)
                .await
                .unwrap();
        let tracked_records: i64 = sqlx::query_scalar(
            "SELECT active_records FROM api_idempotency_capacity WHERE singleton=TRUE",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(tracked_records, actual_records);
        sqlx::query("UPDATE api_idempotency_capacity SET active_records=$1 WHERE singleton=TRUE")
            .bind(MAX_GLOBAL_RECORDS)
            .execute(&pool)
            .await
            .unwrap();
        let global_key = "global-waterline-key";
        let global_request = IdempotencyRequest {
            request_id: Uuid::new_v4(),
            actor_id: Some(actor_id),
            principal_scope: b"global-waterline-principal",
            capacity_scope: b"global-waterline-principal",
            target_scope: b"",
            principal_kind: ApiPrincipalKind::User,
            method: "POST",
            route: "/api/v1/example",
            idempotency_key: global_key,
            request_fingerprint: fingerprint,
            ttl_seconds: 3600,
            lease_seconds: 180,
        };
        let mut global_tx = pool.begin().await.unwrap();
        assert!(matches!(
            acquire_idempotency_in_tx(&new_keys, &mut global_tx, &global_request)
                .await
                .unwrap(),
            IdempotencyAcquire::CapacityLimited { .. }
        ));
        global_tx.rollback().await.unwrap();
        sqlx::query("UPDATE api_idempotency_capacity SET active_records=$1 WHERE singleton=TRUE")
            .bind(actual_records)
            .execute(&pool)
            .await
            .unwrap();

        // Lease fencing prevents a PASSWORD_WORK waiter whose bounded lease
        // expired from committing after a retry recovered the reservation.
        let stale_request = IdempotencyRequest {
            request_id: Uuid::new_v4(),
            actor_id: Some(actor_id),
            principal_scope: b"stale-worker-principal",
            capacity_scope: b"stale-worker-capacity",
            target_scope: b"",
            principal_kind: ApiPrincipalKind::Admin,
            method: "POST",
            route: "/api/v1/admin/example",
            idempotency_key: "stale-worker-key-0001",
            request_fingerprint: fingerprint,
            ttl_seconds: 3600,
            lease_seconds: 5,
        };
        let mut stale_tx = pool.begin().await.unwrap();
        let stale_lease = match acquire_idempotency_in_tx(&new_keys, &mut stale_tx, &stale_request)
            .await
            .unwrap()
        {
            IdempotencyAcquire::Acquired(lease) => lease,
            other => panic!("unexpected stale worker acquire: {other:?}"),
        };
        stale_tx.commit().await.unwrap();
        sqlx::query(
            "UPDATE api_idempotency_records
             SET lease_expires_at=clock_timestamp()-INTERVAL '1 second'
             WHERE id=$1",
        )
        .bind(stale_lease.record_id)
        .execute(&pool)
        .await
        .unwrap();
        let mut recovered_tx = pool.begin().await.unwrap();
        let recovered_lease =
            match acquire_idempotency_in_tx(&new_keys, &mut recovered_tx, &stale_request)
                .await
                .unwrap()
            {
                IdempotencyAcquire::Acquired(lease) => lease,
                other => panic!("unexpected recovered acquire: {other:?}"),
            };
        recovered_tx.commit().await.unwrap();
        let mut stale_commit_tx = pool.begin().await.unwrap();
        assert!(!complete_idempotency_in_tx(
            &new_keys,
            &mut stale_commit_tx,
            &stale_lease,
            200,
            &headers,
            br#"{"stale":true}"#,
        )
        .await
        .unwrap());
        stale_commit_tx.rollback().await.unwrap();
        let mut recovered_commit_tx = pool.begin().await.unwrap();
        assert!(complete_idempotency_in_tx(
            &new_keys,
            &mut recovered_commit_tx,
            &recovered_lease,
            200,
            &headers,
            br#"{"recovered":true}"#,
        )
        .await
        .unwrap());
        recovered_commit_tx.commit().await.unwrap();
    }

    #[tokio::test]
    #[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
    async fn concurrent_register_and_login_execute_once_per_idempotency_key() {
        let url = std::env::var("TEST_DATABASE_URL")
            .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(8)
            .connect(&url)
            .await
            .unwrap();
        crate::db::migrate(&pool).await.unwrap();
        crate::db::initialize_admin_runtime_settings(&pool, false, false, false)
            .await
            .unwrap();

        let suffix = Uuid::new_v4().simple().to_string();
        let username = format!("idem{}", &suffix[..10]);
        let password = "idempotent-registration-password";
        let invitation = format!("invite-{suffix}");
        let invitation_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO invitation_tokens
             (id,token_hash,label,max_uses) VALUES($1,$2,'idempotency-test',1)",
        )
        .bind(invitation_id)
        .bind(crate::auth::token_hash(&invitation))
        .execute(&pool)
        .await
        .unwrap();
        let prepared_a = crate::db::prepare_registration(
            &username,
            password,
            crate::auth::MIN_SCRAM_ITERATIONS,
            false,
        )
        .await
        .unwrap();
        let prepared_b = crate::db::prepare_registration(
            &username,
            password,
            crate::auth::MIN_SCRAM_ITERATIONS,
            false,
        )
        .await
        .unwrap();
        let register_fingerprint = api_request_fingerprint(
            "application/json",
            format!("{{\"username\":\"{username}\"}}").as_bytes(),
        );
        let register_once = |prepared: crate::db::PreparedRegistration| {
            let pool = pool.clone();
            let username = username.clone();
            let invitation = invitation.clone();
            async move {
                let keys =
                    ApiControlKeyring::new(b"route-integration-secret-0000000001", None).unwrap();
                let request = IdempotencyRequest {
                    request_id: Uuid::new_v4(),
                    actor_id: None,
                    principal_scope: b"registration:192.0.2.1",
                    capacity_scope: b"registration:192.0.2.1",
                    target_scope: b"",
                    principal_kind: ApiPrincipalKind::Anonymous,
                    method: "POST",
                    route: "/api/v1/register",
                    idempotency_key: "register-concurrent-key-0001",
                    request_fingerprint: register_fingerprint,
                    ttl_seconds: 3600,
                    lease_seconds: 30,
                };
                let mut prepared = Some(prepared);
                for attempt in 0..40 {
                    let mut tx = pool.begin().await.unwrap();
                    match acquire_idempotency_in_tx(&keys, &mut tx, &request)
                        .await
                        .unwrap()
                    {
                        IdempotencyAcquire::Acquired(lease) => {
                            let user = crate::db::create_user_with_invitation_in_tx(
                                &mut tx,
                                prepared
                                    .take()
                                    .expect("registration credentials were consumed twice"),
                                Some(&invitation),
                                true,
                                100,
                                Some(lease.request_id),
                            )
                            .await
                            .unwrap();
                            assert!(bind_idempotency_actor_in_tx(&mut tx, &lease, user.id)
                                .await
                                .unwrap());
                            let body = serde_json::to_vec(&serde_json::json!({
                                "jid": format!("{}@example.test", username)
                            }))
                            .unwrap();
                            let headers = BTreeMap::from([
                                ("cache-control".to_owned(), "no-store, max-age=0".to_owned()),
                                ("content-type".to_owned(), "application/json".to_owned()),
                            ]);
                            assert!(complete_idempotency_in_tx(
                                &keys, &mut tx, &lease, 201, &headers, &body
                            )
                            .await
                            .unwrap());
                            tx.commit().await.unwrap();
                            return (true, body);
                        }
                        IdempotencyAcquire::Replay(replay) => {
                            tx.commit().await.unwrap();
                            return (false, replay.body);
                        }
                        IdempotencyAcquire::Busy {
                            retry_after_seconds,
                        } => {
                            assert_eq!(retry_after_seconds, 1);
                            tx.rollback().await.unwrap();
                            assert!(attempt < 39, "registration admission stayed busy");
                            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
                        }
                        other => panic!("unexpected concurrent registration result: {other:?}"),
                    }
                }
                unreachable!("bounded registration retry loop returned no outcome")
            }
        };
        let (registered_a, registered_b) =
            tokio::join!(register_once(prepared_a), register_once(prepared_b));
        assert_eq!(usize::from(registered_a.0) + usize::from(registered_b.0), 1);
        assert_eq!(registered_a.1, registered_b.1);
        let user = crate::db::find_user(&pool, &username)
            .await
            .unwrap()
            .unwrap();
        let invitation_uses: i32 =
            sqlx::query_scalar("SELECT use_count FROM invitation_tokens WHERE id=$1")
                .bind(invitation_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(invitation_uses, 1);
        let registrations: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM audit_log
             WHERE actor_id=$1 AND action='user.register' AND request_id IS NOT NULL",
        )
        .bind(user.id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(registrations, 1);

        let prepared_login_a = crate::db::prepare_login(
            &pool,
            &username,
            password,
            crate::auth::MIN_SCRAM_ITERATIONS,
            false,
        )
        .await
        .unwrap()
        .unwrap();
        let prepared_login_b = crate::db::prepare_login(
            &pool,
            &username,
            password,
            crate::auth::MIN_SCRAM_ITERATIONS,
            false,
        )
        .await
        .unwrap()
        .unwrap();
        let login_fingerprint = api_request_fingerprint(
            "application/json",
            format!("{{\"username\":\"{username}\"}}").as_bytes(),
        );
        let login_once = |prepared: crate::db::PreparedLogin| {
            let pool = pool.clone();
            async move {
                let keys =
                    ApiControlKeyring::new(b"route-integration-secret-0000000001", None).unwrap();
                let request = IdempotencyRequest {
                    request_id: Uuid::new_v4(),
                    actor_id: None,
                    principal_scope: b"login:192.0.2.1:account-digest",
                    capacity_scope: b"ip:192.0.2.1",
                    target_scope: b"",
                    principal_kind: ApiPrincipalKind::Anonymous,
                    method: "POST",
                    route: "/api/v1/login",
                    idempotency_key: "login-concurrent-key-0000001",
                    request_fingerprint: login_fingerprint,
                    ttl_seconds: 3600,
                    lease_seconds: 30,
                };
                let mut prepared = Some(prepared);
                for attempt in 0..40 {
                    let mut tx = pool.begin().await.unwrap();
                    match acquire_idempotency_in_tx(&keys, &mut tx, &request)
                        .await
                        .unwrap()
                    {
                        IdempotencyAcquire::Acquired(lease) => {
                            assert!(crate::db::apply_prepared_login_in_tx(
                                &mut tx,
                                prepared
                                    .take()
                                    .expect("login credentials were consumed twice"),
                            )
                            .await
                            .unwrap());
                            assert!(bind_idempotency_actor_in_tx(&mut tx, &lease, user.id)
                                .await
                                .unwrap());
                            let session = crate::db::create_api_session_in_tx(
                                &mut tx,
                                user.id,
                                1,
                                Some(lease.request_id),
                            )
                            .await
                            .unwrap();
                            assert!(bind_idempotency_session_in_tx(
                                &mut tx,
                                &lease,
                                session.id,
                                &session.token_hash,
                                user.auth_generation,
                                session.expires_at,
                            )
                            .await
                            .unwrap());
                            let body =
                                serde_json::to_vec(&serde_json::json!({"token":session.token}))
                                    .unwrap();
                            let headers = BTreeMap::from([
                                ("cache-control".to_owned(), "no-store, max-age=0".to_owned()),
                                ("content-type".to_owned(), "application/json".to_owned()),
                            ]);
                            assert!(complete_idempotency_in_tx(
                                &keys, &mut tx, &lease, 200, &headers, &body
                            )
                            .await
                            .unwrap());
                            tx.commit().await.unwrap();
                            return (true, body);
                        }
                        IdempotencyAcquire::Replay(replay) => {
                            tx.commit().await.unwrap();
                            return (false, replay.body);
                        }
                        IdempotencyAcquire::Busy {
                            retry_after_seconds,
                        } => {
                            assert_eq!(retry_after_seconds, 1);
                            tx.rollback().await.unwrap();
                            assert!(attempt < 39, "login admission stayed busy");
                            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
                        }
                        other => panic!("unexpected concurrent login result: {other:?}"),
                    }
                }
                unreachable!("bounded login retry loop returned no outcome")
            }
        };
        let (login_a, login_b) =
            tokio::join!(login_once(prepared_login_a), login_once(prepared_login_b));
        assert_eq!(usize::from(login_a.0) + usize::from(login_b.0), 1);
        assert_eq!(login_a.1, login_b.1);
        let sessions: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM api_sessions WHERE user_id=$1")
                .bind(user.id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(sessions, 1);
        let login_audits: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM audit_log
             WHERE actor_id=$1 AND action='user.session.login' AND request_id IS NOT NULL",
        )
        .bind(user.id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(login_audits, 1);
        let replay_request = IdempotencyRequest {
            request_id: Uuid::new_v4(),
            actor_id: None,
            principal_scope: b"login:192.0.2.1:account-digest",
            capacity_scope: b"ip:192.0.2.1",
            target_scope: b"",
            principal_kind: ApiPrincipalKind::Anonymous,
            method: "POST",
            route: "/api/v1/login",
            idempotency_key: "login-concurrent-key-0000001",
            request_fingerprint: login_fingerprint,
            ttl_seconds: 3600,
            lease_seconds: 30,
        };
        let replay_keys =
            ApiControlKeyring::new(b"route-integration-secret-0000000001", None).unwrap();
        let mut valid_replay_tx = pool.begin().await.unwrap();
        assert!(matches!(
            acquire_idempotency_in_tx(&replay_keys, &mut valid_replay_tx, &replay_request)
                .await
                .unwrap(),
            IdempotencyAcquire::Replay(_)
        ));
        valid_replay_tx.commit().await.unwrap();
        let replay_outlives_session: bool = sqlx::query_scalar(
            "SELECT idem.expires_at > session.expires_at
             FROM api_idempotency_records idem
             JOIN api_sessions session ON session.id=idem.replay_session_id
             WHERE idem.request_id IN (
                SELECT request_id FROM audit_log
                WHERE actor_id=$1 AND action='user.session.login'
             )",
        )
        .bind(user.id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(!replay_outlives_session);
        sqlx::query("DELETE FROM api_sessions WHERE user_id=$1")
            .bind(user.id)
            .execute(&pool)
            .await
            .unwrap();
        let mut invalidated_tx = pool.begin().await.unwrap();
        assert!(matches!(
            acquire_idempotency_in_tx(&replay_keys, &mut invalidated_tx, &replay_request)
                .await
                .unwrap(),
            IdempotencyAcquire::ReplayInvalidated
        ));
        invalidated_tx.rollback().await.unwrap();

        // Registration and the durable control toggle serialize on the same
        // setting row. A close that begins while an admitted registration is
        // still uncommitted must wait, yielding a deterministic before/after
        // boundary rather than a one-second cache race.
        let race_name = format!("race{}", &suffix[..8]);
        let race_prepared = crate::db::prepare_registration(
            &race_name,
            "registration-toggle-race-password",
            crate::auth::MIN_SCRAM_ITERATIONS,
            false,
        )
        .await
        .unwrap();
        let race_keys =
            ApiControlKeyring::new(b"route-integration-secret-0000000001", None).unwrap();
        let race_request = IdempotencyRequest {
            request_id: Uuid::new_v4(),
            actor_id: None,
            principal_scope: b"registration:192.0.2.3",
            capacity_scope: b"registration:192.0.2.3",
            target_scope: b"",
            principal_kind: ApiPrincipalKind::Anonymous,
            method: "POST",
            route: "/api/v1/register",
            idempotency_key: "registration-toggle-race-0001",
            request_fingerprint: api_request_fingerprint("application/json", b"race"),
            ttl_seconds: 3600,
            lease_seconds: 30,
        };
        let mut race_tx = pool.begin().await.unwrap();
        let race_lease = match acquire_idempotency_in_tx(&race_keys, &mut race_tx, &race_request)
            .await
            .unwrap()
        {
            IdempotencyAcquire::Acquired(lease) => lease,
            other => panic!("unexpected toggle-race acquire: {other:?}"),
        };
        let race_user = crate::db::create_user_with_invitation_in_tx(
            &mut race_tx,
            race_prepared,
            None,
            false,
            100,
            Some(race_lease.request_id),
        )
        .await
        .unwrap();
        assert!(
            bind_idempotency_actor_in_tx(&mut race_tx, &race_lease, race_user.id)
                .await
                .unwrap()
        );
        let headers = BTreeMap::from([
            ("cache-control".to_owned(), "no-store, max-age=0".to_owned()),
            ("content-type".to_owned(), "application/json".to_owned()),
        ]);
        assert!(complete_idempotency_in_tx(
            &race_keys,
            &mut race_tx,
            &race_lease,
            201,
            &headers,
            br#"{"created":true}"#,
        )
        .await
        .unwrap());
        let close_pool = pool.clone();
        let close = tokio::spawn(async move {
            sqlx::query(
                "UPDATE admin_runtime_settings SET enabled=TRUE
                 WHERE key='registration_closed'",
            )
            .execute(&close_pool)
            .await
            .unwrap();
        });
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        assert!(!close.is_finished());
        race_tx.commit().await.unwrap();
        close.await.unwrap();
        assert!(crate::db::find_user(&pool, &race_name)
            .await
            .unwrap()
            .is_some());

        sqlx::query(
            "UPDATE admin_runtime_settings SET enabled=TRUE
             WHERE key='registration_closed'",
        )
        .execute(&pool)
        .await
        .unwrap();
        let blocked_name = format!("closed{}", &suffix[..8]);
        let blocked = crate::db::prepare_registration(
            &blocked_name,
            "closed-registration-password",
            crate::auth::MIN_SCRAM_ITERATIONS,
            false,
        )
        .await
        .unwrap();
        let mut blocked_tx = pool.begin().await.unwrap();
        let blocked_keys =
            ApiControlKeyring::new(b"route-integration-secret-0000000001", None).unwrap();
        let blocked_request = IdempotencyRequest {
            request_id: Uuid::new_v4(),
            actor_id: None,
            principal_scope: b"registration:192.0.2.2",
            capacity_scope: b"registration:192.0.2.2",
            target_scope: b"",
            principal_kind: ApiPrincipalKind::Anonymous,
            method: "POST",
            route: "/api/v1/register",
            idempotency_key: "closed-registration-key-0001",
            request_fingerprint: api_request_fingerprint("application/json", b"closed"),
            ttl_seconds: 3600,
            lease_seconds: 30,
        };
        assert!(matches!(
            acquire_idempotency_in_tx(&blocked_keys, &mut blocked_tx, &blocked_request)
                .await
                .unwrap(),
            IdempotencyAcquire::Acquired(_)
        ));
        assert!(matches!(
            crate::db::create_user_with_invitation_in_tx(
                &mut blocked_tx,
                blocked,
                None,
                false,
                100,
                Some(blocked_request.request_id),
            )
            .await,
            Err(crate::db::RegistrationError::Closed)
        ));
        blocked_tx.rollback().await.unwrap();
        assert!(crate::db::find_user(&pool, &blocked_name)
            .await
            .unwrap()
            .is_none());

        // Missing durable control state is database corruption, not an
        // implicit request to reopen public registration.
        sqlx::query("DELETE FROM admin_runtime_settings WHERE key='registration_closed'")
            .execute(&pool)
            .await
            .unwrap();
        let missing_name = format!("missing{}", &suffix[..7]);
        let missing = crate::db::create_user_with_invitation(
            &pool,
            &missing_name,
            "missing-control-row-password",
            None,
            false,
            100,
            crate::auth::MIN_SCRAM_ITERATIONS,
        )
        .await;
        assert!(matches!(
            missing,
            Err(crate::db::RegistrationError::Internal(_))
        ));
        assert!(crate::db::find_user(&pool, &missing_name)
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    #[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
    async fn admin_sync_mutations_are_authorized_atomic_replay_safe_and_queue_serialized() {
        let url = std::env::var("TEST_DATABASE_URL")
            .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(12)
            .connect(&url)
            .await
            .unwrap();
        crate::db::migrate(&pool).await.unwrap();
        crate::db::initialize_admin_runtime_settings(&pool, false, false, false)
            .await
            .unwrap();
        // A prior test may deliberately remove this fail-closed row.
        sqlx::query(
            "INSERT INTO admin_runtime_settings(key,enabled)
             VALUES('registration_closed',FALSE) ON CONFLICT(key) DO NOTHING",
        )
        .execute(&pool)
        .await
        .unwrap();

        let suffix = Uuid::new_v4().simple().to_string();
        let admin_id = Uuid::new_v4();
        let reporter_id = Uuid::new_v4();
        for (id, prefix, is_admin) in [
            (admin_id, "syncadmin", true),
            (reporter_id, "syncreporter", false),
        ] {
            sqlx::query(
                "INSERT INTO users(id,username,password_hash,is_admin)
                 VALUES($1,$2,'test-only-invalid',$3)",
            )
            .bind(id)
            .bind(format!("{prefix}-{}", &suffix[..10]))
            .bind(is_admin)
            .execute(&pool)
            .await
            .unwrap();
        }
        let admin_session = crate::db::create_api_session(&pool, admin_id, 1)
            .await
            .unwrap();
        let keys = ApiControlKeyring::new(b"admin-sync-api-control-key-000000001", None).unwrap();
        let headers = BTreeMap::from([
            ("cache-control".to_owned(), "no-store, max-age=0".to_owned()),
            ("content-type".to_owned(), "application/json".to_owned()),
        ]);

        // Registration toggle: bearer reauthorization, setting, audit and
        // replay response share one transaction and one request UUID.
        let close_body = br#"{"enabled":false}"#;
        let close_request = admin_request(
            &admin_id,
            "admin-registration-close-0001",
            b"registration_closed",
            "POST",
            "/api/v1/admin/registration",
            close_body,
        );
        let mut close_tx = pool.begin().await.unwrap();
        assert!(
            crate::db::authorize_admin_in_tx(&mut close_tx, admin_id, 0, &admin_session)
                .await
                .unwrap()
        );
        let close_lease = acquired(
            acquire_idempotency_in_tx(&keys, &mut close_tx, &close_request)
                .await
                .unwrap(),
        );
        let close_request_id = close_lease.request_id;
        crate::db::set_admin_runtime_setting_in_tx(
            &mut close_tx,
            admin_id,
            "registration_closed",
            true,
            Some(close_request_id),
        )
        .await
        .unwrap();
        assert!(complete_idempotency_in_tx(
            &keys,
            &mut close_tx,
            &close_lease,
            200,
            &headers,
            br#"{"open_registration":false}"#,
        )
        .await
        .unwrap());
        close_tx.commit().await.unwrap();
        assert!(sqlx::query_scalar::<_, bool>(
            "SELECT enabled FROM admin_runtime_settings WHERE key='registration_closed'"
        )
        .fetch_one(&pool)
        .await
        .unwrap());
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM audit_log
                 WHERE request_id=$1 AND action='admin.runtime_setting.set'"
            )
            .bind(close_request_id)
            .fetch_one(&pool)
            .await
            .unwrap(),
            1
        );
        let mut close_replay_tx = pool.begin().await.unwrap();
        assert!(crate::db::authorize_admin_in_tx(
            &mut close_replay_tx,
            admin_id,
            0,
            &admin_session
        )
        .await
        .unwrap());
        assert!(matches!(
            acquire_idempotency_in_tx(&keys, &mut close_replay_tx, &close_request)
                .await
                .unwrap(),
            IdempotencyAcquire::Replay(IdempotentResponse { status: 200, .. })
        ));
        close_replay_tx.commit().await.unwrap();

        // A later request reopens registration. Replaying the historical
        // close cannot mutate the durable setting again.
        let open_request = admin_request(
            &admin_id,
            "admin-registration-open-0002",
            b"registration_closed",
            "POST",
            "/api/v1/admin/registration",
            br#"{"enabled":true}"#,
        );
        let mut open_tx = pool.begin().await.unwrap();
        assert!(
            crate::db::authorize_admin_in_tx(&mut open_tx, admin_id, 0, &admin_session)
                .await
                .unwrap()
        );
        let open_lease = acquired(
            acquire_idempotency_in_tx(&keys, &mut open_tx, &open_request)
                .await
                .unwrap(),
        );
        crate::db::set_admin_runtime_setting_in_tx(
            &mut open_tx,
            admin_id,
            "registration_closed",
            false,
            Some(open_lease.request_id),
        )
        .await
        .unwrap();
        assert!(complete_idempotency_in_tx(
            &keys,
            &mut open_tx,
            &open_lease,
            200,
            &headers,
            br#"{"open_registration":true}"#,
        )
        .await
        .unwrap());
        open_tx.commit().await.unwrap();
        let mut historical_tx = pool.begin().await.unwrap();
        assert!(
            crate::db::authorize_admin_in_tx(&mut historical_tx, admin_id, 0, &admin_session)
                .await
                .unwrap()
        );
        assert!(matches!(
            acquire_idempotency_in_tx(&keys, &mut historical_tx, &close_request)
                .await
                .unwrap(),
            IdempotencyAcquire::Replay(_)
        ));
        historical_tx.commit().await.unwrap();
        assert!(!sqlx::query_scalar::<_, bool>(
            "SELECT enabled FROM admin_runtime_settings WHERE key='registration_closed'"
        )
        .fetch_one(&pool)
        .await
        .unwrap());

        // The raw invitation secret is only present in the AEAD response.
        // Its replay lifetime is capped by PostgreSQL's resource expiry and
        // every replay revalidates revocation and remaining uses.
        let invitation_id = Uuid::new_v4();
        let invitation_token = crate::auth::new_session_token();
        let invitation_body = serde_json::to_vec(&serde_json::json!({
            "id": invitation_id,
            "token": invitation_token,
            "shown_once": true
        }))
        .unwrap();
        let invite_request = admin_request(
            &admin_id,
            "admin-invitation-create-0001",
            b"invitation:create",
            "POST",
            "/api/v1/admin/invitations",
            br#"{"label":"integration","max_uses":2,"expires_in_hours":1}"#,
        );
        let mut invite_tx = pool.begin().await.unwrap();
        assert!(
            crate::db::authorize_admin_in_tx(&mut invite_tx, admin_id, 0, &admin_session)
                .await
                .unwrap()
        );
        let invite_lease = acquired(
            acquire_idempotency_in_tx(&keys, &mut invite_tx, &invite_request)
                .await
                .unwrap(),
        );
        let invite_request_id = invite_lease.request_id;
        crate::db::create_invitation_in_tx(
            &mut invite_tx,
            admin_id,
            invitation_id,
            &invitation_token,
            "integration",
            2,
            Some(1),
            Some(invite_request_id),
        )
        .await
        .unwrap();
        assert!(complete_idempotency_with_resource_in_tx(
            &keys,
            &mut invite_tx,
            &invite_lease,
            201,
            &headers,
            &invitation_body,
            Some(invitation_id),
        )
        .await
        .unwrap());
        invite_tx.commit().await.unwrap();
        let stored = sqlx::query(
            "SELECT response_ciphertext,expires_at,
                    (SELECT expires_at FROM invitation_tokens WHERE id=$1) AS invitation_expiry
             FROM api_idempotency_records WHERE request_id=$2",
        )
        .bind(invitation_id)
        .bind(invite_request_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        let ciphertext: Vec<u8> = stored.get("response_ciphertext");
        assert!(!ciphertext
            .windows(invitation_token.len())
            .any(|window| window == invitation_token.as_bytes()));
        assert!(
            stored.get::<DateTime<Utc>, _>("expires_at")
                <= stored.get::<DateTime<Utc>, _>("invitation_expiry")
        );
        let audit_details: serde_json::Value = sqlx::query_scalar(
            "SELECT details FROM audit_log
             WHERE request_id=$1 AND action='admin.invitation.create'",
        )
        .bind(invite_request_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(!audit_details.to_string().contains(&invitation_token));
        let mut invite_replay_tx = pool.begin().await.unwrap();
        assert!(crate::db::authorize_admin_in_tx(
            &mut invite_replay_tx,
            admin_id,
            0,
            &admin_session
        )
        .await
        .unwrap());
        match acquire_idempotency_in_tx(&keys, &mut invite_replay_tx, &invite_request)
            .await
            .unwrap()
        {
            IdempotencyAcquire::Replay(replay) => assert_eq!(replay.body, invitation_body),
            other => panic!("expected invitation replay, got {other:?}"),
        }
        invite_replay_tx.commit().await.unwrap();

        let revoke_request = admin_request(
            &admin_id,
            "admin-invitation-revoke-0001",
            invitation_id.as_bytes(),
            "DELETE",
            "/api/v1/admin/invitations/{id}",
            b"",
        );
        let mut revoke_tx = pool.begin().await.unwrap();
        assert!(
            crate::db::authorize_admin_in_tx(&mut revoke_tx, admin_id, 0, &admin_session)
                .await
                .unwrap()
        );
        let revoke_lease = acquired(
            acquire_idempotency_in_tx(&keys, &mut revoke_tx, &revoke_request)
                .await
                .unwrap(),
        );
        assert_eq!(
            crate::db::revoke_invitation_in_tx(
                &mut revoke_tx,
                admin_id,
                invitation_id,
                Some(revoke_lease.request_id),
            )
            .await
            .unwrap(),
            crate::db::InvitationRevokeOutcome::Revoked
        );
        assert!(complete_idempotency_in_tx(
            &keys,
            &mut revoke_tx,
            &revoke_lease,
            200,
            &headers,
            br#"{"revoked":true,"already_revoked":false}"#,
        )
        .await
        .unwrap());
        revoke_tx.commit().await.unwrap();
        let mut invalid_secret_replay_tx = pool.begin().await.unwrap();
        assert!(crate::db::authorize_admin_in_tx(
            &mut invalid_secret_replay_tx,
            admin_id,
            0,
            &admin_session
        )
        .await
        .unwrap());
        assert!(matches!(
            acquire_idempotency_in_tx(&keys, &mut invalid_secret_replay_tx, &invite_request)
                .await
                .unwrap(),
            IdempotencyAcquire::ReplayInvalidated
        ));
        invalid_secret_replay_tx.rollback().await.unwrap();
        sqlx::query(
            "UPDATE invitation_tokens
             SET revoked_at=NULL,expires_at=clock_timestamp()-INTERVAL '1 second'
             WHERE id=$1",
        )
        .bind(invitation_id)
        .execute(&pool)
        .await
        .unwrap();
        let mut expired_secret_replay_tx = pool.begin().await.unwrap();
        assert!(crate::db::authorize_admin_in_tx(
            &mut expired_secret_replay_tx,
            admin_id,
            0,
            &admin_session
        )
        .await
        .unwrap());
        assert!(matches!(
            acquire_idempotency_in_tx(&keys, &mut expired_secret_replay_tx, &invite_request)
                .await
                .unwrap(),
            IdempotencyAcquire::ReplayInvalidated
        ));
        expired_secret_replay_tx.rollback().await.unwrap();
        sqlx::query(
            "UPDATE invitation_tokens
             SET expires_at=clock_timestamp()+INTERVAL '1 hour',use_count=max_uses
             WHERE id=$1",
        )
        .bind(invitation_id)
        .execute(&pool)
        .await
        .unwrap();
        let mut exhausted_secret_replay_tx = pool.begin().await.unwrap();
        assert!(crate::db::authorize_admin_in_tx(
            &mut exhausted_secret_replay_tx,
            admin_id,
            0,
            &admin_session
        )
        .await
        .unwrap());
        assert!(matches!(
            acquire_idempotency_in_tx(&keys, &mut exhausted_secret_replay_tx, &invite_request)
                .await
                .unwrap(),
            IdempotencyAcquire::ReplayInvalidated
        ));
        exhausted_secret_replay_tx.rollback().await.unwrap();
        sqlx::query(
            "UPDATE invitation_tokens SET use_count=0,revoked_at=clock_timestamp() WHERE id=$1",
        )
        .bind(invitation_id)
        .execute(&pool)
        .await
        .unwrap();
        let second_revoke = admin_request(
            &admin_id,
            "admin-invitation-revoke-0002",
            invitation_id.as_bytes(),
            "DELETE",
            "/api/v1/admin/invitations/{id}",
            b"",
        );
        let mut second_revoke_tx = pool.begin().await.unwrap();
        assert!(crate::db::authorize_admin_in_tx(
            &mut second_revoke_tx,
            admin_id,
            0,
            &admin_session
        )
        .await
        .unwrap());
        let second_revoke_lease = acquired(
            acquire_idempotency_in_tx(&keys, &mut second_revoke_tx, &second_revoke)
                .await
                .unwrap(),
        );
        assert_eq!(
            crate::db::revoke_invitation_in_tx(
                &mut second_revoke_tx,
                admin_id,
                invitation_id,
                Some(second_revoke_lease.request_id),
            )
            .await
            .unwrap(),
            crate::db::InvitationRevokeOutcome::AlreadyRevoked
        );
        assert!(complete_idempotency_in_tx(
            &keys,
            &mut second_revoke_tx,
            &second_revoke_lease,
            200,
            &headers,
            br#"{"revoked":true,"already_revoked":true}"#,
        )
        .await
        .unwrap());
        second_revoke_tx.commit().await.unwrap();

        // Report and appeal updates use UUID-bound fingerprints, serialize
        // their rows, and keep the moderation audit in the same commit.
        let report_id = Uuid::new_v4();
        let appeal_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO abuse_reports(id,reporter_id,reported_jid,category)
             VALUES($1,$2,'peer@example.test','spam')",
        )
        .bind(report_id)
        .bind(reporter_id)
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO abuse_appeals(id,report_id,appellant_id,reason)
             VALUES($1,$2,$3,'sufficiently long test appeal reason')",
        )
        .bind(appeal_id)
        .bind(report_id)
        .bind(reporter_id)
        .execute(&pool)
        .await
        .unwrap();
        for (kind, id, route, key) in [
            (
                "report",
                report_id,
                "/api/v1/admin/reports/{id}",
                "admin-report-review-0001",
            ),
            (
                "appeal",
                appeal_id,
                "/api/v1/admin/appeals/{id}",
                "admin-appeal-review-0001",
            ),
        ] {
            let mutation = admin_request(
                &admin_id,
                key,
                id.as_bytes(),
                "PATCH",
                route,
                br#"{"status":"reviewing"}"#,
            );
            let mut tx = pool.begin().await.unwrap();
            assert!(
                crate::db::authorize_admin_in_tx(&mut tx, admin_id, 0, &admin_session)
                    .await
                    .unwrap()
            );
            let lease = acquired(
                acquire_idempotency_in_tx(&keys, &mut tx, &mutation)
                    .await
                    .unwrap(),
            );
            if kind == "report" {
                crate::db::admin_update_report_in_tx(
                    &mut tx,
                    id,
                    admin_id,
                    "reviewing",
                    "",
                    lease.request_id,
                )
                .await
                .unwrap();
            } else {
                crate::db::admin_update_appeal_in_tx(
                    &mut tx,
                    id,
                    admin_id,
                    "reviewing",
                    "",
                    lease.request_id,
                )
                .await
                .unwrap();
            }
            assert!(complete_idempotency_in_tx(
                &keys,
                &mut tx,
                &lease,
                200,
                &headers,
                br#"{"updated":true}"#,
            )
            .await
            .unwrap());
            tx.commit().await.unwrap();
            assert_eq!(
                sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM audit_log WHERE request_id=$1")
                    .bind(lease.request_id)
                    .fetch_one(&pool)
                    .await
                    .unwrap(),
                1
            );
            let mut replay_tx = pool.begin().await.unwrap();
            assert!(
                crate::db::authorize_admin_in_tx(&mut replay_tx, admin_id, 0, &admin_session)
                    .await
                    .unwrap()
            );
            assert!(matches!(
                acquire_idempotency_in_tx(&keys, &mut replay_tx, &mutation)
                    .await
                    .unwrap(),
                IdempotencyAcquire::Replay(_)
            ));
            replay_tx.commit().await.unwrap();
        }

        // Clear takes the exclusive queue gate. Enqueues already committed
        // are removed; a production enqueue beginning afterwards blocks and
        // then survives the completed clear snapshot.
        assert_eq!(
            crate::db::store_offline(
                &pool,
                reporter_id,
                "sender@example.test",
                "<message><body>before</body></message>",
                false,
                crate::db::OfflineStorePolicy {
                    max_messages: 100,
                    max_bytes: 1_000_000,
                    ttl_days: 30,
                    mam_backed: false,
                },
            )
            .await
            .unwrap(),
            crate::db::OfflineStoreOutcome::Stored
        );
        let clear_request = admin_request(
            &admin_id,
            "admin-offline-clear-0001",
            b"offline_messages",
            "DELETE",
            "/api/v1/admin/offline_messages",
            b"",
        );
        let mut clear_tx = pool.begin().await.unwrap();
        assert!(
            crate::db::authorize_admin_in_tx(&mut clear_tx, admin_id, 0, &admin_session)
                .await
                .unwrap()
        );
        let clear_lease = acquired(
            acquire_idempotency_in_tx(&keys, &mut clear_tx, &clear_request)
                .await
                .unwrap(),
        );
        assert_eq!(
            crate::db::clear_offline_messages_in_tx(
                &mut clear_tx,
                admin_id,
                Some(clear_lease.request_id),
            )
            .await
            .unwrap(),
            1
        );
        let enqueue_pool = pool.clone();
        let enqueue = tokio::spawn(async move {
            crate::db::store_offline(
                &enqueue_pool,
                reporter_id,
                "sender@example.test",
                "<message><body>after</body></message>",
                false,
                crate::db::OfflineStorePolicy {
                    max_messages: 100,
                    max_bytes: 1_000_000,
                    ttl_days: 30,
                    mam_backed: false,
                },
            )
            .await
        });
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        assert!(!enqueue.is_finished());
        assert!(complete_idempotency_in_tx(
            &keys,
            &mut clear_tx,
            &clear_lease,
            200,
            &headers,
            br#"{"cleared":true,"removed":1}"#,
        )
        .await
        .unwrap());
        clear_tx.commit().await.unwrap();
        assert_eq!(
            enqueue.await.unwrap().unwrap(),
            crate::db::OfflineStoreOutcome::Stored
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM offline_messages")
                .fetch_one(&pool)
                .await
                .unwrap(),
            1
        );
        let mut clear_replay_tx = pool.begin().await.unwrap();
        assert!(crate::db::authorize_admin_in_tx(
            &mut clear_replay_tx,
            admin_id,
            0,
            &admin_session
        )
        .await
        .unwrap());
        assert!(matches!(
            acquire_idempotency_in_tx(&keys, &mut clear_replay_tx, &clear_request)
                .await
                .unwrap(),
            IdempotencyAcquire::Replay(_)
        ));
        clear_replay_tx.commit().await.unwrap();
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM offline_messages")
                .fetch_one(&pool)
                .await
                .unwrap(),
            1
        );

        // Demotion after completion denies access before an encrypted replay
        // can be inspected. The idempotency row remains untouched.
        sqlx::query("UPDATE users SET is_admin=FALSE WHERE id=$1")
            .bind(admin_id)
            .execute(&pool)
            .await
            .unwrap();
        let mut denied_tx = pool.begin().await.unwrap();
        assert!(
            !crate::db::authorize_admin_in_tx(&mut denied_tx, admin_id, 0, &admin_session)
                .await
                .unwrap()
        );
        denied_tx.rollback().await.unwrap();
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM audit_log WHERE request_id=$1
                 AND action='admin.offline_messages.clear'"
            )
            .bind(clear_lease.request_id)
            .fetch_one(&pool)
            .await
            .unwrap(),
            1
        );

        pool.close().await;
    }
}
