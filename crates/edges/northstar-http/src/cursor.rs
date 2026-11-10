//! Versioned, opaque and scope-bound REST collection cursors.
//!
//! The token carries no bearer credential or raw principal/filter value. Those
//! values are reduced to keyed digests and checked again when the cursor is
//! consumed. Callers supply the current time explicitly; production code must
//! obtain it from PostgreSQL's `clock_timestamp()` in the pagination request,
//! rather than from a node's wall clock. HMAC-tag and keyed-scope-digest byte
//! comparisons use constant-time primitives. Token parsing, public metadata
//! comparisons, expiry checks, and selection between the two public key IDs do
//! not; none of those operations compares a secret value.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use uuid::Uuid;
use zeroize::Zeroize;

type HmacSha256 = Hmac<Sha256>;

const MAGIC: &[u8; 4] = b"NSC1";
const VERSION: u8 = 1;
const TAG_BYTES: usize = 32;
const MAX_TOKEN_BYTES: usize = 2_048;
const MAX_ENDPOINT_BYTES: usize = 128;
const MAX_SORT_BYTES: usize = 64;
const MAX_SCOPE_BYTES: usize = 4_096;
// Governance exports carry an export/snapshot key, a three-column keyset and
// the running SHA-256 chain root. Keep this bounded even though the signed
// token still has substantial room under MAX_TOKEN_BYTES.
const MAX_LAST_VALUES: usize = 8;
const MIN_TTL_SECONDS: i64 = 30;
const MAX_TTL_SECONDS: i64 = 86_400;
const MAX_FUTURE_SKEW_SECONDS: i64 = 60;

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum CursorInvalid {
    /// Deliberately does not reveal whether syntax, signature, expiry or scope
    /// caused rejection.
    #[error("cursor is invalid or expired")]
    Invalid,
}

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum CursorIssueError {
    #[error("cursor key material is invalid")]
    Key,
    #[error("cursor binding is invalid")]
    Binding,
    #[error("cursor lifetime is invalid")]
    Lifetime,
    #[error("cursor position is invalid")]
    Position,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CursorDirection {
    Forward,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CursorValue {
    I64(i64),
    U64(u64),
    TimestampMicros(i64),
    Uuid(Uuid),
    Digest32([u8; 32]),
}

/// Request-specific values that must match before a cursor can be used.
/// `principal_scope` should be a stable account/admin identity, never a bearer
/// token. `filter_scope` is a canonical encoding of all visibility filters.
pub struct CursorBinding<'a> {
    pub endpoint: &'a str,
    pub principal_scope: &'a [u8],
    pub filter_scope: &'a [u8],
    pub sort: &'a str,
    pub direction: CursorDirection,
    pub node_incarnation: Uuid,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CursorPosition {
    pub last: Vec<CursorValue>,
}

impl CursorPosition {
    /// Decode the only position shape used by the descending REST keyset
    /// pages. A signed cursor with another shape is still invalid for those
    /// endpoints, even if it was issued by another internal caller.
    pub fn descending_timestamp_uuid(&self) -> Result<(i64, Uuid), CursorInvalid> {
        match self.last.as_slice() {
            [CursorValue::TimestampMicros(created_at), CursorValue::Uuid(id)]
                if valid_timestamp_micros(*created_at) =>
            {
                Ok((*created_at, *id))
            }
            _ => Err(CursorInvalid::Invalid),
        }
    }
}

/// Ambiguity-free canonical input for `filter_scope` (and, when useful, a
/// compound principal scope). Lowercase ASCII labels must be appended in
/// strictly increasing byte order; duplicates and caller-dependent ordering
/// are rejected. Each label and value is length-prefixed, so absent, empty and
/// concatenated values cannot collide.
#[derive(Default)]
pub struct CanonicalScope {
    bytes: Vec<u8>,
    last_label: Option<String>,
}

impl CanonicalScope {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn field(mut self, label: &str, value: Option<&[u8]>) -> Result<Self, CursorIssueError> {
        if !valid_scope_label(label)
            || self
                .last_label
                .as_deref()
                .is_some_and(|previous| previous >= label)
        {
            return Err(CursorIssueError::Binding);
        }
        let value_len = value.map_or(0, <[u8]>::len);
        let added = 2_usize
            .checked_add(label.len())
            .and_then(|size| size.checked_add(1))
            .and_then(|size| size.checked_add(4))
            .and_then(|size| size.checked_add(value_len))
            .ok_or(CursorIssueError::Binding)?;
        if self.bytes.len().saturating_add(added) > MAX_SCOPE_BYTES {
            return Err(CursorIssueError::Binding);
        }
        self.bytes
            .extend_from_slice(&(label.len() as u16).to_be_bytes());
        self.bytes.extend_from_slice(label.as_bytes());
        self.bytes.push(u8::from(value.is_some()));
        self.bytes
            .extend_from_slice(&(value_len as u32).to_be_bytes());
        if let Some(value) = value {
            self.bytes.extend_from_slice(value);
        }
        self.last_label = Some(label.to_owned());
        Ok(self)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

struct CursorKey {
    id: [u8; 8],
    signing: [u8; 32],
    scope: [u8; 32],
}

impl Drop for CursorKey {
    fn drop(&mut self) {
        self.signing.zeroize();
        self.scope.zeroize();
    }
}

pub struct CursorKeyring {
    current: CursorKey,
    previous: Option<CursorKey>,
}

impl CursorKeyring {
    pub fn new(
        current_secret: &[u8],
        previous_secret: Option<&[u8]>,
    ) -> Result<Self, CursorIssueError> {
        let current = CursorKey::derive(current_secret)?;
        let previous = previous_secret.map(CursorKey::derive).transpose()?;
        if previous.as_ref().is_some_and(|old| old.id == current.id) {
            return Err(CursorIssueError::Key);
        }
        Ok(Self { current, previous })
    }

    pub fn issue(
        &self,
        binding: &CursorBinding<'_>,
        position: &CursorPosition,
        issued_at_unix: i64,
        ttl_seconds: i64,
    ) -> Result<String, CursorIssueError> {
        validate_binding(binding)?;
        validate_position(position)?;
        if !(MIN_TTL_SECONDS..=MAX_TTL_SECONDS).contains(&ttl_seconds) {
            return Err(CursorIssueError::Lifetime);
        }
        let expires_at = issued_at_unix
            .checked_add(ttl_seconds)
            .ok_or(CursorIssueError::Lifetime)?;
        let payload = encode_payload(&self.current, binding, position, issued_at_unix, expires_at);
        let tag = sign(&self.current.signing, &payload);
        let mut token = Vec::with_capacity(payload.len() + TAG_BYTES);
        token.extend_from_slice(&payload);
        token.extend_from_slice(&tag);
        if token.len() > MAX_TOKEN_BYTES {
            return Err(CursorIssueError::Position);
        }
        Ok(URL_SAFE_NO_PAD.encode(token))
    }

    pub fn verify(
        &self,
        token: &str,
        binding: &CursorBinding<'_>,
        now_unix: i64,
    ) -> Result<CursorPosition, CursorInvalid> {
        if token.is_empty() || token.len() > encoded_max_len() || !token.is_ascii() {
            return Err(CursorInvalid::Invalid);
        }
        let decoded = URL_SAFE_NO_PAD
            .decode(token)
            .map_err(|_| CursorInvalid::Invalid)?;
        if decoded.len() <= TAG_BYTES || decoded.len() > MAX_TOKEN_BYTES {
            return Err(CursorInvalid::Invalid);
        }
        let (payload, supplied_tag) = decoded.split_at(decoded.len() - TAG_BYTES);
        let key_id = payload.get(5..13).ok_or(CursorInvalid::Invalid)?;
        let key = self
            .keys()
            .find(|key| bool::from(key.id.as_slice().ct_eq(key_id)))
            .ok_or(CursorInvalid::Invalid)?;
        let expected_tag = sign(&key.signing, payload);
        if !bool::from(expected_tag.as_slice().ct_eq(supplied_tag)) {
            return Err(CursorInvalid::Invalid);
        }
        validate_binding(binding).map_err(|_| CursorInvalid::Invalid)?;
        decode_and_validate_payload(key, payload, binding, now_unix)
    }

    fn keys(&self) -> impl Iterator<Item = &CursorKey> {
        std::iter::once(&self.current).chain(self.previous.iter())
    }
}

impl CursorKey {
    fn derive(secret: &[u8]) -> Result<Self, CursorIssueError> {
        if !(32..=4_096).contains(&secret.len()) || secret.contains(&0) {
            return Err(CursorIssueError::Key);
        }
        let signing = derive(secret, b"northstar/api-cursor/signing/v1");
        let scope = derive(secret, b"northstar/api-cursor/scope/v1");
        let digest = Sha256::digest(
            [
                b"northstar/api-cursor/key-id/v1\0".as_slice(),
                signing.as_slice(),
            ]
            .concat(),
        );
        let mut id = [0_u8; 8];
        id.copy_from_slice(&digest[..8]);
        Ok(Self { id, signing, scope })
    }
}

fn derive(secret: &[u8], label: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts every key length");
    mac.update(label);
    mac.finalize().into_bytes().into()
}

fn sign(key: &[u8; 32], payload: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts a 32-byte key");
    mac.update(payload);
    mac.finalize().into_bytes().into()
}

fn scope_digest(key: &CursorKey, label: &[u8], value: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(&key.scope).expect("HMAC accepts a 32-byte key");
    mac.update(label);
    mac.update(&(value.len() as u64).to_be_bytes());
    mac.update(value);
    mac.finalize().into_bytes().into()
}

fn validate_binding(binding: &CursorBinding<'_>) -> Result<(), CursorIssueError> {
    if !valid_identifier(binding.endpoint, MAX_ENDPOINT_BYTES)
        || !valid_identifier(binding.sort, MAX_SORT_BYTES)
        || binding.principal_scope.is_empty()
        || binding.principal_scope.len() > MAX_SCOPE_BYTES
        || binding.filter_scope.len() > MAX_SCOPE_BYTES
    {
        return Err(CursorIssueError::Binding);
    }
    Ok(())
}

fn valid_identifier(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'_' | b'-' | b'.'))
}

fn valid_scope_label(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-' | b'.')
        })
}

fn validate_position(position: &CursorPosition) -> Result<(), CursorIssueError> {
    if position.last.is_empty() || position.last.len() > MAX_LAST_VALUES {
        return Err(CursorIssueError::Position);
    }
    if position.last.iter().any(|value| {
        matches!(value, CursorValue::TimestampMicros(micros) if !valid_timestamp_micros(*micros))
    }) {
        return Err(CursorIssueError::Position);
    }
    Ok(())
}

fn valid_timestamp_micros(value: i64) -> bool {
    DateTime::<Utc>::from_timestamp_micros(value).is_some()
}

fn encode_payload(
    key: &CursorKey,
    binding: &CursorBinding<'_>,
    position: &CursorPosition,
    issued_at: i64,
    expires_at: i64,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(256);
    out.extend_from_slice(MAGIC);
    out.push(VERSION);
    out.extend_from_slice(&key.id);
    push_short(&mut out, binding.endpoint.as_bytes());
    out.extend_from_slice(&scope_digest(key, b"principal\0", binding.principal_scope));
    out.extend_from_slice(&scope_digest(key, b"filter\0", binding.filter_scope));
    push_short(&mut out, binding.sort.as_bytes());
    out.push(match binding.direction {
        CursorDirection::Forward => 0,
    });
    out.extend_from_slice(binding.node_incarnation.as_bytes());
    out.extend_from_slice(&issued_at.to_be_bytes());
    out.extend_from_slice(&expires_at.to_be_bytes());
    out.push(position.last.len() as u8);
    for value in &position.last {
        match value {
            CursorValue::I64(value) => {
                out.push(1);
                out.extend_from_slice(&value.to_be_bytes());
            }
            CursorValue::U64(value) => {
                out.push(2);
                out.extend_from_slice(&value.to_be_bytes());
            }
            CursorValue::TimestampMicros(value) => {
                out.push(3);
                out.extend_from_slice(&value.to_be_bytes());
            }
            CursorValue::Uuid(value) => {
                out.push(4);
                out.extend_from_slice(value.as_bytes());
            }
            CursorValue::Digest32(value) => {
                out.push(5);
                out.extend_from_slice(value);
            }
        }
    }
    out
}

fn decode_and_validate_payload(
    key: &CursorKey,
    payload: &[u8],
    binding: &CursorBinding<'_>,
    now: i64,
) -> Result<CursorPosition, CursorInvalid> {
    let mut reader = Reader::new(payload);
    if reader.take(4)? != MAGIC || reader.byte()? != VERSION || reader.take(8)? != key.id {
        return Err(CursorInvalid::Invalid);
    }
    let endpoint = reader.short()?;
    let principal = reader.take(32)?;
    let filter = reader.take(32)?;
    let sort = reader.short()?;
    let direction = reader.byte()?;
    let incarnation = reader.take(16)?;
    let issued_at = reader.i64()?;
    let expires_at = reader.i64()?;
    let count = usize::from(reader.byte()?);
    if count == 0 || count > MAX_LAST_VALUES {
        return Err(CursorInvalid::Invalid);
    }
    let mut last = Vec::with_capacity(count);
    for _ in 0..count {
        last.push(match reader.byte()? {
            1 => CursorValue::I64(reader.i64()?),
            2 => CursorValue::U64(reader.u64()?),
            3 => {
                let value = reader.i64()?;
                if !valid_timestamp_micros(value) {
                    return Err(CursorInvalid::Invalid);
                }
                CursorValue::TimestampMicros(value)
            }
            4 => CursorValue::Uuid(
                Uuid::from_slice(reader.take(16)?).map_err(|_| CursorInvalid::Invalid)?,
            ),
            5 => CursorValue::Digest32(
                reader
                    .take(32)?
                    .try_into()
                    .map_err(|_| CursorInvalid::Invalid)?,
            ),
            _ => return Err(CursorInvalid::Invalid),
        });
    }
    if !reader.finished()
        || endpoint != binding.endpoint.as_bytes()
        || sort != binding.sort.as_bytes()
        || direction
            != match binding.direction {
                CursorDirection::Forward => 0,
            }
        || incarnation != binding.node_incarnation.as_bytes()
        || !bool::from(principal.ct_eq(&scope_digest(key, b"principal\0", binding.principal_scope)))
        || !bool::from(filter.ct_eq(&scope_digest(key, b"filter\0", binding.filter_scope)))
        || expires_at <= issued_at
        || expires_at - issued_at > MAX_TTL_SECONDS
        || issued_at > now.saturating_add(MAX_FUTURE_SKEW_SECONDS)
        || now >= expires_at
    {
        return Err(CursorInvalid::Invalid);
    }
    Ok(CursorPosition { last })
}

fn push_short(out: &mut Vec<u8>, value: &[u8]) {
    out.extend_from_slice(&(value.len() as u16).to_be_bytes());
    out.extend_from_slice(value);
}

fn encoded_max_len() -> usize {
    MAX_TOKEN_BYTES.div_ceil(3) * 4
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], CursorInvalid> {
        let end = self.offset.checked_add(len).ok_or(CursorInvalid::Invalid)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(CursorInvalid::Invalid)?;
        self.offset = end;
        Ok(value)
    }

    fn byte(&mut self) -> Result<u8, CursorInvalid> {
        Ok(self.take(1)?[0])
    }

    fn short(&mut self) -> Result<&'a [u8], CursorInvalid> {
        let len = u16::from_be_bytes(
            self.take(2)?
                .try_into()
                .map_err(|_| CursorInvalid::Invalid)?,
        );
        self.take(usize::from(len))
    }

    fn i64(&mut self) -> Result<i64, CursorInvalid> {
        Ok(i64::from_be_bytes(
            self.take(8)?
                .try_into()
                .map_err(|_| CursorInvalid::Invalid)?,
        ))
    }

    fn u64(&mut self) -> Result<u64, CursorInvalid> {
        Ok(u64::from_be_bytes(
            self.take(8)?
                .try_into()
                .map_err(|_| CursorInvalid::Invalid)?,
        ))
    }

    fn finished(&self) -> bool {
        self.offset == self.bytes.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CURRENT: &[u8] = b"cursor-current-secret-with-at-least-32-bytes";
    const PREVIOUS: &[u8] = b"cursor-previous-secret-with-at-least-32-bytes";

    fn binding<'a>(principal: &'a [u8], filter: &'a [u8]) -> CursorBinding<'a> {
        CursorBinding {
            endpoint: "admin/users",
            principal_scope: principal,
            filter_scope: filter,
            sort: "created_at-id",
            direction: CursorDirection::Forward,
            node_incarnation: Uuid::from_u128(7),
        }
    }

    fn position() -> CursorPosition {
        CursorPosition {
            last: vec![
                CursorValue::TimestampMicros(1_700_000_000_123_456),
                CursorValue::Uuid(Uuid::from_u128(99)),
            ],
        }
    }

    #[test]
    fn round_trip_and_rotation_overlap() {
        let old = CursorKeyring::new(PREVIOUS, None).unwrap();
        let token = old
            .issue(
                &binding(b"admin-1", b"enabled=true"),
                &position(),
                1_000,
                300,
            )
            .unwrap();
        let rotating = CursorKeyring::new(CURRENT, Some(PREVIOUS)).unwrap();
        assert_eq!(
            rotating
                .verify(&token, &binding(b"admin-1", b"enabled=true"), 1_100)
                .unwrap(),
            position()
        );
        assert_eq!(
            CursorKeyring::new(CURRENT, None).unwrap().verify(
                &token,
                &binding(b"admin-1", b"enabled=true"),
                1_100
            ),
            Err(CursorInvalid::Invalid)
        );
    }

    #[test]
    fn tamper_expiry_and_every_scope_mismatch_are_indistinguishable() {
        let keys = CursorKeyring::new(CURRENT, None).unwrap();
        let expected = binding(b"user-1", b"status=open");
        let token = keys.issue(&expected, &position(), 5_000, 60).unwrap();
        let mut raw = URL_SAFE_NO_PAD.decode(&token).unwrap();
        raw[20] ^= 1;
        let tampered = URL_SAFE_NO_PAD.encode(raw);
        assert_eq!(
            keys.verify(&tampered, &expected, 5_010),
            Err(CursorInvalid::Invalid)
        );
        assert_eq!(
            keys.verify(&token, &expected, 5_060),
            Err(CursorInvalid::Invalid)
        );
        assert_eq!(
            keys.verify(&token, &binding(b"user-2", b"status=open"), 5_010),
            Err(CursorInvalid::Invalid)
        );
        assert_eq!(
            keys.verify(&token, &binding(b"user-1", b"status=closed"), 5_010),
            Err(CursorInvalid::Invalid)
        );
        let mut other = binding(b"user-1", b"status=open");
        other.endpoint = "admin/reports";
        assert_eq!(
            keys.verify(&token, &other, 5_010),
            Err(CursorInvalid::Invalid)
        );
        let mut other = binding(b"user-1", b"status=open");
        other.node_incarnation = Uuid::from_u128(8);
        assert_eq!(
            keys.verify(&token, &other, 5_010),
            Err(CursorInvalid::Invalid)
        );
    }

    #[test]
    fn malformed_and_resource_exhaustion_inputs_fail_closed() {
        let keys = CursorKeyring::new(CURRENT, None).unwrap();
        let expected = binding(b"user", b"");
        for token in ["", "%%%", &"A".repeat(encoded_max_len() + 1)] {
            assert_eq!(
                keys.verify(token, &expected, 0),
                Err(CursorInvalid::Invalid)
            );
        }
        let oversized_scope = vec![0_u8; MAX_SCOPE_BYTES + 1];
        assert_eq!(
            keys.issue(&binding(&oversized_scope, b""), &position(), 0, 60),
            Err(CursorIssueError::Binding)
        );
        assert_eq!(
            keys.issue(&expected, &CursorPosition { last: vec![] }, 0, 60),
            Err(CursorIssueError::Position)
        );

        let valid = keys.issue(&expected, &position(), 1_000, 60).unwrap();
        let raw = URL_SAFE_NO_PAD.decode(valid).unwrap();
        for length in 0..raw.len() {
            assert_eq!(
                keys.verify(&URL_SAFE_NO_PAD.encode(&raw[..length]), &expected, 1_001),
                Err(CursorInvalid::Invalid)
            );
        }

        // A compromised/internal signer cannot smuggle an out-of-range chrono
        // timestamp through the public page-position decoder.
        let invalid_position = CursorPosition {
            last: vec![
                CursorValue::TimestampMicros(i64::MAX),
                CursorValue::Uuid(Uuid::new_v4()),
            ],
        };
        let payload = encode_payload(&keys.current, &expected, &invalid_position, 1_000, 1_060);
        let mut signed = payload.clone();
        signed.extend_from_slice(&sign(&keys.current.signing, &payload));
        assert_eq!(
            keys.verify(&URL_SAFE_NO_PAD.encode(signed), &expected, 1_001),
            Err(CursorInvalid::Invalid)
        );
    }

    #[test]
    fn identifiers_are_ascii_canonical_and_private_values_are_not_embedded() {
        let keys = CursorKeyring::new(CURRENT, None).unwrap();
        let private_principal = b"alice@example.test";
        let private_filter = b"reported_jid=bob@example.test";
        let token = keys
            .issue(
                &binding(private_principal, private_filter),
                &position(),
                1_000,
                60,
            )
            .unwrap();
        let raw = URL_SAFE_NO_PAD.decode(token).unwrap();
        assert!(!raw
            .windows(private_principal.len())
            .any(|w| w == private_principal));
        assert!(!raw
            .windows(private_filter.len())
            .any(|w| w == private_filter));
        let mut unicode = binding(b"user", b"");
        unicode.endpoint = "管理/users";
        assert_eq!(
            keys.issue(&unicode, &position(), 0, 60),
            Err(CursorIssueError::Binding)
        );
    }

    #[test]
    fn canonical_scopes_distinguish_absent_empty_and_field_boundaries() {
        let absent = CanonicalScope::new().field("status", None).unwrap();
        let empty = CanonicalScope::new().field("status", Some(b"")).unwrap();
        let split = CanonicalScope::new()
            .field("a", Some(b"bc"))
            .unwrap()
            .field("d", Some(b"e"))
            .unwrap();
        let joined = CanonicalScope::new()
            .field("a", Some(b"b"))
            .unwrap()
            .field("c", Some(b"de"))
            .unwrap();
        assert_ne!(absent.as_bytes(), empty.as_bytes());
        assert_ne!(split.as_bytes(), joined.as_bytes());
        assert!(CanonicalScope::new()
            .field("status", Some(b"open"))
            .unwrap()
            .field("status", Some(b"closed"))
            .is_err());
        assert!(CanonicalScope::new()
            .field("z", None)
            .unwrap()
            .field("a", None)
            .is_err());
        assert!(CanonicalScope::new().field("Status", None).is_err());
    }

    #[test]
    fn page_positions_require_exact_timestamp_uuid_shape() {
        let expected = position();
        assert_eq!(
            expected.descending_timestamp_uuid().unwrap(),
            (1_700_000_000_123_456, Uuid::from_u128(99))
        );
        assert_eq!(
            CursorPosition {
                last: vec![CursorValue::I64(1), CursorValue::Uuid(Uuid::nil())]
            }
            .descending_timestamp_uuid(),
            Err(CursorInvalid::Invalid)
        );
        assert_eq!(
            CursorPosition {
                last: vec![
                    CursorValue::TimestampMicros(i64::MAX),
                    CursorValue::Uuid(Uuid::new_v4())
                ]
            }
            .descending_timestamp_uuid(),
            Err(CursorInvalid::Invalid)
        );
        let keys = CursorKeyring::new(CURRENT, None).unwrap();
        assert_eq!(
            keys.issue(
                &binding(b"user", b""),
                &CursorPosition {
                    last: vec![CursorValue::TimestampMicros(i64::MAX)]
                },
                0,
                60
            ),
            Err(CursorIssueError::Position)
        );
    }

    #[test]
    fn governance_position_round_trips_digest_and_six_value_keyset() {
        let keys = CursorKeyring::new(CURRENT, None).unwrap();
        let expected = CursorPosition {
            last: vec![
                CursorValue::Uuid(Uuid::from_u128(8)),
                CursorValue::U64(3),
                CursorValue::TimestampMicros(1_700_000_000_123_456),
                CursorValue::Uuid(Uuid::from_u128(9)),
                CursorValue::TimestampMicros(1_700_000_000_000_000),
                CursorValue::Digest32([0xa5; 32]),
            ],
        };
        let token = keys
            .issue(&binding(b"admin-1", b"hold=8"), &expected, 9_000, 900)
            .unwrap();
        assert_eq!(
            keys.verify(&token, &binding(b"admin-1", b"hold=8"), 9_001)
                .unwrap(),
            expected
        );

        let mut raw = URL_SAFE_NO_PAD.decode(token).unwrap();
        // Any mutation of the cross-page chain root is covered by the token's
        // HMAC and is indistinguishable from another invalid cursor.
        let digest_byte = raw.len() - TAG_BYTES - 1;
        raw[digest_byte] ^= 1;
        assert_eq!(
            keys.verify(
                &URL_SAFE_NO_PAD.encode(raw),
                &binding(b"admin-1", b"hold=8"),
                9_001
            ),
            Err(CursorInvalid::Invalid)
        );
    }
}
