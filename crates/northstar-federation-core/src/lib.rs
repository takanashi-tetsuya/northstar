//! Capability-free XMPP S2S federation and outbox domain models and cryptographic algorithms.

#![forbid(unsafe_code)]

use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use northstar_xmpp_types::prepare_domainpart;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

pub const DIALBACK_NS: &str = "jabber:server:dialback";
pub const STREAM_LIMITS_NS: &str = "urn:xmpp:stream-limits:0";
pub const MAX_S2S_STANZA_BYTES: usize = 1024 * 1024;

/// Capacity and lifetime policy applied whenever a stanza crosses the durable
/// federation-admission boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct S2sOutboxPolicy {
    pub ttl_seconds: u64,
    pub max_rows: i64,
    pub max_bytes: i64,
    pub max_per_domain: i64,
}

impl S2sOutboxPolicy {
    pub fn new(ttl_seconds: u64, max_rows: i64, max_bytes: i64, max_per_domain: i64) -> Self {
        Self {
            ttl_seconds,
            max_rows,
            max_bytes,
            max_per_domain,
        }
    }
}

/// Durable S2S outbox queue entry.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct S2sOutboxItem {
    pub id: Uuid,
    pub target_domain: String,
    pub bounce_to: Option<String>,
    pub stanza: String,
    pub attempt_count: i32,
    pub lock_token: Uuid,
}

/// An expired S2S outbox item ready for notification or deletion.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ExpiredS2sOutboxItem {
    pub id: Uuid,
    pub target_domain: String,
    pub bounce_to: Option<String>,
    pub stanza: String,
    pub attempt_count: i32,
    pub created_at: DateTime<Utc>,
}

/// Mode of federation transport delivery.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub enum FederationDeliveryMode {
    DurableOutbox,
    Volatile,
}

/// XEP-0478 advertised stream limits for S2S.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct AdvertisedStreamLimits {
    pub max_bytes: Option<usize>,
    pub idle_seconds: Option<u32>,
}

/// Outcome of a dialback verification request.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum DialbackOutcome {
    Valid,
    Invalid,
    Error(String),
}

/// Helper to render bytes as lowercase hex.
pub fn hex_encode(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(DIGITS[(byte >> 4) as usize] as char);
        output.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    output
}

/// Helper to decode a hex string.
pub fn hex_decode(value: &str) -> Option<Vec<u8>> {
    if !value.len().is_multiple_of(2) {
        return None;
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = (pair[0] as char).to_digit(16)?;
            let low = (pair[1] as char).to_digit(16)?;
            Some(((high << 4) | low) as u8)
        })
        .collect()
}

/// XEP-0185 generation for XEP-0220: HMAC-SHA256(SHA256(secret),
/// receiving-domain SP originating-domain SP stream-id).
pub fn compute_dialback_key(
    secret: &[u8],
    receiving_domain: &str,
    originating_domain: &str,
    stream_id: &str,
) -> String {
    let derived = hex_encode(&Sha256::digest(secret));
    let mut mac =
        Hmac::<Sha256>::new_from_slice(derived.as_bytes()).expect("SHA-256 accepts any key length");
    mac.update(receiving_domain.as_bytes());
    mac.update(b" ");
    mac.update(originating_domain.as_bytes());
    mac.update(b" ");
    mac.update(stream_id.as_bytes());
    hex_encode(&mac.finalize().into_bytes())
}

/// Pure validation that a dialback key is 64 hex characters.
pub fn is_valid_dialback_key(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

/// Constant-time comparison between expected and supplied dialback keys.
pub fn matches_dialback_key(expected: &str, supplied: &str) -> bool {
    let (Some(expected), Some(supplied)) = (hex_decode(expected), hex_decode(supplied)) else {
        return false;
    };
    let Ok(mut supplied_mac) = Hmac::<Sha256>::new_from_slice(b"northstar-dialback-compare") else {
        return false;
    };
    supplied_mac.update(&supplied);
    let supplied_tag = supplied_mac.finalize().into_bytes();
    let Ok(mut expected_mac) = Hmac::<Sha256>::new_from_slice(b"northstar-dialback-compare") else {
        return false;
    };
    expected_mac.update(&expected);
    expected_mac.verify_slice(&supplied_tag).is_ok()
}

/// Pure comparison to check if two domains match after RFC 7622 preparation.
pub fn same_dialback_domain(left: &str, right: &str) -> bool {
    matches!(
        (prepare_domainpart(left), prepare_domainpart(right)),
        (Ok(left), Ok(right)) if left == right
    )
}

/// Check if a stanza is within the maximum allowed S2S bytes.
pub fn validate_s2s_stanza_size(size: usize, max_allowed: usize) -> bool {
    size > 0 && size <= max_allowed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dialback_key_generation_and_matching() {
        let secret = b"super-secret-key-material";
        let key1 = compute_dialback_key(secret, "example.org", "example.com", "stream-12345");
        assert!(is_valid_dialback_key(&key1));

        let key2 = compute_dialback_key(secret, "example.org", "example.com", "stream-12345");
        assert_eq!(key1, key2);
        assert!(matches_dialback_key(&key1, &key2));

        let key3 = compute_dialback_key(secret, "example.net", "example.com", "stream-12345");
        assert!(!matches_dialback_key(&key1, &key3));
        assert!(!matches_dialback_key(&key1, "invalid_hex"));
    }

    #[test]
    fn dialback_domain_matching() {
        assert!(same_dialback_domain("EXAMPLE.COM", "example.com"));
        assert!(same_dialback_domain("chat.example.org", "CHAT.EXAMPLE.ORG"));
        assert!(!same_dialback_domain("example.com", "other.com"));
    }

    #[test]
    fn stanza_size_validation() {
        assert!(validate_s2s_stanza_size(100, 1024));
        assert!(validate_s2s_stanza_size(1024, 1024));
        assert!(!validate_s2s_stanza_size(0, 1024));
        assert!(!validate_s2s_stanza_size(1025, 1024));
    }
}
