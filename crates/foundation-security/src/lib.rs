//! Security foundation types, token redaction, and principal authorization context.
//!
//! Defined per `northstar_microservices_deep_audit_2026-09-03.md` (Appendix B.4).

use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

pub mod assertion;
pub mod authz;
pub mod keyring;
pub mod principal;
pub mod replay;
pub mod secret;

pub use assertion::{AssertionClaims, AssertionError};
pub use keyring::VerifyKeyRing;
pub use principal::VerifiedPrincipal;
pub use replay::BoundedReplayCache;

/// Secret text that is intentionally not serializable and never prints its
/// contents.  Services must unwrap it only at the password-hashing boundary.
#[derive(Clone, PartialEq, Eq)]
pub struct SecretString(Zeroizing<String>);

impl core::fmt::Debug for SecretString {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SecretString([REDACTED])")
    }
}

/// Secret bytes used for protocol exchanges such as SCRAM client-first and
/// client-final messages.  The value is deliberately not serializable or
/// printable; callers must cross an explicit authorized transport boundary
/// before exposing it.
#[derive(Clone, PartialEq, Eq)]
pub struct SecretBytes(Zeroizing<Vec<u8>>);

impl core::fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SecretBytes([REDACTED])")
    }
}

impl SecretBytes {
    pub fn new(value: impl Into<Vec<u8>>) -> Self {
        Self(Zeroizing::new(value.into()))
    }

    #[inline]
    pub fn expose_for_authorized_use(&self) -> &[u8] {
        &self.0
    }

    /// Runs a short-lived authorized operation without returning the secret.
    pub fn expose_secret<R>(&self, operation: impl FnOnce(&[u8]) -> R) -> R {
        operation(&self.0)
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl SecretString {
    pub fn new(value: impl Into<String>) -> Self {
        Self(Zeroizing::new(value.into()))
    }

    #[inline]
    pub fn expose_for_authorized_use(&self) -> &str {
        &self.0
    }

    /// Runs a short-lived authorized operation without returning the secret.
    pub fn expose_secret<R>(&self, operation: impl FnOnce(&str) -> R) -> R {
        operation(&self.0)
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// Secret opaque token with strict redaction and automatic memory zeroing on drop.
#[derive(Clone, PartialEq, Eq)]
pub struct OpaqueToken(Zeroizing<String>);

impl core::fmt::Debug for OpaqueToken {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("OpaqueToken([REDACTED])")
    }
}

impl core::fmt::Display for OpaqueToken {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("[REDACTED]")
    }
}

impl OpaqueToken {
    pub fn new(secret: impl Into<String>) -> Self {
        Self(Zeroizing::new(secret.into()))
    }

    /// Exposes the inner secret strictly for authorized network transport.
    #[inline]
    pub fn expose_for_authorized_transport(&self) -> &str {
        &self.0
    }

    /// Runs a short-lived authorized transport operation without returning the token.
    pub fn expose_secret<R>(&self, operation: impl FnOnce(&str) -> R) -> R {
        operation(&self.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SensitiveValueClass {
    Jid,
    Ip,
    Token,
    Content,
}

/// Stable, non-reversible pseudonym for logs and metrics.  The original value
/// is never formatted into the result, and the class prefix prevents cross-
/// domain correlation of the same input.
pub fn pseudonymize(value: &str, class: SensitiveValueClass) -> String {
    let label = match class {
        SensitiveValueClass::Jid => "jid",
        SensitiveValueClass::Ip => "ip",
        SensitiveValueClass::Token => "token",
        SensitiveValueClass::Content => "content",
    };
    let mut digest = Sha256::new();
    digest.update(label.as_bytes());
    digest.update([0]);
    digest.update(value.as_bytes());
    let bytes = digest.finalize();
    let mut rendered = String::with_capacity(2 + 12);
    rendered.push_str(label);
    rendered.push(':');
    for byte in bytes.iter().take(12) {
        use core::fmt::Write;
        let _ = write!(rendered, "{byte:02x}");
    }
    rendered
}

/// Authenticated principal context passed between microservices.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AuthContext {
    pub account_id: String,
    pub canonical_jid: String,
    pub credential_generation: u64,
    pub roles: Vec<String>,
    pub home_region: String,
}

impl AuthContext {
    pub fn new(
        account_id: impl Into<String>,
        canonical_jid: impl Into<String>,
        credential_generation: u64,
        home_region: impl Into<String>,
    ) -> Self {
        Self {
            account_id: account_id.into(),
            canonical_jid: canonical_jid.into(),
            credential_generation,
            roles: Vec::new(),
            home_region: home_region.into(),
        }
    }

    pub fn with_role(mut self, role: impl Into<String>) -> Self {
        self.roles.push(role.into());
        self
    }

    pub fn has_role(&self, role: &str) -> bool {
        self.roles.iter().any(|r| r == role)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_redacts_in_debug_and_display() {
        let token = OpaqueToken::new("super-secret-key-12345");
        let debug_str = format!("{token:?}");
        let display_str = format!("{token}");

        assert_eq!(debug_str, "OpaqueToken([REDACTED])");
        assert_eq!(display_str, "[REDACTED]");
        assert!(!debug_str.contains("super-secret"));
        assert!(!display_str.contains("super-secret"));

        assert_eq!(
            token.expose_for_authorized_transport(),
            "super-secret-key-12345"
        );
    }

    #[test]
    fn auth_context_roles_work() {
        let ctx = AuthContext::new("acc-1", "user@example.com", 1, "us-east").with_role("admin");
        assert!(ctx.has_role("admin"));
        assert!(!ctx.has_role("root"));
    }

    #[test]
    fn secret_string_redacts_debug_and_exposes_only_explicitly() {
        let secret = SecretString::new("correct horse battery staple");
        assert_eq!(format!("{secret:?}"), "SecretString([REDACTED])");
        assert_eq!(
            secret.expose_for_authorized_use(),
            "correct horse battery staple"
        );
    }

    #[test]
    fn secret_bytes_redacts_debug_and_exposes_only_explicitly() {
        let secret = SecretBytes::new(vec![1, 2, 3, 4]);
        assert_eq!(format!("{secret:?}"), "SecretBytes([REDACTED])");
        assert_eq!(secret.expose_for_authorized_use(), &[1, 2, 3, 4]);
        assert_eq!(secret.expose_secret(|bytes| bytes.len()), 4);
    }

    #[test]
    fn pseudonyms_are_class_bound_and_do_not_contain_the_source() {
        let jid = pseudonymize("alice@example.com", SensitiveValueClass::Jid);
        let token = pseudonymize("alice@example.com", SensitiveValueClass::Token);
        assert!(jid.starts_with("jid:"));
        assert!(token.starts_with("token:"));
        assert_ne!(jid, token);
        assert!(!jid.contains("alice"));
    }
}
