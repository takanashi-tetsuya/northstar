//! Security foundation types, token redaction, and principal authorization context.
//!
//! Defined per `northstar_microservices_deep_audit_2026-09-03.md` (Appendix B.4).

use zeroize::Zeroizing;

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
}
