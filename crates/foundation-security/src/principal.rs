//! A verified principal cannot be constructed from deserialized input.

use crate::assertion::AssertionClaims;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedPrincipal {
    account_id: String,
    bare_jid: String,
    credential_generation: u64,
    session_epoch: u64,
    region_epoch: u64,
    scopes: Vec<String>,
    roles: Vec<String>,
    key_id: String,
}

impl VerifiedPrincipal {
    pub(crate) fn from_claims(claims: &AssertionClaims) -> Self {
        Self {
            account_id: claims.account_id.clone(),
            bare_jid: claims.bare_jid.clone(),
            credential_generation: claims.credential_generation,
            session_epoch: claims.session_epoch,
            region_epoch: claims.region_epoch,
            scopes: claims.scopes.clone(),
            roles: claims.roles.clone(),
            key_id: claims.key_id.clone(),
        }
    }

    pub fn account_id(&self) -> &str {
        &self.account_id
    }
    pub fn bare_jid(&self) -> &str {
        &self.bare_jid
    }
    pub fn credential_generation(&self) -> u64 {
        self.credential_generation
    }
    pub fn session_epoch(&self) -> u64 {
        self.session_epoch
    }
    pub fn region_epoch(&self) -> u64 {
        self.region_epoch
    }
    pub fn key_id(&self) -> &str {
        &self.key_id
    }
    pub fn has_scope(&self, scope: &str) -> bool {
        self.scopes.iter().any(|v| v == scope)
    }
    pub fn has_role(&self, role: &str) -> bool {
        self.roles.iter().any(|v| v == role)
    }
}
