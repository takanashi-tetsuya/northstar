//! Small authorization helpers that require a `VerifiedPrincipal`.

use crate::principal::VerifiedPrincipal;

pub fn require_scope(principal: &VerifiedPrincipal, scope: &str) -> Result<(), &'static str> {
    if principal.has_scope(scope) {
        Ok(())
    } else {
        Err("missing required scope")
    }
}

pub fn require_role(principal: &VerifiedPrincipal, role: &str) -> Result<(), &'static str> {
    if principal.has_role(role) {
        Ok(())
    } else {
        Err("missing required role")
    }
}
