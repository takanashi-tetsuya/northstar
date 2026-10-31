//! The REST bearer session as other contexts see it.

use uuid::Uuid;

/// Verifier-free identity/status projection for REST bearer authorization.
/// Password and SCRAM material is structurally absent, so ordinary API
/// requests cannot accidentally retain reusable credential verifiers.
#[derive(Clone, Debug)]
pub struct ApiPrincipal {
    pub id: Uuid,
    pub username: String,
    pub display_name: Option<String>,
    pub is_admin: bool,
    pub auth_generation: i64,
}

pub struct ApiReadAuthority<'a> {
    pub user_id: Uuid,
    pub auth_generation: i64,
    pub session_token: &'a str,
}
