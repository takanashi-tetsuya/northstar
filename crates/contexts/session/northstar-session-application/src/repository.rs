//! Repository port traits for Session persistence and account credentials.

use uuid::Uuid;

pub type SessionRepoResult<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

/// Persisted user account information.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccountRecord {
    pub id: Uuid,
    pub username: String,
    pub password_hash: String,
    pub auth_generation: i64,
}

/// Repository port for session account lookup and authentication metadata.
pub trait SessionRepository: Send + Sync {
    /// Retrieve user account record by username.
    fn get_account_by_username(
        &self,
        username: &str,
    ) -> impl std::future::Future<Output = SessionRepoResult<Option<AccountRecord>>> + Send;

    /// Retrieve user account record by ID.
    fn get_account_by_id(
        &self,
        id: Uuid,
    ) -> impl std::future::Future<Output = SessionRepoResult<Option<AccountRecord>>> + Send;

    /// Increment auth generation to invalidate previous sessions.
    fn bump_auth_generation(
        &self,
        id: Uuid,
    ) -> impl std::future::Future<Output = SessionRepoResult<i64>> + Send;
}
