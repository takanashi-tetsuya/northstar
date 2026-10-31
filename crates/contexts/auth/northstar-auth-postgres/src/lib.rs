//! PostgreSQL persistence of accounts, API sessions, credentials and revocations. Each module writes
//! only the auth context's tables; a step in another context's table stays outside.

pub mod account_revocation_repository;
pub mod account_revocations;
pub mod account_teardown_repository;
pub mod authentication;
pub mod effects;
pub mod fast;
pub mod passkeys;
pub mod users;
