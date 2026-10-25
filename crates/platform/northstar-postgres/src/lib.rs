//! The Northstar PostgreSQL schema: the repository's `migrations/` directory, embedded at build time.

#![forbid(unsafe_code)]

/// The release migration set is part of the trusted binary. Both the explicit
/// migrator and the runtime checksum verifier use these exact bytes instead of
/// trusting a mutable working-directory `migrations/` tree.
pub static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("../../../migrations");
