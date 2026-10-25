//! The Northstar PostgreSQL platform: the repository's `migrations/` directory, embedded at build time, and
//! the transaction helpers the PostgreSQL adapters share.

#![forbid(unsafe_code)]

/// The release migration set is part of the trusted binary. Both the explicit
/// migrator and the runtime checksum verifier use these exact bytes instead of
/// trusting a mutable working-directory `migrations/` tree.
pub static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("../../../migrations");

/// `clock_timestamp()` read inside the caller's transaction; keyset pages report it as `database_now`.
pub async fn database_cursor_clock_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
) -> anyhow::Result<chrono::DateTime<chrono::Utc>> {
    Ok(sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(&mut **tx)
        .await?)
}
