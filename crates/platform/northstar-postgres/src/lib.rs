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

/// Whether an error comes from a capacity trigger's rejection, however many contexts wrap it.
pub fn is_capacity_exhausted(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause
            .downcast_ref::<sqlx::Error>()
            .is_some_and(is_capacity_sqlx_error)
            || cause.to_string().contains("capacity exhausted")
    })
}

/// A capacity trigger raises `P0001` with this wording; no other error code carries the meaning.
pub fn is_capacity_sqlx_error(error: &sqlx::Error) -> bool {
    error.as_database_error().is_some_and(|database| {
        database.code().as_deref() == Some("P0001")
            && database.message().contains("capacity exhausted")
    })
}

/// Whether an error is a transaction scheduling outcome rather than a fault, however many contexts
/// wrap it: a serialization failure, a deadlock or a bounded lock wait. The caller may retry it.
pub fn is_retryable_contention(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause
            .downcast_ref::<sqlx::Error>()
            .is_some_and(is_retryable_contention_sqlx_error)
    })
}

/// The SQLSTATE test of [`is_retryable_contention`] for one sqlx error.
pub fn is_retryable_contention_sqlx_error(error: &sqlx::Error) -> bool {
    error
        .as_database_error()
        .and_then(|database| database.code())
        .is_some_and(|code| retryable_contention_sqlstate(code.as_ref()))
}

/// A serialization failure, deadlock, or bounded lock-acquisition failure is a transaction
/// scheduling outcome, not an application fault. PostgreSQL reports NOWAIT/lock_timeout
/// contention as 55P03 (lock_not_available).
pub fn retryable_contention_sqlstate(code: &str) -> bool {
    matches!(code, "40001" | "40P01" | "55P03")
}

pub mod cluster_lock;
pub mod migration_preflight;
pub mod pool;
pub mod role_attestation;
pub mod schema;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn database_scheduling_conflicts_are_the_only_retryable_sqlstates() {
        assert!(retryable_contention_sqlstate("40001"));
        assert!(retryable_contention_sqlstate("40P01"));
        assert!(retryable_contention_sqlstate("55P03"));
        assert!(!retryable_contention_sqlstate("23505"));
        assert!(!retryable_contention_sqlstate("42501"));
    }
}
