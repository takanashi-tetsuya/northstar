//! PostgreSQL session-lock operations for the maintenance process.

use anyhow::{ensure, Result};
use sqlx::{pool::PoolConnection, Postgres};

/// Lock the exact physical session reserved by the caller. Never return this
/// connection to a live pool after an unsuccessful claim.
pub(crate) async fn claim_exact(connection: &mut PoolConnection<Postgres>) -> Result<()> {
    connection.close_on_drop();
    let claimed: bool = sqlx::query_scalar("SELECT pg_try_advisory_lock(hashtextextended(current_database() || ':' || current_schema() || ':northstar:archive-maintenance:v1', 0))")
        .fetch_one(&mut **connection)
        .await?;
    ensure!(
        claimed,
        "archive maintenance is already owned by another process; stop it before changing process topology"
    );
    Ok(())
}

/// Probe the same locked session; a different pooled connection would hide
/// loss of ownership.
pub(crate) async fn probe_exact(connection: &mut PoolConnection<Postgres>) -> Result<()> {
    sqlx::query("SELECT 1").execute(&mut **connection).await?;
    Ok(())
}
