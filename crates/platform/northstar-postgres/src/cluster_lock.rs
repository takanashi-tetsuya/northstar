//! The advisory lock that orders direct commits against node-instance claims.

use anyhow::Result;
use sqlx::{Postgres, Transaction};

pub const CLUSTER_KEY_AUTHORITY_LOCK: i64 = 4_741_070_036_074_865_762;

/// Direct spool producers take the shared claim fence before acquiring the
/// key and instance row locks. A replacement instance takes the exclusive
/// lock first, so a committed wake targets either the old or the new stable
/// node slot without an inverse row/advisory lock cycle.
pub async fn lock_direct_spool_instance_claims_in_transaction(
    transaction: &mut Transaction<'_, Postgres>,
) -> Result<()> {
    sqlx::query("SELECT pg_advisory_xact_lock_shared($1)")
        .bind(CLUSTER_KEY_AUTHORITY_LOCK)
        .execute(&mut **transaction)
        .await?;
    Ok(())
}
