//! The anti-abuse maintenance steps that touch other contexts' tables.

use anyhow::Result;
use chrono::{DateTime, Utc};
use sqlx::{PgPool, Postgres, Transaction};
use std::future::Future;

/// Durable rows of other contexts that still need one key generation.
pub struct ForeignKeyReferences {
    pub offline_admissions: i64,
    pub personal_message_identities: i64,
    pub retraction_identities: i64,
    pub mix_business_identities: i64,
}

/// The composition root implements this port over the contexts that own those tables.
pub trait AbuseEffects: Send + Sync {
    /// Counts the rows that still need `key_id`, inside the caller's key deployment transaction.
    fn foreign_key_references(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        key_id: &str,
        now: DateTime<Utc>,
    ) -> impl Future<Output = Result<ForeignKeyReferences>> + Send;

    /// Deletes one bounded batch of expired offline admissions, in a statement of its own.
    fn delete_expired_offline_admissions(
        &self,
        pool: &PgPool,
    ) -> impl Future<Output = Result<()>> + Send;
}
