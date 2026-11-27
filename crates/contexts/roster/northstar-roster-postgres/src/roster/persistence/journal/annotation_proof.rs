use crate::RosterTransactionEffects;
use anyhow::Result;
use northstar_roster_core::RosterGap;
use sqlx::{Postgres, Transaction};
use std::future::Future;
use uuid::Uuid;

/// Proves that the GET annotation projection is valid for the journal versions being repaired.
pub trait RosterGapAnnotationProof: RosterTransactionEffects {
    fn annotations_proven(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        owner_id: Uuid,
        gap: RosterGap,
    ) -> impl Future<Output = Result<bool>> + Send;
}
