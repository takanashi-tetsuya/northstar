use anyhow::Result;
use futures::future::BoxFuture;
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

/// Authorization supplied by the workflow owning the standalone enqueue.
/// The repository locks both accounts before calling it and writes only on success.
pub trait OfflineAuthorization: Sync {
    fn actor_id(&self) -> Option<Uuid>;
    fn check<'tx>(
        &'tx self,
        transaction: &'tx mut Transaction<'_, Postgres>,
    ) -> BoxFuture<'tx, Result<()>>;
}
