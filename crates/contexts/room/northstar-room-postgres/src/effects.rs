//! The steps of room persistence that read or write other contexts' tables.

use anyhow::Result;
use northstar_federation_core::S2sOutboxPolicy;
use northstar_room_core::{OfflineStoreOutcome, OfflineStorePolicy};
use sqlx::{PgPool, Postgres, Transaction};
use std::future::Future;
use uuid::Uuid;

/// A step that takes a transaction runs at the point the room code reaches it, so locks are taken in
/// one order and a failure rolls back the room change with it. The composition root implements this
/// port over the contexts that own those tables.
pub trait RoomEffects: Clone + Default + Send + Sync + 'static {
    /// Enqueues one stanza on the durable federation outbox and returns its row id.
    fn enqueue_federated_stanza(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        target_domain: &str,
        stanza: &str,
        bounce_to: Option<&str>,
        policy: S2sOutboxPolicy,
    ) -> impl Future<Output = Result<Uuid>> + Send;

    /// Takes the shared side of the lock a node-instance claim holds exclusively.
    fn lock_direct_spool_instance_claims(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
    ) -> impl Future<Output = Result<()>> + Send;

    /// Claims a stored offline message for the cluster's live delivery attempt.
    fn reserve_cluster_live_delivery(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        recipient_id: Uuid,
        message_id: Uuid,
    ) -> impl Future<Output = Result<()>> + Send;

    /// Records the wake that tells a direct spool's owner about a committed row.
    fn record_direct_spool_wake(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        domain: &str,
        recipient_id: Uuid,
    ) -> impl Future<Output = Result<()>> + Send;

    /// Whether the account blocks `candidate`, read outside any transaction.
    fn is_blocked_for_account(
        &self,
        pool: &PgPool,
        owner_id: Uuid,
        owner_bare_jid: &str,
        candidate: &str,
    ) -> impl Future<Output = Result<bool>> + Send;

    /// The account's blocklist.
    fn blocked_jids(
        &self,
        pool: &PgPool,
        user_id: Uuid,
    ) -> impl Future<Output = Result<Vec<String>>> + Send;

    /// Stores a stanza in the recipient's offline queue.
    #[allow(clippy::too_many_arguments)]
    fn store_offline_for_recipient(
        &self,
        pool: &PgPool,
        recipient_id: Uuid,
        recipient_bare_jid: &str,
        sender_jid: &str,
        stanza: &str,
        encrypted: bool,
        policy: OfflineStorePolicy,
    ) -> impl Future<Output = Result<OfflineStoreOutcome>> + Send;
}
