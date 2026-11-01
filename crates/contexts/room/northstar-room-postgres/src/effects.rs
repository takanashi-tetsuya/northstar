//! The steps of room persistence that read or write other contexts' tables.

use anyhow::Result;
use northstar_delivery_core::mix_outbox::ArchiveRequest;
use northstar_federation_core::S2sOutboxPolicy;
use northstar_room_application::mix_service::{PepNodeConfig, SourceArchiveAdmission, VCardRecord};
use northstar_room_core::{OfflineStoreOutcome, OfflineStorePolicy};
use northstar_roster_core::RosterChange;
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

    /// [`Self::enqueue_federated_stanza`] with the row id the caller already fixed.
    fn enqueue_federated_stanza_with_id(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        id: Uuid,
        target_domain: &str,
        stanza: &str,
        bounce_to: Option<&str>,
        policy: S2sOutboxPolicy,
    ) -> impl Future<Output = Result<()>> + Send;

    /// Records a roster change that a channel membership made.
    fn record_roster_change(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        owner_id: Uuid,
        version: i64,
        jid: &str,
        removed: bool,
    ) -> impl Future<Output = Result<RosterChange>> + Send;

    /// Whether the account blocks `candidate`, matched against the stored JIDs.
    fn is_blocked(
        &self,
        pool: &PgPool,
        owner_id: Uuid,
        candidate: &str,
    ) -> impl Future<Output = Result<bool>> + Send;

    /// The configuration of one of the account's PEP nodes.
    fn pep_node(
        &self,
        pool: &PgPool,
        owner_id: Uuid,
        node: &str,
    ) -> impl Future<Output = Result<Option<PepNodeConfig>>> + Send;

    /// Items of one of the account's PEP nodes.
    fn pep_items(
        &self,
        pool: &PgPool,
        owner_id: Uuid,
        node: &str,
        item_id: Option<&str>,
        limit: i64,
    ) -> impl Future<Output = Result<Vec<(String, String)>>> + Send;

    /// The account's stored vCard.
    fn get_vcard(
        &self,
        pool: &PgPool,
        user_id: Uuid,
    ) -> impl Future<Output = Result<VCardRecord>> + Send;

    /// The newest roster change that names `contact_jid`.
    fn latest_roster_change_for_contact(
        &self,
        pool: &PgPool,
        user_id: Uuid,
        contact_jid: &str,
    ) -> impl Future<Output = Result<Option<RosterChange>>> + Send;

    /// Stores a reflected channel message in a personal archive exactly once.
    #[allow(clippy::too_many_arguments)]
    fn archive_mix_message_once(
        &self,
        pool: &PgPool,
        personal_archive_id: Uuid,
        owner_id: Uuid,
        channel_jid: &str,
        authoritative_stanza_id: Uuid,
        stanza: &str,
        encrypted: bool,
        client_stanza_id: Option<&str>,
    ) -> impl Future<Output = Result<SourceArchiveAdmission>> + Send;

    /// [`Self::archive_mix_message_once`] for an observed outbox request.
    fn archive_mix_message_once_observed(
        &self,
        pool: &PgPool,
        request: &ArchiveRequest,
    ) -> impl Future<Output = Result<SourceArchiveAdmission>> + Send;
}
