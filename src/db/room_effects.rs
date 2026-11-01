//! Room persistence's steps in contexts that have not left the root crate yet.

use crate::db;
use anyhow::Result;
use northstar_delivery_core::mix_outbox::ArchiveRequest;
use northstar_federation_core::S2sOutboxPolicy;
use northstar_room_application::mix_service::{PepNodeConfig, SourceArchiveAdmission, VCardRecord};
use northstar_room_core::{OfflineStoreOutcome, OfflineStorePolicy};
use northstar_room_postgres::effects::RoomEffects;
use northstar_roster_core::RosterChange;
use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

#[derive(Clone, Copy, Default)]
pub struct RootRoomEffects;

pub(crate) type PostgresMucRepository =
    northstar_room_postgres::room::PostgresMucRepository<RootRoomEffects>;

pub(crate) type PostgresMixRepository =
    northstar_room_postgres::mix_repository::PostgresMixRepository<RootRoomEffects>;

fn source_admission(admission: db::SourceArchiveAdmission) -> SourceArchiveAdmission {
    match admission {
        db::SourceArchiveAdmission::Stored(id) => SourceArchiveAdmission::Stored(id),
        db::SourceArchiveAdmission::Replay(id) => SourceArchiveAdmission::Replay(id),
    }
}

impl RoomEffects for RootRoomEffects {
    async fn enqueue_federated_stanza(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        target_domain: &str,
        stanza: &str,
        bounce_to: Option<&str>,
        policy: S2sOutboxPolicy,
    ) -> Result<Uuid> {
        db::enqueue_s2s_outbox_in_transaction(transaction, target_domain, stanza, bounce_to, policy)
            .await
    }

    async fn lock_direct_spool_instance_claims(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
    ) -> Result<()> {
        db::cluster_keys::lock_direct_spool_instance_claims_in_transaction(transaction).await
    }

    async fn reserve_cluster_live_delivery(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        recipient_id: Uuid,
        message_id: Uuid,
    ) -> Result<()> {
        db::archive::reserve_cluster_live_delivery_in_transaction(
            transaction,
            recipient_id,
            message_id,
        )
        .await
    }

    async fn record_direct_spool_wake(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        domain: &str,
        recipient_id: Uuid,
    ) -> Result<()> {
        db::direct_spool_wake_repository::record_direct_spool_wake_in_transaction(
            transaction,
            domain,
            recipient_id,
        )
        .await
    }

    async fn is_blocked_for_account(
        &self,
        pool: &PgPool,
        owner_id: Uuid,
        owner_bare_jid: &str,
        candidate: &str,
    ) -> Result<bool> {
        db::is_blocked_for_account(pool, owner_id, owner_bare_jid, candidate).await
    }

    async fn blocked_jids(&self, pool: &PgPool, user_id: Uuid) -> Result<Vec<String>> {
        db::blocked_jids(pool, user_id).await
    }

    async fn store_offline_for_recipient(
        &self,
        pool: &PgPool,
        recipient_id: Uuid,
        recipient_bare_jid: &str,
        sender_jid: &str,
        stanza: &str,
        encrypted: bool,
        policy: OfflineStorePolicy,
    ) -> Result<OfflineStoreOutcome> {
        Ok(
            match db::store_offline_for_recipient(
                pool,
                recipient_id,
                recipient_bare_jid,
                sender_jid,
                stanza,
                encrypted,
                db::OfflineStorePolicy {
                    max_messages: policy.max_messages,
                    max_bytes: policy.max_bytes,
                    ttl_days: policy.ttl_days,
                    mam_backed: policy.mam_backed,
                },
            )
            .await?
            {
                db::OfflineStoreOutcome::Stored => OfflineStoreOutcome::Stored,
                db::OfflineStoreOutcome::Replay => OfflineStoreOutcome::Replay,
                db::OfflineStoreOutcome::QuotaExceeded => OfflineStoreOutcome::QuotaExceeded,
                db::OfflineStoreOutcome::RecipientUnavailable => {
                    OfflineStoreOutcome::RecipientUnavailable
                }
            },
        )
    }

    async fn enqueue_federated_stanza_with_id(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        id: Uuid,
        target_domain: &str,
        stanza: &str,
        bounce_to: Option<&str>,
        policy: S2sOutboxPolicy,
    ) -> Result<()> {
        db::enqueue_s2s_outbox_with_id_in_transaction(
            transaction,
            id,
            target_domain,
            stanza,
            bounce_to,
            policy,
        )
        .await
    }

    async fn record_roster_change(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        owner_id: Uuid,
        version: i64,
        jid: &str,
        removed: bool,
    ) -> Result<RosterChange> {
        northstar_roster_postgres::roster::record_roster_change(
            transaction,
            owner_id,
            version,
            jid,
            removed,
        )
        .await
    }

    async fn is_blocked(&self, pool: &PgPool, owner_id: Uuid, candidate: &str) -> Result<bool> {
        db::is_blocked(pool, owner_id, candidate).await
    }

    async fn pep_node(
        &self,
        pool: &PgPool,
        owner_id: Uuid,
        node: &str,
    ) -> Result<Option<PepNodeConfig>> {
        Ok(db::pep_node(pool, owner_id, node)
            .await?
            .map(|config| PepNodeConfig {
                access_model: config.access_model,
                max_items: config.max_items,
                persist_items: config.persist_items,
                send_last_published_item: config.send_last_published_item,
                deliver_notifications: config.deliver_notifications,
                roster_groups_allowed: config.roster_groups_allowed,
                access_whitelist: config.access_whitelist,
            }))
    }

    async fn pep_items(
        &self,
        pool: &PgPool,
        owner_id: Uuid,
        node: &str,
        item_id: Option<&str>,
        limit: i64,
    ) -> Result<Vec<(String, String)>> {
        db::pep_items(pool, owner_id, node, item_id, limit).await
    }

    async fn get_vcard(&self, pool: &PgPool, user_id: Uuid) -> Result<VCardRecord> {
        let record = db::get_vcard(pool, user_id).await?;
        Ok(VCardRecord {
            payload_vcard_temp: record.payload_vcard_temp,
        })
    }

    async fn latest_roster_change_for_contact(
        &self,
        pool: &PgPool,
        user_id: Uuid,
        contact_jid: &str,
    ) -> Result<Option<RosterChange>> {
        db::latest_roster_change_for_contact(pool, user_id, contact_jid).await
    }

    async fn archive_mix_message_once(
        &self,
        pool: &PgPool,
        personal_archive_id: Uuid,
        owner_id: Uuid,
        channel_jid: &str,
        authoritative_stanza_id: Uuid,
        stanza: &str,
        encrypted: bool,
        client_stanza_id: Option<&str>,
    ) -> Result<SourceArchiveAdmission> {
        db::archive_mix_message_once(
            pool,
            personal_archive_id,
            owner_id,
            channel_jid,
            authoritative_stanza_id,
            stanza,
            encrypted,
            client_stanza_id,
        )
        .await
        .map(source_admission)
    }

    async fn archive_mix_message_once_observed(
        &self,
        pool: &PgPool,
        request: &ArchiveRequest,
    ) -> Result<SourceArchiveAdmission> {
        db::archive_mix_message_once_observed(pool, request)
            .await
            .map(source_admission)
    }
}
