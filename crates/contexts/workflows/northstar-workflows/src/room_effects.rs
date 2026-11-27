//! Room persistence's steps over the message, federation, roster, pubsub and session tables.

use anyhow::Result;
use northstar_delivery_core::mix_outbox::ArchiveRequest;
use northstar_federation_core::S2sOutboxPolicy;
use northstar_room_application::mix_service::{
    MixRelayProfileKind, MixRelayProfileResult, ReflectedMixArchiveOutcome, SourceArchiveAdmission,
    VerifiedMixReflection,
};
use northstar_room_core::{OfflineStoreOutcome, OfflineStorePolicy};
use northstar_room_postgres::effects::RoomEffects;
use northstar_roster_core::RosterChange;
use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

mod relay_policy;

#[derive(Clone, Copy, Default)]
pub struct WorkflowRoomEffects;

pub type PostgresMucRepository =
    northstar_room_postgres::room::PostgresMucRepository<WorkflowRoomEffects>;

pub type PostgresMixRepository =
    northstar_room_postgres::mix_repository::PostgresMixRepository<WorkflowRoomEffects>;

impl RoomEffects for WorkflowRoomEffects {
    async fn enqueue_federated_stanza(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        target_domain: &str,
        stanza: &str,
        bounce_to: Option<&str>,
        policy: S2sOutboxPolicy,
    ) -> Result<Uuid> {
        northstar_federation_postgres::enqueue_s2s_outbox_in_transaction(
            transaction,
            target_domain,
            stanza,
            bounce_to,
            policy,
        )
        .await
    }

    async fn reserve_cluster_live_delivery(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        recipient_id: Uuid,
        message_id: Uuid,
    ) -> Result<()> {
        northstar_message_postgres::personal_history::reserve_cluster_live_delivery_in_transaction(
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
        northstar_message_postgres::direct_spool_wake::record_direct_spool_wake_in_transaction(
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
        northstar_roster_postgres::roster::is_blocked_for_account(
            pool,
            owner_id,
            owner_bare_jid,
            candidate,
        )
        .await
    }

    async fn blocked_jids(&self, pool: &PgPool, user_id: Uuid) -> Result<Vec<String>> {
        northstar_roster_postgres::roster::blocked_jids(pool, user_id).await
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
        northstar_message_postgres::offline::store_offline_for_recipient(
            pool,
            recipient_id,
            recipient_bare_jid,
            sender_jid,
            stanza,
            encrypted,
            policy,
        )
        .await
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
        northstar_federation_postgres::enqueue_s2s_outbox_with_id_in_transaction(
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
        northstar_roster_postgres::roster::is_blocked(pool, owner_id, candidate).await
    }

    async fn relay_is_blocked(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        owner_id: Uuid,
        candidate: &str,
    ) -> Result<bool> {
        northstar_roster_postgres::roster::is_blocked(&mut **transaction, owner_id, candidate).await
    }

    async fn relay_profile_in_transaction(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        owner_id: Uuid,
        kind: &MixRelayProfileKind,
    ) -> Result<MixRelayProfileResult> {
        use MixRelayProfileResult as Profile;
        match kind {
            MixRelayProfileKind::VCardTemp => {
                let record =
                    northstar_pubsub_postgres::get_vcard(&mut **transaction, owner_id).await?;
                Ok(record
                    .payload_vcard_temp
                    .map_or(Profile::EmptyCard, Profile::VCardTemp))
            }
            MixRelayProfileKind::VCard4 { item_id } => {
                const NODE: &str = "urn:xmpp:vcard4";
                // MIX admission controls visibility, including for legacy non-open nodes.
                if northstar_pubsub_postgres::pep_node(&mut **transaction, owner_id, NODE)
                    .await?
                    .is_none()
                {
                    return Ok(Profile::VCard4Missing);
                }
                let mut items = northstar_pubsub_postgres::pep_items(
                    &mut **transaction,
                    owner_id,
                    NODE,
                    item_id.as_deref(),
                    1,
                )
                .await?;
                Ok(items
                    .pop()
                    .map_or(Profile::VCard4Missing, |(_, xml)| Profile::VCard4(xml)))
            }
        }
    }

    async fn latest_roster_change_for_contact(
        &self,
        pool: &PgPool,
        user_id: Uuid,
        contact_jid: &str,
    ) -> Result<Option<RosterChange>> {
        northstar_roster_postgres::roster::latest_roster_change_for_contact(
            pool,
            user_id,
            contact_jid,
        )
        .await
    }

    async fn record_mix_source_retraction_in_tx(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        channel: &str,
        target: Uuid,
        action: Uuid,
        participant: &str,
    ) -> Result<()> {
        use northstar_archive_postgres::mix_source_retractions::{
            lock_sources_in_tx, record_locked_in_tx,
        };

        anyhow::ensure!(target != action, "MIX retraction action equals its target");
        lock_sources_in_tx(tx, channel, &[target, action], true).await?;
        anyhow::ensure!(
            record_locked_in_tx(tx, channel, target, action, participant).await?,
            "conflicting MIX source action binding"
        );
        Ok(())
    }

    async fn archive_verified_mix_reflection(
        &self,
        pool: &PgPool,
        request: VerifiedMixReflection<'_>,
    ) -> Result<ReflectedMixArchiveOutcome> {
        crate::mix_archive::archive_verified_mix_reflection(pool, request).await
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
        crate::mix_archive::archive_mix_message_once(
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
    }

    async fn archive_mix_message_once_observed(
        &self,
        pool: &PgPool,
        request: &ArchiveRequest,
    ) -> Result<SourceArchiveAdmission> {
        crate::mix_archive::archive_mix_message_once_observed(pool, request).await
    }
}
