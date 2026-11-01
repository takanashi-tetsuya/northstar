//! Room persistence's steps in contexts that have not left the root crate yet.

use crate::db;
use anyhow::Result;
use northstar_federation_core::S2sOutboxPolicy;
use northstar_room_core::{OfflineStoreOutcome, OfflineStorePolicy};
use northstar_room_postgres::effects::RoomEffects;
use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

#[derive(Clone, Copy, Default)]
pub(crate) struct RootRoomEffects;

pub(crate) type PostgresMucRepository =
    northstar_room_postgres::room::PostgresMucRepository<RootRoomEffects>;

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
}
