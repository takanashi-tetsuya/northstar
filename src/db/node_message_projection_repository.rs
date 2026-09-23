//! PostgreSQL projections used to verify an inbound cluster delivery contract.

use crate::services::node_message_contract_verifier::{
    MixDeliveryProjection, NodeMessageProjectionRepository,
};
use anyhow::Result;
use sqlx::PgPool;
use uuid::Uuid;

pub(crate) struct PostgresNodeMessageProjectionRepository {
    pool: PgPool,
}

impl PostgresNodeMessageProjectionRepository {
    pub(crate) fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

impl NodeMessageProjectionRepository for PostgresNodeMessageProjectionRepository {
    async fn durable_c2s_stanza(
        &self,
        recipient_id: Uuid,
        message_id: Uuid,
    ) -> Result<Option<String>> {
        Ok(sqlx::query_scalar(
            "SELECT stanza FROM offline_messages WHERE recipient_id=$1 AND id=$2",
        )
        .bind(recipient_id)
        .bind(message_id)
        .fetch_optional(&self.pool)
        .await?)
    }

    async fn durable_mix_projection(
        &self,
        delivery_id: Uuid,
        lease_token: Uuid,
    ) -> Result<Option<MixDeliveryProjection>> {
        let row: Option<(String, String, bool, bool)> = sqlx::query_as(
            "SELECT recipient.recipient_jid,event.stanza_template,
                    recipient.lease_until>clock_timestamp() AS lease_active,
                    event.expires_at>clock_timestamp() AS event_active
               FROM mix_delivery_recipients recipient
               JOIN mix_delivery_events event ON event.event_id=recipient.event_id
              WHERE recipient.delivery_id=$1 AND recipient.lease_token=$2",
        )
        .bind(delivery_id)
        .bind(lease_token)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(
            |(recipient_jid, stanza_template, lease_active, event_active)| MixDeliveryProjection {
                recipient_jid,
                stanza_template,
                lease_active,
                event_active,
            },
        ))
    }

    async fn legacy_c2s_projection(&self, message_id: Uuid) -> Result<Option<(Uuid, String)>> {
        Ok(
            sqlx::query_as("SELECT recipient_id, stanza FROM offline_messages WHERE id=$1")
                .bind(message_id)
                .fetch_optional(&self.pool)
                .await?,
        )
    }
}
