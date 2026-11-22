//! PostgreSQL implementation of the durable MIX delivery repository port.

use super::*;

impl<E: RoomEffects> MixDeliveryRepository for PostgresMixRepository<E> {
    #[allow(clippy::too_many_arguments)]
    async fn archive_mix_message_once(
        &self,
        personal_archive_id: Uuid,
        owner_id: Uuid,
        channel_jid: &str,
        authoritative_stanza_id: Uuid,
        stanza: &str,
        encrypted: bool,
        client_stanza_id: Option<&str>,
    ) -> Result<SourceArchiveAdmission> {
        self.effects
            .archive_mix_message_once(
                &self.pool,
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

    async fn claim_mix_deliveries(
        &self,
        limit: i64,
        max_bytes: i64,
    ) -> Result<Vec<ClaimedMixDelivery>> {
        let deliveries = {
            let deliveries = crate::mix::claim_mix_deliveries(&self.pool, limit, max_bytes).await?;
            deliveries
        };
        Ok(deliveries
            .into_iter()
            .map(|delivery| ClaimedMixDelivery {
                delivery_id: delivery.delivery_id,
                event_id: delivery.event_id,
                channel_id: delivery.channel_id,
                channel_jid: delivery.channel_jid,
                recipient: delivery.recipient,
                stanza: delivery.stanza,
                authoritative_stanza_id: delivery.authoritative_stanza_id,
                archive: delivery.archive,
                encrypted: delivery.encrypted,
                attempt_count: delivery.attempt_count,
                lease_token: delivery.lease_token,
                route_wake_generation: delivery.route_wake_generation,
            })
            .collect())
    }
    async fn claim_mix_deliveries_observed(
        &self,
        request: &outbox::core::ClaimRequest,
    ) -> Result<outbox::core::Rows> {
        crate::mix::claim_mix_deliveries_observed(&self.pool, request).await
    }
    async fn archive_mix_message_once_observed(
        &self,
        request: &outbox::core::ArchiveRequest,
    ) -> Result<outbox::core::ArchiveResult> {
        Ok(
            match self
                .effects
                .archive_mix_message_once_observed(&self.pool, request)
                .await?
            {
                SourceArchiveAdmission::Stored(id) => outbox::core::ArchiveResult::Stored(id),
                SourceArchiveAdmission::Replay(id) => outbox::core::ArchiveResult::Replay(id),
            },
        )
    }
    async fn renew_mix_delivery_lease_observed(
        &self,
        request: &outbox::core::RenewalRequest,
    ) -> Result<bool> {
        crate::mix::renew_mix_delivery_lease_observed(&self.pool, request).await
    }
    async fn settle_mix_delivery_observed(
        &self,
        request: &outbox::core::SettlementRequest,
    ) -> Result<outbox::core::SettlementResult> {
        use outbox::core::{SettlementCommand, SettlementResult};
        Ok(match request.command() {
            SettlementCommand::Ack => SettlementResult::Ack(
                crate::mix::acknowledge_mix_delivery_worker_observed(&self.pool, request).await?,
            ),
            SettlementCommand::Defer { .. } => SettlementResult::Defer(
                crate::mix::defer_mix_delivery_worker_observed(&self.pool, request).await?,
            ),
            SettlementCommand::Retry { .. } => SettlementResult::Retry(
                crate::mix::retry_mix_delivery_worker_observed(&self.pool, request).await?,
            ),
            SettlementCommand::DeadLetter { .. } => SettlementResult::DeadLetter(
                crate::mix::dead_letter_mix_delivery_worker_observed(&self.pool, request).await?,
            ),
        })
    }
    async fn maintain_mix_delivery_retention(&self) -> Result<()> {
        crate::mix::maintain_mix_delivery_retention(&self.pool).await
    }
    async fn acknowledge_mix_delivery(
        &self,
        delivery_id: Uuid,
        lease_token: Uuid,
        observation: Option<&northstar_delivery_core::native_write::AckRequest>,
    ) -> Result<bool> {
        match observation {
            Some(observation) => {
                crate::mix::acknowledge_mix_delivery_observed(
                    &self.pool,
                    delivery_id,
                    lease_token,
                    Some(observation),
                )
                .await
            }
            None => {
                crate::mix::acknowledge_mix_delivery(&self.pool, delivery_id, lease_token).await
            }
        }
    }
    async fn fence_mix_socket_write(
        &self,
        source: northstar_delivery_core::MixDelivery,
    ) -> Result<northstar_delivery_core::MixDelivery> {
        crate::mix::fence_mix_socket_write(&self.pool, source).await
    }
    async fn transfer_mix_delivery_to_cluster(
        &self,
        source: northstar_delivery_core::MixDelivery,
        node_id: &str,
        request_id: Uuid,
        ttl_seconds: u64,
    ) -> Result<northstar_delivery_core::MixDelivery> {
        crate::mix::transfer_mix_delivery_to_cluster(
            &self.pool,
            source,
            node_id,
            request_id,
            ttl_seconds,
        )
        .await
    }
    async fn release_mix_cluster_delivery(
        &self,
        source: northstar_delivery_core::MixDelivery,
        node_id: &str,
        request_id: Uuid,
    ) -> Result<bool> {
        let released =
            crate::mix::release_mix_cluster_delivery(&self.pool, source, node_id, request_id)
                .await?;

        Ok(released)
    }
    async fn transfer_mix_delivery_to_bosh(
        &self,
        request: &northstar_delivery_core::bosh_ownership::TransferRequest,
    ) -> Result<northstar_delivery_core::MixDelivery> {
        crate::mix::transfer_mix_delivery_to_bosh(&self.pool, request).await
    }

    async fn renew_mix_delivery_lease(&self, delivery_id: Uuid, lease_token: Uuid) -> Result<bool> {
        crate::mix::renew_mix_delivery_lease(&self.pool, delivery_id, lease_token).await
    }
    async fn dead_letter_mix_delivery(
        &self,
        delivery_id: Uuid,
        lease_token: Uuid,
        terminal_reason: &str,
        error: &str,
    ) -> Result<bool> {
        let moved = crate::mix::dead_letter_mix_delivery(
            &self.pool,
            delivery_id,
            lease_token,
            terminal_reason,
            error,
        )
        .await?;

        Ok(moved)
    }
    async fn retry_mix_delivery(
        &self,
        delivery_id: Uuid,
        lease_token: Uuid,
        _claimed_attempt_count: i32,
        route_wake_generation: i64,
        error: &str,
    ) -> Result<MixDeliveryRetryOutcome> {
        // The repository rereads the authoritative attempt count under the
        // exact lease row lock. Keep the protocol-facing snapshot argument
        // until the protocol completion DTO can be narrowed independently,
        // but never let it decide the terminal boundary.
        let outcome = crate::mix::retry_mix_delivery(
            &self.pool,
            delivery_id,
            lease_token,
            route_wake_generation,
            error,
        )
        .await?;
        Ok(outcome)
    }
    async fn defer_mix_delivery(
        &self,
        delivery_id: Uuid,
        lease_token: Uuid,
        route_wake_generation: i64,
        delay_seconds: i64,
    ) -> Result<bool> {
        crate::mix::defer_mix_delivery(
            &self.pool,
            delivery_id,
            lease_token,
            route_wake_generation,
            delay_seconds,
        )
        .await
    }
    async fn wake_mix_delivery_recipient(&self, recipient_jid: &str) -> Result<u64> {
        let woken = crate::mix::wake_mix_delivery_recipient(&self.pool, recipient_jid).await?;

        Ok(woken)
    }
    #[allow(dead_code)]
    async fn mix_delivery_dead_letters(
        &self,
        before: Option<(DateTime<Utc>, Uuid)>,
        limit: i64,
    ) -> Result<Vec<MixDeliveryDeadLetter>> {
        let dead_letters =
            { crate::mix::mix_delivery_dead_letters(&self.pool, before, limit).await? };
        Ok(dead_letters
            .into_iter()
            .map(|dead| MixDeliveryDeadLetter {
                dead_letter_id: dead.dead_letter_id,
                delivery_id: dead.delivery_id,
                event_id: dead.event_id,
                channel_id: dead.channel_id,
                channel_jid: dead.channel_jid,
                recipient_jid: dead.recipient_jid,
                attempt_count: dead.attempt_count,
                terminal_reason: dead.terminal_reason,
                last_error: dead.last_error,
                failed_at: dead.failed_at,
            })
            .collect())
    }
    #[allow(dead_code)]
    async fn requeue_mix_delivery_dead_letter(&self, dead_letter_id: Uuid) -> Result<bool> {
        let requeued =
            crate::mix::requeue_mix_delivery_dead_letter(&self.pool, dead_letter_id).await?;

        Ok(requeued)
    }
}
