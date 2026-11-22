//! Repository port for durable MIX delivery.

use super::{
    outbox, ClaimedMixDelivery, MixDeliveryDeadLetter, MixDeliveryRetryOutcome,
    SourceArchiveAdmission,
};
use anyhow::Result;
use northstar_time::{DateTime, Utc};
use uuid::Uuid;

/// Persists durable MIX delivery, including archive admission and transport ownership.
pub trait MixDeliveryRepository: Send + Sync {
    #[allow(clippy::too_many_arguments)]
    fn archive_mix_message_once(
        &self,
        personal_archive_id: Uuid,
        owner_id: Uuid,
        channel_jid: &str,
        authoritative_stanza_id: Uuid,
        stanza: &str,
        encrypted: bool,
        client_stanza_id: Option<&str>,
    ) -> impl std::future::Future<Output = Result<SourceArchiveAdmission>> + Send;

    fn claim_mix_deliveries(
        &self,
        limit: i64,
        max_bytes: i64,
    ) -> impl std::future::Future<Output = Result<Vec<ClaimedMixDelivery>>> + Send;
    fn claim_mix_deliveries_observed(
        &self,
        request: &outbox::core::ClaimRequest,
    ) -> impl std::future::Future<Output = Result<outbox::core::Rows>> + Send;
    fn archive_mix_message_once_observed(
        &self,
        request: &outbox::core::ArchiveRequest,
    ) -> impl std::future::Future<Output = Result<outbox::core::ArchiveResult>> + Send;
    fn renew_mix_delivery_lease_observed(
        &self,
        request: &outbox::core::RenewalRequest,
    ) -> impl std::future::Future<Output = Result<bool>> + Send;
    fn settle_mix_delivery_observed(
        &self,
        request: &outbox::core::SettlementRequest,
    ) -> impl std::future::Future<Output = Result<outbox::core::SettlementResult>> + Send;
    fn maintain_mix_delivery_retention(
        &self,
    ) -> impl std::future::Future<Output = Result<()>> + Send;
    fn acknowledge_mix_delivery(
        &self,
        delivery_id: Uuid,
        lease_token: Uuid,
        observation: Option<&northstar_delivery_core::native_write::AckRequest>,
    ) -> impl std::future::Future<Output = Result<bool>> + Send;
    fn fence_mix_socket_write(
        &self,
        source: northstar_delivery_core::MixDelivery,
    ) -> impl std::future::Future<Output = Result<northstar_delivery_core::MixDelivery>> + Send;
    fn transfer_mix_delivery_to_cluster(
        &self,
        source: northstar_delivery_core::MixDelivery,
        node_id: &str,
        request_id: Uuid,
        ttl_seconds: u64,
    ) -> impl std::future::Future<Output = Result<northstar_delivery_core::MixDelivery>> + Send;
    fn release_mix_cluster_delivery(
        &self,
        source: northstar_delivery_core::MixDelivery,
        node_id: &str,
        request_id: Uuid,
    ) -> impl std::future::Future<Output = Result<bool>> + Send;
    fn transfer_mix_delivery_to_bosh(
        &self,
        request: &northstar_delivery_core::bosh_ownership::TransferRequest,
    ) -> impl std::future::Future<Output = Result<northstar_delivery_core::MixDelivery>> + Send;
    fn renew_mix_delivery_lease(
        &self,
        delivery_id: Uuid,
        lease_token: Uuid,
    ) -> impl std::future::Future<Output = Result<bool>> + Send;
    fn dead_letter_mix_delivery(
        &self,
        delivery_id: Uuid,
        lease_token: Uuid,
        terminal_reason: &str,
        error: &str,
    ) -> impl std::future::Future<Output = Result<bool>> + Send;
    fn retry_mix_delivery(
        &self,
        delivery_id: Uuid,
        lease_token: Uuid,
        _claimed_attempt_count: i32,
        route_wake_generation: i64,
        error: &str,
    ) -> impl std::future::Future<Output = Result<MixDeliveryRetryOutcome>> + Send;
    fn defer_mix_delivery(
        &self,
        delivery_id: Uuid,
        lease_token: Uuid,
        route_wake_generation: i64,
        delay_seconds: i64,
    ) -> impl std::future::Future<Output = Result<bool>> + Send;
    fn wake_mix_delivery_recipient(
        &self,
        recipient_jid: &str,
    ) -> impl std::future::Future<Output = Result<u64>> + Send;
    #[allow(dead_code)]
    fn mix_delivery_dead_letters(
        &self,
        before: Option<(DateTime<Utc>, Uuid)>,
        limit: i64,
    ) -> impl std::future::Future<Output = Result<Vec<MixDeliveryDeadLetter>>> + Send;
    #[allow(dead_code)]
    fn requeue_mix_delivery_dead_letter(
        &self,
        dead_letter_id: Uuid,
    ) -> impl std::future::Future<Output = Result<bool>> + Send;
}
