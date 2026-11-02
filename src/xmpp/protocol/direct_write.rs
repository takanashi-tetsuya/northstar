//! The session's side of a native write: stream management records the stanza, and the C2S and MIX delivery
//! fences and acknowledgements run under one bounded backend deadline.

use super::ProtocolSession;
use anyhow::{Context, Result};
use northstar_c2s::direct_delivery::DirectWritePort;
use northstar_delivery_core::native_write::AckRequest;
use northstar_stream::outbound::{DurableDelivery, MixDelivery, OutboundItem};
use std::time::Duration;
use uuid::Uuid;

const C2S_BACKEND_OPERATION_TIMEOUT: Duration = Duration::from_secs(5);

impl DirectWritePort for ProtocolSession {
    async fn record(&mut self, item: &OutboundItem) -> Result<bool> {
        self.record_outbound_item(item).await
    }
    async fn fence_c2s(&self, delivery: DurableDelivery) -> Result<DurableDelivery> {
        tokio::time::timeout(
            C2S_BACKEND_OPERATION_TIMEOUT,
            self.fence_c2s_socket_write(delivery),
        )
        .await
        .context("C2S socket-write fence timed out")?
    }
    async fn fence_mix(&self, delivery: MixDelivery) -> Result<MixDelivery> {
        tokio::time::timeout(
            C2S_BACKEND_OPERATION_TIMEOUT,
            self.fence_mix_socket_write(delivery),
        )
        .await
        .context("MIX socket-write fence timed out")?
    }
    async fn acknowledge_c2s(&self, request: &AckRequest) -> Result<()> {
        tokio::time::timeout(
            C2S_BACKEND_OPERATION_TIMEOUT,
            self.acknowledge_c2s_socket_write(request),
        )
        .await
        .context("C2S socket-write acknowledgement timed out")?
    }
    async fn acknowledge_mix(&self, request: &AckRequest) -> Result<bool> {
        tokio::time::timeout(
            C2S_BACKEND_OPERATION_TIMEOUT,
            self.acknowledge_mix_socket_write(request),
        )
        .await
        .context("MIX socket-write acknowledgement timed out")?
    }
    fn connection_id(&self) -> Uuid {
        self.route_connection_id()
    }
}
