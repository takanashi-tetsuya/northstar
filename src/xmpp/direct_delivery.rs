//! Durable ownership around one ordered TCP or WebSocket write.
//!
//! BOSH has a separate response acknowledgement boundary and does not use this
//! lease. The transport still owns framing, the actual write and its errors.

use super::{protocol::ProtocolSession, C2S_BACKEND_OPERATION_TIMEOUT};
use crate::outbound::{DurableDelivery, MixDelivery, MixTransportCompletion, OutboundItem};
use anyhow::{Context, Result};
use std::future::Future;
use uuid::Uuid;

/// The only persistence operations a direct writer needs. Keeping them here
/// also lets the fence/write/ack sequence be tested without a socket or DB.
trait DirectWritePort {
    fn record(&mut self, item: &OutboundItem) -> impl Future<Output = Result<bool>> + Send;
    fn fence_c2s(
        &self,
        delivery: DurableDelivery,
    ) -> impl Future<Output = Result<DurableDelivery>> + Send;
    fn fence_mix(&self, delivery: MixDelivery) -> impl Future<Output = Result<MixDelivery>> + Send;
    fn acknowledge_c2s(&self, delivery: DurableDelivery)
        -> impl Future<Output = Result<()>> + Send;
    fn acknowledge_mix(&self, delivery: MixDelivery) -> impl Future<Output = Result<bool>> + Send;
    fn connection_id(&self) -> Uuid;
}

impl DirectWritePort for ProtocolSession {
    async fn record(&mut self, item: &OutboundItem) -> Result<bool> {
        self.record_outbound_item(item).await
    }

    async fn fence_c2s(&self, delivery: DurableDelivery) -> Result<DurableDelivery> {
        tokio::time::timeout(
            C2S_BACKEND_OPERATION_TIMEOUT,
            self.state.replay_service().fence_socket_write(delivery),
        )
        .await
        .context("C2S socket-write fence timed out")?
    }

    async fn fence_mix(&self, delivery: MixDelivery) -> Result<MixDelivery> {
        tokio::time::timeout(
            C2S_BACKEND_OPERATION_TIMEOUT,
            self.state.mix_service().fence_mix_socket_write(delivery),
        )
        .await
        .context("MIX socket-write fence timed out")?
    }

    async fn acknowledge_c2s(&self, delivery: DurableDelivery) -> Result<()> {
        tokio::time::timeout(
            C2S_BACKEND_OPERATION_TIMEOUT,
            self.state
                .replay_service()
                .acknowledge_socket_write(delivery),
        )
        .await
        .context("C2S socket-write acknowledgement timed out")?
    }

    async fn acknowledge_mix(&self, delivery: MixDelivery) -> Result<bool> {
        tokio::time::timeout(
            C2S_BACKEND_OPERATION_TIMEOUT,
            self.state
                .mix_service()
                .acknowledge_mix_delivery(delivery.delivery_id, delivery.lease_token),
        )
        .await
        .context("MIX socket-write acknowledgement timed out")?
    }

    fn connection_id(&self) -> Uuid {
        self.connection_id
    }
}

/// A prepared direct write owns any non-SM fence until bytes are accepted.
/// Dropping it after a failed write deliberately leaves the durable row for
/// lease expiry/recovery; it never acknowledges on drop.
pub(super) struct DirectWriteLease {
    managed_by_sm: bool,
    c2s: Option<DurableDelivery>,
    mix: Option<MixDelivery>,
}

impl DirectWriteLease {
    pub(super) async fn prepare(
        session: &mut ProtocolSession,
        item: &OutboundItem,
    ) -> Result<Self> {
        Self::prepare_with(session, item).await
    }

    async fn prepare_with<P: DirectWritePort>(port: &mut P, item: &OutboundItem) -> Result<Self> {
        let managed_by_sm = port.record(item).await.context("record outbound stanza")?;
        let c2s = match item.c2s_delivery().filter(|_| !managed_by_sm) {
            Some(delivery) => Some(port.fence_c2s(delivery).await.context("fence C2S write")?),
            None => None,
        };
        let mix = match item.mix_delivery().filter(|_| !managed_by_sm) {
            Some(delivery) => {
                let fenced = port.fence_mix(delivery).await.context("fence MIX write")?;
                // The claiming worker may stop only after the new exact fence
                // exists. A later route retry cannot reuse its old token.
                item.complete_mix_handoff(MixTransportCompletion::SocketFenced {
                    connection_id: port.connection_id(),
                });
                Some(fenced)
            }
            None => None,
        };
        Ok(Self {
            managed_by_sm,
            c2s,
            mix,
        })
    }

    pub(super) async fn written(self, session: &ProtocolSession, item: &OutboundItem) {
        self.written_with(session, item).await;
    }

    async fn written_with<P: DirectWritePort>(self, port: &P, item: &OutboundItem) {
        item.confirm_transport_write();
        if !self.managed_by_sm {
            item.confirm_transport_ownership();
        }
        if let Some(delivery) = self.c2s {
            if let Err(error) = port.acknowledge_c2s(delivery).await {
                tracing::warn!(?error, message_id = %delivery.message_id, "direct write succeeded but durable C2S acknowledgement failed");
            }
        }
        if let Some(delivery) = self.mix {
            match port.acknowledge_mix(delivery).await {
                Ok(true) => {}
                Ok(false) => {
                    tracing::warn!(delivery_id = %delivery.delivery_id, "MIX socket fence changed before direct-write acknowledgement")
                }
                Err(error) => {
                    tracing::warn!(?error, delivery_id = %delivery.delivery_id, "direct write succeeded but durable MIX acknowledgement failed")
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use tokio::sync::mpsc;

    #[derive(Default)]
    struct FakePort {
        events: Mutex<Vec<&'static str>>,
        managed_by_sm: bool,
        fail_at: Option<&'static str>,
        acknowledged: Mutex<bool>,
    }

    impl FakePort {
        fn event(&self, name: &'static str) -> Result<()> {
            self.events.lock().unwrap().push(name);
            anyhow::ensure!(self.fail_at != Some(name), "injected {name} failure");
            Ok(())
        }

        fn events(&self) -> Vec<&'static str> {
            self.events.lock().unwrap().clone()
        }
    }

    impl DirectWritePort for FakePort {
        async fn record(&mut self, _: &OutboundItem) -> Result<bool> {
            self.event("record")?;
            Ok(self.managed_by_sm)
        }

        async fn fence_c2s(&self, delivery: DurableDelivery) -> Result<DurableDelivery> {
            self.event("fence_c2s")?;
            Ok(DurableDelivery {
                claim_id: Some(Uuid::from_u128(11)),
                ..delivery
            })
        }

        async fn fence_mix(&self, delivery: MixDelivery) -> Result<MixDelivery> {
            self.event("fence_mix")?;
            Ok(MixDelivery {
                lease_token: Uuid::from_u128(12),
                ..delivery
            })
        }

        async fn acknowledge_c2s(&self, delivery: DurableDelivery) -> Result<()> {
            assert_eq!(delivery.claim_id, Some(Uuid::from_u128(11)));
            self.event("ack_c2s")?;
            *self.acknowledged.lock().unwrap() = true;
            Ok(())
        }

        async fn acknowledge_mix(&self, delivery: MixDelivery) -> Result<bool> {
            assert_eq!(delivery.lease_token, Uuid::from_u128(12));
            self.event("ack_mix")?;
            *self.acknowledged.lock().unwrap() = true;
            Ok(true)
        }

        fn connection_id(&self) -> Uuid {
            Uuid::from_u128(13)
        }
    }

    fn c2s_item() -> OutboundItem {
        OutboundItem::durable(
            "<message/>".to_owned(),
            DurableDelivery {
                recipient_id: Uuid::from_u128(1),
                message_id: Uuid::from_u128(2),
                claim_id: Some(Uuid::from_u128(3)),
            },
        )
    }

    #[tokio::test]
    async fn c2s_fence_precedes_write_and_only_rotated_lease_is_acknowledged() {
        let mut port = FakePort::default();
        let (receipt, mut received) = mpsc::unbounded_channel();
        let mut item = c2s_item();
        item.transport_receipt = Some(receipt);
        let lease = DirectWriteLease::prepare_with(&mut port, &item)
            .await
            .unwrap();
        assert_eq!(port.events(), ["record", "fence_c2s"]);
        assert!(received.try_recv().is_err());
        port.event("write").unwrap();
        lease.written_with(&port, &item).await;
        assert_eq!(port.events(), ["record", "fence_c2s", "write", "ack_c2s"]);
        assert!(received.try_recv().is_ok());
        assert!(*port.acknowledged.lock().unwrap());
    }

    #[tokio::test]
    async fn mix_handoff_follows_fence_and_ack_follows_write() {
        let mut port = FakePort::default();
        let (item, handoff) = OutboundItem::durable_mix(
            "<message/>".to_owned(),
            MixDelivery {
                delivery_id: Uuid::from_u128(4),
                lease_token: Uuid::from_u128(5),
            },
        );
        let lease = DirectWriteLease::prepare_with(&mut port, &item)
            .await
            .unwrap();
        assert_eq!(port.events(), ["record", "fence_mix"]);
        assert_eq!(
            handoff.await.unwrap(),
            MixTransportCompletion::SocketFenced {
                connection_id: Uuid::from_u128(13)
            }
        );
        port.event("write").unwrap();
        lease.written_with(&port, &item).await;
        assert_eq!(port.events(), ["record", "fence_mix", "write", "ack_mix"]);
    }

    #[tokio::test]
    async fn fence_failure_and_write_cancellation_never_acknowledge() {
        let mut port = FakePort {
            fail_at: Some("fence_c2s"),
            ..FakePort::default()
        };
        assert!(DirectWriteLease::prepare_with(&mut port, &c2s_item())
            .await
            .is_err());
        assert_eq!(port.events(), ["record", "fence_c2s"]);

        let mut port = FakePort::default();
        let item = c2s_item();
        {
            let _lease = DirectWriteLease::prepare_with(&mut port, &item)
                .await
                .unwrap();
            // The transport is cancelled before it can call `written_with`.
        }
        assert_eq!(port.events(), ["record", "fence_c2s"]);
        assert!(!*port.acknowledged.lock().unwrap());
    }

    #[tokio::test]
    async fn acknowledgement_failure_leaves_durable_lease_for_recovery() {
        let mut port = FakePort {
            fail_at: Some("ack_c2s"),
            ..FakePort::default()
        };
        let item = c2s_item();
        let lease = DirectWriteLease::prepare_with(&mut port, &item)
            .await
            .unwrap();
        port.event("write").unwrap();
        lease.written_with(&port, &item).await;
        assert_eq!(port.events(), ["record", "fence_c2s", "write", "ack_c2s"]);
        assert!(!*port.acknowledged.lock().unwrap());
    }

    #[tokio::test]
    async fn sm_owner_never_uses_direct_fence_or_ack() {
        let mut port = FakePort {
            managed_by_sm: true,
            ..FakePort::default()
        };
        let item = c2s_item();
        let lease = DirectWriteLease::prepare_with(&mut port, &item)
            .await
            .unwrap();
        port.event("write").unwrap();
        lease.written_with(&port, &item).await;
        assert_eq!(port.events(), ["record", "write"]);
        assert!(!*port.acknowledged.lock().unwrap());
    }
}
