//! The native lease over a real SM record turn: stream management records the stanza, and the lease neither
//! fences nor acknowledges natively.

use crate::direct_delivery::{DirectWriteLease, DirectWritePort};
use anyhow::Result;
use northstar_delivery_core::native_write::{AckKnowledge, AckRequest, Observation};
use northstar_stream::outbound::{
    DurableDelivery, MixDelivery, MixTransportCompletion, OutboundItem,
};
use northstar_stream::protocol::sm_owner::test_support::{
    c2s_item, mix, SmRecordFixture, SmRecordTurn,
};
use std::sync::atomic::{AtomicU64, Ordering};
use uuid::Uuid;

struct NativeSm<'a> {
    turn: SmRecordTurn<'a>,
    native_calls: AtomicU64,
}
impl DirectWritePort for NativeSm<'_> {
    async fn record(&mut self, item: &OutboundItem) -> Result<bool> {
        self.turn.record(item).await
    }
    async fn fence_c2s(&self, _: DurableDelivery) -> Result<DurableDelivery> {
        self.native_calls.fetch_add(1, Ordering::Relaxed);
        anyhow::bail!("unexpected native C2S fence")
    }
    async fn fence_mix(&self, _: MixDelivery) -> Result<MixDelivery> {
        self.native_calls.fetch_add(1, Ordering::Relaxed);
        anyhow::bail!("unexpected native MIX fence")
    }
    async fn acknowledge_c2s(&self, _: &AckRequest) -> Result<()> {
        self.native_calls.fetch_add(1, Ordering::Relaxed);
        anyhow::bail!("unexpected native C2S ACK")
    }
    async fn acknowledge_mix(&self, _: &AckRequest) -> Result<bool> {
        self.native_calls.fetch_add(1, Ordering::Relaxed);
        anyhow::bail!("unexpected native MIX ACK")
    }
    fn connection_id(&self) -> Uuid {
        self.turn.connection_id()
    }
}
#[tokio::test]
async fn real_sm_record_composes_with_native_lease_without_native_fence_or_ack() {
    for use_mix in [false, true] {
        let mut fixture = SmRecordFixture::persisted(use_mix);
        let (item, mut mix_receipt) = if use_mix {
            let (item, receipt) =
                OutboundItem::durable_mix("<message id='actual-mix'/>".to_owned(), mix());
            (item, Some(receipt))
        } else {
            (c2s_item(), None)
        };
        let (ownership_tx, mut ownership_rx) = tokio::sync::mpsc::unbounded_channel();
        let (write_tx, mut write_rx) = tokio::sync::mpsc::unbounded_channel();
        let mut item = item;
        item.transport_receipt = Some(ownership_tx);
        item.transport_write_receipt = Some(write_tx);
        let native = Observation::new(item.durable_source);
        let mut port = NativeSm {
            turn: fixture.turn(),
            native_calls: AtomicU64::new(0),
        };
        let lease = DirectWriteLease::prepare(&mut port, &item, &native)
            .await
            .unwrap();
        assert!(port.turn.operation().notification_attempted);
        if let Some(receipt) = mix_receipt.as_mut() {
            assert_eq!(
                receipt.try_recv().unwrap(),
                MixTransportCompletion::SmPersisted {
                    session_id: port.turn.db_id().unwrap()
                }
            );
            assert!(ownership_rx.try_recv().is_err());
        } else {
            ownership_rx.try_recv().unwrap();
        }
        assert!(write_rx.try_recv().is_err());
        let expected = item.stanza.as_str();
        let written = lease
            .write(|stanza| async move {
                assert_eq!(stanza, expected);
                Ok(())
            })
            .await
            .unwrap();
        written.settle(&port).await;
        write_rx.try_recv().unwrap();
        assert_eq!(port.native_calls.load(Ordering::Relaxed), 0);
        assert!(ownership_rx.try_recv().is_err());
        assert_eq!(native.snapshot().managed_by_sm, Some(true));
        assert_eq!(native.snapshot().ack, AckKnowledge::NotRequested);
    }
}
