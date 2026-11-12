//! BOSH response recording over a real SM record turn: the BOSH source is cleared before the stanza joins
//! the FIFO, and a refused item keeps the prior SM ownership.

use crate::stage4_support::sm_record_composition;
use crate::RecordPort;
use anyhow::Result;
use northstar_delivery_core::sm_ownership::KnowledgeClass;
use northstar_delivery_core::TransportOwnershipSource;
use northstar_stream::outbound::{MixTransportCompletion, OutboundItem};
use northstar_stream::protocol::sm_owner::test_support::{
    c2s, c2s_item, mix, SmRecordFixture, SmRecordTurn,
};
use uuid::Uuid;

struct SmRecord<'a> {
    turn: SmRecordTurn<'a>,
}
impl RecordPort for SmRecord<'_> {
    async fn record(&mut self, item: &OutboundItem) -> Result<bool> {
        self.turn.record(item).await
    }
}
#[tokio::test]
async fn actual_sm_record_clears_bosh_source_before_fifo_and_preserves_prior_sm_ownership_on_refusal(
) {
    for full in [false, true] {
        for use_mix in [false, true] {
            let mut fixture = SmRecordFixture::persisted(use_mix);
            let (item, mut mix_receipt) = if use_mix {
                let (item, receipt) =
                    OutboundItem::durable_mix("<message id='sm-bosh-mix'/>".to_owned(), mix());
                (item, Some(receipt))
            } else {
                (c2s_item(), None)
            };
            let (tx, mut c2s_receipt) = tokio::sync::mpsc::unbounded_channel();
            let mut item = item;
            item.transport_receipt = Some(tx);
            let pointer = item.stanza.as_ptr();
            let size = item.stanza.len();
            let mut record = SmRecord {
                turn: fixture.turn(),
            };
            let (accepted, items, bytes, bosh) =
                sm_record_composition(&mut record, item, full).await;
            assert_eq!(accepted, !full);
            assert_eq!(record.turn.unacked().len(), 1);
            assert_eq!(record.turn.outbound_h(), 11);
            let sm = record.turn.operation();
            assert_eq!(sm.summary().knowledge, KnowledgeClass::ReceiptKnown);
            assert!(sm.notification_attempted);
            if let Some(receipt) = mix_receipt.as_mut() {
                assert_eq!(
                    record.turn.unacked()[0]
                        .source
                        .unwrap()
                        .mix()
                        .unwrap()
                        .lease_token,
                    Uuid::from_u128(999)
                );
                assert_eq!(
                    receipt.try_recv().unwrap(),
                    MixTransportCompletion::SmPersisted {
                        session_id: record.turn.db_id().unwrap()
                    }
                );
                assert!(c2s_receipt.try_recv().is_err());
            } else {
                assert_eq!(
                    record.turn.unacked()[0].source,
                    Some(TransportOwnershipSource::C2s(c2s()))
                );
                c2s_receipt.try_recv().unwrap();
            }
            let bosh = bosh.snapshot();
            assert!(bosh.transfers.is_empty());
            assert_eq!(bosh.keep_running, Some(!full));
            if full {
                assert_eq!(items.len(), 2);
                assert_eq!(bytes, "<presence/>".len() * 2);
            } else {
                assert_eq!(items.len(), 1);
                assert_eq!(items[0].stanza.as_ptr(), pointer);
                assert_eq!(bytes, size);
                assert!(items[0].durable_source.is_none());
                assert!(items[0].mix_handoff.is_none());
                assert!(items[0].transport_receipt.is_some());
            }
        }
    }
}
