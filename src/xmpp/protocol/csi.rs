use super::{Action, ProtocolSession};
use northstar_xep_0352::{
    classify_stanza, CsiIndication, CsiPolicyConfig, DeferredQueue, DeliveryAction, EnqueueResult,
    OverflowDecision, StanzaMetadata,
};

impl ProtocolSession {
    pub(crate) fn client_state(&mut self, indication: CsiIndication) -> Action {
        // XEP-0352 is advertised immediately after authentication, alongside
        // resource binding, so the state may be changed before binding.
        if self.authenticated.is_none() {
            return Action::Send(crate::xmpp::xml_util::stream_error("not-authorized"));
        }
        self.csi_state.apply_indication(indication);
        if indication.is_inactive() {
            return Action::None;
        }
        Action::SendManyItems(self.csi_deferred.drain_all())
    }

    /// Applies the XEP-0352 policy to transient outbound traffic. Durable
    /// delivery and transport acknowledgement fences always bypass deferral.
    pub(crate) fn csi_filter_outbound(
        &mut self,
        item: crate::outbound::OutboundItem,
    ) -> Option<crate::outbound::OutboundItem> {
        if self.csi_state.is_active() {
            return Some(item);
        }
        defer_stanza(&mut self.csi_deferred, item)
    }
}

fn defer_stanza(
    deferred: &mut DeferredQueue<crate::outbound::OutboundItem>,
    item: crate::outbound::OutboundItem,
) -> Option<crate::outbound::OutboundItem> {
    let metadata = StanzaMetadata {
        is_durable: item.durable_delivery.is_some(),
        has_transport_receipt: item.transport_receipt.is_some(),
        is_carbon: false,
        custom_bypass: false,
    };
    let key = match classify_stanza(&item.stanza, &metadata, deferred.config()) {
        DeliveryAction::Immediate => return Some(item),
        DeliveryAction::Discard => return None,
        DeliveryAction::Defer(key) => key,
    };
    let byte_size = item.stanza.len();
    match deferred.enqueue(item, byte_size, Some(key)) {
        EnqueueResult::Enqueued { .. } | EnqueueResult::Discarded { .. } => None,
        EnqueueResult::Overflow {
            decision: OverflowDecision::EvictedOldest { .. },
        } => None,
        EnqueueResult::Overflow {
            decision: OverflowDecision::Disconnect { unhandled_item, .. },
        } => Some(unhandled_item),
        EnqueueResult::Overflow {
            decision: OverflowDecision::Reject { rejected_item },
        } => Some(rejected_item),
        EnqueueResult::Overflow {
            decision: OverflowDecision::Persist { item_to_persist },
        } => Some(item_to_persist),
    }
}

pub(crate) fn valid_indication(root: roxmltree::Node<'_, '_>) -> bool {
    northstar_xep_0352::is_valid_indication_node(root)
}

pub(crate) fn default_queue() -> DeferredQueue<crate::outbound::OutboundItem> {
    DeferredQueue::new(CsiPolicyConfig::default())
}

#[cfg(test)]
mod tests {
    use super::{default_queue, defer_stanza, valid_indication};
    use crate::outbound::{DurableDelivery, OutboundItem};
    use roxmltree::Document;

    #[test]
    fn csi_indications_are_schema_empty() {
        for xml in [
            "<active xmlns='urn:xmpp:csi:0'/>",
            "<inactive xmlns='urn:xmpp:csi:0'></inactive>",
        ] {
            let document = Document::parse(xml).unwrap();
            assert!(valid_indication(document.root_element()), "{xml}");
        }
        for xml in [
            "<active xmlns='urn:xmpp:csi:0' id='unexpected'/>",
            "<inactive xmlns='urn:xmpp:csi:0'> </inactive>",
            "<active xmlns='urn:xmpp:csi:0'><child/></active>",
        ] {
            let document = Document::parse(xml).unwrap();
            assert!(!valid_indication(document.root_element()), "{xml}");
        }
    }

    #[test]
    fn inactive_queue_coalesces_chat_state_and_flushes_in_insertion_order() {
        let mut queue = default_queue();
        let presence = "<presence from='bob@example.test/Phone'><show>away</show></presence>";
        let composing = "<message from='bob@example.test/Phone' id='state-1'><composing xmlns='http://jabber.org/protocol/chatstates'/><no-store xmlns='urn:xmpp:hints'/><stanza-id xmlns='urn:xmpp:sid:0' id='server-1' by='alice@example.test'/></message>";
        let paused = "<message from='bob@example.test/Phone' id='state-2'><paused xmlns='http://jabber.org/protocol/chatstates'/><no-store xmlns='urn:xmpp:hints'/><stanza-id xmlns='urn:xmpp:sid:0' id='server-2' by='alice@example.test'/></message>";
        assert!(defer_stanza(&mut queue, OutboundItem::plain(presence.to_owned())).is_none());
        assert!(defer_stanza(&mut queue, OutboundItem::plain(composing.to_owned())).is_none());
        assert!(defer_stanza(&mut queue, OutboundItem::plain(paused.to_owned())).is_none());
        let flushed = queue.drain_all();
        assert_eq!(flushed.len(), 2);
        assert_eq!(flushed[0].stanza, presence);
        assert_eq!(flushed[1].stanza, paused);
        assert!(queue.is_empty());
        assert_eq!(queue.total_bytes(), 0);
    }

    #[test]
    fn durable_delivery_fence_bypasses_csi_defer_and_coalescing() {
        let mut queue = default_queue();
        let delivery = DurableDelivery {
            recipient_id: uuid::Uuid::from_u128(1),
            message_id: uuid::Uuid::from_u128(2),
            claim_id: None,
        };
        let item = OutboundItem::durable(
            "<message from='bob@example.test/Phone'><composing xmlns='http://jabber.org/protocol/chatstates'/></message>".to_owned(),
            delivery,
        );
        let forwarded = defer_stanza(&mut queue, item.clone())
            .expect("durable delivery must bypass CSI deferral");
        assert_eq!(forwarded.stanza, item.stanza);
        assert_eq!(forwarded.durable_delivery, item.durable_delivery);
        assert!(queue.is_empty());
    }

    #[test]
    fn canonical_classifier_keeps_critical_messages_immediate() {
        let mut queue = default_queue();
        for stanza in [
            "<message from='a@example.test'><body>important</body><composing xmlns='http://jabber.org/protocol/chatstates'/></message>",
            "<message from='a@example.test'><received xmlns='urn:xmpp:receipts' id='1'/></message>",
            "<presence from='a@example.test' type='subscribe'/>",
        ] {
            assert!(defer_stanza(&mut queue, OutboundItem::plain(stanza.to_owned())).is_some());
        }
        assert!(queue.is_empty());
    }
}
