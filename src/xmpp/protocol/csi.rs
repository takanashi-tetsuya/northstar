use super::{Action, ProtocolSession};
use roxmltree::Document;

const MAX_DEFERRED_STANZAS: usize = 512;
const MAX_DEFERRED_BYTES: usize = 2 * 1024 * 1024;

pub(crate) struct DeferredStanza {
    key: String,
    item: crate::outbound::OutboundItem,
}

impl ProtocolSession {
    pub(crate) fn client_state(&mut self, active: bool) -> Action {
        // XEP-0352 advertises CSI immediately after authentication, alongside
        // resource binding.  A client is therefore allowed to indicate its
        // state before it has selected a resource.
        if self.authenticated.is_none() {
            return Action::Send(crate::xmpp::xml_util::stream_error("not-authorized"));
        }
        if !active {
            self.csi_active = false;
            return Action::None;
        }
        self.csi_active = true;
        Action::SendManyItems(drain_deferred(
            &mut self.csi_deferred,
            &mut self.csi_deferred_bytes,
        ))
    }

    /// Applies the optional traffic optimisations described by XEP-0352.
    /// Important stanzas are never delayed. Presence, PEP events, and standalone
    /// chat-state notifications are coalesced while a client is inactive.
    pub(crate) fn csi_filter_outbound(
        &mut self,
        item: crate::outbound::OutboundItem,
    ) -> Option<crate::outbound::OutboundItem> {
        if self.csi_active {
            return Some(item);
        }
        defer_stanza(&mut self.csi_deferred, &mut self.csi_deferred_bytes, item)
    }
}

fn defer_stanza(
    deferred: &mut std::collections::VecDeque<DeferredStanza>,
    deferred_bytes: &mut usize,
    item: crate::outbound::OutboundItem,
) -> Option<crate::outbound::OutboundItem> {
    // A durable item owns an exact database fence and its relative order is
    // part of the recovery contract. CSI coalescing may replace an older soft
    // signal with a newer one, so allowing a durable item into this queue
    // could orphan the replaced fence or reorder an SM/BOSH acknowledgement.
    // Current durable normal/chat messages are not otherwise deferrable, but
    // keep this fail-safe explicit for future stanza classifiers.
    if item.durable_delivery.is_some() || item.transport_receipt.is_some() {
        return Some(item);
    }
    let Some(key) = deferrable_key(&item.stanza) else {
        return Some(item);
    };
    if let Some(existing) = deferred.iter_mut().find(|deferred| deferred.key == key) {
        *deferred_bytes = deferred_bytes
            .saturating_sub(existing.item.stanza.len())
            .saturating_add(item.stanza.len());
        existing.item = item;
        while *deferred_bytes > MAX_DEFERRED_BYTES {
            let Some(removed) = deferred.pop_front() else {
                *deferred_bytes = 0;
                break;
            };
            *deferred_bytes = deferred_bytes.saturating_sub(removed.item.stanza.len());
        }
        return None;
    }
    while deferred.len() >= MAX_DEFERRED_STANZAS
        || deferred_bytes.saturating_add(item.stanza.len()) > MAX_DEFERRED_BYTES
    {
        let removed = deferred.pop_front()?;
        *deferred_bytes = deferred_bytes.saturating_sub(removed.item.stanza.len());
    }
    *deferred_bytes = deferred_bytes.saturating_add(item.stanza.len());
    deferred.push_back(DeferredStanza { key, item });
    None
}

fn drain_deferred(
    deferred: &mut std::collections::VecDeque<DeferredStanza>,
    deferred_bytes: &mut usize,
) -> Vec<crate::outbound::OutboundItem> {
    *deferred_bytes = 0;
    deferred.drain(..).map(|deferred| deferred.item).collect()
}

pub(crate) fn valid_indication(root: roxmltree::Node<'_, '_>) -> bool {
    root.attributes().len() == 0
        && !root.children().any(|child| child.is_element())
        && root.text().is_none_or(str::is_empty)
}

fn deferrable_key(stanza: &str) -> Option<String> {
    let document = Document::parse(stanza).ok()?;
    let root = document.root_element();
    // RFC 7622 resourceparts are OpaqueStrings: account/domain preparation is
    // canonical, while resource case remains significant for coalescing.
    let from = crate::jid::canonicalize(root.attribute("from")?).ok()?;
    match root.tag_name().name() {
        "presence" => match root.attribute("type").unwrap_or("available") {
            "available" | "unavailable" => Some(format!("presence:{from}")),
            _ => None,
        },
        "message" => {
            let elements = root
                .children()
                .filter(|child| child.is_element())
                .collect::<Vec<_>>();
            let events = elements
                .iter()
                .filter(|child| {
                    child.tag_name().name() == "event"
                        && child.tag_name().namespace()
                            == Some("http://jabber.org/protocol/pubsub#event")
                })
                .collect::<Vec<_>>();
            if let [event] = events.as_slice() {
                let has_meaningful_sibling = elements.iter().any(|child| {
                    *child != **event
                        && !matches!(
                            child.tag_name().namespace(),
                            Some("urn:xmpp:hints" | "urn:xmpp:sid:0")
                        )
                });
                let event_children = event
                    .children()
                    .filter(|child| child.is_element())
                    .collect::<Vec<_>>();
                if !has_meaningful_sibling {
                    if let [items] = event_children.as_slice() {
                        if items.tag_name().name() == "items"
                            && items.tag_name().namespace()
                                == Some("http://jabber.org/protocol/pubsub#event")
                        {
                            let node = items.attribute("node").filter(|node| !node.is_empty())?;
                            let mut item_keys = items
                                .children()
                                .filter(|child| child.is_element())
                                .map(|item| {
                                    (matches!(item.tag_name().name(), "item" | "retract")
                                        && item.tag_name().namespace()
                                            == Some("http://jabber.org/protocol/pubsub#event"))
                                    .then(|| {
                                        item.attribute("id")
                                            .filter(|id| !id.is_empty())
                                            .map(|id| format!("{}:{id}", item.tag_name().name()))
                                    })
                                    .flatten()
                                })
                                .collect::<Option<Vec<_>>>()?;
                            if !item_keys.is_empty() {
                                item_keys.sort();
                                item_keys.dedup();
                                return Some(format!("pep:{from}:{node}:{}", item_keys.join(",")));
                            }
                        }
                    }
                }
            }
            let mut has_chat_state = false;
            let mut meaningful = false;
            for child in root.children().filter(|child| child.is_element()) {
                if child.tag_name().namespace() == Some("http://jabber.org/protocol/chatstates")
                    && matches!(
                        child.tag_name().name(),
                        "active" | "composing" | "gone" | "inactive" | "paused"
                    )
                {
                    has_chat_state = true;
                } else if !matches!(
                    child.tag_name().namespace(),
                    Some("urn:xmpp:hints" | "urn:xmpp:sid:0")
                ) {
                    meaningful = true;
                }
            }
            (has_chat_state && !meaningful).then(|| format!("chatstate:{from}"))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{defer_stanza, deferrable_key, drain_deferred, valid_indication};
    use crate::outbound::{DurableDelivery, OutboundItem};
    use roxmltree::Document;

    #[test]
    fn only_non_critical_updates_are_deferrable() {
        assert!(deferrable_key("<presence from='a@example.test/r'/>").is_some());
        assert!(deferrable_key("<presence from='a@example.test' type='subscribe'/>").is_none());
        assert!(deferrable_key("<message from='a@example.test'><composing xmlns='http://jabber.org/protocol/chatstates'/></message>").is_some());
        assert!(deferrable_key("<message from='a@example.test'><composing xmlns='http://jabber.org/protocol/chatstates'/><stanza-id xmlns='urn:xmpp:sid:0' id='1' by='a@example.test'/></message>").is_some());
        assert!(deferrable_key("<message from='a@example.test'><body>important</body><composing xmlns='http://jabber.org/protocol/chatstates'/></message>").is_none());
        assert!(deferrable_key(
            "<message from='a@example.test'><received xmlns='urn:xmpp:receipts' id='1'/></message>"
        )
        .is_none());
        assert!(deferrable_key(
            "<message type='chat' from='a@example.test'><propose xmlns='urn:xmpp:jingle-message:0' id='call'><description xmlns='urn:xmpp:jingle:apps:rtp:1' media='audio'/></propose><store xmlns='urn:xmpp:hints'/></message>"
        )
        .is_none());
    }

    #[test]
    fn opaque_resource_case_is_not_coalesced() {
        let upper = deferrable_key("<presence from='ALICE@Example.test/Phone'/>").unwrap();
        let lower = deferrable_key("<presence from='alice@example.test/phone'/>").unwrap();
        assert_eq!(upper, "presence:alice@example.test/Phone");
        assert_eq!(lower, "presence:alice@example.test/phone");
        assert_ne!(upper, lower);
    }

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
        let mut queue = std::collections::VecDeque::new();
        let mut bytes = 0;
        let presence = "<presence from='bob@example.test/Phone'><show>away</show></presence>";
        let composing = "<message from='bob@example.test/Phone' id='state-1'><composing xmlns='http://jabber.org/protocol/chatstates'/><no-store xmlns='urn:xmpp:hints'/><stanza-id xmlns='urn:xmpp:sid:0' id='server-1' by='alice@example.test'/></message>";
        let paused = "<message from='bob@example.test/Phone' id='state-2'><paused xmlns='http://jabber.org/protocol/chatstates'/><no-store xmlns='urn:xmpp:hints'/><stanza-id xmlns='urn:xmpp:sid:0' id='server-2' by='alice@example.test'/></message>";
        assert!(defer_stanza(
            &mut queue,
            &mut bytes,
            OutboundItem::plain(presence.to_owned())
        )
        .is_none());
        assert!(defer_stanza(
            &mut queue,
            &mut bytes,
            OutboundItem::plain(composing.to_owned())
        )
        .is_none());
        assert!(defer_stanza(
            &mut queue,
            &mut bytes,
            OutboundItem::plain(paused.to_owned())
        )
        .is_none());
        let flushed = drain_deferred(&mut queue, &mut bytes);
        assert_eq!(flushed.len(), 2);
        assert_eq!(flushed[0].stanza, presence);
        assert!(flushed[0].durable_delivery.is_none());
        assert!(flushed[0].transport_receipt.is_none());
        assert_eq!(flushed[1].stanza, paused);
        assert!(flushed[1].durable_delivery.is_none());
        assert!(flushed[1].transport_receipt.is_none());
        assert_eq!(bytes, 0);
        assert!(queue.is_empty());
    }

    #[test]
    fn durable_delivery_fence_bypasses_csi_defer_and_coalescing() {
        let mut queue = std::collections::VecDeque::new();
        let mut bytes = 0;
        let delivery = DurableDelivery {
            recipient_id: uuid::Uuid::from_u128(1),
            message_id: uuid::Uuid::from_u128(2),
            claim_id: None,
        };
        let item = OutboundItem::durable(
            "<message from='bob@example.test/Phone'><composing xmlns='http://jabber.org/protocol/chatstates'/></message>".to_owned(),
            delivery,
        );
        let forwarded = defer_stanza(&mut queue, &mut bytes, item.clone())
            .expect("durable delivery must bypass CSI deferral");
        assert_eq!(forwarded.stanza, item.stanza);
        assert_eq!(forwarded.durable_delivery, item.durable_delivery);
        assert!(forwarded.transport_receipt.is_none());
        assert!(drain_deferred(&mut queue, &mut bytes).is_empty());
        assert_eq!(bytes, 0);
    }

    #[test]
    fn only_replaceable_pubsub_item_updates_are_coalesced() {
        let first = deferrable_key(
            "<message from='pub@example.test'><event xmlns='http://jabber.org/protocol/pubsub#event'><items node='urn:test'><item id='one'><payload/></item></items></event></message>",
        );
        let replacement = deferrable_key(
            "<message from='pub@example.test'><event xmlns='http://jabber.org/protocol/pubsub#event'><items node='urn:test'><item id='one'><new/></item></items></event></message>",
        );
        let independent = deferrable_key(
            "<message from='pub@example.test'><event xmlns='http://jabber.org/protocol/pubsub#event'><items node='urn:test'><item id='two'/></items></event></message>",
        );
        assert_eq!(first, replacement);
        assert_ne!(first, independent);
        for critical in [
            "<message from='pub@example.test'><event xmlns='http://jabber.org/protocol/pubsub#event'><subscription node='urn:test' subscription='none'/></event></message>",
            "<message from='pub@example.test'><event xmlns='http://jabber.org/protocol/pubsub#event'><delete node='urn:test'/></event></message>",
            "<message from='pub@example.test'><event xmlns='http://jabber.org/protocol/pubsub#event'><items node='urn:test'><retract id='one'/></items></event><body>important</body></message>",
        ] {
            assert!(deferrable_key(critical).is_none(), "{critical}");
        }
    }
}
