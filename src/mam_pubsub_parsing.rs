//! Compatibility facade for the capability-free XEP-0060 wire crate.
//!
//! Application handlers retain their existing names while all envelope,
//! item-id, and RSM grammar is owned and tested by `northstar-xep-0060`.

use roxmltree::Node;

pub(crate) type PubSubNamespace = northstar_xep_0060::EnvelopeNamespace;
pub(crate) type ParsedPubSubEnvelope<'a, 'input> =
    northstar_xep_0060::ParsedPubSubEnvelope<'a, 'input>;
pub(crate) type PubSubRsmRequest = northstar_xep_0060::RsmRequest;

pub(crate) fn parse_pubsub_envelope<'a, 'input>(
    child: Node<'a, 'input>,
    kind: &str,
) -> Result<ParsedPubSubEnvelope<'a, 'input>, &'static str> {
    northstar_xep_0060::parse_pubsub_envelope(child, kind).map_err(|error| error.condition)
}

pub(crate) fn parse_pubsub_rsm(set: Node<'_, '_>) -> Result<PubSubRsmRequest, &'static str> {
    northstar_xep_0060::parse_rsm_element(set).map_err(|error| error.condition)
}

#[cfg(test)]
mod tests {
    use super::*;
    use roxmltree::Document;

    #[test]
    fn facade_preserves_entity_envelope_and_rsm_contract() {
        let document = Document::parse(
            "<pubsub xmlns='http://jabber.org/protocol/pubsub'><items node='n'/><set xmlns='http://jabber.org/protocol/rsm'><max>10</max></set></pubsub>",
        )
        .unwrap();
        let parsed = parse_pubsub_envelope(document.root_element(), "get").unwrap();
        assert_eq!(parsed.namespace, PubSubNamespace::Entity);
        assert_eq!(parsed.operations.len(), 2);
        assert_eq!(
            parse_pubsub_rsm(parsed.operations[1]).unwrap().max,
            Some(10)
        );
    }

    #[test]
    fn facade_rejects_ambiguous_envelopes_and_cursors() {
        for xml in [
            "<pubsub xmlns='http://jabber.org/protocol/pubsub'/>",
            "<pubsub xmlns='http://jabber.org/protocol/pubsub'><items/><set xmlns='http://jabber.org/protocol/rsm'/><set xmlns='http://jabber.org/protocol/rsm'/></pubsub>",
            "<pubsub xmlns='http://jabber.org/protocol/pubsub#owner'><configure/><items xmlns='http://jabber.org/protocol/pubsub'/></pubsub>",
        ] {
            let document = Document::parse(xml).unwrap();
            assert_eq!(
                parse_pubsub_envelope(document.root_element(), "get").unwrap_err(),
                "bad-request",
                "{xml}"
            );
        }

        for xml in [
            "<set xmlns='http://jabber.org/protocol/rsm'><max>1001</max></set>",
            "<set xmlns='http://jabber.org/protocol/rsm'><after>a</after><before>b</before></set>",
            "<set xmlns='http://jabber.org/protocol/rsm'><max>1</max><max>2</max></set>",
        ] {
            let document = Document::parse(xml).unwrap();
            assert_eq!(
                parse_pubsub_rsm(document.root_element()),
                Err("bad-request")
            );
        }
    }
}
