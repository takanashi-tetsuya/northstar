use northstar_pubsub_core::{PubSubNodeConfig, PubSubPublishOutcome};

fn serialized_item_payload_matches_type(item_xml: &str, payload_type: &str) -> bool {
    roxmltree::Document::parse(item_xml)
        .ok()
        .is_some_and(|document| {
            document
                .root_element()
                .children()
                .find(roxmltree::Node::is_element)
                .and_then(|payload| payload.tag_name().namespace())
                == Some(payload_type)
        })
}

fn item_xml_has_payload(item_xml: &str) -> bool {
    roxmltree::Document::parse(item_xml)
        .ok()
        .is_some_and(|document| {
            document
                .root_element()
                .children()
                .any(|node| node.is_element())
        })
}

pub fn publish_validation_outcome(
    config: &PubSubNodeConfig,
    items: &[(String, String)],
) -> Option<PubSubPublishOutcome> {
    if config.node_type != "leaf" {
        return Some(PubSubPublishOutcome::NotLeafNode);
    }
    if items.len() > config.max_items as usize {
        return Some(PubSubPublishOutcome::MaxItemsExceeded);
    }
    if config.persist_items && items.is_empty() {
        return Some(PubSubPublishOutcome::ItemRequired);
    }
    if !config.persist_items && !config.deliver_payloads && !items.is_empty() {
        return Some(PubSubPublishOutcome::ItemForbidden);
    }
    if !config.persist_items && config.deliver_payloads && items.is_empty() {
        return Some(PubSubPublishOutcome::ItemRequired);
    }
    if config.deliver_payloads
        && items
            .iter()
            .any(|(_, item_xml)| !item_xml_has_payload(item_xml))
    {
        return Some(PubSubPublishOutcome::PayloadRequired);
    }
    if items
        .iter()
        .any(|(_, item_xml)| item_xml.len() > config.max_payload_size as usize)
    {
        return Some(PubSubPublishOutcome::PayloadTooBig);
    }
    if config.payload_type.as_deref().is_some_and(|expected| {
        items
            .iter()
            .any(|(_, item_xml)| !serialized_item_payload_matches_type(item_xml, expected))
    }) {
        return Some(PubSubPublishOutcome::InvalidPayload);
    }
    None
}

/// Authorization runs before payload policy for an existing node, so an
/// unauthorized publisher cannot inspect private configuration through errors.
pub fn existing_node_publish_admission_outcome(
    authorized: bool,
    config: &PubSubNodeConfig,
    publish_options: Option<&PubSubNodeConfig>,
    items: &[(String, String)],
) -> Option<PubSubPublishOutcome> {
    if !authorized {
        return Some(PubSubPublishOutcome::Forbidden);
    }
    if publish_options.is_some_and(|options| options != config) {
        return Some(PubSubPublishOutcome::PreconditionNotMet);
    }
    publish_validation_outcome(config, items)
}
