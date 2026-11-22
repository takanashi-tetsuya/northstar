use northstar_pubsub_core::{PubSubNodeConfig, PubSubPublishOutcome, PublishPolicyRejection};

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
    publish_policy_rejection(config, None, items).map(Into::into)
}

/// Evaluate explicit publish options and payload policy against one node config.
pub fn publish_policy_rejection(
    config: &PubSubNodeConfig,
    publish_options: Option<&PubSubNodeConfig>,
    items: &[(String, String)],
) -> Option<PublishPolicyRejection> {
    if publish_options.is_some_and(|options| options != config) {
        return Some(PublishPolicyRejection::PreconditionNotMet);
    }
    if config.node_type != "leaf" {
        return Some(PublishPolicyRejection::NotLeafNode);
    }
    if items.len() > config.max_items as usize {
        return Some(PublishPolicyRejection::MaxItemsExceeded);
    }
    if config.persist_items && items.is_empty() {
        return Some(PublishPolicyRejection::ItemRequired);
    }
    if !config.persist_items && !config.deliver_payloads && !items.is_empty() {
        return Some(PublishPolicyRejection::ItemForbidden);
    }
    if !config.persist_items && config.deliver_payloads && items.is_empty() {
        return Some(PublishPolicyRejection::ItemRequired);
    }
    if config.deliver_payloads
        && items
            .iter()
            .any(|(_, item_xml)| !item_xml_has_payload(item_xml))
    {
        return Some(PublishPolicyRejection::PayloadRequired);
    }
    if items
        .iter()
        .any(|(_, item_xml)| item_xml.len() > config.max_payload_size as usize)
    {
        return Some(PublishPolicyRejection::PayloadTooBig);
    }
    if config.payload_type.as_deref().is_some_and(|expected| {
        items
            .iter()
            .any(|(_, item_xml)| !serialized_item_payload_matches_type(item_xml, expected))
    }) {
        return Some(PublishPolicyRejection::InvalidPayload);
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
    publish_policy_rejection(config, publish_options, items).map(Into::into)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn locked_policy_and_prechecks_follow_the_same_validation_order() {
        use PubSubPublishOutcome as Outcome;
        use PublishPolicyRejection as Rejection;

        let default = PubSubNodeConfig::default();
        let collection = PubSubNodeConfig {
            node_type: "collection".to_owned(),
            max_items: 0,
            ..default.clone()
        };
        let zero_items = PubSubNodeConfig {
            max_items: 0,
            ..default.clone()
        };
        let transient = PubSubNodeConfig {
            persist_items: false,
            ..default.clone()
        };
        let notification_only = PubSubNodeConfig {
            deliver_payloads: false,
            ..transient.clone()
        };
        let typed = PubSubNodeConfig {
            payload_type: Some("urn:expected".to_owned()),
            ..default.clone()
        };
        let tiny = PubSubNodeConfig {
            max_payload_size: 1,
            ..typed.clone()
        };
        let empty: &[(String, String)] = &[];
        let payloadless = [("item".to_owned(), "<item/>".to_owned())];
        let payload = [(
            "item".to_owned(),
            "<item><value xmlns='urn:other'/></item>".to_owned(),
        )];

        for (config, items, expected) in [
            (
                &collection,
                payloadless.as_slice(),
                Some(Rejection::NotLeafNode),
            ),
            (
                &zero_items,
                payloadless.as_slice(),
                Some(Rejection::MaxItemsExceeded),
            ),
            (&default, empty, Some(Rejection::ItemRequired)),
            (&transient, empty, Some(Rejection::ItemRequired)),
            (
                &notification_only,
                payloadless.as_slice(),
                Some(Rejection::ItemForbidden),
            ),
            (
                &tiny,
                payloadless.as_slice(),
                Some(Rejection::PayloadRequired),
            ),
            (&tiny, payload.as_slice(), Some(Rejection::PayloadTooBig)),
            (&typed, payload.as_slice(), Some(Rejection::InvalidPayload)),
            (&default, payload.as_slice(), None),
            (&notification_only, empty, None),
        ] {
            let outcome = expected.map(Outcome::from);
            assert_eq!(publish_validation_outcome(config, items), outcome);
            for options in [None, Some(config)] {
                assert_eq!(publish_policy_rejection(config, options, items), expected);
                assert_eq!(
                    existing_node_publish_admission_outcome(true, config, options, items),
                    outcome
                );
            }
            let different = PubSubNodeConfig {
                title: Some("different title".to_owned()),
                ..config.clone()
            };
            assert_eq!(
                publish_policy_rejection(config, Some(&different), items),
                Some(Rejection::PreconditionNotMet)
            );
            assert_eq!(
                existing_node_publish_admission_outcome(true, config, Some(&different), items),
                Some(Outcome::PreconditionNotMet)
            );
            assert_eq!(
                existing_node_publish_admission_outcome(false, config, Some(&different), items),
                Some(Outcome::Forbidden)
            );
        }
    }
}
