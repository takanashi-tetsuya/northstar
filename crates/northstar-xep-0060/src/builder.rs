//! Safe XML payload and message builders for XEP-0060 responses and event notifications.

use crate::constants::{
    NS_DELAY, NS_DISCO_INFO, NS_DISCO_ITEMS, NS_PUBSUB, NS_PUBSUB_EVENT, NS_PUBSUB_OWNER, NS_SHIM,
    SERVICE_FEATURES, SUBSCRIBE_AUTH_FORM,
};
use crate::error::PubSubError;
use crate::models::{NodeType, SubscriptionState};
use crate::wire::{
    AffiliationEntryWire, DiscoItemWire, OwnerAffiliationEntryWire, OwnerSubscriptionEntryWire,
    SubscriptionEntryWire,
};
use crate::xml::XmlElement;

/// Wrap a payload in a standard `<iq type='result' ...>` stanza.
pub fn build_iq_result(id: &str, from: &str, payload: &str) -> String {
    let mut iq = XmlElement::namespaced("iq", "jabber:client")
        .attr("type", "result")
        .attr("from", from)
        .attr("id", id);
    if !payload.is_empty() {
        let _ = iq.push_validated_fragment(payload);
    }
    iq.finish()
}

/// Wrap a payload in a standard server-to-server `<iq type='result' ...>` stanza.
pub fn build_s2s_iq_result(id: &str, from: &str, to: &str, payload: &str) -> String {
    let mut iq = XmlElement::namespaced("iq", "jabber:server")
        .attr("type", "result")
        .attr("id", id)
        .attr("from", from)
        .attr("to", to);
    if !payload.is_empty() {
        let _ = iq.push_validated_fragment(payload);
    }
    iq.finish()
}

/// Build an entity `<create node='...'/>` response payload.
pub fn build_create_response(node: &str) -> String {
    XmlElement::namespaced("pubsub", NS_PUBSUB)
        .child(XmlElement::new("create").attr("node", node))
        .finish()
}

/// Build an entity `<publish node='...'>` response payload.
pub fn build_publish_response(node: &str, item_ids: &[&str]) -> String {
    let mut publish = XmlElement::new("publish").attr("node", node);
    for item_id in item_ids {
        publish.push_child(XmlElement::new("item").attr("id", *item_id));
    }
    XmlElement::namespaced("pubsub", NS_PUBSUB)
        .child(publish)
        .finish()
}

/// Build a `<subscription>` element.
pub fn build_subscription_element(
    node: &str,
    jid: &str,
    state: SubscriptionState,
    subid: Option<&str>,
    expiry: Option<&str>,
) -> XmlElement {
    XmlElement::new("subscription")
        .attr("node", node)
        .attr("jid", jid)
        .attr("subscription", state.as_str())
        .optional_attr("subid", subid)
        .optional_attr("expiry", expiry)
}

/// Build an entity subscription response payload.
pub fn build_subscribe_response(
    node: &str,
    jid: &str,
    state: SubscriptionState,
    subid: Option<&str>,
    expiry: Option<&str>,
) -> String {
    XmlElement::namespaced("pubsub", NS_PUBSUB)
        .child(build_subscription_element(node, jid, state, subid, expiry))
        .finish()
}

/// Build an entity unsubscription response payload.
pub fn build_unsubscribe_response(node: &str, jid: &str, subid: Option<&str>) -> String {
    build_subscribe_response(node, jid, SubscriptionState::None, subid, None)
}

/// Build an entity `<options>` response payload.
pub fn build_options_response(
    node: &str,
    jid: &str,
    subid: Option<&str>,
    form_xml: &str,
) -> Result<String, PubSubError> {
    let mut options = XmlElement::new("options")
        .attr("node", node)
        .attr("jid", jid)
        .optional_attr("subid", subid);
    options
        .push_validated_fragment(form_xml)
        .map_err(|_| PubSubError::bad_request())?;
    Ok(XmlElement::namespaced("pubsub", NS_PUBSUB)
        .child(options)
        .finish())
}

/// Build an entity `<default>` options response payload.
pub fn build_default_options_response(
    node: Option<&str>,
    form_xml: &str,
) -> Result<String, PubSubError> {
    let mut default = XmlElement::new("default").optional_attr("node", node);
    default
        .push_validated_fragment(form_xml)
        .map_err(|_| PubSubError::bad_request())?;
    Ok(XmlElement::namespaced("pubsub", NS_PUBSUB)
        .child(default)
        .finish())
}

/// Build an entity `<items>` response payload.
pub fn build_items_response(
    node: &str,
    items_xml: &[&str],
    rsm_xml: Option<&str>,
) -> Result<String, PubSubError> {
    let mut items = XmlElement::new("items").attr("node", node);
    for item_xml in items_xml {
        items
            .push_validated_fragment(item_xml)
            .map_err(|_| PubSubError::bad_request())?;
    }
    let mut pubsub = XmlElement::namespaced("pubsub", NS_PUBSUB).child(items);
    if let Some(rsm) = rsm_xml {
        pubsub
            .push_validated_fragment(rsm)
            .map_err(|_| PubSubError::bad_request())?;
    }
    Ok(pubsub.finish())
}

/// Build an entity `<subscriptions>` response payload.
pub fn build_subscriptions_response(
    node: Option<&str>,
    subscriptions: &[SubscriptionEntryWire],
) -> String {
    let mut entries = XmlElement::new("subscriptions").optional_attr("node", node);
    for sub in subscriptions {
        entries.push_child(build_subscription_element(
            &sub.node,
            &sub.jid,
            sub.state,
            sub.subid.as_deref(),
            sub.expiry.as_deref(),
        ));
    }
    XmlElement::namespaced("pubsub", NS_PUBSUB)
        .child(entries)
        .finish()
}

/// Build an entity `<affiliations>` response payload.
pub fn build_affiliations_response(affiliations: &[AffiliationEntryWire]) -> String {
    let mut entries = XmlElement::new("affiliations");
    for aff in affiliations {
        entries.push_child(
            XmlElement::new("affiliation")
                .attr("node", &aff.node)
                .attr("affiliation", aff.affiliation.as_str()),
        );
    }
    XmlElement::namespaced("pubsub", NS_PUBSUB)
        .child(entries)
        .finish()
}

// Owner Response Builders

/// Build an owner `<configure>` response payload.
pub fn build_owner_configure_response(node: &str, form_xml: &str) -> Result<String, PubSubError> {
    let mut configure = XmlElement::new("configure").attr("node", node);
    configure
        .push_validated_fragment(form_xml)
        .map_err(|_| PubSubError::bad_request())?;
    Ok(XmlElement::namespaced("pubsub", NS_PUBSUB_OWNER)
        .child(configure)
        .finish())
}

/// Build an owner `<default>` response payload.
pub fn build_owner_default_response(form_xml: &str) -> Result<String, PubSubError> {
    let mut default = XmlElement::new("default");
    default
        .push_validated_fragment(form_xml)
        .map_err(|_| PubSubError::bad_request())?;
    Ok(XmlElement::namespaced("pubsub", NS_PUBSUB_OWNER)
        .child(default)
        .finish())
}

/// Build an owner `<subscriptions>` response payload.
pub fn build_owner_subscriptions_response(
    node: &str,
    subscriptions: &[OwnerSubscriptionEntryWire],
) -> String {
    let mut entries = XmlElement::new("subscriptions").attr("node", node);
    for sub in subscriptions {
        entries.push_child(
            XmlElement::new("subscription")
                .attr("jid", &sub.jid)
                .attr("subscription", sub.state.as_str())
                .attr("subid", &sub.subid)
                .optional_attr("expiry", sub.expiry.as_deref()),
        );
    }
    XmlElement::namespaced("pubsub", NS_PUBSUB_OWNER)
        .child(entries)
        .finish()
}

/// Build an owner `<affiliations>` response payload.
pub fn build_owner_affiliations_response(
    node: &str,
    affiliations: &[OwnerAffiliationEntryWire],
) -> String {
    let mut entries = XmlElement::new("affiliations").attr("node", node);
    for aff in affiliations {
        entries.push_child(
            XmlElement::new("affiliation")
                .attr("jid", &aff.jid)
                .attr("affiliation", aff.affiliation.as_str()),
        );
    }
    XmlElement::namespaced("pubsub", NS_PUBSUB_OWNER)
        .child(entries)
        .finish()
}

// Event Notification Builders

/// Build an `<event xmlns='http://jabber.org/protocol/pubsub#event'>` with items or retractions.
pub fn build_event_items(
    node: &str,
    items_xml: &[&str],
    retract_ids: &[&str],
) -> Result<String, PubSubError> {
    let mut items = XmlElement::new("items").attr("node", node);
    for item_xml in items_xml {
        items
            .push_validated_fragment(item_xml)
            .map_err(|_| PubSubError::bad_request())?;
    }
    for retract_id in retract_ids {
        items.push_child(XmlElement::new("retract").attr("id", *retract_id));
    }
    Ok(XmlElement::namespaced("event", NS_PUBSUB_EVENT)
        .child(items)
        .finish())
}

/// Build an event delete payload (`<delete node='...'><redirect uri='...'?></delete>`).
pub fn build_event_delete(node: &str, redirect: Option<&str>) -> String {
    let mut delete = XmlElement::new("delete").attr("node", node);
    if let Some(uri) = redirect {
        delete.push_child(XmlElement::new("redirect").attr("uri", uri));
    }
    XmlElement::namespaced("event", NS_PUBSUB_EVENT)
        .child(delete)
        .finish()
}

/// Build an event purge payload (`<purge node='...'/>`).
pub fn build_event_purge(node: &str) -> String {
    XmlElement::namespaced("event", NS_PUBSUB_EVENT)
        .child(XmlElement::new("purge").attr("node", node))
        .finish()
}

/// Build an event configuration payload (`<configuration node='...'>...`).
pub fn build_event_configuration(
    node: &str,
    form_xml: Option<&str>,
) -> Result<String, PubSubError> {
    let mut config = XmlElement::new("configuration").attr("node", node);
    if let Some(form) = form_xml {
        config
            .push_validated_fragment(form)
            .map_err(|_| PubSubError::bad_request())?;
    }
    Ok(XmlElement::namespaced("event", NS_PUBSUB_EVENT)
        .child(config)
        .finish())
}

/// Assemble the inner child stanzas for a subscription notification message:
/// `<event xmlns='pubsub#event'>`, optional `<body>`, SHIM `<headers>`, and optional `<delay>`.
pub fn build_subscription_event_children(
    event_payload: &str,
    subid: &str,
    collection: Option<&str>,
    body: Option<&str>,
    delay_stamp_rfc3339: Option<&str>,
) -> Result<String, PubSubError> {
    let mut headers = XmlElement::namespaced("headers", NS_SHIM)
        .child(XmlElement::new("header").attr("name", "SubID").text(subid));
    if let Some(coll) = collection {
        headers.push_child(
            XmlElement::new("header")
                .attr("name", "Collection")
                .text(coll),
        );
    }

    let mut wrapper = XmlElement::new("northstar-children");
    let mut event = XmlElement::namespaced("event", NS_PUBSUB_EVENT);
    event
        .push_validated_fragment(event_payload)
        .map_err(|_| PubSubError::bad_request())?;
    wrapper.push_child(event);

    if let Some(body_text) = body {
        wrapper.push_child(XmlElement::new("body").text(body_text));
    }
    wrapper.push_child(headers);

    if let Some(stamp) = delay_stamp_rfc3339 {
        wrapper.push_child(XmlElement::namespaced("delay", NS_DELAY).attr("stamp", stamp));
    }

    Ok(wrapper.finish_children())
}

/// Build an authorization request XData form to send to node owners (`pubsub#subscribe_authorization`).
pub fn build_subscription_auth_request_form(
    node: &str,
    subscriber_jid: &str,
    subid: &str,
) -> String {
    XmlElement::namespaced("x", crate::constants::NS_DATA)
        .attr("type", "form")
        .child(
            XmlElement::new("field")
                .attr("var", "FORM_TYPE")
                .attr("type", "hidden")
                .child(XmlElement::new("value").text(SUBSCRIBE_AUTH_FORM)),
        )
        .child(
            XmlElement::new("field")
                .attr("var", "pubsub#node")
                .child(XmlElement::new("value").text(node)),
        )
        .child(
            XmlElement::new("field")
                .attr("var", "pubsub#subscriber_jid")
                .child(XmlElement::new("value").text(subscriber_jid)),
        )
        .child(
            XmlElement::new("field")
                .attr("var", "pubsub#subid")
                .child(XmlElement::new("value").text(subid)),
        )
        .child(
            XmlElement::new("field")
                .attr("var", "pubsub#allow")
                .attr("type", "boolean")
                .child(XmlElement::new("value").text("0")),
        )
        .finish()
}

// Service Discovery Response Builders

/// Build the PubSub root service `disco#info` query response.
pub fn build_service_disco_info(server_name: &str) -> String {
    let mut query = XmlElement::namespaced("query", NS_DISCO_INFO)
        .child(
            XmlElement::new("identity")
                .attr("category", "pubsub")
                .attr("type", "service")
                .attr("name", format!("{server_name} PubSub Service")),
        )
        .child(XmlElement::new("feature").attr("var", NS_PUBSUB));

    for feature in SERVICE_FEATURES {
        query.push_child(XmlElement::new("feature").attr(
            "var",
            format!("http://jabber.org/protocol/pubsub#{feature}"),
        ));
    }

    query.finish()
}

/// Build a node-level `disco#info` query response.
pub fn build_node_disco_info(
    node_name: &str,
    node_type: NodeType,
    persist_items: bool,
    metadata_form_xml: &str,
) -> Result<String, PubSubError> {
    let mut query = XmlElement::namespaced("query", NS_DISCO_INFO)
        .attr("node", node_name)
        .child(
            XmlElement::new("identity")
                .attr("category", "pubsub")
                .attr("type", node_type.as_str()),
        )
        .child(XmlElement::new("feature").attr("var", NS_PUBSUB));

    if persist_items && node_type == NodeType::Leaf {
        query.push_child(
            XmlElement::new("feature")
                .attr("var", "http://jabber.org/protocol/pubsub#persistent-items"),
        );
    }

    query.push_child(
        XmlElement::new("feature").attr("var", "http://jabber.org/protocol/pubsub#retrieve-items"),
    );

    query
        .push_validated_fragment(metadata_form_xml)
        .map_err(|_| PubSubError::bad_request())?;

    Ok(query.finish())
}

/// Build a `disco#items` query response payload.
pub fn build_disco_items(
    service_jid: &str,
    requested_node: Option<&str>,
    items: &[DiscoItemWire],
    rsm_xml: Option<&str>,
) -> Result<String, PubSubError> {
    let mut query =
        XmlElement::namespaced("query", NS_DISCO_ITEMS).optional_attr("node", requested_node);

    for item in items {
        if item.published_item {
            // Leaf items use 'name' and omit 'node' per XEP-0060 section 5.5
            let name_val = item.name.as_deref().or(item.node.as_deref());
            query.push_child(
                XmlElement::new("item")
                    .attr("jid", service_jid)
                    .optional_attr("name", name_val),
            );
        } else {
            query.push_child(
                XmlElement::new("item")
                    .attr("jid", service_jid)
                    .optional_attr("node", item.node.as_deref())
                    .optional_attr("name", item.name.as_deref()),
            );
        }
    }

    if let Some(rsm) = rsm_xml {
        query
            .push_validated_fragment(rsm)
            .map_err(|_| PubSubError::bad_request())?;
    }

    Ok(query.finish())
}

#[cfg(test)]
mod tests {
    use super::*;
    use roxmltree::Document;

    #[test]
    fn builds_valid_publish_and_subscribe_responses() {
        let pub_resp = build_publish_response("test-node", &["id1", "id2"]);
        let doc = Document::parse(&pub_resp).unwrap();
        assert_eq!(doc.root_element().tag_name().name(), "pubsub");
        let publish = doc
            .root_element()
            .children()
            .find(|c| c.tag_name().name() == "publish")
            .unwrap();
        assert_eq!(publish.attribute("node"), Some("test-node"));

        let sub_resp = build_subscribe_response(
            "test-node",
            "user@example.com",
            SubscriptionState::Subscribed,
            Some("sub1"),
            None,
        );
        let doc = Document::parse(&sub_resp).unwrap();
        let sub = doc
            .root_element()
            .children()
            .find(|c| c.tag_name().name() == "subscription")
            .unwrap();
        assert_eq!(sub.attribute("subid"), Some("sub1"));
    }

    #[test]
    fn builds_disco_items_with_xep_distinctions() {
        let items = [
            DiscoItemWire {
                jid: "pubsub.example.com".to_owned(),
                node: Some("item-1".to_owned()),
                name: None,
                published_item: true,
            },
            DiscoItemWire {
                jid: "pubsub.example.com".to_owned(),
                node: Some("child-node".to_owned()),
                name: Some("Child Node".to_owned()),
                published_item: false,
            },
        ];

        let xml = build_disco_items("pubsub.example.com", Some("parent"), &items, None).unwrap();
        let doc = Document::parse(&xml).unwrap();
        let mut child_items = doc
            .root_element()
            .children()
            .filter(|c| c.tag_name().name() == "item");

        let first = child_items.next().unwrap();
        assert_eq!(first.attribute("name"), Some("item-1"));
        assert_eq!(first.attribute("node"), None);

        let second = child_items.next().unwrap();
        assert_eq!(second.attribute("node"), Some("child-node"));
        assert_eq!(second.attribute("name"), Some("Child Node"));
    }
}
