//! PubSub discovery results, configuration forms and event rendering.

use crate::PubSubCollectionDiscoChild;
use anyhow::Result;
use northstar_pubsub_core::{PubSubNodeConfig, PubSubSubscription, PubSubTimeSources};
use northstar_xml_builder::XmlElement;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LeafDiscoItems {
    NotFound,
    NotLeaf,
    Forbidden,
    Items(Vec<String>),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CollectionDiscoItems {
    NotFound,
    NotCollection,
    Forbidden,
    Items(Vec<PubSubCollectionDiscoChild>),
}

#[derive(Clone)]
pub struct PubSubEventRenderer {
    pub(super) service_jid: String,
    pub(super) time: PubSubTimeSources,
}
impl PubSubEventRenderer {
    pub fn new(domain: &str) -> Self {
        Self {
            service_jid: format!("pubsub.{domain}"),
            time: PubSubTimeSources::default(),
        }
    }

    /// Use the same clock and UUID source as the service issuing the mutation.
    pub fn with_time_sources(mut self, time: &PubSubTimeSources) -> Self {
        self.time = time.clone();
        self
    }
}
pub(super) const NS_PUBSUB_EVENT: &str = "http://jabber.org/protocol/pubsub#event";
pub(super) const NS_DATA: &str = "jabber:x:data";
const NODE_CONFIG_FORM: &str = "http://jabber.org/protocol/pubsub#node_config";

fn pubsub_config_field(
    variable: &str,
    field_type: Option<&str>,
    values: impl IntoIterator<Item = impl ToString>,
) -> XmlElement {
    let mut field = XmlElement::new("field")
        .attr("var", variable)
        .optional_attr("type", field_type);
    for value in values {
        field.push_child(XmlElement::new("value").text(value.to_string()));
    }
    field
}

fn pubsub_bool_text(value: bool) -> &'static str {
    if value {
        "true"
    } else {
        "false"
    }
}

/// Render a complete node-configuration form from a locked database snapshot.
/// The same helper is used for owner IQ responses and durable notifications so
/// notification XML cannot be assembled from a pre-lock request object.
pub fn pubsub_node_config_form(config: &PubSubNodeConfig, form_type: &str) -> String {
    let mut form = XmlElement::namespaced("x", NS_DATA).attr("type", form_type);
    form.push_child(pubsub_config_field(
        "FORM_TYPE",
        Some("hidden"),
        [NODE_CONFIG_FORM],
    ));
    for (variable, field_type, value) in [
        (
            "pubsub#title",
            "text-single",
            config.title.clone().unwrap_or_default(),
        ),
        (
            "pubsub#description",
            "text-single",
            config.description.clone().unwrap_or_default(),
        ),
        (
            "pubsub#access_model",
            "list-single",
            config.access_model.clone(),
        ),
        (
            "pubsub#publish_model",
            "list-single",
            config.publish_model.clone(),
        ),
        (
            "pubsub#max_items",
            "text-single",
            config.max_items.to_string(),
        ),
        (
            "pubsub#deliver_notifications",
            "boolean",
            pubsub_bool_text(config.deliver_notifications).to_owned(),
        ),
        (
            "pubsub#deliver_payloads",
            "boolean",
            pubsub_bool_text(config.deliver_payloads).to_owned(),
        ),
        (
            "pubsub#notify_config",
            "boolean",
            pubsub_bool_text(config.notify_config).to_owned(),
        ),
        (
            "pubsub#notify_delete",
            "boolean",
            pubsub_bool_text(config.notify_delete).to_owned(),
        ),
        (
            "pubsub#notify_retract",
            "boolean",
            pubsub_bool_text(config.notify_retract).to_owned(),
        ),
        (
            "pubsub#notify_sub",
            "boolean",
            pubsub_bool_text(config.notify_sub).to_owned(),
        ),
        (
            "pubsub#persist_items",
            "boolean",
            pubsub_bool_text(config.persist_items).to_owned(),
        ),
        (
            "pubsub#send_last_published_item",
            "list-single",
            config.send_last_published_item.clone(),
        ),
        (
            "pubsub#language",
            "text-single",
            config.language.clone().unwrap_or_default(),
        ),
        (
            "pubsub#type",
            "text-single",
            config.payload_type.clone().unwrap_or_default(),
        ),
        (
            "pubsub#max_payload_size",
            "text-single",
            config.max_payload_size.to_string(),
        ),
        ("pubsub#node_type", "list-single", config.node_type.clone()),
    ] {
        form.push_child(pubsub_config_field(variable, Some(field_type), [value]));
    }
    form.push_child(pubsub_config_field(
        "pubsub#collection",
        Some("text-multi"),
        config.collections.iter(),
    ));
    form.push_child(pubsub_config_field(
        "pubsub#children",
        Some("text-multi"),
        config.children.iter(),
    ));
    form.push_child(pubsub_config_field(
        "pubsub#children_max",
        Some("text-single"),
        [config.children_max.to_string()],
    ));
    form.push_child(pubsub_config_field(
        "pubsub#children_association_policy",
        Some("list-single"),
        [if config.children_association_policy == "owner" {
            "owners"
        } else {
            &config.children_association_policy
        }],
    ));
    form.push_child(pubsub_config_field(
        "pubsub#children_association_whitelist",
        Some("jid-multi"),
        config.children_association_whitelist.iter(),
    ));
    form.finish()
}
pub(super) const SUBSCRIBE_AUTH_FORM: &str =
    "http://jabber.org/protocol/pubsub#subscribe_authorization";

pub fn subscription_event_children(
    subscription: &PubSubSubscription,
    event: &str,
    collection: Option<&str>,
    delay: Option<northstar_time::DateTime<northstar_time::Utc>>,
) -> Result<String> {
    let body = if subscription.include_body {
        northstar_xep_0060::extract_atom_event_body(event)
            .map_err(|error| anyhow::anyhow!(error.to_string()))?
    } else {
        None
    };
    let stamp = delay.map(|stamp| stamp.to_rfc3339());
    northstar_xep_0060::build_subscription_event_children(
        event,
        &subscription.subid,
        collection,
        body.as_deref(),
        stamp.as_deref(),
    )
    .map_err(|error| anyhow::anyhow!(error.to_string()))
}
