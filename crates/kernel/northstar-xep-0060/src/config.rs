//! Node configuration and subscription options validation, normalization, and form transformations.

use crate::constants::{
    MAX_DESCRIPTION_BYTES, MAX_ITEM_XML_BYTES, MAX_PAYLOAD_TYPE_BYTES, MAX_TITLE_BYTES,
    NODE_CONFIG_FORM, NODE_METADATA_FORM, NS_DATA, PUBLISH_OPTIONS_FORM, SUBSCRIBE_OPTIONS_FORM,
};
use crate::error::{invalid_subscription_options, PubSubError};
use crate::models::{
    bool_text, parse_bool, valid_bare_jid, valid_language_tag, valid_node_id, AccessModel,
    ChildrenAssociationPolicy, NodeType, PublishModel, SendLastPublishedItem, ShowValue,
    SubscriptionType,
};
use crate::xml::XmlElement;
use northstar_xmpp_types::CanonicalJid;
use roxmltree::Node;
use std::collections::{BTreeSet, HashMap};

/// Fully validated and typed configuration for a PubSub Node.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeConfig {
    pub access_model: AccessModel,
    pub publish_model: PublishModel,
    pub max_items: u32,
    pub title: Option<String>,
    pub description: Option<String>,
    pub deliver_payloads: bool,
    pub notify_delete: bool,
    pub notify_retract: bool,
    pub persist_items: bool,
    pub send_last_published_item: SendLastPublishedItem,
    pub node_type: NodeType,
    pub deliver_notifications: bool,
    pub notify_config: bool,
    pub notify_sub: bool,
    pub language: Option<String>,
    pub payload_type: Option<String>,
    pub max_payload_size: u32,
    pub children_max: u32,
    pub children_association_policy: ChildrenAssociationPolicy,
    pub children_association_whitelist: Vec<String>,
    pub collections: Vec<String>,
    pub children: Vec<String>,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            access_model: AccessModel::Open,
            publish_model: PublishModel::Publishers,
            max_items: 100,
            title: None,
            description: None,
            deliver_payloads: true,
            notify_delete: true,
            notify_retract: true,
            persist_items: true,
            send_last_published_item: SendLastPublishedItem::OnSubAndPresence,
            node_type: NodeType::Leaf,
            deliver_notifications: true,
            notify_config: true,
            notify_sub: true,
            language: None,
            payload_type: None,
            max_payload_size: MAX_ITEM_XML_BYTES as u32,
            children_max: 1_000,
            children_association_policy: ChildrenAssociationPolicy::Owner,
            children_association_whitelist: Vec::new(),
            collections: Vec::new(),
            children: Vec::new(),
        }
    }
}

impl NodeConfig {
    /// Return the standard collection node defaults.
    pub fn default_collection() -> Self {
        Self {
            node_type: NodeType::Collection,
            persist_items: false,
            deliver_payloads: false,
            send_last_published_item: SendLastPublishedItem::Never,
            ..Self::default()
        }
    }

    /// Enforce deterministic constraints and normalization invariants:
    /// - If `node_type == Collection`, items cannot be persisted or payloads delivered.
    /// - If `node_type != Collection` and `children` is non-empty, error `not-allowed`.
    /// - If `!persist_items`, `send_last_published_item` is set to `Never`.
    pub fn validate_and_normalize(&mut self) -> Result<(), PubSubError> {
        if self.node_type == NodeType::Collection {
            self.persist_items = false;
            self.deliver_payloads = false;
        } else if !self.children.is_empty() {
            return Err(PubSubError::not_allowed());
        }
        if !self.persist_items {
            self.send_last_published_item = SendLastPublishedItem::Never;
        }
        Ok(())
    }
}

/// Check if two `NodeConfig` instances are semantically equivalent.
pub fn config_equivalent(left: &NodeConfig, right: &NodeConfig) -> bool {
    left == right
}

/// Fully validated subscription configuration options.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubscriptionOptions {
    pub deliver: bool,
    pub digest: bool,
    pub digest_frequency: u32,
    pub expire: Option<String>,
    pub include_body: bool,
    pub show_values: Vec<ShowValue>,
    pub subscription_type: SubscriptionType,
    pub subscription_depth: Option<u32>,
}

impl Default for SubscriptionOptions {
    fn default() -> Self {
        Self::for_node_type(NodeType::Leaf)
    }
}

impl SubscriptionOptions {
    /// Construct default subscription options for leaf vs collection nodes.
    pub fn for_node_type(node_type: NodeType) -> Self {
        Self {
            deliver: true,
            digest: false,
            digest_frequency: 86_400_000,
            expire: None,
            include_body: false,
            show_values: ShowValue::ALL.to_vec(),
            subscription_type: match node_type {
                NodeType::Collection => SubscriptionType::Nodes,
                NodeType::Leaf => SubscriptionType::Items,
            },
            subscription_depth: Some(1),
        }
    }
}

/// True if the given payload type namespace represents an Atom feed entry.
pub fn supports_include_body(payload_type: Option<&str>) -> bool {
    payload_type == Some("http://www.w3.org/2005/Atom")
}

// XData Form Parsing Helpers

fn has_only_attributes(node: Node<'_, '_>, allowed: &[&str]) -> bool {
    node.attributes()
        .all(|attribute| attribute.namespace().is_none() && allowed.contains(&attribute.name()))
}

fn has_only_whitespace_text(node: Node<'_, '_>) -> bool {
    node.children()
        .filter(|child| child.is_text())
        .all(|child| child.text().is_none_or(|text| text.trim().is_empty()))
}

fn valid_submit_form_structure(form: Node<'_, '_>) -> bool {
    if form.tag_name().name() != "x"
        || form.tag_name().namespace() != Some(NS_DATA)
        || !has_only_attributes(form, &["type"])
        || form.attribute("type") != Some("submit")
        || !has_only_whitespace_text(form)
    {
        return false;
    }
    let fields = form.children().filter(|child| child.is_element());
    if fields.clone().count() > 100 {
        return false;
    }
    fields.into_iter().all(|field| {
        field.tag_name().name() == "field"
            && field.tag_name().namespace() == Some(NS_DATA)
            && has_only_attributes(field, &["var", "type", "label"])
            && field
                .attribute("var")
                .is_some_and(|var| !var.is_empty() && var.len() <= 256)
            && has_only_whitespace_text(field)
            && field
                .children()
                .filter(|child| child.is_element())
                .all(|value| {
                    value.tag_name().name() == "value"
                        && value.tag_name().namespace() == Some(NS_DATA)
                        && value.attributes().len() == 0
                        && !value.children().any(|child| child.is_element())
                        && value
                            .text()
                            .is_none_or(|text| text.len() <= MAX_ITEM_XML_BYTES)
                })
    })
}

pub fn has_duplicate_fields(form: Node<'_, '_>) -> bool {
    let mut names = BTreeSet::new();
    form.children()
        .filter(|node| {
            node.is_element()
                && node.tag_name().name() == "field"
                && node.tag_name().namespace() == Some(NS_DATA)
        })
        .filter_map(|field| field.attribute("var"))
        .any(|name| !names.insert(name))
}

pub fn data_form_fields(form: Node<'_, '_>) -> HashMap<String, Vec<String>> {
    let mut fields = HashMap::new();
    for field in form.children().filter(|node| {
        node.is_element()
            && node.tag_name().name() == "field"
            && node.tag_name().namespace() == Some(NS_DATA)
    }) {
        let Some(var) = field.attribute("var") else {
            continue;
        };
        let values = field
            .children()
            .filter(|node| {
                node.is_element()
                    && node.tag_name().name() == "value"
                    && node.tag_name().namespace() == Some(NS_DATA)
            })
            .map(|node| node.text().unwrap_or_default().to_owned())
            .collect::<Vec<_>>();
        fields.insert(var.to_owned(), values);
    }
    fields
}

pub fn first_field<'a>(fields: &'a HashMap<String, Vec<String>>, name: &str) -> Option<&'a str> {
    fields.get(name)?.first().map(String::as_str)
}

/// Parse and validate an XData submit form for node configuration (`pubsub#node_config`).
pub fn parse_node_config(
    container: Node<'_, '_>,
    config: NodeConfig,
) -> Result<NodeConfig, PubSubError> {
    parse_node_config_form(container, config, NODE_CONFIG_FORM, false)
}

/// Parse and validate an XData submit form for publish options (`pubsub#publish-options`).
pub fn parse_publish_options(
    container: Node<'_, '_>,
    config: NodeConfig,
) -> Result<NodeConfig, PubSubError> {
    parse_node_config_form(container, config, PUBLISH_OPTIONS_FORM, true)
}

/// Parse and validate an XData submit form for node configuration with explicit form type.
pub fn parse_node_config_form(
    container: Node<'_, '_>,
    mut config: NodeConfig,
    expected_form_type: &str,
    reject_unknown_fields: bool,
) -> Result<NodeConfig, PubSubError> {
    if !has_only_whitespace_text(container) {
        return Err(PubSubError::bad_request());
    }
    let form = if container.tag_name().name() == "x"
        && container.tag_name().namespace() == Some(NS_DATA)
    {
        container
    } else {
        let mut children = container.children().filter(|node| node.is_element());
        let Some(form) = children.next() else {
            return Ok(config);
        };
        if children.next().is_some() {
            return Err(PubSubError::bad_request());
        }
        form
    };
    if !valid_submit_form_structure(form) || form.tag_name().namespace() != Some(NS_DATA) {
        return Err(PubSubError::bad_request());
    }
    if has_duplicate_fields(form) {
        return Err(PubSubError::bad_request());
    }
    let fields = data_form_fields(form);
    for name in [
        "FORM_TYPE",
        "pubsub#access_model",
        "pubsub#publish_model",
        "pubsub#max_items",
        "pubsub#title",
        "pubsub#description",
        "pubsub#deliver_payloads",
        "pubsub#notify_delete",
        "pubsub#notify_retract",
        "pubsub#persist_items",
        "pubsub#send_last_published_item",
        "pubsub#node_type",
        "pubsub#deliver_notifications",
        "pubsub#notify_config",
        "pubsub#notify_sub",
        "pubsub#language",
        "pubsub#type",
        "pubsub#max_payload_size",
        "pubsub#children_max",
        "pubsub#children_association_policy",
    ] {
        if fields.get(name).is_some_and(|values| values.len() != 1) {
            return Err(PubSubError::bad_request());
        }
    }
    if first_field(&fields, "FORM_TYPE") != Some(expected_form_type) {
        return Err(PubSubError::bad_request());
    }
    if reject_unknown_fields {
        const KNOWN: &[&str] = &[
            "FORM_TYPE",
            "pubsub#access_model",
            "pubsub#publish_model",
            "pubsub#max_items",
            "pubsub#title",
            "pubsub#description",
            "pubsub#deliver_payloads",
            "pubsub#notify_delete",
            "pubsub#notify_retract",
            "pubsub#persist_items",
            "pubsub#send_last_published_item",
            "pubsub#node_type",
            "pubsub#deliver_notifications",
            "pubsub#notify_config",
            "pubsub#notify_sub",
            "pubsub#language",
            "pubsub#type",
            "pubsub#max_payload_size",
            "pubsub#children_max",
            "pubsub#children_association_policy",
            "pubsub#children_association_whitelist",
            "pubsub#collection",
            "pubsub#children",
        ];
        if fields.keys().any(|name| !KNOWN.contains(&name.as_str())) {
            return Err(PubSubError::bad_request());
        }
    }
    if let Some(value) = first_field(&fields, "pubsub#access_model") {
        config.access_model = value.parse::<AccessModel>()?;
    }
    if let Some(value) = first_field(&fields, "pubsub#publish_model") {
        config.publish_model = value.parse::<PublishModel>()?;
    }
    if let Some(value) = first_field(&fields, "pubsub#max_items") {
        config.max_items = if value == "max" {
            1_000
        } else {
            value
                .parse::<u32>()
                .ok()
                .filter(|v| (1..=1_000).contains(v))
                .ok_or_else(PubSubError::not_acceptable)?
        };
    }
    if let Some(value) = first_field(&fields, "pubsub#title") {
        if value.len() > MAX_TITLE_BYTES || value.chars().any(char::is_control) {
            return Err(PubSubError::not_acceptable());
        }
        config.title = (!value.is_empty()).then(|| value.to_owned());
    }
    if let Some(value) = first_field(&fields, "pubsub#description") {
        if value.len() > MAX_DESCRIPTION_BYTES || value.chars().any(char::is_control) {
            return Err(PubSubError::not_acceptable());
        }
        config.description = (!value.is_empty()).then(|| value.to_owned());
    }
    for (field, target) in [
        ("pubsub#deliver_payloads", &mut config.deliver_payloads),
        ("pubsub#notify_delete", &mut config.notify_delete),
        ("pubsub#notify_retract", &mut config.notify_retract),
        ("pubsub#persist_items", &mut config.persist_items),
    ] {
        if let Some(value) = first_field(&fields, field) {
            *target = parse_bool(Some(value)).ok_or_else(PubSubError::not_acceptable)?;
        }
    }
    if let Some(value) = first_field(&fields, "pubsub#send_last_published_item") {
        config.send_last_published_item = value.parse::<SendLastPublishedItem>()?;
    }
    if let Some(value) = first_field(&fields, "pubsub#node_type") {
        config.node_type = value.parse::<NodeType>()?;
    }
    for (field, target) in [
        (
            "pubsub#deliver_notifications",
            &mut config.deliver_notifications,
        ),
        ("pubsub#notify_config", &mut config.notify_config),
        ("pubsub#notify_sub", &mut config.notify_sub),
    ] {
        if let Some(value) = first_field(&fields, field) {
            *target = parse_bool(Some(value)).ok_or_else(PubSubError::not_acceptable)?;
        }
    }
    if let Some(value) = first_field(&fields, "pubsub#language") {
        if !value.is_empty() && !valid_language_tag(value) {
            return Err(PubSubError::not_acceptable());
        }
        config.language = (!value.is_empty()).then(|| value.to_owned());
    }
    if let Some(value) = first_field(&fields, "pubsub#type") {
        if value.len() > MAX_PAYLOAD_TYPE_BYTES || value.chars().any(char::is_control) {
            return Err(PubSubError::not_acceptable());
        }
        config.payload_type = (!value.is_empty()).then(|| value.to_owned());
    }
    if let Some(value) = first_field(&fields, "pubsub#max_payload_size") {
        config.max_payload_size = value
            .parse::<u32>()
            .ok()
            .filter(|v| *v <= MAX_ITEM_XML_BYTES as u32)
            .ok_or_else(PubSubError::not_acceptable)?;
    }
    if let Some(value) = first_field(&fields, "pubsub#children_max") {
        config.children_max = if value == "max" {
            1_000
        } else {
            value
                .parse::<u32>()
                .ok()
                .filter(|v| *v <= 1_000)
                .ok_or_else(PubSubError::not_acceptable)?
        };
    }
    if let Some(value) = first_field(&fields, "pubsub#children_association_policy") {
        config.children_association_policy = value.parse::<ChildrenAssociationPolicy>()?;
    }
    if let Some(values) = fields.get("pubsub#children_association_whitelist") {
        if values.len() > 100
            || values
                .iter()
                .any(|jid| !valid_bare_jid(jid) || jid.len() > 3071)
        {
            return Err(PubSubError::not_acceptable());
        }
        config.children_association_whitelist = values
            .iter()
            .map(|jid| {
                CanonicalJid::parse_bare(jid)
                    .map(|c| c.to_string())
                    .map_err(|_| PubSubError::not_acceptable())
            })
            .collect::<Result<Vec<_>, _>>()?;
    }
    for (field, target) in [
        ("pubsub#collection", &mut config.collections),
        ("pubsub#children", &mut config.children),
    ] {
        if let Some(values) = fields.get(field) {
            if values.len() > 1_000
                || values
                    .iter()
                    .any(|node| !node.is_empty() && valid_node_id(Some(node)).is_none())
            {
                return Err(PubSubError::not_acceptable());
            }
            *target = values
                .iter()
                .filter(|node| !node.is_empty())
                .cloned()
                .collect();
        }
    }

    config.validate_and_normalize()?;
    Ok(config)
}

/// Parse and validate an XData submit form for subscription options (`pubsub#subscribe_options`).
pub fn parse_subscription_options(
    form: Node<'_, '_>,
    mut options: SubscriptionOptions,
    node_type: NodeType,
    supports_include_body: bool,
) -> Result<SubscriptionOptions, PubSubError> {
    if !valid_submit_form_structure(form) || has_duplicate_fields(form) {
        return Err(PubSubError::bad_request());
    }
    let fields = data_form_fields(form);
    if first_field(&fields, "FORM_TYPE") != Some(SUBSCRIBE_OPTIONS_FORM) {
        return Err(PubSubError::bad_request());
    }
    for field in [
        "FORM_TYPE",
        "pubsub#deliver",
        "pubsub#digest",
        "pubsub#digest_frequency",
        "pubsub#expire",
        "pubsub#include_body",
        "pubsub#subscription_type",
        "pubsub#subscription_depth",
    ] {
        if fields.get(field).is_some_and(|values| values.len() != 1) {
            return Err(invalid_subscription_options());
        }
    }
    for (field, target) in [
        ("pubsub#deliver", &mut options.deliver),
        ("pubsub#digest", &mut options.digest),
        ("pubsub#include_body", &mut options.include_body),
    ] {
        if let Some(value) = first_field(&fields, field) {
            *target = parse_bool(Some(value)).ok_or_else(invalid_subscription_options)?;
        }
    }
    if options.include_body && !supports_include_body {
        return Err(invalid_subscription_options());
    }
    if let Some(value) = first_field(&fields, "pubsub#digest_frequency") {
        options.digest_frequency = value
            .parse::<u32>()
            .ok()
            .filter(|v| (1_000..=86_400_000).contains(v))
            .ok_or_else(invalid_subscription_options)?;
    }
    if let Some(value) = first_field(&fields, "pubsub#expire") {
        options.expire = if value.is_empty() {
            None
        } else if value == "presence" {
            return Err(invalid_subscription_options());
        } else {
            // Require ISO 8601 / RFC 3339 dateTime format validation
            if value.len() < 20 || value.len() > 64 || !value.contains('T') {
                return Err(invalid_subscription_options());
            }
            Some(value.to_owned())
        };
    }
    if let Some(values) = fields.get("pubsub#show-values") {
        if values.is_empty() || values.len() > 5 {
            return Err(invalid_subscription_options());
        }
        let mut parsed_shows = Vec::with_capacity(values.len());
        for val in values {
            let show = val.parse::<ShowValue>()?;
            if !parsed_shows.contains(&show) {
                parsed_shows.push(show);
            }
        }
        options.show_values = parsed_shows;
    }
    if let Some(value) = first_field(&fields, "pubsub#subscription_type") {
        let valid = match node_type {
            NodeType::Collection => matches!(value, "items" | "nodes" | "all"),
            NodeType::Leaf => value == "items",
        };
        if !valid {
            return Err(invalid_subscription_options());
        }
        options.subscription_type = value.parse::<SubscriptionType>()?;
    }
    if let Some(value) = first_field(&fields, "pubsub#subscription_depth") {
        if node_type != NodeType::Collection {
            return Err(invalid_subscription_options());
        }
        options.subscription_depth = if value == "all" {
            None
        } else {
            Some(
                value
                    .parse::<u32>()
                    .ok()
                    .ok_or_else(invalid_subscription_options)?,
            )
        };
    }
    Ok(options)
}

// XML Data Form Builders

fn data_field_element(
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

/// Render a NodeConfig into a `jabber:x:data` form XML string.
pub fn build_node_config_form(config: &NodeConfig, form_type: &str) -> String {
    let mut form = XmlElement::namespaced("x", NS_DATA)
        .attr("type", form_type)
        .child(data_field_element(
            "FORM_TYPE",
            Some("hidden"),
            [NODE_CONFIG_FORM],
        ))
        .child(data_field_element(
            "pubsub#access_model",
            Some("list-single"),
            [config.access_model.as_str()],
        ))
        .child(data_field_element(
            "pubsub#publish_model",
            Some("list-single"),
            [config.publish_model.as_str()],
        ))
        .child(data_field_element(
            "pubsub#max_items",
            Some("text-single"),
            [config.max_items.to_string()],
        ))
        .child(data_field_element(
            "pubsub#title",
            Some("text-single"),
            [config.title.clone().unwrap_or_default()],
        ))
        .child(data_field_element(
            "pubsub#description",
            Some("text-single"),
            [config.description.clone().unwrap_or_default()],
        ))
        .child(data_field_element(
            "pubsub#deliver_payloads",
            Some("boolean"),
            [bool_text(config.deliver_payloads)],
        ))
        .child(data_field_element(
            "pubsub#notify_delete",
            Some("boolean"),
            [bool_text(config.notify_delete)],
        ))
        .child(data_field_element(
            "pubsub#notify_retract",
            Some("boolean"),
            [bool_text(config.notify_retract)],
        ))
        .child(data_field_element(
            "pubsub#persist_items",
            Some("boolean"),
            [bool_text(config.persist_items)],
        ))
        .child(data_field_element(
            "pubsub#send_last_published_item",
            Some("list-single"),
            [config.send_last_published_item.as_str()],
        ))
        .child(data_field_element(
            "pubsub#node_type",
            Some("list-single"),
            [config.node_type.as_str()],
        ))
        .child(data_field_element(
            "pubsub#deliver_notifications",
            Some("boolean"),
            [bool_text(config.deliver_notifications)],
        ))
        .child(data_field_element(
            "pubsub#notify_config",
            Some("boolean"),
            [bool_text(config.notify_config)],
        ))
        .child(data_field_element(
            "pubsub#notify_sub",
            Some("boolean"),
            [bool_text(config.notify_sub)],
        ))
        .child(data_field_element(
            "pubsub#language",
            Some("text-single"),
            [config.language.clone().unwrap_or_default()],
        ))
        .child(data_field_element(
            "pubsub#type",
            Some("text-single"),
            [config.payload_type.clone().unwrap_or_default()],
        ))
        .child(data_field_element(
            "pubsub#max_payload_size",
            Some("text-single"),
            [config.max_payload_size.to_string()],
        ))
        .child(data_field_element(
            "pubsub#children_max",
            Some("text-single"),
            [config.children_max.to_string()],
        ))
        .child(data_field_element(
            "pubsub#children_association_policy",
            Some("list-single"),
            [config.children_association_policy.wire_value()],
        ));

    if !config.children_association_whitelist.is_empty() {
        form.push_child(data_field_element(
            "pubsub#children_association_whitelist",
            Some("jid-multi"),
            config.children_association_whitelist.iter(),
        ));
    }
    if !config.collections.is_empty() {
        form.push_child(data_field_element(
            "pubsub#collection",
            Some("text-multi"),
            config.collections.iter(),
        ));
    }
    if !config.children.is_empty() {
        form.push_child(data_field_element(
            "pubsub#children",
            Some("text-multi"),
            config.children.iter(),
        ));
    }

    form.finish()
}

/// Render a SubscriptionOptions into a `jabber:x:data` form XML string.
pub fn build_subscription_options_form(
    options: &SubscriptionOptions,
    form_type: &str,
    supports_include_body: bool,
    node_type: NodeType,
) -> String {
    let expiry = options.expire.as_deref().unwrap_or_default();
    let depth = options
        .subscription_depth
        .map(|v| v.to_string())
        .unwrap_or_else(|| "all".to_owned());

    let mut form = XmlElement::namespaced("x", NS_DATA)
        .attr("type", form_type)
        .child(data_field_element(
            "FORM_TYPE",
            Some("hidden"),
            [SUBSCRIBE_OPTIONS_FORM],
        ))
        .child(data_field_element(
            "pubsub#deliver",
            Some("boolean"),
            [bool_text(options.deliver)],
        ))
        .child(data_field_element(
            "pubsub#digest",
            Some("boolean"),
            [bool_text(options.digest)],
        ))
        .child(data_field_element(
            "pubsub#digest_frequency",
            Some("text-single"),
            [options.digest_frequency.to_string()],
        ))
        .child(data_field_element(
            "pubsub#expire",
            Some("text-single"),
            [expiry],
        ));

    if supports_include_body {
        form.push_child(data_field_element(
            "pubsub#include_body",
            Some("boolean"),
            [bool_text(options.include_body)],
        ));
    }

    form.push_child(data_field_element(
        "pubsub#show-values",
        Some("list-multi"),
        options.show_values.iter().map(ShowValue::as_str),
    ));

    if node_type == NodeType::Collection {
        form.push_child(data_field_element(
            "pubsub#subscription_type",
            Some("list-single"),
            [options.subscription_type.as_str()],
        ));
        form.push_child(data_field_element(
            "pubsub#subscription_depth",
            Some("text-single"),
            [depth],
        ));
    }

    form.finish()
}

/// Render the Node Metadata discovery form (`http://jabber.org/protocol/pubsub#meta-data`).
#[allow(clippy::too_many_arguments)]
pub fn build_node_metadata_form(
    node_name: &str,
    title: Option<&str>,
    description: Option<&str>,
    payload_type: Option<&str>,
    creator_jid: &str,
    creation_date_rfc3339: &str,
    language: Option<&str>,
    access_model: AccessModel,
    publish_model: PublishModel,
    max_items: u32,
    num_subscribers: usize,
    owners: &[&str],
    publishers: &[&str],
) -> String {
    let title_val = title.unwrap_or(node_name);
    let desc_val = description.unwrap_or_default();
    let type_val = payload_type.unwrap_or_default();
    let lang_val = language.unwrap_or_default();

    XmlElement::namespaced("x", NS_DATA)
        .attr("type", "result")
        .child(data_field_element(
            "FORM_TYPE",
            Some("hidden"),
            [NODE_METADATA_FORM],
        ))
        .child(data_field_element("pubsub#title", None, [title_val]))
        .child(data_field_element("pubsub#description", None, [desc_val]))
        .child(data_field_element("pubsub#type", None, [type_val]))
        .child(data_field_element("pubsub#creator", None, [creator_jid]))
        .child(data_field_element(
            "pubsub#creation_date",
            None,
            [creation_date_rfc3339],
        ))
        .child(data_field_element("pubsub#language", None, [lang_val]))
        .child(data_field_element(
            "pubsub#access_model",
            None,
            [access_model.as_str()],
        ))
        .child(data_field_element(
            "pubsub#publish_model",
            None,
            [publish_model.as_str()],
        ))
        .child(data_field_element(
            "pubsub#max_items",
            None,
            [max_items.to_string()],
        ))
        .child(data_field_element(
            "pubsub#num_subscribers",
            None,
            [num_subscribers.to_string()],
        ))
        .child(data_field_element(
            "pubsub#owner",
            Some("jid-multi"),
            owners.iter(),
        ))
        .child(data_field_element(
            "pubsub#publisher",
            Some("jid-multi"),
            publishers.iter(),
        ))
        .finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use roxmltree::Document;

    #[test]
    fn parses_and_round_trips_node_config() {
        let mut config = NodeConfig {
            access_model: AccessModel::Authorize,
            max_items: 42,
            persist_items: false,
            ..Default::default()
        };
        config.validate_and_normalize().unwrap();

        let form_xml = build_node_config_form(&config, "submit");
        let doc = Document::parse(&form_xml).unwrap();
        let parsed = parse_node_config(doc.root_element(), NodeConfig::default()).unwrap();

        assert_eq!(parsed.access_model, AccessModel::Authorize);
        assert_eq!(parsed.max_items, 42);
        assert!(!parsed.persist_items);
        assert_eq!(
            parsed.send_last_published_item,
            SendLastPublishedItem::Never
        );
    }

    #[test]
    fn parses_and_round_trips_subscription_options() {
        let options = SubscriptionOptions {
            digest: true,
            digest_frequency: 60_000,
            include_body: true,
            subscription_type: SubscriptionType::All,
            subscription_depth: None,
            show_values: vec![ShowValue::Chat, ShowValue::Online],
            ..SubscriptionOptions::for_node_type(NodeType::Collection)
        };

        let form_xml =
            build_subscription_options_form(&options, "submit", true, NodeType::Collection);
        let doc = Document::parse(&form_xml).unwrap();
        let parsed = parse_subscription_options(
            doc.root_element(),
            SubscriptionOptions::for_node_type(NodeType::Collection),
            NodeType::Collection,
            true,
        )
        .unwrap();

        assert_eq!(parsed, options);
    }
}
