//! Strict XML wire parsing, item serialization, and Atom summary extraction for XEP-0060.

use crate::config::{
    has_duplicate_fields, parse_node_config, parse_publish_options, parse_subscription_options,
    NodeConfig, SubscriptionOptions,
};
use crate::constants::{
    MAX_ATOM_BODY_BYTES, MAX_ITEM_XML_BYTES, MAX_PUBLISH_ITEMS, MAX_PUBLISH_XML_BYTES, NS_DATA,
    NS_PUBSUB, NS_PUBSUB_OWNER, NS_RSM, SUBSCRIBE_AUTH_FORM,
};
use crate::error::PubSubError;
use crate::models::{parse_bool, required_node_id, valid_item_id, valid_node_id, NodeType};
use crate::rsm::parse_rsm_element;
use crate::wire::*;
use crate::xml::{attr_escape, escape_xml_text, validate_qname};
use northstar_xmpp_types::CanonicalJid;
use roxmltree::Node;
use std::collections::BTreeSet;

/// Identifies the namespace scope of an incoming `<pubsub>` envelope.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EnvelopeNamespace {
    Entity,
    Owner,
}

/// Parsed wrapper containing the envelope namespace and child operation nodes.
#[derive(Debug)]
pub struct ParsedPubSubEnvelope<'a, 'input> {
    pub namespace: EnvelopeNamespace,
    pub operations: Vec<Node<'a, 'input>>,
}

fn has_only_attributes(node: Node<'_, '_>, allowed: &[&str]) -> bool {
    node.attributes()
        .all(|attribute| attribute.namespace().is_none() && allowed.contains(&attribute.name()))
}

fn has_only_whitespace_text(node: Node<'_, '_>) -> bool {
    node.children()
        .filter(|child| child.is_text())
        .all(|child| child.text().is_none_or(|text| text.trim().is_empty()))
}

fn has_no_element_content(node: Node<'_, '_>) -> bool {
    has_only_whitespace_text(node) && !node.children().any(|child| child.is_element())
}

fn single_element_child<'a, 'input>(node: Node<'a, 'input>) -> Option<Node<'a, 'input>> {
    if !has_only_whitespace_text(node) {
        return None;
    }
    let mut children = node.children().filter(|child| child.is_element());
    let child = children.next()?;
    children.next().is_none().then_some(child)
}

/// Parse the top-level `<pubsub>` envelope element for `get` or `set` IQ stanzas.
pub fn parse_pubsub_envelope<'a, 'input>(
    child: Node<'a, 'input>,
    kind: &str,
) -> Result<ParsedPubSubEnvelope<'a, 'input>, PubSubError> {
    let namespace = child.tag_name().namespace().unwrap_or_default();
    if child.tag_name().name() != "pubsub" {
        return Err(PubSubError::simple("feature-not-implemented"));
    }
    if !has_only_whitespace_text(child) {
        return Err(PubSubError::bad_request());
    }
    let operations = child
        .children()
        .filter(|node| node.is_element())
        .collect::<Vec<_>>();
    if operations.is_empty() {
        return Err(PubSubError::bad_request());
    }
    let rsm_count = operations
        .iter()
        .filter(|operation| {
            operation.tag_name().name() == "set" && operation.tag_name().namespace() == Some(NS_RSM)
        })
        .count();
    if rsm_count > 1
        || operations.iter().any(|operation| {
            operation.tag_name().namespace() != Some(namespace)
                && !(kind == "get"
                    && namespace == NS_PUBSUB
                    && operation.tag_name().name() == "set"
                    && operation.tag_name().namespace() == Some(NS_RSM))
        })
    {
        return Err(PubSubError::bad_request());
    }
    let namespace_enum = match (namespace, kind) {
        (NS_PUBSUB, "get" | "set") => EnvelopeNamespace::Entity,
        (NS_PUBSUB_OWNER, "get" | "set") => EnvelopeNamespace::Owner,
        _ => return Err(PubSubError::simple("feature-not-implemented")),
    };
    Ok(ParsedPubSubEnvelope {
        namespace: namespace_enum,
        operations,
    })
}

/// Parse a `<create>` operation from an `iq[type=set]` envelope.
pub fn parse_create_operation(
    operations: &[Node<'_, '_>],
) -> Result<CreateNodeRequest, PubSubError> {
    let primary = operations[0];
    if operations.len() > 2
        || operations
            .get(1)
            .is_some_and(|node| node.tag_name().name() != "configure")
    {
        return Err(PubSubError::bad_request());
    }
    if !has_only_attributes(primary, &["node"]) || !has_no_element_content(primary) {
        return Err(PubSubError::bad_request());
    }
    let node = match primary.attribute("node") {
        Some(value) => {
            let Some(val) = valid_node_id(Some(value)) else {
                return Err(PubSubError::bad_request());
            };
            Some(val.to_owned())
        }
        None => None,
    };
    let mut configure = None;
    if let Some(config_node) = operations.get(1) {
        if !has_only_attributes(*config_node, &[]) {
            return Err(PubSubError::bad_request());
        }
        let parsed = parse_node_config(*config_node, NodeConfig::default())?;
        configure = Some(parsed);
    }
    Ok(CreateNodeRequest { node, configure })
}

/// Parse a `<publish>` operation from an `iq[type=set]` envelope.
pub fn parse_publish_operation(operations: &[Node<'_, '_>]) -> Result<PublishRequest, PubSubError> {
    let primary = operations[0];
    if operations.len() > 2
        || operations
            .get(1)
            .is_some_and(|node| node.tag_name().name() != "publish-options")
    {
        return Err(PubSubError::bad_request());
    }
    if !has_only_attributes(primary, &["node"])
        || operations
            .get(1)
            .is_some_and(|options| !has_only_attributes(*options, &[]))
    {
        return Err(PubSubError::bad_request());
    }
    let node_name = required_node_id(primary.attribute("node"))?;
    let publish_options = if let Some(options_node) = operations.get(1) {
        Some(parse_publish_options(*options_node, NodeConfig::default())?)
    } else {
        None
    };

    let item_nodes: Vec<_> = primary
        .children()
        .filter(|node| node.is_element())
        .collect();
    if item_nodes.len() > MAX_PUBLISH_ITEMS {
        return Err(PubSubError::bad_request());
    }

    let mut items = Vec::with_capacity(item_nodes.len());
    let mut seen_item_ids = BTreeSet::new();
    let mut total_bytes = 0usize;

    for item_node in item_nodes {
        let payload_count = item_node
            .children()
            .filter(|node| node.is_element())
            .count();
        if item_node.tag_name().name() != "item"
            || item_node.tag_name().namespace() != Some(NS_PUBSUB)
            || item_node
                .attributes()
                .any(|attribute| attribute.namespace().is_some() || attribute.name() != "id")
        {
            return Err(PubSubError::bad_request());
        }
        if payload_count > 1 {
            return Err(PubSubError::new("bad-request", "invalid-payload"));
        }
        let item_id = item_node
            .attribute("id")
            .map(ToOwned::to_owned)
            .unwrap_or_else(|| "".to_owned());
        if !item_id.is_empty() && !valid_item_id(&item_id) {
            return Err(PubSubError::bad_request());
        }
        if !item_id.is_empty() && !seen_item_ids.insert(item_id.clone()) {
            return Err(PubSubError::bad_request());
        }
        let item_xml = serialize_pubsub_item(item_node, &item_id)?;
        total_bytes = total_bytes.saturating_add(item_xml.len());
        if item_xml.len() > MAX_ITEM_XML_BYTES || total_bytes > MAX_PUBLISH_XML_BYTES {
            return Err(PubSubError::policy_violation());
        }
        items.push(PublishItemWire {
            id: item_id,
            payload_xml: item_xml,
        });
    }

    Ok(PublishRequest {
        node: node_name.to_owned(),
        items,
        publish_options,
    })
}

/// Parse a `<retract>` operation from an `iq[type=set]` envelope.
pub fn parse_retract_operation(operations: &[Node<'_, '_>]) -> Result<RetractRequest, PubSubError> {
    if operations.len() != 1 {
        return Err(PubSubError::bad_request());
    }
    let primary = operations[0];
    if !has_only_attributes(primary, &["node", "notify"]) {
        return Err(PubSubError::bad_request());
    }
    let notify = match primary.attribute("notify") {
        Some(value) => parse_bool(Some(value)).ok_or_else(PubSubError::bad_request)?,
        None => false,
    };
    let node = required_node_id(primary.attribute("node"))?.to_owned();
    let mut item_ids = BTreeSet::new();
    for item in primary.children().filter(|node| node.is_element()) {
        if item.tag_name().name() != "item"
            || item.tag_name().namespace() != Some(NS_PUBSUB)
            || item
                .attributes()
                .any(|attribute| attribute.namespace().is_some() || attribute.name() != "id")
            || item.children().any(|child| {
                child.is_element() || child.text().is_some_and(|text| !text.trim().is_empty())
            })
        {
            return Err(PubSubError::bad_request());
        }
        let Some(item_id) = item.attribute("id").filter(|value| valid_item_id(value)) else {
            return Err(PubSubError::bad_request());
        };
        if !item_ids.insert(item_id.to_owned()) {
            return Err(PubSubError::bad_request());
        }
    }
    if item_ids.is_empty() {
        return Err(PubSubError::new("bad-request", "item-required"));
    }
    Ok(RetractRequest {
        node,
        item_ids: item_ids.into_iter().collect(),
        notify,
    })
}

/// Parse a `<subscribe>` operation from an `iq[type=set]` envelope.
pub fn parse_subscribe_operation(
    operations: &[Node<'_, '_>],
    node_type: NodeType,
    supports_include_body: bool,
) -> Result<SubscribeRequest, PubSubError> {
    let primary = operations[0];
    if operations.len() > 2
        || operations
            .get(1)
            .is_some_and(|operation| operation.tag_name().name() != "options")
    {
        return Err(PubSubError::bad_request());
    }
    if !has_only_attributes(primary, &["node", "jid"])
        || !has_no_element_content(primary)
        || operations.get(1).is_some_and(|options| {
            !has_only_attributes(*options, &[]) || single_element_child(*options).is_none()
        })
    {
        return Err(PubSubError::bad_request());
    }
    let node = required_node_id(primary.attribute("node"))?.to_owned();
    let Some(raw_jid) = primary.attribute("jid") else {
        return Err(PubSubError::new("bad-request", "jid-required"));
    };
    let canonical_jid =
        CanonicalJid::parse(raw_jid).map_err(|_| PubSubError::new("bad-request", "invalid-jid"))?;
    let jid = canonical_jid.to_string();

    let options = if let Some(options_node) = operations.get(1) {
        let form = single_element_child(*options_node).ok_or_else(PubSubError::bad_request)?;
        let parsed = parse_subscription_options(
            form,
            SubscriptionOptions::for_node_type(node_type),
            node_type,
            supports_include_body,
        )?;
        Some(parsed)
    } else {
        None
    };

    Ok(SubscribeRequest { node, jid, options })
}

/// Parse an `<unsubscribe>` operation from an `iq[type=set]` envelope.
pub fn parse_unsubscribe_operation(
    operations: &[Node<'_, '_>],
) -> Result<UnsubscribeRequest, PubSubError> {
    if operations.len() != 1 {
        return Err(PubSubError::bad_request());
    }
    let primary = operations[0];
    if !has_only_attributes(primary, &["node", "jid", "subid"]) || !has_no_element_content(primary)
    {
        return Err(PubSubError::bad_request());
    }
    let node = required_node_id(primary.attribute("node"))?.to_owned();
    let Some(raw_jid) = primary.attribute("jid") else {
        return Err(PubSubError::new("bad-request", "jid-required"));
    };
    let canonical_jid =
        CanonicalJid::parse(raw_jid).map_err(|_| PubSubError::new("bad-request", "invalid-jid"))?;
    let jid = canonical_jid.to_string();
    let subid = primary.attribute("subid").map(ToOwned::to_owned);

    Ok(UnsubscribeRequest { node, jid, subid })
}

/// Parse an `<items>` operation from an `iq[type=get]` envelope.
pub fn parse_get_items_operation(
    operations: &[Node<'_, '_>],
) -> Result<GetItemsRequest, PubSubError> {
    let rsm_node = operations.iter().find(|node| {
        node.tag_name().name() == "set" && node.tag_name().namespace() == Some(NS_RSM)
    });
    let primary = operations
        .iter()
        .filter(|node| node.tag_name().namespace() == Some(NS_PUBSUB))
        .copied()
        .collect::<Vec<_>>();
    if primary.len() != 1 {
        return Err(PubSubError::bad_request());
    }
    let op = primary[0];
    if !has_only_attributes(op, &["node", "max_items", "subid"]) {
        return Err(PubSubError::bad_request());
    }
    let rsm = match rsm_node {
        Some(set) => Some(parse_rsm_element(*set)?),
        None => None,
    };
    let node = required_node_id(op.attribute("node"))?.to_owned();
    let max_items = match op.attribute("max_items") {
        Some(val) => {
            let parsed = val.parse::<u32>().map_err(|_| PubSubError::bad_request())?;
            if parsed == 0 {
                return Err(PubSubError::bad_request());
            }
            Some(parsed)
        }
        None => None,
    };
    let subid = op.attribute("subid").map(ToOwned::to_owned);

    let mut item_ids = Vec::new();
    let mut unique_item_ids = BTreeSet::new();
    for item in op.children().filter(|node| node.is_element()) {
        if item.tag_name().name() != "item"
            || item.tag_name().namespace() != Some(NS_PUBSUB)
            || item
                .attributes()
                .any(|attribute| attribute.namespace().is_some() || attribute.name() != "id")
            || item.children().any(|child| {
                child.is_element() || child.text().is_some_and(|text| !text.trim().is_empty())
            })
        {
            return Err(PubSubError::bad_request());
        }
        let Some(item_id) = item.attribute("id").filter(|v| valid_item_id(v)) else {
            return Err(PubSubError::bad_request());
        };
        if !unique_item_ids.insert(item_id) {
            return Err(PubSubError::bad_request());
        }
        item_ids.push(item_id.to_owned());
    }

    if rsm.is_some() && (!item_ids.is_empty() || op.attribute("max_items").is_some()) {
        return Err(PubSubError::bad_request());
    }

    Ok(GetItemsRequest {
        node,
        max_items,
        subid,
        item_ids,
        rsm,
    })
}

/// Serialize and normalize an item XML node into canonical string form for storage.
///
/// Strips the top-level `xmlns='http://jabber.org/protocol/pubsub'` namespace declaration
/// so that the stored item inherits `pubsub` on IQ get and `pubsub#event` on notifications.
pub fn serialize_pubsub_item(node: Node<'_, '_>, item_id: &str) -> Result<String, PubSubError> {
    fn prefix_for(node: Node<'_, '_>, namespace: &str, attribute: bool) -> Option<String> {
        if namespace == "http://www.w3.org/XML/1998/namespace" {
            return Some("xml".to_owned());
        }
        if !attribute && node.default_namespace() == Some(namespace) {
            return Some(String::new());
        }
        node.namespaces()
            .find(|binding| binding.uri() == namespace && binding.name().is_some())
            .and_then(|binding| binding.name())
            .map(ToOwned::to_owned)
    }

    fn write_element(
        node: Node<'_, '_>,
        output: &mut String,
        root_item_id: Option<&str>,
    ) -> Result<(), PubSubError> {
        let namespace = node.tag_name().namespace();
        let prefix = namespace
            .map(|ns| prefix_for(node, ns, false).ok_or_else(PubSubError::bad_request))
            .transpose()?
            .unwrap_or_default();
        let qualified = if prefix.is_empty() {
            node.tag_name().name().to_owned()
        } else {
            format!("{prefix}:{}", node.tag_name().name())
        };
        validate_qname(&qualified).map_err(|_| PubSubError::bad_request())?;
        output.push('<');
        output.push_str(&qualified);

        for binding in node.namespaces() {
            if root_item_id.is_some() && binding.name().is_none() && binding.uri() == NS_PUBSUB {
                continue;
            }
            if let Some(prefix) = binding.name() {
                let namespace_attribute = format!("xmlns:{prefix}");
                validate_qname(&namespace_attribute).map_err(|_| PubSubError::bad_request())?;
                output.push_str(&format!(
                    " xmlns:{}='{}'",
                    prefix,
                    attr_escape(binding.uri())
                ));
            } else {
                output.push_str(&format!(" xmlns='{}'", attr_escape(binding.uri())));
            }
        }

        let mut has_id = false;
        for attribute in node.attributes() {
            let is_id = attribute.namespace().is_none() && attribute.name() == "id";
            has_id |= is_id;
            let value = if is_id {
                root_item_id.unwrap_or(attribute.value())
            } else {
                attribute.value()
            };
            let name = if let Some(ns) = attribute.namespace() {
                let prefix = prefix_for(node, ns, true).ok_or_else(PubSubError::bad_request)?;
                format!("{prefix}:{}", attribute.name())
            } else {
                attribute.name().to_owned()
            };
            validate_qname(&name).map_err(|_| PubSubError::bad_request())?;
            output.push_str(&format!(" {}='{}'", name, attr_escape(value)));
        }

        if root_item_id.is_some() && !has_id {
            output.push_str(&format!(
                " id='{}'",
                attr_escape(root_item_id.unwrap_or_default())
            ));
        }

        output.push('>');
        for child in node.children() {
            if child.is_element() {
                write_element(child, output, None)?;
            } else if child.is_text() {
                escape_xml_text(output, child.text().unwrap_or_default());
            }
        }
        output.push_str("</");
        output.push_str(&qualified);
        output.push('>');
        Ok(())
    }

    let mut output = String::new();
    write_element(node, &mut output, Some(item_id))?;
    if output.len() > MAX_ITEM_XML_BYTES {
        return Err(PubSubError::new("not-acceptable", "payload-too-big"));
    }
    Ok(output)
}

/// Parse an authorization form submission from a node owner (`pubsub#subscribe_authorization`).
pub fn parse_subscription_auth_response(
    message: Node<'_, '_>,
) -> Result<Option<SubscriptionAuthResponse>, PubSubError> {
    let mut forms = message.children().filter(|node| {
        node.is_element()
            && node.tag_name().name() == "x"
            && node.tag_name().namespace() == Some(NS_DATA)
            && node.attribute("type") == Some("submit")
    });
    let Some(form) = forms.next() else {
        return Ok(None);
    };
    if forms.next().is_some() || has_duplicate_fields(form) {
        return Err(PubSubError::bad_request());
    }

    let fields = crate::config::data_form_fields(form);
    const AUTH_FIELDS: &[&str] = &[
        "FORM_TYPE",
        "pubsub#node",
        "pubsub#subscriber_jid",
        "pubsub#subid",
        "pubsub#allow",
    ];

    if fields
        .keys()
        .any(|field| !AUTH_FIELDS.contains(&field.as_str()))
        || AUTH_FIELDS
            .iter()
            .filter_map(|field| fields.get(*field))
            .any(|values| values.len() != 1)
    {
        return Err(PubSubError::bad_request());
    }

    if crate::config::first_field(&fields, "FORM_TYPE") != Some(SUBSCRIBE_AUTH_FORM) {
        return Err(PubSubError::bad_request());
    }

    let Some(node_name) =
        crate::config::first_field(&fields, "pubsub#node").and_then(|v| valid_node_id(Some(v)))
    else {
        return Err(PubSubError::bad_request());
    };

    let Some(subscriber_raw) = crate::config::first_field(&fields, "pubsub#subscriber_jid") else {
        return Err(PubSubError::bad_request());
    };
    let subscriber = CanonicalJid::parse(subscriber_raw)
        .map_err(|_| PubSubError::bad_request())?
        .to_string();

    let Some(allow) =
        crate::config::first_field(&fields, "pubsub#allow").and_then(|v| parse_bool(Some(v)))
    else {
        return Err(PubSubError::bad_request());
    };

    let subid = crate::config::first_field(&fields, "pubsub#subid").map(ToOwned::to_owned);

    Ok(Some(SubscriptionAuthResponse {
        node: node_name.to_owned(),
        subscriber_jid: subscriber,
        subid,
        allow,
    }))
}

/// Extract Atom entry summary/title/content body from an event payload.
pub fn extract_atom_event_body(event_xml: &str) -> Result<Option<String>, PubSubError> {
    let wrapped = format!("<_root_>{event_xml}</_root_>");
    let doc = roxmltree::Document::parse(&wrapped).map_err(|_| PubSubError::bad_request())?;
    let Some(entry) = doc.descendants().find(|node| {
        node.is_element()
            && node.tag_name().name() == "entry"
            && node.tag_name().namespace() == Some("http://www.w3.org/2005/Atom")
    }) else {
        return Ok(None);
    };
    let Some(source) = ["summary", "title", "content"]
        .into_iter()
        .find_map(|name| {
            entry.children().find(|node| {
                node.is_element()
                    && node.tag_name().name() == name
                    && node.tag_name().namespace() == Some("http://www.w3.org/2005/Atom")
            })
        })
    else {
        return Ok(None);
    };

    let mut body = String::new();
    for text in source
        .descendants()
        .filter(|node| node.is_text())
        .filter_map(|node| node.text())
    {
        let text = text.trim();
        if text.is_empty() {
            continue;
        }
        if !body.is_empty() {
            body.push(' ');
        }
        body.push_str(text);
        if body.len() >= MAX_ATOM_BODY_BYTES {
            truncate_utf8_to_bytes(&mut body, MAX_ATOM_BODY_BYTES);
            break;
        }
    }
    Ok((!body.is_empty()).then_some(body))
}

/// Truncate a UTF-8 string at or before `max_bytes` on a valid character boundary.
pub fn truncate_utf8_to_bytes(s: &mut String, max_bytes: usize) {
    if s.len() <= max_bytes {
        return;
    }
    let mut boundary = max_bytes;
    while boundary > 0 && !s.is_char_boundary(boundary) {
        boundary -= 1;
    }
    s.truncate(boundary);
}

/// True if a serialized item payload matches the expected XML namespace.
pub fn serialized_item_payload_matches_type(item_xml: &str, expected_namespace: &str) -> bool {
    roxmltree::Document::parse(item_xml)
        .ok()
        .is_some_and(|document| {
            document
                .root_element()
                .children()
                .find(Node::is_element)
                .and_then(|payload| payload.tag_name().namespace())
                == Some(expected_namespace)
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use roxmltree::Document;

    #[test]
    fn parses_create_and_publish_envelopes() {
        let xml =
            "<pubsub xmlns='http://jabber.org/protocol/pubsub'><create node='test'/></pubsub>";
        let doc = Document::parse(xml).unwrap();
        let env = parse_pubsub_envelope(doc.root_element(), "set").unwrap();
        assert_eq!(env.namespace, EnvelopeNamespace::Entity);
        let req = parse_create_operation(&env.operations).unwrap();
        assert_eq!(req.node.as_deref(), Some("test"));
    }

    #[test]
    fn serializes_pubsub_items_cleanly() {
        let xml = "<item xmlns='http://jabber.org/protocol/pubsub' id='item-1'><payload xmlns='urn:test'>data &amp; text</payload></item>";
        let doc = Document::parse(xml).unwrap();
        let serialized = serialize_pubsub_item(doc.root_element(), "normalized-id").unwrap();
        assert_eq!(
            serialized,
            "<item id='normalized-id'><payload xmlns='urn:test'>data &amp; text</payload></item>"
        );
    }

    #[test]
    fn extracts_atom_summary_with_utf8_boundary_safety() {
        let atom = "<entry xmlns='http://www.w3.org/2005/Atom'><title>Hello World</title></entry>";
        let body = extract_atom_event_body(atom).unwrap();
        assert_eq!(body.as_deref(), Some("Hello World"));
    }
}
