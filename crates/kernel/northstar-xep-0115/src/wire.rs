//! Strict XML wire parsing and building for presence `<c>` and disco#info payloads.

use crate::constants::*;
use crate::error::CapsError;
use crate::model::{CapsAdvertisement, DiscoInfo, ExtendedForm, Feature, FormField, Identity};
use northstar_xml_builder::XmlElement;
use roxmltree::{Document, Node};
use std::collections::HashSet;

/// Parses a `<c xmlns='http://jabber.org/protocol/caps'/>` child from an enclosing `<presence>` stanza node.
///
/// Returns `Ok(None)` if no caps element is present.
/// Returns `Err(CapsError)` if the caps element is malformed or invalid.
pub fn parse_caps_from_presence<'a, 'input>(
    presence: Node<'a, 'input>,
) -> Result<Option<CapsAdvertisement>, CapsError> {
    let caps_nodes: Vec<Node<'a, 'input>> = presence
        .children()
        .filter(|node| {
            node.is_element()
                && node.tag_name().name() == "c"
                && node.tag_name().namespace() == Some(CAPS_NS)
        })
        .collect();

    if caps_nodes.is_empty() {
        return Ok(None);
    }
    if caps_nodes.len() > 1 {
        return Err(CapsError::MalformedXml(
            "multiple <c> caps elements found in presence".to_owned(),
        ));
    }

    let caps_node = caps_nodes[0];
    parse_caps_element(caps_node).map(Some)
}

/// Parses a standalone `<c xmlns='http://jabber.org/protocol/caps'/>` XML element.
pub fn parse_caps_element(caps_node: Node<'_, '_>) -> Result<CapsAdvertisement, CapsError> {
    if caps_node.tag_name().name() != "c" || caps_node.tag_name().namespace() != Some(CAPS_NS) {
        return Err(CapsError::UnexpectedRootElement {
            expected: "c",
            found: caps_node.tag_name().name().to_owned(),
        });
    }

    let node = caps_node
        .attribute("node")
        .ok_or(CapsError::MissingAttribute("node"))?;
    let ver = caps_node
        .attribute("ver")
        .ok_or(CapsError::MissingAttribute("ver"))?;
    let hash = caps_node.attribute("hash");
    let ext = caps_node.attribute("ext");

    CapsAdvertisement::new(node, ver, hash, ext)
}

/// Parses a `<c .../>` XML string directly into a `CapsAdvertisement`.
pub fn parse_caps_xml(xml: &str) -> Result<CapsAdvertisement, CapsError> {
    let doc = Document::parse(xml).map_err(|err| CapsError::MalformedXml(err.to_string()))?;
    parse_caps_element(doc.root_element())
}

/// Builds a `<c xmlns='http://jabber.org/protocol/caps' .../>` XML string from a `CapsAdvertisement`.
pub fn build_caps_element(caps: &CapsAdvertisement) -> String {
    XmlElement::namespaced("c", CAPS_NS)
        .optional_attr("hash", caps.hash.as_deref())
        .attr("node", &caps.node)
        .attr("ver", &caps.ver)
        .optional_attr("ext", caps.ext.as_deref())
        .finish()
}

/// Parses a `<query xmlns='http://jabber.org/protocol/disco#info'/>` XML node into `DiscoInfo`.
pub fn parse_disco_info_element(query_node: Node<'_, '_>) -> Result<DiscoInfo, CapsError> {
    if query_node.tag_name().name() != "query"
        || query_node.tag_name().namespace() != Some(DISCO_INFO_NS)
    {
        return Err(CapsError::UnexpectedRootElement {
            expected: "query",
            found: query_node.tag_name().name().to_owned(),
        });
    }

    let node_attr = query_node.attribute("node").map(str::to_owned);

    let mut identities = Vec::new();
    let mut features = Vec::new();
    let mut forms = Vec::new();

    let mut total_children = 0;

    for child in query_node.children().filter(Node::is_element) {
        total_children += 1;
        if total_children > MAX_DISCO_CHILDREN {
            return Err(CapsError::TooManyChildren {
                count: total_children,
                limit: MAX_DISCO_CHILDREN,
            });
        }

        match (child.tag_name().name(), child.tag_name().namespace()) {
            ("identity", Some(DISCO_INFO_NS)) => {
                let category = child
                    .attribute("category")
                    .ok_or(CapsError::MissingAttribute("category"))?;
                let kind = child
                    .attribute("type")
                    .ok_or(CapsError::MissingAttribute("type"))?;
                let lang = child
                    .attribute((XML_NS, "lang"))
                    .or_else(|| child.attribute("xml:lang"));
                let name = child.attribute("name");

                let identity = Identity::new(category, kind, lang, name)?;
                identities.push(identity);
            }
            ("feature", Some(DISCO_INFO_NS)) => {
                let var = child
                    .attribute("var")
                    .ok_or(CapsError::MissingAttribute("var"))?;
                let feature = Feature::new(var)?;
                features.push(feature);
            }
            ("x", Some(DATA_NS)) if child.attribute("type") == Some("result") => {
                if let Some(form) = parse_data_form(child)? {
                    forms.push(form);
                }
            }
            _ => {
                // Other extension elements are ignored per XEP-0115 / XEP-0030
            }
        }
    }

    DiscoInfo::new(node_attr, identities, features, forms)
}

/// Parses an extended service discovery `<x xmlns='jabber:x:data' type='result'>` node.
fn parse_data_form(form_node: Node<'_, '_>) -> Result<Option<ExtendedForm>, CapsError> {
    let form_type_fields: Vec<Node<'_, '_>> = form_node
        .children()
        .filter(|node| {
            node.is_element()
                && node.tag_name().name() == "field"
                && node.tag_name().namespace() == Some(DATA_NS)
                && node.attribute("var") == Some("FORM_TYPE")
        })
        .collect();

    if form_type_fields.len() > 1 {
        return Err(CapsError::AmbiguousFormType);
    }

    let Some(form_type_field) = form_type_fields.first().copied() else {
        // Forms without FORM_TYPE are ignored according to XEP-0115 Section 5.3
        return Ok(None);
    };

    if form_type_field.attribute("type") != Some("hidden") {
        // FORM_TYPE must be hidden
        return Ok(None);
    };

    let form_type_values: Vec<String> = form_type_field
        .children()
        .filter(|node| {
            node.is_element()
                && node.tag_name().name() == "value"
                && node.tag_name().namespace() == Some(DATA_NS)
        })
        .map(|node| node.text().unwrap_or_default().to_owned())
        .take(MAX_DISCO_CHILDREN + 1)
        .collect();

    if form_type_values.is_empty() || form_type_values.len() > MAX_DISCO_CHILDREN {
        return Ok(None);
    }

    // Check if multiple differing FORM_TYPE values exist
    let first_val = &form_type_values[0];
    if form_type_values.iter().any(|v| v != first_val) {
        return Err(CapsError::AmbiguousFormType);
    }
    let form_type = first_val.clone();

    let mut fields = Vec::new();
    let mut seen_vars = HashSet::new();

    for field_node in form_node.children().filter(|node| {
        node.is_element()
            && node.tag_name().name() == "field"
            && node.tag_name().namespace() == Some(DATA_NS)
    }) {
        let var = field_node
            .attribute("var")
            .ok_or(CapsError::MissingAttribute("var"))?;

        if !seen_vars.insert(var.to_owned()) {
            return Err(CapsError::DuplicateFormField(var.to_owned()));
        }

        if var == "FORM_TYPE" {
            continue;
        }

        let mut values = Vec::new();
        for val_node in field_node.children().filter(|node| {
            node.is_element()
                && node.tag_name().name() == "value"
                && node.tag_name().namespace() == Some(DATA_NS)
        }) {
            values.push(val_node.text().unwrap_or_default().to_owned());
        }

        fields.push(FormField::new(var, values)?);
    }

    ExtendedForm::new(form_type, fields).map(Some)
}

/// Parses a `<query xmlns='http://jabber.org/protocol/disco#info' ...>` XML string.
pub fn parse_disco_info_xml(xml: &str) -> Result<DiscoInfo, CapsError> {
    if xml.len() > MAX_DISCO_PAYLOAD_BYTES {
        return Err(CapsError::OversizedPayload {
            size: xml.len(),
            limit: MAX_DISCO_PAYLOAD_BYTES,
        });
    }
    let doc = Document::parse(xml).map_err(|err| CapsError::MalformedXml(err.to_string()))?;
    parse_disco_info_element(doc.root_element())
}

/// Builds a `<query xmlns='http://jabber.org/protocol/disco#info' ...>` XML element from `DiscoInfo`.
pub fn build_disco_info_query(disco: &DiscoInfo) -> String {
    let mut query =
        XmlElement::namespaced("query", DISCO_INFO_NS).optional_attr("node", disco.node.as_deref());
    for identity in &disco.identities {
        query.push_child(
            XmlElement::new("identity")
                .attr("category", identity.category())
                .attr("type", identity.kind())
                .optional_attr("xml:lang", identity.lang())
                .optional_attr("name", identity.name()),
        );
    }
    for feature in &disco.features {
        query.push_child(XmlElement::new("feature").attr("var", feature.var()));
    }
    for form in &disco.forms {
        let mut x = XmlElement::namespaced("x", "jabber:x:data")
            .attr("type", "result")
            .child(
                XmlElement::new("field")
                    .attr("var", "FORM_TYPE")
                    .attr("type", "hidden")
                    .child(XmlElement::new("value").text(form.form_type())),
            );
        for field in form.fields() {
            let mut field_element = XmlElement::new("field").attr("var", field.var());
            for val in field.values() {
                field_element.push_child(XmlElement::new("value").text(val.as_str()));
            }
            x.push_child(field_element);
        }
        query.push_child(x);
    }
    query.finish()
}

/// Builds a disco#info IQ request query string:
/// `<iq type='get' from='{from}' to='{to}' id='{id}'><query xmlns='http://jabber.org/protocol/disco#info' node='{node}#{ver}'/></iq>`
pub fn build_disco_info_request(from: &str, to: &str, id: &str, node: &str, ver: &str) -> String {
    XmlElement::new("iq")
        .attr("type", "get")
        .attr("from", from)
        .attr("to", to)
        .attr("id", id)
        .child(XmlElement::namespaced("query", DISCO_INFO_NS).attr("node", format!("{node}#{ver}")))
        .finish()
}

/// Validates that the node attribute in a disco#info query response matches the expected `"{node}#{ver}"`.
pub fn validate_disco_node_attribute(
    advertisement: &CapsAdvertisement,
    actual_node_attr: Option<&str>,
) -> Result<(), CapsError> {
    let expected = format!("{}#{}", advertisement.node, advertisement.ver);
    match actual_node_attr {
        Some(actual) if actual == expected => Ok(()),
        Some(actual) => Err(CapsError::NodeMismatch {
            expected,
            actual: actual.to_owned(),
        }),
        None => Err(CapsError::NodeMismatch {
            expected,
            actual: "<none>".to_owned(),
        }),
    }
}
