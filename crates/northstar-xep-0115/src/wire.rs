//! Strict XML wire parsing and building for presence `<c>` and disco#info payloads.

use crate::constants::*;
use crate::error::CapsError;
use crate::model::{CapsAdvertisement, DiscoInfo, ExtendedForm, Feature, FormField, Identity};
use roxmltree::{Document, Node};
use std::collections::HashSet;
use std::fmt::Write;

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
    let mut xml = String::with_capacity(128);
    xml.push_str("<c xmlns='http://jabber.org/protocol/caps'");

    if let Some(ref hash) = caps.hash {
        xml.push_str(" hash='");
        escape_attribute(&mut xml, hash);
        xml.push('\'');
    }

    xml.push_str(" node='");
    escape_attribute(&mut xml, &caps.node);
    xml.push_str("' ver='");
    escape_attribute(&mut xml, &caps.ver);
    xml.push('\'');

    if let Some(ref ext) = caps.ext {
        xml.push_str(" ext='");
        escape_attribute(&mut xml, ext);
        xml.push('\'');
    }

    xml.push_str("/>");
    xml
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
    let mut xml = String::with_capacity(512);
    xml.push_str("<query xmlns='http://jabber.org/protocol/disco#info'");

    if let Some(ref node) = disco.node {
        xml.push_str(" node='");
        escape_attribute(&mut xml, node);
        xml.push('\'');
    }

    xml.push('>');

    for identity in &disco.identities {
        xml.push_str("<identity category='");
        escape_attribute(&mut xml, identity.category());
        xml.push_str("' type='");
        escape_attribute(&mut xml, identity.kind());
        xml.push('\'');

        if let Some(lang) = identity.lang() {
            xml.push_str(" xml:lang='");
            escape_attribute(&mut xml, lang);
            xml.push('\'');
        }

        if let Some(name) = identity.name() {
            xml.push_str(" name='");
            escape_attribute(&mut xml, name);
            xml.push('\'');
        }

        xml.push_str("/>");
    }

    for feature in &disco.features {
        xml.push_str("<feature var='");
        escape_attribute(&mut xml, feature.var());
        xml.push_str("'/>");
    }

    for form in &disco.forms {
        xml.push_str(
            "<x xmlns='jabber:x:data' type='result'><field var='FORM_TYPE' type='hidden'><value>",
        );
        escape_text(&mut xml, form.form_type());
        xml.push_str("</value></field>");

        for field in form.fields() {
            xml.push_str("<field var='");
            escape_attribute(&mut xml, field.var());
            xml.push_str("'>");
            for val in field.values() {
                xml.push_str("<value>");
                escape_text(&mut xml, val);
                xml.push_str("</value>");
            }
            xml.push_str("</field>");
        }

        xml.push_str("</x>");
    }

    xml.push_str("</query>");
    xml
}

/// Builds a disco#info IQ request query string:
/// `<iq type='get' from='{from}' to='{to}' id='{id}'><query xmlns='http://jabber.org/protocol/disco#info' node='{node}#{ver}'/></iq>`
pub fn build_disco_info_request(from: &str, to: &str, id: &str, node: &str, ver: &str) -> String {
    let mut xml = String::with_capacity(256);
    xml.push_str("<iq type='get' from='");
    escape_attribute(&mut xml, from);
    xml.push_str("' to='");
    escape_attribute(&mut xml, to);
    xml.push_str("' id='");
    escape_attribute(&mut xml, id);
    xml.push_str("'><query xmlns='http://jabber.org/protocol/disco#info' node='");
    escape_attribute(&mut xml, node);
    xml.push('#');
    escape_attribute(&mut xml, ver);
    xml.push_str("'/></iq>");
    xml
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

fn escape_attribute(output: &mut String, value: &str) {
    for c in value.chars() {
        match c {
            '&' => output.push_str("&amp;"),
            '<' => output.push_str("&lt;"),
            '>' => output.push_str("&gt;"),
            '\'' => output.push_str("&apos;"),
            '"' => output.push_str("&quot;"),
            other => {
                let _ = output.write_char(other);
            }
        }
    }
}

fn escape_text(output: &mut String, value: &str) {
    for c in value.chars() {
        match c {
            '&' => output.push_str("&amp;"),
            '<' => output.push_str("&lt;"),
            '>' => output.push_str("&gt;"),
            other => {
                let _ = output.write_char(other);
            }
        }
    }
}
