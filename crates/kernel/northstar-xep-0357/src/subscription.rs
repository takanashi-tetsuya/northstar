//! Typed push subscription identity, configuration, and bounded value validation.

use crate::constants::{
    MAX_FIELD_VALUES, MAX_FIELD_VAR_BYTES, MAX_FORM_FIELDS, MAX_NODE_BYTES, MAX_OPTIONS_XML_BYTES,
    MAX_VALUE_BYTES, XMLNS_DATA, XMLNS_PUBLISH_OPTIONS,
};
use crate::error::PushError;
use crate::xml::XmlElement;
use northstar_xmpp_types::CanonicalJid;
use roxmltree::Node;
use std::collections::HashSet;
use std::fmt;
use std::ops::Deref;

/// Bounded, validated push subscription node identifier.
///
/// A node string must be non-empty, at most [`MAX_NODE_BYTES`] octets (1024 bytes),
/// and contain no ASCII control characters.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PushNode(String);

impl PushNode {
    /// Validate and construct a [`PushNode`].
    pub fn new(node: impl Into<String>) -> Result<Self, PushError> {
        let s = node.into();
        validate_push_node(&s)?;
        Ok(Self(s))
    }

    /// Access the underlying node string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consume the wrapper and return the inner `String`.
    pub fn into_inner(self) -> String {
        self.0
    }
}

impl Deref for PushNode {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AsRef<str> for PushNode {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for PushNode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("PushNode").field(&self.0).finish()
    }
}

impl fmt::Display for PushNode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Validate node identifier rules: non-empty, <= 1024 octets, no control characters.
pub fn validate_push_node(node: &str) -> Result<(), PushError> {
    if node.is_empty() {
        return Err(PushError::InvalidNode(
            "node identifier is empty".to_owned(),
        ));
    }
    if node.len() > MAX_NODE_BYTES {
        return Err(PushError::InvalidNode(format!(
            "node length {} exceeds maximum allowed {}",
            node.len(),
            MAX_NODE_BYTES
        )));
    }
    if node.chars().any(char::is_control) {
        return Err(PushError::InvalidNode(
            "node identifier contains forbidden control characters".to_owned(),
        ));
    }
    Ok(())
}

/// A single field in a `publish-options` submit form.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublishOptionField {
    pub var: String,
    pub field_type: Option<String>,
    pub label: Option<String>,
    pub values: Vec<String>,
}

impl PublishOptionField {
    /// Construct a field with variable name and values.
    pub fn new(var: impl Into<String>, values: Vec<String>) -> Result<Self, PushError> {
        let var = var.into();
        validate_field_var(&var)?;
        validate_field_values(&values)?;
        Ok(Self {
            var,
            field_type: None,
            label: None,
            values,
        })
    }

    /// Construct a single-value field.
    pub fn single(var: impl Into<String>, value: impl Into<String>) -> Result<Self, PushError> {
        Self::new(var, vec![value.into()])
    }

    /// Construct a FORM_TYPE field for publish-options.
    pub fn form_type() -> Self {
        Self {
            var: "FORM_TYPE".to_owned(),
            field_type: Some("hidden".to_owned()),
            label: None,
            values: vec![XMLNS_PUBLISH_OPTIONS.to_owned()],
        }
    }
}

fn validate_field_var(var: &str) -> Result<(), PushError> {
    if var.is_empty() {
        return Err(PushError::InvalidPublishOptions(
            "field var cannot be empty".to_owned(),
        ));
    }
    if var.len() > MAX_FIELD_VAR_BYTES {
        return Err(PushError::InvalidPublishOptions(format!(
            "field var length {} exceeds maximum {}",
            var.len(),
            MAX_FIELD_VAR_BYTES
        )));
    }
    if var.chars().any(char::is_control) {
        return Err(PushError::InvalidPublishOptions(
            "field var contains forbidden control characters".to_owned(),
        ));
    }
    Ok(())
}

fn validate_field_values(values: &[String]) -> Result<(), PushError> {
    if values.is_empty() {
        return Err(PushError::InvalidPublishOptions(
            "field must have at least one value".to_owned(),
        ));
    }
    if values.len() > MAX_FIELD_VALUES {
        return Err(PushError::InvalidPublishOptions(format!(
            "field value count {} exceeds maximum {}",
            values.len(),
            MAX_FIELD_VALUES
        )));
    }
    for value in values {
        if value.len() > MAX_VALUE_BYTES {
            return Err(PushError::InvalidPublishOptions(format!(
                "field value byte length {} exceeds maximum {}",
                value.len(),
                MAX_VALUE_BYTES
            )));
        }
    }
    Ok(())
}

/// Validated `publish-options` submit data form per XEP-0060 and XEP-0357.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublishOptions {
    fields: Vec<PublishOptionField>,
}

impl PublishOptions {
    /// Create a new validated `PublishOptions` collection.
    ///
    /// Automatically ensures `FORM_TYPE = "http://jabber.org/protocol/pubsub#publish-options"` is present.
    pub fn new(fields: Vec<PublishOptionField>) -> Result<Self, PushError> {
        let mut final_fields = Vec::with_capacity(fields.len() + 1);
        let mut seen = HashSet::new();
        let mut has_form_type = false;

        for field in fields {
            validate_field_var(&field.var)?;
            validate_field_values(&field.values)?;

            if !seen.insert(field.var.clone()) {
                return Err(PushError::InvalidPublishOptions(format!(
                    "duplicate field var '{}' in publish-options",
                    field.var
                )));
            }
            if field.var == "FORM_TYPE" {
                if field.values.len() != 1 || field.values[0].trim() != XMLNS_PUBLISH_OPTIONS {
                    return Err(PushError::InvalidPublishOptions(
                        "FORM_TYPE must be exactly 'http://jabber.org/protocol/pubsub#publish-options'".to_owned(),
                    ));
                }
                has_form_type = true;
            }
            final_fields.push(field);
        }

        if !has_form_type {
            final_fields.insert(0, PublishOptionField::form_type());
        }

        if final_fields.len() > MAX_FORM_FIELDS {
            return Err(PushError::InvalidPublishOptions(format!(
                "publish-options field count {} exceeds maximum {}",
                final_fields.len(),
                MAX_FORM_FIELDS
            )));
        }

        let options = Self {
            fields: final_fields,
        };
        let xml = options.to_xml();
        if xml.len() > MAX_OPTIONS_XML_BYTES {
            return Err(PushError::ResourceConstraint(format!(
                "publish-options XML length {} exceeds maximum {}",
                xml.len(),
                MAX_OPTIONS_XML_BYTES
            )));
        }
        Ok(options)
    }

    /// Parse and validate `publish-options` data form from a roxmltree XML node.
    pub fn parse(form: Node<'_, '_>) -> Result<Self, PushError> {
        if form.tag_name().name() != "x" {
            return Err(PushError::UnexpectedTagName {
                expected: "x",
                actual: form.tag_name().name().to_owned(),
            });
        }
        if form.tag_name().namespace() != Some(XMLNS_DATA) {
            return Err(PushError::UnexpectedNamespace {
                expected: XMLNS_DATA,
                actual: form.tag_name().namespace().unwrap_or("").to_owned(),
            });
        }
        if form.attribute("type") != Some("submit") {
            return Err(PushError::InvalidPublishOptions(
                "publish-options x form type must be 'submit'".to_owned(),
            ));
        }

        for attr in form.attributes() {
            if attr.namespace().is_some() || attr.name() != "type" {
                return Err(PushError::InvalidPublishOptions(format!(
                    "unexpected attribute '{}' on publish-options form",
                    attr.name()
                )));
            }
        }

        if form
            .children()
            .any(|child| !child.is_element() && child.text().is_some_and(|t| !t.trim().is_empty()))
        {
            return Err(PushError::InvalidPublishOptions(
                "publish-options form contains non-whitespace text nodes".to_owned(),
            ));
        }

        let field_nodes: Vec<_> = form.children().filter(|c| c.is_element()).collect();
        if field_nodes.is_empty() {
            return Err(PushError::InvalidPublishOptions(
                "publish-options form has no fields".to_owned(),
            ));
        }
        if field_nodes.len() > MAX_FORM_FIELDS {
            return Err(PushError::InvalidPublishOptions(format!(
                "field count {} exceeds maximum {}",
                field_nodes.len(),
                MAX_FORM_FIELDS
            )));
        }

        let mut seen = HashSet::new();
        let mut form_type_found = false;
        let mut parsed_fields = Vec::with_capacity(field_nodes.len());

        for field_node in field_nodes {
            if field_node.tag_name().name() != "field"
                || field_node.tag_name().namespace() != Some(XMLNS_DATA)
            {
                return Err(PushError::InvalidPublishOptions(
                    "expected only <field xmlns='jabber:x:data'> children in form".to_owned(),
                ));
            }
            for attr in field_node.attributes() {
                if attr.namespace().is_some() || !matches!(attr.name(), "var" | "type" | "label") {
                    return Err(PushError::InvalidPublishOptions(format!(
                        "unexpected attribute '{}' on field",
                        attr.name()
                    )));
                }
            }
            if field_node.children().any(|child| {
                !child.is_element() && child.text().is_some_and(|t| !t.trim().is_empty())
            }) {
                return Err(PushError::InvalidPublishOptions(
                    "field contains unexpected text nodes".to_owned(),
                ));
            }

            let var = field_node.attribute("var").ok_or_else(|| {
                PushError::InvalidPublishOptions("field is missing 'var' attribute".to_owned())
            })?;
            validate_field_var(var)?;

            if !seen.insert(var.to_owned()) {
                return Err(PushError::InvalidPublishOptions(format!(
                    "duplicate field var '{var}' in publish-options form"
                )));
            }

            let value_nodes: Vec<_> = field_node.children().filter(|c| c.is_element()).collect();
            if value_nodes.is_empty() {
                return Err(PushError::InvalidPublishOptions(format!(
                    "field '{var}' has no <value> elements"
                )));
            }
            if value_nodes.len() > MAX_FIELD_VALUES {
                return Err(PushError::InvalidPublishOptions(format!(
                    "field '{var}' value count {} exceeds maximum {}",
                    value_nodes.len(),
                    MAX_FIELD_VALUES
                )));
            }

            let mut values = Vec::with_capacity(value_nodes.len());
            for value_node in value_nodes {
                if value_node.tag_name().name() != "value"
                    || value_node.tag_name().namespace() != Some(XMLNS_DATA)
                {
                    return Err(PushError::InvalidPublishOptions(
                        "expected only <value xmlns='jabber:x:data'> elements in field".to_owned(),
                    ));
                }
                if value_node.attributes().count() != 0 {
                    return Err(PushError::InvalidPublishOptions(
                        "value elements must not have attributes".to_owned(),
                    ));
                }
                if value_node.children().any(|c| c.is_element()) {
                    return Err(PushError::InvalidPublishOptions(
                        "value elements must not contain child elements".to_owned(),
                    ));
                }
                let val_text = value_node.text().unwrap_or("");
                if val_text.len() > MAX_VALUE_BYTES {
                    return Err(PushError::InvalidPublishOptions(format!(
                        "value text length {} in field '{var}' exceeds maximum {}",
                        val_text.len(),
                        MAX_VALUE_BYTES
                    )));
                }
                values.push(val_text.to_owned());
            }

            if var == "FORM_TYPE" {
                if values.len() != 1 || values[0].trim() != XMLNS_PUBLISH_OPTIONS {
                    return Err(PushError::InvalidPublishOptions(
                        "FORM_TYPE must have a single value of 'http://jabber.org/protocol/pubsub#publish-options'".to_owned(),
                    ));
                }
                form_type_found = true;
            }

            parsed_fields.push(PublishOptionField {
                var: var.to_owned(),
                field_type: field_node.attribute("type").map(str::to_owned),
                label: field_node.attribute("label").map(str::to_owned),
                values,
            });
        }

        if !form_type_found {
            return Err(PushError::InvalidPublishOptions(
                "publish-options form is missing FORM_TYPE field".to_owned(),
            ));
        }

        if form.range().len() > MAX_OPTIONS_XML_BYTES {
            return Err(PushError::ResourceConstraint(format!(
                "publish-options XML byte length {} exceeds maximum {}",
                form.range().len(),
                MAX_OPTIONS_XML_BYTES
            )));
        }

        Ok(Self {
            fields: parsed_fields,
        })
    }

    /// Parse publish-options from an XML string.
    pub fn parse_xml(xml: &str) -> Result<Self, PushError> {
        if xml.len() > MAX_OPTIONS_XML_BYTES {
            return Err(PushError::ResourceConstraint(format!(
                "XML string length {} exceeds maximum {}",
                xml.len(),
                MAX_OPTIONS_XML_BYTES
            )));
        }
        let doc =
            roxmltree::Document::parse(xml).map_err(|e| PushError::XmlParse(e.to_string()))?;
        Self::parse(doc.root_element())
    }

    /// Access the fields in this form.
    pub fn fields(&self) -> &[PublishOptionField] {
        &self.fields
    }

    /// Find a field by variable name.
    pub fn get_field(&self, var: &str) -> Option<&PublishOptionField> {
        self.fields.iter().find(|f| f.var == var)
    }

    /// Find the first value of a field by variable name.
    pub fn get_value(&self, var: &str) -> Option<&str> {
        self.get_field(var)
            .and_then(|f| f.values.first().map(String::as_str))
    }

    /// Serialize this form to an XML string.
    pub fn to_xml(&self) -> String {
        let mut form = XmlElement::namespaced("x", XMLNS_DATA).attr("type", "submit");
        for field in &self.fields {
            let mut field_el = XmlElement::new("field").attr("var", &field.var);
            if let Some(ref ft) = field.field_type {
                field_el = field_el.attr("type", ft);
            }
            if let Some(ref lbl) = field.label {
                field_el = field_el.attr("label", lbl);
            }
            for val in &field.values {
                field_el = field_el.child(XmlElement::new("value").text(val));
            }
            form.push_child(field_el);
        }
        form.finish()
    }
}

/// Push target identity comprising the bare Push Service JID and optional node.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct PushSubscriptionKey {
    service_jid: CanonicalJid,
    node: Option<PushNode>,
}

impl PushSubscriptionKey {
    /// Construct a new subscription key.
    pub fn new(service_jid: CanonicalJid, node: Option<PushNode>) -> Self {
        Self { service_jid, node }
    }

    /// Parse and validate a service JID string and optional node string.
    pub fn parse(service_jid: &str, node: Option<&str>) -> Result<Self, PushError> {
        let canonical_service = CanonicalJid::parse_bare(service_jid).map_err(|e| {
            PushError::JidMalformed(format!("invalid service bare JID '{service_jid}': {e}"))
        })?;
        let parsed_node = match node {
            Some(n) if !n.is_empty() => Some(PushNode::new(n)?),
            _ => None,
        };
        Ok(Self {
            service_jid: canonical_service,
            node: parsed_node,
        })
    }

    /// The canonical bare JID of the push service component.
    pub fn service_jid(&self) -> &CanonicalJid {
        &self.service_jid
    }

    /// The optional push node.
    pub fn node(&self) -> Option<&PushNode> {
        self.node.as_ref()
    }

    /// Node string slice, returning empty string if None.
    pub fn node_str(&self) -> &str {
        self.node.as_ref().map_or("", PushNode::as_str)
    }
}

/// Typed push enable request payload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PushEnableRequest {
    pub target: PushSubscriptionKey,
    pub options: Option<PublishOptions>,
}

impl PushEnableRequest {
    /// Construct a new push enable request.
    pub fn new(target: PushSubscriptionKey, options: Option<PublishOptions>) -> Self {
        Self { target, options }
    }

    /// Service bare JID.
    pub fn service_jid(&self) -> &CanonicalJid {
        self.target.service_jid()
    }

    /// Push node.
    pub fn node(&self) -> Option<&PushNode> {
        self.target.node()
    }

    /// Push node as string.
    pub fn node_str(&self) -> &str {
        self.target.node_str()
    }
}

/// Typed push disable request payload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PushDisableRequest {
    pub service_jid: CanonicalJid,
    pub node: Option<PushNode>,
}

impl PushDisableRequest {
    /// Construct a new push disable request.
    pub fn new(service_jid: CanonicalJid, node: Option<PushNode>) -> Self {
        Self { service_jid, node }
    }

    /// Parse and validate service JID and optional node.
    pub fn parse(service_jid: &str, node: Option<&str>) -> Result<Self, PushError> {
        let canonical_service = CanonicalJid::parse_bare(service_jid).map_err(|e| {
            PushError::JidMalformed(format!("invalid service bare JID '{service_jid}': {e}"))
        })?;
        let parsed_node = match node {
            Some(n) if !n.is_empty() => Some(PushNode::new(n)?),
            _ => None,
        };
        Ok(Self {
            service_jid: canonical_service,
            node: parsed_node,
        })
    }
}
