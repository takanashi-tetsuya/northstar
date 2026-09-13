#![forbid(unsafe_code)]

//! Capability-free XEP-0380 Explicit Message Encryption (EME) wire support.
//!
//! This module validates, classifies, and serializes XEP-0380 `<encryption/>`
//! elements. It provides advisory metadata only and never performs cryptographic
//! operations, key exchange, or message decryption. It has no runtime, database,
//! storage, or transport dependencies and maintains no global state.

use northstar_xep_core::{ExtensionDescriptor, StanzaKind, StanzaRoute, XepId};
use roxmltree::Node;
use std::fmt::{self, Write};

pub const XEP_ID: XepId = XepId::new(380);
pub const NAMESPACE: &str = "urn:xmpp:eme:0";

/// Well-known encryption mechanism namespace for OMEMO 2 (XEP-0384 v0.8+).
pub const MECHANISM_OMEMO_2: &str = "urn:xmpp:omemo:2";

/// Well-known encryption mechanism namespace for OMEMO 1 (XEP-0384 v0.3-0.7).
pub const MECHANISM_OMEMO_1: &str = "urn:xmpp:omemo:1";

/// Well-known legacy encryption mechanism namespace for OMEMO 0 (Conversations Axolotl).
pub const MECHANISM_OMEMO_0: &str = "eu.siacs.conversations.axolotl";

/// Well-known encryption mechanism namespace for OpenPGP for XMPP (XEP-0373).
pub const MECHANISM_OX_0: &str = "urn:xmpp:ox:0";

/// Well-known encryption mechanism namespace for Stateless Inline OpenPGP (XEP-0392).
pub const MECHANISM_OPENPGP_0: &str = "urn:xmpp:openpgp:0";

/// Well-known legacy encryption mechanism namespace for OpenPGP (XEP-0027).
pub const MECHANISM_LEGACY_OPENPGP: &str = "jabber:x:encrypted";

pub static DESCRIPTOR: ExtensionDescriptor = ExtensionDescriptor {
    id: XEP_ID,
    name: "Explicit Message Encryption",
    default_enabled: true,
    dependencies: &[XepId::new(30)],
    conflicts: &[],
    disco_features: &[NAMESPACE],
    routes: &[StanzaRoute {
        stanza: StanzaKind::Message,
        namespace: NAMESPACE,
        local_name: "encryption",
    }],
};

/// Typed representation of an XEP-0380 explicit encryption advisory element.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExplicitEncryption<'a> {
    /// The XML namespace of the encryption protocol used by the message payload.
    pub mechanism_namespace: &'a str,
    /// An optional human-readable name for the encryption protocol (e.g. "OMEMO").
    pub name: Option<&'a str>,
}

impl<'a> ExplicitEncryption<'a> {
    /// Construct a new [`ExplicitEncryption`] metadata descriptor.
    pub const fn new(mechanism_namespace: &'a str, name: Option<&'a str>) -> Self {
        Self {
            mechanism_namespace,
            name,
        }
    }

    /// Routing policy classification for explicit message encryption metadata.
    pub const fn routing_policy(self) -> RoutingPolicy {
        RoutingPolicy::AdvisoryMetadata
    }

    /// Returns `true` since EME is purely advisory metadata.
    pub const fn is_advisory_metadata(self) -> bool {
        true
    }
}

/// Routing policy classification for XEP-0380 encryption elements.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum RoutingPolicy {
    /// Explicit Message Encryption (EME) is advisory metadata describing
    /// the encryption protocol used by an accompanying payload; it carries
    /// no keys and performs no cryptographic operations.
    AdvisoryMetadata,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ValidationError {
    AmbiguousEncryption,
    ElementHasContent,
    MissingMechanismNamespace,
    InvalidMechanismNamespace,
    InvalidName,
    InvalidEncryptionAttributes,
    UnexpectedNamespace,
    UnexpectedTagName,
}

impl fmt::Display for ValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AmbiguousEncryption => {
                write!(formatter, "multiple encryption elements in message")
            }
            Self::ElementHasContent => {
                write!(
                    formatter,
                    "encryption element must not contain child elements or text"
                )
            }
            Self::MissingMechanismNamespace => {
                write!(
                    formatter,
                    "encryption element is missing required 'namespace' attribute"
                )
            }
            Self::InvalidMechanismNamespace => {
                write!(formatter, "encryption 'namespace' attribute is empty, oversized, or contains control characters")
            }
            Self::InvalidName => {
                write!(formatter, "encryption 'name' attribute is empty, oversized, or contains control characters")
            }
            Self::InvalidEncryptionAttributes => {
                write!(
                    formatter,
                    "encryption element contains unrecognized or namespaced attributes"
                )
            }
            Self::UnexpectedNamespace => {
                write!(formatter, "element namespace does not match urn:xmpp:eme:0")
            }
            Self::UnexpectedTagName => {
                write!(formatter, "expected <encryption> element tag name")
            }
        }
    }
}

impl std::error::Error for ValidationError {}

fn validate_value(value: &str) -> Result<(), ()> {
    if value.is_empty() || value.len() > 1_024 || value.chars().any(char::is_control) {
        Err(())
    } else {
        Ok(())
    }
}

/// Parse and validate a single direct `<encryption xmlns='urn:xmpp:eme:0'/>` XML element.
pub fn parse_encryption_element<'a, 'input>(
    node: Node<'a, 'input>,
) -> Result<ExplicitEncryption<'a>, ValidationError> {
    if !node.is_element() {
        return Err(ValidationError::UnexpectedTagName);
    }
    if node.tag_name().namespace() != Some(NAMESPACE) {
        return Err(ValidationError::UnexpectedNamespace);
    }
    if node.tag_name().name() != "encryption" {
        return Err(ValidationError::UnexpectedTagName);
    }
    if node.children().any(|child| child.is_element())
        || node.text().is_some_and(|text| !text.trim().is_empty())
    {
        return Err(ValidationError::ElementHasContent);
    }

    let mechanism_namespace = node
        .attribute("namespace")
        .ok_or(ValidationError::MissingMechanismNamespace)?;
    validate_value(mechanism_namespace).map_err(|()| ValidationError::InvalidMechanismNamespace)?;

    let name = node.attribute("name");
    if let Some(n) = name {
        validate_value(n).map_err(|()| ValidationError::InvalidName)?;
    }

    for attribute in node.attributes() {
        if attribute.namespace().is_some() || !matches!(attribute.name(), "namespace" | "name") {
            return Err(ValidationError::InvalidEncryptionAttributes);
        }
    }

    Ok(ExplicitEncryption {
        mechanism_namespace,
        name,
    })
}

/// Parse and validate the direct XEP-0380 encryption child of an enclosing `<message>`.
///
/// Only direct children of the message are inspected; nested payloads (e.g., inside
/// forwarded messages or encrypted payload containers) are ignored.
///
/// At most one `<encryption/>` element is permitted per message.
pub fn parse_message<'a, 'input>(
    root: Node<'a, 'input>,
) -> Result<Option<ExplicitEncryption<'a>>, ValidationError> {
    let encryptions = root
        .children()
        .filter(|node| node.is_element() && node.tag_name().namespace() == Some(NAMESPACE))
        .collect::<Vec<_>>();

    if encryptions.len() > 1 {
        return Err(ValidationError::AmbiguousEncryption);
    }
    let Some(encryption_node) = encryptions.into_iter().next() else {
        return Ok(None);
    };

    parse_encryption_element(encryption_node).map(Some)
}

/// Build an XML string for the `<encryption/>` element per XEP-0380.
///
/// The `mechanism_namespace` is required and non-empty. The `name` is optional.
/// All attribute values are XML-escaped.
pub fn build_encryption(
    mechanism_namespace: &str,
    name: Option<&str>,
) -> Result<String, ValidationError> {
    validate_value(mechanism_namespace).map_err(|()| ValidationError::InvalidMechanismNamespace)?;
    if let Some(n) = name {
        validate_value(n).map_err(|()| ValidationError::InvalidName)?;
    }

    let name_len = name.map_or(0, |n| n.len() + 10);
    let mut xml = String::with_capacity(mechanism_namespace.len() + name_len + 64);
    xml.push_str("<encryption xmlns='urn:xmpp:eme:0' namespace='");
    escape_attribute(&mut xml, mechanism_namespace);
    xml.push('\'');

    if let Some(n) = name {
        xml.push_str(" name='");
        escape_attribute(&mut xml, n);
        xml.push('\'');
    }

    xml.push_str("/>");
    Ok(xml)
}

fn escape_attribute(output: &mut String, value: &str) {
    for character in value.chars() {
        match character {
            '&' => output.push_str("&amp;"),
            '<' => output.push_str("&lt;"),
            '>' => output.push_str("&gt;"),
            '\'' => output.push_str("&apos;"),
            '"' => output.push_str("&quot;"),
            character => {
                let _ = output.write_char(character);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use roxmltree::Document;

    #[derive(Debug, Eq, PartialEq)]
    enum OwnedEncryption {
        Encryption {
            mechanism_namespace: String,
            name: Option<String>,
        },
    }

    fn to_owned(encryption: ExplicitEncryption<'_>) -> OwnedEncryption {
        OwnedEncryption::Encryption {
            mechanism_namespace: encryption.mechanism_namespace.to_owned(),
            name: encryption.name.map(str::to_owned),
        }
    }

    fn parse(xml: &str) -> Result<Option<OwnedEncryption>, ValidationError> {
        let document = Document::parse(xml).expect("valid fixture XML");
        parse_message(document.root_element()).map(|opt| opt.map(to_owned))
    }

    fn parse_element(xml: &str) -> Result<OwnedEncryption, ValidationError> {
        let document = Document::parse(xml).expect("valid fixture XML");
        parse_encryption_element(document.root_element()).map(to_owned)
    }

    #[test]
    fn parses_valid_encryption_elements() {
        assert_eq!(
            parse("<message><encryption xmlns='urn:xmpp:eme:0' namespace='urn:xmpp:omemo:2' name='OMEMO'/></message>"),
            Ok(Some(OwnedEncryption::Encryption {
                mechanism_namespace: "urn:xmpp:omemo:2".to_owned(),
                name: Some("OMEMO".to_owned()),
            }))
        );
        assert_eq!(
            parse(
                "<message><encryption xmlns='urn:xmpp:eme:0' namespace='urn:xmpp:ox:0'/></message>"
            ),
            Ok(Some(OwnedEncryption::Encryption {
                mechanism_namespace: "urn:xmpp:ox:0".to_owned(),
                name: None,
            }))
        );
    }

    #[test]
    fn returns_none_when_no_encryption_element_present() {
        assert_eq!(parse("<message><body>Plaintext</body></message>"), Ok(None));
    }

    #[test]
    fn ignores_nested_encryption_in_forwarded_payloads() {
        let xml = "<message>\
            <forwarded xmlns='urn:xmpp:forward:0'>\
                <message><encryption xmlns='urn:xmpp:eme:0' namespace='urn:xmpp:omemo:2'/></message>\
            </forwarded>\
        </message>";
        assert_eq!(parse(xml), Ok(None));
    }

    #[test]
    fn rejects_ambiguous_multiple_encryptions() {
        assert_eq!(
            parse(
                "<message>\
                    <encryption xmlns='urn:xmpp:eme:0' namespace='urn:xmpp:omemo:2'/>\
                    <encryption xmlns='urn:xmpp:eme:0' namespace='urn:xmpp:ox:0'/>\
                </message>"
            ),
            Err(ValidationError::AmbiguousEncryption)
        );
    }

    #[test]
    fn rejects_missing_namespace_attribute() {
        assert_eq!(
            parse("<message><encryption xmlns='urn:xmpp:eme:0' name='OMEMO'/></message>"),
            Err(ValidationError::MissingMechanismNamespace)
        );
        assert_eq!(
            parse("<message><encryption xmlns='urn:xmpp:eme:0'/></message>"),
            Err(ValidationError::MissingMechanismNamespace)
        );
    }

    #[test]
    fn rejects_invalid_mechanism_namespace() {
        assert_eq!(
            parse("<message><encryption xmlns='urn:xmpp:eme:0' namespace=''/></message>"),
            Err(ValidationError::InvalidMechanismNamespace)
        );
        assert_eq!(
            parse("<message><encryption xmlns='urn:xmpp:eme:0' namespace='bad\x7fns'/></message>"),
            Err(ValidationError::InvalidMechanismNamespace)
        );
        let oversized_ns = "u".repeat(1025);
        assert_eq!(
            parse(&format!("<message><encryption xmlns='urn:xmpp:eme:0' namespace='{oversized_ns}'/></message>")),
            Err(ValidationError::InvalidMechanismNamespace)
        );
    }

    #[test]
    fn rejects_invalid_name_attribute() {
        assert_eq!(
            parse("<message><encryption xmlns='urn:xmpp:eme:0' namespace='urn:xmpp:omemo:2' name=''/></message>"),
            Err(ValidationError::InvalidName)
        );
        assert_eq!(
            parse("<message><encryption xmlns='urn:xmpp:eme:0' namespace='urn:xmpp:omemo:2' name='bad\x7fname'/></message>"),
            Err(ValidationError::InvalidName)
        );
        let oversized_name = "n".repeat(1025);
        assert_eq!(
            parse(&format!("<message><encryption xmlns='urn:xmpp:eme:0' namespace='urn:xmpp:omemo:2' name='{oversized_name}'/></message>")),
            Err(ValidationError::InvalidName)
        );
    }

    #[test]
    fn rejects_unexpected_or_namespaced_attributes() {
        assert_eq!(
            parse("<message><encryption xmlns='urn:xmpp:eme:0' namespace='urn:xmpp:omemo:2' extra='val'/></message>"),
            Err(ValidationError::InvalidEncryptionAttributes)
        );
        assert_eq!(
            parse("<message><encryption xmlns='urn:xmpp:eme:0' namespace='urn:xmpp:omemo:2' evil:attr='val' xmlns:evil='urn:evil'/></message>"),
            Err(ValidationError::InvalidEncryptionAttributes)
        );
    }

    #[test]
    fn rejects_child_elements_or_non_whitespace_content() {
        assert_eq!(
            parse("<message><encryption xmlns='urn:xmpp:eme:0' namespace='urn:xmpp:omemo:2'><child/></encryption></message>"),
            Err(ValidationError::ElementHasContent)
        );
        assert_eq!(
            parse("<message><encryption xmlns='urn:xmpp:eme:0' namespace='urn:xmpp:omemo:2'>content</encryption></message>"),
            Err(ValidationError::ElementHasContent)
        );
    }

    #[test]
    fn rejects_unrecognized_tag_or_namespace() {
        assert_eq!(
            parse_element("<crypto xmlns='urn:xmpp:eme:0' namespace='urn:xmpp:omemo:2'/>"),
            Err(ValidationError::UnexpectedTagName)
        );
        assert_eq!(
            parse_element("<encryption xmlns='urn:other:ns' namespace='urn:xmpp:omemo:2'/>"),
            Err(ValidationError::UnexpectedNamespace)
        );
    }

    #[test]
    fn builder_escapes_attributes_and_round_trips() {
        let ns = "urn:xmpp:omemo:2&<'\"";
        let name = "OMEMO & Friends <v2>";

        let xml_with_name = build_encryption(ns, Some(name)).expect("build encryption with name");
        assert_eq!(
            xml_with_name,
            "<encryption xmlns='urn:xmpp:eme:0' namespace='urn:xmpp:omemo:2&amp;&lt;&apos;&quot;' name='OMEMO &amp; Friends &lt;v2&gt;'/>"
        );
        let parsed = parse_element(&xml_with_name).expect("parse encryption with name");
        assert_eq!(
            parsed,
            OwnedEncryption::Encryption {
                mechanism_namespace: ns.to_owned(),
                name: Some(name.to_owned()),
            }
        );

        let xml_without_name = build_encryption(ns, None).expect("build encryption without name");
        assert_eq!(
            xml_without_name,
            "<encryption xmlns='urn:xmpp:eme:0' namespace='urn:xmpp:omemo:2&amp;&lt;&apos;&quot;'/>"
        );
        let parsed = parse_element(&xml_without_name).expect("parse encryption without name");
        assert_eq!(
            parsed,
            OwnedEncryption::Encryption {
                mechanism_namespace: ns.to_owned(),
                name: None,
            }
        );
    }

    #[test]
    fn builder_rejects_invalid_inputs() {
        assert_eq!(
            build_encryption("", None),
            Err(ValidationError::InvalidMechanismNamespace)
        );
        assert_eq!(
            build_encryption("urn:xmpp:omemo:2", Some("")),
            Err(ValidationError::InvalidName)
        );
        assert_eq!(
            build_encryption("urn:xmpp:omemo:2\0", None),
            Err(ValidationError::InvalidMechanismNamespace)
        );
    }

    #[test]
    fn explicit_encryption_classification_and_routing_policy() {
        let eme = ExplicitEncryption::new("urn:xmpp:omemo:2", Some("OMEMO"));
        assert!(eme.is_advisory_metadata());
        assert_eq!(eme.routing_policy(), RoutingPolicy::AdvisoryMetadata);
    }

    #[test]
    fn descriptor_matches_manifest() {
        assert_eq!(DESCRIPTOR.id, XEP_ID);
        assert_eq!(DESCRIPTOR.name, "Explicit Message Encryption");
        assert!(DESCRIPTOR.default_enabled);
        assert_eq!(DESCRIPTOR.dependencies, &[XepId::new(30)]);
        assert!(DESCRIPTOR.conflicts.is_empty());
        assert_eq!(DESCRIPTOR.disco_features, &[NAMESPACE]);
        assert_eq!(DESCRIPTOR.routes.len(), 1);
        assert_eq!(DESCRIPTOR.routes[0].stanza, StanzaKind::Message);
        assert_eq!(DESCRIPTOR.routes[0].namespace, NAMESPACE);
        assert_eq!(DESCRIPTOR.routes[0].local_name, "encryption");
    }

    #[test]
    fn known_mechanism_constants_match_spec() {
        assert_eq!(MECHANISM_OMEMO_2, "urn:xmpp:omemo:2");
        assert_eq!(MECHANISM_OMEMO_1, "urn:xmpp:omemo:1");
        assert_eq!(MECHANISM_OMEMO_0, "eu.siacs.conversations.axolotl");
        assert_eq!(MECHANISM_OX_0, "urn:xmpp:ox:0");
        assert_eq!(MECHANISM_OPENPGP_0, "urn:xmpp:openpgp:0");
        assert_eq!(MECHANISM_LEGACY_OPENPGP, "jabber:x:encrypted");
    }

    #[test]
    fn error_display_formatting() {
        assert_eq!(
            ValidationError::AmbiguousEncryption.to_string(),
            "multiple encryption elements in message"
        );
        assert_eq!(
            ValidationError::ElementHasContent.to_string(),
            "encryption element must not contain child elements or text"
        );
        assert_eq!(
            ValidationError::MissingMechanismNamespace.to_string(),
            "encryption element is missing required 'namespace' attribute"
        );
        assert_eq!(
            ValidationError::InvalidMechanismNamespace.to_string(),
            "encryption 'namespace' attribute is empty, oversized, or contains control characters"
        );
        assert_eq!(
            ValidationError::InvalidName.to_string(),
            "encryption 'name' attribute is empty, oversized, or contains control characters"
        );
        assert_eq!(
            ValidationError::InvalidEncryptionAttributes.to_string(),
            "encryption element contains unrecognized or namespaced attributes"
        );
        assert_eq!(
            ValidationError::UnexpectedNamespace.to_string(),
            "element namespace does not match urn:xmpp:eme:0"
        );
        assert_eq!(
            ValidationError::UnexpectedTagName.to_string(),
            "expected <encryption> element tag name"
        );
    }
}
