#![forbid(unsafe_code)]

//! Strict wire parsing, validation, and builders for XEP-0352 Client State Indication.

use crate::error::WireError;
use roxmltree::{Document, Node};
use std::fmt;

pub const NAMESPACE: &str = "urn:xmpp:csi:0";

/// Typed representation of a client state indication payload.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum CsiIndication {
    /// `<active xmlns='urn:xmpp:csi:0'/>`
    Active,
    /// `<inactive xmlns='urn:xmpp:csi:0'/>`
    Inactive,
}

impl CsiIndication {
    /// Returns the local XML element name.
    pub const fn local_name(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Inactive => "inactive",
        }
    }

    /// Parse a CSI indication from a local XML element name.
    pub fn from_local_name(name: &str) -> Option<Self> {
        match name {
            "active" => Some(Self::Active),
            "inactive" => Some(Self::Inactive),
            _ => None,
        }
    }

    /// Whether this indication requests the active state.
    pub const fn is_active(self) -> bool {
        matches!(self, Self::Active)
    }

    /// Whether this indication requests the inactive state.
    pub const fn is_inactive(self) -> bool {
        matches!(self, Self::Inactive)
    }

    /// Returns the exact wire XML string for this indication.
    pub const fn as_xml(self) -> &'static str {
        match self {
            Self::Active => "<active xmlns='urn:xmpp:csi:0'/>",
            Self::Inactive => "<inactive xmlns='urn:xmpp:csi:0'/>",
        }
    }
}

impl fmt::Display for CsiIndication {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.local_name())
    }
}

/// Checks whether an XML node is a schema-valid CSI indication element.
///
/// Under XEP-0352 Section 3:
/// - The element must be `<active/>` or `<inactive/>` in `urn:xmpp:csi:0`.
/// - The element must have no attributes.
/// - The element must have no child elements.
/// - The element must contain no text (or empty string).
pub fn is_valid_indication_node(root: Node<'_, '_>) -> bool {
    root.is_element()
        && root.tag_name().namespace() == Some(NAMESPACE)
        && matches!(root.tag_name().name(), "active" | "inactive")
        && root.attributes().len() == 0
        && !root.children().any(|child| child.is_element())
        && root.text().is_none_or(str::is_empty)
}

/// Parse and strictly validate a CSI indication XML node.
pub fn parse_indication_node(root: Node<'_, '_>) -> Result<CsiIndication, WireError> {
    if !root.is_element() {
        return Err(WireError::NotAnElement);
    }
    if root.tag_name().namespace() != Some(NAMESPACE) {
        return Err(WireError::UnexpectedNamespace {
            expected: NAMESPACE,
            actual: root.tag_name().namespace().map(str::to_owned),
        });
    }

    let indication = CsiIndication::from_local_name(root.tag_name().name()).ok_or_else(|| {
        WireError::UnexpectedTagName {
            actual: root.tag_name().name().to_owned(),
        }
    })?;

    if root.attributes().len() != 0 {
        return Err(WireError::AttributesNotPermitted);
    }
    if root.children().any(|child| child.is_element()) {
        return Err(WireError::ChildrenNotPermitted);
    }
    if !root.text().is_none_or(str::is_empty) {
        return Err(WireError::TextContentNotPermitted);
    }

    Ok(indication)
}

/// Parse and strictly validate a CSI indication XML string.
pub fn parse_indication(xml: &str) -> Result<CsiIndication, WireError> {
    let doc = Document::parse(xml).map_err(|err| WireError::MalformedXml(err.to_string()))?;
    parse_indication_node(doc.root_element())
}

/// Build an XML string for the `<active/>` indication.
pub const fn build_active() -> &'static str {
    CsiIndication::Active.as_xml()
}

/// Build an XML string for the `<inactive/>` indication.
pub const fn build_inactive() -> &'static str {
    CsiIndication::Inactive.as_xml()
}

/// Build an XML string for a [`CsiIndication`].
pub const fn build_indication(indication: CsiIndication) -> &'static str {
    indication.as_xml()
}

/// Build the stream feature advertisement element `<csi xmlns='urn:xmpp:csi:0'/>`.
pub const fn build_stream_feature() -> &'static str {
    "<csi xmlns='urn:xmpp:csi:0'/>"
}
