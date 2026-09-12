#![forbid(unsafe_code)]

//! Capability-free XEP-0092 Software Version wire support.
//!
//! The module validates and describes XEP-0092 Software Version stanzas. It does not
//! gain access to system environment, operating system calls, accounts, sessions,
//! persistence, or transports. All server and software identity parameters are
//! injected explicitly as typed values.

use northstar_xep_core::{ExtensionDescriptor, StanzaKind, StanzaRoute, XepId};
use roxmltree::Node;
use std::fmt::{self, Write};

pub const XEP_ID: XepId = XepId::new(92);
pub const NAMESPACE: &str = "jabber:iq:version";

pub static DESCRIPTOR: ExtensionDescriptor = ExtensionDescriptor {
    id: XEP_ID,
    name: "Software Version",
    default_enabled: true,
    dependencies: &[XepId::new(30)],
    conflicts: &[],
    disco_features: &[NAMESPACE],
    routes: &[StanzaRoute {
        stanza: StanzaKind::IqGet,
        namespace: NAMESPACE,
        local_name: "query",
    }],
};

/// A validated XEP-0092 software version query request.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct VersionRequest;

/// A typed, capability-free representation of server or client software identity.
///
/// Per XEP-0092:
/// - `name`: The natural-language name of the software (REQUIRED).
/// - `version`: The specific version of the software (REQUIRED).
/// - `os`: The operating system on which the software is running (OPTIONAL).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ServerIdentity<'a> {
    pub name: &'a str,
    pub version: &'a str,
    pub os: Option<&'a str>,
}

impl<'a> ServerIdentity<'a> {
    /// Construct a new [`ServerIdentity`] with optional OS information.
    pub const fn new(name: &'a str, version: &'a str, os: Option<&'a str>) -> Self {
        Self { name, version, os }
    }

    /// Construct a new [`ServerIdentity`] with specific OS information.
    pub const fn with_os(name: &'a str, version: &'a str, os: &'a str) -> Self {
        Self {
            name,
            version,
            os: Some(os),
        }
    }

    /// Construct a new [`ServerIdentity`] omitting OS information.
    pub const fn without_os(name: &'a str, version: &'a str) -> Self {
        Self {
            name,
            version,
            os: None,
        }
    }
}

/// An owned representation of software version information parsed from an incoming response.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SoftwareVersion {
    pub name: String,
    pub version: String,
    pub os: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ValidationError {
    AmbiguousQuery,
    ElementHasContent,
    InvalidQueryAttributes,
    UnexpectedNamespace,
    UnexpectedTagName,
    MissingName,
    MissingVersion,
    DuplicateName,
    DuplicateVersion,
    DuplicateOs,
    EmptyName,
    EmptyVersion,
    InvalidFieldContent,
    UnexpectedChildElement,
}

impl fmt::Display for ValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AmbiguousQuery => write!(formatter, "multiple version query elements in stanza"),
            Self::ElementHasContent => {
                write!(
                    formatter,
                    "version query request must not have child elements or text"
                )
            }
            Self::InvalidQueryAttributes => {
                write!(
                    formatter,
                    "version query element must not contain custom attributes"
                )
            }
            Self::UnexpectedNamespace => {
                write!(
                    formatter,
                    "element namespace does not match jabber:iq:version"
                )
            }
            Self::UnexpectedTagName => write!(formatter, "expected <query> element tag"),
            Self::MissingName => write!(formatter, "missing required <name> child element"),
            Self::MissingVersion => write!(formatter, "missing required <version> child element"),
            Self::DuplicateName => write!(formatter, "duplicate <name> element found in response"),
            Self::DuplicateVersion => {
                write!(formatter, "duplicate <version> element found in response")
            }
            Self::DuplicateOs => write!(formatter, "duplicate <os> element found in response"),
            Self::EmptyName => write!(formatter, "software name must not be empty"),
            Self::EmptyVersion => write!(formatter, "software version must not be empty"),
            Self::InvalidFieldContent => {
                write!(
                    formatter,
                    "field content contains invalid or control characters"
                )
            }
            Self::UnexpectedChildElement => {
                write!(
                    formatter,
                    "unexpected child element in software version payload"
                )
            }
        }
    }
}

impl std::error::Error for ValidationError {}

fn validate_field_text(value: &str) -> Result<(), ValidationError> {
    if value.len() > 1_024 || value.chars().any(char::is_control) {
        Err(ValidationError::InvalidFieldContent)
    } else {
        Ok(())
    }
}

/// Parse and validate a single direct `<query xmlns='jabber:iq:version'/>` request element.
pub fn parse_query_request_element(node: Node<'_, '_>) -> Result<VersionRequest, ValidationError> {
    if !node.is_element() {
        return Err(ValidationError::UnexpectedTagName);
    }
    if node.tag_name().namespace() != Some(NAMESPACE) {
        return Err(ValidationError::UnexpectedNamespace);
    }
    if node.tag_name().name() != "query" {
        return Err(ValidationError::UnexpectedTagName);
    }
    if node.attributes().len() != 0 {
        return Err(ValidationError::InvalidQueryAttributes);
    }
    if node.children().any(|child| {
        child.is_element()
            || (child.is_text() && child.text().is_some_and(|text| !text.trim().is_empty()))
    }) {
        return Err(ValidationError::ElementHasContent);
    }
    Ok(VersionRequest)
}

/// Parse and validate the XEP-0092 version child of an enclosing stanza (e.g. an `<iq type='get'>`).
///
/// Returns `Ok(Some(VersionRequest))` if a single valid `<query/>` request element is present,
/// `Ok(None)` if no elements in the `jabber:iq:version` namespace exist,
/// or `Err(ValidationError)` if the request is malformed or ambiguous.
pub fn parse_iq<'a, 'input>(
    root: Node<'a, 'input>,
) -> Result<Option<VersionRequest>, ValidationError> {
    let mut query = None;
    for child in root
        .children()
        .filter(|node| node.is_element() && node.tag_name().namespace() == Some(NAMESPACE))
    {
        if query.replace(parse_query_request_element(child)?).is_some() {
            return Err(ValidationError::AmbiguousQuery);
        }
    }
    Ok(query)
}

/// Parse and validate an XEP-0092 `<query xmlns='jabber:iq:version'>` response element.
pub fn parse_version_response_element<'a, 'input>(
    node: Node<'a, 'input>,
) -> Result<SoftwareVersion, ValidationError> {
    if !node.is_element() {
        return Err(ValidationError::UnexpectedTagName);
    }
    if node.tag_name().namespace() != Some(NAMESPACE) {
        return Err(ValidationError::UnexpectedNamespace);
    }
    if node.tag_name().name() != "query" {
        return Err(ValidationError::UnexpectedTagName);
    }
    if node.attributes().len() != 0 {
        return Err(ValidationError::InvalidQueryAttributes);
    }
    if node
        .children()
        .any(|child| child.is_text() && child.text().is_some_and(|text| !text.trim().is_empty()))
    {
        return Err(ValidationError::UnexpectedChildElement);
    }

    let mut name: Option<String> = None;
    let mut version: Option<String> = None;
    let mut os: Option<String> = None;

    for child in node.children().filter(|n| n.is_element()) {
        match child.tag_name().name() {
            "name" => {
                if name.is_some() {
                    return Err(ValidationError::DuplicateName);
                }
                let text = field_text(child)?;
                if text.trim().is_empty() {
                    return Err(ValidationError::EmptyName);
                }
                validate_field_text(&text)?;
                name = Some(text);
            }
            "version" => {
                if version.is_some() {
                    return Err(ValidationError::DuplicateVersion);
                }
                let text = field_text(child)?;
                if text.trim().is_empty() {
                    return Err(ValidationError::EmptyVersion);
                }
                validate_field_text(&text)?;
                version = Some(text);
            }
            "os" => {
                if os.is_some() {
                    return Err(ValidationError::DuplicateOs);
                }
                let text = field_text(child)?;
                if !text.trim().is_empty() {
                    validate_field_text(&text)?;
                    os = Some(text);
                }
            }
            _ => return Err(ValidationError::UnexpectedChildElement),
        }
    }

    let name = name.ok_or(ValidationError::MissingName)?;
    let version = version.ok_or(ValidationError::MissingVersion)?;

    Ok(SoftwareVersion { name, version, os })
}

fn field_text(node: Node<'_, '_>) -> Result<String, ValidationError> {
    if node.tag_name().namespace() != Some(NAMESPACE)
        || node.attributes().len() != 0
        || node.children().any(|nested| nested.is_element())
    {
        return Err(ValidationError::UnexpectedChildElement);
    }
    Ok(node
        .children()
        .filter_map(|child| child.is_text().then(|| child.text()).flatten())
        .collect())
}

/// Build an XEP-0092 version query request XML payload string.
pub const fn build_request() -> &'static str {
    "<query xmlns='jabber:iq:version'/>"
}

/// Build an XEP-0092 version response XML payload string from typed [`ServerIdentity`].
///
/// All text fields (name, version, optional OS) are XML-escaped.
pub fn build_response(identity: &ServerIdentity<'_>) -> Result<String, ValidationError> {
    if identity.name.trim().is_empty() {
        return Err(ValidationError::EmptyName);
    }
    validate_field_text(identity.name)?;

    if identity.version.trim().is_empty() {
        return Err(ValidationError::EmptyVersion);
    }
    validate_field_text(identity.version)?;

    let os_len = identity.os.map_or(0, |s| s.len() + 10);
    let mut output =
        String::with_capacity(64 + identity.name.len() + identity.version.len() + os_len);
    output.push_str("<query xmlns='jabber:iq:version'><name>");
    escape_xml_text(&mut output, identity.name);
    output.push_str("</name><version>");
    escape_xml_text(&mut output, identity.version);
    output.push_str("</version>");

    if let Some(os) = identity.os {
        if !os.trim().is_empty() {
            validate_field_text(os)?;
            output.push_str("<os>");
            escape_xml_text(&mut output, os);
            output.push_str("</os>");
        }
    }

    output.push_str("</query>");
    Ok(output)
}

/// Build an XEP-0092 version response XML payload string from raw parts.
pub fn build_response_from_parts(
    name: &str,
    version: &str,
    os: Option<&str>,
) -> Result<String, ValidationError> {
    let identity = ServerIdentity::new(name, version, os);
    build_response(&identity)
}

fn escape_xml_text(output: &mut String, value: &str) {
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

    fn parse_doc(xml: &str) -> Result<Option<VersionRequest>, ValidationError> {
        let document = Document::parse(xml).expect("valid fixture XML");
        parse_iq(document.root_element())
    }

    fn parse_raw_element(xml: &str) -> Result<VersionRequest, ValidationError> {
        let document = Document::parse(xml).expect("valid fixture XML");
        parse_query_request_element(document.root_element())
    }

    fn parse_response(xml: &str) -> Result<SoftwareVersion, ValidationError> {
        let document = Document::parse(xml).expect("valid fixture XML");
        parse_version_response_element(document.root_element())
    }

    #[test]
    fn parses_valid_version_request() {
        assert_eq!(
            parse_raw_element("<query xmlns='jabber:iq:version'/>"),
            Ok(VersionRequest)
        );
        assert_eq!(
            parse_doc(
                "<iq type='get' id='v1' from='a@example.com' to='example.com'>\
                    <query xmlns='jabber:iq:version'/>\
                 </iq>"
            ),
            Ok(Some(VersionRequest))
        );
        assert_eq!(
            parse_doc("<iq type='get' id='v1'><body>other</body></iq>"),
            Ok(None)
        );
    }

    #[test]
    fn rejects_malformed_version_requests() {
        assert_eq!(
            parse_raw_element("<query xmlns='jabber:iq:version' attr='val'/>"),
            Err(ValidationError::InvalidQueryAttributes)
        );
        assert_eq!(
            parse_raw_element("<query xmlns='jabber:iq:version'><sub/></query>"),
            Err(ValidationError::ElementHasContent)
        );
        assert_eq!(
            parse_raw_element("<query xmlns='jabber:iq:version'>text</query>"),
            Err(ValidationError::ElementHasContent)
        );
        assert_eq!(
            parse_raw_element("<other xmlns='jabber:iq:version'/>"),
            Err(ValidationError::UnexpectedTagName)
        );
        assert_eq!(
            parse_raw_element("<query xmlns='jabber:wrong:ns'/>"),
            Err(ValidationError::UnexpectedNamespace)
        );
        assert_eq!(
            parse_doc(
                "<iq type='get' id='v1'>\
                    <query xmlns='jabber:iq:version'/>\
                    <query xmlns='jabber:iq:version'/>\
                 </iq>"
            ),
            Err(ValidationError::AmbiguousQuery)
        );
    }

    #[test]
    fn builds_and_parses_response_with_os() {
        let identity = ServerIdentity::with_os("Northstar", "0.2.0", "Linux");
        let xml = build_response(&identity).expect("build response succeeds");

        assert_eq!(
            xml,
            "<query xmlns='jabber:iq:version'><name>Northstar</name><version>0.2.0</version><os>Linux</os></query>"
        );

        let parsed = parse_response(&xml).expect("parse response succeeds");
        assert_eq!(parsed.name, "Northstar");
        assert_eq!(parsed.version, "0.2.0");
        assert_eq!(parsed.os.as_deref(), Some("Linux"));
    }

    #[test]
    fn builds_and_parses_response_without_os() {
        let identity = ServerIdentity::without_os("Northstar", "0.2.0");
        let xml = build_response(&identity).expect("build response succeeds");

        assert_eq!(
            xml,
            "<query xmlns='jabber:iq:version'><name>Northstar</name><version>0.2.0</version></query>"
        );

        let parsed = parse_response(&xml).expect("parse response succeeds");
        assert_eq!(parsed.name, "Northstar");
        assert_eq!(parsed.version, "0.2.0");
        assert_eq!(parsed.os, None);
    }

    #[test]
    fn escapes_special_characters_in_response() {
        let identity = ServerIdentity::with_os(
            "Northstar & Friends <edition>",
            "0.2.0 \"preview'1\"",
            "Linux > Unix & BSD",
        );
        let xml = build_response(&identity).expect("build response succeeds");

        assert_eq!(
            xml,
            "<query xmlns='jabber:iq:version'><name>Northstar &amp; Friends &lt;edition&gt;</name><version>0.2.0 &quot;preview&apos;1&quot;</version><os>Linux &gt; Unix &amp; BSD</os></query>"
        );

        let parsed = parse_response(&xml).expect("parse response succeeds");
        assert_eq!(parsed.name, "Northstar & Friends <edition>");
        assert_eq!(parsed.version, "0.2.0 \"preview'1\"");
        assert_eq!(parsed.os.as_deref(), Some("Linux > Unix & BSD"));
    }

    #[test]
    fn rejects_empty_identity_fields() {
        let identity_empty_name = ServerIdentity::without_os("", "0.2.0");
        assert_eq!(
            build_response(&identity_empty_name),
            Err(ValidationError::EmptyName)
        );

        let identity_whitespace_name = ServerIdentity::without_os("   ", "0.2.0");
        assert_eq!(
            build_response(&identity_whitespace_name),
            Err(ValidationError::EmptyName)
        );

        let identity_empty_version = ServerIdentity::without_os("Northstar", "");
        assert_eq!(
            build_response(&identity_empty_version),
            Err(ValidationError::EmptyVersion)
        );
    }

    #[test]
    fn rejects_control_characters_in_identity() {
        let identity = ServerIdentity::without_os("Northstar\0", "0.2.0");
        assert_eq!(
            build_response(&identity),
            Err(ValidationError::InvalidFieldContent)
        );

        let identity = ServerIdentity::without_os("Northstar", "0.2.0\x07");
        assert_eq!(
            build_response(&identity),
            Err(ValidationError::InvalidFieldContent)
        );

        let identity = ServerIdentity::with_os("Northstar", "0.2.0", "Linux\x1F");
        assert_eq!(
            build_response(&identity),
            Err(ValidationError::InvalidFieldContent)
        );
    }

    #[test]
    fn rejects_malformed_responses() {
        // Missing name
        assert_eq!(
            parse_response("<query xmlns='jabber:iq:version'><version>0.2.0</version></query>"),
            Err(ValidationError::MissingName)
        );
        // Missing version
        assert_eq!(
            parse_response("<query xmlns='jabber:iq:version'><name>Northstar</name></query>"),
            Err(ValidationError::MissingVersion)
        );
        // Duplicate name
        assert_eq!(
            parse_response(
                "<query xmlns='jabber:iq:version'>\
                    <name>First</name>\
                    <name>Second</name>\
                    <version>0.2.0</version>\
                 </query>"
            ),
            Err(ValidationError::DuplicateName)
        );
        // Duplicate version
        assert_eq!(
            parse_response(
                "<query xmlns='jabber:iq:version'>\
                    <name>Northstar</name>\
                    <version>0.1.0</version>\
                    <version>0.2.0</version>\
                 </query>"
            ),
            Err(ValidationError::DuplicateVersion)
        );
        // Duplicate os
        assert_eq!(
            parse_response(
                "<query xmlns='jabber:iq:version'>\
                    <name>Northstar</name>\
                    <version>0.2.0</version>\
                    <os>Linux</os>\
                    <os>Windows</os>\
                 </query>"
            ),
            Err(ValidationError::DuplicateOs)
        );
        // Unexpected child element
        assert_eq!(
            parse_response(
                "<query xmlns='jabber:iq:version'>\
                    <name>Northstar</name>\
                    <version>0.2.0</version>\
                    <extra>invalid</extra>\
                 </query>"
            ),
            Err(ValidationError::UnexpectedChildElement)
        );
        for malformed in [
            "<query xmlns='jabber:iq:version' extra='1'><name>Northstar</name><version>0.2.0</version></query>",
            "<query xmlns='jabber:iq:version'><name xmlns=''>Northstar</name><version>0.2.0</version></query>",
            "<query xmlns='jabber:iq:version'><name><nested/>Northstar</name><version>0.2.0</version></query>",
            "<query xmlns='jabber:iq:version'>unexpected<name>Northstar</name><version>0.2.0</version></query>",
        ] {
            assert!(parse_response(malformed).is_err(), "{malformed}");
        }
    }

    #[test]
    fn response_text_split_by_comments_is_not_truncated() {
        let parsed = parse_response(
            "<query xmlns='jabber:iq:version'><name>North<!--split-->star</name><version>0.<!--split-->2.0</version></query>",
        )
        .unwrap();
        assert_eq!(parsed.name, "Northstar");
        assert_eq!(parsed.version, "0.2.0");
    }

    #[test]
    fn builder_deterministic() {
        let xml = build_response_from_parts("Northstar", "0.2.0", Some("Linux")).unwrap();
        assert_eq!(
            xml,
            "<query xmlns='jabber:iq:version'><name>Northstar</name><version>0.2.0</version><os>Linux</os></query>"
        );
        assert_eq!(build_request(), "<query xmlns='jabber:iq:version'/>");
    }

    #[test]
    fn descriptor_matches_manifest() {
        assert_eq!(DESCRIPTOR.id, XEP_ID);
        assert_eq!(DESCRIPTOR.name, "Software Version");
        assert!(DESCRIPTOR.default_enabled);
        assert_eq!(DESCRIPTOR.disco_features, &[NAMESPACE]);
        assert_eq!(DESCRIPTOR.routes.len(), 1);
        assert_eq!(DESCRIPTOR.routes[0].stanza, StanzaKind::IqGet);
        assert_eq!(DESCRIPTOR.routes[0].namespace, NAMESPACE);
        assert_eq!(DESCRIPTOR.routes[0].local_name, "query");
    }

    #[test]
    fn error_display_formatting() {
        assert_eq!(
            ValidationError::AmbiguousQuery.to_string(),
            "multiple version query elements in stanza"
        );
        assert_eq!(
            ValidationError::ElementHasContent.to_string(),
            "version query request must not have child elements or text"
        );
        assert_eq!(
            ValidationError::MissingName.to_string(),
            "missing required <name> child element"
        );
        assert_eq!(
            ValidationError::MissingVersion.to_string(),
            "missing required <version> child element"
        );
        assert_eq!(
            ValidationError::EmptyName.to_string(),
            "software name must not be empty"
        );
        assert_eq!(
            ValidationError::EmptyVersion.to_string(),
            "software version must not be empty"
        );
    }
}
