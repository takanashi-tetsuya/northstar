#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! Capability-free XEP-0363 HTTP File Upload wire support.
//!
//! The crate validates slot requests and renders bounded protocol payloads.
//! It deliberately owns no quota, token generation, database, object-store,
//! HTTP listener or URL-construction authority.

use northstar_xep_core::{ExtensionDescriptor, StanzaKind, StanzaRoute, XepId};
use roxmltree::Node;

/// XEP-0363 numeric identifier.
pub const XEP_ID: XepId = XepId::new(363);

/// XEP-0363 namespace.
pub const NAMESPACE: &str = "urn:xmpp:http:upload:0";

/// Maximum accepted UTF-8 filename length in bytes.
pub const MAX_FILENAME_BYTES: usize = 255;

/// Maximum accepted media-type length in bytes.
pub const MAX_CONTENT_TYPE_BYTES: usize = 255;

/// Maximum URL length accepted by the response builder.
pub const MAX_URL_BYTES: usize = 8_192;

/// Maximum bearer token length accepted by the response builder.
pub const MAX_TOKEN_BYTES: usize = 4_096;

/// Runtime extension descriptor.
pub static DESCRIPTOR: ExtensionDescriptor = ExtensionDescriptor {
    id: XEP_ID,
    name: "HTTP File Upload",
    default_enabled: true,
    dependencies: &[XepId::new(30)],
    conflicts: &[],
    disco_features: &[NAMESPACE],
    routes: &[StanzaRoute {
        stanza: StanzaKind::IqGet,
        namespace: NAMESPACE,
        local_name: "request",
    }],
};

/// A validated upload-slot request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UploadRequest<'a> {
    /// Client-visible filename without path separators or controls.
    pub filename: &'a str,
    /// ASCII media type.
    pub content_type: &'a str,
    /// Requested positive byte length.
    pub size: u64,
}

/// Upload request or response validation failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ValidationError {
    /// Element name or namespace is not the XEP-0363 request element.
    #[error("unexpected upload request element")]
    UnexpectedElement,
    /// Attributes, text, or the size value are malformed.
    #[error("malformed upload request")]
    MalformedRequest,
    /// An optional purpose/profile child is not implemented by this server.
    #[error("unsupported upload request child")]
    UnsupportedChild,
    /// Filename or media type violates the bounded wire contract.
    #[error("invalid upload metadata")]
    InvalidMetadata,
    /// A server-provided response value is empty, unbounded, or contains controls.
    #[error("invalid upload response value")]
    InvalidResponseValue,
}

/// Parse one XEP-0363 `<request/>` element.
pub fn parse_request<'a>(request: Node<'a, 'a>) -> Result<UploadRequest<'a>, ValidationError> {
    if !request.is_element()
        || request.tag_name().name() != "request"
        || request.tag_name().namespace() != Some(NAMESPACE)
    {
        return Err(ValidationError::UnexpectedElement);
    }
    if request.attributes().any(|attribute| {
        attribute.namespace().is_some()
            || !matches!(attribute.name(), "filename" | "size" | "content-type")
    }) || request
        .children()
        .any(|child| child.is_text() && child.text().is_some_and(|text| !text.trim().is_empty()))
    {
        return Err(ValidationError::MalformedRequest);
    }
    if request.children().any(|child| child.is_element()) {
        return Err(ValidationError::UnsupportedChild);
    }

    let filename = request.attribute("filename").unwrap_or_default();
    let content_type = request
        .attribute("content-type")
        .unwrap_or("application/octet-stream");
    let size = request
        .attribute("size")
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|size| *size > 0)
        .ok_or(ValidationError::MalformedRequest)?;
    if !valid_filename(filename) || !valid_content_type(content_type) {
        return Err(ValidationError::InvalidMetadata);
    }
    Ok(UploadRequest {
        filename,
        content_type,
        size,
    })
}

/// Return whether a filename is a bounded leaf name rather than a path.
pub fn valid_filename(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_FILENAME_BYTES
        && !value
            .chars()
            .any(|character| character.is_control() || matches!(character, '/' | '\\'))
}

/// Return whether a content type is bounded visible ASCII with a type/subtype separator.
pub fn valid_content_type(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_CONTENT_TYPE_BYTES
        && value.is_ascii()
        && value.contains('/')
        && !value
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
}

/// Build a XEP-0363 `<slot/>` payload with a bearer authorization header.
pub fn build_slot(
    put_url: &str,
    bearer_token: &str,
    get_url: &str,
) -> Result<String, ValidationError> {
    if !valid_response_value(put_url, MAX_URL_BYTES)
        || !valid_response_value(get_url, MAX_URL_BYTES)
        || !valid_response_value(bearer_token, MAX_TOKEN_BYTES)
    {
        return Err(ValidationError::InvalidResponseValue);
    }
    Ok(format!(
        "<slot xmlns='{NAMESPACE}'><put url='{}'><header name='Authorization'>Bearer {}</header></put><get url='{}'/></slot>",
        escape_attribute(put_url),
        escape_text(bearer_token),
        escape_attribute(get_url),
    ))
}

/// Build the XEP-0363 application-condition payload for an oversized request.
pub fn build_file_too_large(maximum: u64) -> String {
    format!(
        "<file-too-large xmlns='{NAMESPACE}'><max-file-size>{maximum}</max-file-size></file-too-large>"
    )
}

fn valid_response_value(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && !value.chars().any(|character| character.is_control())
}

fn escape_attribute(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('\'', "&apos;")
        .replace('"', "&quot;")
}

fn escape_text(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

#[cfg(test)]
mod tests {
    use super::*;
    use roxmltree::Document;

    fn parse(xml: &str) -> Result<(String, String, u64), ValidationError> {
        let document = Document::parse(xml).expect("fixture XML");
        let request = parse_request(document.root_element())?;
        Ok((
            request.filename.to_owned(),
            request.content_type.to_owned(),
            request.size,
        ))
    }

    #[test]
    fn parses_default_and_explicit_media_types() {
        assert_eq!(
            parse("<request xmlns='urn:xmpp:http:upload:0' filename='cipher.bin' size='12'/>")
                .expect("valid request"),
            (
                "cipher.bin".to_owned(),
                "application/octet-stream".to_owned(),
                12,
            )
        );
        assert_eq!(
            parse("<request xmlns='urn:xmpp:http:upload:0' filename='a.txt' size='1' content-type='text/plain'/>")
                .expect("valid request")
                .1,
            "text/plain".to_owned()
        );
    }

    #[test]
    fn rejects_wrong_element_attributes_text_and_size() {
        for xml in [
            "<request xmlns='urn:wrong' filename='a' size='1'/>",
            "<slot xmlns='urn:xmpp:http:upload:0'/>",
            "<request xmlns='urn:xmpp:http:upload:0' filename='a' size='0'/>",
            "<request xmlns='urn:xmpp:http:upload:0' filename='a' size='-1'/>",
            "<request xmlns='urn:xmpp:http:upload:0' filename='a' size='1' extra='x'/>",
            "<request xmlns='urn:xmpp:http:upload:0' filename='a' size='1'>text</request>",
        ] {
            assert!(parse(xml).is_err(), "{xml}");
        }
    }

    #[test]
    fn reports_unsupported_children_separately() {
        let document = Document::parse(
            "<request xmlns='urn:xmpp:http:upload:0' filename='a' size='1'><profile xmlns='urn:xmpp:http:upload:purpose:0'/></request>",
        )
        .unwrap();
        assert_eq!(
            parse_request(document.root_element()),
            Err(ValidationError::UnsupportedChild)
        );
    }

    #[test]
    fn filename_and_content_type_are_bounded() {
        assert!(valid_filename("avatar.webp"));
        assert!(!valid_filename("../avatar.webp"));
        assert!(!valid_filename("a\\b"));
        assert!(!valid_filename(&"a".repeat(MAX_FILENAME_BYTES + 1)));
        assert!(valid_content_type("image/webp"));
        assert!(!valid_content_type(" image/webp"));
        assert!(!valid_content_type("image"));
    }

    #[test]
    fn slot_builder_escapes_and_round_trips_values() {
        let put = "https://example.test/put?a='&b=<evil>";
        let token = "token<&already-&amp;";
        let get = "https://example.test/get?'&x=1";
        let xml = build_slot(put, token, get).expect("slot");
        let document = Document::parse(&xml).expect("built XML");
        let slot = document.root_element();
        let put_element = slot
            .children()
            .find(|node| node.has_tag_name("put"))
            .unwrap();
        let header = put_element
            .children()
            .find(|node| node.has_tag_name("header"))
            .unwrap();
        let get_element = slot
            .children()
            .find(|node| node.has_tag_name("get"))
            .unwrap();
        assert_eq!(put_element.attribute("url"), Some(put));
        assert_eq!(header.text(), Some(format!("Bearer {token}").as_str()));
        assert_eq!(get_element.attribute("url"), Some(get));
    }

    #[test]
    fn slot_builder_rejects_empty_control_and_unbounded_values() {
        assert_eq!(
            build_slot("", "token", "https://example.test/get"),
            Err(ValidationError::InvalidResponseValue)
        );
        assert_eq!(
            build_slot(
                "https://example.test/put",
                "bad\ntoken",
                "https://example.test/get"
            ),
            Err(ValidationError::InvalidResponseValue)
        );
        assert!(build_slot(&"a".repeat(MAX_URL_BYTES + 1), "token", "b").is_err());
    }

    #[test]
    fn file_too_large_builder_is_exact() {
        assert_eq!(
            build_file_too_large(25_000_000),
            "<file-too-large xmlns='urn:xmpp:http:upload:0'><max-file-size>25000000</max-file-size></file-too-large>"
        );
    }

    #[test]
    fn descriptor_matches_manifest() {
        assert_eq!(DESCRIPTOR.id, XEP_ID);
        assert_eq!(DESCRIPTOR.dependencies, &[XepId::new(30)]);
        assert_eq!(DESCRIPTOR.disco_features, &[NAMESPACE]);
        assert_eq!(DESCRIPTOR.routes.len(), 1);
    }
}
