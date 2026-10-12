//! Bounded, dependency-light parsing at HTTP/WebSocket transport boundaries.
//!
//! Keeping these checks outside of the transport actors makes the exact parser
//! available to the fuzz harness without constructing an `AppState`, socket,
//! or database connection. This module deliberately stops before protocol
//! dispatch: it only establishes that one bounded XML transport unit exists.

use anyhow::Result;
use roxmltree::Document;

pub(crate) const WEBSOCKET_FRAMING_NS: &str = "urn:ietf:params:xml:ns:xmpp-framing";

const MAX_BOSH_REQUEST_BYTES: usize = 4 * 1024 * 1024;
const MAX_BODY_ATTRIBUTES: usize = 24;
const MAX_ATTRIBUTE_BYTES: usize = 2_048;

/// Return the one complete BOSH `<body/>` frame after enforcing the shared
/// XML structural limits and BOSH transport ceilings.
///
/// Attribute allow-lists and request-state validation intentionally remain in
/// `bosh::parse_body`, where creation versus established-session semantics are
/// known. Keeping the expensive document/frame work here prevents that policy
/// layer from becoming a second, divergent transport parser.
pub(crate) fn parse_bosh_frame(
    raw: &str,
    max_stanzas: usize,
    max_stanza_bytes: usize,
    http_bind_ns: &str,
) -> Result<String, &'static str> {
    if raw.len() > MAX_BOSH_REQUEST_BYTES {
        return Err("bad-request");
    }
    let mut frame_buffer = raw.to_owned();
    let frame = crate::xmpp::framing::take_frame(&mut frame_buffer)
        .map_err(
            |error| match crate::xmpp::framing::stream_error_condition(&error) {
                "policy-violation" => "policy-violation",
                _ => "bad-request",
            },
        )?
        .ok_or("bad-request")?;
    if !frame_buffer
        .chars()
        .all(crate::xmpp::framing::is_xml_whitespace)
    {
        return Err("bad-request");
    }
    let document = Document::parse(&frame).map_err(|_| "bad-request")?;
    let root = document.root_element();
    if root.tag_name().name() != "body" || root.tag_name().namespace() != Some(http_bind_ns) {
        return Err("bad-request");
    }
    if root.attributes().len() > MAX_BODY_ATTRIBUTES
        || root
            .attributes()
            .any(|attribute| attribute.value().len() > MAX_ATTRIBUTE_BYTES)
        || root.children().any(|child| {
            child.is_text()
                && !child
                    .text()
                    .unwrap_or_default()
                    .chars()
                    .all(crate::xmpp::framing::is_xml_whitespace)
        })
    {
        return Err("bad-request");
    }

    let stanza_count = root.children().filter(|child| child.is_element()).count();
    if stanza_count > max_stanzas
        || root
            .children()
            .filter(|child| child.is_element())
            .any(|child| {
                frame
                    .get(child.range())
                    .map(|stanza| stanza.len() > max_stanza_bytes)
                    .unwrap_or(true)
            })
    {
        return Err("policy-violation");
    }
    Ok(frame)
}

pub(crate) fn websocket_frame_starts_with_markup(value: &str) -> bool {
    value.as_bytes().first() == Some(&b'<')
}

/// Enforce RFC 7395's one-text-message/one-XML-frame invariant using the
/// production XML entity framer. WebSocket messages cannot legally carry a
/// partial stanza or leading/trailing XML stream whitespace.
pub(crate) fn take_websocket_frame(
    value: &str,
    framer: &mut crate::xmpp::framing::XmlEntityFramer,
    max_frame_bytes: usize,
) -> Result<String> {
    // RFC 7395 forbids carrying an incomplete XML frame into a later text
    // message. Preserve entity-level declaration state, but make each message
    // start with a fresh top-level scan even if a defensive caller continues
    // after rejecting the previous message.
    framer.reset_pending_frame();
    let result = (|| {
        if value.len() > max_frame_bytes {
            return Err(crate::xmpp::framing::resource_limit(
                "WebSocket frame bytes",
            ));
        }
        anyhow::ensure!(
            websocket_frame_starts_with_markup(value),
            "an RFC 7395 frame must begin with '<'"
        );
        let mut payload = value.to_owned();
        let frame = framer
            .take_frame(&mut payload)?
            .ok_or_else(|| anyhow::anyhow!("incomplete RFC 7395 XML frame"))?;
        anyhow::ensure!(
            payload.is_empty(),
            "an RFC 7395 message must contain exactly one XML frame"
        );
        Ok(frame)
    })();
    framer.reset_pending_frame();
    result
}

pub(crate) fn websocket_has_invalid_stream_header_namespace(frame: &str) -> bool {
    let Ok(document) = Document::parse(frame) else {
        return false;
    };
    let root = document.root_element();
    matches!(root.tag_name().name(), "open" | "close")
        && root.tag_name().namespace() != Some(WEBSOCKET_FRAMING_NS)
}

pub(crate) fn websocket_close_has_content(frame: &str) -> bool {
    let Ok(document) = Document::parse(frame) else {
        return false;
    };
    let root = document.root_element();
    root.tag_name().name() == "close"
        && root.tag_name().namespace() == Some(WEBSOCKET_FRAMING_NS)
        && root.children().next().is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    const HTTP_BIND_NS: &str = "http://jabber.org/protocol/httpbind";

    #[test]
    fn bosh_frame_rejects_extra_text_and_enforces_stanza_bounds() {
        assert!(parse_bosh_frame(
            "<body xmlns='http://jabber.org/protocol/httpbind' rid='1'/>tail",
            1,
            1024,
            HTTP_BIND_NS,
        )
        .is_err());
        assert_eq!(
            parse_bosh_frame(
                "<body xmlns='http://jabber.org/protocol/httpbind'><iq/><iq/></body>",
                1,
                1024,
                HTTP_BIND_NS,
            ),
            Err("policy-violation")
        );

        let nested_elements = format!("{}{}", "<x>".repeat(257), "</x>".repeat(257));
        let deeply_nested = format!("<body xmlns='{HTTP_BIND_NS}'>{nested_elements}</body>");
        assert_eq!(
            parse_bosh_frame(&deeply_nested, 1, 1024 * 1024, HTTP_BIND_NS),
            Err("policy-violation")
        );
        assert_eq!(
            parse_bosh_frame(
                &format!("\u{00a0}<body xmlns='{HTTP_BIND_NS}'/>"),
                1,
                1024,
                HTTP_BIND_NS,
            ),
            Err("bad-request")
        );
    }

    #[test]
    fn websocket_parser_enforces_one_markup_frame_and_framing_namespace_helpers() {
        let mut framer = crate::xmpp::framing::XmlEntityFramer::default();
        assert_eq!(
            take_websocket_frame("<message xmlns='jabber:client'/>", &mut framer, 1024).unwrap(),
            "<message xmlns='jabber:client'/>"
        );
        assert!(take_websocket_frame(
            "<message xmlns='jabber:client'/><presence xmlns='jabber:client'/>",
            &mut crate::xmpp::framing::XmlEntityFramer::default(),
            1024,
        )
        .is_err());
        assert!(websocket_has_invalid_stream_header_namespace(
            "<open xmlns='jabber:client'/>"
        ));
        assert!(websocket_close_has_content(
            "<close xmlns='urn:ietf:params:xml:ns:xmpp-framing'> </close>"
        ));

        let oversized = format!("<message>{}</message>", "x".repeat(1_025));
        let error = take_websocket_frame(
            &oversized,
            &mut crate::xmpp::framing::XmlEntityFramer::default(),
            1_024,
        )
        .unwrap_err();
        assert_eq!(
            crate::xmpp::framing::stream_error_condition(&error),
            "policy-violation"
        );
    }

    #[test]
    fn rejected_partial_websocket_message_cannot_poison_the_next_utf8_message() {
        let mut framer = crate::xmpp::framing::XmlEntityFramer::default();
        assert!(take_websocket_frame("<xy", &mut framer, 1_024).is_err());

        // The stale cursor from `<xy` was byte 3, which is inside the two-byte
        // `ƞ` in this replacement buffer. Each WebSocket text message must be
        // parsed as an independent top-level frame.
        assert_eq!(
            take_websocket_frame("<aƞ/>", &mut framer, 1_024).unwrap(),
            "<aƞ/>"
        );
    }
}
