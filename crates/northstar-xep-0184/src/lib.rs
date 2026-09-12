//! Capability-free XEP-0184 Message Delivery Receipts wire support.
//!
//! The module validates and describes end-to-end receipt payloads. It does not
//! gain access to accounts, sessions, persistence, or transports, and it never
//! generates an acknowledgement merely because the server observed delivery.

use northstar_xep_core::{ExtensionDescriptor, StanzaKind, StanzaRoute, XepId};
use roxmltree::Node;
use std::fmt::Write;

pub const XEP_ID: XepId = XepId::new(184);
pub const NAMESPACE: &str = "urn:xmpp:receipts";

pub static DESCRIPTOR: ExtensionDescriptor = ExtensionDescriptor {
    id: XEP_ID,
    name: "Message Delivery Receipts",
    default_enabled: true,
    dependencies: &[XepId::new(30)],
    conflicts: &[],
    disco_features: &[NAMESPACE],
    routes: &[
        StanzaRoute {
            stanza: StanzaKind::Message,
            namespace: NAMESPACE,
            local_name: "request",
        },
        StanzaRoute {
            stanza: StanzaKind::Message,
            namespace: NAMESPACE,
            local_name: "received",
        },
    ],
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeliveryReceipt<'a> {
    Request { message_id: &'a str },
    Received { id: &'a str },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RoutingPolicy {
    /// A request accompanies the message content and follows its durability
    /// decision; the server does not acknowledge it itself.
    EndToEndRequest,
    /// A receipt is a client-originated signal and is transient unless another
    /// extension gives the enclosing message durable content.
    EndToEndTransientAcknowledgement,
}

impl DeliveryReceipt<'_> {
    pub const fn routing_policy(self) -> RoutingPolicy {
        match self {
            Self::Request { .. } => RoutingPolicy::EndToEndRequest,
            Self::Received { .. } => RoutingPolicy::EndToEndTransientAcknowledgement,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ValidationError {
    AmbiguousReceipt,
    ElementHasContent,
    InvalidRequestAttributes,
    MissingMessageId,
    InvalidMessageId,
    MissingReceivedId,
    InvalidReceivedId,
}

/// Parse and validate the direct XEP-0184 child of an enclosing message.
///
/// Unknown elements in the receipts namespace are not claimed by this XEP
/// module. At most one `request` or `received` is accepted, and the two forms
/// cannot coexist.
pub fn parse_message<'a, 'input>(
    root: Node<'a, 'input>,
) -> Result<Option<DeliveryReceipt<'a>>, ValidationError> {
    let receipts = root
        .children()
        .filter(|node| {
            node.is_element()
                && node.tag_name().namespace() == Some(NAMESPACE)
                && matches!(node.tag_name().name(), "request" | "received")
        })
        .collect::<Vec<_>>();
    if receipts.len() > 1 {
        return Err(ValidationError::AmbiguousReceipt);
    }
    let Some(receipt) = receipts.into_iter().next() else {
        return Ok(None);
    };
    if receipt.children().any(|node| node.is_element())
        || receipt.text().is_some_and(|text| !text.trim().is_empty())
    {
        return Err(ValidationError::ElementHasContent);
    }

    match receipt.tag_name().name() {
        "request" => {
            if receipt.attributes().len() != 0 {
                return Err(ValidationError::InvalidRequestAttributes);
            }
            let id = root
                .attribute("id")
                .ok_or(ValidationError::MissingMessageId)?;
            validate_id(id).map_err(|()| ValidationError::InvalidMessageId)?;
            Ok(Some(DeliveryReceipt::Request { message_id: id }))
        }
        "received" => {
            let id = receipt
                .attribute("id")
                .ok_or(ValidationError::MissingReceivedId)?;
            validate_id(id).map_err(|()| ValidationError::InvalidReceivedId)?;
            if receipt
                .attributes()
                .any(|attribute| attribute.namespace().is_some() || attribute.name() != "id")
            {
                return Err(ValidationError::InvalidReceivedId);
            }
            Ok(Some(DeliveryReceipt::Received { id }))
        }
        _ => unreachable!("receipt child filter admits only XEP-0184 elements"),
    }
}

pub const fn build_request() -> &'static str {
    "<request xmlns='urn:xmpp:receipts'/>"
}

pub fn build_received(id: &str) -> Result<String, ValidationError> {
    validate_id(id).map_err(|()| ValidationError::InvalidReceivedId)?;
    let mut xml = String::with_capacity(id.len() + 48);
    xml.push_str("<received xmlns='urn:xmpp:receipts' id='");
    escape_attribute(&mut xml, id);
    xml.push_str("'/>");
    Ok(xml)
}

fn validate_id(id: &str) -> Result<(), ()> {
    if id.is_empty() || id.len() > 1_024 || id.chars().any(char::is_control) {
        Err(())
    } else {
        Ok(())
    }
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
                // Writing a char into a String cannot fail.
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
    enum OwnedReceipt {
        Request(String),
        Received(String),
    }

    fn parse(xml: &str) -> Result<Option<OwnedReceipt>, ValidationError> {
        let document = Document::parse(xml).expect("valid fixture XML");
        parse_message(document.root_element()).map(|receipt| {
            receipt.map(|receipt| match receipt {
                DeliveryReceipt::Request { message_id } => {
                    OwnedReceipt::Request(message_id.to_owned())
                }
                DeliveryReceipt::Received { id } => OwnedReceipt::Received(id.to_owned()),
            })
        })
    }

    #[test]
    fn parses_request_and_received_forms() {
        assert_eq!(
            parse("<message id='m1'><request xmlns='urn:xmpp:receipts'/></message>"),
            Ok(Some(OwnedReceipt::Request("m1".to_owned())))
        );
        assert_eq!(
            parse("<message><received xmlns='urn:xmpp:receipts' id='m1'/></message>"),
            Ok(Some(OwnedReceipt::Received("m1".to_owned())))
        );
        assert_eq!(parse("<message><body>none</body></message>"), Ok(None));
    }

    #[test]
    fn rejects_ambiguous_or_malformed_receipts() {
        for xml in [
            "<message><request xmlns='urn:xmpp:receipts'/></message>",
            "<message><received xmlns='urn:xmpp:receipts'/></message>",
            "<message id='m1'><request xmlns='urn:xmpp:receipts'/><received xmlns='urn:xmpp:receipts' id='m0'/></message>",
            "<message id='m1'><received xmlns='urn:xmpp:receipts' evil:id='m0' xmlns:evil='urn:evil'/></message>",
            "<message id='m1'><request xmlns='urn:xmpp:receipts'>text</request></message>",
        ] {
            assert!(parse(xml).is_err(), "{xml}");
        }
    }

    #[test]
    fn builder_escapes_id_and_round_trips() {
        let xml = format!(
            "<message>{}</message>",
            build_received("one'&\"<two>").unwrap()
        );
        assert_eq!(
            parse(&xml),
            Ok(Some(OwnedReceipt::Received("one'&\"<two>".to_owned())))
        );
        assert_eq!(build_request(), "<request xmlns='urn:xmpp:receipts'/>");
    }

    #[test]
    fn policy_keeps_receipts_end_to_end() {
        assert_eq!(
            DeliveryReceipt::Request { message_id: "m1" }.routing_policy(),
            RoutingPolicy::EndToEndRequest
        );
        assert_eq!(
            DeliveryReceipt::Received { id: "m1" }.routing_policy(),
            RoutingPolicy::EndToEndTransientAcknowledgement
        );
    }
}
