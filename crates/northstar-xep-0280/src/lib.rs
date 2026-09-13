//! Capability-free XEP-0280 Message Carbons control and copy policy.

use northstar_xep_core::{ExtensionDescriptor, StanzaKind, StanzaRoute, XepId};
use northstar_xml_builder::XmlElement;
use roxmltree::{Document, Node};

pub const XEP_ID: XepId = XepId::new(280);
pub const NAMESPACE: &str = "urn:xmpp:carbons:2";
pub const RULES_NAMESPACE: &str = "urn:xmpp:carbons:rules:0";

pub static DESCRIPTOR: ExtensionDescriptor = ExtensionDescriptor {
    id: XEP_ID,
    name: "Message Carbons",
    default_enabled: true,
    dependencies: &[XepId::new(30)],
    conflicts: &[],
    disco_features: &[NAMESPACE, RULES_NAMESPACE],
    routes: &[
        StanzaRoute {
            stanza: StanzaKind::IqSet,
            namespace: NAMESPACE,
            local_name: "enable",
        },
        StanzaRoute {
            stanza: StanzaKind::IqSet,
            namespace: NAMESPACE,
            local_name: "disable",
        },
    ],
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Control {
    Enable,
    Disable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ControlError {
    UnexpectedAttributes,
    UnexpectedContent,
    UnsupportedElement,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Direction {
    Sent,
    Received,
}

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum BuildError {
    #[error("Carbon address is not a canonical JID")]
    InvalidAddress,
    #[error("forwarded payload is not a standalone jabber:client message")]
    InvalidForwardedMessage,
    #[error("forwarded payload exceeds the safe XML fragment boundary")]
    InvalidFragment,
}

pub fn parse_control(control: Node<'_, '_>) -> Result<Control, ControlError> {
    if control.tag_name().namespace() != Some(NAMESPACE) {
        return Err(ControlError::UnsupportedElement);
    }
    let result = match control.tag_name().name() {
        "enable" => Control::Enable,
        "disable" => Control::Disable,
        _ => return Err(ControlError::UnsupportedElement),
    };
    if control.attributes().len() != 0 {
        return Err(ControlError::UnexpectedAttributes);
    }
    if control.children().any(|child| child.is_element())
        || control.text().is_some_and(|text| !text.trim().is_empty())
    {
        return Err(ControlError::UnexpectedContent);
    }
    Ok(result)
}

/// Decide whether the enclosing client message is eligible for a Carbon.
/// Explicit `<private/>`, applicable XEP-0334 `<no-copy/>`, groupchat and
/// headline messages suppress copies.
pub fn should_copy(root: Node<'_, '_>) -> bool {
    let kind = root.attribute("type").unwrap_or("normal");
    if root.children().any(|node| {
        node.is_element()
            && ((node.tag_name().namespace() == Some(NAMESPACE)
                && node.tag_name().name() == "private")
                || (kind != "error"
                    && root.attribute("to").is_some_and(|to| {
                        northstar_xmpp_types::CanonicalJid::parse(to)
                            .is_ok_and(|target| target.resourcepart().is_some())
                    })
                    && node.tag_name().namespace() == Some("urn:xmpp:hints")
                    && node.tag_name().name() == "no-copy"))
    }) {
        return false;
    }
    if matches!(kind, "groupchat" | "headline") {
        return false;
    }
    if kind == "chat" {
        return true;
    }
    let im_payload = root.children().any(|node| {
        if !node.is_element() {
            return false;
        }
        let namespace = node.tag_name().namespace().unwrap_or_default();
        let name = node.tag_name().name();
        (matches!(namespace, "" | "jabber:client") && name == "body")
            || (namespace == "urn:xmpp:receipts" && matches!(name, "request" | "received"))
            || (namespace == "http://jabber.org/protocol/chatstates"
                && matches!(
                    name,
                    "active" | "composing" | "paused" | "inactive" | "gone"
                ))
            || (namespace == "urn:xmpp:chat-markers:0" && matches!(name, "markable" | "displayed"))
            || (namespace == "jabber:x:conference" && name == "x")
            || (namespace == "http://jabber.org/protocol/muc#user"
                && node.children().any(|child| {
                    child.is_element()
                        && child.tag_name().namespace()
                            == Some("http://jabber.org/protocol/muc#user")
                        && child.tag_name().name() == "invite"
                }))
    });
    matches!(kind, "normal" | "error") && im_payload
}

/// Resource-scoped opt-in plus exact-incarnation exclusions.
pub fn resource_selected(jid: &str, enabled: bool, excluded: &[Option<&str>]) -> bool {
    enabled && !excluded.iter().flatten().any(|excluded| jid == *excluded)
}

pub fn forwarded_sender(forwarded: &str) -> Option<String> {
    forwarded_address(forwarded, "from")
}

pub fn forwarded_recipient(forwarded: &str) -> Option<String> {
    forwarded_address(forwarded, "to")
}

/// Build a server-generated Carbon wrapper around an already standalone
/// `jabber:client` message. Runtime addresses are canonicalized and escaped;
/// the forwarded stanza crosses the shared validated-fragment boundary.
pub fn build_carbon(
    direction: Direction,
    from: &str,
    to: &str,
    forwarded: &str,
) -> Result<String, BuildError> {
    let from = northstar_xmpp_types::canonicalize(from).map_err(|_| BuildError::InvalidAddress)?;
    let to = northstar_xmpp_types::canonicalize(to).map_err(|_| BuildError::InvalidAddress)?;
    let document = Document::parse(forwarded).map_err(|_| BuildError::InvalidForwardedMessage)?;
    let root = document.root_element();
    if root.tag_name().name() != "message" || root.tag_name().namespace() != Some("jabber:client") {
        return Err(BuildError::InvalidForwardedMessage);
    }
    let message_type = root.attribute("type").unwrap_or("normal");
    let mut forwarded_wrapper = XmlElement::namespaced("forwarded", "urn:xmpp:forward:0");
    forwarded_wrapper
        .push_validated_fragment(forwarded)
        .map_err(|_| BuildError::InvalidFragment)?;
    let carbon_name = match direction {
        Direction::Sent => "sent",
        Direction::Received => "received",
    };
    Ok(XmlElement::namespaced("message", "jabber:client")
        .attr("from", from)
        .attr("to", to)
        .attr("type", message_type)
        .child(XmlElement::namespaced(carbon_name, NAMESPACE).child(forwarded_wrapper))
        .finish())
}

fn forwarded_address(forwarded: &str, attribute: &str) -> Option<String> {
    let document = Document::parse(forwarded).ok()?;
    let root = document.root_element();
    (root.tag_name().name() == "message")
        .then(|| root.attribute(attribute))
        .flatten()
        .and_then(|jid| northstar_xmpp_types::canonicalize(jid).ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn document(xml: &str) -> Document<'_> {
        Document::parse(xml).unwrap()
    }

    #[test]
    fn controls_are_empty_and_closed() {
        for (xml, expected) in [
            ("<enable xmlns='urn:xmpp:carbons:2'/>", Control::Enable),
            ("<disable xmlns='urn:xmpp:carbons:2'/>", Control::Disable),
        ] {
            let doc = document(xml);
            assert_eq!(parse_control(doc.root_element()), Ok(expected));
        }
        for xml in [
            "<enable xmlns='urn:xmpp:carbons:2' value='1'/>",
            "<enable xmlns='urn:xmpp:carbons:2'><x/></enable>",
            "<private xmlns='urn:xmpp:carbons:2'/>",
        ] {
            let doc = document(xml);
            assert!(parse_control(doc.root_element()).is_err());
        }
    }

    #[test]
    fn private_and_full_jid_no_copy_suppress_carbons() {
        for xml in [
            "<message type='chat'><private xmlns='urn:xmpp:carbons:2'/></message>",
            "<message type='chat' to='a@example.test/device'><no-copy xmlns='urn:xmpp:hints'/></message>",
            "<message type='headline'><body>news</body></message>",
        ] {
            let doc = document(xml);
            assert!(!should_copy(doc.root_element()), "{xml}");
        }
        let doc = document("<message type='chat'><body>hello</body></message>");
        assert!(should_copy(doc.root_element()));
    }

    #[test]
    fn resource_selection_excludes_primary_and_exact_delivery() {
        assert!(resource_selected("a@example.test/three", true, &[None]));
        assert!(!resource_selected(
            "a@example.test/one",
            true,
            &[Some("a@example.test/one"), None]
        ));
        assert!(!resource_selected("a@example.test/three", false, &[]));
    }

    #[test]
    fn forwarded_peers_must_be_canonicalizable_message_addresses() {
        assert_eq!(
            forwarded_sender("<message from='a@EXAMPLE.test/device'/>").as_deref(),
            Some("a@example.test/device")
        );
        assert_eq!(
            forwarded_recipient("<message to='b@example.test'/>").as_deref(),
            Some("b@example.test")
        );
        assert_eq!(forwarded_sender("<presence from='a@example.test'/>"), None);
    }

    #[test]
    fn carbon_builder_preserves_nested_client_namespace_and_escapes_addresses() {
        let carbon = build_carbon(
            Direction::Sent,
            "alice@EXAMPLE.test",
            "alice@example.test/phone",
            "<message xmlns='jabber:client' to='bob@example.test' type='chat'><body>&lt;safe&gt;</body></message>",
        )
        .unwrap();
        let document = Document::parse(&carbon).unwrap();
        let root = document.root_element();
        assert_eq!(root.attribute("from"), Some("alice@example.test"));
        assert_eq!(root.attribute("type"), Some("chat"));
        let forwarded_message = root
            .descendants()
            .filter(|node| node.is_element() && node.tag_name().name() == "message")
            .nth(1)
            .unwrap();
        assert_eq!(
            forwarded_message.tag_name().namespace(),
            Some("jabber:client")
        );
    }
}
