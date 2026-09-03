//! Strict parsing of XEP-0357 enable/disable IQ payloads and push notification pubsub wire format.

use crate::constants::{XMLNS_PUBSUB, XMLNS_PUSH};
use crate::error::PushError;
use crate::subscription::{
    PublishOptions, PushDisableRequest, PushEnableRequest, PushNode, PushSubscriptionKey,
};
use crate::summary::PushSummary;
use northstar_xmpp_types::CanonicalJid;
use roxmltree::Node;

/// Parse an `<enable xmlns='urn:xmpp:push:0'>` element and return a typed enable request.
///
/// Strict validation:
/// - `jid` attribute is required, must parse as a bare JID (no resource).
/// - `node` attribute is optional; when present, must be non-empty, <= 1024 bytes, no control chars.
/// - At most one child element is permitted (a publish-options `<x>` data form).
/// - No unrecognized or namespaced attributes.
/// - No non-whitespace text nodes.
pub fn parse_enable<'a, 'input>(
    enable: Node<'a, 'input>,
) -> Result<(PushEnableRequest, Option<Node<'a, 'input>>), PushError> {
    // Validate tag
    if enable.tag_name().name() != "enable" {
        return Err(PushError::UnexpectedTagName {
            expected: "enable",
            actual: enable.tag_name().name().to_owned(),
        });
    }
    if enable.tag_name().namespace() != Some(XMLNS_PUSH) {
        return Err(PushError::UnexpectedNamespace {
            expected: XMLNS_PUSH,
            actual: enable.tag_name().namespace().unwrap_or("").to_owned(),
        });
    }

    // Reject unrecognized or namespaced attributes
    for attr in enable.attributes() {
        if attr.namespace().is_some() || !matches!(attr.name(), "jid" | "node") {
            return Err(PushError::BadRequest(format!(
                "unrecognized attribute '{}' on <enable>",
                attr.name()
            )));
        }
    }

    // Reject non-whitespace text content
    if enable
        .children()
        .any(|child| !child.is_element() && child.text().is_some_and(|t| !t.trim().is_empty()))
    {
        return Err(PushError::BadRequest(
            "enable element contains unexpected text content".to_owned(),
        ));
    }

    // Parse service JID (must be bare)
    let service_jid_raw = enable.attribute("jid").ok_or_else(|| {
        PushError::BadRequest("enable element is missing 'jid' attribute".to_owned())
    })?;

    let service_jid = CanonicalJid::parse_bare(service_jid_raw).map_err(|e| {
        // If the JID has a resource part, it will fail parse_bare
        PushError::JidMalformed(format!(
            "push service JID '{service_jid_raw}' is invalid: {e}"
        ))
    })?;

    // Parse optional node
    let node = match enable.attribute("node") {
        None => None,
        Some(n) => Some(PushNode::new(n)?),
    };

    // Parse optional publish-options child element
    let children: Vec<_> = enable.children().filter(|c| c.is_element()).collect();
    if children.len() > 1 {
        return Err(PushError::BadRequest(
            "enable element has more than one child element".to_owned(),
        ));
    }

    let (options, options_node) = if let Some(form_node) = children.first().copied() {
        let opts = PublishOptions::parse(form_node)?;
        (Some(opts), Some(form_node))
    } else {
        (None, None)
    };

    let target = PushSubscriptionKey::new(service_jid, node);
    let request = PushEnableRequest::new(target, options);
    Ok((request, options_node))
}

/// Parse a `<disable xmlns='urn:xmpp:push:0'>` element and return a typed disable request.
///
/// Strict validation:
/// - `jid` attribute is required, must parse as a bare JID.
/// - `node` attribute is optional; when present, must be non-empty and valid.
/// - No child elements or non-whitespace text allowed.
/// - No unrecognized or namespaced attributes.
pub fn parse_disable(disable: Node<'_, '_>) -> Result<PushDisableRequest, PushError> {
    // Validate tag
    if disable.tag_name().name() != "disable" {
        return Err(PushError::UnexpectedTagName {
            expected: "disable",
            actual: disable.tag_name().name().to_owned(),
        });
    }
    if disable.tag_name().namespace() != Some(XMLNS_PUSH) {
        return Err(PushError::UnexpectedNamespace {
            expected: XMLNS_PUSH,
            actual: disable.tag_name().namespace().unwrap_or("").to_owned(),
        });
    }

    // Reject unrecognized or namespaced attributes
    for attr in disable.attributes() {
        if attr.namespace().is_some() || !matches!(attr.name(), "jid" | "node") {
            return Err(PushError::BadRequest(format!(
                "unrecognized attribute '{}' on <disable>",
                attr.name()
            )));
        }
    }

    // Reject any child elements or non-whitespace text
    if disable
        .children()
        .any(|child| child.is_element() || child.text().is_some_and(|t| !t.trim().is_empty()))
    {
        return Err(PushError::BadRequest(
            "disable element must not contain child elements or text".to_owned(),
        ));
    }

    // Parse service JID (must be bare)
    let service_jid_raw = disable.attribute("jid").ok_or_else(|| {
        PushError::BadRequest("disable element is missing 'jid' attribute".to_owned())
    })?;

    let service_jid = CanonicalJid::parse_bare(service_jid_raw).map_err(|e| {
        PushError::JidMalformed(format!(
            "push service JID '{service_jid_raw}' is invalid: {e}"
        ))
    })?;

    // Parse optional node
    let node = match disable.attribute("node") {
        None => None,
        Some(n) => Some(PushNode::new(n)?),
    };

    Ok(PushDisableRequest::new(service_jid, node))
}

/// Validate that an IQ `to` attribute (if present) targets the sender's own bare JID.
///
/// Per XEP-0357 §3, an IQ-set for enable/disable is addressed to the user's own account
/// (bare JID) or has no explicit `to` attribute.
pub fn iq_targets_own_account(iq: Node<'_, '_>, own_bare: &str) -> bool {
    iq.attribute("to").is_none_or(|to| {
        CanonicalJid::parse_bare(to).is_ok_and(|target| target.to_string() == own_bare)
    })
}

/// Parse an inbound push notification IQ-set's `<pubsub>` → `<publish>` → `<item>` →
/// `<notification>` → `<x>` data form chain.
///
/// This extracts the node attribute from `<publish>` and the summary from the inner
/// `<notification xmlns='urn:xmpp:push:0'>` payload.
pub fn parse_notification_iq_payload(
    pubsub: Node<'_, '_>,
) -> Result<(Option<String>, PushSummary), PushError> {
    if pubsub.tag_name().name() != "pubsub" {
        return Err(PushError::UnexpectedTagName {
            expected: "pubsub",
            actual: pubsub.tag_name().name().to_owned(),
        });
    }
    if pubsub.tag_name().namespace() != Some(XMLNS_PUBSUB) {
        return Err(PushError::UnexpectedNamespace {
            expected: XMLNS_PUBSUB,
            actual: pubsub.tag_name().namespace().unwrap_or("").to_owned(),
        });
    }

    let publish = pubsub
        .children()
        .find(|c| c.is_element() && c.tag_name().name() == "publish")
        .ok_or_else(|| {
            PushError::BadRequest("pubsub element is missing <publish> child".to_owned())
        })?;

    let node = publish.attribute("node").map(str::to_owned);

    let item = publish
        .children()
        .find(|c| c.is_element() && c.tag_name().name() == "item")
        .ok_or_else(|| {
            PushError::BadRequest("publish element is missing <item> child".to_owned())
        })?;

    let notification = item
        .children()
        .find(|c| {
            c.is_element()
                && c.tag_name().name() == "notification"
                && c.tag_name().namespace() == Some(XMLNS_PUSH)
        })
        .ok_or_else(|| {
            PushError::BadRequest(
                "item element is missing <notification xmlns='urn:xmpp:push:0'> child".to_owned(),
            )
        })?;

    let summary = PushSummary::parse_notification(notification)?;
    Ok((node, summary))
}

#[cfg(test)]
mod tests {
    use super::*;
    use roxmltree::Document;

    #[test]
    fn parse_enable_with_node_and_options() {
        let xml = "<enable xmlns='urn:xmpp:push:0' jid='Push.Example.test' node='device-1'>\
            <x xmlns='jabber:x:data' type='submit'>\
                <field var='FORM_TYPE'><value>http://jabber.org/protocol/pubsub#publish-options</value></field>\
                <field var='secret'><value>opaque</value></field>\
            </x>\
        </enable>";
        let doc = Document::parse(xml).unwrap();
        let (req, opts_node) = parse_enable(doc.root_element()).unwrap();
        assert_eq!(req.service_jid().to_string(), "push.example.test");
        assert_eq!(req.node_str(), "device-1");
        assert!(req.options.is_some());
        assert!(opts_node.is_some());
    }

    #[test]
    fn parse_enable_without_node_or_options() {
        let xml = "<enable xmlns='urn:xmpp:push:0' jid='push.example.test'/>";
        let doc = Document::parse(xml).unwrap();
        let (req, opts_node) = parse_enable(doc.root_element()).unwrap();
        assert_eq!(req.service_jid().to_string(), "push.example.test");
        assert!(req.node().is_none());
        assert!(req.options.is_none());
        assert!(opts_node.is_none());
    }

    #[test]
    fn parse_enable_rejects_full_jid() {
        let xml = "<enable xmlns='urn:xmpp:push:0' jid='push.example.test/Resource' node='d'/>";
        let doc = Document::parse(xml).unwrap();
        assert!(parse_enable(doc.root_element()).is_err());
    }

    #[test]
    fn parse_enable_rejects_empty_node() {
        let xml = "<enable xmlns='urn:xmpp:push:0' jid='push.example.test' node=''/>";
        let doc = Document::parse(xml).unwrap();
        assert!(parse_enable(doc.root_element()).is_err());
    }

    #[test]
    fn parse_enable_rejects_unknown_child() {
        let xml = "<enable xmlns='urn:xmpp:push:0' jid='push.example.test' node='device'><unknown/></enable>";
        let doc = Document::parse(xml).unwrap();
        assert!(parse_enable(doc.root_element()).is_err());
    }

    #[test]
    fn parse_enable_rejects_wrong_form_type() {
        let xml = "<enable xmlns='urn:xmpp:push:0' jid='push.example.test' node='device'>\
            <x xmlns='jabber:x:data' type='submit'>\
                <field var='FORM_TYPE'><value>wrong</value></field>\
            </x>\
        </enable>";
        let doc = Document::parse(xml).unwrap();
        assert!(parse_enable(doc.root_element()).is_err());
    }

    #[test]
    fn parse_enable_rejects_duplicate_form_type() {
        let xml = "<enable xmlns='urn:xmpp:push:0' jid='push.example.test' node='device'>\
            <x xmlns='jabber:x:data' type='submit'>\
                <field var='FORM_TYPE'><value>http://jabber.org/protocol/pubsub#publish-options</value></field>\
                <field var='FORM_TYPE'><value>http://jabber.org/protocol/pubsub#publish-options</value></field>\
            </x>\
        </enable>";
        let doc = Document::parse(xml).unwrap();
        assert!(parse_enable(doc.root_element()).is_err());
    }

    #[test]
    fn parse_disable_service_wide() {
        let xml = "<disable xmlns='urn:xmpp:push:0' jid='push.example.test'/>";
        let doc = Document::parse(xml).unwrap();
        let req = parse_disable(doc.root_element()).unwrap();
        assert_eq!(req.service_jid.to_string(), "push.example.test");
        assert!(req.node.is_none());
    }

    #[test]
    fn parse_disable_specific_node() {
        let xml = "<disable xmlns='urn:xmpp:push:0' jid='push.example.test' node='device'/>";
        let doc = Document::parse(xml).unwrap();
        let req = parse_disable(doc.root_element()).unwrap();
        assert_eq!(req.service_jid.to_string(), "push.example.test");
        assert_eq!(req.node.as_ref().unwrap().as_str(), "device");
    }

    #[test]
    fn parse_disable_rejects_child_elements() {
        let xml = "<disable xmlns='urn:xmpp:push:0' jid='push.example.test'><x/></disable>";
        let doc = Document::parse(xml).unwrap();
        assert!(parse_disable(doc.root_element()).is_err());
    }

    #[test]
    fn iq_target_validation() {
        let omitted = Document::parse("<iq type='set' id='1'/>").unwrap();
        assert!(iq_targets_own_account(
            omitted.root_element(),
            "alice@example.test"
        ));

        let own = Document::parse("<iq type='set' id='1' to='Alice@Example.test'/>").unwrap();
        assert!(iq_targets_own_account(
            own.root_element(),
            "alice@example.test"
        ));

        let other = Document::parse("<iq type='set' id='1' to='bob@example.test'/>").unwrap();
        assert!(!iq_targets_own_account(
            other.root_element(),
            "alice@example.test"
        ));
    }
}
