//! The transport-independent validation of routed messages and the rewrites that make a stanza safe to forward.

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use northstar_xml_builder::rewrite::set_client_namespace;
use roxmltree::{Document, Node};
use std::collections::HashSet;

mod message_validation;

use self::message_validation::{
    validate_chat_states, validate_correction, validate_displayed_marker,
    validate_explicit_encryption, validate_fallbacks, validate_file_sharing,
    validate_no_client_tombstone, validate_omemo2_envelope, validate_private_carbon_marker,
    validate_processing_hints, validate_reactions, validate_reply, validate_stanza_ids,
    validate_sticker, validate_trust_message,
};

/// Reject a client-provided Carbon wrapper.  A server must be the only entity
/// that can assert `<sent/>` or `<received/>`; forwarding such a wrapper would
/// recreate the impersonation class behind CVE-2017-5589 and can also create
/// Carbon loops between resources.
pub fn validate_no_client_carbon(root: Node<'_, '_>) -> Result<(), &'static str> {
    if root.descendants().any(|node| {
        node.is_element()
            && node.tag_name().namespace() == Some("urn:xmpp:carbons:2")
            && matches!(node.tag_name().name(), "sent" | "received")
    }) {
        return Err("not-allowed");
    }
    Ok(())
}

/// Apply the complete, transport-independent validation boundary for a
/// routed message. Keeping this ordering in one place prevents C2S, S2S,
/// federated MUC and federated MIX from accepting different archive/copy
/// controls merely because they entered through different transports.
pub fn validate_routed_message(
    root: Node<'_, '_>,
    extensions: &northstar_xep_catalog::ExtensionRuntime,
) -> Result<(), &'static str> {
    validate_enabled_message_extensions(root, extensions)?;
    validate_delivery_receipts(root)?;
    validate_modern_message_payloads(root)?;
    validate_no_client_carbon(root)
}

/// Fail closed before interpreting an optional message extension. A disabled
/// XEP is absent from service discovery and every transport-facing route; an
/// endpoint cannot bypass that decision by sending the namespace over S2S,
/// federated MUC or federated MIX instead of C2S.
fn validate_enabled_message_extensions(
    root: Node<'_, '_>,
    extensions: &northstar_xep_catalog::ExtensionRuntime,
) -> Result<(), &'static str> {
    for (id, namespace) in [
        (northstar_xep_0085::XEP_ID, northstar_xep_0085::NAMESPACE),
        (northstar_xep_0184::XEP_ID, northstar_xep_0184::NAMESPACE),
        (northstar_xep_0308::XEP_ID, northstar_xep_0308::NAMESPACE),
        (northstar_xep_0333::XEP_ID, northstar_xep_0333::NAMESPACE),
        (northstar_xep_0359::XEP_ID, northstar_xep_0359::NAMESPACE),
        (northstar_xep_0380::XEP_ID, northstar_xep_0380::NAMESPACE),
        (northstar_xep_0444::XEP_ID, northstar_xep_0444::NAMESPACE),
        (northstar_xep_0461::XEP_ID, northstar_xep_0461::NAMESPACE),
    ] {
        if !extensions.enabled(id)
            && root
                .children()
                .any(|node| node.is_element() && node.tag_name().namespace() == Some(namespace))
        {
            return Err("feature-not-implemented");
        }
    }
    Ok(())
}

pub fn carbon_message(kind: &str, from: &str, to: &str, forwarded: &str) -> Option<String> {
    // The XEP-0280 wrapper name is protocol state, never caller-controlled
    // XML. Keep the legacy string-shaped API temporarily, but collapse it to
    // the only two legal element names before it reaches the serializer. This
    // makes an accidental future call with an untrusted value non-injectable.
    let direction = if kind == "sent" {
        northstar_xep_0280::Direction::Sent
    } else if kind == "received" {
        northstar_xep_0280::Direction::Received
    } else {
        return None;
    };
    // A stanza received on a TCP stream is allowed to inherit
    // `jabber:client` from the stream root, so its standalone serialization
    // does not necessarily contain an xmlns attribute. Once that stanza is
    // nested below XEP-0297 <forwarded/>, however, it would inherit
    // `urn:xmpp:forward:0` and stop being a client <message/>. Standards
    // clients (including Gajim) correctly ignore such a malformed Carbon.
    // Make the namespace boundary explicit before embedding the stanza; the
    // same conversion also turns an S2S `jabber:server` root into the C2S
    // namespace expected by the receiving resource.
    let forwarded = set_client_namespace(forwarded);
    northstar_xep_0280::build_carbon(direction, from, to, &forwarded).ok()
}

/// Remove direct XEP-0203 assertions that the current transport cannot
/// authenticate. Nested delays inside a `<forwarded/>` payload are opaque
/// extension data and are intentionally left alone. A C2S client has no
/// authority to assert a server delay, while an S2S peer may assert one only
/// from the exact domain authenticated on that stream.
pub fn strip_untrusted_direct_delays(stanza: &str, trusted_domain: Option<&str>) -> String {
    let trusted_domain = trusted_domain
        .and_then(|domain| northstar_xmpp_types::jid::prepare_domainpart(domain).ok());
    let Ok(document) = Document::parse(stanza) else {
        return stanza.to_owned();
    };
    let direct_delays = document
        .root_element()
        .children()
        .filter(|child| {
            child.is_element()
                && child.tag_name().name() == "delay"
                && child.tag_name().namespace() == Some("urn:xmpp:delay")
        })
        .collect::<Vec<_>>();
    if direct_delays.is_empty() {
        return stanza.to_owned();
    }
    // XEP-0203 requires one and only one direct delay marker. Preserve that
    // marker only when the authenticated S2S hop can vouch for its source and
    // the timestamp uses XEP-0082's UTC (`Z`) profile. Natural-language reason
    // text is permitted by XEP-0203 and remains bounded here.
    let keep_single = direct_delays.len() == 1
        && direct_delays[0].attributes().all(|attribute| {
            attribute.namespace().is_none() && matches!(attribute.name(), "from" | "stamp")
        })
        && direct_delays[0].attribute("stamp").is_some_and(|stamp| {
            stamp.len() <= 64
                && stamp.ends_with('Z')
                && chrono::DateTime::parse_from_rfc3339(stamp)
                    .is_ok_and(|stamp| stamp.offset().local_minus_utc() == 0)
        })
        && !direct_delays[0].children().any(|node| node.is_element())
        && direct_delays[0]
            .text()
            .is_none_or(|text| text.len() <= 4_096)
        && trusted_domain.as_ref().is_some_and(|trusted| {
            direct_delays[0]
                .attribute("from")
                .map(|from| {
                    northstar_xmpp_types::jid::CanonicalJid::parse(from)
                        .is_ok_and(|from| from.domainpart() == trusted)
                })
                // `from` is only RECOMMENDED, not required. The authenticated
                // S2S domain is still authoritative for an omitted source.
                .unwrap_or(true)
        });
    if keep_single {
        return stanza.to_owned();
    }
    let mut ranges = direct_delays
        .into_iter()
        .map(|child| child.range())
        .collect::<Vec<_>>();
    ranges.sort_by_key(|range| std::cmp::Reverse(range.start));
    let mut sanitized = stanza.to_owned();
    for range in ranges {
        sanitized.replace_range(range, "");
    }
    sanitized
}

/// Validate XEP-0184 wire invariants without generating a receipt on behalf of
/// a client. A receipt is an end-to-end client assertion; the server only
/// validates and routes it.
pub fn validate_delivery_receipts(root: Node<'_, '_>) -> Result<(), &'static str> {
    northstar_xep_0184::parse_message(root)
        .map(|_| ())
        .map_err(|_| "bad-request")
}

/// Validate message-extension wire shapes before routing and archiving.
/// Rendering and decryption belong to the client.
pub fn validate_modern_message_payloads(root: Node<'_, '_>) -> Result<(), &'static str> {
    validate_processing_hints(root)?;
    validate_private_carbon_marker(root)?;
    validate_stanza_ids(root)?;
    crate::jingle::validate_jmi_message(root)?;
    validate_chat_states(root)?;
    validate_omemo2_envelope(root)?;
    validate_explicit_encryption(root)?;
    validate_fallbacks(root)?;
    validate_correction(root)?;
    validate_displayed_marker(root)?;
    validate_no_client_tombstone(root)?;
    validate_reactions(root)?;
    validate_reply(root)?;
    validate_file_sharing(root)?;
    validate_sticker(root)?;
    validate_trust_message(root)?;
    Ok(())
}

const OMEMO2: &str = northstar_xml_builder::message_policy::OMEMO2;
const SCE: &str = "urn:xmpp:sce:1";
const MAX_OMEMO2_ENCRYPTED_BYTES: usize = 2 * 1024 * 1024;
const MAX_OMEMO2_PAYLOAD_BYTES: usize = 1024 * 1024;
const MAX_OMEMO2_KEY_BYTES: usize = 64 * 1024;
const MAX_OMEMO2_KEY_GROUPS: usize = 1024;
const MAX_OMEMO2_KEYS_PER_GROUP: usize = 1024;
const MAX_OMEMO2_TOTAL_KEYS: usize = 8192;

#[cfg(test)]
mod tests;
