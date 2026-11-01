//! Pure judgments and projections of one message stanza: XEP-0334 processing
//! hints, the XEP-0203 delay, the end-to-end encrypted archive projection and
//! the abuse-rated payload test.

use crate::rewrite::{append_root_element, append_root_validated_fragment};
use crate::stanza::{is_encrypted, is_encryption_node};
use crate::XmlElement;
use roxmltree::{Document, Node};
use std::collections::HashSet;

pub const OMEMO2: &str = "urn:xmpp:omemo:2";

pub fn add_delay_from(
    stanza: &str,
    created_at: chrono::DateTime<chrono::Utc>,
    from: Option<&str>,
) -> String {
    let mut delayed = stanza.to_owned();
    if let Ok(document) = Document::parse(stanza) {
        let mut ranges = document
            .root_element()
            .children()
            .filter(|child| {
                child.is_element()
                    && child.tag_name().name() == "delay"
                    && child.tag_name().namespace() == Some("urn:xmpp:delay")
            })
            .map(|child| child.range())
            .collect::<Vec<_>>();
        ranges.sort_by_key(|range| std::cmp::Reverse(range.start));
        for range in ranges {
            delayed.replace_range(range, "");
        }
    }
    let delay = XmlElement::namespaced("delay", "urn:xmpp:delay")
        .optional_attr("from", from)
        .attr("stamp", created_at.format("%Y-%m-%dT%H:%M:%SZ"));
    append_root_element(&delayed, &delay).unwrap_or_else(|| stanza.to_owned())
}

pub fn is_abuse_rated_message(root: Node<'_, '_>) -> bool {
    is_encrypted(root)
        || root.children().any(|node| {
            node.is_element()
                && ((matches!(node.tag_name().name(), "body" | "subject")
                    && matches!(node.tag_name().namespace(), None | Some("jabber:client")))
                    || matches!(
                        (node.tag_name().namespace(), node.tag_name().name()),
                        (Some("urn:xmpp:reactions:0"), "reactions")
                            | (Some("urn:xmpp:sfs:0"), "file-sharing")
                            | (Some("urn:xmpp:chat-markers:0"), "markable" | "displayed")
                            | (Some("http://jabber.org/protocol/chatstates"), _)
                            | (Some("urn:xmpp:message-retract:1"), "retract")
                            | (Some("urn:xmpp:message-correct:0"), "replace")
                            | (Some("urn:xmpp:reply:0"), "reply")
                            | (Some("urn:xmpp:eme:0"), "encryption")
                            | (Some("urn:xmpp:stickers:0"), "sticker")
                            | (Some("urn:xmpp:tm:1"), "trust-message")
                            | (Some("urn:xmpp:jingle-message:0"), _)
                    ))
        })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MessageStoragePolicy {
    pub temporary: bool,
    pub permanent: bool,
}

/// Preserve XEP-0334 hints when a service has to rebuild a routed message
/// (for example, when a MUC service rewrites an invitation). Callers validate
/// the original stanza before using this fragment.
pub fn processing_hints_fragment(root: Node<'_, '_>, raw: &str) -> String {
    root.children()
        .filter(|node| node.is_element() && node.tag_name().namespace() == Some("urn:xmpp:hints"))
        .map(|node| {
            let range = node.range();
            &raw[range.start..range.end]
        })
        .collect()
}

/// Parse XEP-0334 processing hints as a bounded, privacy-preserving policy.
/// The server never treats extension-namespace lookalikes or payload-bearing
/// hints as policy. XEP-0334 defines these elements as hints and does not make
/// combinations a stanza error, so overlapping storage hints use a fixed
/// order independent of child order: `no-store`, `no-permanent-store`, then
/// `store`.
pub fn message_storage_policy(root: Node<'_, '_>) -> Result<MessageStoragePolicy, &'static str> {
    // XEP-0334 section 3 requires intermediaries to ignore processing hints
    // attached to error messages. Error stanzas are never eligible for
    // offline or permanent storage, so do not parse (or reject) hint-shaped
    // children on this branch.
    if root.attribute("type") == Some("error") {
        return Ok(MessageStoragePolicy {
            temporary: false,
            permanent: false,
        });
    }
    let mut store = false;
    let mut no_store = false;
    let mut no_permanent_store = false;
    let mut seen = HashSet::new();
    for hint in root
        .children()
        .filter(|node| node.is_element() && node.tag_name().namespace() == Some("urn:xmpp:hints"))
    {
        let name = hint.tag_name().name();
        if !matches!(
            name,
            "store" | "no-store" | "no-permanent-store" | "no-copy"
        ) {
            // XEP-0334 explicitly permits future hints. Preserve them as
            // opaque data, but apply a small structural bound below.
            if hint.attributes().len() > 16
                || hint.descendants().filter(|node| node.is_element()).count() > 64
                || hint.range().len() > 65_536
            {
                return Err("resource-constraint");
            }
            continue;
        }
        if !seen.insert(name)
            || hint.attributes().len() != 0
            || hint.children().any(|child| child.is_element())
            || hint.text().is_some_and(|text| !text.trim().is_empty())
        {
            return Err("bad-request");
        }
        match name {
            "store" => store = true,
            "no-store" => no_store = true,
            "no-permanent-store" => no_permanent_store = true,
            // XEP-0334 says senders MUST only place this hint on messages to
            // full JIDs.  It also explicitly says the hint does not override
            // RFC 6121 bare-JID fan-out.  An intermediary therefore validates
            // the empty element but ignores its copy semantics unless `to`
            // is a valid full JID; rejecting the whole message would turn a
            // sender-side hint error into avoidable message loss.
            "no-copy" => {}
            _ => unreachable!(),
        }
    }
    if no_store {
        return Ok(MessageStoragePolicy {
            temporary: false,
            permanent: false,
        });
    }
    if no_permanent_store {
        return Ok(MessageStoragePolicy {
            temporary: true,
            permanent: false,
        });
    }
    if store {
        return Ok(MessageStoragePolicy {
            temporary: true,
            permanent: true,
        });
    }

    // Pure chat states and delivery receipts are transient by default.
    let mut found_signal = false;
    for node in root.children().filter(|node| node.is_element()) {
        let namespace = node.tag_name().namespace().unwrap_or_default();
        let name = node.tag_name().name();
        let is_signal = (namespace == "http://jabber.org/protocol/chatstates"
            && matches!(
                name,
                "active" | "composing" | "paused" | "inactive" | "gone"
            ))
            || (namespace == "urn:xmpp:receipts" && name == "received")
            || (namespace == "urn:xmpp:chat-markers:0" && matches!(name, "markable" | "displayed"));
        let is_signal_metadata = namespace == "urn:xmpp:hints"
            || (matches!(namespace, "" | "jabber:client") && name == "thread")
            || namespace == "urn:xmpp:sid:0"
            || (namespace == "urn:northstar:pow:1" && name == "pow");
        if is_signal || is_signal_metadata {
            found_signal |= is_signal;
            continue;
        }
        return Ok(MessageStoragePolicy {
            temporary: true,
            permanent: true,
        });
    }
    Ok(MessageStoragePolicy {
        temporary: !found_signal,
        permanent: !found_signal,
    })
}

pub fn encrypted_archive_stanza(stanza: &str) -> String {
    let Ok(document) = Document::parse(stanza) else {
        return stanza.to_owned();
    };
    let mut ranges: Vec<_> = document
        .root_element()
        .children()
        .filter(|node| {
            node.is_element()
                && !is_encryption_node(*node)
                && !is_safe_encrypted_archive_metadata(*node)
        })
        .map(|node| node.range())
        .collect();
    ranges.sort_by_key(|range| std::cmp::Reverse(range.start));
    let mut safe = stanza.to_owned();
    for range in ranges {
        safe.replace_range(range, "");
    }
    // XEP-0420 0.5.0 forbids a fallback body on SCE messages. Preserve the
    // historical generic fallback only for older encryption formats.
    if document.root_element().children().any(|node| {
        node.is_element()
            && node.tag_name().name() == "encrypted"
            && node.tag_name().namespace() == Some(OMEMO2)
    }) {
        safe
    } else {
        append_root_element(
            &safe,
            &XmlElement::namespaced("body", "jabber:client")
                .text("This message is end-to-end encrypted."),
        )
        .unwrap_or(safe)
    }
}

/// Build the encrypted archive projection for a XEP-0424 retraction without
/// exposing the generic root-fragment insertion primitive outside this
/// serializer module. The runtime target is escaped by the typed builder and
/// callers are expected to have applied the protocol length/control checks.
pub fn encrypted_retraction_archive_stanza(stanza: &str, target_id: &str) -> String {
    let safe = encrypted_archive_stanza(stanza);
    let retract = XmlElement::namespaced("retract", "urn:xmpp:message-retract:1")
        .attr("id", target_id)
        .finish();
    append_root_validated_fragment(&safe, &retract).unwrap_or(safe)
}

fn is_safe_encrypted_archive_metadata(node: Node<'_, '_>) -> bool {
    matches!(
        (node.tag_name().namespace(), node.tag_name().name()),
        (
            Some("urn:xmpp:sid:0"),
            "origin-id" | "stanza-id" | "referenced-stanza"
        ) | (Some("urn:xmpp:eme:0"), "encryption")
            // OMEMO 2 payload messages require the explicit XEP-0334 store
            // hint.  Preserve it in the encrypted projection so a MUC/MAM
            // replay remains a valid stanza when it crosses an S2S boundary
            // and is validated again by the recipient server.
            | (Some("urn:xmpp:hints"), "store")
            | (Some("urn:xmpp:message-correct:0"), "replace")
            | (Some("urn:xmpp:reply:0"), "reply")
            | (Some("urn:xmpp:chat-markers:0"), "markable")
            | (Some("urn:xmpp:receipts"), "request")
    )
}

pub fn has_no_store_hint(root: Node<'_, '_>) -> bool {
    message_storage_policy(root)
        .map(|policy| !policy.permanent)
        .unwrap_or(true)
}

/// Return whether the sender explicitly requested XEP-0334 `no-store`.
///
/// This is intentionally different from [`has_no_store_hint`]: delivery
/// receipts and chat-state notifications are transient *by default*, but
/// that default must not be mistaken for an explicit prohibition on a
/// volatile online delivery.
pub fn has_explicit_no_store_hint(root: Node<'_, '_>) -> bool {
    root.attribute("type") != Some("error")
        && root.children().any(|node| {
            node.is_element()
                && node.tag_name().namespace() == Some("urn:xmpp:hints")
                && node.tag_name().name() == "no-store"
        })
}

pub fn offline_storage_permitted(root: Node<'_, '_>) -> bool {
    message_storage_policy(root)
        .map(|policy| policy.temporary)
        .unwrap_or(false)
}

/// XEP-0313 archives accepted messages, never generated/rejected error
/// stanzas. Processing hints on an error are ignored per XEP-0334, so a
/// malicious `<store/>` cannot force a bounce into somebody's archive.
pub fn mam_storage_eligible(root: Node<'_, '_>) -> bool {
    root.attribute("type") != Some("error")
        && message_storage_policy(root)
            .map(|policy| policy.permanent)
            .unwrap_or(false)
}
