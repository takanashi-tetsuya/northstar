use northstar_message_core::{DirectPostCommitMode, DirectSpoolEligibility};
use northstar_xml_builder::stanza::is_encrypted;

/// A degraded node can accept only an account-scoped, recoverable direct
/// message. Resource-affine and transient stanzas require a live route.
pub(super) fn degraded_inbound_direct_eligible(
    root: roxmltree::Node<'_, '_>,
    bare_target: bool,
    personal_retraction: bool,
    archive_requires_encryption: bool,
) -> bool {
    bare_target
        && matches!(
            root.attribute("type").unwrap_or("normal"),
            "normal" | "chat"
        )
        && !personal_retraction
        && !root.children().any(|node| {
            node.is_element()
                && ((node.tag_name().name() == "x"
                    && node.tag_name().namespace() == Some("jabber:x:conference"))
                    || (node.tag_name().name() == "pubsub"
                        && node.tag_name().namespace()
                            == Some("http://jabber.org/protocol/pubsub")))
        })
        && !signal_only_inbound_direct_message(root)
        && northstar_message_core::direct_delivery_mode(root)
            == northstar_message_core::DirectDeliveryMode::Durable
        && (!archive_requires_encryption || is_encrypted(root))
}

/// A storage hint does not turn a receipt or chat-state signal into a
/// recoverable direct message when live delivery is unavailable.
fn signal_only_inbound_direct_message(root: roxmltree::Node<'_, '_>) -> bool {
    let mut signal = false;
    for node in root.children().filter(roxmltree::Node::is_element) {
        let namespace = node.tag_name().namespace().unwrap_or_default();
        let name = node.tag_name().name();
        let is_signal = (namespace == "http://jabber.org/protocol/chatstates"
            && matches!(
                name,
                "active" | "composing" | "paused" | "inactive" | "gone"
            ))
            || (namespace == "urn:xmpp:receipts" && name == "received")
            || (namespace == "urn:xmpp:chat-markers:0" && matches!(name, "markable" | "displayed"));
        if is_signal {
            signal = true;
            continue;
        }
        if namespace == "urn:xmpp:hints"
            || (matches!(namespace, "" | "jabber:client" | "jabber:server") && name == "thread")
            || namespace == "urn:xmpp:sid:0"
            || (namespace == "urn:northstar:pow:1" && name == "pow")
        {
            continue;
        }
        return false;
    }
    signal
}

pub(super) fn degraded_inbound_privacy_uses_default(
    mode: DirectPostCommitMode,
    spool_eligible: bool,
) -> Option<bool> {
    match mode {
        DirectPostCommitMode::Live => Some(false),
        DirectPostCommitMode::SpoolOnly if spool_eligible => Some(true),
        DirectPostCommitMode::SpoolOnly | DirectPostCommitMode::Rejected => None,
    }
}

pub(super) fn inbound_direct_spool_eligibility(
    statically_eligible: bool,
    default_privacy_denied: bool,
) -> DirectSpoolEligibility {
    if statically_eligible && !default_privacy_denied {
        DirectSpoolEligibility::Eligible
    } else {
        DirectSpoolEligibility::LiveOnly
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum InboundLiveEffect {
    Proceed,
    AcceptedSpool,
    Reject,
}

pub(super) fn inbound_live_effect(
    mode: DirectPostCommitMode,
    committed: bool,
) -> InboundLiveEffect {
    match mode {
        DirectPostCommitMode::Live => InboundLiveEffect::Proceed,
        DirectPostCommitMode::SpoolOnly | DirectPostCommitMode::Rejected if committed => {
            InboundLiveEffect::AcceptedSpool
        }
        DirectPostCommitMode::SpoolOnly | DirectPostCommitMode::Rejected => {
            InboundLiveEffect::Reject
        }
    }
}
