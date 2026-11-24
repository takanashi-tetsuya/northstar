use northstar_message_core::processing_policy::{
    classify_message_effects, MessageDirection, MessageEffects,
};
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
        && matches!(
            classify_message_effects(root, MessageDirection::Local { healthy: false }),
            MessageEffects::Persist { .. }
        )
        && (!archive_requires_encryption || is_encrypted(root))
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
