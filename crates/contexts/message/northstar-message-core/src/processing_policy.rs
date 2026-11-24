//! Storage and volatile routing policy for validated one-to-one messages.

use crate::DirectDeliveryMode;
use northstar_xml_builder::message_policy::{
    has_explicit_no_store_hint, is_signal_only_message, message_storage_policy,
};
use northstar_xml_builder::stanza::stanza_error_type;
use roxmltree::Node;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MessageDirection {
    Local { healthy: bool },
    Federation { healthy: bool },
    Component { healthy: bool },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MessageEffects {
    /// Storage is permitted, subject to the destination's admission rules.
    Persist {
        permanent: bool,
    },
    NoStore,
    SignalOnly,
    VolatileOnly,
}

impl MessageEffects {
    /// An explicit no-store request requires live acceptance. Other
    /// best-effort traffic can be dropped without reflecting a bounce.
    pub const fn volatile_route_refusal(self) -> Option<(&'static str, &'static str)> {
        match self {
            Self::NoStore => Some(("wait", "service-unavailable")),
            _ => None,
        }
    }
}

/// The stanza error a validation refusal reflects: its RFC 6120 error type
/// and the defined condition.
pub fn validation_refusal(condition: &'static str) -> (&'static str, &'static str) {
    (stanza_error_type(condition), condition)
}

impl From<MessageEffects> for DirectDeliveryMode {
    fn from(effects: MessageEffects) -> Self {
        match effects {
            MessageEffects::Persist { .. } => Self::Durable,
            MessageEffects::NoStore => Self::VolatileExplicitNoStore,
            MessageEffects::SignalOnly | MessageEffects::VolatileOnly => Self::Volatile,
        }
    }
}

pub fn classify_message_effects(root: Node<'_, '_>, direction: MessageDirection) -> MessageEffects {
    let Ok(storage) = message_storage_policy(root) else {
        return MessageEffects::VolatileOnly;
    };
    if root.attribute("type") == Some("error") {
        return MessageEffects::VolatileOnly;
    }
    if has_explicit_no_store_hint(root) {
        return MessageEffects::NoStore;
    }
    if is_signal_only_message(root) {
        let signal_storage = match direction {
            MessageDirection::Local { healthy } => healthy && storage.temporary,
            MessageDirection::Federation { healthy } | MessageDirection::Component { healthy } => {
                healthy
                    && storage.temporary
                    && root.children().any(|child| {
                        child.is_element() && child.has_tag_name(("urn:xmpp:hints", "store"))
                    })
            }
        };
        if !signal_storage {
            return MessageEffects::SignalOnly;
        }
    }
    if storage.temporary {
        MessageEffects::Persist {
            permanent: storage.permanent,
        }
    } else {
        MessageEffects::VolatileOnly
    }
}

#[cfg(test)]
mod tests;
