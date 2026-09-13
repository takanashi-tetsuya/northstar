//! Capability-free durable delivery values shared by transports and XEP-0198.

#![forbid(unsafe_code)]

use std::{future::Future, pin::Pin};
use uuid::Uuid;

/// Loss-explicit result returned by a non-blocking ordered transport sink.
/// The rejected item is always returned to its caller so a durable owner can
/// release or retry the exact database projection instead of silently losing
/// it in an adapter-specific error.
#[derive(Debug)]
pub enum OutboundQueueError<T> {
    Backpressured(T),
    Closed(T),
}

impl<T> OutboundQueueError<T> {
    pub fn into_item(self) -> T {
        match self {
            Self::Backpressured(item) | Self::Closed(item) => item,
        }
    }
}

/// A guarded send can decline an item after waiting for capacity when the
/// caller's route/claim fence is no longer current. This is not a transport
/// failure: the authoritative durable projection remains with the caller.
#[derive(Debug)]
pub enum GuardedEnqueue<T> {
    Queued,
    Stale(T),
}

pub type OutboundFuture<'a, T, R> =
    Pin<Box<dyn Future<Output = Result<R, OutboundQueueError<T>>> + Send + 'a>>;

/// Transport-neutral ordered output port used by the session/application
/// layers. Implementations may use Tokio, another executor, an in-process
/// test double or a remote transport actor, but must preserve FIFO admission
/// and return every item which did not cross the queue boundary.
pub trait OrderedOutboundSink<T>: Send + Sync {
    fn try_enqueue(&self, item: T) -> Result<(), OutboundQueueError<T>>;

    fn enqueue<'a>(&'a self, item: T) -> OutboundFuture<'a, T, ()>;

    fn enqueue_if_current<'a>(
        &'a self,
        item: T,
        is_current: &'a (dyn Fn() -> bool + Send + Sync),
    ) -> OutboundFuture<'a, T, GuardedEnqueue<T>>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DurableDelivery {
    pub recipient_id: Uuid,
    pub message_id: Uuid,
    pub claim_id: Option<Uuid>,
}

/// The exact lease of a durable MIX recipient projection.
///
/// Unlike a C2S offline message, a MIX delivery is not identified by a
/// recipient/message pair.  Both UUIDs are required at every transport
/// hand-off so an old BOSH or XEP-0198 acknowledgement cannot consume a row
/// which a later worker has re-leased.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MixDelivery {
    pub delivery_id: Uuid,
    pub lease_token: Uuid,
}

/// One recoverable source for an outbound stanza.
///
/// Keeping this as an enum makes C2S and MIX ownership mutually exclusive at
/// the type boundary.  It replaces the former pattern where an item could
/// accidentally carry an offline fence plus an unrelated in-memory receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransportOwnershipSource {
    C2s(DurableDelivery),
    Mix(MixDelivery),
}

impl TransportOwnershipSource {
    pub const fn c2s(self) -> Option<DurableDelivery> {
        match self {
            Self::C2s(delivery) => Some(delivery),
            Self::Mix(_) => None,
        }
    }

    pub const fn mix(self) -> Option<MixDelivery> {
        match self {
            Self::C2s(_) => None,
            Self::Mix(delivery) => Some(delivery),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SmUnackedStanza {
    pub stanza: String,
    pub source: Option<TransportOwnershipSource>,
}

impl SmUnackedStanza {
    pub fn plain(stanza: String) -> Self {
        Self {
            stanza,
            source: None,
        }
    }

    pub fn with_source(stanza: String, source: Option<TransportOwnershipSource>) -> Self {
        Self { stanza, source }
    }

    /// Compatibility constructor for the C2S-only callers.  New durable
    /// paths must use [`Self::with_source`] so the source kind stays explicit.
    pub fn with_delivery(stanza: String, durable_delivery: Option<DurableDelivery>) -> Self {
        Self::with_source(stanza, durable_delivery.map(TransportOwnershipSource::C2s))
    }

    pub fn durable_delivery(&self) -> Option<DurableDelivery> {
        self.source.and_then(TransportOwnershipSource::c2s)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecipientDeliveryIdentity {
    Missing,
    Exact(Uuid),
    Invalid,
}

pub fn recipient_delivery_identity(
    stanza: &str,
    expected_recipient: &str,
) -> RecipientDeliveryIdentity {
    let Ok(recipient) = northstar_xmpp_types::CanonicalJid::parse(expected_recipient) else {
        return RecipientDeliveryIdentity::Invalid;
    };
    let expected_by = recipient.bare();
    let Ok(document) = roxmltree::Document::parse(stanza) else {
        return RecipientDeliveryIdentity::Invalid;
    };
    let root = document.root_element();
    if root.tag_name().name() != "message" {
        return RecipientDeliveryIdentity::Invalid;
    }
    let mut identities = root.children().filter_map(|child| {
        if !child.is_element()
            || child.tag_name().name() != "stanza-id"
            || child.tag_name().namespace() != Some("urn:xmpp:sid:0")
        {
            return None;
        }
        let by = northstar_xmpp_types::CanonicalJid::parse(child.attribute("by")?).ok()?;
        (by.bare() == expected_by).then_some(child.attribute("id"))
    });
    let Some(first) = identities.next() else {
        return RecipientDeliveryIdentity::Missing;
    };
    if identities.next().is_some() {
        return RecipientDeliveryIdentity::Invalid;
    }
    first.and_then(|value| Uuid::parse_str(value).ok()).map_or(
        RecipientDeliveryIdentity::Invalid,
        RecipientDeliveryIdentity::Exact,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recovers_only_the_recipient_authoritative_identity() {
        let message_id = Uuid::from_u128(2);
        let stanza = format!(
            "<message to='Bob@Example.COM/Phone'><stanza-id xmlns='urn:xmpp:sid:0' by='sender.test' id='ignored'/><stanza-id xmlns='urn:xmpp:sid:0' by='bob@example.com' id='{message_id}'/></message>"
        );
        assert_eq!(
            recipient_delivery_identity(&stanza, "bob@example.com/OtherResource"),
            RecipientDeliveryIdentity::Exact(message_id)
        );
    }

    #[test]
    fn rejects_ambiguous_unrelated_and_malformed_identities() {
        let first = Uuid::from_u128(3);
        let second = Uuid::from_u128(4);
        let ambiguous = format!(
            "<message><stanza-id xmlns='urn:xmpp:sid:0' by='bob@example.com' id='{first}'/><stanza-id xmlns='urn:xmpp:sid:0' by='Bob@Example.COM' id='{second}'/></message>"
        );
        assert_eq!(
            recipient_delivery_identity(&ambiguous, "bob@example.com"),
            RecipientDeliveryIdentity::Invalid
        );
        assert_eq!(
            recipient_delivery_identity("<message/>", "bob@example.com"),
            RecipientDeliveryIdentity::Missing
        );
        assert_eq!(
            recipient_delivery_identity("<presence/>", "bob@example.com"),
            RecipientDeliveryIdentity::Invalid
        );
    }

    #[test]
    fn sm_entry_keeps_the_exact_delivery_fence() {
        let delivery = DurableDelivery {
            recipient_id: Uuid::from_u128(1),
            message_id: Uuid::from_u128(2),
            claim_id: Some(Uuid::from_u128(3)),
        };
        let entry = SmUnackedStanza::with_delivery("<message/>".to_owned(), Some(delivery));
        assert_eq!(entry.source, Some(TransportOwnershipSource::C2s(delivery)));
        assert_eq!(entry.durable_delivery(), Some(delivery));
    }

    #[test]
    fn sm_entry_cannot_mix_c2s_and_mix_ownership() {
        let source = TransportOwnershipSource::Mix(MixDelivery {
            delivery_id: Uuid::from_u128(4),
            lease_token: Uuid::from_u128(5),
        });
        let entry = SmUnackedStanza::with_source("<message/>".to_owned(), Some(source));
        assert_eq!(entry.source, Some(source));
        assert_eq!(entry.durable_delivery(), None);
    }
}
