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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SmUnackedStanza {
    pub stanza: String,
    pub durable_delivery: Option<DurableDelivery>,
}

impl SmUnackedStanza {
    pub fn plain(stanza: String) -> Self {
        Self {
            stanza,
            durable_delivery: None,
        }
    }

    pub fn with_delivery(stanza: String, durable_delivery: Option<DurableDelivery>) -> Self {
        Self {
            stanza,
            durable_delivery,
        }
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
        assert_eq!(entry.durable_delivery, Some(delivery));
    }
}
