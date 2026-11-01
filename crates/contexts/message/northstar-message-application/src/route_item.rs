//! The contract between a route and the transport queue that takes its stanza. The application decides what to
//! enqueue and owns the one-use receipt permit; the transport owns the queue and its item type.

use crate::direct_handoff::{LocalEnqueuePermit, Refusal};
use northstar_delivery_core::DurableDelivery;

/// What a route needs from a transport's queue item.
pub trait RouteItem: Sized {
    fn plain(stanza: String) -> Self;
    fn durable(stanza: String, delivery: DurableDelivery) -> Self;
    fn stanza(&self) -> &str;
    fn c2s_delivery(&self) -> Option<DurableDelivery>;
    fn validate_durable_source_shape(&self) -> bool;
}

/// A queue's refusal hands the exact item back.
pub enum QueueRefusal<I> {
    Full(I),
    Closed(I),
}

/// The pre-enqueue gate owns the actual item and its one-use receipt permit.
/// Neither can be replaced after binding. Rejection is not queue backpressure.
pub struct RouteEnqueue<I> {
    item: I,
    permit: Option<LocalEnqueuePermit>,
}
pub struct RouteBindingRejected<I>(pub I);
impl<I> std::fmt::Debug for RouteBindingRejected<I> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RouteBindingRejected { item: [redacted] }")
    }
}
impl<I> std::fmt::Debug for RouteEnqueue<I> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RouteEnqueue { item: [redacted], permit: [redacted] }")
    }
}
pub enum RouteSendError<I> {
    Binding(RouteBindingRejected<I>),
    Full(I),
    Closed(I),
}
impl<I> std::fmt::Debug for RouteSendError<I> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Binding(_) => "RouteSendError::Binding { item: [redacted] }",
            Self::Full(_) => "RouteSendError::Full { item: [redacted] }",
            Self::Closed(_) => "RouteSendError::Closed { item: [redacted] }",
        })
    }
}
impl<I: RouteItem> RouteEnqueue<I> {
    pub fn bind(
        item: I,
        permit: Option<LocalEnqueuePermit>,
        expected_stanza: &str,
    ) -> Result<Self, RouteBindingRejected<I>> {
        if item.stanza() != expected_stanza
            || permit.as_ref().is_some_and(|permit| {
                item.c2s_delivery() != Some(permit.source())
                    || !item.validate_durable_source_shape()
            })
        {
            return Err(RouteBindingRejected(item));
        }
        Ok(Self { item, permit })
    }
    pub fn unobserved(item: I) -> Self {
        Self { item, permit: None }
    }
    /// Offers the exact item to a queue and settles the permit by the queue's answer. The positive receipt is
    /// retained at the actual queue boundary; `send` does its own transport work before it refuses.
    pub fn send_with(
        self,
        send: impl FnOnce(I) -> Result<(), QueueRefusal<I>>,
    ) -> Result<(), RouteSendError<I>> {
        let Self { item, permit } = self;
        let permit = match permit.map(|permit| permit.enter()).transpose() {
            Ok(permit) => permit,
            Err(_) => return Err(RouteSendError::Binding(RouteBindingRejected(item))),
        };
        match send(item) {
            Ok(()) => {
                if let Some(permit) = permit {
                    permit.accepted();
                }
                Ok(())
            }
            Err(QueueRefusal::Full(item)) => {
                if let Some(permit) = permit {
                    permit.refused(Refusal::Full);
                }
                Err(RouteSendError::Full(item))
            }
            Err(QueueRefusal::Closed(item)) => {
                if let Some(permit) = permit {
                    permit.refused(Refusal::Closed);
                }
                Err(RouteSendError::Closed(item))
            }
        }
    }
    #[cfg(any(test, feature = "test-support"))]
    pub fn item(&self) -> &I {
        &self.item
    }
    #[cfg(any(test, feature = "test-support"))]
    pub fn complete_for_fake(self, accepted: bool) -> Result<(), RouteSendError<I>> {
        self.send_with(|item| {
            if accepted {
                Ok(())
            } else {
                Err(QueueRefusal::Closed(item))
            }
        })
    }
}
