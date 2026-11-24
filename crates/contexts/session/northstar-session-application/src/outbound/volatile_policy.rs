use super::{GuardedEnqueue, OrderedOutboundSink, OutboundFuture, OutboundItem};
use std::{future::Future, pin::Pin};

pub(super) type FinalOutboundPolicy<'a> = Pin<Box<dyn Future<Output = bool> + Send + 'a>>;

pub(super) trait VolatilePolicySink: OrderedOutboundSink<OutboundItem> {
    fn enqueue_with_policy<'a>(
        &'a self,
        item: OutboundItem,
        is_current: &'a (dyn Fn() -> bool + Send + Sync),
        policy: Option<FinalOutboundPolicy<'a>>,
    ) -> OutboundFuture<'a, OutboundItem, GuardedEnqueue<OutboundItem>>;
}
