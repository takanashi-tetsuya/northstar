//! Borrowed telemetry capabilities for specific federation delivery steps.
//! These ports do not expose the process-wide metric registry.

use northstar_telemetry::metrics::DurationHistogram;
use northstar_telemetry::metrics::DurationTimer;
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Clone, Copy)]
pub struct OnlineQueueAcceptanceTelemetry<'a> {
    durable: &'a AtomicU64,
    volatile: &'a AtomicU64,
}

impl<'a> OnlineQueueAcceptanceTelemetry<'a> {
    pub fn new(durable: &'a AtomicU64, volatile: &'a AtomicU64) -> Self {
        Self { durable, volatile }
    }

    pub fn accepted(self, durable: bool) {
        let counter = if durable { self.durable } else { self.volatile };
        counter.fetch_add(1, Ordering::Relaxed);
    }
}

#[derive(Clone, Copy)]
pub struct OutboxDeliveryTelemetry<'a> {
    duration: &'a DurationHistogram,
}

impl<'a> OutboxDeliveryTelemetry<'a> {
    pub fn new(duration: &'a DurationHistogram) -> Self {
        Self { duration }
    }

    pub fn start_timer(self) -> DurationTimer<'a> {
        self.duration.start_timer()
    }
}

#[derive(Clone, Copy)]
pub struct InboundConnectionTelemetry<'a> {
    total: &'a AtomicU64,
    active: &'a AtomicU64,
}

impl<'a> InboundConnectionTelemetry<'a> {
    pub fn new(total: &'a AtomicU64, active: &'a AtomicU64) -> Self {
        Self { total, active }
    }

    pub fn started(self) {
        self.total.fetch_add(1, Ordering::Relaxed);
        self.active.fetch_add(1, Ordering::Relaxed);
    }

    pub fn finished(self) {
        self.active.fetch_sub(1, Ordering::Relaxed);
    }
}

#[derive(Clone, Copy)]
pub struct InboundDeliveryTelemetry<'a> {
    post_accept_failure: &'a AtomicU64,
    routed: &'a AtomicU64,
}

impl<'a> InboundDeliveryTelemetry<'a> {
    pub fn new(post_accept_failure: &'a AtomicU64, routed: &'a AtomicU64) -> Self {
        Self {
            post_accept_failure,
            routed,
        }
    }

    pub fn post_accept_failed(self) {
        self.post_accept_failure.fetch_add(1, Ordering::Relaxed);
    }

    pub fn routed(self) {
        self.routed.fetch_add(1, Ordering::Relaxed);
    }
}

#[derive(Clone, Copy)]
pub struct OutboundDispositionTelemetry<'a> {
    connection_failure: &'a AtomicU64,
    lease_lost: &'a AtomicU64,
    delivered: &'a AtomicU64,
    permanent_failure: &'a AtomicU64,
    expired: &'a AtomicU64,
    retry: &'a AtomicU64,
}

impl<'a> OutboundDispositionTelemetry<'a> {
    pub fn new(
        connection_failure: &'a AtomicU64,
        lease_lost: &'a AtomicU64,
        delivered: &'a AtomicU64,
        permanent_failure: &'a AtomicU64,
        expired: &'a AtomicU64,
        retry: &'a AtomicU64,
    ) -> Self {
        Self {
            connection_failure,
            lease_lost,
            delivered,
            permanent_failure,
            expired,
            retry,
        }
    }

    pub fn connection_failed(self) {
        self.connection_failure.fetch_add(1, Ordering::Relaxed);
    }
    pub fn lease_lost(self) {
        self.lease_lost.fetch_add(1, Ordering::Relaxed);
    }
    pub fn delivered(self) {
        self.delivered.fetch_add(1, Ordering::Relaxed);
    }
    pub fn permanent_failure(self) {
        self.permanent_failure.fetch_add(1, Ordering::Relaxed);
    }
    pub fn expired(self) {
        self.expired.fetch_add(1, Ordering::Relaxed);
    }
    pub fn retry(self) {
        self.retry.fetch_add(1, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn queue_acceptance_counts_only_the_selected_kind() {
        let durable = AtomicU64::new(0);
        let volatile = AtomicU64::new(0);
        let telemetry = OnlineQueueAcceptanceTelemetry::new(&durable, &volatile);
        telemetry.accepted(true);
        telemetry.accepted(false);
        telemetry.accepted(true);
        assert_eq!(durable.load(Ordering::Relaxed), 2);
        assert_eq!(volatile.load(Ordering::Relaxed), 1);
    }
}
