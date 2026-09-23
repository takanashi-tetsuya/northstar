//! Borrowed telemetry capabilities for specific federation delivery steps.
//! These ports do not expose the process-wide metric registry.

use crate::metrics::{DurationHistogram, DurationTimer};
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Clone, Copy)]
pub(crate) struct OnlineQueueAcceptanceTelemetry<'a> {
    durable: &'a AtomicU64,
    volatile: &'a AtomicU64,
}

impl<'a> OnlineQueueAcceptanceTelemetry<'a> {
    pub(crate) fn new(durable: &'a AtomicU64, volatile: &'a AtomicU64) -> Self {
        Self { durable, volatile }
    }

    pub(crate) fn accepted(self, durable: bool) {
        let counter = if durable { self.durable } else { self.volatile };
        counter.fetch_add(1, Ordering::Relaxed);
    }
}

#[derive(Clone, Copy)]
pub(crate) struct AcceptedHistoryTelemetry<'a> {
    failure: &'a AtomicU64,
}

impl<'a> AcceptedHistoryTelemetry<'a> {
    pub(crate) fn new(failure: &'a AtomicU64) -> Self {
        Self { failure }
    }

    pub(crate) fn failed(self) {
        self.failure.fetch_add(1, Ordering::Relaxed);
    }
}

#[derive(Clone, Copy)]
pub(crate) struct OutboxDeliveryTelemetry<'a> {
    duration: &'a DurationHistogram,
}

impl<'a> OutboxDeliveryTelemetry<'a> {
    pub(crate) fn new(duration: &'a DurationHistogram) -> Self {
        Self { duration }
    }

    pub(crate) fn start_timer(self) -> DurationTimer<'a> {
        self.duration.start_timer()
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
