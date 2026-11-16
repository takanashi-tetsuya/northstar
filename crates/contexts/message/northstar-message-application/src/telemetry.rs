//! Personal-message routing counters.

use northstar_telemetry::metrics::{DurationHistogram, DurationTimer};
use std::sync::atomic::{AtomicU64, Ordering};

/// Counters granted to personal-message routing. A rejected queue write must
/// not become an accepted delivery, including after durable admission.
pub struct PersonalMessageTelemetry<'a> {
    routing_duration: &'a DurationHistogram,
    rate_limited: &'a AtomicU64,
    abuse_backend_failures: &'a AtomicU64,
    messages_routed: &'a AtomicU64,
    post_accept_failures: &'a AtomicU64,
    durable_queue_acceptances: &'a AtomicU64,
    volatile_queue_acceptances: &'a AtomicU64,
    carbon_delivery_failures: &'a AtomicU64,
    carbon_target_timeouts: &'a AtomicU64,
    cluster_legacy_acceptances: &'a AtomicU64,
}

pub struct PersonalMessageTelemetryCells<'a> {
    pub routing_duration: &'a DurationHistogram,
    pub rate_limited: &'a AtomicU64,
    pub abuse_backend_failures: &'a AtomicU64,
    pub messages_routed: &'a AtomicU64,
    pub post_accept_failures: &'a AtomicU64,
    pub durable_queue_acceptances: &'a AtomicU64,
    pub volatile_queue_acceptances: &'a AtomicU64,
    pub carbon_delivery_failures: &'a AtomicU64,
    pub carbon_target_timeouts: &'a AtomicU64,
    pub cluster_legacy_acceptances: &'a AtomicU64,
}

impl<'a> PersonalMessageTelemetry<'a> {
    pub fn new(cells: PersonalMessageTelemetryCells<'a>) -> Self {
        Self {
            routing_duration: cells.routing_duration,
            rate_limited: cells.rate_limited,
            abuse_backend_failures: cells.abuse_backend_failures,
            messages_routed: cells.messages_routed,
            post_accept_failures: cells.post_accept_failures,
            durable_queue_acceptances: cells.durable_queue_acceptances,
            volatile_queue_acceptances: cells.volatile_queue_acceptances,
            carbon_delivery_failures: cells.carbon_delivery_failures,
            carbon_target_timeouts: cells.carbon_target_timeouts,
            cluster_legacy_acceptances: cells.cluster_legacy_acceptances,
        }
    }

    pub fn start_routing_timer(&self) -> DurationTimer<'_> {
        self.routing_duration.start_timer()
    }

    pub fn rate_limited(&self) {
        self.rate_limited.fetch_add(1, Ordering::Relaxed);
    }

    pub fn abuse_backend_failed(&self) {
        self.abuse_backend_failures.fetch_add(1, Ordering::Relaxed);
    }

    pub fn message_routed(&self) {
        self.messages_routed.fetch_add(1, Ordering::Relaxed);
    }

    pub fn post_accept_failed(&self) {
        self.post_accept_failures.fetch_add(1, Ordering::Relaxed);
    }

    pub fn online_queue_result(&self, accepted: bool, durable: bool) {
        if accepted {
            let counter = if durable {
                self.durable_queue_acceptances
            } else {
                self.volatile_queue_acceptances
            };
            counter.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn carbon_delivery_failed(&self) {
        self.carbon_delivery_failures
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn carbon_target_timed_out(&self) {
        self.carbon_target_timeouts.fetch_add(1, Ordering::Relaxed);
    }

    pub fn cluster_legacy_accepted(&self) {
        self.cluster_legacy_acceptances
            .fetch_add(1, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::{PersonalMessageTelemetry, PersonalMessageTelemetryCells};
    use northstar_telemetry::metrics::DurationHistogram;
    use std::sync::atomic::{AtomicU64, Ordering};

    #[test]
    fn queue_acceptance_counts_only_success_and_selects_delivery_class() {
        let histogram = DurationHistogram::default();
        let counters: [AtomicU64; 9] = std::array::from_fn(|_| AtomicU64::new(0));
        let personal = PersonalMessageTelemetry::new(PersonalMessageTelemetryCells {
            routing_duration: &histogram,
            rate_limited: &counters[0],
            abuse_backend_failures: &counters[1],
            messages_routed: &counters[2],
            post_accept_failures: &counters[3],
            durable_queue_acceptances: &counters[4],
            volatile_queue_acceptances: &counters[5],
            carbon_delivery_failures: &counters[6],
            carbon_target_timeouts: &counters[7],
            cluster_legacy_acceptances: &counters[8],
        });

        personal.online_queue_result(false, true);
        assert_eq!(counters[4].load(Ordering::Relaxed), 0);
        assert_eq!(counters[5].load(Ordering::Relaxed), 0);

        personal.online_queue_result(true, true);
        assert_eq!(counters[4].load(Ordering::Relaxed), 1);
        assert_eq!(counters[5].load(Ordering::Relaxed), 0);
    }
}
