//! Narrow telemetry borrowed from the metrics owner for XMPP runtime tasks.
//! Protocol handlers receive only the counters and timer they actually use;
//! this module never exposes the complete process registry or application state.

use std::sync::atomic::{AtomicU64, Ordering};

use crate::metrics::{DurationHistogram, DurationTimer};

pub(crate) struct PostActionTelemetry<'a> {
    started: &'a AtomicU64,
    completed: &'a AtomicU64,
    panicked: &'a AtomicU64,
    aborted: &'a AtomicU64,
    capacity_rejected: &'a AtomicU64,
}

impl<'a> PostActionTelemetry<'a> {
    pub(crate) fn new(
        started: &'a AtomicU64,
        completed: &'a AtomicU64,
        panicked: &'a AtomicU64,
        aborted: &'a AtomicU64,
        capacity_rejected: &'a AtomicU64,
    ) -> Self {
        Self {
            started,
            completed,
            panicked,
            aborted,
            capacity_rejected,
        }
    }

    pub(crate) fn started(&self) {
        self.started.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn completed(&self) {
        self.completed.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn panicked(&self) {
        self.panicked.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn aborted(&self, count: usize) {
        self.aborted.fetch_add(count as u64, Ordering::Relaxed);
    }

    pub(crate) fn capacity_rejected(&self) {
        self.capacity_rejected.fetch_add(1, Ordering::Relaxed);
    }
}

/// Counters granted to personal-message routing. A rejected queue write must
/// not become an accepted delivery, including after durable admission.
pub(crate) struct PersonalMessageTelemetry<'a> {
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

pub(crate) struct PersonalMessageTelemetryCells<'a> {
    pub(crate) routing_duration: &'a DurationHistogram,
    pub(crate) rate_limited: &'a AtomicU64,
    pub(crate) abuse_backend_failures: &'a AtomicU64,
    pub(crate) messages_routed: &'a AtomicU64,
    pub(crate) post_accept_failures: &'a AtomicU64,
    pub(crate) durable_queue_acceptances: &'a AtomicU64,
    pub(crate) volatile_queue_acceptances: &'a AtomicU64,
    pub(crate) carbon_delivery_failures: &'a AtomicU64,
    pub(crate) carbon_target_timeouts: &'a AtomicU64,
    pub(crate) cluster_legacy_acceptances: &'a AtomicU64,
}

impl<'a> PersonalMessageTelemetry<'a> {
    pub(crate) fn new(cells: PersonalMessageTelemetryCells<'a>) -> Self {
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

    pub(crate) fn start_routing_timer(&self) -> DurationTimer<'_> {
        self.routing_duration.start_timer()
    }

    pub(crate) fn rate_limited(&self) {
        self.rate_limited.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn abuse_backend_failed(&self) {
        self.abuse_backend_failures.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn message_routed(&self) {
        self.messages_routed.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn post_accept_failed(&self) {
        self.post_accept_failures.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn online_queue_result(&self, accepted: bool, durable: bool) {
        if accepted {
            let counter = if durable {
                self.durable_queue_acceptances
            } else {
                self.volatile_queue_acceptances
            };
            counter.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub(crate) fn carbon_delivery_failed(&self) {
        self.carbon_delivery_failures
            .fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn carbon_target_timed_out(&self) {
        self.carbon_target_timeouts.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn cluster_legacy_accepted(&self) {
        self.cluster_legacy_acceptances
            .fetch_add(1, Ordering::Relaxed);
    }
}

/// Only the counters touched by federated MUC room/invite delivery.
pub(crate) struct FederatedMucTelemetry<'a> {
    post_commit_delivery_failures: &'a AtomicU64,
    post_accept_failures: &'a AtomicU64,
    capacity_rejections: &'a AtomicU64,
    durable_queue_acceptances: &'a AtomicU64,
    volatile_queue_acceptances: &'a AtomicU64,
    messages_routed: &'a AtomicU64,
}

impl<'a> FederatedMucTelemetry<'a> {
    pub(crate) fn new(
        post_commit_delivery_failures: &'a AtomicU64,
        post_accept_failures: &'a AtomicU64,
        capacity_rejections: &'a AtomicU64,
        durable_queue_acceptances: &'a AtomicU64,
        volatile_queue_acceptances: &'a AtomicU64,
        messages_routed: &'a AtomicU64,
    ) -> Self {
        Self {
            post_commit_delivery_failures,
            post_accept_failures,
            capacity_rejections,
            durable_queue_acceptances,
            volatile_queue_acceptances,
            messages_routed,
        }
    }

    pub(crate) fn post_commit_delivery_failed(&self) {
        self.post_commit_delivery_failures
            .fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn post_accept_failed(&self) {
        self.post_accept_failures.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn capacity_rejected(&self) {
        self.capacity_rejections.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn online_queue_result(&self, accepted: bool, durable: bool) {
        if accepted {
            let counter = if durable {
                self.durable_queue_acceptances
            } else {
                self.volatile_queue_acceptances
            };
            counter.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub(crate) fn message_routed(&self) {
        self.messages_routed.fetch_add(1, Ordering::Relaxed);
    }
}

/// PEP result counters. Callers record only after the corresponding service
/// operation has returned its successful outcome.
pub(crate) struct PepTelemetry<'a> {
    published_items: &'a AtomicU64,
    retracted_items: &'a AtomicU64,
    retrievals: &'a AtomicU64,
}

impl<'a> PepTelemetry<'a> {
    pub(crate) fn new(
        published_items: &'a AtomicU64,
        retracted_items: &'a AtomicU64,
        retrievals: &'a AtomicU64,
    ) -> Self {
        Self {
            published_items,
            retracted_items,
            retrievals,
        }
    }

    pub(crate) fn published(&self, count: u64) {
        self.published_items.fetch_add(count, Ordering::Relaxed);
    }

    pub(crate) fn retracted(&self, count: u64) {
        self.retracted_items.fetch_add(count, Ordering::Relaxed);
    }

    pub(crate) fn retrieved(&self) {
        self.retrievals.fetch_add(1, Ordering::Relaxed);
    }
}

/// PubSub outbox worker timing and last-successful-maintenance gauges.
pub(crate) struct PubSubOutboxTelemetry<'a> {
    delivery_duration: &'a DurationHistogram,
    pending_rows: &'a AtomicU64,
    pending_bytes: &'a AtomicU64,
    dead_letter_rows: &'a AtomicU64,
}

impl<'a> PubSubOutboxTelemetry<'a> {
    pub(crate) fn new(
        delivery_duration: &'a DurationHistogram,
        pending_rows: &'a AtomicU64,
        pending_bytes: &'a AtomicU64,
        dead_letter_rows: &'a AtomicU64,
    ) -> Self {
        Self {
            delivery_duration,
            pending_rows,
            pending_bytes,
            dead_letter_rows,
        }
    }

    pub(crate) fn start_delivery_timer(&self) -> DurationTimer<'_> {
        self.delivery_duration.start_timer()
    }

    pub(crate) fn publish_snapshot(
        &self,
        pending_rows: i64,
        pending_bytes: i64,
        dead_letter_rows: i64,
    ) {
        let nonnegative = |value: i64| u64::try_from(value.max(0)).unwrap_or(u64::MAX);
        self.pending_rows
            .store(nonnegative(pending_rows), Ordering::Relaxed);
        self.pending_bytes
            .store(nonnegative(pending_bytes), Ordering::Relaxed);
        self.dead_letter_rows
            .store(nonnegative(dead_letter_rows), Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::{
        FederatedMucTelemetry, PepTelemetry, PersonalMessageTelemetry,
        PersonalMessageTelemetryCells, PubSubOutboxTelemetry,
    };
    use crate::metrics::DurationHistogram;
    use std::sync::atomic::{AtomicU64, Ordering};

    #[test]
    fn queue_acceptance_counts_only_success_and_selects_delivery_class() {
        let histogram = DurationHistogram::default();
        let counters: [AtomicU64; 11] = std::array::from_fn(|_| AtomicU64::new(0));
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
        let federated = FederatedMucTelemetry::new(
            &counters[9],
            &counters[3],
            &counters[10],
            &counters[4],
            &counters[5],
            &counters[2],
        );

        personal.online_queue_result(false, true);
        federated.online_queue_result(false, false);
        assert_eq!(counters[4].load(Ordering::Relaxed), 0);
        assert_eq!(counters[5].load(Ordering::Relaxed), 0);

        personal.online_queue_result(true, true);
        federated.online_queue_result(true, false);
        assert_eq!(counters[4].load(Ordering::Relaxed), 1);
        assert_eq!(counters[5].load(Ordering::Relaxed), 1);
    }

    #[test]
    fn pubsub_snapshot_clamps_negative_database_counts() {
        let histogram = DurationHistogram::default();
        let pending_rows = AtomicU64::new(7);
        let pending_bytes = AtomicU64::new(11);
        let dead_letters = AtomicU64::new(13);
        let telemetry =
            PubSubOutboxTelemetry::new(&histogram, &pending_rows, &pending_bytes, &dead_letters);

        telemetry.publish_snapshot(-1, i64::MAX, -3);
        assert_eq!(pending_rows.load(Ordering::Relaxed), 0);
        assert_eq!(pending_bytes.load(Ordering::Relaxed), i64::MAX as u64);
        assert_eq!(dead_letters.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn pep_records_item_counts_without_conflating_retrievals() {
        let published = AtomicU64::new(0);
        let retracted = AtomicU64::new(0);
        let retrievals = AtomicU64::new(0);
        let telemetry = PepTelemetry::new(&published, &retracted, &retrievals);

        telemetry.published(3);
        telemetry.retracted(2);
        telemetry.retrieved();
        assert_eq!(published.load(Ordering::Relaxed), 3);
        assert_eq!(retracted.load(Ordering::Relaxed), 2);
        assert_eq!(retrievals.load(Ordering::Relaxed), 1);
    }
}
