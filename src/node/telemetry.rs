//! Narrow telemetry borrowed from the metrics owner for XMPP runtime tasks.
//! Protocol handlers receive only the counters and timer they actually use;
//! this module never exposes the complete process registry or application state.

use std::sync::atomic::{AtomicU64, Ordering};

/// MIX delivery failures are observed after their durable commit.
pub(crate) struct MixPostCommitTelemetry<'a> {
    delivery_failures: &'a AtomicU64,
    post_accept_failures: &'a AtomicU64,
}

impl<'a> MixPostCommitTelemetry<'a> {
    pub(crate) fn new(
        delivery_failures: &'a AtomicU64,
        post_accept_failures: &'a AtomicU64,
    ) -> Self {
        Self {
            delivery_failures,
            post_accept_failures,
        }
    }

    pub(crate) fn delivery_failed(&self) {
        self.delivery_failures.fetch_add(1, Ordering::Relaxed);
        self.post_accept_failures.fetch_add(1, Ordering::Relaxed);
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

#[cfg(test)]
mod tests {
    use super::PepTelemetry;
    use northstar_message_application::telemetry::{
        PersonalMessageTelemetry, PersonalMessageTelemetryCells,
    };
    use northstar_room_core::telemetry::FederatedMucTelemetry;
    use northstar_roster_xmpp::PostAcceptFailureTelemetry;
    use northstar_telemetry::metrics::DurationHistogram;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;

    #[test]
    fn deferred_failure_telemetry_shares_its_counter() {
        let failures = Arc::new(AtomicU64::new(0));
        let telemetry = PostAcceptFailureTelemetry::new(Arc::clone(&failures));
        telemetry.record_failure();

        assert_eq!(failures.load(Ordering::Relaxed), 1);
    }

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
