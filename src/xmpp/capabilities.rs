//! Narrow telemetry borrowed from the metrics owner for XMPP runtime tasks.
//! Protocol handlers receive only the counters and timer they actually use;
//! this module never exposes the complete process registry or application state.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use crate::metrics::{DurationHistogram, DurationTimer};

/// Admission and completion observations for caps side effects.
pub(crate) struct CapsEffectTelemetry<'a> {
    coalesced: &'a AtomicU64,
    queue_saturated: &'a AtomicU64,
    failures: &'a AtomicU64,
    latency: &'a DurationHistogram,
}

impl<'a> CapsEffectTelemetry<'a> {
    pub(crate) fn new(
        coalesced: &'a AtomicU64,
        queue_saturated: &'a AtomicU64,
        failures: &'a AtomicU64,
        latency: &'a DurationHistogram,
    ) -> Self {
        Self {
            coalesced,
            queue_saturated,
            failures,
            latency,
        }
    }

    pub(crate) fn coalesced(&self) {
        self.coalesced.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn queue_saturated(&self) {
        self.queue_saturated.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn failed(&self, failures: u64) {
        self.failures.fetch_add(failures, Ordering::Relaxed);
    }

    pub(crate) fn completed_after(&self, elapsed: Duration) {
        self.latency.observe(elapsed);
    }
}

/// One counter for every client frame entering the protocol dispatcher,
/// including stream framing and malformed XML.
pub(crate) struct InboundStanzaTelemetry<'a> {
    received: &'a AtomicU64,
}

impl<'a> InboundStanzaTelemetry<'a> {
    pub(crate) fn new(received: &'a AtomicU64) -> Self {
        Self { received }
    }

    pub(crate) fn received(&self) {
        self.received.fetch_add(1, Ordering::Relaxed);
    }
}

/// One post-commit delivery failure counter shared by roster, blocking and
/// privacy pushes. Each caller retains its own recovery/disconnect decision.
pub(crate) struct PostAcceptFailureTelemetry<'a> {
    failures: &'a AtomicU64,
}

impl<'a> PostAcceptFailureTelemetry<'a> {
    pub(crate) fn new(failures: &'a AtomicU64) -> Self {
        Self { failures }
    }

    pub(crate) fn record_failure(&self) {
        self.failures.fetch_add(1, Ordering::Relaxed);
    }
}

/// A rejected XEP-0357 subscription contributes to both the global and
/// feature-specific rate-limit counters, in that order.
pub(crate) struct PushSubscriptionTelemetry<'a> {
    rate_limited: &'a AtomicU64,
    push_rate_limited: &'a AtomicU64,
}

impl<'a> PushSubscriptionTelemetry<'a> {
    pub(crate) fn new(rate_limited: &'a AtomicU64, push_rate_limited: &'a AtomicU64) -> Self {
        Self {
            rate_limited,
            push_rate_limited,
        }
    }

    pub(crate) fn rate_limited(&self) {
        self.rate_limited.fetch_add(1, Ordering::Relaxed);
        self.push_rate_limited.fetch_add(1, Ordering::Relaxed);
    }
}

/// Results of accepted push-notification attempts and service responses.
pub(crate) struct PushDeliveryTelemetry<'a> {
    failed: &'a AtomicU64,
    routed: &'a AtomicU64,
    attempted: &'a AtomicU64,
}

impl<'a> PushDeliveryTelemetry<'a> {
    pub(crate) fn new(
        failed: &'a AtomicU64,
        routed: &'a AtomicU64,
        attempted: &'a AtomicU64,
    ) -> Self {
        Self {
            failed,
            routed,
            attempted,
        }
    }

    pub(crate) fn failed(&self) {
        self.failed.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn routed(&self) {
        self.routed.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn attempted(&self) {
        self.attempted.fetch_add(1, Ordering::Relaxed);
    }
}

/// XEP-0077 and XEP-0389 registration outcome counters. Account maintenance
/// receives a smaller capability below and cannot record new registrations.
pub(crate) struct RegistrationTelemetry<'a> {
    backend_failures: &'a AtomicU64,
    registrations: &'a AtomicU64,
    rate_limited: &'a AtomicU64,
    capacity_rejected: &'a AtomicU64,
}

impl<'a> RegistrationTelemetry<'a> {
    pub(crate) fn new(
        backend_failures: &'a AtomicU64,
        registrations: &'a AtomicU64,
        rate_limited: &'a AtomicU64,
        capacity_rejected: &'a AtomicU64,
    ) -> Self {
        Self {
            backend_failures,
            registrations,
            rate_limited,
            capacity_rejected,
        }
    }

    pub(crate) fn backend_failed(&self) {
        self.backend_failures.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn registered(&self) {
        self.registrations.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn rate_limited(&self) {
        self.rate_limited.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn capacity_rejected(&self) {
        self.capacity_rejected.fetch_add(1, Ordering::Relaxed);
    }
}

/// XEP-0077 password change and account deletion need only abuse outcomes.
pub(crate) struct AccountAbuseTelemetry<'a> {
    backend_failures: &'a AtomicU64,
    rate_limited: &'a AtomicU64,
}

impl<'a> AccountAbuseTelemetry<'a> {
    pub(crate) fn new(backend_failures: &'a AtomicU64, rate_limited: &'a AtomicU64) -> Self {
        Self {
            backend_failures,
            rate_limited,
        }
    }

    pub(crate) fn backend_failed(&self) {
        self.backend_failures.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn rate_limited(&self) {
        self.rate_limited.fetch_add(1, Ordering::Relaxed);
    }
}

/// Binding reservation and exact staged-route installation counters. The
/// route count is paired with the exact compare-remove once fence.
pub(crate) struct SessionBindTelemetry<'a> {
    capacity_rejected: &'a AtomicU64,
    active_sessions: &'a AtomicU64,
}

impl<'a> SessionBindTelemetry<'a> {
    pub(crate) fn new(capacity_rejected: &'a AtomicU64, active_sessions: &'a AtomicU64) -> Self {
        Self {
            capacity_rejected,
            active_sessions,
        }
    }

    pub(crate) fn capacity_rejected(&self) {
        self.capacity_rejected.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn staged_route_installed(&self) {
        self.active_sessions.fetch_add(1, Ordering::Relaxed);
    }
}

/// SM capacity denials and exact staged resume-route installation. The route
/// count is decremented by the existing exact compare-remove once fence.
pub(crate) struct SmSessionTelemetry<'a> {
    capacity_rejected: &'a AtomicU64,
    active_sessions: &'a AtomicU64,
}

impl<'a> SmSessionTelemetry<'a> {
    pub(crate) fn new(capacity_rejected: &'a AtomicU64, active_sessions: &'a AtomicU64) -> Self {
        Self {
            capacity_rejected,
            active_sessions,
        }
    }

    pub(crate) fn capacity_rejected(&self) {
        self.capacity_rejected.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn staged_route_installed(&self) {
        self.active_sessions.fetch_add(1, Ordering::Relaxed);
    }
}

/// SASL2 authentication timing and verifier/backend failure counters.
pub(crate) struct Sasl2AuthenticationTelemetry<'a> {
    duration: &'a DurationHistogram,
    integrity_failures: &'a AtomicU64,
    backend_failures: &'a AtomicU64,
}

impl<'a> Sasl2AuthenticationTelemetry<'a> {
    pub(crate) fn new(
        duration: &'a DurationHistogram,
        integrity_failures: &'a AtomicU64,
        backend_failures: &'a AtomicU64,
    ) -> Self {
        Self {
            duration,
            integrity_failures,
            backend_failures,
        }
    }

    pub(crate) fn start_timer(&self) -> DurationTimer<'_> {
        self.duration.start_timer()
    }

    pub(crate) fn integrity_failed(&self) {
        self.integrity_failures.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn backend_failed(&self) {
        self.backend_failures.fetch_add(1, Ordering::Relaxed);
    }
}

/// Transport-confirmed publication and SASL exchange outcome counters.
pub(crate) struct C2sAuthenticationTelemetry<'a> {
    backend_failures: &'a AtomicU64,
    integrity_failures: &'a AtomicU64,
    authentication_failures: &'a AtomicU64,
    rate_limited: &'a AtomicU64,
}

impl<'a> C2sAuthenticationTelemetry<'a> {
    pub(crate) fn new(
        backend_failures: &'a AtomicU64,
        integrity_failures: &'a AtomicU64,
        authentication_failures: &'a AtomicU64,
        rate_limited: &'a AtomicU64,
    ) -> Self {
        Self {
            backend_failures,
            integrity_failures,
            authentication_failures,
            rate_limited,
        }
    }

    pub(crate) fn backend_failed(&self) {
        self.backend_failures.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn integrity_failed(&self) {
        self.integrity_failures.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn authentication_failed(&self) {
        self.authentication_failures.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn rate_limited(&self) {
        self.rate_limited.fetch_add(1, Ordering::Relaxed);
    }
}

/// Counts outbound stanza recording and replay before any SM checkpoint.
pub(crate) struct OutboundStanzaTelemetry<'a> {
    recorded: &'a AtomicU64,
}

impl<'a> OutboundStanzaTelemetry<'a> {
    pub(crate) fn new(recorded: &'a AtomicU64) -> Self {
        Self { recorded }
    }

    pub(crate) fn recorded(&self) {
        self.recorded.fetch_add(1, Ordering::Relaxed);
    }
}

/// Synchronous Drop fallback marker, separate from session gauge authority.
pub(crate) struct SessionDropFallbackTelemetry<'a> {
    started: &'a AtomicU64,
}

impl<'a> SessionDropFallbackTelemetry<'a> {
    pub(crate) fn new(started: &'a AtomicU64) -> Self {
        Self { started }
    }

    pub(crate) fn started(&self) {
        self.started.fetch_add(1, Ordering::Relaxed);
    }
}

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
        PersonalMessageTelemetryCells, PubSubOutboxTelemetry, PushSubscriptionTelemetry,
    };
    use crate::metrics::DurationHistogram;
    use std::sync::atomic::{AtomicU64, Ordering};

    #[test]
    fn push_subscription_rejection_counts_global_and_feature_limits() {
        let global = AtomicU64::new(2);
        let push = AtomicU64::new(4);
        PushSubscriptionTelemetry::new(&global, &push).rate_limited();

        assert_eq!(global.load(Ordering::Relaxed), 3);
        assert_eq!(push.load(Ordering::Relaxed), 5);
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
