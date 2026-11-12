//! Narrow telemetry views the session core receives from the node. Each borrows only the counters and timer it
//! uses and never exposes the process registry or the node state.

use northstar_telemetry::metrics::DurationHistogram;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

/// Admission and completion observations for caps side effects.
pub struct CapsEffectTelemetry<'a> {
    coalesced: &'a AtomicU64,
    queue_saturated: &'a AtomicU64,
    failures: &'a AtomicU64,
    latency: &'a DurationHistogram,
}

impl<'a> CapsEffectTelemetry<'a> {
    pub fn new(
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

    pub fn coalesced(&self) {
        self.coalesced.fetch_add(1, Ordering::Relaxed);
    }

    pub fn queue_saturated(&self) {
        self.queue_saturated.fetch_add(1, Ordering::Relaxed);
    }

    pub fn failed(&self, failures: u64) {
        self.failures.fetch_add(failures, Ordering::Relaxed);
    }

    pub fn completed_after(&self, elapsed: Duration) {
        self.latency.observe(elapsed);
    }
}

/// One counter for every client frame entering the protocol dispatcher,
/// including stream framing and malformed XML.
pub struct InboundStanzaTelemetry<'a> {
    received: &'a AtomicU64,
}

impl<'a> InboundStanzaTelemetry<'a> {
    pub fn new(received: &'a AtomicU64) -> Self {
        Self { received }
    }

    pub fn received(&self) {
        self.received.fetch_add(1, Ordering::Relaxed);
    }
}

/// A rejected XEP-0357 subscription contributes to both the global and
/// feature-specific rate-limit counters, in that order.
pub struct PushSubscriptionTelemetry<'a> {
    rate_limited: &'a AtomicU64,
    push_rate_limited: &'a AtomicU64,
}

impl<'a> PushSubscriptionTelemetry<'a> {
    pub fn new(rate_limited: &'a AtomicU64, push_rate_limited: &'a AtomicU64) -> Self {
        Self {
            rate_limited,
            push_rate_limited,
        }
    }

    pub fn rate_limited(&self) {
        self.rate_limited.fetch_add(1, Ordering::Relaxed);
        self.push_rate_limited.fetch_add(1, Ordering::Relaxed);
    }
}

/// Results of accepted push-notification attempts and service responses.
pub struct PushDeliveryTelemetry<'a> {
    failed: &'a AtomicU64,
    routed: &'a AtomicU64,
    attempted: &'a AtomicU64,
}

impl<'a> PushDeliveryTelemetry<'a> {
    pub fn new(failed: &'a AtomicU64, routed: &'a AtomicU64, attempted: &'a AtomicU64) -> Self {
        Self {
            failed,
            routed,
            attempted,
        }
    }

    pub fn failed(&self) {
        self.failed.fetch_add(1, Ordering::Relaxed);
    }

    pub fn routed(&self) {
        self.routed.fetch_add(1, Ordering::Relaxed);
    }

    pub fn attempted(&self) {
        self.attempted.fetch_add(1, Ordering::Relaxed);
    }
}

/// XEP-0077 and XEP-0389 registration outcome counters. Account maintenance
/// receives a smaller capability below and cannot record new registrations.
pub struct RegistrationTelemetry<'a> {
    backend_failures: &'a AtomicU64,
    registrations: &'a AtomicU64,
    rate_limited: &'a AtomicU64,
    capacity_rejected: &'a AtomicU64,
}

impl<'a> RegistrationTelemetry<'a> {
    pub fn new(
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

    pub fn backend_failed(&self) {
        self.backend_failures.fetch_add(1, Ordering::Relaxed);
    }

    pub fn registered(&self) {
        self.registrations.fetch_add(1, Ordering::Relaxed);
    }

    pub fn rate_limited(&self) {
        self.rate_limited.fetch_add(1, Ordering::Relaxed);
    }

    pub fn capacity_rejected(&self) {
        self.capacity_rejected.fetch_add(1, Ordering::Relaxed);
    }
}

/// XEP-0077 password change and account deletion need only abuse outcomes.
pub struct AccountAbuseTelemetry<'a> {
    backend_failures: &'a AtomicU64,
    rate_limited: &'a AtomicU64,
}

impl<'a> AccountAbuseTelemetry<'a> {
    pub fn new(backend_failures: &'a AtomicU64, rate_limited: &'a AtomicU64) -> Self {
        Self {
            backend_failures,
            rate_limited,
        }
    }

    pub fn backend_failed(&self) {
        self.backend_failures.fetch_add(1, Ordering::Relaxed);
    }

    pub fn rate_limited(&self) {
        self.rate_limited.fetch_add(1, Ordering::Relaxed);
    }
}

/// Binding reservation and exact staged-route installation counters. The
/// route count is paired with the exact compare-remove once fence.
pub struct SessionBindTelemetry<'a> {
    capacity_rejected: &'a AtomicU64,
    active_sessions: &'a AtomicU64,
}

impl<'a> SessionBindTelemetry<'a> {
    pub fn new(capacity_rejected: &'a AtomicU64, active_sessions: &'a AtomicU64) -> Self {
        Self {
            capacity_rejected,
            active_sessions,
        }
    }

    pub fn capacity_rejected(&self) {
        self.capacity_rejected.fetch_add(1, Ordering::Relaxed);
    }

    pub fn staged_route_installed(&self) {
        self.active_sessions.fetch_add(1, Ordering::Relaxed);
    }
}

/// SM capacity denials and exact staged resume-route installation. The route
/// count is decremented by the existing exact compare-remove once fence.
pub struct SmSessionTelemetry<'a> {
    capacity_rejected: &'a AtomicU64,
    active_sessions: &'a AtomicU64,
}

impl<'a> SmSessionTelemetry<'a> {
    pub fn new(capacity_rejected: &'a AtomicU64, active_sessions: &'a AtomicU64) -> Self {
        Self {
            capacity_rejected,
            active_sessions,
        }
    }

    pub fn capacity_rejected(&self) {
        self.capacity_rejected.fetch_add(1, Ordering::Relaxed);
    }

    pub fn staged_route_installed(&self) {
        self.active_sessions.fetch_add(1, Ordering::Relaxed);
    }
}

/// SASL2 verifier/backend failure counters. Timing has an independently owned
/// histogram handle so a mutable session operation need not retain full state.
pub struct Sasl2AuthenticationTelemetry<'a> {
    integrity_failures: &'a AtomicU64,
    backend_failures: &'a AtomicU64,
}

impl<'a> Sasl2AuthenticationTelemetry<'a> {
    pub fn new(integrity_failures: &'a AtomicU64, backend_failures: &'a AtomicU64) -> Self {
        Self {
            integrity_failures,
            backend_failures,
        }
    }

    pub fn integrity_failed(&self) {
        self.integrity_failures.fetch_add(1, Ordering::Relaxed);
    }

    pub fn backend_failed(&self) {
        self.backend_failures.fetch_add(1, Ordering::Relaxed);
    }
}

/// Transport-confirmed publication and SASL exchange outcome counters.
pub struct C2sAuthenticationTelemetry<'a> {
    backend_failures: &'a AtomicU64,
    integrity_failures: &'a AtomicU64,
    authentication_failures: &'a AtomicU64,
    rate_limited: &'a AtomicU64,
}

impl<'a> C2sAuthenticationTelemetry<'a> {
    pub fn new(
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

    pub fn backend_failed(&self) {
        self.backend_failures.fetch_add(1, Ordering::Relaxed);
    }

    pub fn integrity_failed(&self) {
        self.integrity_failures.fetch_add(1, Ordering::Relaxed);
    }

    pub fn authentication_failed(&self) {
        self.authentication_failures.fetch_add(1, Ordering::Relaxed);
    }

    pub fn rate_limited(&self) {
        self.rate_limited.fetch_add(1, Ordering::Relaxed);
    }
}

/// Counts outbound stanza recording and replay before any SM checkpoint.
pub struct OutboundStanzaTelemetry<'a> {
    recorded: &'a AtomicU64,
}

impl<'a> OutboundStanzaTelemetry<'a> {
    pub fn new(recorded: &'a AtomicU64) -> Self {
        Self { recorded }
    }

    pub fn recorded(&self) {
        self.recorded.fetch_add(1, Ordering::Relaxed);
    }
}

/// Synchronous Drop fallback marker, separate from session gauge authority.
pub struct SessionDropFallbackTelemetry<'a> {
    started: &'a AtomicU64,
}

impl<'a> SessionDropFallbackTelemetry<'a> {
    pub fn new(started: &'a AtomicU64) -> Self {
        Self { started }
    }

    pub fn started(&self) {
        self.started.fetch_add(1, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::PushSubscriptionTelemetry;
    use std::sync::atomic::{AtomicU64, Ordering};

    #[test]
    fn push_subscription_rejection_counts_global_and_feature_limits() {
        let global = AtomicU64::new(2);
        let push = AtomicU64::new(4);
        PushSubscriptionTelemetry::new(&global, &push).rate_limited();

        assert_eq!(global.load(Ordering::Relaxed), 3);
        assert_eq!(push.load(Ordering::Relaxed), 5);
    }
}
