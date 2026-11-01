//! Counters of the MUC handlers. The caller owns the atomics.

use std::sync::atomic::{AtomicU64, Ordering};

/// Observations emitted only after MUC authority or delivery decisions.
pub struct MucTelemetry<'a> {
    post_commit_failures: &'a AtomicU64,
    post_accept_failures: &'a AtomicU64,
    authority_rejections: &'a AtomicU64,
    durable_queue_acceptances: &'a AtomicU64,
    volatile_queue_acceptances: &'a AtomicU64,
    messages_routed: &'a AtomicU64,
    capacity_rejections: &'a AtomicU64,
}

impl<'a> MucTelemetry<'a> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        post_commit_failures: &'a AtomicU64,
        post_accept_failures: &'a AtomicU64,
        authority_rejections: &'a AtomicU64,
        durable_queue_acceptances: &'a AtomicU64,
        volatile_queue_acceptances: &'a AtomicU64,
        messages_routed: &'a AtomicU64,
        capacity_rejections: &'a AtomicU64,
    ) -> Self {
        Self {
            post_commit_failures,
            post_accept_failures,
            authority_rejections,
            durable_queue_acceptances,
            volatile_queue_acceptances,
            messages_routed,
            capacity_rejections,
        }
    }

    pub fn post_commit_failure(&self) {
        self.post_commit_failures.fetch_add(1, Ordering::Relaxed);
        self.post_accept_failures.fetch_add(1, Ordering::Relaxed);
    }

    pub fn authority_rejected(&self) {
        self.authority_rejections.fetch_add(1, Ordering::Relaxed);
    }

    pub fn online_queue_accepted(&self, durable: bool) {
        let counter = if durable {
            self.durable_queue_acceptances
        } else {
            self.volatile_queue_acceptances
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    pub fn message_routed(&self) {
        self.messages_routed.fetch_add(1, Ordering::Relaxed);
    }

    pub fn capacity_rejected(&self) {
        self.capacity_rejections.fetch_add(1, Ordering::Relaxed);
    }
}

/// Only the counters touched by federated MUC room/invite delivery.
pub struct FederatedMucTelemetry<'a> {
    post_commit_delivery_failures: &'a AtomicU64,
    post_accept_failures: &'a AtomicU64,
    capacity_rejections: &'a AtomicU64,
    durable_queue_acceptances: &'a AtomicU64,
    volatile_queue_acceptances: &'a AtomicU64,
    messages_routed: &'a AtomicU64,
}

impl<'a> FederatedMucTelemetry<'a> {
    pub fn new(
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

    pub fn post_commit_delivery_failed(&self) {
        self.post_commit_delivery_failures
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn post_accept_failed(&self) {
        self.post_accept_failures.fetch_add(1, Ordering::Relaxed);
    }

    pub fn capacity_rejected(&self) {
        self.capacity_rejections.fetch_add(1, Ordering::Relaxed);
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

    pub fn message_routed(&self) {
        self.messages_routed.fetch_add(1, Ordering::Relaxed);
    }
}
