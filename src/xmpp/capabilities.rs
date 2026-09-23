//! Narrow telemetry granted to the C2S post-transport task supervisor.
//! The five counters are borrowed from the metrics owner; this module never
//! exposes the complete process metric registry or application state.

use std::sync::atomic::{AtomicU64, Ordering};

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
