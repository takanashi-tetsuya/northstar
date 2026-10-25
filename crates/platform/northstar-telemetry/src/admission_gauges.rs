//! Process-wide gauges of the PubSub mutation admission. `northstar-pubsub-application` updates them and the metrics
//! registry reads them.

use std::sync::atomic::{AtomicU64, Ordering};

pub static PUBSUB_MUTATION_ADMISSION_REJECTIONS_TOTAL: AtomicU64 = AtomicU64::new(0);
pub static PUBSUB_MUTATION_ADMISSION_WAITERS: AtomicU64 = AtomicU64::new(0);
pub static PUBSUB_MUTATION_ADMISSION_ACTIVE: AtomicU64 = AtomicU64::new(0);

pub fn pubsub_mutation_admission_rejections_total() -> u64 {
    PUBSUB_MUTATION_ADMISSION_REJECTIONS_TOTAL.load(Ordering::Relaxed)
}

pub fn pubsub_mutation_admission_waiters() -> u64 {
    PUBSUB_MUTATION_ADMISSION_WAITERS.load(Ordering::Relaxed)
}

pub fn pubsub_mutation_admission_active() -> u64 {
    PUBSUB_MUTATION_ADMISSION_ACTIVE.load(Ordering::Relaxed)
}
