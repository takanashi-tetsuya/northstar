//! Process-wide counters of the durable PubSub, MIX and S2S delivery queues. The database adapter increments them
//! and the metrics registry reads them.

use std::sync::atomic::{AtomicU64, Ordering};

pub static PUBSUB_OUTBOX_CAPACITY_REJECTIONS_TOTAL: AtomicU64 = AtomicU64::new(0);
pub static PUBSUB_OUTBOX_DEAD_LETTERS_TOTAL: AtomicU64 = AtomicU64::new(0);
pub static PUBSUB_OUTBOX_LEASE_LOST_TOTAL: AtomicU64 = AtomicU64::new(0);
pub static PUBSUB_OUTBOX_RETRIES_TOTAL: AtomicU64 = AtomicU64::new(0);
pub static PUBSUB_OUTBOX_UNVERIFIABLE_PEP_DROPS_TOTAL: AtomicU64 = AtomicU64::new(0);
pub static MIX_DELIVERY_CAPACITY_REJECTIONS_TOTAL: AtomicU64 = AtomicU64::new(0);
pub static MIX_DELIVERY_LEASE_LOST_TOTAL: AtomicU64 = AtomicU64::new(0);
pub static MIX_DELIVERY_DEAD_LETTERS_TOTAL: AtomicU64 = AtomicU64::new(0);
pub static MIX_DELIVERY_RETRIES_TOTAL: AtomicU64 = AtomicU64::new(0);
pub static S2S_OUTBOX_CAPACITY_REJECTIONS_TOTAL: AtomicU64 = AtomicU64::new(0);

pub fn pubsub_outbox_capacity_rejections_total() -> u64 {
    PUBSUB_OUTBOX_CAPACITY_REJECTIONS_TOTAL.load(Ordering::Relaxed)
}

pub fn pubsub_outbox_dead_letters_total() -> u64 {
    PUBSUB_OUTBOX_DEAD_LETTERS_TOTAL.load(Ordering::Relaxed)
}

pub fn pubsub_outbox_lease_lost_total() -> u64 {
    PUBSUB_OUTBOX_LEASE_LOST_TOTAL.load(Ordering::Relaxed)
}

pub fn pubsub_outbox_retries_total() -> u64 {
    PUBSUB_OUTBOX_RETRIES_TOTAL.load(Ordering::Relaxed)
}

pub fn record_unverifiable_pep_drop() {
    PUBSUB_OUTBOX_UNVERIFIABLE_PEP_DROPS_TOTAL.fetch_add(1, Ordering::Relaxed);
}

pub fn pubsub_outbox_unverifiable_pep_drops_total() -> u64 {
    PUBSUB_OUTBOX_UNVERIFIABLE_PEP_DROPS_TOTAL.load(Ordering::Relaxed)
}

pub fn mix_delivery_capacity_rejections_total() -> u64 {
    MIX_DELIVERY_CAPACITY_REJECTIONS_TOTAL.load(Ordering::Relaxed)
}

pub fn mix_delivery_lease_lost_total() -> u64 {
    MIX_DELIVERY_LEASE_LOST_TOTAL.load(Ordering::Relaxed)
}

pub fn mix_delivery_dead_letters_total() -> u64 {
    MIX_DELIVERY_DEAD_LETTERS_TOTAL.load(Ordering::Relaxed)
}

pub fn mix_delivery_retries_total() -> u64 {
    MIX_DELIVERY_RETRIES_TOTAL.load(Ordering::Relaxed)
}

pub fn s2s_outbox_capacity_rejections_total() -> u64 {
    S2S_OUTBOX_CAPACITY_REJECTIONS_TOTAL.load(Ordering::Relaxed)
}
