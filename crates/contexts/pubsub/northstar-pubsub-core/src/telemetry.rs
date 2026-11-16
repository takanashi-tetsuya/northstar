//! PEP result counters borrowed from the metrics owner.

use std::sync::atomic::{AtomicU64, Ordering};

/// PEP result counters. Callers record only after the corresponding service
/// operation has returned its successful outcome.
pub struct PepTelemetry<'a> {
    published_items: &'a AtomicU64,
    retracted_items: &'a AtomicU64,
    retrievals: &'a AtomicU64,
}

impl<'a> PepTelemetry<'a> {
    pub fn new(
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

    pub fn published(&self, count: u64) {
        self.published_items.fetch_add(count, Ordering::Relaxed);
    }

    pub fn retracted(&self, count: u64) {
        self.retracted_items.fetch_add(count, Ordering::Relaxed);
    }

    pub fn retrieved(&self) {
        self.retrievals.fetch_add(1, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::PepTelemetry;
    use std::sync::atomic::{AtomicU64, Ordering};

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
