//! Bounded request limits shared by all service front doors.

use std::time::Duration;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequestLimits {
    pub max_payload_bytes: usize,
    pub max_concurrency: usize,
    pub deadline: Duration,
}

impl RequestLimits {
    pub fn new(
        max_payload_bytes: usize,
        max_concurrency: usize,
        deadline: Duration,
    ) -> Option<Self> {
        (max_payload_bytes > 0 && max_concurrency > 0 && !deadline.is_zero()).then_some(Self {
            max_payload_bytes,
            max_concurrency,
            deadline,
        })
    }

    pub fn permit(&self, semaphore: &std::sync::Arc<Semaphore>) -> Option<OwnedSemaphorePermit> {
        semaphore.clone().try_acquire_owned().ok()
    }
}

#[derive(Debug)]
pub struct ConcurrencyGate {
    semaphore: std::sync::Arc<Semaphore>,
}

impl ConcurrencyGate {
    pub fn new(max_concurrency: usize) -> Option<Self> {
        (max_concurrency > 0).then(|| Self {
            semaphore: std::sync::Arc::new(Semaphore::new(max_concurrency)),
        })
    }

    pub fn try_acquire(&self) -> Option<OwnedSemaphorePermit> {
        self.semaphore.clone().try_acquire_owned().ok()
    }

    pub fn available(&self) -> usize {
        self.semaphore.available_permits()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limits_reject_unbounded_values() {
        assert!(RequestLimits::new(0, 1, Duration::from_secs(1)).is_none());
        assert!(RequestLimits::new(1024, 0, Duration::from_secs(1)).is_none());
        assert!(RequestLimits::new(1024, 1, Duration::ZERO).is_none());
        assert!(RequestLimits::new(1024, 1, Duration::from_secs(1)).is_some());
    }

    #[tokio::test]
    async fn concurrency_gate_is_fail_fast() {
        let gate = ConcurrencyGate::new(1).unwrap();
        let permit = gate.try_acquire().unwrap();
        assert!(gate.try_acquire().is_none());
        drop(permit);
        assert!(gate.try_acquire().is_some());
    }
}
