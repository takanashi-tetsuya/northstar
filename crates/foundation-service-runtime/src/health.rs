//! Production service readiness and liveness health status management.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct ServiceHealth {
    is_live: Arc<AtomicBool>,
    is_ready: Arc<AtomicBool>,
}

impl ServiceHealth {
    pub fn new() -> Self {
        Self {
            is_live: Arc::new(AtomicBool::new(true)),
            // Readiness starts as false until all internal dependencies (DB, routes, listeners) are initialized
            is_ready: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn set_ready(&self, ready: bool) {
        self.is_ready.store(ready, Ordering::SeqCst);
    }

    pub fn set_live(&self, live: bool) {
        self.is_live.store(live, Ordering::SeqCst);
    }

    pub fn is_ready(&self) -> bool {
        self.is_ready.load(Ordering::SeqCst)
    }

    pub fn is_live(&self) -> bool {
        self.is_live.load(Ordering::SeqCst)
    }
}

impl Default for ServiceHealth {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn health_lifecycle() {
        let health = ServiceHealth::new();
        assert!(health.is_live());
        assert!(
            !health.is_ready(),
            "readiness must start false until initialization completes"
        );

        health.set_ready(true);
        assert!(health.is_ready());

        health.set_ready(false);
        assert!(!health.is_ready());
    }
}
