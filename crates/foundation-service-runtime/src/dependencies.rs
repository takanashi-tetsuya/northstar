//! Dependency readiness is explicit and fail-closed.

use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DependencyState {
    Unknown,
    Healthy,
    Degraded,
    Failed,
}

#[derive(Debug, Clone, Default)]
pub struct DependencyRegistry {
    states: Arc<RwLock<BTreeMap<String, DependencyState>>>,
}

impl DependencyRegistry {
    pub fn register(&self, name: impl Into<String>) {
        self.states
            .write()
            .unwrap()
            .entry(name.into())
            .or_insert(DependencyState::Unknown);
    }

    pub fn set(&self, name: &str, state: DependencyState) {
        self.states.write().unwrap().insert(name.to_string(), state);
    }

    pub fn is_ready(&self) -> bool {
        let states = self.states.read().unwrap();
        !states.is_empty()
            && states
                .values()
                .all(|state| *state == DependencyState::Healthy)
    }

    pub fn snapshot(&self) -> BTreeMap<String, DependencyState> {
        self.states.read().unwrap().clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dependency_registry_fails_closed() {
        let registry = DependencyRegistry::default();
        assert!(!registry.is_ready());
        registry.register("database");
        assert!(!registry.is_ready());
        registry.set("database", DependencyState::Healthy);
        assert!(registry.is_ready());
        registry.set("database", DependencyState::Failed);
        assert!(!registry.is_ready());
    }
}
