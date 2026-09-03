//! C2s runtime capability ports bundling.
//!
//! Bundles capability access for protocol sessions to provide typed, explicit
//! runtime boundaries instead of unconstrained access to `AppState`.

use crate::state::AppState;
use std::sync::Arc;

/// Capability bundle representing the runtime ports needed by a C2S protocol session.
#[derive(Clone)]
pub struct C2sRuntimePorts {
    state: Arc<AppState>,
}

impl C2sRuntimePorts {
    pub fn new(state: Arc<AppState>) -> Self {
        Self { state }
    }

    #[inline]
    pub fn state(&self) -> &Arc<AppState> {
        &self.state
    }

    #[inline]
    pub fn config(&self) -> &crate::config::Config {
        &self.state.config
    }

    #[inline]
    pub fn metrics(&self) -> &crate::metrics::Metrics {
        &self.state.metrics
    }

    #[inline]
    pub fn sessions(&self) -> &dashmap::DashMap<String, crate::state::OnlineSession> {
        &self.state.sessions
    }

    #[inline]
    pub fn muc_occupants(&self) -> &dashmap::DashMap<String, crate::state::MucOccupant> {
        &self.state.muc_occupants
    }
}
