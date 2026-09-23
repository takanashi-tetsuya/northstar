//! Federation policy transition for a committed administrator operation.

use super::{AppState, FederationWritePolicy};
use crate::s2s::S2sOutboundClearance;
use std::sync::Arc;

pub(crate) struct OperationIslandEffects {
    policy: Arc<FederationWritePolicy>,
    outbound: S2sOutboundClearance,
}

impl AppState {
    pub(crate) fn operation_island_effects(&self) -> OperationIslandEffects {
        OperationIslandEffects {
            policy: Arc::clone(&self.federation_write_policy),
            outbound: self.s2s_connection_registry.outbound_clearance(),
        }
    }
}

impl OperationIslandEffects {
    pub(crate) async fn converge(&self, enabled: bool) {
        self.policy.apply(enabled).await;
        if enabled {
            self.outbound.clear_for_island_mode();
        }
    }
}
