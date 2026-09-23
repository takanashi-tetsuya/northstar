//! Federation policy transition for a committed administrator operation.

use super::{AppState, FederationWritePolicy};
use crate::s2s::S2sConnectionRegistry;
use std::sync::Arc;

pub(crate) struct OperationIslandEffects {
    policy: Arc<FederationWritePolicy>,
    outbound: Arc<S2sConnectionRegistry>,
}

impl AppState {
    pub(crate) fn operation_island_effects(&self) -> OperationIslandEffects {
        OperationIslandEffects {
            policy: Arc::clone(&self.federation_write_policy),
            outbound: Arc::clone(&self.s2s_connection_registry),
        }
    }
}

impl OperationIslandEffects {
    pub(crate) async fn converge(&self, enabled: bool) {
        self.policy.apply(enabled).await;
        if enabled {
            self.outbound.clear_outbound_for_island_mode();
        }
    }
}
