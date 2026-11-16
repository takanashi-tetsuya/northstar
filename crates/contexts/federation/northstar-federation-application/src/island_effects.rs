//! Federation policy transition for a committed administrator operation.

use crate::registry::S2sOutboundClearance;
use crate::write_policy::FederationWritePolicy;
use std::sync::Arc;

pub struct OperationIslandEffects {
    policy: Arc<FederationWritePolicy>,
    outbound: S2sOutboundClearance,
}

impl OperationIslandEffects {
    pub fn new(policy: Arc<FederationWritePolicy>, outbound: S2sOutboundClearance) -> Self {
        Self { policy, outbound }
    }

    pub async fn converge(&self, enabled: bool) {
        self.policy.apply(enabled).await;
        if enabled {
            self.outbound.clear_for_island_mode();
        }
    }
}
