//! Local cancellation and durable teardown for committed panic-disconnect operations.

use super::{session_cleanup_sm_revoker::SessionCleanupSmRevoker, AppState};
use anyhow::Result;
use northstar_operations_xmpp::operation_runtime::{
    panic_disconnect_with, LocalPanicDisconnectRoutes,
};
use serde_json::Value;

pub(crate) struct OperationPanicEffects {
    routes: LocalPanicDisconnectRoutes,
    sm: SessionCleanupSmRevoker,
}

impl AppState {
    pub(crate) fn operation_panic_effects(&self) -> OperationPanicEffects {
        OperationPanicEffects {
            routes: northstar_operations_xmpp::operation_runtime::LocalPanicDisconnectRoutes::new(
                std::sync::Arc::clone(&self.sessions),
            ),
            sm: self.session_cleanup_sm_revoker(),
        }
    }
}

impl OperationPanicEffects {
    pub(crate) async fn execute(&self) -> Result<Value> {
        panic_disconnect_with(&self.routes, || self.sm.revoke_all_with_teardown()).await
    }
}
