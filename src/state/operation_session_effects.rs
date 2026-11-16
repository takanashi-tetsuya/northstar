//! Local session effects for committed administrator operations.

use super::AppState;
use anyhow::Result;
use northstar_operations_xmpp::operation_runtime::{
    LocalBroadcastRoutes, LocalGenerationCleanupRoutes, LocalSessionKickRoutes,
};
use serde_json::Value;
use uuid::Uuid;

pub(crate) struct OperationSessionEffects {
    kick: LocalSessionKickRoutes,
    broadcast: LocalBroadcastRoutes,
    generation_cleanup: LocalGenerationCleanupRoutes,
}

impl AppState {
    pub(crate) fn operation_session_effects(&self) -> OperationSessionEffects {
        OperationSessionEffects {
            kick: northstar_operations_xmpp::operation_runtime::LocalSessionKickRoutes::new(
                std::sync::Arc::clone(&self.sessions),
            ),
            broadcast: northstar_operations_xmpp::operation_runtime::LocalBroadcastRoutes::new(
                std::sync::Arc::clone(&self.sessions),
                self.config.domain.clone(),
                self.cluster.node_id.clone(),
            ),
            generation_cleanup:
                northstar_operations_xmpp::operation_runtime::LocalGenerationCleanupRoutes::new(
                    std::sync::Arc::clone(&self.sessions),
                ),
        }
    }
}

impl OperationSessionEffects {
    pub(crate) fn kick_exact(
        &self,
        user_id: Uuid,
        auth_generation: i64,
        connection_id: Uuid,
    ) -> bool {
        self.kick
            .kick_exact(user_id, auth_generation, connection_id)
    }

    pub(crate) fn send_broadcast_exact(&self, payload: &Value) -> Result<Value> {
        self.broadcast.send_exact(payload)
    }

    pub(crate) fn cancel_exact_generation(&self, user_id: Uuid, auth_generation: i64) -> u64 {
        self.generation_cleanup
            .cancel_exact_generation(user_id, auth_generation)
    }
}
