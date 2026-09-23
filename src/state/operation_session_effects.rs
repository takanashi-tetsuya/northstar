//! Local session effects for committed administrator operations.

use super::AppState;
use crate::operation_runtime::{
    LocalBroadcastRoutes, LocalGenerationCleanupRoutes, LocalSessionKickRoutes,
};
use anyhow::Result;
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
            kick: self.session_kick_routes(),
            broadcast: self.broadcast_routes(),
            generation_cleanup: self.generation_cleanup_routes(),
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
