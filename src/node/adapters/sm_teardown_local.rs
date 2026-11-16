//! Builds the process-local SM teardown effects (`xmpp::local_routes::sm_teardown`).

use crate::node::ServerNode;
use northstar_stream::local_routes::sm_teardown::SmTeardownLocalEffects;
use std::sync::Arc;

impl ServerNode {
    pub(in crate::node) fn sm_teardown_local_effects(&self) -> SmTeardownLocalEffects {
        SmTeardownLocalEffects {
            occupants: Arc::clone(&self.room.muc_occupants),
            suspended_muc_sessions: Arc::clone(&self.room.suspended_muc_sessions),
        }
    }
}
