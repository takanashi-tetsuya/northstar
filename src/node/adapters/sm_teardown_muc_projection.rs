//! Bind the suspended MUC occupant projection to this node's room services.

use crate::node::ServerNode;
use northstar_muc_xmpp::sm_teardown_projection::SmTeardownMucProjection;
use northstar_workflows::sm_teardown_muc_repository::PostgresSmTeardownMucRepository;
use std::sync::Arc;

impl ServerNode {
    pub(in crate::node) fn sm_teardown_muc_projection(
        &self,
    ) -> SmTeardownMucProjection<PostgresSmTeardownMucRepository> {
        SmTeardownMucProjection::new_with_time_sources(
            self.room.sm_teardown_muc_service().clone(),
            Arc::clone(&self.room.muc_occupants),
            self.room.muc_service().time_sources().clone(),
        )
    }
}
