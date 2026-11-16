//! Session suspension, recovery and memory admission handles.

use crate::node::ServerNode;
use std::sync::Arc;

impl ServerNode {
    pub(crate) fn sm_suspension_context(
        &self,
    ) -> northstar_stream::session_cleanup::suspension::SmSuspensionContext<
        northstar_workflows::sm_suspension::PostgresSmSuspensionRepository,
        crate::cluster::ClusterSmSuspension,
    > {
        northstar_stream::session_cleanup::suspension::SmSuspensionContext::new(
            northstar_workflows::sm_suspension::PostgresSmSuspensionRepository::new(
                self.pool.clone(),
            ),
            northstar_session_application::sm_suspension::SmSuspensionLimits {
                max_stanzas: self.config.sm_max_unacked_stanzas,
                max_bytes: self.config.sm_max_unacked_bytes,
            },
            Arc::clone(&self.room.muc_occupants),
            self.cluster.sm_suspension(),
        )
    }

    pub(crate) fn sm_suspension_recovery_queue(
        &self,
    ) -> &Arc<northstar_stream::session_cleanup::recovery::SmSuspensionRecoveryQueue> {
        &self.session.sm_suspension_recovery
    }

    pub(crate) fn sm_memory_governor(
        &self,
    ) -> &Arc<northstar_session_application::sm_capacity::SmMemoryGovernor> {
        &self.session.sm_memory_governor
    }
}
