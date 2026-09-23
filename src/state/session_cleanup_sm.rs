//! SM persistence, suspended MUC handoff, and bounded recovery for cleanup.

use super::{suspension::SmSuspensionContext, AppState, SmBufferLimits, SuspendedMucEndpoint};
use crate::db::{
    sm_repository::PostgresSmRepository, sm_suspension::PostgresSmSuspensionRepository,
};
use crate::services::{
    session_cleanup::{SessionCleanupAccount, SmSuspensionRecoveryQueue},
    sm::{SmService, SmSessionSnapshot},
    sm_capacity::{SmCapacityLease, SmMemoryGovernor},
};
use anyhow::Result;
use std::sync::Arc;
use uuid::Uuid;

pub(crate) struct SessionCleanupSm {
    suspension: SmSuspensionContext<PostgresSmSuspensionRepository>,
    sessions: SmService<PostgresSmRepository>,
    recovery: Arc<SmSuspensionRecoveryQueue>,
    memory: Arc<SmMemoryGovernor>,
    limits: SmBufferLimits,
}

impl AppState {
    pub(crate) fn session_cleanup_sm(&self) -> SessionCleanupSm {
        SessionCleanupSm {
            suspension: self.sm_suspension_context(),
            sessions: self.sm_service.clone(),
            recovery: Arc::clone(&self.sm_suspension_recovery),
            memory: Arc::clone(&self.sm_memory_governor),
            limits: self.sm_buffer_limits(),
        }
    }
}

impl SessionCleanupSm {
    pub(crate) async fn snapshot_suspended_muc_for_disconnect(
        &self,
        endpoints: &[Arc<SuspendedMucEndpoint>],
        snapshot: &mut SmSessionSnapshot,
    ) -> Result<()> {
        self.suspension
            .snapshot_suspended_muc_for_disconnect(endpoints, snapshot)
            .await
    }

    pub(crate) async fn seal_suspended_muc_endpoints(
        &self,
        endpoints: &[Arc<SuspendedMucEndpoint>],
    ) {
        self.suspension
            .seal_suspended_muc_endpoints(endpoints)
            .await;
    }

    pub(crate) fn mark_memory_invariant_failure(&self) {
        self.memory.mark_invariant_failure();
    }

    pub(crate) async fn suspend_exact_session(
        &self,
        session_id: Uuid,
        connection_id: Uuid,
        account: &SessionCleanupAccount,
        snapshot: &SmSessionSnapshot,
        ttl_seconds: u64,
    ) -> Result<bool> {
        self.sessions
            .suspend_exact_session(
                session_id,
                connection_id,
                account.user_id,
                account.auth_generation,
                snapshot,
                ttl_seconds,
                self.limits.max_unacked_stanzas,
                self.limits.max_unacked_bytes,
            )
            .await
    }

    pub(crate) async fn mark_suspended_muc_durable(
        &self,
        endpoints: Vec<Arc<SuspendedMucEndpoint>>,
    ) -> bool {
        self.suspension.mark_suspended_muc_durable(endpoints).await
    }

    pub(crate) fn queue_promotion(
        &self,
        connection_id: Uuid,
        session_id: Uuid,
        endpoints: Vec<Arc<SuspendedMucEndpoint>>,
        capacity: SmCapacityLease,
    ) -> bool {
        self.recovery
            .enqueue_promote(connection_id, session_id, endpoints, capacity)
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn queue_suspension(
        &self,
        account: SessionCleanupAccount,
        connection_id: Uuid,
        session_id: Uuid,
        snapshot: SmSessionSnapshot,
        ttl_seconds: u64,
        endpoints: Vec<Arc<SuspendedMucEndpoint>>,
        capacity: SmCapacityLease,
    ) -> bool {
        self.recovery.enqueue(
            account,
            connection_id,
            session_id,
            snapshot,
            ttl_seconds,
            endpoints,
            capacity,
        )
    }

    pub(crate) fn retain_suspended_sm_capacity(
        &self,
        endpoints: &[Arc<SuspendedMucEndpoint>],
        capacity: SmCapacityLease,
    ) {
        self.suspension
            .retain_suspended_sm_capacity(endpoints, capacity);
    }

    pub(crate) async fn revoke_session(&self, session_id: Uuid) -> Result<()> {
        self.sessions.revoke_session(session_id).await
    }

    pub(crate) async fn release_live_session(&self, connection_id: Uuid) -> Result<bool> {
        self.sessions.release_live_session(connection_id).await
    }
}
