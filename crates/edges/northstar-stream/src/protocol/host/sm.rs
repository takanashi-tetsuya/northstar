use crate::local_routes::session::OnlineSession;
use crate::local_routes::session::SmPresenceEpoch;
use crate::local_routes::session::SmStagedRouteClaim;
use northstar_session_application::sm::{SmBufferLimits, SmSessionPolicy};
use std::sync::Arc;

/// Stream management services, policy, route ownership, and recovery.
pub trait SessionSmHost: Send + Sync + 'static {
    /// The repository behind [`SessionSmHost::replay_service`].
    type ReplayStore: northstar_session_application::replay::ReplayAuthorityRepository
        + Clone
        + 'static;
    /// The repository behind [`SessionSmHost::sm_service`].
    type SmStore: northstar_session_application::sm::SmRepository + 'static;
    /// See `ServerNode::replay_service`.
    fn replay_service(
        &self,
    ) -> &northstar_session_application::replay::ReplayService<Self::ReplayStore>;
    /// See `ServerNode::sm_memory_governor`.
    fn sm_memory_governor(
        &self,
    ) -> &Arc<northstar_session_application::sm_capacity::SmMemoryGovernor>;
    /// See `ServerNode::sm_service`.
    fn sm_service(&self) -> &northstar_session_application::sm::SmService<Self::SmStore>;
    /// See `ServerNode::claim_sm_resume_route`.
    fn claim_sm_resume_route(
        &self,
        full_jid: &str,
        connection_id: uuid::Uuid,
        session_id: uuid::Uuid,
        claim_token: uuid::Uuid,
    ) -> impl std::future::Future<Output = anyhow::Result<bool>> + Send;
    /// See `ServerNode::finalize_sm_resume`.
    fn finalize_sm_resume(
        &self,
        request: northstar_session_application::sm::SmResumeFinalizationRequest<'_>,
        observation: Option<
            &northstar_auth_application::authentication::publication::PreparedCredential,
        >,
    ) -> impl std::future::Future<
        Output = anyhow::Result<northstar_session_application::sm::SmResumeFinalizationOutcome>,
    > + Send;
    /// See `ServerNode::release_exact_local_session_route`.
    fn release_exact_local_session_route(
        &self,
        full_jid: &str,
        connection_id: uuid::Uuid,
    ) -> impl std::future::Future<Output = anyhow::Result<()>> + Send;
    /// See `ServerNode::revoke_sm_session_with_teardown`.
    fn revoke_sm_session_with_teardown(
        &self,
        id: uuid::Uuid,
    ) -> impl std::future::Future<Output = anyhow::Result<()>> + Send;
    /// See `ServerNode::sm_buffer_limits`.
    fn sm_buffer_limits(&self) -> SmBufferLimits;
    /// See `ServerNode::sm_ip_binding`.
    fn sm_ip_binding(&self) -> &str;
    /// See `LocalSessionTable::sm_pending_route_removal_signal`.
    fn sm_pending_route_removal_signal(
        &self,
        key: &str,
        old_connection_id: uuid::Uuid,
        user_id: uuid::Uuid,
        sm_session_id: uuid::Uuid,
        cancel_live_route: bool,
    ) -> Option<tokio::sync::watch::Receiver<bool>>;
    /// See `LocalSessionTable::sm_presence_epoch`.
    fn sm_presence_epoch(&self, key: &str) -> Option<SmPresenceEpoch>;
    /// See `ServerNode::sm_session_policy`.
    fn sm_session_policy(&self) -> SmSessionPolicy;
    /// Queues an exact SM suspension whose database write failed for bounded retry; false when the recovery
    /// budget is exhausted.
    #[allow(clippy::too_many_arguments)]
    fn enqueue_sm_suspension_recovery(
        &self,
        account: northstar_session_application::SessionCleanupAccount,
        connection_id: uuid::Uuid,
        session_id: uuid::Uuid,
        snapshot: northstar_session_application::sm::SmSessionSnapshot,
        ttl_seconds: u64,
        endpoints: Vec<Arc<crate::local_routes::muc::SuspendedMucEndpoint>>,
        capacity: northstar_session_application::sm_capacity::SmCapacityLease,
    ) -> bool;
    /// Queues the durable MUC handoff of a suspended session for bounded retry; false when the recovery budget
    /// is exhausted.
    fn enqueue_sm_promote_recovery(
        &self,
        connection_id: uuid::Uuid,
        session_id: uuid::Uuid,
        endpoints: Vec<Arc<crate::local_routes::muc::SuspendedMucEndpoint>>,
        capacity: northstar_session_application::sm_capacity::SmCapacityLease,
    ) -> bool;
    /// Inspect/insert inside one DashMap entry operation. The caller owns the
    /// returned gate and route-incarnation handles before any async wait.
    fn stage_sm_resumed_session(
        &self,
        key: String,
        candidate: OnlineSession,
        claimant_user: uuid::Uuid,
        claimed_sm_id: uuid::Uuid,
        expected_gate: &Arc<tokio::sync::Mutex<()>>,
    ) -> SmStagedRouteClaim;
}
