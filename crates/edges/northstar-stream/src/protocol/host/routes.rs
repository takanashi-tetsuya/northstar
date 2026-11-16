use crate::local_routes::session::OnlineSession;
use std::sync::atomic::AtomicU8;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;

/// Exact session route ownership, publication, and remote routing.
pub trait SessionRoutesHost: Send + Sync + 'static {
    /// Claim a route that remains unpublished until the login transaction
    /// commits. The binding proof is fixed at this boundary.
    fn claim_staged_binding_route(
        &self,
        full_jid: &str,
        connection_id: uuid::Uuid,
    ) -> impl std::future::Future<Output = anyhow::Result<bool>> + Send;
    /// See `ServerNode::finalize_resource_binding`.
    #[allow(clippy::too_many_arguments)]
    fn finalize_resource_binding(
        &self,
        connection_id: uuid::Uuid,
        user_id: uuid::Uuid,
        expected_auth_generation: i64,
        full_jid: &str,
        device_id: Option<uuid::Uuid>,
        fast_plan: Option<&northstar_auth_application::authentication::FastCommitPlan>,
        observation: Option<
            &northstar_auth_application::authentication::publication::PreparedCredential,
        >,
    ) -> impl std::future::Future<
        Output = anyhow::Result<northstar_session_application::sm::BindingFinalizationOutcome>,
    > + Send;
    /// See `ServerNode::release_staged_binding_route`.
    fn release_staged_binding_route(
        &self,
        full_jid: &str,
        connection_id: uuid::Uuid,
    ) -> impl std::future::Future<Output = anyhow::Result<()>> + Send;
    /// Remove exactly one local route incarnation. Every rollback and Drop
    /// path must use this instead of an unconditional DashMap removal: a late
    /// old connection must never delete a newly bound/resumed replacement.
    fn remove_session_if_connection(
        &self,
        key: &str,
        connection_id: uuid::Uuid,
    ) -> Option<OnlineSession>;
    /// See `LocalSessionTable::staged_session_is_current`.
    fn staged_session_is_current(
        &self,
        key: &str,
        connection_id: uuid::Uuid,
        user_id: uuid::Uuid,
        auth_generation: i64,
        lifecycle: &Arc<AtomicU8>,
    ) -> bool;
    /// Reserve a non-routable bind candidate under the same map entry guard
    /// that rejects a concurrent bind or resume for this full JID.
    fn try_stage_bound_session(&self, key: String, session: OnlineSession) -> bool;
    /// Publish only the exact staged route incarnation that survived every
    /// authorization and lifecycle fence.  The DashMap write guard provides
    /// a local linearization point with account/session revocation helpers;
    /// the cancellation/lifecycle recheck after publication also closes a
    /// concurrent out-of-band transport cancellation window.
    fn activate_session_if_current(
        &self,
        full_jid: &str,
        connection_id: uuid::Uuid,
        user_id: uuid::Uuid,
        auth_generation: i64,
        lifecycle: &Arc<AtomicU8>,
        disconnect: &CancellationToken,
    ) -> bool;
    /// See `ServerNode::notify_remote_user_agent_replacement`.
    fn notify_remote_user_agent_replacement(
        &self,
        account: &str,
        user_id: uuid::Uuid,
        device_id: uuid::Uuid,
        epoch: i64,
    ) -> impl std::future::Future<Output = anyhow::Result<()>> + Send;
    /// See `LocalSessionTable::publish_user_agent_epoch_if_current`.
    fn publish_user_agent_epoch_if_current(
        &self,
        key: &str,
        connection_id: uuid::Uuid,
        user_id: uuid::Uuid,
        auth_generation: i64,
        lifecycle: &Arc<AtomicU8>,
        user_agent_epoch: Option<i64>,
    ) -> bool;
    /// See `LocalSessionTable::session_entries_for`.
    fn session_entries_for(&self, jid: &str) -> Vec<(String, OnlineSession)>;
    /// A failed route lookup supplies no evidence of an exact remote resource.
    fn personal_message_remote_resource_exists(
        &self,
        jid: &str,
    ) -> impl std::future::Future<Output = bool> + Send;
    /// Client IQs addressed to a full JID stop at the first accepting node.
    fn route_client_iq_to_remote_resource(
        &self,
        full_jid: &str,
        stanza: &str,
    ) -> impl std::future::Future<Output = bool> + Send;
}
