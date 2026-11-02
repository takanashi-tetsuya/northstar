//! Local effects permitted after a cluster listener authenticates a command.

use crate::{
    ClusterAdapters, ClusterListenerMucProjection, ClusterListenerPresenceRoutes,
    ClusterMucOutboxSignal, ClusterSessionTerminationIdentity, SessionTerminationEffect,
};
use northstar_session_application::session_termination_authority::{
    SessionTerminationAuthority, SessionTerminationAuthorityService,
};
use northstar_stream::local_routes::session::{AccountRevocationRoutes, OnlineSession};
use northstar_stream::local_routes::session_table::{
    fence_local_session_in, session_entries_for_in, LocalSessionFence,
};
use uuid::Uuid;

pub struct ClusterListenerDispatch<A: ClusterAdapters> {
    pub muc_outbox: ClusterMucOutboxSignal,
    pub muc_projection: ClusterListenerMucProjection,
    pub presence_routes: ClusterListenerPresenceRoutes,
    pub account_routes: AccountRevocationRoutes,
    pub session_identity: ClusterSessionTerminationIdentity,
    pub session_authority: SessionTerminationAuthorityService<A::SessionTermination>,
}

impl<A: ClusterAdapters> ClusterListenerDispatch<A> {
    pub fn node_id(&self) -> &str {
        self.presence_routes.node_id()
    }

    pub async fn remote_presence_nodes(&self, recipient: &str) -> anyhow::Result<Vec<String>> {
        self.presence_routes.remote_nodes(recipient).await
    }

    pub async fn leave_empty_muc_room(&self, room_jid: &str) -> anyhow::Result<()> {
        self.muc_projection.leave_empty_room(room_jid).await
    }

    pub fn wake_muc_outbox(&self) {
        self.muc_outbox.notify();
    }

    pub fn revoke_account_before_generation(
        &self,
        user_id: Uuid,
        bare_jid: &str,
        generation: i64,
    ) -> usize {
        self.account_routes
            .revoke(user_id, bare_jid, Some(generation))
    }

    /// Return cloned routable routes; no DashMap guard crosses listener I/O.
    pub fn session_entries_for(&self, jid: &str) -> Vec<(String, OnlineSession)> {
        session_entries_for_in(&self.account_routes.sessions, jid)
    }

    pub fn fence_sm_session(&self, full_jid: &str, sm_session_id: Uuid) -> bool {
        fence_local_session_in(
            &self.account_routes.sessions,
            full_jid,
            LocalSessionFence::Sm(sm_session_id),
        )
    }

    pub async fn terminate_exact_session(
        &self,
        full_jid: &str,
        connection_id: Uuid,
    ) -> anyhow::Result<SessionTerminationEffect> {
        let authority = self
            .session_authority
            .authorize(
                self.session_identity.namespace(),
                full_jid,
                connection_id,
                || self.session_identity.local_instance(),
            )
            .await?;
        Ok(match authority {
            SessionTerminationAuthority::Absent => SessionTerminationEffect::Absent,
            SessionTerminationAuthority::WrongOwner => SessionTerminationEffect::WrongOwner,
            SessionTerminationAuthority::Authorized => {
                if fence_local_session_in(
                    &self.account_routes.sessions,
                    full_jid,
                    LocalSessionFence::Instance(connection_id),
                ) {
                    SessionTerminationEffect::Matched
                } else {
                    SessionTerminationEffect::WrongOwner
                }
            }
        })
    }
}
