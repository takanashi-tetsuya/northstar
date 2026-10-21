//! Local effects permitted after a cluster listener authenticates a command.

use crate::xmpp::local_routes::{
    session::{AccountRevocationRoutes, OnlineSession},
    session_table::{fence_local_session_in, session_entries_for_in, LocalSessionFence},
};
use crate::{
    cluster::{
        ClusterListenerMucProjection, ClusterListenerPresenceRoutes, ClusterMucOutboxSignal,
        ClusterSessionTerminationIdentity, SessionTerminationEffect,
    },
    db::session_termination_authority_repository::PostgresSessionTerminationAuthorityRepository,
    services::session_termination_authority::{
        SessionTerminationAuthority, SessionTerminationAuthorityService,
    },
};
use uuid::Uuid;

pub(crate) struct ClusterListenerDispatch {
    pub(crate) muc_outbox: ClusterMucOutboxSignal,
    pub(crate) muc_projection: ClusterListenerMucProjection,
    pub(crate) presence_routes: ClusterListenerPresenceRoutes,
    pub(crate) account_routes: AccountRevocationRoutes,
    pub(crate) session_identity: ClusterSessionTerminationIdentity,
    pub(crate) session_authority:
        SessionTerminationAuthorityService<PostgresSessionTerminationAuthorityRepository>,
}

impl ClusterListenerDispatch {
    pub(crate) fn node_id(&self) -> &str {
        self.presence_routes.node_id()
    }

    pub(crate) async fn remote_presence_nodes(
        &self,
        recipient: &str,
    ) -> anyhow::Result<Vec<String>> {
        self.presence_routes.remote_nodes(recipient).await
    }

    pub(crate) async fn leave_empty_muc_room(&self, room_jid: &str) -> anyhow::Result<()> {
        self.muc_projection.leave_empty_room(room_jid).await
    }

    pub(crate) fn wake_muc_outbox(&self) {
        self.muc_outbox.notify();
    }

    pub(crate) fn revoke_account_before_generation(
        &self,
        user_id: Uuid,
        bare_jid: &str,
        generation: i64,
    ) -> usize {
        self.account_routes
            .revoke(user_id, bare_jid, Some(generation))
    }

    /// Return cloned routable routes; no DashMap guard crosses listener I/O.
    pub(crate) fn session_entries_for(&self, jid: &str) -> Vec<(String, OnlineSession)> {
        session_entries_for_in(&self.account_routes.sessions, jid)
    }

    pub(crate) fn fence_sm_session(&self, full_jid: &str, sm_session_id: Uuid) -> bool {
        fence_local_session_in(
            &self.account_routes.sessions,
            full_jid,
            LocalSessionFence::Sm(sm_session_id),
        )
    }

    pub(crate) async fn terminate_exact_session(
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
