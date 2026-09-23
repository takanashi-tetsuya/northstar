//! Local effects permitted after a cluster listener authenticates a command.

use super::{fence_local_session_in, AccountRevocationRoutes, AppState, LocalSessionFence};
use crate::{
    cluster::{ClusterMucOutboxSignal, ClusterSessionTerminationIdentity},
    db::session_termination_authority_repository::PostgresSessionTerminationAuthorityRepository,
    services::session_termination_authority::{
        SessionTerminationAuthority, SessionTerminationAuthorityService,
    },
};
use std::sync::Arc;
use uuid::Uuid;

pub(crate) struct ClusterListenerDispatch {
    muc_outbox: ClusterMucOutboxSignal,
    account_routes: AccountRevocationRoutes,
    session_identity: ClusterSessionTerminationIdentity,
    session_authority:
        SessionTerminationAuthorityService<PostgresSessionTerminationAuthorityRepository>,
}

pub(crate) enum SessionTerminationEffect {
    Absent,
    WrongOwner,
    Matched,
}

impl AppState {
    pub(crate) fn cluster_listener_dispatch(&self) -> ClusterListenerDispatch {
        ClusterListenerDispatch {
            muc_outbox: self.cluster.muc_outbox_signal(),
            account_routes: AccountRevocationRoutes::new(Arc::clone(&self.sessions)),
            session_identity: self.cluster.session_termination_identity(),
            session_authority: SessionTerminationAuthorityService::new(
                PostgresSessionTerminationAuthorityRepository::new(self.pool.clone()),
            ),
        }
    }
}

impl ClusterListenerDispatch {
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
