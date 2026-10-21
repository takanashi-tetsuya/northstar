//! Builds the cluster listener's session-termination dispatch (`cluster::listener_dispatch`).

use super::AppState;
use crate::cluster::listener_dispatch::ClusterListenerDispatch;
use crate::db::session_termination_authority_repository::PostgresSessionTerminationAuthorityRepository;
use crate::services::session_termination_authority::SessionTerminationAuthorityService;
use crate::xmpp::local_routes::session::AccountRevocationRoutes;
use std::sync::Arc;

impl AppState {
    pub(crate) fn cluster_listener_dispatch(&self) -> ClusterListenerDispatch {
        ClusterListenerDispatch {
            muc_outbox: self.cluster.muc_outbox_signal(),
            muc_projection: self.cluster.listener_muc_projection(),
            presence_routes: self.cluster.listener_presence_routes(),
            account_routes: AccountRevocationRoutes::new(Arc::clone(&self.sessions)),
            session_identity: self.cluster.session_termination_identity(),
            session_authority: SessionTerminationAuthorityService::new(
                PostgresSessionTerminationAuthorityRepository::new(self.pool.clone()),
            ),
        }
    }
}
