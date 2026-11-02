//! Builds the cluster listener's session-termination dispatch (`cluster::listener_dispatch`).

use super::cluster_adapters::PostgresClusterAdapters;
use super::AppState;
use crate::cluster::listener_dispatch::ClusterListenerDispatch;
use northstar_session_application::session_termination_authority::SessionTerminationAuthorityService;
use northstar_session_postgres::session_termination_authority_repository::PostgresSessionTerminationAuthorityRepository;
use northstar_stream::local_routes::session::AccountRevocationRoutes;
use std::sync::Arc;

impl AppState {
    pub(crate) fn cluster_listener_dispatch(
        &self,
    ) -> ClusterListenerDispatch<PostgresClusterAdapters> {
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
