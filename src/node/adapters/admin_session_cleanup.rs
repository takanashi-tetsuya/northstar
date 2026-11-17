//! Lease and process-local route fences for administrator session cleanup.

use crate::node::{
    fence_local_session_in, AccountRevocationRoutes, LocalSessionFence, OnlineSession, ServerNode,
};
use dashmap::DashMap;
use northstar_operations_application::admin_session_cleanup_worker::AdminSessionCleanupWorkerService;
use northstar_operations_postgres::admin_session_cleanup_worker_repository::PostgresAdminSessionCleanupRepository;
use std::sync::Arc;
use uuid::Uuid;

pub(crate) struct AdminSessionCleanupContext {
    service: AdminSessionCleanupWorkerService<PostgresAdminSessionCleanupRepository>,
    notifier: northstar_cluster::ClusterAccountTeardownNotifier,
    routes: AccountRevocationRoutes,
    sessions: Arc<DashMap<String, OnlineSession>>,
    local_domain: String,
}

impl ServerNode {
    pub(crate) fn admin_session_cleanup_context(&self) -> AdminSessionCleanupContext {
        AdminSessionCleanupContext {
            service: self.operations.admin_session_cleanup_worker_service.clone(),
            notifier: self.cluster_account_teardown_notifier(),
            routes: AccountRevocationRoutes::new(Arc::clone(self.session.live().sessions())),
            sessions: Arc::clone(self.session.live().sessions()),
            local_domain: self.config.domain.clone(),
        }
    }
}

impl AdminSessionCleanupContext {
    pub(crate) fn notifier(&self) -> &northstar_cluster::ClusterAccountTeardownNotifier {
        &self.notifier
    }

    pub(crate) fn service(
        &self,
    ) -> &AdminSessionCleanupWorkerService<PostgresAdminSessionCleanupRepository> {
        &self.service
    }

    pub(crate) fn local_domain(&self) -> &str {
        &self.local_domain
    }

    pub(crate) fn revoke_generation_routes(
        &self,
        user_id: Uuid,
        bare_account_jid: &str,
        auth_generation: i64,
    ) -> usize {
        self.routes
            .revoke(user_id, bare_account_jid, Some(auth_generation))
    }

    pub(crate) fn fence_exact_session(
        &self,
        full_jid: &str,
        user_id: Uuid,
        auth_generation: i64,
        connection_id: Uuid,
    ) -> bool {
        fence_local_session_in(
            &self.sessions,
            full_jid,
            LocalSessionFence::Admin {
                user_id,
                auth_generation,
                connection_id,
            },
        )
    }
}
