//! Lease and process-local route fences for administrator session cleanup.

use super::{
    fence_local_session_in, AccountRevocationRoutes, AppState, LocalSessionFence, OnlineSession,
};
use crate::{
    db::admin_session_cleanup_worker_repository::PostgresAdminSessionCleanupRepository,
    services::admin_session_cleanup_worker::AdminSessionCleanupWorkerService,
};
use dashmap::DashMap;
use std::sync::Arc;
use uuid::Uuid;

pub(crate) struct AdminSessionCleanupContext {
    service: AdminSessionCleanupWorkerService<PostgresAdminSessionCleanupRepository>,
    notifier: crate::cluster::ClusterAccountTeardownNotifier,
    routes: AccountRevocationRoutes,
    sessions: Arc<DashMap<String, OnlineSession>>,
    local_domain: String,
}

impl AppState {
    pub(crate) fn admin_session_cleanup_context(&self) -> AdminSessionCleanupContext {
        AdminSessionCleanupContext {
            service: self.admin_session_cleanup_worker_service.clone(),
            notifier: self.cluster_account_teardown_notifier(),
            routes: AccountRevocationRoutes::new(Arc::clone(&self.sessions)),
            sessions: Arc::clone(&self.sessions),
            local_domain: self.local_domain().to_owned(),
        }
    }
}

impl AdminSessionCleanupContext {
    pub(crate) fn notifier(&self) -> &crate::cluster::ClusterAccountTeardownNotifier {
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
