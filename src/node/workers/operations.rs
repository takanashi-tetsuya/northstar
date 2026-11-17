//! Independently supervised administrator session cleanup.

use crate::node::{AdminSessionCleanupContext, ServerNode};
use anyhow::Result;
use northstar_operations_application::admin_session_cleanup_worker::AdminSessionCleanupWorkerService;
use northstar_operations_postgres::admin_session_cleanup_worker_repository::PostgresAdminSessionCleanupRepository;
use northstar_operations_xmpp::operation_runtime::ports;
use northstar_runtime::workers::{WorkerCriticality, WorkerMode};
use std::sync::Arc;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

struct RuntimeAdminSessionCleanup(AdminSessionCleanupContext);

pub(super) fn start(state: &Arc<ServerNode>, cancel: &CancellationToken) {
    let worker_registry = state.runtime.workers();
    // Credential-generation and exact-connection cleanup is a security
    // authority, not ordinary administrator background work. Keep it on an
    // independently supervised worker so a large broadcast cannot delay a
    // committed revocation. One attempt owns a 60-second renewable database
    // lease; the watchdog includes a bounded margin for delivery and cleanup.
    let admin_cleanup_context = Arc::new(RuntimeAdminSessionCleanup(
        state.admin_session_cleanup_context(),
    ));
    let admin_cleanup_cancel = cancel.clone();
    worker_registry.supervise(
        "admin-session-cleanup",
        WorkerCriticality::Critical,
        WorkerMode::Continuous,
        Some(std::time::Duration::from_secs(90)),
        cancel.clone(),
        move |heartbeat| {
            northstar_operations_xmpp::operation_runtime::serve_admin_session_cleanup(
                Arc::clone(&admin_cleanup_context),
                admin_cleanup_cancel.clone(),
                heartbeat,
            )
        },
    );
}

impl ports::AdminSessionCleanupContext for RuntimeAdminSessionCleanup {
    type Repository = PostgresAdminSessionCleanupRepository;

    fn service(&self) -> &AdminSessionCleanupWorkerService<Self::Repository> {
        self.0.service()
    }

    fn local_domain(&self) -> &str {
        self.0.local_domain()
    }

    fn revoke_generation_routes(
        &self,
        user_id: Uuid,
        bare_account_jid: &str,
        auth_generation: i64,
    ) -> usize {
        self.0
            .revoke_generation_routes(user_id, bare_account_jid, auth_generation)
    }

    fn fence_exact_session(
        &self,
        full_jid: &str,
        user_id: Uuid,
        auth_generation: i64,
        connection_id: Uuid,
    ) -> bool {
        self.0
            .fence_exact_session(full_jid, user_id, auth_generation, connection_id)
    }

    async fn send_account_generation_teardown(
        &self,
        bare_jid: &str,
        user_id: Uuid,
        auth_generation: i64,
    ) -> Result<()> {
        self.0
            .notifier()
            .send_account_generation_teardown(bare_jid, user_id, auth_generation)
            .await
    }

    async fn send_session_instance_termination(
        &self,
        full_jid: &str,
        connection_id: Uuid,
    ) -> Result<bool> {
        self.0
            .notifier()
            .send_session_instance_termination(full_jid, connection_id)
            .await
    }
}
