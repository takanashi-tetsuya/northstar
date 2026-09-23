//! Exact durable SM revocation after a client cleanup fallback.

use super::{sm_teardown_runtime::SmTeardownRuntime, AppState};
use crate::{
    db::sm_teardown_repository::PostgresSmTeardownRepository,
    services::sm_teardown::SmTeardownService,
};
use anyhow::Result;
use uuid::Uuid;

pub(crate) struct SessionCleanupSmRevoker {
    claims: SmTeardownService<PostgresSmTeardownRepository>,
    effects: SmTeardownRuntime,
}

impl AppState {
    pub(crate) fn session_cleanup_sm_revoker(&self) -> SessionCleanupSmRevoker {
        SessionCleanupSmRevoker {
            claims: SmTeardownService::new(
                PostgresSmTeardownRepository::new(self.pool.clone()),
                self.config.sm_claim_lease_seconds,
            ),
            effects: self.sm_teardown_runtime(),
        }
    }
}

impl SessionCleanupSmRevoker {
    pub(crate) async fn revoke_with_teardown(&self, session_id: Uuid) -> Result<()> {
        self.claims
            .revoke_exact(session_id, |snapshot| async move {
                self.effects.teardown_snapshot(&snapshot).await
            })
            .await
    }

    pub(crate) async fn revoke_all_with_teardown(&self) -> Result<usize> {
        self.claims
            .revoke_all(|snapshot| async move { self.effects.teardown_snapshot(&snapshot).await })
            .await
    }

    pub(crate) async fn revoke_user_with_teardown(&self, user_id: Uuid) -> Result<usize> {
        self.claims
            .revoke_user(user_id, |snapshot| async move {
                self.effects.teardown_snapshot(&snapshot).await
            })
            .await
    }
}
