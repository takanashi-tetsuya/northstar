//! Post-commit account teardown for credential changes that replace all sessions.

use super::{
    session_cleanup_sm_revoker::SessionCleanupSmRevoker, AccountRevocationRoutes, AppState,
};
use crate::{
    cluster::ClusterAccountTeardownNotifier,
    db::account_teardown_repository::PostgresAccountGenerationRepository,
    services::account_teardown::AccountGenerationService,
};
use axum::extract::FromRef;
use std::sync::Arc;
use uuid::Uuid;

pub(crate) struct AccountTeardownRuntime {
    routes: AccountRevocationRoutes,
    sm: SessionCleanupSmRevoker,
    generation: AccountGenerationService<PostgresAccountGenerationRepository>,
    notifier: ClusterAccountTeardownNotifier,
}

impl FromRef<Arc<AppState>> for AccountTeardownRuntime {
    fn from_ref(state: &Arc<AppState>) -> Self {
        state.account_teardown_runtime()
    }
}

impl AppState {
    pub(crate) fn account_teardown_runtime(&self) -> AccountTeardownRuntime {
        AccountTeardownRuntime {
            routes: AccountRevocationRoutes::new(Arc::clone(&self.sessions)),
            sm: self.session_cleanup_sm_revoker(),
            generation: AccountGenerationService::new(PostgresAccountGenerationRepository::new(
                self.pool.clone(),
            )),
            notifier: self.cluster_account_teardown_notifier(),
        }
    }
}

impl AccountTeardownRuntime {
    pub(crate) async fn disconnect_account(&self, user_id: Uuid, bare_account_jid: &str) {
        self.routes.revoke(user_id, bare_account_jid, None);
        if let Err(error) = self.sm.revoke_user_with_teardown(user_id).await {
            tracing::error!(?error, %user_id, "failed to revoke durable SM sessions");
        }
        // Credentials are already committed. A read failure leaves the
        // periodic generation sweep responsible for cross-node teardown.
        let generation = match self.generation.committed_generation(user_id).await {
            Ok(generation) => generation,
            Err(error) => {
                tracing::error!(?error, %user_id, "could not load the post-mutation auth generation");
                return;
            }
        };
        if let Err(error) = self
            .notifier
            .send_account_generation_teardown(bare_account_jid, user_id, generation)
            .await
        {
            tracing::error!(
                ?error,
                %user_id,
                auth_generation = generation,
                "cross-node account revocation was not acknowledged; maintenance will retry"
            );
        }
    }
}
