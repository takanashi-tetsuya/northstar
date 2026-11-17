//! Post-commit account teardown for credential changes that replace all sessions.

use crate::node::{
    adapters::session_cleanup_sm_revoker::SessionCleanupSmRevoker, AccountRevocationRoutes,
    ServerNode,
};
use futures::future::BoxFuture;
use northstar_auth_application::account_teardown::{
    disconnect_account, AccountGenerationService, AccountTeardownEffects,
};
use northstar_auth_postgres::account_teardown_repository::PostgresAccountGenerationRepository;
use northstar_cluster::ClusterAccountTeardownNotifier;
use northstar_http::contexts::account_teardown::AccountSessionTeardown;
use std::sync::Arc;
use uuid::Uuid;

pub(crate) struct AccountTeardownRuntime {
    routes: AccountRevocationRoutes,
    sm: SessionCleanupSmRevoker,
    generation: AccountGenerationService<PostgresAccountGenerationRepository>,
    notifier: ClusterAccountTeardownNotifier,
}

impl AccountSessionTeardown for AccountTeardownRuntime {
    fn disconnect_account<'a>(
        &'a self,
        user_id: Uuid,
        bare_account_jid: &'a str,
    ) -> BoxFuture<'a, ()> {
        Box::pin(AccountTeardownRuntime::disconnect_account(
            self,
            user_id,
            bare_account_jid,
        ))
    }
}

impl ServerNode {
    pub(crate) fn account_teardown_runtime(&self) -> AccountTeardownRuntime {
        AccountTeardownRuntime {
            routes: AccountRevocationRoutes::new(Arc::clone(self.session.live().sessions())),
            sm: self.session_cleanup_sm_revoker(),
            generation: AccountGenerationService::new(PostgresAccountGenerationRepository::new(
                self.pool.clone(),
            )),
            notifier: self.cluster_account_teardown_notifier(),
        }
    }
}

impl AccountTeardownEffects for AccountTeardownRuntime {
    fn revoke_local_routes(&self, user_id: Uuid, bare_account_jid: &str) {
        self.routes.revoke(user_id, bare_account_jid, None);
    }

    async fn revoke_sm_sessions(&self, user_id: Uuid) -> anyhow::Result<usize> {
        self.sm.revoke_user_with_teardown(user_id).await
    }

    async fn committed_generation(&self, user_id: Uuid) -> anyhow::Result<i64> {
        self.generation.committed_generation(user_id).await
    }

    async fn notify_generation_teardown(
        &self,
        bare_account_jid: &str,
        user_id: Uuid,
        generation: i64,
    ) -> anyhow::Result<()> {
        self.notifier
            .send_account_generation_teardown(bare_account_jid, user_id, generation)
            .await
    }
}

impl AccountTeardownRuntime {
    pub(crate) async fn disconnect_account(&self, user_id: Uuid, bare_account_jid: &str) {
        disconnect_account(self, user_id, bare_account_jid).await;
    }
}
