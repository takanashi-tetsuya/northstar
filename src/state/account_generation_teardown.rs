//! Root bindings for the auth-owned ordered account generation teardown.

use super::{
    sm_teardown_runtime::{sm_teardown_snapshot, AppSmTeardownRuntime},
    AccountRevocationRoutes, AppState,
};
use crate::cluster::ClusterAccountTeardownNotifier;
use anyhow::Result;
use futures::future::BoxFuture;
use northstar_auth_xmpp::account_generation_teardown::{
    AccountGenerationTeardownPorts, AccountGenerationTeardownSequence,
};
use northstar_http::contexts::account_teardown::AccountGenerationTeardown;
use northstar_session_application::sm_teardown::SmTeardownService;
use northstar_workflows::sm_teardown_repository::PostgresSmTeardownRepository;
use std::sync::Arc;
use uuid::Uuid;

#[derive(Clone)]
pub(crate) struct AccountGenerationTeardownAdapters {
    routes: AccountRevocationRoutes,
    sm: SmTeardownService<PostgresSmTeardownRepository>,
    sm_effects: Arc<AppSmTeardownRuntime>,
    notifier: ClusterAccountTeardownNotifier,
}

#[derive(Clone)]
pub(crate) struct AccountGenerationTeardownAdapter {
    sequence: AccountGenerationTeardownSequence<AccountGenerationTeardownAdapters>,
}

impl AccountGenerationTeardown for AccountGenerationTeardownAdapter {
    fn run<'a>(
        &'a self,
        user_id: Uuid,
        bare_account_jid: &'a str,
        auth_generation_exclusive: i64,
    ) -> BoxFuture<'a, ()> {
        Box::pin(
            self.sequence
                .run(user_id, bare_account_jid, auth_generation_exclusive),
        )
    }
}

impl AppState {
    pub(crate) fn account_generation_teardown_sequence(&self) -> AccountGenerationTeardownAdapter {
        AccountGenerationTeardownAdapter {
            sequence: AccountGenerationTeardownSequence::new(AccountGenerationTeardownAdapters {
                routes: AccountRevocationRoutes::new(Arc::clone(&self.sessions)),
                sm: SmTeardownService::new(
                    PostgresSmTeardownRepository::new(self.pool.clone()),
                    self.config.sm_claim_lease_seconds,
                ),
                sm_effects: Arc::new(self.sm_teardown_runtime()),
                notifier: self.cluster_account_teardown_notifier(),
            }),
        }
    }
}

impl AccountGenerationTeardownPorts for AccountGenerationTeardownAdapters {
    fn revoke_local_routes(
        &self,
        user_id: Uuid,
        bare_account_jid: &str,
        auth_generation_exclusive: Option<i64>,
    ) -> usize {
        self.routes
            .revoke(user_id, bare_account_jid, auth_generation_exclusive)
    }

    async fn revoke_durable_sm(
        &self,
        user_id: Uuid,
        auth_generation_exclusive: i64,
    ) -> Result<usize> {
        let effects = Arc::clone(&self.sm_effects);
        self.sm
            .revoke_before_generation(user_id, auth_generation_exclusive, move |snapshot| {
                let effects = Arc::clone(&effects);
                async move {
                    effects
                        .teardown_snapshot(&sm_teardown_snapshot(&snapshot))
                        .await
                }
            })
            .await
    }

    async fn notify_cluster(
        &self,
        bare_account_jid: &str,
        user_id: Uuid,
        auth_generation_exclusive: i64,
    ) -> Result<()> {
        self.notifier
            .send_account_generation_teardown(bare_account_jid, user_id, auth_generation_exclusive)
            .await
    }
}
