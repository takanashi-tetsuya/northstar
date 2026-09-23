//! Ordered post-commit account revocation.

use super::{sm_teardown_runtime::SmTeardownRuntime, AccountRevocationRoutes, AppState};
use crate::cluster::ClusterAccountTeardownNotifier;
use crate::db::sm_teardown_repository::PostgresSmTeardownRepository;
use crate::services::sm_teardown::SmTeardownService;
use axum::extract::FromRef;
use std::future::Future;
use std::sync::Arc;
use uuid::Uuid;

#[derive(Clone)]
pub(crate) struct AccountGenerationTeardownSequence {
    routes: AccountRevocationRoutes,
    sm: SmTeardownService<PostgresSmTeardownRepository>,
    sm_effects: Arc<SmTeardownRuntime>,
    notifier: ClusterAccountTeardownNotifier,
}

impl FromRef<Arc<AppState>> for AccountGenerationTeardownSequence {
    fn from_ref(state: &Arc<AppState>) -> Self {
        state.account_generation_teardown_sequence()
    }
}

impl AppState {
    pub(crate) fn account_generation_teardown_sequence(&self) -> AccountGenerationTeardownSequence {
        AccountGenerationTeardownSequence {
            routes: AccountRevocationRoutes::new(std::sync::Arc::clone(&self.sessions)),
            sm: SmTeardownService::new(
                PostgresSmTeardownRepository::new(self.pool.clone()),
                self.config.sm_claim_lease_seconds,
            ),
            sm_effects: Arc::new(self.sm_teardown_runtime()),
            notifier: self.cluster_account_teardown_notifier(),
        }
    }
}

impl AccountGenerationTeardownSequence {
    pub(crate) async fn run(
        &self,
        user_id: Uuid,
        bare_account_jid: &str,
        auth_generation_exclusive: i64,
    ) {
        run_ordered(
            &self.routes,
            user_id,
            bare_account_jid,
            auth_generation_exclusive,
            || {
                let effects = Arc::clone(&self.sm_effects);
                self.sm.revoke_before_generation(
                    user_id,
                    auth_generation_exclusive,
                    move |snapshot| {
                        let effects = Arc::clone(&effects);
                        async move { effects.teardown_snapshot(&snapshot).await }
                    },
                )
            },
            || {
                self.notifier.send_account_generation_teardown(
                    bare_account_jid,
                    user_id,
                    auth_generation_exclusive,
                )
            },
        )
        .await;
    }
}

async fn run_ordered<Sm, SmFuture, Cluster, ClusterFuture>(
    routes: &AccountRevocationRoutes,
    user_id: Uuid,
    bare_account_jid: &str,
    auth_generation_exclusive: i64,
    revoke_durable_sm: Sm,
    notify_cluster: Cluster,
) where
    Sm: FnOnce() -> SmFuture,
    SmFuture: Future<Output = anyhow::Result<usize>>,
    Cluster: FnOnce() -> ClusterFuture,
    ClusterFuture: Future<Output = anyhow::Result<()>>,
{
    if auth_generation_exclusive <= 0 {
        tracing::error!(
            %user_id,
            auth_generation = auth_generation_exclusive,
            "refused invalid account authorization teardown fence"
        );
        return;
    }
    routes.revoke(user_id, bare_account_jid, Some(auth_generation_exclusive));
    if let Err(error) = revoke_durable_sm().await {
        tracing::error!(
            ?error,
            %user_id,
            auth_generation = auth_generation_exclusive,
            "failed to revoke generation-fenced durable SM sessions"
        );
    }
    if let Err(error) = notify_cluster().await {
        tracing::error!(
            ?error,
            %user_id,
            auth_generation = auth_generation_exclusive,
            "generation-fenced cross-node account revocation was not acknowledged"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dashmap::DashMap;
    use std::sync::{Arc, Mutex};

    #[tokio::test]
    async fn failed_sm_teardown_still_notifies_cluster() {
        let routes = AccountRevocationRoutes::new(Arc::new(DashMap::new()));
        let calls = Arc::new(Mutex::new(Vec::new()));
        let sm_calls = Arc::clone(&calls);
        let cluster_calls = Arc::clone(&calls);
        run_ordered(
            &routes,
            Uuid::new_v4(),
            "alice@example.test",
            5,
            move || async move {
                sm_calls.lock().unwrap().push("sm");
                anyhow::bail!("fixture SM failure")
            },
            move || async move {
                cluster_calls.lock().unwrap().push("cluster");
                Ok(())
            },
        )
        .await;
        assert_eq!(*calls.lock().unwrap(), ["sm", "cluster"]);
    }

    #[tokio::test]
    async fn invalid_generation_runs_no_teardown_effects() {
        let routes = AccountRevocationRoutes::new(Arc::new(DashMap::new()));
        let calls = Arc::new(Mutex::new(Vec::new()));
        let sm_calls = Arc::clone(&calls);
        let cluster_calls = Arc::clone(&calls);
        run_ordered(
            &routes,
            Uuid::new_v4(),
            "alice@example.test",
            0,
            move || async move {
                sm_calls.lock().unwrap().push("sm");
                Ok(0)
            },
            move || async move {
                cluster_calls.lock().unwrap().push("cluster");
                Ok(())
            },
        )
        .await;
        assert!(calls.lock().unwrap().is_empty());
    }
}
