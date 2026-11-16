//! Ordered post-commit account revocation.

use anyhow::Result;
use std::future::Future;
use uuid::Uuid;

/// The local route fence, durable SM service and signed cluster notifier supplied by the node.
pub trait AccountGenerationTeardownPorts: Send + Sync + 'static {
    fn revoke_local_routes(
        &self,
        user_id: Uuid,
        bare_account_jid: &str,
        auth_generation_exclusive: Option<i64>,
    ) -> usize;
    fn revoke_durable_sm(
        &self,
        user_id: Uuid,
        auth_generation_exclusive: i64,
    ) -> impl Future<Output = Result<usize>> + Send;
    fn notify_cluster(
        &self,
        bare_account_jid: &str,
        user_id: Uuid,
        auth_generation_exclusive: i64,
    ) -> impl Future<Output = Result<()>> + Send;
}

#[derive(Clone)]
pub struct AccountGenerationTeardownSequence<P> {
    ports: P,
}

impl<P: AccountGenerationTeardownPorts> AccountGenerationTeardownSequence<P> {
    pub fn new(ports: P) -> Self {
        Self { ports }
    }

    pub async fn run(&self, user_id: Uuid, bare_account_jid: &str, auth_generation_exclusive: i64) {
        run_ordered(
            |user_id, bare_account_jid, generation| {
                self.ports
                    .revoke_local_routes(user_id, bare_account_jid, generation)
            },
            user_id,
            bare_account_jid,
            auth_generation_exclusive,
            || {
                self.ports
                    .revoke_durable_sm(user_id, auth_generation_exclusive)
            },
            || {
                self.ports
                    .notify_cluster(bare_account_jid, user_id, auth_generation_exclusive)
            },
        )
        .await;
    }
}

async fn run_ordered<Local, Sm, SmFuture, Cluster, ClusterFuture>(
    revoke_local_routes: Local,
    user_id: Uuid,
    bare_account_jid: &str,
    auth_generation_exclusive: i64,
    revoke_durable_sm: Sm,
    notify_cluster: Cluster,
) where
    Local: FnOnce(Uuid, &str, Option<i64>) -> usize,
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
    revoke_local_routes(user_id, bare_account_jid, Some(auth_generation_exclusive));
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
    use std::sync::{Arc, Mutex};

    #[tokio::test]
    async fn failed_sm_teardown_still_notifies_cluster() {
        let routes = |_: Uuid, _: &str, _: Option<i64>| 0;
        let calls = Arc::new(Mutex::new(Vec::new()));
        let sm_calls = Arc::clone(&calls);
        let cluster_calls = Arc::clone(&calls);
        run_ordered(
            routes,
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
        let routes = |_: Uuid, _: &str, _: Option<i64>| 0;
        let calls = Arc::new(Mutex::new(Vec::new()));
        let sm_calls = Arc::clone(&calls);
        let cluster_calls = Arc::clone(&calls);
        run_ordered(
            routes,
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
