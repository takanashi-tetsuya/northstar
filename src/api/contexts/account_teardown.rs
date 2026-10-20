//! Post-commit account teardown ports for credential REST routes; the composition root implements them.

use futures::future::BoxFuture;
use std::sync::Arc;
use uuid::Uuid;

/// Disconnects every local and durable session of an account after a committed credential change.
pub(crate) trait AccountSessionTeardown: Send + Sync {
    fn disconnect_account<'a>(
        &'a self,
        user_id: Uuid,
        bare_account_jid: &'a str,
    ) -> BoxFuture<'a, ()>;
}

/// Revokes every session of an account older than a committed auth generation, in order.
pub(crate) trait AccountGenerationTeardown: Send + Sync {
    fn run<'a>(
        &'a self,
        user_id: Uuid,
        bare_account_jid: &'a str,
        auth_generation_exclusive: i64,
    ) -> BoxFuture<'a, ()>;
}

#[derive(Clone)]
pub(crate) struct AccountTeardownContext {
    teardown: Arc<dyn AccountSessionTeardown>,
}

impl AccountTeardownContext {
    pub(crate) fn new(teardown: Arc<dyn AccountSessionTeardown>) -> Self {
        Self { teardown }
    }

    pub(crate) async fn disconnect_account(&self, user_id: Uuid, bare_account_jid: &str) {
        self.teardown
            .disconnect_account(user_id, bare_account_jid)
            .await
    }
}

#[derive(Clone)]
pub(crate) struct AccountGenerationTeardownContext {
    teardown: Arc<dyn AccountGenerationTeardown>,
}

impl AccountGenerationTeardownContext {
    pub(crate) fn new(teardown: Arc<dyn AccountGenerationTeardown>) -> Self {
        Self { teardown }
    }

    pub(crate) async fn run(
        &self,
        user_id: Uuid,
        bare_account_jid: &str,
        auth_generation_exclusive: i64,
    ) {
        self.teardown
            .run(user_id, bare_account_jid, auth_generation_exclusive)
            .await
    }
}
