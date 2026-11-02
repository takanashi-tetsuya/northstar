//! Expired durable stream claims and their post-claim teardown effects.

use super::{sm_teardown_runtime::SmTeardownRuntime, AppState};
use northstar_session_application::sm_teardown::SmTeardownService;
use northstar_workflows::sm_teardown_repository::PostgresSmTeardownRepository;

pub(crate) struct SmExpiryContext {
    service: SmTeardownService<PostgresSmTeardownRepository>,
    runtime: SmTeardownRuntime,
}

impl AppState {
    pub(crate) fn sm_expiry_context(&self) -> SmExpiryContext {
        SmExpiryContext {
            service: SmTeardownService::new(
                PostgresSmTeardownRepository::new(self.pool.clone()),
                self.config.sm_claim_lease_seconds,
            ),
            runtime: self.sm_teardown_runtime(),
        }
    }
}

impl SmExpiryContext {
    pub(crate) async fn cleanup(&self) -> anyhow::Result<usize> {
        self.service
            .cleanup_expired(
                |snapshot| async move { self.runtime.teardown_snapshot(&snapshot).await },
            )
            .await
    }
}
