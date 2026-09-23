//! Durable runtime policy and service-control reads on one reserved connection.

use anyhow::Result;
use uuid::Uuid;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DurableServiceControl {
    pub generation: Uuid,
    pub action: String,
    pub execute_at: chrono::DateTime<chrono::Utc>,
    pub fired_at: Option<chrono::DateTime<chrono::Utc>>,
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum RuntimeControlReadPhase {
    Snapshot,
}

pub(crate) struct RuntimePolicySnapshot {
    pub(crate) island_mode: bool,
    pub(crate) registration_closed: bool,
    pub(crate) blacklist: Vec<String>,
    pub(crate) whitelist: Vec<String>,
}

pub(crate) trait RuntimeControlRepository: Send {
    async fn policy_snapshot(
        &mut self,
        read_phase: impl FnMut(RuntimeControlReadPhase) + Send,
    ) -> Result<RuntimePolicySnapshot>;

    async fn service_control(&mut self) -> Result<Option<DurableServiceControl>>;
}

pub(crate) struct RuntimeControlService<R> {
    repository: R,
}

impl<R: RuntimeControlRepository> RuntimeControlService<R> {
    pub(crate) fn new(repository: R) -> Self {
        Self { repository }
    }

    pub(crate) async fn policy_snapshot(
        &mut self,
        read_phase: impl FnMut(RuntimeControlReadPhase) + Send,
    ) -> Result<RuntimePolicySnapshot> {
        self.repository.policy_snapshot(read_phase).await
    }

    pub(crate) async fn service_control(&mut self) -> Result<Option<DurableServiceControl>> {
        self.repository.service_control().await
    }
}
