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
pub enum RuntimeControlReadPhase {
    Snapshot,
}

pub struct RuntimePolicySnapshot {
    pub island_mode: bool,
    pub registration_closed: bool,
    pub blacklist: Vec<String>,
    pub whitelist: Vec<String>,
}

pub trait RuntimeControlRepository: Send {
    fn policy_snapshot(
        &mut self,
        read_phase: impl FnMut(RuntimeControlReadPhase) + Send,
    ) -> impl std::future::Future<Output = Result<RuntimePolicySnapshot>> + Send;

    fn service_control(
        &mut self,
    ) -> impl std::future::Future<Output = Result<Option<DurableServiceControl>>> + Send;
}

pub struct RuntimeControlService<R> {
    repository: R,
}

impl<R: RuntimeControlRepository> RuntimeControlService<R> {
    pub fn new(repository: R) -> Self {
        Self { repository }
    }

    pub async fn policy_snapshot(
        &mut self,
        read_phase: impl FnMut(RuntimeControlReadPhase) + Send,
    ) -> Result<RuntimePolicySnapshot> {
        self.repository.policy_snapshot(read_phase).await
    }

    pub async fn service_control(&mut self) -> Result<Option<DurableServiceControl>> {
        self.repository.service_control().await
    }
}
