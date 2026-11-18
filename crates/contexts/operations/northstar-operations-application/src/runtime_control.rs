//! Durable runtime policy and service-control reads on one reserved connection.

use anyhow::Result;
use uuid::Uuid;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DurableServiceControl {
    pub generation: Uuid,
    pub action: String,
    pub execute_at: northstar_time::DateTime<northstar_time::Utc>,
    pub fired_at: Option<northstar_time::DateTime<northstar_time::Utc>>,
    pub expires_at: northstar_time::DateTime<northstar_time::Utc>,
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

pub fn service_control_applies(
    process_started_at: northstar_time::DateTime<northstar_time::Utc>,
    control: &DurableServiceControl,
) -> bool {
    control
        .fired_at
        .is_some_and(|fired_at| process_started_at < fired_at)
}

#[cfg(test)]
mod tests {
    use super::{service_control_applies, DurableServiceControl};

    #[test]
    fn service_control_only_stops_processes_started_before_the_fire_epoch() {
        let fired_at = northstar_time::Utc::now();
        let control = DurableServiceControl {
            generation: uuid::Uuid::new_v4(),
            action: "restart".to_owned(),
            execute_at: fired_at - northstar_time::Duration::seconds(1),
            fired_at: Some(fired_at),
            expires_at: fired_at + northstar_time::Duration::minutes(5),
        };
        assert!(service_control_applies(
            fired_at - northstar_time::Duration::seconds(1),
            &control
        ));
        assert!(!service_control_applies(fired_at, &control));
        assert!(!service_control_applies(
            fired_at + northstar_time::Duration::seconds(1),
            &control
        ));
        let pending = DurableServiceControl {
            fired_at: None,
            ..control
        };
        assert!(!service_control_applies(
            fired_at - northstar_time::Duration::seconds(1),
            &pending
        ));
    }
}
