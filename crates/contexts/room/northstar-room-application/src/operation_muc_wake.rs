//! Best-effort wake for an already committed administrator MUC operation.

use crate::muc_service::{notify_committed_operation, MucWakePort};
use anyhow::Result;
use northstar_room_core::ClusterMucWakeDescriptor;
use std::future::Future;
use uuid::Uuid;

pub trait CommittedMucWakeRepository: Send + Sync {
    fn descriptor(
        &self,
        operation_id: Uuid,
    ) -> impl Future<Output = Result<Option<ClusterMucWakeDescriptor>>> + Send;
}

pub struct CommittedMucWakeService<R> {
    repository: R,
}

impl<R: CommittedMucWakeRepository> CommittedMucWakeService<R> {
    pub fn new(repository: R) -> Self {
        Self { repository }
    }

    /// Wake is an accelerator; the durable PostgreSQL outbox remains the
    /// fallback when either descriptor lookup or signed publication fails.
    pub async fn notify(&self, wake: &impl MucWakePort, operation_id: Uuid) {
        notify_committed_operation(self.repository.descriptor(operation_id), wake, operation_id)
            .await;
    }
}
