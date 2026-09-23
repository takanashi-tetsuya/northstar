//! Best-effort wake for an already committed administrator MUC operation.

use crate::services::muc::{notify_committed_operation, MucWakePort};
use anyhow::Result;
use northstar_room_core::ClusterMucWakeDescriptor;
use std::future::Future;
use uuid::Uuid;

pub(crate) trait CommittedMucWakeRepository: Send + Sync {
    fn descriptor(
        &self,
        operation_id: Uuid,
    ) -> impl Future<Output = Result<Option<ClusterMucWakeDescriptor>>> + Send;
}

pub(crate) struct CommittedMucWakeService<R> {
    repository: R,
}

impl<R: CommittedMucWakeRepository> CommittedMucWakeService<R> {
    pub(crate) fn new(repository: R) -> Self {
        Self { repository }
    }

    /// Wake is an accelerator; the durable PostgreSQL outbox remains the
    /// fallback when either descriptor lookup or signed publication fails.
    pub(crate) async fn notify(&self, wake: &impl MucWakePort, operation_id: Uuid) {
        notify_committed_operation(self.repository.descriptor(operation_id), wake, operation_id)
            .await;
    }
}
