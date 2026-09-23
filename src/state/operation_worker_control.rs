//! Durable operation claim, lease, and point-of-no-return authority.

use super::AppState;
use crate::{
    db::{
        operation_effect_fence_repository::PostgresOperationEffectFenceRepository,
        operation_journal_worker_repository::PostgresOperationJournalWorkerRepository,
        OperationLease,
    },
    operation_runtime::LocalBroadcastTargetSnapshot,
    services::{
        operation_effect_fence::OperationEffectFenceService,
        operation_journal_worker::OperationJournalWorkerService,
    },
};
use anyhow::Result;
use uuid::Uuid;

pub(crate) struct OperationWorkerControl {
    journal: OperationJournalWorkerService<PostgresOperationJournalWorkerRepository>,
    effects: OperationEffectFenceService<PostgresOperationEffectFenceRepository>,
    routes: LocalBroadcastTargetSnapshot,
}

impl AppState {
    pub(crate) fn operation_worker_control(&self) -> OperationWorkerControl {
        OperationWorkerControl {
            journal: self.operation_journal_worker_service.clone(),
            effects: self.operation_effect_fence_service.clone(),
            routes: self.broadcast_routes().target_snapshot(),
        }
    }
}

impl OperationWorkerControl {
    /// The route snapshot is computed by the journal's claim transaction,
    /// before any target rows are committed.
    pub(crate) async fn claim_parent_with_targets(
        &self,
        worker_id: Uuid,
        lease_seconds: i64,
    ) -> Result<Option<OperationLease>> {
        self.journal
            .claim_parent_with_targets(worker_id, lease_seconds, |operation| {
                self.routes.target_seeds(operation)
            })
            .await
    }

    pub(crate) fn journal(
        &self,
    ) -> &OperationJournalWorkerService<PostgresOperationJournalWorkerRepository> {
        &self.journal
    }

    pub(crate) fn effects(
        &self,
    ) -> &OperationEffectFenceService<PostgresOperationEffectFenceRepository> {
        &self.effects
    }
}
