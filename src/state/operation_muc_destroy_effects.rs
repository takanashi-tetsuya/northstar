//! Exact post-commit effects for an administrator room destroy operation.

use super::{
    remove_local_muc_occupant_exact_from, AppState, LocalMucOccupantIdentity, MucOccupant,
};
use crate::{
    cluster::ClusterMucOperationWake,
    db::{
        operation_muc_destroy_repository::PostgresMucDestroyRepository,
        operation_muc_wake_repository::PostgresCommittedMucWakeRepository,
    },
    services::{
        operation_muc_destroy::{MucDestroyCommit, MucDestroyEffect, MucDestroyService},
        operation_muc_wake::CommittedMucWakeService,
    },
};
use anyhow::Result;
use dashmap::DashMap;
use std::sync::Arc;
use uuid::Uuid;

pub(crate) struct OperationMucDestroyEffects {
    destroy: Arc<MucDestroyService<PostgresMucDestroyRepository>>,
    wake: CommittedMucWakeService<PostgresCommittedMucWakeRepository>,
    publisher: ClusterMucOperationWake,
    audience: LocalMucDestroyAudience,
}

struct LocalMucDestroyAudience {
    occupants: Arc<DashMap<String, MucOccupant>>,
}

impl AppState {
    pub(crate) fn operation_muc_destroy_effects(&self) -> OperationMucDestroyEffects {
        OperationMucDestroyEffects {
            destroy: Arc::clone(&self.operation_muc_destroy_service),
            wake: CommittedMucWakeService::new(PostgresCommittedMucWakeRepository::new(
                self.pool.clone(),
            )),
            publisher: self.cluster.muc_operation_wake(),
            audience: LocalMucDestroyAudience {
                occupants: Arc::clone(&self.muc_occupants),
            },
        }
    }
}

impl OperationMucDestroyEffects {
    pub(crate) async fn commit(&self, effect: MucDestroyEffect<'_>) -> Result<MucDestroyCommit> {
        self.destroy.execute(effect).await
    }

    pub(crate) async fn notify_committed(&self, operation_id: Uuid) {
        self.wake.notify(&self.publisher, operation_id).await;
    }

    pub(crate) fn remove_local_occupant_exact(
        &self,
        identity: LocalMucOccupantIdentity<'_>,
    ) -> bool {
        remove_local_muc_occupant_exact_from(&self.audience.occupants, identity).is_some()
    }
}
