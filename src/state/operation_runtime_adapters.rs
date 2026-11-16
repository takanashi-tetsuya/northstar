//! Bind the durable workers to the live root effect contexts and repositories.

use super::{
    AppState, OperationIslandEffects, OperationMucDestroyEffects, OperationPanicEffects,
    OperationSessionEffects, OperationTlsReloadEffects, OperationWorkerControl,
};
use anyhow::Result;
use northstar_operations_application::operation_effect_fence::OperationEffectFenceService;
use northstar_operations_application::operation_journal_worker::OperationJournalWorkerService;
use northstar_operations_application::operation_muc_destroy::{MucDestroyCommit, MucDestroyEffect};
use northstar_operations_application::operations::{OperationRecord, OperationTargetRecord};
use northstar_operations_postgres::api_operations::{OperationLease, OperationTargetLease};
use northstar_operations_postgres::operation_effect_fence_repository::PostgresOperationEffectFenceRepository;
use northstar_operations_postgres::operation_journal_worker_repository::PostgresOperationJournalWorkerRepository;
use northstar_operations_xmpp::operation_runtime::{ports, OperationWorkerRuntime};
use northstar_room_core::occupancy::LocalMucOccupantIdentity;
use northstar_security::tls::TlsReloadOutcome;
use serde_json::Value;
use uuid::Uuid;

pub(crate) struct RuntimeControl(OperationWorkerControl);
pub(crate) struct RuntimeSessionEffects(OperationSessionEffects);
pub(crate) struct RuntimeTlsReloadEffects(OperationTlsReloadEffects);
pub(crate) struct RuntimeIslandEffects(OperationIslandEffects);
pub(crate) struct RuntimeMucDestroyEffects(OperationMucDestroyEffects);
pub(crate) struct RuntimePanicEffects(OperationPanicEffects);

pub(crate) type BoundOperationWorkerRuntime = OperationWorkerRuntime<
    RuntimeControl,
    RuntimeSessionEffects,
    RuntimeTlsReloadEffects,
    RuntimeIslandEffects,
    RuntimeMucDestroyEffects,
    RuntimePanicEffects,
>;

impl AppState {
    pub(crate) fn operation_worker_runtime(&self) -> BoundOperationWorkerRuntime {
        OperationWorkerRuntime::new(
            RuntimeControl(self.operation_worker_control()),
            RuntimeSessionEffects(self.operation_session_effects()),
            RuntimeTlsReloadEffects(self.operation_tls_reload_effects()),
            RuntimeIslandEffects(self.operation_island_effects()),
            RuntimeMucDestroyEffects(self.operation_muc_destroy_effects()),
            RuntimePanicEffects(self.operation_panic_effects()),
        )
    }
}

impl ports::OperationWorkerControl for RuntimeControl {
    type Parent = OperationLease;
    type Target = OperationTargetLease;
    type Journal = PostgresOperationJournalWorkerRepository;
    type Fence = PostgresOperationEffectFenceRepository;

    async fn claim_parent_with_targets(
        &self,
        worker_id: Uuid,
        lease_seconds: i64,
    ) -> Result<Option<Self::Parent>> {
        self.0
            .claim_parent_with_targets(worker_id, lease_seconds)
            .await
    }

    fn journal(&self) -> &OperationJournalWorkerService<Self::Journal> {
        self.0.journal()
    }

    fn effects(&self) -> &OperationEffectFenceService<Self::Fence> {
        self.0.effects()
    }

    fn operation(parent: &Self::Parent) -> &OperationRecord {
        &parent.operation
    }

    fn target(target: &Self::Target) -> &OperationTargetRecord {
        &target.target
    }
}

impl ports::OperationSessionEffects for RuntimeSessionEffects {
    fn kick_exact(&self, user_id: Uuid, auth_generation: i64, connection_id: Uuid) -> bool {
        self.0.kick_exact(user_id, auth_generation, connection_id)
    }

    fn send_broadcast_exact(&self, payload: &Value) -> Result<Value> {
        self.0.send_broadcast_exact(payload)
    }

    fn cancel_exact_generation(&self, user_id: Uuid, auth_generation: i64) -> u64 {
        self.0.cancel_exact_generation(user_id, auth_generation)
    }
}

impl ports::OperationTlsReloadEffects for RuntimeTlsReloadEffects {
    async fn reload(&self) -> Result<TlsReloadOutcome> {
        self.0.reload().await
    }
}

impl ports::OperationIslandEffects for RuntimeIslandEffects {
    async fn converge(&self, enabled: bool) {
        self.0.converge(enabled).await;
    }
}

impl ports::OperationMucDestroyEffects for RuntimeMucDestroyEffects {
    async fn commit(&self, effect: MucDestroyEffect<'_>) -> Result<MucDestroyCommit> {
        self.0.commit(effect).await
    }

    async fn notify_committed(&self, operation_id: Uuid) {
        self.0.notify_committed(operation_id).await;
    }

    fn remove_local_occupant_exact(&self, identity: LocalMucOccupantIdentity<'_>) -> bool {
        self.0.remove_local_occupant_exact(identity)
    }
}

impl ports::OperationPanicEffects for RuntimePanicEffects {
    async fn execute(&self) -> Result<Value> {
        self.0.execute().await
    }
}
