//! Capabilities bound by the composition root for durable operation workers.

use anyhow::Result;
use northstar_operations_application::admin_session_cleanup_worker::{
    AdminSessionCleanupRepository, AdminSessionCleanupWorkerService,
};
use northstar_operations_application::operation_effect_fence::{
    OperationEffectFenceRepository, OperationEffectFenceService,
};
use northstar_operations_application::operation_journal_worker::{
    OperationJournalWorkerRepository, OperationJournalWorkerService,
};
use northstar_operations_application::operation_muc_destroy::{MucDestroyCommit, MucDestroyEffect};
use northstar_operations_application::operations::{OperationRecord, OperationTargetRecord};
use northstar_room_core::occupancy::LocalMucOccupantIdentity;
use northstar_security::tls::TlsReloadOutcome;
use serde_json::Value;
use std::future::Future;
use uuid::Uuid;

/// Journal and effect fences share opaque repository-owned lease identities.
pub trait OperationWorkerControl: Send + Sync + 'static {
    type Parent: Clone + Send + Sync + 'static;
    type Target: Clone + Send + Sync + 'static;
    type Journal: OperationJournalWorkerRepository<Parent = Self::Parent, Target = Self::Target>;
    type Fence: OperationEffectFenceRepository<Parent = Self::Parent, Target = Self::Target>;

    fn claim_parent_with_targets(
        &self,
        worker_id: Uuid,
        lease_seconds: i64,
    ) -> impl Future<Output = Result<Option<Self::Parent>>> + Send;
    fn journal(&self) -> &OperationJournalWorkerService<Self::Journal>;
    fn effects(&self) -> &OperationEffectFenceService<Self::Fence>;
    fn operation(parent: &Self::Parent) -> &OperationRecord;
    fn target(target: &Self::Target) -> &OperationTargetRecord;
}

pub trait OperationSessionEffects: Send + Sync {
    fn kick_exact(&self, user_id: Uuid, auth_generation: i64, connection_id: Uuid) -> bool;
    fn send_broadcast_exact(&self, payload: &Value) -> Result<Value>;
    fn cancel_exact_generation(&self, user_id: Uuid, auth_generation: i64) -> u64;
}

pub trait OperationTlsReloadEffects: Send + Sync {
    fn reload(&self) -> impl Future<Output = Result<TlsReloadOutcome>> + Send;
}

pub trait OperationIslandEffects: Send + Sync {
    fn converge(&self, enabled: bool) -> impl Future<Output = ()> + Send;
}

pub trait OperationMucDestroyEffects: Send + Sync {
    fn commit(
        &self,
        effect: MucDestroyEffect<'_>,
    ) -> impl Future<Output = Result<MucDestroyCommit>> + Send;
    fn notify_committed(&self, operation_id: Uuid) -> impl Future<Output = ()> + Send;
    fn remove_local_occupant_exact(&self, identity: LocalMucOccupantIdentity<'_>) -> bool;
}

pub trait OperationPanicEffects: Send + Sync {
    fn execute(&self) -> impl Future<Output = Result<Value>> + Send;
}

/// Independent cleanup authority: renewable outbox leases, exact local fences,
/// and teardown delivery, without ordinary administrator operation authority.
pub trait AdminSessionCleanupContext: Send + Sync {
    type Repository: AdminSessionCleanupRepository;

    fn service(&self) -> &AdminSessionCleanupWorkerService<Self::Repository>;
    fn local_domain(&self) -> &str;
    fn revoke_generation_routes(
        &self,
        user_id: Uuid,
        bare_account_jid: &str,
        auth_generation: i64,
    ) -> usize;
    fn fence_exact_session(
        &self,
        full_jid: &str,
        user_id: Uuid,
        auth_generation: i64,
        connection_id: Uuid,
    ) -> bool;
    fn send_account_generation_teardown(
        &self,
        bare_jid: &str,
        user_id: Uuid,
        auth_generation: i64,
    ) -> impl Future<Output = Result<()>> + Send;
    fn send_session_instance_termination(
        &self,
        full_jid: &str,
        connection_id: Uuid,
    ) -> impl Future<Output = Result<bool>> + Send;
}
