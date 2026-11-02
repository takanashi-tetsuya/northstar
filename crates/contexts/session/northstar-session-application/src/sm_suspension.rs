//! Durable operations needed to recover an exact SM suspension.
use crate::sm::SmSessionSnapshot;
use anyhow::Result;
use northstar_room_core::{ClusterMucTransitionOutcome, ClusterMucWakeDescriptor};
use std::time::Duration;
use uuid::Uuid;

#[derive(Clone, Copy)]
pub struct SmSuspensionLimits {
    pub max_stanzas: usize,
    pub max_bytes: usize,
}

pub struct SmSuspensionRequest<'a> {
    pub session_id: Uuid,
    pub connection_id: Uuid,
    pub user_id: Uuid,
    pub auth_generation: i64,
    pub snapshot: &'a SmSessionSnapshot,
    pub ttl_seconds: u64,
}

pub struct MucSuspensionRequest<'a> {
    pub operation_id: Uuid,
    pub room_localpart: &'a str,
    pub occupant_incarnation: Uuid,
    pub connection_id: Uuid,
    pub sm_session_id: Uuid,
    pub node_id: &'a str,
    pub lease: Duration,
}

pub trait SmSuspensionRepository: Send + Sync {
    fn suspend_exact_session(
        &self,
        request: SmSuspensionRequest<'_>,
        limits: SmSuspensionLimits,
    ) -> impl std::future::Future<Output = Result<bool>> + Send;
    fn append_suspended_stanza(
        &self,
        session_id: Uuid,
        source_id: Uuid,
        stanza: &str,
        max_stanzas: usize,
        max_bytes: usize,
    ) -> impl std::future::Future<Output = Result<bool>> + Send;
    fn suspend_muc_occupant(
        &self,
        request: MucSuspensionRequest<'_>,
    ) -> impl std::future::Future<Output = Result<ClusterMucTransitionOutcome>> + Send;
    fn committed_muc_wake(
        &self,
        operation_id: Uuid,
    ) -> impl std::future::Future<Output = Result<Option<ClusterMucWakeDescriptor>>> + Send;
}
