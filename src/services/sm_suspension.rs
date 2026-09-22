//! Durable operations needed to recover an exact SM suspension.
use crate::services::{
    muc::{ClusterMucTransitionOutcome, ClusterMucWakeDescriptor},
    sm::SmSessionSnapshot,
};
use anyhow::Result;
use std::time::Duration;
use uuid::Uuid;

#[derive(Clone, Copy)]
pub(crate) struct SmSuspensionLimits {
    pub(crate) max_stanzas: usize,
    pub(crate) max_bytes: usize,
}

pub(crate) struct SmSuspensionRequest<'a> {
    pub(crate) session_id: Uuid,
    pub(crate) connection_id: Uuid,
    pub(crate) user_id: Uuid,
    pub(crate) auth_generation: i64,
    pub(crate) snapshot: &'a SmSessionSnapshot,
    pub(crate) ttl_seconds: u64,
}

pub(crate) struct MucSuspensionRequest<'a> {
    pub(crate) operation_id: Uuid,
    pub(crate) room_localpart: &'a str,
    pub(crate) occupant_incarnation: Uuid,
    pub(crate) connection_id: Uuid,
    pub(crate) sm_session_id: Uuid,
    pub(crate) node_id: &'a str,
    pub(crate) lease: Duration,
}

pub(crate) trait SmSuspensionRepository: Send + Sync {
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
