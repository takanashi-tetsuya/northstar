//! Process-local projections needed by the cluster maintenance pass.
//! No database pool, Redis client, or signing authority crosses this boundary.

use super::{
    cluster_muc_projection::local_cluster_muc_projection_snapshot_in,
    local_session_authority_snapshots_in, local_session_lease_snapshots_in, AppState,
    LocalSessionAuthoritySnapshot, LocalSessionLeaseSnapshot, MucOccupant, OnlineSession,
};
use crate::metrics::{DurationTimer, Metrics};
use dashmap::DashMap;
use std::sync::{atomic::Ordering, Arc};

#[derive(Clone)]
pub(crate) struct ClusterMaintenanceLocals {
    sessions: Arc<DashMap<String, OnlineSession>>,
    occupants: Arc<DashMap<String, MucOccupant>>,
    metrics: Arc<Metrics>,
}

impl ClusterMaintenanceLocals {
    pub(crate) fn session_authority_snapshots(&self) -> Vec<LocalSessionAuthoritySnapshot> {
        local_session_authority_snapshots_in(&self.sessions)
    }

    pub(crate) fn session_lease_snapshots(&self) -> Vec<LocalSessionLeaseSnapshot> {
        local_session_lease_snapshots_in(&self.sessions)
    }

    pub(crate) fn muc_occupant_snapshots(&self) -> Vec<MucOccupant> {
        local_cluster_muc_projection_snapshot_in(&self.occupants)
    }

    pub(crate) fn record_background_failure(&self) {
        self.metrics
            .background_maintenance_failures_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_muc_reconciliation(&self) {
        self.metrics
            .cluster_muc_pg_reconciliations_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn redis_operation_timer(&self) -> DurationTimer<'_> {
        self.metrics.redis_operation_duration_seconds.start_timer()
    }
}

impl AppState {
    pub(crate) fn cluster_maintenance_handles(
        &self,
    ) -> (
        crate::cluster::ClusterMaintenanceControl,
        crate::cluster::ClusterMaintenanceRedis,
    ) {
        (
            self.cluster.maintenance_control(),
            self.cluster.maintenance_redis(),
        )
    }

    pub(crate) fn cluster_maintenance_locals(&self) -> ClusterMaintenanceLocals {
        ClusterMaintenanceLocals {
            sessions: Arc::clone(&self.sessions),
            occupants: Arc::clone(&self.muc_occupants),
            metrics: Arc::clone(&self.metrics),
        }
    }
}
