//! Deployment-capacity lease renewal and expiry workers.

use super::super::ServerNode;
use northstar_runtime::workers::{WorkerCriticality, WorkerMode};
use northstar_session_application::capacity_maintenance::CapacityMaintenanceRepository;
use northstar_session_postgres::capacity_maintenance_repository::PostgresCapacityMaintenanceRepository;
use sqlx::PgPool;
use std::collections::HashSet;
use std::{sync::Arc, time::Duration};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

pub(super) fn start(state: &Arc<ServerNode>, cancel: &CancellationToken) {
    let worker_registry = state.runtime.workers();
    let capacity_context = capacity_lease_renewal_context(state);
    let capacity_reaper_context = capacity_context.reaper();
    let capacity_interval = capacity_context.heartbeat_interval();
    let capacity_cancel = cancel.clone();
    worker_registry.supervise(
        "deployment-capacity-session-leases",
        WorkerCriticality::Critical,
        WorkerMode::Continuous,
        Some(capacity_interval.saturating_mul(2)),
        cancel.clone(),
        move |heartbeat| {
            northstar_stream::capacity_maintenance::serve_renewal(
                capacity_context.clone(),
                capacity_cancel.clone(),
                heartbeat,
            )
        },
    );
    let capacity_reaper_cancel = cancel.clone();
    worker_registry.supervise(
        "deployment-capacity-lease-reaper",
        WorkerCriticality::Restartable,
        WorkerMode::Continuous,
        Some(std::time::Duration::from_secs(120)),
        cancel.clone(),
        move |heartbeat| {
            northstar_stream::capacity_maintenance::serve_reaper(
                capacity_reaper_context.clone(),
                capacity_reaper_cancel.clone(),
                heartbeat,
            )
        },
    );
}

fn capacity_lease_renewal_context(
    state: &ServerNode,
) -> northstar_stream::capacity_maintenance::CapacityLeaseRenewalContext<CapacityAndPrivacyLeases> {
    northstar_stream::capacity_maintenance::CapacityLeaseRenewalContext::new(
        northstar_session_application::capacity_maintenance::CapacityMaintenanceService::new(
            CapacityAndPrivacyLeases {
                capacity: PostgresCapacityMaintenanceRepository::new(state.pool.clone()),
                pool: state.pool.clone(),
            },
        ),
        Arc::clone(state.session.live().sessions()),
        Arc::clone(&state.metrics),
        Duration::from_secs(state.config.capacity_session_heartbeat_seconds),
        state.config.capacity_session_lease_seconds,
    )
}

#[derive(Clone)]
struct CapacityAndPrivacyLeases {
    capacity: PostgresCapacityMaintenanceRepository,
    pool: PgPool,
}

impl CapacityMaintenanceRepository for CapacityAndPrivacyLeases {
    async fn renew_live_connections(
        &self,
        connection_ids: &[Uuid],
        lease_seconds: u64,
    ) -> anyhow::Result<HashSet<Uuid>> {
        let live = self
            .capacity
            .renew_live_connections(connection_ids, lease_seconds)
            .await?;
        if !live.is_empty() {
            let live_ids = live.iter().copied().collect::<Vec<_>>();
            northstar_roster_postgres::privacy::renew_active_privacy_selection(
                &self.pool, &live_ids,
            )
            .await?;
        }
        Ok(live)
    }

    async fn try_reap_expired(&self, limit: i64) -> anyhow::Result<Option<u64>> {
        self.capacity.try_reap_expired(limit).await
    }
}
