//! Exact local connection snapshots for capacity renewal; no routing authority escapes.
use crate::local_routes::session::OnlineSession;
use anyhow::{Context, Result};
use dashmap::DashMap;
use northstar_runtime::workers::WorkerHeartbeat;
use northstar_session_application::capacity_maintenance::{
    CapacityMaintenanceRepository, CapacityMaintenanceService,
};
use northstar_telemetry::metrics::Metrics;
use std::{
    sync::{atomic::Ordering, Arc},
    time::Duration,
};
use tokio_util::sync::CancellationToken;

const AUTHORITY_QUERY_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone)]
pub struct CapacityLeaseRenewalContext<R> {
    service: CapacityMaintenanceService<R>,
    sessions: Arc<DashMap<String, OnlineSession>>,
    metrics: Arc<Metrics>,
    heartbeat_interval: Duration,
    lease_seconds: u64,
}

#[derive(Clone)]
pub struct CapacityLeaseReaperContext<R> {
    service: CapacityMaintenanceService<R>,
    heartbeat_interval: Duration,
}

impl<R: CapacityMaintenanceRepository> CapacityLeaseRenewalContext<R> {
    pub fn new(
        service: CapacityMaintenanceService<R>,
        sessions: Arc<DashMap<String, OnlineSession>>,
        metrics: Arc<Metrics>,
        heartbeat_interval: Duration,
        lease_seconds: u64,
    ) -> Self {
        Self {
            service,
            sessions,
            metrics,
            heartbeat_interval,
            lease_seconds,
        }
    }

    pub fn heartbeat_interval(&self) -> Duration {
        self.heartbeat_interval
    }

    pub async fn renew_once(&self, cancel: &CancellationToken) -> Result<bool> {
        self.renew_with_timeout(cancel, AUTHORITY_QUERY_TIMEOUT)
            .await
    }

    async fn renew_with_timeout(
        &self,
        cancel: &CancellationToken,
        query_timeout: Duration,
    ) -> Result<bool> {
        let local = self
            .sessions
            .iter()
            .filter(|session| {
                session.routable.load(Ordering::Acquire)
                    && session.lifecycle.load(Ordering::Acquire) == 0
                    && !session.disconnect.is_cancelled()
            })
            .map(|session| (session.connection_id, session.disconnect.clone()))
            .collect::<Vec<_>>();
        // An idle node owns no lease to renew. The elected reaper handles
        // deployment-wide expiry without creating traffic on every idle node.
        if local.is_empty() {
            return Ok(true);
        }
        let ids = local.iter().map(|(id, _)| *id).collect::<Vec<_>>();
        let refreshed = tokio::select! {
            _ = cancel.cancelled() => return Ok(false),
            result = tokio::time::timeout(
                query_timeout,
                self.service.renew_live_connections(&ids, self.lease_seconds),
            ) => result
                .context("deployment live-session lease refresh timed out")?
                .context("could not refresh deployment live-session capacity leases")?,
        };
        // Keep the tokens captured before the database await: a replacement
        // at the same JID must not inherit an older connection's lease loss.
        for (connection_id, disconnect) in local {
            if !refreshed.contains(&connection_id) {
                self.metrics
                    .capacity_session_lease_losses_total
                    .fetch_add(1, Ordering::Relaxed);
                tracing::error!(%connection_id, "committed route lost its PostgreSQL capacity lease; disconnecting fail closed");
                disconnect.cancel();
            }
        }
        Ok(true)
    }
}

impl<R: CapacityMaintenanceRepository + Clone> CapacityLeaseRenewalContext<R> {
    pub fn reaper(&self) -> CapacityLeaseReaperContext<R> {
        CapacityLeaseReaperContext {
            service: self.service.clone(),
            heartbeat_interval: self.heartbeat_interval,
        }
    }
}

impl<R: CapacityMaintenanceRepository> CapacityLeaseReaperContext<R> {
    pub fn heartbeat_interval(&self) -> Duration {
        self.heartbeat_interval
    }

    pub async fn reap_once(&self, cancel: &CancellationToken) -> Result<bool> {
        let result = tokio::select! {
            _ = cancel.cancelled() => return Ok(false),
            result = tokio::time::timeout(
                AUTHORITY_QUERY_TIMEOUT,
                self.service.try_reap_expired(1024),
            ) => result
                .context("deployment live-session lease reaper timed out")?
                .context("could not elect deployment live-session lease reaper")?,
        };
        if let Some(removed) = result {
            tracing::debug!(removed, "reaped expired deployment live-session leases");
        }
        Ok(true)
    }
}

pub async fn serve_renewal<R: CapacityMaintenanceRepository>(
    context: CapacityLeaseRenewalContext<R>,
    cancel: CancellationToken,
    heartbeat: WorkerHeartbeat,
) -> Result<()> {
    let mut interval = tokio::time::interval(context.heartbeat_interval());
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            _ = cancel.cancelled() => return Ok(()),
            _ = interval.tick() => {
                if !context.renew_once(&cancel).await? {
                    return Ok(());
                }
                heartbeat.ok();
            }
        }
    }
}

pub async fn serve_reaper<R: CapacityMaintenanceRepository>(
    context: CapacityLeaseReaperContext<R>,
    cancel: CancellationToken,
    heartbeat: WorkerHeartbeat,
) -> Result<()> {
    let mut interval = tokio::time::interval(context.heartbeat_interval());
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _ = cancel.cancelled() => return Ok(()),
            _ = interval.tick() => {
                if !context.reap_once(&cancel).await? {
                    return Ok(());
                }
                heartbeat.ok();
            }
        }
    }
}

#[cfg(test)]
mod privacy_lease_tests;
#[cfg(test)]
pub(crate) mod tests;
