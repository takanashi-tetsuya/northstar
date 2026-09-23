//! Ordered once-per-minute maintenance with only its cleanup capabilities.

use super::{sm_expiry::SmExpiryContext, AppState};
use crate::{
    db::{
        admin_command_repository::PostgresAdminCommandRepository,
        background_housekeeping_repository::PostgresBackgroundHousekeepingRepository,
        challenge_issuance_repository::PostgresChallengeRepository,
    },
    services::{
        admin_commands::AdminCommandService,
        background_housekeeping::{BackgroundHousekeepingContext, BackgroundHousekeepingCounters},
        challenge_issuance::ChallengeCleanupService,
    },
    workers::WorkerHeartbeat,
};
use std::{sync::Arc, time::Duration};
use tokio_util::sync::CancellationToken;

pub(crate) struct BackgroundMaintenanceContext {
    challenge: ChallengeCleanupService<PostgresChallengeRepository>,
    database: BackgroundHousekeepingContext<PostgresBackgroundHousekeepingRepository>,
    admin: AdminCommandService<PostgresAdminCommandRepository>,
    sm_expiry: SmExpiryContext,
    caps_cache: Arc<northstar_protocol_runtime::caps::CapsCacheIndex>,
    counters: BackgroundHousekeepingCounters,
}

impl AppState {
    pub(crate) fn background_maintenance_context(&self) -> BackgroundMaintenanceContext {
        let counters = self.background_housekeeping_counters();
        BackgroundMaintenanceContext {
            challenge: self.challenge_cleanup_service.clone(),
            database: self.background_housekeeping_context(counters.clone()),
            admin: self.admin_command_service.clone(),
            sm_expiry: self.sm_expiry_context(),
            caps_cache: Arc::clone(&self.caps_cache),
            counters,
        }
    }
}

pub(crate) async fn serve(
    context: Arc<BackgroundMaintenanceContext>,
    cancel: CancellationToken,
    heartbeat: WorkerHeartbeat,
) -> anyhow::Result<()> {
    let mut interval = tokio::time::interval(Duration::from_secs(60));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            _ = cancel.cancelled() => return Ok(()),
            _ = interval.tick() => {
                let failures_before = context.counters.failures_total();
                if let Err(error) = context.challenge.cleanup().await {
                    tracing::warn!(?error, "anti-abuse cleanup failed");
                    context.counters.record_failure();
                }
                context.database.sweep_database().await;
                if let Err(error) = context.admin.cleanup_sessions().await {
                    tracing::error!("failed to cleanup expired admin command sessions: {error}");
                    context.counters.record_failure();
                }
                match context.sm_expiry.cleanup().await {
                    Ok(expired) if expired > 0 => {
                        tracing::info!(expired, "tore down expired SM resume sessions");
                    }
                    Ok(_) => {}
                    Err(error) => {
                        tracing::error!("failed to cleanup expired SM resume sessions: {error}");
                        context.counters.record_failure();
                    }
                }
                context.caps_cache.sweep(std::time::Instant::now());
                if context.counters.failures_total() == failures_before {
                    heartbeat.ok();
                } else {
                    heartbeat.error("one or more background maintenance operations failed");
                }
            }
        }
    }
}
