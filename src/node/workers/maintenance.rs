//! Construction, cleanup delegation and registration for maintenance workers.

use crate::node::{adapters::sm_expiry::SmExpiryContext, ServerNode};
use northstar_abuse_application::challenge::ChallengeCleanupService;
use northstar_abuse_postgres::challenge::PostgresChallengeRepository;
use northstar_operations_application::admin_commands::AdminCommandService;
use northstar_operations_application::background_housekeeping::{
    BackgroundHousekeepingContext, BackgroundHousekeepingCounters,
};
use northstar_operations_application::maintenance_worker::{
    serve_background_maintenance, BackgroundMaintenancePorts,
};
use northstar_runtime::workers::{WorkerCriticality, WorkerMode};
use northstar_workflows::admin_command_repository::WorkflowAdminCommandRepository;
use northstar_workflows::background_housekeeping_repository::PostgresBackgroundHousekeepingRepository;
use std::{sync::Arc, time::Duration};
use tokio_util::sync::CancellationToken;

struct BackgroundMaintenanceContext {
    challenge: ChallengeCleanupService<PostgresChallengeRepository>,
    database: BackgroundHousekeepingContext<PostgresBackgroundHousekeepingRepository>,
    admin: AdminCommandService<WorkflowAdminCommandRepository>,
    sm_expiry: SmExpiryContext,
    caps_cache: Arc<northstar_protocol_runtime::caps::CapsCacheIndex>,
    counters: BackgroundHousekeepingCounters,
}

fn background_maintenance_context(state: &ServerNode) -> BackgroundMaintenanceContext {
    let counters = background_housekeeping_counters(state);
    BackgroundMaintenanceContext {
        challenge: state.abuse.challenge_cleanup_service.clone(),
        database: background_housekeeping_context(state, counters.clone()),
        admin: state.operations.admin_command_service.clone(),
        sm_expiry: state.sm_expiry_context(),
        caps_cache: Arc::clone(state.session.live().caps_cache()),
        counters,
    }
}

impl BackgroundMaintenancePorts for BackgroundMaintenanceContext {
    async fn cleanup_challenges(&self) -> anyhow::Result<()> {
        self.challenge.cleanup().await
    }

    async fn sweep_database(&self) {
        self.database.sweep_database().await;
    }

    async fn cleanup_admin_sessions(&self) -> anyhow::Result<u64> {
        self.admin.cleanup_sessions().await
    }

    async fn cleanup_expired_sm(&self) -> anyhow::Result<usize> {
        self.sm_expiry.cleanup().await
    }

    fn sweep_caps_cache(&self, now: std::time::Instant) {
        self.caps_cache.sweep(now);
    }

    fn maintenance_counters(&self) -> &BackgroundHousekeepingCounters {
        &self.counters
    }
}

pub(super) fn start_background(state: &Arc<ServerNode>, cancel: &CancellationToken) {
    let worker_registry = state.runtime.workers();
    let bg_context = Arc::new(background_maintenance_context(state));
    let bg_cancel = cancel.clone();
    worker_registry.supervise(
        "background-maintenance",
        WorkerCriticality::Restartable,
        WorkerMode::Continuous,
        Some(std::time::Duration::from_secs(180)),
        cancel.clone(),
        move |heartbeat| {
            let bg_context = Arc::clone(&bg_context);
            let bg_cancel = bg_cancel.clone();
            async move { serve_background_maintenance(bg_context, bg_cancel, heartbeat).await }
        },
    );
}

pub(super) fn start_account_deletion_recovery(state: &Arc<ServerNode>, cancel: &CancellationToken) {
    let worker_registry = state.runtime.workers();
    let deletion_context = Arc::new(state.account_deletion_recovery_context());
    let deletion_cancel = cancel.clone();
    worker_registry.supervise(
        "account-deletion-recovery",
        WorkerCriticality::Restartable,
        WorkerMode::Continuous,
        // One SM teardown/storage reconciliation can legitimately consume most
        // of the 900-second recovery lease. Do not abort a healthy attempt.
        Some(std::time::Duration::from_secs(1_200)),
        cancel.clone(),
        move |heartbeat| {
            northstar_auth_xmpp::account_deletion::serve(
                Arc::clone(&deletion_context),
                deletion_cancel.clone(),
                heartbeat,
            )
        },
    );
}

pub(super) fn start_retention(
    state: &Arc<ServerNode>,
    cancel: &CancellationToken,
    process_role: crate::runtime::subservers::ProcessRole,
) {
    let worker_registry = state.runtime.workers();
    if process_role.embeds_retention() {
        let retention_context = Arc::new(retention_context(state));
        let retention_cancel = cancel.clone();
        let retention_max_silence = retention_worker_max_silence(state);
        worker_registry.supervise(
            "archive-retention",
            WorkerCriticality::Restartable,
            WorkerMode::Continuous,
            Some(retention_max_silence),
            cancel.clone(),
            move |heartbeat| {
                let context = Arc::clone(&retention_context);
                let retention_cancel = retention_cancel.clone();
                async move {
                    northstar_operations_application::retention_worker::serve_context(
                        context,
                        retention_cancel,
                        heartbeat,
                    )
                    .await
                }
            },
        );
        let subscriptions = Arc::new(subscription_cleanup_context(state));
        let subscription_cancel = cancel.clone();
        worker_registry.supervise(
            "pubsub-subscription-cleanup",
            WorkerCriticality::Restartable,
            WorkerMode::Continuous,
            Some(northstar_pubsub_application::subscription_cleanup::MAX_SILENCE),
            cancel.clone(),
            move |heartbeat| {
                northstar_pubsub_application::subscription_cleanup::serve_context(
                    Arc::clone(&subscriptions),
                    subscription_cancel.clone(),
                    heartbeat,
                )
            },
        );
    }
}

fn background_housekeeping_counters(
    state: &ServerNode,
) -> northstar_operations_application::background_housekeeping::BackgroundHousekeepingCounters {
    northstar_operations_application::background_housekeeping::BackgroundHousekeepingCounters::new(
        Arc::clone(&state.metrics.retention_moderation_cases_deleted_total),
        Arc::clone(&state.metrics.background_maintenance_failures_total),
    )
}

fn background_housekeeping_context(
    state: &ServerNode,
    counters: northstar_operations_application::background_housekeeping::BackgroundHousekeepingCounters,
) -> northstar_operations_application::background_housekeeping::BackgroundHousekeepingContext<
    northstar_workflows::background_housekeeping_repository::PostgresBackgroundHousekeepingRepository,
>{
    northstar_operations_application::background_housekeeping::BackgroundHousekeepingContext::new(
        northstar_workflows::background_housekeeping_repository::PostgresBackgroundHousekeepingRepository::new(
            state.pool.clone(),
        ),
        state.config.moderation_retention_days,
        state.config.retention_cleanup_batch_size,
        counters,
    )
}

fn retention_context(
    state: &ServerNode,
) -> northstar_operations_application::retention_worker::RetentionContext<
    northstar_workflows::maintenance_repository::PostgresMaintenanceRepository,
> {
    northstar_operations_application::retention_worker::RetentionContext::new(
        northstar_workflows::maintenance_repository::PostgresMaintenanceRepository::new(
            state.pool.clone(),
        ),
        northstar_operations_application::retention_worker::RetentionPolicy::from_config(
            &state.config,
        ),
        northstar_operations_application::retention_worker::RetentionCounters::from_metrics(
            &state.metrics,
        ),
    )
}

fn retention_worker_max_silence(state: &ServerNode) -> Duration {
    northstar_config::maintenance::RetentionPolicy::from_config(&state.config).max_silence()
}

fn subscription_cleanup_context(
    state: &ServerNode,
) -> northstar_pubsub_application::subscription_cleanup::SubscriptionCleanupContext<
    northstar_pubsub_postgres::subscription_cleanup::PostgresSubscriptionCleanupRepository,
> {
    northstar_pubsub_application::subscription_cleanup::SubscriptionCleanupContext::new(
        northstar_pubsub_postgres::subscription_cleanup::PostgresSubscriptionCleanupRepository::new(
            state.pool.clone(),
        ),
        Arc::clone(&state.metrics.subscription_cleanup),
    )
}
