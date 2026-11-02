//! The session context as the composition root builds it: stream management, offline replay, the SM
//! memory governor and the supervised SM suspension recovery queue.

use super::*;

/// The session context's services, built once at startup.
pub(super) struct SessionModule {
    pub(super) sm_service: northstar_session_application::sm::SmService<
        northstar_workflows::sm_repository::PostgresSmRepository,
    >,
    pub(super) replay_service: northstar_session_application::replay::ReplayService<
        northstar_session_postgres::replay_repository::PostgresReplayRepository,
    >,
    /// Supervised retry ownership for an exact SM suspension whose database
    /// outcome was an error or timeout. The corresponding MUC FIFO remains
    /// sealed until this queue proves a durable handoff.
    pub(super) sm_suspension_recovery:
        Arc<crate::state::session_cleanup::SmSuspensionRecoveryQueue>,
    pub(super) sm_memory_governor:
        Arc<northstar_session_application::sm_capacity::SmMemoryGovernor>,
}

/// What the session context is built from.
pub(super) struct SessionModuleParts<'a> {
    pub(super) config: &'a Config,
    pub(super) pool: &'a PgPool,
    pub(super) fast_token_secret: &'a Arc<Zeroizing<Vec<u8>>>,
    pub(super) sm_authority_schema: String,
}

impl SessionModule {
    /// Builds the services over the primary pool, with one capacity metrics sink shared by the
    /// memory governor and the recovery queue.
    pub(super) fn new(parts: SessionModuleParts<'_>) -> anyhow::Result<Self> {
        let SessionModuleParts {
            config,
            pool,
            fast_token_secret,
            sm_authority_schema,
        } = parts;
        let sm_capacity_metrics =
            Arc::new(northstar_session_application::sm_capacity::SmCapacityMetrics::default());
        let sm_memory_governor = northstar_session_application::sm_capacity::SmMemoryGovernor::new(
            config.sm_memory_budget_bytes,
            config.sm_recovery_max_bytes,
            config.sm_recovery_max_jobs,
            config.sm_max_snapshot_bytes,
            Arc::clone(&sm_capacity_metrics),
        )?;
        Ok(Self {
            sm_service: northstar_session_application::sm::SmService::new(
                northstar_workflows::sm_repository::PostgresSmRepository::new(
                    pool.clone(),
                    Arc::clone(fast_token_secret),
                ),
                sm_authority_schema,
            )?,
            replay_service: northstar_session_application::replay::ReplayService::new(
                northstar_session_postgres::replay_repository::PostgresReplayRepository::new(
                    pool.clone(),
                ),
                &config.domain,
                config.offline_message_ttl_days,
            ),
            sm_suspension_recovery: crate::state::session_cleanup::SmSuspensionRecoveryQueue::new(
                config.sm_recovery_max_jobs,
                config.sm_recovery_max_bytes,
                sm_capacity_metrics,
                Arc::clone(&sm_memory_governor),
            ),
            sm_memory_governor,
        })
    }
}
