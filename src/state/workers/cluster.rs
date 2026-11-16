//! Cluster bus, authority, revocation and standalone MUC workers.

use super::super::{cluster_adapters::PostgresClusterAdapters, AppState};
use crate::cluster::{
    self, failure_supervisor_context::ClusterFailureSupervisorContext,
    maintenance_context::ClusterMaintenanceContext,
    standalone_muc_maintenance::StandaloneMucMaintenanceContext,
};
use northstar_runtime::workers::{WorkerCriticality, WorkerMode};
use northstar_stream::local_routes::session::AccountRevocationRoutes;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;

pub(super) fn start(state: &Arc<AppState>, cancel: &CancellationToken) {
    let worker_registry = &state.workers;
    if state.cluster.is_enabled() {
        let pubsub_transport = Arc::new(state.cluster.pubsub_listener_transport());
        let listener_admission = Arc::new(state.cluster.listener_admission());
        let state_pubsub = state.clone();
        let pubsub_cancel = cancel.clone();
        worker_registry.supervise(
            "redis-pubsub",
            WorkerCriticality::Restartable,
            WorkerMode::Continuous,
            Some(std::time::Duration::from_secs(45)),
            cancel.clone(),
            move |heartbeat| {
                cluster::run_pubsub_listener(
                    Arc::clone(&pubsub_transport),
                    Arc::clone(&listener_admission),
                    cluster_listener_runtime(&state_pubsub),
                    pubsub_cancel.clone(),
                    heartbeat,
                )
            },
        );

        let revocation_context = Arc::new(account_revocation_worker_context(state));
        let revocation_cancel = cancel.clone();
        worker_registry.supervise(
            "account-revocations",
            WorkerCriticality::Critical,
            WorkerMode::Continuous,
            Some(std::time::Duration::from_secs(10)),
            cancel.clone(),
            move |heartbeat| {
                cluster::run_account_revocations(
                    Arc::clone(&revocation_context),
                    revocation_cancel.clone(),
                    heartbeat,
                )
            },
        );

        let maintenance_context = Arc::new(cluster_maintenance_context(state));
        let maintenance_cancel = cancel.clone();
        worker_registry.supervise(
            "cluster-maintenance",
            WorkerCriticality::Restartable,
            WorkerMode::Continuous,
            Some(std::time::Duration::from_secs(90)),
            cancel.clone(),
            move |heartbeat| {
                let maintenance_context = Arc::clone(&maintenance_context);
                let maintenance_cancel = maintenance_cancel.clone();
                async move {
                    cluster::run_maintenance(maintenance_context, maintenance_cancel, heartbeat)
                        .await
                }
            },
        );

        let state_policy = Arc::new(cluster_failure_supervisor_context(state));
        let policy_cancel = cancel.clone();
        worker_registry.supervise(
            "cluster-failure-policy",
            WorkerCriticality::Critical,
            WorkerMode::Continuous,
            Some(std::time::Duration::from_secs(15)),
            cancel.clone(),
            move |heartbeat| {
                cluster::run_failure_supervisor(
                    Arc::clone(&state_policy),
                    policy_cancel.clone(),
                    heartbeat,
                )
            },
        );
    } else if state.cluster.muc_pg_authority_enabled() {
        let maintenance_context = Arc::new(standalone_muc_maintenance_context(state));
        let maintenance_cancel = cancel.clone();
        worker_registry.supervise(
            "standalone-muc-occupancy",
            WorkerCriticality::Restartable,
            WorkerMode::Continuous,
            Some(std::time::Duration::from_secs(45)),
            cancel.clone(),
            move |heartbeat| {
                let maintenance_context = Arc::clone(&maintenance_context);
                let maintenance_cancel = maintenance_cancel.clone();
                async move {
                    cluster::standalone_muc_maintenance::run(
                        maintenance_context,
                        maintenance_cancel,
                        heartbeat,
                    )
                    .await
                }
            },
        );
    }
}

fn account_revocation_worker_context(
    state: &AppState,
) -> crate::cluster::AccountRevocationWorkerContext<
    northstar_auth_postgres::account_revocation_repository::PostgresAccountRevocationRepository,
> {
    crate::cluster::AccountRevocationWorkerContext::new(
        state.auth.account_revocation_consumer_service.clone(),
        AccountRevocationRoutes::new(Arc::clone(&state.sessions)),
        state.cluster.account_revocation_authority(),
    )
}

fn cluster_listener_runtime(
    state: &AppState,
) -> crate::cluster::ClusterListenerRuntime<PostgresClusterAdapters> {
    crate::cluster::ClusterListenerRuntime {
        message_policy: Arc::new(state.cluster_listener_message_policy()),
        dispatch: state.cluster_listener_dispatch(),
        muc_endpoints: state.cluster_muc_delivery_endpoints(),
        muc_delivery: state.muc_delivery_context(),
        mix_caps: state.cluster_listener_mix_caps(),
        blocking: state.cluster_listener_blocking(),
        sm_muc_teardown: state.cluster_listener_sm_muc_teardown(),
        presence_sender: Arc::new(state.cluster.node_delivery()),
        security: Arc::new(state.cluster.listener_security()),
    }
}

fn standalone_muc_maintenance_context(
    state: &AppState,
) -> StandaloneMucMaintenanceContext<
    northstar_room_postgres::room::PostgresClusterMucOccupancyMaintenanceRepository,
> {
    StandaloneMucMaintenanceContext::new(
        state.cluster.muc_cluster_node_id().to_owned(),
        northstar_xmpp_types::jid::prepare_domainpart(&format!(
            "conference.{}",
            state.config.domain
        ))
        .expect("configured XMPP domain must form a valid MUC domain"),
        state.cluster_maintenance_locals(),
        state
            .room
            .cluster_muc_occupancy_maintenance_service()
            .clone(),
    )
}

fn cluster_maintenance_context(
    state: &AppState,
) -> ClusterMaintenanceContext<PostgresClusterAdapters> {
    let (control, redis) = state.cluster_maintenance_handles();
    let replay_wake = state.cluster_recovery_replay_wake();
    ClusterMaintenanceContext {
        control,
        session_routes:
            northstar_session_application::session_route_maintenance::SessionRouteRenewalService::new(redis.clone()),
        redis,
        locals: state.cluster_maintenance_locals(),
        direct_spool_wake: state.direct_spool_wake_consumer(replay_wake.clone()),
        replay_wake,
        session_authority: northstar_session_application::session_authority_sweep::SessionAuthoritySweepService::new(
            northstar_workflows::session_authority_sweep_repository::PostgresSessionAuthoritySweepRepository::new(
                state.pool.clone(),
            ),
        ),
        cluster_authority: state.session.cluster_authority_service().clone(),
        muc_occupancy: state.room.cluster_muc_occupancy_maintenance_service().clone(),
    }
}

fn cluster_failure_supervisor_context(
    state: &AppState,
) -> ClusterFailureSupervisorContext<PostgresClusterAdapters> {
    ClusterFailureSupervisorContext {
        authority: state.cluster.failure_supervisor_authority(),
        authority_service: northstar_session_application::cluster_authority::ClusterAuthorityService::new(
            northstar_session_postgres::cluster_authority_repository::PostgresClusterAuthorityRepository::new(
                state.pool.clone(),
            ),
        ),
        replay_maintenance:
            northstar_session_application::cluster_replay_maintenance::ClusterReplayMaintenanceService::new(
                northstar_session_postgres::cluster_replay_maintenance_repository::PostgresClusterReplayMaintenanceRepository::new(
                    state.pool.clone(),
                ),
            ),
        route_maintenance: northstar_session_application::cluster_session_route_maintenance::ClusterSessionRouteMaintenanceService::new(
            northstar_session_postgres::cluster_session_route_maintenance_repository::PostgresClusterSessionRouteMaintenanceRepository::new(
                state.pool.clone(),
            ),
        ),
    }
}
