//! The operations context as the composition root builds it: the read models of the REST API, the
//! administrative services, reports, retention policy and the workers of the operation journal.

use super::*;

/// The operations context's services, built once at startup.
pub(super) struct OperationsModule {
    pub(super) api_query_context: ApiQueryContext,
    pub(super) metrics_snapshot_service: northstar_operations_application::metrics_snapshot::MetricsSnapshotService<
        northstar_workflows::metrics_snapshot_repository::PostgresMetricsSnapshotRepository,
    >,
    pub(super) readiness_service: northstar_operations_application::readiness::ReadinessService<
        db::readiness_repository::PostgresReadinessRepository,
    >,
    /// XEP-0050/XEP-0133 session and execution authority. Protocol handlers
    /// never receive the backing PostgreSQL pool through this capability.
    pub(super) admin_command_service: northstar_operations_application::admin_commands::AdminCommandService<
        northstar_workflows::admin_command_repository::WorkflowAdminCommandRepository,
    >,
    pub(super) report_service:
        northstar_operations_application::reports::ReportService<northstar_workflows::report_repository::PostgresReportRepository>,
    pub(super) operation_admin_service: OperationAdminContext,
    pub(super) operation_muc_destroy_service: Arc<
        northstar_operations_application::operation_muc_destroy::MucDestroyService<
            northstar_workflows::operation_muc_destroy_repository::PostgresMucDestroyRepository,
        >,
    >,
    pub(super) operation_effect_fence_service:
        northstar_operations_application::operation_effect_fence::OperationEffectFenceService<
            northstar_operations_postgres::operation_effect_fence_repository::PostgresOperationEffectFenceRepository,
        >,
    pub(super) operation_journal_worker_service:
        northstar_operations_application::operation_journal_worker::OperationJournalWorkerService<
            northstar_operations_postgres::operation_journal_worker_repository::PostgresOperationJournalWorkerRepository,
        >,
    pub(super) admin_session_cleanup_worker_service:
        northstar_operations_application::admin_session_cleanup_worker::AdminSessionCleanupWorkerService<
            northstar_operations_postgres::admin_session_cleanup_worker_repository::PostgresAdminSessionCleanupRepository,
        >,
    pub(super) admin_dispatch_service: AdminDispatchContext,
    pub(super) upload_admin_service: UploadAdminContext,
    pub(super) report_moderation_service: ReportModerationContext,
    pub(super) retention_policy_context: RetentionPolicyContext,
    pub(super) governance_context: GovernanceContext,
}

/// What the operations context's services are built from.
pub(super) struct OperationsModuleParts<'a> {
    pub(super) config: &'a Config,
    pub(super) pool: &'a PgPool,
    pub(super) command_pool: &'a PgPool,
    pub(super) abuse: &'a Arc<AbuseGuard>,
    pub(super) api_control: &'a Arc<northstar_operations_postgres::api_control::ApiControlKeyring>,
    pub(super) api_cursor: &'a Arc<crate::api::cursor::CursorKeyring>,
    pub(super) admin_mutations: &'a northstar_workflows::admin_mutations::AdminMutationStore,
    pub(super) cluster: &'a crate::cluster::ClusterManager,
    pub(super) metrics: &'a Arc<Metrics>,
    pub(super) registration_closed: &'a Arc<AtomicBool>,
    pub(super) federation_write_policy: &'a Arc<FederationWritePolicy>,
    pub(super) sessions: &'a Arc<DashMap<String, OnlineSession>>,
    pub(super) muc_occupants: &'a Arc<DashMap<String, MucOccupant>>,
    pub(super) started_at: Instant,
}

impl OperationsModule {
    /// Builds the services over the stores and policies the composition root owns.
    pub(super) fn new(parts: OperationsModuleParts<'_>) -> Self {
        let OperationsModuleParts {
            config,
            pool,
            command_pool,
            abuse,
            api_control,
            api_cursor,
            admin_mutations,
            cluster,
            metrics,
            registration_closed,
            federation_write_policy,
            sessions,
            muc_occupants,
            started_at,
        } = parts;
        let api_query_context = api_queries::ApiQueryContext::new(
            northstar_operations_application::api_queries::ApiQueryService::new(
                northstar_workflows::api_queries::PostgresApiQueryRepository::new(pool.clone()),
            ),
            Arc::clone(api_cursor),
            api_queries::ApiQueryRuntime {
                domain: config.domain.clone(),
                node_id: cluster.node_id.clone(),
                require_encrypted_archive: config.require_encrypted_archive,
                federation_configured: config.federation_enabled,
                configured_registration_mode: config.configured_registration_mode(),
                registration_dependency_locked: config.registration_dependency_locked(),
                registration_closed: Arc::clone(registration_closed),
                island_mode: federation_write_policy.island_flag(),
                presence: Arc::new(api_query_presence::LocalApiQueryPresence {
                    sessions: Arc::clone(sessions),
                    occupants: Arc::clone(muc_occupants),
                }),
                metrics: Arc::clone(metrics),
                started_at,
            },
        );
        let operation_admin_service =
            northstar_operations_application::operations::OperationAdminService::new(
                northstar_workflows::operation_admin_repository::PostgresOperationAdminRepository::new(
                    admin_mutations.clone(),
                ),
            );
        let operation_muc_destroy_service = Arc::new(
            northstar_operations_application::operation_muc_destroy::MucDestroyService::new(
                northstar_workflows::operation_muc_destroy_repository::PostgresMucDestroyRepository::new(
                    pool.clone(),
                ),
                config.domain.clone(),
            ),
        );
        let operation_effect_fence_service =
            northstar_operations_application::operation_effect_fence::OperationEffectFenceService::new(
                northstar_operations_postgres::operation_effect_fence_repository::PostgresOperationEffectFenceRepository::new(
                    pool.clone(),
                ),
            );
        let operation_journal_worker_service =
            northstar_operations_application::operation_journal_worker::OperationJournalWorkerService::new(
                northstar_operations_postgres::operation_journal_worker_repository::PostgresOperationJournalWorkerRepository::new(
                    pool.clone(),
                ),
            );
        let admin_session_cleanup_worker_service =
            northstar_operations_application::admin_session_cleanup_worker::AdminSessionCleanupWorkerService::new(
                northstar_operations_postgres::admin_session_cleanup_worker_repository::PostgresAdminSessionCleanupRepository::new(pool.clone()),
            );
        let admin_dispatch_service =
            northstar_operations_application::admin_dispatch::AdminDispatchService::new(
                northstar_workflows::admin_dispatch_repository::PostgresAdminDispatchRepository::new(
                    admin_mutations.clone(),
                    command_pool.clone(),
                    Arc::clone(api_control),
                    cluster.admission(),
                ),
                config.domain.clone(),
            );
        let upload_admin_service =
            northstar_operations_application::upload_admin::UploadAdminService::new(
                northstar_workflows::upload_admin_repository::PostgresUploadAdminRepository::new(
                    admin_mutations.clone(),
                ),
            );
        let report_moderation_service =
            northstar_operations_application::report_moderation::ReportModerationService::new(
                northstar_workflows::report_moderation_repository::PostgresReportModerationRepository::new(
                    admin_mutations.clone(),
                ),
            );
        let retention_policy_context = retention_policy::RetentionPolicyContext::new(
            northstar_operations_application::retention_policy::RetentionPolicyService::new(
                northstar_workflows::retention_policy_repository::PostgresRetentionPolicyRepository::new(
                    pool.clone(),
                    Arc::clone(api_control),
                ),
                northstar_operations_application::retention_policy::RetentionPolicyLimits {
                    personal_mam_days: config.mam_retention_days,
                    offline_message_days: config.offline_message_ttl_days,
                    moderation_evidence_days: config.moderation_retention_days,
                },
                config.muc_mam_retention_days,
            ),
            Arc::clone(metrics),
        );
        let governance_context = governance::GovernanceContext::new(
            northstar_operations_application::governance::GovernanceService::new(
                northstar_workflows::governance_repository::PostgresGovernanceRepository::new(
                    pool.clone(),
                    admin_mutations.clone(),
                    Arc::clone(api_control),
                    crate::api::governance_cursor::SignedGovernanceCursors::new(Arc::clone(
                        api_cursor,
                    )),
                ),
            ),
            Arc::clone(metrics),
        );
        let report_service = northstar_operations_application::reports::ReportService::new(
            northstar_workflows::report_repository::PostgresReportRepository::new(
                pool.clone(),
                Arc::clone(api_control),
                Arc::clone(abuse),
            ),
        );
        Self {
            api_query_context,
            metrics_snapshot_service:
                northstar_operations_application::metrics_snapshot::MetricsSnapshotService::new(
                    northstar_workflows::metrics_snapshot_repository::PostgresMetricsSnapshotRepository::new(
                        pool.clone(),
                    ),
                ),
            readiness_service: northstar_operations_application::readiness::ReadinessService::new(
                db::readiness_repository::PostgresReadinessRepository::new(pool.clone()),
            ),
            admin_command_service:
                northstar_operations_application::admin_commands::AdminCommandService::new(
                    northstar_workflows::admin_command_repository::WorkflowAdminCommandRepository::new(
                        pool.clone(),
                        command_pool.clone(),
                        northstar_workflows::roster::WorkflowRosterEffects,
                    ),
                ),
            report_service,
            operation_admin_service: crate::api::contexts::ServiceContext(operation_admin_service),
            operation_muc_destroy_service,
            operation_effect_fence_service,
            operation_journal_worker_service,
            admin_session_cleanup_worker_service,
            admin_dispatch_service: crate::api::contexts::ServiceContext(admin_dispatch_service),
            upload_admin_service: crate::api::contexts::ServiceContext(upload_admin_service),
            report_moderation_service: crate::api::contexts::ServiceContext(
                report_moderation_service,
            ),
            retention_policy_context,
            governance_context,
        }
    }
}
