//! REST extractor contexts: the query, governance, retention, report and HTTP entry contexts, and the
//! service bindings handlers receive. The composition root constructs them and implements FromRef.

pub(crate) mod api_queries;
pub(crate) mod governance;
pub(crate) mod http_body_admission;
pub(crate) mod http_policy;
pub(crate) mod reports;
pub(crate) mod retention_policy;

pub(crate) use self::http_policy::{
    AdminGatewayVerifier, HttpTransportPolicy, PublicDiscoveryContext,
};

pub(crate) type AccountAdminContext = crate::services::account_admin::AccountAdminService<
    crate::db::account_admin_repository::PostgresAccountAdminRepository,
>;

pub(crate) type AdminDispatchContext = crate::services::admin_dispatch::AdminDispatchService<
    crate::db::admin_dispatch_repository::PostgresAdminDispatchRepository,
>;

pub(crate) type InvitationAdminContext = crate::services::invitation_admin::InvitationAdminService<
    crate::db::invitation_admin_repository::PostgresInvitationAdminRepository,
>;

pub(crate) type GovernanceContext = governance::GovernanceContext<
    crate::db::governance_repository::PostgresGovernanceRepository<
        crate::api::governance_cursor::SignedGovernanceCursors,
    >,
>;

pub(crate) type RetentionPolicyContext = retention_policy::RetentionPolicyContext<
    crate::db::retention_policy_repository::PostgresRetentionPolicyRepository,
>;

pub(crate) type ReportModerationContext =
    crate::services::report_moderation::ReportModerationService<
        crate::db::report_moderation_repository::PostgresReportModerationRepository,
    >;

pub(crate) type UploadAdminContext = crate::services::upload_admin::UploadAdminService<
    crate::db::upload_admin_repository::PostgresUploadAdminRepository,
>;

pub(crate) type OperationAdminContext = crate::services::operations::OperationAdminService<
    crate::db::operation_admin_repository::PostgresOperationAdminRepository,
>;

pub(crate) type ReportContext = reports::ReportContext<
    crate::db::report_repository::PostgresReportRepository,
    crate::db::api_queries::PostgresApiQueryRepository,
>;

pub(crate) type ApiQueryContext =
    api_queries::ApiQueryContext<crate::db::api_queries::PostgresApiQueryRepository>;
