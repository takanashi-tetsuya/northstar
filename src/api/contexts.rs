//! REST and private listener extractor contexts: query, governance, retention, report, HTTP entry,
//! upload, account teardown, readiness and metrics contexts, and the service bindings handlers
//! receive. The composition root constructs them, implements FromRef and the ports they hold.

use std::sync::Arc;

pub(crate) mod account_teardown;
pub(crate) mod api_queries;
pub(crate) mod api_session_http;
pub(crate) mod governance;
pub(crate) mod http_body_admission;
pub(crate) mod http_challenge_endpoint;
pub(crate) mod http_login_endpoint;
pub(crate) mod http_policy;
pub(crate) mod http_registration_endpoint;
pub(crate) mod metrics;
pub(crate) mod omemo_poll;
pub(crate) mod omemo_recovery_http;
pub(crate) mod passkey_http;
pub(crate) mod passkey_login_finish;
pub(crate) mod password_change_http;
pub(crate) mod readiness;
pub(crate) mod reports;
pub(crate) mod retention_policy;
pub(crate) mod upload_admission;
pub(crate) mod upload_http_delete;
pub(crate) mod upload_http_read;
pub(crate) mod upload_http_write;

pub(crate) use self::http_login_endpoint::HttpLoginEndpointContext;
pub(crate) use self::http_policy::{
    AdminGatewayVerifier, HttpTransportPolicy, PublicDiscoveryContext,
};
pub(crate) use self::metrics::MetricsContext;
pub(crate) use self::passkey_login_finish::PasskeyLoginFinishContext;
pub(crate) use self::readiness::ReadinessContext;
pub(crate) use self::upload_http_read::{UploadHttpReadContext, UploadHttpReplayReadContext};

/// A service as an extractor context. `FromRef<Arc<AppState>>` can be implemented only for a type of
/// this crate, and the service of an extracted context is not one.
#[derive(Clone)]
pub(crate) struct ServiceContext<S>(pub(crate) S);

impl<S> std::ops::Deref for ServiceContext<S> {
    type Target = S;

    fn deref(&self) -> &S {
        &self.0
    }
}

pub(crate) type AccountAdminContext = ServiceContext<
    northstar_auth_application::account_admin::AccountAdminService<
        northstar_workflows::account_admin_repository::PostgresAccountAdminRepository,
    >,
>;

pub(crate) type AdminDispatchContext = ServiceContext<
    northstar_operations_application::admin_dispatch::AdminDispatchService<
        northstar_workflows::admin_dispatch_repository::PostgresAdminDispatchRepository,
    >,
>;

pub(crate) type InvitationAdminContext = ServiceContext<
    northstar_auth_application::invitation_admin::InvitationAdminService<
        northstar_workflows::invitation_admin_repository::PostgresInvitationAdminRepository,
    >,
>;

pub(crate) type GovernanceContext = governance::GovernanceContext<
    northstar_workflows::governance_repository::PostgresGovernanceRepository<
        crate::api::governance_cursor::SignedGovernanceCursors,
    >,
>;

pub(crate) type RetentionPolicyContext = retention_policy::RetentionPolicyContext<
    northstar_workflows::retention_policy_repository::PostgresRetentionPolicyRepository,
>;

pub(crate) type ReportModerationContext = ServiceContext<
    northstar_operations_application::report_moderation::ReportModerationService<
        northstar_workflows::report_moderation_repository::PostgresReportModerationRepository,
    >,
>;

pub(crate) type UploadAdminContext = ServiceContext<
    northstar_operations_application::upload_admin::UploadAdminService<
        northstar_workflows::upload_admin_repository::PostgresUploadAdminRepository,
    >,
>;

pub(crate) type OperationAdminContext = ServiceContext<
    northstar_operations_application::operations::OperationAdminService<
        northstar_workflows::operation_admin_repository::PostgresOperationAdminRepository,
    >,
>;

pub(crate) type ReportContext = reports::ReportContext<
    northstar_workflows::report_repository::PostgresReportRepository,
    northstar_workflows::api_queries::PostgresApiQueryRepository,
>;

pub(crate) type ApiQueryContext =
    api_queries::ApiQueryContext<northstar_workflows::api_queries::PostgresApiQueryRepository>;

pub(crate) type OmemoRecoveryPollContext = omemo_poll::OmemoRecoveryPollContext<
    northstar_auth_postgres::omemo_recovery_repository::PostgresOmemoRecoveryPollRepository,
>;

pub(crate) type PasskeyService = northstar_auth_application::passkeys::PasskeyService<
    northstar_auth_postgres::passkeys::PostgresPasskeyRepository,
>;
pub(crate) type UploadService = northstar_upload_application::service::UploadService<
    northstar_upload_postgres::PostgresUploadRepository,
>;

pub(crate) type RegistrationAdminContext = ServiceContext<
    northstar_auth_application::account_admin::RegistrationAdminService<
        northstar_workflows::account_admin_repository::PostgresRegistrationAdminRepository,
        Arc<dyn northstar_auth_application::account_admin::RegistrationCache>,
    >,
>;

pub(crate) type SessionAdminContext = ServiceContext<
    northstar_auth_application::account_admin::SessionAdminService<
        northstar_workflows::account_admin_repository::PostgresSessionAdminRepository,
        Arc<dyn northstar_auth_application::account_admin::AdminSessionLookup>,
    >,
>;
