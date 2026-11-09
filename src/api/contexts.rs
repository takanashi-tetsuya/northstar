//! REST and private listener extractor contexts: query, governance, retention, report, HTTP entry,
//! upload, account teardown, readiness and metrics contexts, and the service bindings handlers
//! receive. The composition root constructs them, implements FromRef and the ports they hold.

use crate::api::postgres_repositories::PostgresHttpRepositories;
use crate::api::repositories::HttpRepositories;
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

pub(crate) type AccountAdminContext<R = PostgresHttpRepositories> = ServiceContext<
    northstar_auth_application::account_admin::AccountAdminService<
        <R as HttpRepositories>::AccountAdmin,
    >,
>;

pub(crate) type AdminDispatchContext<R = PostgresHttpRepositories> = ServiceContext<
    northstar_operations_application::admin_dispatch::AdminDispatchService<
        <R as HttpRepositories>::AdminDispatch,
    >,
>;

pub(crate) type InvitationAdminContext<R = PostgresHttpRepositories> = ServiceContext<
    northstar_auth_application::invitation_admin::InvitationAdminService<
        <R as HttpRepositories>::InvitationAdmin,
    >,
>;

pub(crate) type GovernanceContext<R = PostgresHttpRepositories> =
    governance::GovernanceContext<<R as HttpRepositories>::Governance>;

pub(crate) type RetentionPolicyContext<R = PostgresHttpRepositories> =
    retention_policy::RetentionPolicyContext<<R as HttpRepositories>::RetentionPolicy>;

pub(crate) type ReportModerationContext<R = PostgresHttpRepositories> = ServiceContext<
    northstar_operations_application::report_moderation::ReportModerationService<
        <R as HttpRepositories>::ReportModeration,
    >,
>;

pub(crate) type UploadAdminContext<R = PostgresHttpRepositories> = ServiceContext<
    northstar_operations_application::upload_admin::UploadAdminService<
        <R as HttpRepositories>::UploadAdmin,
    >,
>;

pub(crate) type OperationAdminContext<R = PostgresHttpRepositories> = ServiceContext<
    northstar_operations_application::operations::OperationAdminService<
        <R as HttpRepositories>::OperationAdmin,
    >,
>;

pub(crate) type ReportContext<R = PostgresHttpRepositories> =
    reports::ReportContext<<R as HttpRepositories>::Reports, <R as HttpRepositories>::ApiQueries>;

pub(crate) type ApiQueryContext<R = PostgresHttpRepositories> =
    api_queries::ApiQueryContext<<R as HttpRepositories>::ApiQueries>;

pub(crate) type OmemoRecoveryPollContext<R = PostgresHttpRepositories> =
    omemo_poll::OmemoRecoveryPollContext<<R as HttpRepositories>::OmemoRecoveryPoll>;

pub(crate) type PasskeyService<R = PostgresHttpRepositories> =
    northstar_auth_application::passkeys::PasskeyService<<R as HttpRepositories>::Passkeys>;
pub(crate) type UploadService<R = PostgresHttpRepositories> =
    northstar_upload_application::service::UploadService<<R as HttpRepositories>::Uploads>;

pub(crate) type RegistrationAdminContext<R = PostgresHttpRepositories> = ServiceContext<
    northstar_auth_application::account_admin::RegistrationAdminService<
        <R as HttpRepositories>::RegistrationAdmin,
        Arc<dyn northstar_auth_application::account_admin::RegistrationCache>,
    >,
>;

pub(crate) type SessionAdminContext<R = PostgresHttpRepositories> = ServiceContext<
    northstar_auth_application::account_admin::SessionAdminService<
        <R as HttpRepositories>::SessionAdmin,
        Arc<dyn northstar_auth_application::account_admin::AdminSessionLookup>,
    >,
>;
