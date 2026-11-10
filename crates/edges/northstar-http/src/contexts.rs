//! REST and private listener extractor contexts: query, governance, retention, report, HTTP entry,
//! upload, account teardown, readiness and metrics contexts, and the service bindings handlers
//! receive. The composition root builds them through
//! [`HttpHost`](crate::host::HttpHost) and implements the ports they hold.

use crate::repositories::HttpRepositories;
use std::sync::Arc;

pub mod account_teardown;
pub mod api_queries;
pub mod api_session_http;
pub mod governance;
pub mod http_body_admission;
pub mod http_challenge_endpoint;
pub mod http_login_endpoint;
pub mod http_policy;
pub mod http_registration_endpoint;
pub mod metrics;
pub mod omemo_poll;
pub mod omemo_recovery_http;
pub mod passkey_http;
pub mod passkey_login_finish;
pub mod password_change_http;
pub mod readiness;
pub mod reports;
pub mod retention_policy;
pub mod upload_admission;
pub mod upload_http_delete;
pub mod upload_http_read;
pub mod upload_http_write;

pub use self::http_login_endpoint::HttpLoginEndpointContext;
pub use self::http_policy::{AdminGatewayVerifier, HttpTransportPolicy, PublicDiscoveryContext};
pub use self::metrics::MetricsContext;
pub use self::passkey_login_finish::PasskeyLoginFinishContext;
pub use self::readiness::ReadinessContext;
pub use self::upload_http_read::{UploadHttpReadContext, UploadHttpReplayReadContext};

/// A service as an extractor context. The route states implement `FromRef` only for a type of this crate, and
/// the service of an extracted context is not one.
#[derive(Clone)]
pub struct ServiceContext<S>(pub S);

impl<S> std::ops::Deref for ServiceContext<S> {
    type Target = S;

    fn deref(&self) -> &S {
        &self.0
    }
}

pub type AccountAdminContext<R> = ServiceContext<
    northstar_auth_application::account_admin::AccountAdminService<
        <R as HttpRepositories>::AccountAdmin,
    >,
>;

pub type AdminDispatchContext<R> = ServiceContext<
    northstar_operations_application::admin_dispatch::AdminDispatchService<
        <R as HttpRepositories>::AdminDispatch,
    >,
>;

pub type InvitationAdminContext<R> = ServiceContext<
    northstar_auth_application::invitation_admin::InvitationAdminService<
        <R as HttpRepositories>::InvitationAdmin,
    >,
>;

pub type GovernanceContext<R> = governance::GovernanceContext<<R as HttpRepositories>::Governance>;

pub type RetentionPolicyContext<R> =
    retention_policy::RetentionPolicyContext<<R as HttpRepositories>::RetentionPolicy>;

pub type ReportModerationContext<R> = ServiceContext<
    northstar_operations_application::report_moderation::ReportModerationService<
        <R as HttpRepositories>::ReportModeration,
    >,
>;

pub type UploadAdminContext<R> = ServiceContext<
    northstar_operations_application::upload_admin::UploadAdminService<
        <R as HttpRepositories>::UploadAdmin,
    >,
>;

pub type OperationAdminContext<R> = ServiceContext<
    northstar_operations_application::operations::OperationAdminService<
        <R as HttpRepositories>::OperationAdmin,
    >,
>;

pub type ReportContext<R> =
    reports::ReportContext<<R as HttpRepositories>::Reports, <R as HttpRepositories>::ApiQueries>;

pub type ApiQueryContext<R> = api_queries::ApiQueryContext<<R as HttpRepositories>::ApiQueries>;

pub type OmemoRecoveryPollContext<R> =
    omemo_poll::OmemoRecoveryPollContext<<R as HttpRepositories>::OmemoRecoveryPoll>;

pub type PasskeyService<R> =
    northstar_auth_application::passkeys::PasskeyService<<R as HttpRepositories>::Passkeys>;
pub type UploadService<R> =
    northstar_upload_application::service::UploadService<<R as HttpRepositories>::Uploads>;

pub type RegistrationAdminContext<R> = ServiceContext<
    northstar_auth_application::account_admin::RegistrationAdminService<
        <R as HttpRepositories>::RegistrationAdmin,
        Arc<dyn northstar_auth_application::account_admin::RegistrationCache>,
    >,
>;

pub type SessionAdminContext<R> = ServiceContext<
    northstar_auth_application::account_admin::SessionAdminService<
        <R as HttpRepositories>::SessionAdmin,
        Arc<dyn northstar_auth_application::account_admin::AdminSessionLookup>,
    >,
>;
