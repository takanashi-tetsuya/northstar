//! The REST contexts the node holds: each over the PostgreSQL repositories
//! [`PostgresHttpRepositories`] selects.

use super::http_repositories::PostgresHttpRepositories;

pub(crate) type AccountAdminContext =
    northstar_http::contexts::AccountAdminContext<PostgresHttpRepositories>;
pub(crate) type AdminDispatchContext =
    northstar_http::contexts::AdminDispatchContext<PostgresHttpRepositories>;
pub(crate) type ApiQueryContext =
    northstar_http::contexts::ApiQueryContext<PostgresHttpRepositories>;
pub(crate) type ApiSessionHttpContext =
    northstar_http::contexts::api_session_http::ApiSessionHttpContext<PostgresHttpRepositories>;
pub(crate) type GovernanceContext =
    northstar_http::contexts::GovernanceContext<PostgresHttpRepositories>;
pub(crate) type HttpChallengeEndpointContext =
    northstar_http::contexts::http_challenge_endpoint::HttpChallengeEndpointContext<
        PostgresHttpRepositories,
    >;
pub(crate) type HttpLoginEndpointContext =
    northstar_http::contexts::http_login_endpoint::HttpLoginEndpointContext<
        PostgresHttpRepositories,
    >;
pub(crate) type HttpRegistrationEndpointContext =
    northstar_http::contexts::http_registration_endpoint::HttpRegistrationEndpointContext<
        PostgresHttpRepositories,
    >;
pub(crate) type InvitationAdminContext =
    northstar_http::contexts::InvitationAdminContext<PostgresHttpRepositories>;
pub(crate) type MetricsContext =
    northstar_http::contexts::metrics::MetricsContext<PostgresHttpRepositories>;
pub(crate) type OmemoRecoveryHttpContext =
    northstar_http::contexts::omemo_recovery_http::OmemoRecoveryHttpContext<
        PostgresHttpRepositories,
    >;
pub(crate) type OmemoRecoveryPollContext =
    northstar_http::contexts::OmemoRecoveryPollContext<PostgresHttpRepositories>;
pub(crate) type OperationAdminContext =
    northstar_http::contexts::OperationAdminContext<PostgresHttpRepositories>;
pub(crate) type PasskeyAccountHttpContext =
    northstar_http::contexts::passkey_http::PasskeyAccountHttpContext<PostgresHttpRepositories>;
pub(crate) type PasskeyLoginFinishContext =
    northstar_http::contexts::passkey_login_finish::PasskeyLoginFinishContext<
        PostgresHttpRepositories,
    >;
pub(crate) type PasskeyService = northstar_http::contexts::PasskeyService<PostgresHttpRepositories>;
pub(crate) type PasskeyStartHttpContext =
    northstar_http::contexts::passkey_http::PasskeyStartHttpContext<PostgresHttpRepositories>;
pub(crate) type PasswordChangeHttpContext =
    northstar_http::contexts::password_change_http::PasswordChangeHttpContext<
        PostgresHttpRepositories,
    >;
pub(crate) type ReadinessContext =
    northstar_http::contexts::readiness::ReadinessContext<PostgresHttpRepositories>;
pub(crate) type RegistrationAdminContext =
    northstar_http::contexts::RegistrationAdminContext<PostgresHttpRepositories>;
pub(crate) type ReportContext = northstar_http::contexts::ReportContext<PostgresHttpRepositories>;
pub(crate) type ReportModerationContext =
    northstar_http::contexts::ReportModerationContext<PostgresHttpRepositories>;
pub(crate) type RetentionPolicyContext =
    northstar_http::contexts::RetentionPolicyContext<PostgresHttpRepositories>;
pub(crate) type SessionAdminContext =
    northstar_http::contexts::SessionAdminContext<PostgresHttpRepositories>;
pub(crate) type UploadAdminContext =
    northstar_http::contexts::UploadAdminContext<PostgresHttpRepositories>;
pub(crate) type UploadHttpDeleteContext =
    northstar_http::contexts::upload_http_delete::UploadHttpDeleteContext<PostgresHttpRepositories>;
pub(crate) type UploadHttpReadContext =
    northstar_http::contexts::upload_http_read::UploadHttpReadContext<PostgresHttpRepositories>;
pub(crate) type UploadHttpWriteContext =
    northstar_http::contexts::upload_http_write::UploadHttpWriteContext<PostgresHttpRepositories>;
pub(crate) type UploadService = northstar_http::contexts::UploadService<PostgresHttpRepositories>;
