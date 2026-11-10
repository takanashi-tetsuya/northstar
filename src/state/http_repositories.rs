//! The PostgreSQL adapters behind the REST contexts.

use northstar_http::repositories::HttpRepositories;

/// Selects the PostgreSQL repository of every REST use case.
#[derive(Clone, Copy)]
pub struct PostgresHttpRepositories;

impl HttpRepositories for PostgresHttpRepositories {
    type Accounts = northstar_workflows::account_repository::WorkflowAccountRepository;
    type AccountAdmin =
        northstar_workflows::account_admin_repository::PostgresAccountAdminRepository;
    type AdminDispatch =
        northstar_workflows::admin_dispatch_repository::PostgresAdminDispatchRepository;
    type ApiQueries = northstar_workflows::api_queries::PostgresApiQueryRepository;
    type ApiSessions =
        northstar_auth_postgres::api_session_repository::PostgresApiSessionRepository;
    type Challenges = northstar_abuse_postgres::challenge::PostgresChallengeRepository;
    type Governance = northstar_workflows::governance_repository::PostgresGovernanceRepository<
        northstar_http::governance_cursor::SignedGovernanceCursors,
    >;
    type HttpLogin = northstar_workflows::http_login_repository::PostgresHttpLoginRepository;
    type InvitationAdmin =
        northstar_workflows::invitation_admin_repository::PostgresInvitationAdminRepository;
    type MetricsSnapshot =
        northstar_workflows::metrics_snapshot_repository::PostgresMetricsSnapshotRepository;
    type OmemoRecovery =
        northstar_auth_postgres::omemo_recovery_repository::PostgresOmemoRecoveryRepository;
    type OmemoRecoveryPoll =
        northstar_auth_postgres::omemo_recovery_repository::PostgresOmemoRecoveryPollRepository;
    type OperationAdmin =
        northstar_workflows::operation_admin_repository::PostgresOperationAdminRepository;
    type PasskeyLogins = northstar_abuse_postgres::login::PostgresPasskeyLoginAbuseRepository;
    type Passkeys = northstar_auth_postgres::passkeys::PostgresPasskeyRepository;
    type PasswordChange =
        northstar_workflows::password_change_repository::PostgresPasswordChangeRepository;
    type Readiness = northstar_workflows::readiness_repository::PostgresReadinessRepository;
    type RegistrationAdmin =
        northstar_workflows::account_admin_repository::PostgresRegistrationAdminRepository;
    type ReportModeration =
        northstar_workflows::report_moderation_repository::PostgresReportModerationRepository;
    type Reports = northstar_workflows::report_repository::PostgresReportRepository;
    type RetentionPolicy =
        northstar_workflows::retention_policy_repository::PostgresRetentionPolicyRepository;
    type SessionAdmin =
        northstar_workflows::account_admin_repository::PostgresSessionAdminRepository;
    type UploadAdmin = northstar_workflows::upload_admin_repository::PostgresUploadAdminRepository;
    type Uploads = northstar_upload_postgres::PostgresUploadRepository;
}
