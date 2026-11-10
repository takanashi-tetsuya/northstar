//! The repositories the REST contexts drive, named once. The composition root
//! chooses the adapters; the contexts and their handlers see only these
//! application traits.

use northstar_abuse_application::{
    challenge::ChallengeIssueRepository, login::PasskeyLoginAbuseRepository,
};
use northstar_auth_application::{
    account::AccountRepository,
    account_admin::{AccountAdminRepository, RegistrationAdminRepository, SessionAdminRepository},
    api_sessions::ApiSessionRepository,
    http_login::HttpLoginRepository,
    invitation_admin::InvitationAdminRepository,
    omemo_recovery::{OmemoRecoveryPollRepository, OmemoRecoveryRepository},
    passkeys::PasskeyRepository,
    password_change::PasswordChangeRepository,
};
use northstar_operations_application::{
    admin_dispatch::AdminDispatchRepository, api_queries::ApiQueryRepository,
    governance::GovernanceRepository, metrics_snapshot::MetricsSnapshotRepository,
    operations::OperationAdminRepository, readiness::ReadinessRepository,
    report_moderation::ReportModerationRepository, reports::ReportRepository,
    retention_policy::RetentionPolicyRepository, upload_admin::UploadAdminRepository,
};
use northstar_upload_application::{service::UploadLifecycleRepository, UploadRepository};

/// One repository per REST use case. A context is generic over an implementation
/// of this trait and reaches its repository as an associated type, so a handler
/// names one type parameter however many repositories its route touches.
pub trait HttpRepositories: Clone + Send + Sync + 'static {
    type Accounts: AccountRepository + Clone + 'static;
    type AccountAdmin: AccountAdminRepository + Clone + 'static;
    type AdminDispatch: AdminDispatchRepository + Clone + 'static;
    type ApiQueries: ApiQueryRepository + Clone + 'static;
    type ApiSessions: ApiSessionRepository + 'static;
    type Challenges: ChallengeIssueRepository + Clone + 'static;
    type Governance: GovernanceRepository + Clone + 'static;
    type HttpLogin: HttpLoginRepository + Clone + 'static;
    type InvitationAdmin: InvitationAdminRepository + Clone + 'static;
    type MetricsSnapshot: MetricsSnapshotRepository + Clone + 'static;
    type OmemoRecovery: OmemoRecoveryRepository + Clone + 'static;
    type OmemoRecoveryPoll: OmemoRecoveryPollRepository + Clone + 'static;
    type OperationAdmin: OperationAdminRepository + Clone + 'static;
    type PasskeyLogins: PasskeyLoginAbuseRepository + 'static;
    type Passkeys: PasskeyRepository + 'static;
    type PasswordChange: PasswordChangeRepository + Clone + 'static;
    type Readiness: ReadinessRepository + Clone + 'static;
    type RegistrationAdmin: RegistrationAdminRepository + Clone + 'static;
    type ReportModeration: ReportModerationRepository + Clone + 'static;
    type Reports: ReportRepository + Clone + 'static;
    type RetentionPolicy: RetentionPolicyRepository + Clone + 'static;
    type SessionAdmin: SessionAdminRepository + Clone + 'static;
    type UploadAdmin: UploadAdminRepository + Clone + 'static;
    type Uploads: UploadRepository<Error = anyhow::Error>
        + UploadLifecycleRepository
        + Clone
        + 'static;
}
