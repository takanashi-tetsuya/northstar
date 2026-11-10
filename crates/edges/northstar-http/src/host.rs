//! What the HTTP listeners need from the node: their bind addresses and entry policies, and one
//! context per route family. A route family asks for its context only when the router composes it.

use crate::contexts::{
    account_teardown::{AccountGenerationTeardownContext, AccountTeardownContext},
    api_session_http::ApiSessionHttpContext,
    http_challenge_endpoint::HttpChallengeEndpointContext,
    http_registration_endpoint::HttpRegistrationEndpointContext,
    omemo_recovery_http::OmemoRecoveryHttpContext,
    passkey_http::{PasskeyAccountHttpContext, PasskeyStartHttpContext},
    password_change_http::PasswordChangeHttpContext,
    upload_http_delete::UploadHttpDeleteContext,
    upload_http_write::UploadHttpWriteContext,
    AccountAdminContext, AdminDispatchContext, AdminGatewayVerifier, ApiQueryContext,
    GovernanceContext, HttpLoginEndpointContext, HttpTransportPolicy, InvitationAdminContext,
    OmemoRecoveryPollContext, OperationAdminContext, PasskeyLoginFinishContext,
    PublicDiscoveryContext, ReadinessContext, RegistrationAdminContext, ReportContext,
    ReportModerationContext, RetentionPolicyContext, SessionAdminContext, UploadAdminContext,
    UploadHttpReadContext, UploadHttpReplayReadContext,
};
use crate::repositories::HttpRepositories;
use std::net::SocketAddr;

pub trait HttpHost: Send + Sync + 'static {
    /// The repositories behind every REST use case.
    type Repositories: HttpRepositories;

    fn public_http_bind_address(&self) -> SocketAddr;
    fn admin_http_bind_address(&self) -> SocketAddr;
    fn admin_gateway_authentication_enabled(&self) -> bool;
    fn admin_gateway_verifier(&self) -> AdminGatewayVerifier;
    fn http_transport_policy(&self) -> HttpTransportPolicy;
    fn public_discovery_context(&self) -> &PublicDiscoveryContext;
    fn readiness_context(&self) -> ReadinessContext<Self::Repositories>;
    fn api_query_context(&self) -> ApiQueryContext<Self::Repositories>;

    fn account_admin_context(&self) -> AccountAdminContext<Self::Repositories>;
    fn registration_admin_context(&self) -> RegistrationAdminContext<Self::Repositories>;
    fn session_admin_context(&self) -> SessionAdminContext<Self::Repositories>;
    fn admin_dispatch_context(&self) -> AdminDispatchContext<Self::Repositories>;
    fn invitation_admin_context(&self) -> InvitationAdminContext<Self::Repositories>;
    fn governance_context(&self) -> GovernanceContext<Self::Repositories>;
    fn retention_policy_context(&self) -> RetentionPolicyContext<Self::Repositories>;
    fn report_moderation_context(&self) -> ReportModerationContext<Self::Repositories>;
    fn upload_admin_context(&self) -> UploadAdminContext<Self::Repositories>;
    fn operation_admin_context(&self) -> OperationAdminContext<Self::Repositories>;
    fn report_context(&self) -> ReportContext<Self::Repositories>;

    fn api_session_http_context(&self) -> ApiSessionHttpContext<Self::Repositories>;
    fn http_challenge_endpoint_context(&self) -> HttpChallengeEndpointContext<Self::Repositories>;
    fn http_registration_endpoint_context(
        &self,
    ) -> HttpRegistrationEndpointContext<Self::Repositories>;
    fn http_login_endpoint_context(&self) -> HttpLoginEndpointContext<Self::Repositories>;
    fn omemo_recovery_http_context(&self) -> OmemoRecoveryHttpContext<Self::Repositories>;
    fn omemo_recovery_poll_context(&self) -> OmemoRecoveryPollContext<Self::Repositories>;
    fn password_change_http_context(&self) -> PasswordChangeHttpContext<Self::Repositories>;
    fn passkey_account_http_context(&self) -> PasskeyAccountHttpContext<Self::Repositories>;
    fn passkey_start_http_context(&self) -> PasskeyStartHttpContext<Self::Repositories>;
    fn passkey_login_finish_context(&self) -> PasskeyLoginFinishContext<Self::Repositories>;
    fn account_teardown_context(&self) -> AccountTeardownContext;
    fn account_generation_teardown_context(&self) -> AccountGenerationTeardownContext;

    fn upload_http_read_context(&self) -> UploadHttpReadContext<Self::Repositories>;
    fn upload_http_replay_read_context(&self) -> UploadHttpReplayReadContext;
    fn upload_http_write_context(&self) -> UploadHttpWriteContext<Self::Repositories>;
    fn upload_http_delete_context(&self) -> UploadHttpDeleteContext<Self::Repositories>;
}
