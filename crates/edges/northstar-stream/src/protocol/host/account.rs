use anyhow::Result;
use northstar_auth_application::account_teardown::FinalizeAccountDeletion;
use northstar_auth_application::authentication::Sasl2FastTokenPolicy;

/// Account services, registration policy, and account revocation.
pub trait SessionAccountHost: Send + Sync + 'static {
    /// The repository behind [`SessionAccountHost::account_service`].
    type AccountStore: northstar_auth_application::account::AccountRepository + 'static;
    /// The repository behind [`SessionAccountHost::authentication_service`].
    type AuthenticationStore: northstar_auth_application::authentication::AuthenticationRepository
        + 'static;
    /// The repository behind [`SessionAccountHost::challenge_issue_service`].
    type ChallengeStore: northstar_abuse_application::challenge::ChallengeIssueRepository + 'static;
    /// The repository behind [`SessionAccountHost::sasl_login_abuse_service`].
    type LoginAbuseStore: northstar_abuse_application::login::SaslLoginAbuseRepository + 'static;
    /// See `ServerNode::account_service`.
    fn account_service(
        &self,
    ) -> &northstar_auth_application::account::AccountService<Self::AccountStore>;
    /// See `ServerNode::authentication_service`.
    fn authentication_service(
        &self,
    ) -> &northstar_auth_application::authentication::AuthenticationService<Self::AuthenticationStore>;
    /// Effective XEP-0313 availability for inline Bind 2.
    fn mam_enabled(&self) -> bool;
    /// See `ServerNode::challenge_issue_service`.
    fn challenge_issue_service(
        &self,
    ) -> &northstar_abuse_application::challenge::ChallengeIssueService<Self::ChallengeStore>;
    /// Read the public-registration kill switch with acquire ordering.
    fn registration_is_closed(&self) -> bool;
    /// See `ServerNode::registration_requires_invitation`.
    fn registration_requires_invitation(&self) -> bool;
    /// See `ServerNode::sasl2_fast_token_policy`.
    fn sasl2_fast_token_policy(&self) -> Sasl2FastTokenPolicy;
    /// See `ServerNode::sasl_login_abuse_service`.
    fn sasl_login_abuse_service(
        &self,
    ) -> &northstar_abuse_application::login::SaslLoginAbuseService<Self::LoginAbuseStore>;
    /// Commits a XEP-0077 account deletion that the session's proof authorized.
    fn finalize_account_deletion(
        &self,
        user_id: uuid::Uuid,
        username: &str,
    ) -> impl std::future::Future<Output = Result<FinalizeAccountDeletion>> + Send;
    /// Revoke local account routes and request durable SM revocation.
    /// Remote nodes receive the generation fence over Redis, with a 30-second
    /// maintenance sweep as fallback while PostgreSQL remains available.
    fn disconnect_account(
        &self,
        user_id: uuid::Uuid,
        bare_account_jid: &str,
    ) -> impl std::future::Future<Output = ()> + Send;
}
