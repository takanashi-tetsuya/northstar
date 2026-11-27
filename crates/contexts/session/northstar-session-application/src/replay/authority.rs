use super::*;

/// Exact bound resource for one replay pass, not a locator for a replacement.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReplayRoute {
    pub recipient_id: Uuid,
    pub auth_generation: i64,
    pub connection_id: Uuid,
    pub full_jid: String,
}

#[derive(Debug, Eq, PartialEq)]
pub struct ReplayPolicyVersion(pub String);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplayDisposition {
    Deliver,
    Denied,
    MamProjection(Uuid),
}

#[derive(Debug)]
pub struct AuthorizedReplayPage {
    pub claim_token: Uuid,
    pub policy_version: ReplayPolicyVersion,
    pub messages: Vec<(ReplayMessage, ReplayDisposition)>,
}

#[derive(Debug)]
pub enum AuthorizedReplayClaim {
    Claimed(AuthorizedReplayPage),
    Empty,
    PendingClaims,
    LeaseLost,
    StaleRoute,
}

#[derive(Clone, Copy)]
pub struct ReplayPageAuthority<'a> {
    pub active_privacy_list: Option<&'a str>,
    pub is_current: &'a (dyn Fn() -> bool + Send + Sync),
}

#[derive(Clone, Copy)]
pub struct ReplayMessageAuthority<'a> {
    pub route: ReplayPageAuthority<'a>,
    pub policy_version: &'a ReplayPolicyVersion,
    pub claim_token: Uuid,
    pub message_id: Uuid,
    pub disposition: ReplayDisposition,
}

pub enum ReplayPreparation {
    Ready(RecoveryReplayAuthorizationGuard),
    Suppressed,
    RetryPage,
    StaleRoute,
}

pub trait ReplayAuthorityRepository:
    ReplayRepository + super::pending_presence::PendingPresenceRepository
{
    fn claim_current_page(
        &self,
        session: &ReplaySession,
        authority: ReplayPageAuthority<'_>,
        bind2_mam_catchup: bool,
        offline_ttl_days: i64,
    ) -> impl Future<Output = Result<AuthorizedReplayClaim>> + Send;

    fn prepare_current_message(
        &self,
        session: &ReplaySession,
        authority: ReplayMessageAuthority<'_>,
    ) -> impl Future<Output = Result<ReplayPreparation>> + Send;
}

impl<R: ReplayAuthorityRepository> ReplayService<R> {
    pub async fn claim_current_page(
        &self,
        session: &ReplaySession,
        authority: ReplayPageAuthority<'_>,
        bind2_mam_catchup: bool,
    ) -> Result<AuthorizedReplayClaim> {
        self.repository
            .claim_current_page(session, authority, bind2_mam_catchup, self.offline_ttl_days)
            .await
    }

    pub async fn prepare_current_message(
        &self,
        session: &ReplaySession,
        authority: ReplayMessageAuthority<'_>,
    ) -> Result<ReplayPreparation> {
        self.repository
            .prepare_current_message(session, authority)
            .await
    }
}
