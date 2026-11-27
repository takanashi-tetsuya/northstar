use super::dispatch::full_jid_iq::full_jid_iq_visible;
use crate::local_routes::session::OnlineSession;
use crate::local_routes::session_table::LocalSessionTable;
use anyhow::Result;
pub use northstar_message_application::messaging::ExactMessageRoute;
use northstar_message_application::messaging::ResourceStanzaPolicy;
use northstar_session_application::sm_teardown_presence::DirectedGrant;
use northstar_xep_0016::PrivacyStanzaKind;
use northstar_xmpp_types::jid::CanonicalJid;
use northstar_xmpp_types::jid_text::bare_jid;
use std::future::Future;
use uuid::Uuid;

pub trait IqVisibilityHost: Send + Sync {
    fn authorize_iq_resource(
        &self,
        admission: &LocalIqAdmission<'_>,
    ) -> impl Future<Output = Result<bool>> + Send;

    fn local_iq_handoff(&self, admission: &LocalIqAdmission<'_>, stanza: Option<&str>) -> bool;

    fn capture_remote_iq_route(
        &self,
        full_jid: &str,
    ) -> impl Future<Output = Result<Option<ExactMessageRoute>>> + Send;

    fn remote_iq_handoff(
        &self,
        route: &ExactMessageRoute,
        stanza: &str,
        admission_only: bool,
    ) -> impl Future<Output = bool> + Send;

    fn remote_iq_route_current(
        &self,
        route: &ExactMessageRoute,
    ) -> impl Future<Output = Result<bool>> + Send;
}

/// One resource incarnation and the volatile inputs sampled before the policy read.
pub struct LocalIqAdmission<'a> {
    route: ExactMessageRoute,
    active_list: Option<String>,
    requester: &'a str,
    requester_fence: Option<RequesterFence>,
    directed: bool,
    require_subscription: bool,
}

/// The exact incarnation of a local client resource that sends an IQ.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct RequesterFence {
    pub account_id: Uuid,
    pub auth_generation: i64,
    pub connection_id: Uuid,
}

impl<'a> LocalIqAdmission<'a> {
    /// Captures an IQ from a federated, component or other-node sender. Only
    /// address-scoped directed grants apply; an exact local grant needs the
    /// requester's incarnation, which this caller does not have.
    pub fn capture(
        jid: String,
        session: &OnlineSession,
        requester: &'a str,
        request: bool,
    ) -> Result<Self> {
        Self::capture_with(jid, session, requester, None, request)
    }

    /// Captures an IQ from a local client resource. Only an exact directed
    /// grant for this incarnation applies, never an address-scoped one.
    pub fn capture_local(
        jid: String,
        session: &OnlineSession,
        requester: &'a str,
        fence: RequesterFence,
        request: bool,
    ) -> Result<Self> {
        Self::capture_with(jid, session, requester, Some(fence), request)
    }

    fn capture_with(
        jid: String,
        session: &OnlineSession,
        requester: &'a str,
        requester_fence: Option<RequesterFence>,
        request: bool,
    ) -> Result<Self> {
        let same_account = CanonicalJid::parse(requester)?.bare() == bare_jid(&jid);
        let directed =
            request && !same_account && has_directed_grant(session, requester, requester_fence);
        Ok(Self {
            route: ExactMessageRoute {
                full_jid: jid,
                account_id: session.user_id,
                auth_generation: session.auth_generation,
                connection_id: session.connection_id,
                node_id: None,
                priority: None,
                available: None,
            },
            active_list: session.privacy_active_snapshot(),
            requester,
            requester_fence,
            directed,
            require_subscription: request && !full_jid_iq_visible(same_account, false, directed),
        })
    }

    pub fn policy(&self) -> ResourceStanzaPolicy<'_> {
        ResourceStanzaPolicy {
            account: Some(bare_jid(&self.route.full_jid)),
            account_id: self.route.account_id,
            auth_generation: Some(self.route.auth_generation),
            connection_id: self.route.connection_id,
            expects_active: self.active_list.is_some(),
            peer: self.requester,
            kind: PrivacyStanzaKind::Iq,
        }
    }

    pub fn requires_subscription(&self) -> bool {
        self.require_subscription
    }

    pub fn handoff(&self, sessions: &LocalSessionTable, stanza: Option<&str>) -> bool {
        sessions.with_exact_message_route(&self.route, |current| {
            current.privacy_active_snapshot() == self.active_list
                && (!self.directed
                    || has_directed_grant(current, self.requester, self.requester_fence))
                && stanza.is_none_or(|xml| current.sender.try_send(xml.to_owned()).is_ok())
        }) == Some(true)
    }
}

/// An exact grant (WP-756) names the accepting resource's incarnation, so a
/// replacement connection never inherits it; an address-scoped grant is kept
/// only for federated and component recipients.
fn has_directed_grant(
    session: &OnlineSession,
    requester: &str,
    fence: Option<RequesterFence>,
) -> bool {
    session.directed_presence.iter().any(|authorized| {
        match DirectedGrant::decode(authorized.key()) {
            Ok(Some(grant)) => {
                grant.route.full_jid == requester
                    && fence.is_some_and(|fence| {
                        fence
                            == RequesterFence {
                                account_id: grant.route.account_id,
                                auth_generation: grant.route.auth_generation,
                                connection_id: grant.route.connection_id,
                            }
                    })
            }
            Ok(None) => {
                fence.is_none()
                    && northstar_presence_core::directed_recipient_matches(
                        authorized.key(),
                        requester,
                    )
            }
            Err(_) => false,
        }
    })
}
