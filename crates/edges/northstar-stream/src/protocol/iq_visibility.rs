use super::dispatch::full_jid_iq::full_jid_iq_visible;
use crate::local_routes::session::OnlineSession;
use crate::local_routes::session_table::LocalSessionTable;
use anyhow::Result;
pub use northstar_message_application::messaging::ExactMessageRoute;
use northstar_message_application::messaging::ResourceStanzaPolicy;
use northstar_xep_0016::PrivacyStanzaKind;
use northstar_xmpp_types::jid::CanonicalJid;
use northstar_xmpp_types::jid_text::bare_jid;
use std::future::Future;

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
    directed: bool,
    require_subscription: bool,
}

impl<'a> LocalIqAdmission<'a> {
    pub fn capture(
        jid: String,
        session: &OnlineSession,
        requester: &'a str,
        request: bool,
    ) -> Result<Self> {
        let same_account = CanonicalJid::parse(requester)?.bare() == bare_jid(&jid);
        let directed = request && !same_account && has_directed_grant(session, requester);
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
                && (!self.directed || has_directed_grant(current, self.requester))
                && stanza.is_none_or(|xml| current.sender.try_send(xml.to_owned()).is_ok())
        }) == Some(true)
    }
}

fn has_directed_grant(session: &OnlineSession, requester: &str) -> bool {
    session.directed_presence.iter().any(|authorized| {
        northstar_presence_core::directed_recipient_matches(authorized.key(), requester)
    })
}
