use super::{LocalSessionTable, OnlineSession, SessionLookup};
use crate::outbound::{RouteEnqueue, RouteSendError};
use dashmap::DashMap;
use northstar_message_application::messaging::ExactMessageRoute;
use northstar_message_core::route_item::QueueRefusal;
use northstar_xmpp_types::jid_text::bare_jid;
use std::sync::atomic::Ordering;

pub fn session_lookup(jid: &str) -> Option<SessionLookup> {
    let jid = northstar_xmpp_types::jid::CanonicalJid::parse(jid).ok()?;
    Some(if jid.resourcepart().is_some() {
        SessionLookup::Full(jid.to_string())
    } else {
        SessionLookup::Bare(jid.bare())
    })
}

pub fn session_entries_for_in(
    sessions: &DashMap<String, OnlineSession>,
    jid: &str,
) -> Vec<(String, OnlineSession)> {
    let Some(lookup) = session_lookup(jid) else {
        return Vec::new();
    };
    match lookup {
        SessionLookup::Full(full) => sessions
            .get(&full)
            .filter(|entry| entry.routable.load(Ordering::Acquire))
            .map(|entry| vec![(entry.key().clone(), entry.value().clone())])
            .unwrap_or_default(),
        SessionLookup::Bare(bare) => sessions
            .iter()
            .filter(|entry| {
                bare_jid(entry.key()) == bare.as_str() && entry.routable.load(Ordering::Acquire)
            })
            .map(|entry| (entry.key().clone(), entry.value().clone()))
            .collect(),
    }
}

pub fn try_send_to_entries_in(sessions: &DashMap<String, OnlineSession>, jid: &str, stanza: &str) {
    for (_, session) in session_entries_for_in(sessions, jid) {
        let _ = session.sender.try_send(stanza.to_owned());
    }
}

/// Clone routable sibling routes before sending; no DashMap guard is held
/// while a transport accepts the unavailable presence.
pub fn try_send_to_available_entries_in(
    sessions: &DashMap<String, OnlineSession>,
    jid: &str,
    stanza: &str,
) {
    for (jid, target) in session_entries_for_in(sessions, jid)
        .into_iter()
        .filter(|(_, target)| target.available.load(Ordering::Relaxed))
    {
        let _ = target
            .sender
            .try_send(northstar_xml_builder::rewrite::set_to(stanza, &jid));
    }
}

impl LocalSessionTable {
    fn exact_message_session(
        &self,
        route: &ExactMessageRoute,
    ) -> Option<dashmap::mapref::one::Ref<'_, String, OnlineSession>> {
        self.0.get(&route.full_jid).filter(|session| {
            session.routable.load(Ordering::Acquire)
                && !session.disconnect.is_cancelled()
                && session.user_id == route.account_id
                && session.auth_generation == route.auth_generation
                && session.connection_id == route.connection_id
        })
    }

    pub fn with_exact_message_route<T>(
        &self,
        route: &ExactMessageRoute,
        send: impl FnOnce(&OnlineSession) -> T,
    ) -> Option<T> {
        self.exact_message_session(route)
            .map(|session| send(&session))
    }

    pub fn with_exact_policy_session<T>(
        &self,
        actor: &northstar_roster_core::RosterActor,
        send: impl FnOnce(&OnlineSession) -> T,
    ) -> Option<T> {
        self.with_exact_message_route(
            &ExactMessageRoute {
                full_jid: actor.full_jid.clone(),
                account_id: actor.account_id,
                auth_generation: actor.auth_generation,
                connection_id: actor.connection_id,
                node_id: None,
                priority: None,
                available: None,
            },
            send,
        )
    }

    #[expect(
        clippy::result_large_err,
        reason = "return the exact refused outbound item"
    )]
    pub fn try_send_exact_message_route(
        &self,
        route: &ExactMessageRoute,
        enqueue: RouteEnqueue,
    ) -> Result<(), RouteSendError> {
        match self.exact_message_session(route) {
            Some(session) => session.sender.try_send_route_item(enqueue),
            None => enqueue.send_with(|item| Err(QueueRefusal::Closed(item))),
        }
    }

    pub fn sessions_for(&self, jid: &str) -> Vec<OnlineSession> {
        let Some(lookup) = session_lookup(jid) else {
            return Vec::new();
        };
        match lookup {
            SessionLookup::Full(full) => self
                .0
                .get(&full)
                .filter(|entry| entry.routable.load(Ordering::Acquire))
                .map(|entry| vec![entry.value().clone()])
                .unwrap_or_default(),
            SessionLookup::Bare(bare) => self
                .0
                .iter()
                .filter(|entry| {
                    bare_jid(entry.key()) == bare.as_str() && entry.routable.load(Ordering::Acquire)
                })
                .map(|entry| entry.value().clone())
                .collect(),
        }
    }

    pub fn privacy_list_active_locally(&self, account: &str, name: &str) -> bool {
        self.sessions_for(account).iter().any(|session| {
            session
                .privacy_active
                .read()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .as_deref()
                == Some(name)
        })
    }

    pub fn session_entries_for(&self, jid: &str) -> Vec<(String, OnlineSession)> {
        session_entries_for_in(&self.0, jid)
    }
}
