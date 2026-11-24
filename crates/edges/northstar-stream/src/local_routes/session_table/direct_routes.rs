use super::{LocalSessionTable, OnlineSession, SessionLookup};
use dashmap::DashMap;
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
