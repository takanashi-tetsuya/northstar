//! Presence audience and process-local sibling delivery during session cleanup.

use super::{session_entries_for_in, AppState, OnlineSession};
use crate::{
    db::presence_repository::PostgresPresenceRepository, services::presence::PresenceService,
};
use anyhow::Result;
use dashmap::DashMap;
use std::sync::{atomic::Ordering, Arc};
use uuid::Uuid;

pub(crate) struct SessionCleanupPresence {
    audience: PresenceService<PostgresPresenceRepository>,
    sessions: Arc<DashMap<String, OnlineSession>>,
    domain: String,
}

impl AppState {
    pub(crate) fn session_cleanup_presence(&self) -> SessionCleanupPresence {
        SessionCleanupPresence {
            audience: self.presence_service.clone(),
            sessions: Arc::clone(&self.sessions),
            domain: self.local_domain().to_owned(),
        }
    }
}

impl SessionCleanupPresence {
    /// Preserve repository order; the caller publishes roster unavailability
    /// before local sibling and directed-presence notifications.
    pub(crate) async fn unavailable_recipients(&self, owner_id: Uuid) -> Result<Vec<String>> {
        self.audience.unavailable_recipients(owner_id).await
    }

    pub(crate) fn actor_bare_jid(&self, username: &str) -> String {
        format!("{username}@{}", self.domain)
    }

    /// Clone routable sibling routes before sending; no DashMap guard is held
    /// while a transport accepts the unavailable presence.
    pub(crate) fn send_available_sibling_presence(&self, actor_bare: &str, presence: &str) {
        for (jid, target) in session_entries_for_in(&self.sessions, actor_bare)
            .into_iter()
            .filter(|(_, target)| target.available.load(Ordering::Relaxed))
        {
            let _ = target
                .sender
                .try_send(crate::xmpp::xml_util::set_to(presence, &jid));
        }
    }
}
