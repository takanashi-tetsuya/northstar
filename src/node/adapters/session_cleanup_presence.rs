//! Presence audience and process-local sibling delivery during session cleanup.

use crate::node::{OnlineSession, ServerNode};
use anyhow::Result;
use dashmap::DashMap;
use northstar_roster_application::presence::PresenceService;
use northstar_stream::local_routes::session_table::try_send_to_available_entries_in;
use northstar_workflows::presence_repository::PostgresPresenceRepository;
use std::sync::Arc;
use uuid::Uuid;

pub(crate) struct SessionCleanupPresence {
    audience: PresenceService<PostgresPresenceRepository>,
    sessions: Arc<DashMap<String, OnlineSession>>,
    domain: String,
}

impl ServerNode {
    pub(crate) fn session_cleanup_presence(&self) -> SessionCleanupPresence {
        SessionCleanupPresence {
            audience: self.roster.presence_service.clone(),
            sessions: Arc::clone(&self.sessions),
            domain: self.config.domain.clone(),
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

    pub(crate) fn send_available_sibling_presence(&self, actor_bare: &str, presence: &str) {
        try_send_to_available_entries_in(&self.sessions, actor_bare, presence);
    }
}
