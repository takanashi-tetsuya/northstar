//! Presence audience and process-local sibling delivery during session cleanup.

use crate::node::ServerNode;

pub(crate) struct SessionCleanupPresence {
    domain: String,
}

impl ServerNode {
    pub(crate) fn session_cleanup_presence(&self) -> SessionCleanupPresence {
        SessionCleanupPresence {
            domain: self.config.domain.clone(),
        }
    }
}

impl SessionCleanupPresence {
    pub(crate) fn actor_bare_jid(&self, username: &str) -> String {
        format!("{username}@{}", self.domain)
    }
}
