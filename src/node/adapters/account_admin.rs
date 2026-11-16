//! Process-local state exposed to registration and exact-session commands.
use crate::node::OnlineSession;
use dashmap::DashMap;
use northstar_auth_application::account_admin::{AdminSessionLookup, SessionKickSnapshot};
use std::sync::Arc;
use uuid::Uuid;

#[derive(Clone)]
pub(crate) struct LocalAdminSessions {
    sessions: Arc<DashMap<String, OnlineSession>>,
}
impl LocalAdminSessions {
    pub(in crate::node) fn new(sessions: Arc<DashMap<String, OnlineSession>>) -> Self {
        Self { sessions }
    }
}
impl AdminSessionLookup for LocalAdminSessions {
    fn exact_connection(&self, connection_id: Uuid) -> Option<SessionKickSnapshot> {
        self.sessions.iter().find_map(|entry| {
            let session = entry.value();
            (session.connection_id == connection_id).then_some(SessionKickSnapshot {
                user_id: session.user_id,
                auth_generation: session.auth_generation,
                connection_id: session.connection_id,
            })
        })
    }
}

#[cfg(test)]
#[path = "account_admin_tests.rs"]
mod tests;
