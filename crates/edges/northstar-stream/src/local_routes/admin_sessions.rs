//! Process-local state exposed to registration and exact-session commands.
use super::session::OnlineSession;
use dashmap::DashMap;
use northstar_auth_application::account_admin::{AdminSessionLookup, SessionKickSnapshot};
use std::sync::Arc;
use uuid::Uuid;

#[derive(Clone)]
pub struct StreamAdminSessions {
    sessions: Arc<DashMap<String, OnlineSession>>,
}
impl StreamAdminSessions {
    pub fn new(sessions: Arc<DashMap<String, OnlineSession>>) -> Self {
        Self { sessions }
    }
}
impl AdminSessionLookup for StreamAdminSessions {
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
mod tests {
    use super::*;
    use crate::capacity_maintenance::tests::session;

    #[test]
    fn snapshot_uses_shared_sessions_including_pending_and_survives_route_replacement() {
        let shared = Arc::new(DashMap::new());
        let lookup = StreamAdminSessions::new(Arc::clone(&shared));
        let old_id = Uuid::new_v4();
        let mut pending = session(old_id, false);
        pending.auth_generation = 17;
        let expected_user = pending.user_id;
        let old_cancel = pending.disconnect.clone();
        shared.insert("alice@example.test/fixture".into(), pending);
        let old = lookup.exact_connection(old_id).unwrap();
        assert_eq!(
            old,
            SessionKickSnapshot {
                user_id: expected_user,
                auth_generation: 17,
                connection_id: old_id
            }
        );
        let new_id = Uuid::new_v4();
        let replacement = session(new_id, true);
        let new_cancel = replacement.disconnect.clone();
        // This write uses the same map shard; the snapshot must not own its guard.
        shared.insert("alice@example.test/fixture".into(), replacement);
        assert!(lookup.exact_connection(old_id).is_none());
        assert_eq!(
            lookup.exact_connection(new_id).unwrap().connection_id,
            new_id
        );
        assert_eq!(old.connection_id, old_id);
        assert_eq!(old.auth_generation, 17);
        assert!(!old_cancel.is_cancelled());
        assert!(!new_cancel.is_cancelled());
    }
}
