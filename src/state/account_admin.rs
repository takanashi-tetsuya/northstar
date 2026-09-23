//! Process-local state exposed to registration and exact-session commands.
use super::OnlineSession;
use crate::services::account_admin::{AdminSessionLookup, RegistrationCache, SessionKickSnapshot};
use dashmap::DashMap;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use uuid::Uuid;

#[derive(Clone)]
pub(crate) struct LocalRegistrationCache {
    dependency_locked: bool,
    closed: Arc<AtomicBool>,
}
impl LocalRegistrationCache {
    pub(super) fn new(dependency_locked: bool, closed: Arc<AtomicBool>) -> Self {
        Self {
            dependency_locked,
            closed,
        }
    }
}
impl RegistrationCache for LocalRegistrationCache {
    fn dependency_locked(&self) -> bool {
        self.dependency_locked
    }
    fn apply_current_closed(&self, closed: bool) {
        self.closed
            .store(closed || self.dependency_locked, Ordering::Release);
    }
}

#[derive(Clone)]
pub(crate) struct LocalAdminSessions {
    sessions: Arc<DashMap<String, OnlineSession>>,
}
impl LocalAdminSessions {
    pub(super) fn new(sessions: Arc<DashMap<String, OnlineSession>>) -> Self {
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
