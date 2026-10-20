//! The REST query context's read-only view of this node's live session and MUC occupant maps.

use super::{MucOccupant, OnlineSession};
use crate::services::api_queries::SessionView;
use dashmap::DashMap;
use std::{
    sync::{atomic::Ordering, Arc},
    time::Instant,
};

pub(super) struct LocalApiQueryPresence {
    pub(super) sessions: Arc<DashMap<String, OnlineSession>>,
    pub(super) occupants: Arc<DashMap<String, MucOccupant>>,
}

impl crate::api::contexts::api_queries::LocalPresenceDirectory for LocalApiQueryPresence {
    fn online_session_count(&self) -> usize {
        self.sessions.len()
    }

    fn room_occupant_total(&self) -> usize {
        self.occupants.len()
    }

    fn routable_sessions(&self, node: &str) -> Vec<SessionView> {
        let now = Instant::now();
        self.sessions
            .iter()
            .filter_map(|entry| {
                let session = entry.value();
                if !session.routable.load(Ordering::Acquire) {
                    return None;
                }
                Some(SessionView {
                    connection_id: session.connection_id,
                    node: node.to_owned(),
                    jid: entry.key().clone(),
                    ip: session.ip.map(|ip| ip.to_string()),
                    resource: session.resource.clone(),
                    carbons_enabled: session.carbons.load(Ordering::Acquire),
                    connected_duration_seconds: now
                        .saturating_duration_since(session.connected_at)
                        .as_secs(),
                })
            })
            .collect()
    }

    fn room_occupant_count(&self, room_jid: &str) -> usize {
        self.occupants
            .iter()
            .filter(|occupant| occupant.room_jid == room_jid)
            .count()
    }
}
