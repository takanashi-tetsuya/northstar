//! Live-route fences for MIX presence recovery.

use crate::ports::MixPresenceRoutes;
use dashmap::DashMap;
use northstar_stream::local_routes::session::OnlineSession;
use northstar_stream::local_routes::session_table::{
    mix_presence_epoch_is_current, mix_presence_fallback_is_suppressed, session_entries_for_in,
};
use std::sync::{atomic::Ordering, Arc};
use uuid::Uuid;

pub struct MixPresenceRecoveryRoutes {
    sessions: Arc<DashMap<String, OnlineSession>>,
}

impl MixPresenceRecoveryRoutes {
    pub fn new(sessions: Arc<DashMap<String, OnlineSession>>) -> Self {
        Self { sessions }
    }
}

impl MixPresenceRoutes for MixPresenceRecoveryRoutes {
    fn local_epochs(&self, participant: &str) -> Vec<(String, Uuid, u64)> {
        session_entries_for_in(&self.sessions, participant)
            .into_iter()
            .map(|(full_jid, session)| {
                (
                    full_jid,
                    session.connection_id,
                    session.caps_observation_generation.load(Ordering::Acquire),
                )
            })
            .collect()
    }

    fn gate(&self, full_jid: &str, connection_id: Uuid) -> Option<Arc<tokio::sync::Mutex<()>>> {
        self.sessions
            .get(full_jid)
            .filter(|session| session.connection_id == connection_id)
            .map(|session| Arc::clone(&session.mix_presence_gate))
    }

    fn epoch_state(
        &self,
        full_jid: &str,
        expected_connection_id: Uuid,
        expected_caps_generation: u64,
        expected_gate: &Arc<tokio::sync::Mutex<()>>,
        channel_jid: &str,
    ) -> Option<(bool, bool)> {
        self.sessions.get(full_jid).map(|session| {
            (
                mix_presence_epoch_is_current(
                    session.connection_id,
                    expected_connection_id,
                    session.caps_observation_generation.load(Ordering::Acquire),
                    expected_caps_generation,
                    session.routable.load(Ordering::Acquire),
                    session.available.load(Ordering::Acquire),
                    Arc::ptr_eq(&session.mix_presence_gate, expected_gate),
                ),
                mix_presence_fallback_is_suppressed(
                    &session.mix_presence_fallback_suppressed,
                    channel_jid,
                ),
            )
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use northstar_stream::local_routes::session::test_online_session;

    fn session(user_id: Uuid, generation: i64, routable: bool) -> OnlineSession {
        let (session, _receiver) =
            test_online_session(user_id, generation, Uuid::new_v4(), "fixture", 1);
        session.routable.store(routable, Ordering::Release);
        session
    }

    #[tokio::test]
    async fn mix_recovery_rechecks_the_live_epoch_after_waiting_for_its_gate() {
        let sessions = Arc::new(DashMap::new());
        let full_jid = "alice@example.test/fixture";
        let current = session(uuid::Uuid::new_v4(), 1, true);
        current.available.store(true, Ordering::Release);
        current
            .caps_observation_generation
            .store(7, Ordering::Release);
        sessions.insert(full_jid.into(), current);
        let routes = MixPresenceRecoveryRoutes::new(Arc::clone(&sessions));
        let [(snapshot_jid, connection_id, generation)] = routes
            .local_epochs("alice@example.test")
            .try_into()
            .unwrap();
        assert_eq!(snapshot_jid, full_jid);
        let gate = routes.gate(full_jid, connection_id).unwrap();
        let held = Arc::clone(&gate).lock_owned().await;
        let (waiting_tx, waiting_rx) = tokio::sync::oneshot::channel();
        let recheck = tokio::spawn(async move {
            let _ = waiting_tx.send(());
            let _epoch = Arc::clone(&gate).lock_owned().await;
            routes.epoch_state(
                &snapshot_jid,
                connection_id,
                generation,
                &gate,
                "room@mix.example.test",
            )
        });
        waiting_rx.await.unwrap();
        sessions
            .get(full_jid)
            .unwrap()
            .caps_observation_generation
            .store(8, Ordering::Release);
        drop(held);
        assert_eq!(recheck.await.unwrap(), Some((false, false)));
    }

    #[test]
    fn mix_recovery_rejects_a_replaced_route_even_when_its_generation_matches() {
        let sessions = Arc::new(DashMap::new());
        let full_jid = "alice@example.test/fixture";
        let old = session(uuid::Uuid::new_v4(), 1, true);
        old.available.store(true, Ordering::Release);
        sessions.insert(full_jid.into(), old);
        let routes = MixPresenceRecoveryRoutes::new(Arc::clone(&sessions));
        let [(snapshot_jid, connection_id, generation)] = routes
            .local_epochs("alice@example.test")
            .try_into()
            .unwrap();
        let old_gate = routes.gate(full_jid, connection_id).unwrap();
        let replacement = session(uuid::Uuid::new_v4(), 1, true);
        replacement.available.store(true, Ordering::Release);
        sessions.insert(full_jid.into(), replacement);
        assert!(routes.gate(full_jid, connection_id).is_none());
        assert_eq!(
            routes.epoch_state(
                &snapshot_jid,
                connection_id,
                generation,
                &old_gate,
                "room@mix.example.test",
            ),
            Some((false, false)),
        );
    }

    #[test]
    fn recovery_routes_reject_replaced_gate() {
        let sessions = Arc::new(DashMap::new());
        let full_jid = "alice@example.test/fixture";
        let current = session(Uuid::new_v4(), 1, true);
        current.available.store(true, Ordering::Release);
        let connection_id = current.connection_id;
        let old_gate = Arc::clone(&current.mix_presence_gate);
        sessions.insert(full_jid.into(), current);
        let routes = MixPresenceRecoveryRoutes::new(Arc::clone(&sessions));
        assert_eq!(
            routes.epoch_state(
                full_jid,
                connection_id,
                0,
                &old_gate,
                "room@mix.example.test"
            ),
            Some((true, false)),
        );
        sessions.get_mut(full_jid).unwrap().mix_presence_gate = Arc::default();
        assert_eq!(
            routes.epoch_state(
                full_jid,
                connection_id,
                0,
                &old_gate,
                "room@mix.example.test"
            ),
            Some((false, false)),
        );
    }

    #[test]
    fn recovery_routes_reject_unavailable_or_unroutable_sessions() {
        for (available, routable) in [(false, true), (true, false), (false, false)] {
            let sessions = Arc::new(DashMap::new());
            let full_jid = "alice@example.test/fixture";
            let current = session(Uuid::new_v4(), 1, routable);
            current.available.store(available, Ordering::Release);
            let connection_id = current.connection_id;
            let gate = Arc::clone(&current.mix_presence_gate);
            sessions.insert(full_jid.into(), current);
            let routes = MixPresenceRecoveryRoutes::new(sessions);
            assert_eq!(
                routes.epoch_state(full_jid, connection_id, 0, &gate, "room@mix.example.test"),
                Some((false, false)),
            );
            assert_eq!(
                routes.local_epochs("alice@example.test").len(),
                usize::from(routable),
            );
        }
    }

    #[test]
    fn recovery_routes_report_channel_and_wildcard_fallback_suppression() {
        let sessions = Arc::new(DashMap::new());
        let full_jid = "alice@example.test/fixture";
        let current = session(Uuid::new_v4(), 1, true);
        current.available.store(true, Ordering::Release);
        let connection_id = current.connection_id;
        let gate = Arc::clone(&current.mix_presence_gate);
        let suppressed = Arc::clone(&current.mix_presence_fallback_suppressed);
        sessions.insert(full_jid.into(), current);
        let routes = MixPresenceRecoveryRoutes::new(sessions);
        suppressed.insert("room@mix.example.test".into());
        assert_eq!(
            routes.epoch_state(full_jid, connection_id, 0, &gate, "room@mix.example.test"),
            Some((true, true)),
        );
        assert_eq!(
            routes.epoch_state(full_jid, connection_id, 0, &gate, "other@mix.example.test"),
            Some((true, false)),
        );
        suppressed.insert("*".into());
        assert_eq!(
            routes.epoch_state(full_jid, connection_id, 0, &gate, "other@mix.example.test"),
            Some((true, true)),
        );
    }
}
