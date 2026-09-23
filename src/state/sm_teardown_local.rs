//! Process-local effects of a durable SM teardown. The database and cluster
//! authorities remain with the caller; this handle can only fence an exact
//! live session and inspect or retire its suspended MUC projection.

use super::{
    muc_suspended_teardown_identity_matches, AppState, MucOccupant, MucOccupantEndpoint,
    OnlineSession, SerializableMucOccupant, SuspendedMucEndpoint,
};
use dashmap::DashMap;
use std::sync::{atomic::Ordering, Arc};
use uuid::Uuid;

pub(super) struct SmTeardownLocalEffects {
    sessions: Arc<DashMap<String, OnlineSession>>,
    occupants: Arc<DashMap<String, MucOccupant>>,
    suspended_muc_sessions: Arc<DashMap<Uuid, Arc<SuspendedMucEndpoint>>>,
}

impl AppState {
    pub(super) fn sm_teardown_local_effects(&self) -> SmTeardownLocalEffects {
        SmTeardownLocalEffects {
            sessions: Arc::clone(&self.sessions),
            occupants: Arc::clone(&self.muc_occupants),
            suspended_muc_sessions: Arc::clone(&self.suspended_muc_sessions),
        }
    }
}

impl SmTeardownLocalEffects {
    pub(super) fn fence_exact_session(&self, full_jid: &str, sm_session_id: Uuid) {
        if let Some(session) = self.sessions.get_mut(full_jid) {
            let matches = *session
                .sm_session_id
                .read()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                == Some(sm_session_id);
            if matches {
                session.routable.store(false, Ordering::Release);
                session.disconnect.cancel();
            }
        }
    }

    pub(super) fn cached_suspended_occupant(
        &self,
        sm_session_id: Uuid,
        full_jid: &str,
        room_jid: &str,
        nick: &str,
    ) -> Option<SerializableMucOccupant> {
        let key = crate::xmpp::xml_util::muc_occupant_key(room_jid, nick);
        self.occupants
            .get(&key)
            .filter(|occupant| {
                occupant.full_jid == full_jid
                    && occupant.room_jid == room_jid
                    && occupant.nick == nick
                    && !occupant.cluster_epoch.is_nil()
                    && !occupant.connection_id.is_nil()
                    && matches!(
                        &occupant.endpoint,
                        MucOccupantEndpoint::Suspended(endpoint)
                            if endpoint.sm_session_id == sm_session_id
                    )
            })
            .map(|occupant| SerializableMucOccupant::from(&*occupant))
    }

    pub(super) fn finish_suspended_session(&self, sm_session_id: Uuid) {
        self.suspended_muc_sessions.remove(&sm_session_id);
    }

    pub(super) fn remove_exact_suspended_occupant(
        &self,
        sm_session_id: Uuid,
        occupant: &SerializableMucOccupant,
    ) -> bool {
        let key = crate::xmpp::xml_util::muc_occupant_key(&occupant.room_jid, &occupant.nick);
        self.occupants
            .remove_if(&key, |_, current| {
                muc_suspended_teardown_identity_matches(current, sm_session_id, occupant)
            })
            .is_some()
    }

    pub(super) fn room_occupants(&self, room_jid: &str) -> Vec<(String, MucOccupant)> {
        let Ok(room_jid) = crate::jid::canonicalize_bare(room_jid) else {
            return Vec::new();
        };
        self.occupants
            .iter()
            .filter(|entry| entry.value().room_jid == room_jid)
            .map(|entry| (entry.key().clone(), entry.value().clone()))
            .collect()
    }
}
