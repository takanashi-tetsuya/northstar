//! Process-local effects of a durable SM teardown. The database and cluster
//! authorities remain with the caller; this handle can only inspect or retire
//! an exact suspended MUC projection.

use super::{
    muc_suspended_teardown_identity_matches, AppState, MucOccupant, SerializableMucOccupant,
    SuspendedMucEndpoint,
};
use dashmap::DashMap;
use std::sync::Arc;
use uuid::Uuid;

pub(super) struct SmTeardownLocalEffects {
    occupants: Arc<DashMap<String, MucOccupant>>,
    suspended_muc_sessions: Arc<DashMap<Uuid, Arc<SuspendedMucEndpoint>>>,
}

impl AppState {
    pub(super) fn sm_teardown_local_effects(&self) -> SmTeardownLocalEffects {
        SmTeardownLocalEffects {
            occupants: Arc::clone(&self.muc_occupants),
            suspended_muc_sessions: Arc::clone(&self.suspended_muc_sessions),
        }
    }
}

impl SmTeardownLocalEffects {
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
