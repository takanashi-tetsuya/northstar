//! Synchronous, process-local ownership changes made before session cleanup I/O.

use crate::local_routes::muc::{MucOccupant, MucOccupantEndpoint, SuspendedMucEndpoint};
use crate::local_routes::muc_table::{
    muc_occupants_for_room_in, remove_live_muc_membership_in, remove_local_muc_occupant_exact_from,
};
use crate::local_routes::session::OnlineSession;
use crate::local_routes::suspended_muc::{
    begin_suspended_muc_route_transition, canonical_suspended_muc_endpoint, muc_actor_epoch_matches,
};
use dashmap::DashMap;
use northstar_room_application::muc_service::{LocalMucOccupantIdentity, SerializableMucOccupant};
use northstar_session_core::JoinedMucMembership;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};
use uuid::Uuid;

pub struct SessionCleanupLocal {
    sessions: Arc<DashMap<String, OnlineSession>>,
    occupants: Arc<DashMap<String, MucOccupant>>,
    suspended_muc_sessions: Arc<DashMap<Uuid, Arc<SuspendedMucEndpoint>>>,
    caps_effect_dispatcher: Arc<northstar_protocol_runtime::caps::CapsEffectDispatcher>,
    caps_by_jid: Arc<northstar_protocol_runtime::caps::CapsResourceIndex>,
    pending_caps: Arc<northstar_protocol_runtime::caps::PendingCapsIndex>,
    active_sessions: Arc<AtomicU64>,
}

impl SessionCleanupLocal {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        sessions: Arc<DashMap<String, OnlineSession>>,
        occupants: Arc<DashMap<String, MucOccupant>>,
        suspended_muc_sessions: Arc<DashMap<Uuid, Arc<SuspendedMucEndpoint>>>,
        caps_effect_dispatcher: Arc<northstar_protocol_runtime::caps::CapsEffectDispatcher>,
        caps_by_jid: Arc<northstar_protocol_runtime::caps::CapsResourceIndex>,
        pending_caps: Arc<northstar_protocol_runtime::caps::PendingCapsIndex>,
        active_sessions: Arc<AtomicU64>,
    ) -> Self {
        Self {
            sessions,
            occupants,
            suspended_muc_sessions,
            caps_effect_dispatcher,
            caps_by_jid,
            pending_caps,
            active_sessions,
        }
    }

    pub fn suspend_local_muc_occupants(
        &self,
        full_jid: &str,
        connection_id: Uuid,
        sm_session_id: Uuid,
        memberships: &DashMap<String, JoinedMucMembership>,
        base_stanzas: usize,
        base_bytes: usize,
    ) -> Vec<Arc<SuspendedMucEndpoint>> {
        suspend_local_muc_occupants_in(
            &self.occupants,
            &self.suspended_muc_sessions,
            full_jid,
            connection_id,
            sm_session_id,
            memberships,
            base_stanzas,
            base_bytes,
        )
    }

    pub fn remove_local_muc_occupant_exact(
        &self,
        identity: LocalMucOccupantIdentity<'_>,
    ) -> Option<MucOccupant> {
        remove_local_muc_occupant_exact_from(&self.occupants, identity)
    }

    pub(super) fn remove_retired_muc_route(&self, identity: LocalMucOccupantIdentity<'_>) {
        if let Some(occupant) = self.remove_local_muc_occupant_exact(identity) {
            remove_live_muc_membership_in(
                &self.sessions,
                &SerializableMucOccupant::from(&occupant),
            );
        }
    }

    pub fn muc_occupants_for(&self, room_jid: &str) -> Vec<(String, MucOccupant)> {
        muc_occupants_for_room_in(&self.occupants, room_jid)
    }

    /// Remove only the old incarnation, then publish its removal before
    /// retiring associated CAPS state and its active-session metric.
    pub fn remove_session_if_connection(
        &self,
        key: &str,
        connection_id: Uuid,
    ) -> Option<OnlineSession> {
        let (_, removed) = self
            .sessions
            .remove_if(key, |_, session| session.connection_id == connection_id)?;
        debug_assert_eq!(removed.route_incarnation.connection_id(), connection_id);
        removed.route_incarnation.publish_removed();
        self.caps_effect_dispatcher
            .cancel_local(key, removed.connection_id);
        self.caps_by_jid
            .remove_local_resource(key, removed.connection_id);
        self.pending_caps
            .remove_local_resource(key, removed.connection_id);
        if removed.metrics_counted.swap(false, Ordering::AcqRel) {
            self.active_sessions.fetch_sub(1, Ordering::Relaxed);
        }
        Some(removed)
    }
}

/// Publish the session-wide suspension fence before walking room entries.
/// The SM context and cleanup service share this exact process-local step.
#[allow(clippy::too_many_arguments)]
pub fn suspend_local_muc_occupants_in(
    occupants: &DashMap<String, MucOccupant>,
    suspended_muc_sessions: &DashMap<Uuid, Arc<SuspendedMucEndpoint>>,
    full_jid: &str,
    connection_id: Uuid,
    sm_session_id: Uuid,
    memberships: &DashMap<String, JoinedMucMembership>,
    base_stanzas: usize,
    base_bytes: usize,
) -> Vec<Arc<SuspendedMucEndpoint>> {
    let proposed = Arc::new(SuspendedMucEndpoint::new_collecting(
        sm_session_id,
        base_stanzas,
        base_bytes,
    ));
    let endpoint =
        canonical_suspended_muc_endpoint(suspended_muc_sessions, sm_session_id, proposed);
    begin_suspended_muc_route_transition(&endpoint, base_stanzas, base_bytes);
    for membership in memberships {
        let room_jid = membership.key();
        let membership = membership.value();
        let key = northstar_room_core::stanza::muc_occupant_key(room_jid, &membership.nick);
        let Some(mut occupant) = occupants.get_mut(&key) else {
            continue;
        };
        if !muc_actor_epoch_matches(&occupant, full_jid, connection_id, room_jid, membership)
            || occupant.sm_session_id != Some(sm_session_id)
        {
            continue;
        }
        match &occupant.endpoint {
            MucOccupantEndpoint::Local(_) => {
                occupant.endpoint = MucOccupantEndpoint::Suspended(Arc::clone(&endpoint));
            }
            MucOccupantEndpoint::Suspended(current)
                if Arc::ptr_eq(current, &endpoint) && current.sm_session_id == sm_session_id => {}
            MucOccupantEndpoint::Suspended(_) | MucOccupantEndpoint::Federated { .. } => {}
        }
    }
    // An in-flight delivery may already hold this fence, even if every
    // membership in the cleanup plan is stale.
    vec![endpoint]
}
