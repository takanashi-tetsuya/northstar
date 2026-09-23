//! Process-local endpoints and projections for committed MUC outbox events.

use super::{
    remove_local_muc_occupant_exact_from, with_local_muc_occupant_exact, AppState,
    LocalMucOccupantIdentity, MucOccupant, MucOccupantEndpoint, OnlineSession,
    SerializableMucOccupant, SuspendedMucEndpoint,
};
use crate::db::ClusterMucAudienceSnapshot;
use dashmap::DashMap;
use std::sync::Arc;

pub(crate) struct ClusterMucDeliveryEndpoints {
    sessions: Arc<DashMap<String, OnlineSession>>,
    occupants: Arc<DashMap<String, MucOccupant>>,
}

impl AppState {
    pub(crate) fn cluster_muc_delivery_endpoints(&self) -> ClusterMucDeliveryEndpoints {
        ClusterMucDeliveryEndpoints {
            sessions: Arc::clone(&self.sessions),
            occupants: Arc::clone(&self.muc_occupants),
        }
    }
}

impl ClusterMucDeliveryEndpoints {
    pub(crate) fn room_occupants(&self, room_jid: &str) -> Vec<MucOccupant> {
        let Ok(room_jid) = crate::jid::canonicalize_bare(room_jid) else {
            return Vec::new();
        };
        self.occupants
            .iter()
            .filter(|entry| entry.value().room_jid == room_jid)
            .map(|entry| entry.value().clone())
            .collect()
    }

    pub(crate) fn cached_recipient(&self, room_jid: &str, nick: &str) -> Option<MucOccupant> {
        let room_jid = crate::jid::canonicalize_bare(room_jid).ok()?;
        let key = crate::xmpp::xml_util::muc_occupant_key(&room_jid, nick);
        self.occupants
            .get(&key)
            .filter(|occupant| occupant.room_jid == room_jid)
            .map(|occupant| occupant.value().clone())
    }

    /// A terminal event may outlive the live occupancy. Reconstruct only its
    /// endpoint from the immutable audience; this never restores membership.
    pub(crate) fn recipient_from_snapshot(
        &self,
        snapshot: &ClusterMucAudienceSnapshot,
        room_jid: &str,
        room_non_anonymous: bool,
        occupant_id: String,
    ) -> Option<MucOccupant> {
        let endpoint = match snapshot.identity_kind.as_str() {
            "local" => {
                if let Some(session) = self.sessions.get(&snapshot.full_jid) {
                    if session.connection_id == snapshot.connection_uuid
                        && snapshot.local_user_id == Some(session.user_id)
                    {
                        MucOccupantEndpoint::Local(session.sender.clone())
                    } else {
                        drop(session);
                        let sm_session_id = snapshot.sm_session_id?;
                        MucOccupantEndpoint::Suspended(Arc::new(SuspendedMucEndpoint::new_durable(
                            sm_session_id,
                        )))
                    }
                } else {
                    let sm_session_id = snapshot.sm_session_id?;
                    MucOccupantEndpoint::Suspended(Arc::new(SuspendedMucEndpoint::new_durable(
                        sm_session_id,
                    )))
                }
            }
            "federated" => MucOccupantEndpoint::Federated {
                authenticated_domain: snapshot.authenticated_domain.clone()?,
                connection_id: snapshot.connection_uuid,
            },
            _ => return None,
        };
        Some(MucOccupant {
            full_jid: snapshot.full_jid.clone(),
            room_jid: room_jid.to_owned(),
            nick: snapshot.nick.clone(),
            endpoint,
            affiliation: snapshot.affiliation.clone(),
            role: snapshot.role.clone(),
            room_non_anonymous,
            occupant_id,
            cluster_epoch: snapshot.occupant_incarnation,
            connection_id: snapshot.connection_uuid,
            sm_session_id: snapshot.sm_session_id,
            // Delivery-only snapshots never resurrect advertised presence.
            payload: String::new(),
        })
    }

    pub(crate) fn actor_nick(&self, room_jid: &str, actor_full_jid: &str) -> Option<String> {
        let room_jid = crate::jid::canonicalize_bare(room_jid).ok()?;
        self.occupants.iter().find_map(|entry| {
            let actor = entry.value();
            (actor.room_jid == room_jid && actor.full_jid == actor_full_jid)
                .then(|| actor.nick.clone())
        })
    }

    pub(crate) fn apply_role_projection_exact(&self, snapshot: &SerializableMucOccupant) -> bool {
        self.apply_projection_exact(snapshot, false)
    }

    pub(crate) fn apply_policy_projection_exact(&self, snapshot: &SerializableMucOccupant) -> bool {
        self.apply_projection_exact(snapshot, true)
    }

    fn apply_projection_exact(
        &self,
        snapshot: &SerializableMucOccupant,
        update_anonymity: bool,
    ) -> bool {
        with_local_muc_occupant_exact(
            &self.occupants,
            LocalMucOccupantIdentity::from(snapshot),
            |current| {
                current.affiliation.clone_from(&snapshot.affiliation);
                current.role.clone_from(&snapshot.role);
                if update_anonymity {
                    current.room_non_anonymous = snapshot.room_non_anonymous;
                }
            },
        )
        .is_some()
    }

    /// The protocol membership and cached occupant share the same exact
    /// incarnation fence; a later nickname or transport owner is untouched.
    pub(crate) fn revoke_exact_recipient(&self, occupant: &SerializableMucOccupant) {
        self.revoke_exact_recipient_returning_local(occupant);
    }

    /// Listener eviction needs the removed endpoint for its self-presence.
    /// Keep live-membership removal ahead of the local occupancy removal.
    pub(crate) fn revoke_exact_recipient_returning_local(
        &self,
        occupant: &SerializableMucOccupant,
    ) -> Option<MucOccupant> {
        self.remove_live_membership_exact(occupant);
        self.remove_local_exact(LocalMucOccupantIdentity::from(occupant))
    }

    pub(crate) fn remove_local_exact(
        &self,
        identity: LocalMucOccupantIdentity<'_>,
    ) -> Option<MucOccupant> {
        remove_local_muc_occupant_exact_from(&self.occupants, identity)
    }

    pub(crate) fn remove_live_membership_exact(&self, occupant: &SerializableMucOccupant) -> bool {
        let Ok(full_jid) = crate::jid::canonical_session_key(&occupant.full_jid) else {
            return false;
        };
        let Some(session) = self.sessions.get(&full_jid) else {
            return false;
        };
        if occupant.connection_id.is_nil() || session.connection_id != occupant.connection_id {
            return false;
        }
        session
            .muc_memberships
            .remove_if(&occupant.room_jid, |_, membership| {
                membership.nick == occupant.nick
                    && membership.cluster_epoch == occupant.cluster_epoch
                    && !membership.cluster_epoch.is_nil()
            })
            .is_some()
    }
}
