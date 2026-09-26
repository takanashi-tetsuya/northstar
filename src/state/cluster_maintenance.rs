//! Process-local projections needed by the cluster maintenance pass.
//! No database pool, Redis client, or signing authority crosses this boundary.

use super::{
    cluster_muc_projection::local_cluster_muc_projection_snapshot_in,
    local_session_authority_snapshots_in, local_session_lease_snapshots_in,
    remove_live_muc_membership_in, remove_local_muc_occupant_exact_from, AppState,
    JoinedMucMembership, LocalSessionAuthoritySnapshot, LocalSessionLeaseSnapshot, MucOccupant,
    OnlineSession, SerializableMucOccupant,
};
use crate::metrics::{DurationTimer, Metrics};
use dashmap::DashMap;
use std::sync::{atomic::Ordering, Arc};
use tokio_util::sync::CancellationToken;

fn fence_stale_muc_membership_exact(
    memberships: &DashMap<String, JoinedMucMembership>,
    disconnect: &CancellationToken,
    occupant: &MucOccupant,
) -> bool {
    memberships
        .remove_if(&occupant.room_jid, |_, current| {
            if current.nick != occupant.nick || current.cluster_epoch != occupant.cluster_epoch {
                return false;
            }
            // A same-connection rejoin cannot replace this entry between the
            // exact-epoch check and cancellation.
            disconnect.cancel();
            true
        })
        .is_some()
}

#[derive(Clone)]
pub(crate) struct ClusterMaintenanceLocals {
    sessions: Arc<DashMap<String, OnlineSession>>,
    occupants: Arc<DashMap<String, MucOccupant>>,
    metrics: Arc<Metrics>,
}

impl ClusterMaintenanceLocals {
    pub(crate) fn session_authority_snapshots(&self) -> Vec<LocalSessionAuthoritySnapshot> {
        local_session_authority_snapshots_in(&self.sessions)
    }

    pub(crate) fn session_lease_snapshots(&self) -> Vec<LocalSessionLeaseSnapshot> {
        local_session_lease_snapshots_in(&self.sessions)
    }

    pub(crate) fn muc_occupant_snapshots(&self) -> Vec<MucOccupant> {
        local_cluster_muc_projection_snapshot_in(&self.occupants)
    }

    pub(crate) fn remove_stale_muc_actor(&self, occupant: &MucOccupant) {
        if let Ok(full_jid) = crate::jid::canonical_session_key(&occupant.full_jid) {
            if let Some(session) = self.sessions.get(&full_jid) {
                if !occupant.connection_id.is_nil()
                    && session.connection_id == occupant.connection_id
                {
                    fence_stale_muc_membership_exact(
                        &session.muc_memberships,
                        &session.disconnect,
                        occupant,
                    );
                }
            }
        }
        remove_local_muc_occupant_exact_from(&self.occupants, occupant.into());
    }

    /// A committed room transition has already removed this membership's
    /// authority. It must not revoke the unrelated C2S route.
    pub(crate) fn remove_committed_terminal_muc_actor(&self, occupant: &MucOccupant) {
        self.remove_muc_actor_projection(occupant);
    }

    fn remove_muc_actor_projection(&self, occupant: &MucOccupant) {
        let serializable = SerializableMucOccupant::from(occupant);
        remove_live_muc_membership_in(&self.sessions, &serializable);
        remove_local_muc_occupant_exact_from(&self.occupants, occupant.into());
    }

    pub(crate) fn record_background_failure(&self) {
        self.metrics
            .background_maintenance_failures_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_muc_reconciliation(&self) {
        self.metrics
            .cluster_muc_pg_reconciliations_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn redis_operation_timer(&self) -> DurationTimer<'_> {
        self.metrics.redis_operation_duration_seconds.start_timer()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::{MucOccupantEndpoint, RouteIncarnationSignal};
    use std::{sync::atomic::AtomicBool, time::Instant};

    fn session(connection_id: uuid::Uuid) -> OnlineSession {
        let (sender, _receiver) = tokio::sync::mpsc::channel(1);
        OnlineSession {
            user_id: uuid::Uuid::new_v4(),
            auth_generation: 1,
            user_agent_epoch: None,
            connection_id,
            route_incarnation: RouteIncarnationSignal::new(connection_id),
            lifecycle: Arc::default(),
            metrics_counted: Arc::default(),
            routable: Arc::new(AtomicBool::new(true)),
            sender: crate::outbound::OutboundSender::new(sender),
            available: Arc::default(),
            mix_presence_gate: Arc::default(),
            mix_presence_fallback_suppressed: Arc::default(),
            caps_observation_generation: Arc::default(),
            carbons: Arc::default(),
            priority: Arc::default(),
            show: Arc::default(),
            blocklist_requested: Arc::default(),
            roster_requested: Arc::default(),
            roster_sync: Arc::default(),
            mix_roster_annotations: Arc::default(),
            privacy_active: Arc::default(),
            privacy_requested: Arc::default(),
            directed_presence: Arc::default(),
            last_presence: Arc::default(),
            ip: None,
            resource: "Phone".to_owned(),
            user_agent_id: None,
            sm_session_id: Arc::default(),
            muc_memberships: Arc::default(),
            connected_at: Instant::now(),
            last_activity: Arc::new(std::sync::RwLock::new(Instant::now())),
            disconnect: CancellationToken::new(),
        }
    }

    fn occupant(connection_id: uuid::Uuid, cluster_epoch: uuid::Uuid) -> MucOccupant {
        let (sender, _receiver) = tokio::sync::mpsc::channel(1);
        MucOccupant {
            full_jid: "alice@example.test/Phone".to_owned(),
            room_jid: "room@conference.example.test".to_owned(),
            nick: "Alice".to_owned(),
            endpoint: MucOccupantEndpoint::Local(crate::outbound::OutboundSender::new(sender)),
            affiliation: "member".to_owned(),
            role: "participant".to_owned(),
            room_non_anonymous: false,
            occupant_id: "opaque".to_owned(),
            cluster_epoch,
            connection_id,
            sm_session_id: None,
            payload: String::new(),
        }
    }

    #[test]
    fn stale_snapshot_cannot_cancel_same_connection_after_rejoin() {
        let connection_id = uuid::Uuid::new_v4();
        let old = occupant(connection_id, uuid::Uuid::new_v4());
        let replacement = occupant(connection_id, uuid::Uuid::new_v4());
        let sessions = Arc::new(DashMap::new());
        let occupants = Arc::new(DashMap::new());
        let live = session(connection_id);
        let disconnect = live.disconnect.clone();
        let memberships = Arc::clone(&live.muc_memberships);
        memberships.insert(
            old.room_jid.clone(),
            JoinedMucMembership::new(replacement.nick.clone(), replacement.cluster_epoch),
        );
        sessions.insert(old.full_jid.clone(), live);
        let key = crate::xmpp::xml_util::muc_occupant_key(&old.room_jid, &old.nick);
        occupants.insert(key.clone(), replacement.clone());
        let locals = ClusterMaintenanceLocals {
            sessions,
            occupants: Arc::clone(&occupants),
            metrics: Arc::default(),
        };

        locals.remove_stale_muc_actor(&old);
        assert!(!disconnect.is_cancelled());
        assert_eq!(
            memberships.get(&old.room_jid).unwrap().cluster_epoch,
            replacement.cluster_epoch,
        );
        assert_eq!(
            occupants.get(&key).unwrap().cluster_epoch,
            replacement.cluster_epoch
        );

        memberships.insert(
            old.room_jid.clone(),
            JoinedMucMembership::new(old.nick.clone(), old.cluster_epoch),
        );
        occupants.insert(key.clone(), old.clone());
        locals.remove_stale_muc_actor(&old);
        assert!(disconnect.is_cancelled());
        assert!(!memberships.contains_key(&old.room_jid));
        assert!(!occupants.contains_key(&key));
    }

    #[test]
    fn invalid_nil_membership_is_still_fenced() {
        let old = occupant(uuid::Uuid::new_v4(), uuid::Uuid::nil());
        let memberships = DashMap::new();
        memberships.insert(
            old.room_jid.clone(),
            JoinedMucMembership::new(old.nick.clone(), uuid::Uuid::nil()),
        );
        let disconnect = CancellationToken::new();

        assert!(fence_stale_muc_membership_exact(
            &memberships,
            &disconnect,
            &old,
        ));
        assert!(disconnect.is_cancelled());
    }
}

impl AppState {
    pub(crate) fn cluster_maintenance_handles(
        &self,
    ) -> (
        crate::cluster::ClusterMaintenanceControl,
        crate::cluster::ClusterMaintenanceRedis,
    ) {
        (
            self.cluster.maintenance_control(),
            self.cluster.maintenance_redis(),
        )
    }

    pub(crate) fn cluster_maintenance_locals(&self) -> ClusterMaintenanceLocals {
        ClusterMaintenanceLocals {
            sessions: Arc::clone(&self.sessions),
            occupants: Arc::clone(&self.muc_occupants),
            metrics: Arc::clone(&self.metrics),
        }
    }
}
