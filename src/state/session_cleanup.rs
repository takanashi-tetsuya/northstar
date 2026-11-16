//! The composition of C2S session finalization: the node services the
//! stream-owned orchestrator drives, bound to their root implementations.

use crate::cluster::{ClusterMucDeparture, ClusterSessionRouteRelease};
use crate::state::muc_delivery::MucDeliveryContext;
use crate::state::AppState;
use crate::state::{
    session_cleanup_bookkeeping::SessionCleanupBookkeeping, session_cleanup_mix::SessionCleanupMix,
    session_cleanup_muc_departure::SessionCleanupPgMucDeparture,
    session_cleanup_presence::SessionCleanupPresence, session_cleanup_rooms::SessionCleanupRooms,
    session_cleanup_sm::SessionCleanupSm, session_cleanup_sm_revoker::SessionCleanupSmRevoker,
    session_cleanup_unavailable::AppSessionCleanupUnavailable,
};
use anyhow::Result;
use northstar_room_application::muc_service::ClusterMucTransitionOutcome;
use northstar_runtime::workers::WorkerRegistry;
use northstar_session_application::sm::SmSessionSnapshot;
use northstar_session_application::sm_capacity::SmCapacityLease;
use northstar_session_application::SessionCleanupAccount;
use northstar_stream::local_routes::muc::{MucOccupant, SuspendedMucEndpoint};
use northstar_stream::session_cleanup::local::SessionCleanupLocal;
use northstar_stream::session_cleanup::service::{SessionCleanupPorts, SessionCleanupService};
use std::sync::Arc;
use uuid::Uuid;

/// The root services a session finalization drives.
pub struct SessionCleanupAdapters {
    sm: SessionCleanupSm,
    sm_revoker: SessionCleanupSmRevoker,
    presence: SessionCleanupPresence,
    rooms: SessionCleanupRooms,
    muc_delivery: MucDeliveryContext,
    muc_departure: ClusterMucDeparture,
    pg_muc_departure: Option<SessionCleanupPgMucDeparture>,
    unavailable: AppSessionCleanupUnavailable,
    mix: SessionCleanupMix,
    route_release: ClusterSessionRouteRelease,
    bookkeeping: SessionCleanupBookkeeping,
}

impl AppState {
    pub(crate) fn compose_session_cleanup(&self) -> SessionCleanupService<SessionCleanupAdapters> {
        let sm = self.session_cleanup_sm();
        let sm_revoker = self.session_cleanup_sm_revoker();
        let local = self.session_cleanup_local();
        let presence = self.session_cleanup_presence();
        let rooms = self.session_cleanup_rooms();
        let muc_delivery = self.muc_delivery_context();
        let muc_departure = self.session_cleanup_muc_departure();
        let pg_muc_departure = self.session_cleanup_pg_muc_departure();
        let unavailable = self.session_cleanup_unavailable();
        let mix = self.session_cleanup_mix();
        let route_release = self.session_cleanup_route_release();
        let bookkeeping = self.session_cleanup_bookkeeping();
        SessionCleanupService::new(
            local,
            SessionCleanupAdapters {
                sm,
                sm_revoker,
                presence,
                rooms,
                muc_delivery,
                muc_departure,
                pg_muc_departure,
                unavailable,
                mix,
                route_release,
                bookkeeping,
            },
        )
    }

    pub(crate) fn session_cleanup_local(&self) -> SessionCleanupLocal {
        SessionCleanupLocal::new(
            Arc::clone(&self.sessions),
            Arc::clone(&self.room.muc_occupants),
            Arc::clone(&self.room.suspended_muc_sessions),
            Arc::clone(&self.caps_effect_dispatcher),
            Arc::clone(&self.caps_by_jid),
            Arc::clone(&self.pending_caps),
            Arc::clone(&self.metrics.active_sessions),
        )
    }
}

impl SessionCleanupPorts for SessionCleanupAdapters {
    async fn snapshot_suspended_muc_for_disconnect(
        &self,
        endpoints: &[Arc<SuspendedMucEndpoint>],
        snapshot: &mut SmSessionSnapshot,
    ) -> Result<()> {
        self.sm
            .snapshot_suspended_muc_for_disconnect(endpoints, snapshot)
            .await
    }

    async fn seal_suspended_muc_endpoints(&self, endpoints: &[Arc<SuspendedMucEndpoint>]) {
        self.sm.seal_suspended_muc_endpoints(endpoints).await;
    }

    fn mark_memory_invariant_failure(&self) {
        self.sm.mark_memory_invariant_failure();
    }

    async fn suspend_exact_session(
        &self,
        session_id: Uuid,
        connection_id: Uuid,
        account: &SessionCleanupAccount,
        snapshot: &SmSessionSnapshot,
        ttl_seconds: u64,
    ) -> Result<bool> {
        self.sm
            .suspend_exact_session(session_id, connection_id, account, snapshot, ttl_seconds)
            .await
    }

    async fn mark_suspended_muc_durable(&self, endpoints: Vec<Arc<SuspendedMucEndpoint>>) -> bool {
        self.sm.mark_suspended_muc_durable(endpoints).await
    }

    fn queue_promotion(
        &self,
        connection_id: Uuid,
        session_id: Uuid,
        endpoints: Vec<Arc<SuspendedMucEndpoint>>,
        capacity: SmCapacityLease,
    ) -> bool {
        self.sm
            .queue_promotion(connection_id, session_id, endpoints, capacity)
    }

    fn queue_suspension(
        &self,
        account: SessionCleanupAccount,
        connection_id: Uuid,
        session_id: Uuid,
        snapshot: SmSessionSnapshot,
        ttl_seconds: u64,
        endpoints: Vec<Arc<SuspendedMucEndpoint>>,
        capacity: SmCapacityLease,
    ) -> bool {
        self.sm.queue_suspension(
            account,
            connection_id,
            session_id,
            snapshot,
            ttl_seconds,
            endpoints,
            capacity,
        )
    }

    async fn revoke_session(&self, session_id: Uuid) -> Result<()> {
        self.sm.revoke_session(session_id).await
    }

    async fn revoke_session_with_teardown(&self, session_id: Uuid) -> Result<()> {
        self.sm_revoker.revoke_with_teardown(session_id).await
    }

    async fn release_live_session(&self, connection_id: Uuid) -> Result<bool> {
        self.sm.release_live_session(connection_id).await
    }

    async fn release_exact_local_session_route(
        &self,
        full_jid: &str,
        connection_id: Uuid,
    ) -> Result<()> {
        self.route_release
            .release_exact_local_session_route(full_jid, connection_id)
            .await
    }

    async fn unavailable_recipients(&self, owner_id: Uuid) -> Result<Vec<String>> {
        self.presence.unavailable_recipients(owner_id).await
    }

    fn actor_bare_jid(&self, username: &str) -> String {
        self.presence.actor_bare_jid(username)
    }

    fn send_available_sibling_presence(&self, actor_bare: &str, presence: &str) {
        self.presence
            .send_available_sibling_presence(actor_bare, presence);
    }

    async fn route_unavailable_with_policy(
        &self,
        owner_id: Uuid,
        active_privacy_list: Option<&str>,
        from: &str,
        unavailable: &str,
        target: &str,
    ) -> Result<()> {
        self.unavailable
            .route_with_policy(owner_id, active_privacy_list, from, unavailable, target)
            .await
    }

    async fn disconnect_mix_presence(
        &self,
        user_id: Uuid,
        actor_bare: &str,
        actor_full: &str,
    ) -> Result<()> {
        self.mix
            .disconnect_presence(user_id, actor_bare, actor_full)
            .await
    }

    fn pg_muc_authoritative(&self) -> bool {
        self.pg_muc_departure.is_some()
    }

    async fn leave_pg_muc_exact(
        &self,
        room_jid: &str,
        departed: &MucOccupant,
    ) -> Result<Option<ClusterMucTransitionOutcome>> {
        match &self.pg_muc_departure {
            Some(departure) => departure.leave_exact(room_jid, departed).await,
            None => Ok(None),
        }
    }

    async fn publish_local_muc_departure(
        &self,
        departed: &MucOccupant,
        was_last: bool,
    ) -> Result<()> {
        self.muc_departure
            .publish_local_departure(departed, was_last)
            .await
    }

    async fn deliver_to_muc_occupant(&self, occupant: &MucOccupant, stanza: String) -> bool {
        self.muc_delivery
            .deliver_to_muc_occupant(occupant, stanza)
            .await
    }

    async fn delete_temporary_room(&self, room_jid: &str) -> Result<()> {
        self.rooms.delete_temporary_room(room_jid).await
    }

    async fn clear_active_privacy_session(&self, user_id: Uuid, connection_id: Uuid) -> Result<()> {
        self.bookkeeping
            .clear_active_privacy_session(user_id, connection_id)
            .await
    }

    fn finalization_started(&self) {
        self.bookkeeping.finalization_started();
    }

    fn finalization_failed(&self, failures: usize) {
        self.bookkeeping.finalization_failed(failures);
    }

    fn worker_registry(&self) -> &WorkerRegistry {
        self.bookkeeping.worker_registry()
    }
}
