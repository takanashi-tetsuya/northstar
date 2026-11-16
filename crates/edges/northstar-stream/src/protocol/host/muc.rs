use crate::local_routes::muc::MucOccupant;
use crate::local_routes::muc::RestoreLocalMucOccupantsRequest;
use crate::local_routes::muc::SuspendedMucEndpoint;
use crate::protocol::{ProtocolSession, SessionHost};
use anyhow::Result;
use dashmap::DashMap;
use northstar_room_application::muc_service::LocalMucOccupantIdentity;
use northstar_session_core::JoinedMucMembership;
use std::sync::Arc;

/// Local MUC occupancy, delivery, and stream resumption.
pub trait SessionMucHost: Send + Sync + 'static {
    /// Associate MUC occupants which were joined before SM enable with the
    /// newly-created durable stream epoch and update their Redis control
    /// records. This also makes active-session revocation exact and immune to
    /// nick reuse races.
    fn associate_local_muc_sm_session(
        &self,
        full_jid: &str,
        connection_id: uuid::Uuid,
        sm_session_id: uuid::Uuid,
        memberships: &DashMap<String, JoinedMucMembership>,
    ) -> impl std::future::Future<Output = ()> + Send;
    /// Compare and remove under one map shard lock. Callers retain the removed
    /// value for any post-removal delivery; no map guard crosses an await.
    fn remove_local_muc_occupant_exact(
        &self,
        identity: LocalMucOccupantIdentity<'_>,
    ) -> Option<MucOccupant>;
    /// The local MUC occupancies a resumed stream restored, until it commits or aborts them.
    type RestoredMuc: crate::local_routes::muc::RestoredMucOccupancy;
    /// Roll a failed restore back to a suspended actor without taking suffix
    /// ownership away from its sole durable source. `snapshot_backed` is true
    /// only after the protocol session itself contains the staged suffix; in
    /// that case successful connection cleanup clears this backup instead of
    /// appending it again.
    fn abort_local_muc_resume(
        &self,
        restored: &Self::RestoredMuc,
        snapshot_backed: bool,
    ) -> impl std::future::Future<Output = ()> + Send;
    /// Install the exact post-finalization replay base. `claim_resume` is only
    /// a preliminary snapshot: acknowledgements may advance before the
    /// PostgreSQL activation CAS returns. Keeping the endpoint in `Waiting`
    /// until this method prevents that stale claim size from opening excess
    /// stanza or byte budget.
    fn begin_suspended_muc_resume(
        &self,
        endpoints: &[Arc<SuspendedMucEndpoint>],
        base_stanzas: usize,
        base_bytes: usize,
    ) -> impl std::future::Future<Output = bool> + Send;
    /// Transfer the volatile suffix to the exact live SM checkpoint. The
    /// queue is cleared only after PostgreSQL accepted that checkpoint, while
    /// the endpoint mutex still excludes both delivery and transport
    /// publication. A later socket failure therefore re-suspends the snapshot
    /// without appending a duplicate copy of the suffix.
    fn checkpoint_local_muc_resume(
        &self,
        restored: &Self::RestoredMuc,
    ) -> impl std::future::Future<Output = bool> + Send;
    /// See `local_routes::suspended_muc::clear_suspended_sm_capacity`.
    fn clear_suspended_sm_capacity(&self, endpoints: &[Arc<SuspendedMucEndpoint>]);
    /// Publish a restore plan only after the `<resumed/>` control and complete
    /// replay have reached the transport. The endpoint mutex is held while all
    /// exact actors are swapped, so an arriving stanza observes either the
    /// sealed gate or the final live route, never a partially transferred FIFO.
    fn commit_local_muc_resume(
        &self,
        restored: Self::RestoredMuc,
        sender: &crate::outbound::OutboundSender,
        capacity: northstar_session_application::sm_capacity::SmCapacityLease,
    ) -> impl std::future::Future<Output = crate::local_routes::muc::CommittedLocalMucResume> + Send;
    /// See `ServerNode::mark_suspended_muc_durable`.
    fn mark_suspended_muc_durable(
        &self,
        endpoints: Vec<Arc<SuspendedMucEndpoint>>,
    ) -> impl std::future::Future<Output = bool> + Send;
    /// See `local_routes::suspended_muc::pause_suspended_muc_delivery`.
    fn pause_suspended_muc_delivery(
        &self,
        sm_session_id: uuid::Uuid,
    ) -> impl std::future::Future<Output = Vec<Arc<SuspendedMucEndpoint>>> + Send;
    /// Reattach only memberships that can still be proven valid. Existing
    /// suspended actors are swapped in place; after a process restart a new
    /// actor is recreated without join broadcast or history replay. The
    /// volatile suspension FIFO moves into the returned replay suffix so the
    /// resumed stream emits it strictly after `<resumed/>` and the durable
    /// unacked replay.
    fn restore_local_muc_occupants(
        &self,
        request: RestoreLocalMucOccupantsRequest<'_>,
    ) -> impl std::future::Future<Output = Self::RestoredMuc> + Send;
    /// See `ServerNode::seal_suspended_muc_endpoints`.
    fn seal_suspended_muc_endpoints(
        &self,
        endpoints: &[Arc<SuspendedMucEndpoint>],
    ) -> impl std::future::Future<Output = ()> + Send;
    /// The session's own occupant of the local MUC room `room_jid`, while its membership is authorized.
    fn authorized_muc_occupant(
        session: &ProtocolSession<Self>,
        room_jid: &str,
    ) -> impl std::future::Future<Output = Result<Option<MucOccupant>>> + Send
    where
        Self: SessionHost;
    /// See `MucDeliveryContext::blocked_muc_recipient_accounts`.
    fn blocked_muc_recipient_accounts(
        &self,
        occupants: &[MucOccupant],
        stanza_senders: &[String],
    ) -> impl std::future::Future<Output = std::collections::HashSet<String>> + Send;
    /// See `MucDeliveryContext::deliver_to_muc_occupant`.
    fn deliver_to_muc_occupant(
        &self,
        occupant: &MucOccupant,
        stanza: String,
    ) -> impl std::future::Future<Output = bool> + Send;
    /// See `LocalMucOccupantTable::local_muc_occupant_by_nick`.
    fn local_muc_occupant_by_nick(&self, room_jid: &str, nick: &str) -> Option<MucOccupant>;
}
