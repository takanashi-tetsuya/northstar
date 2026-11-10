//! Fence transport delivery and support session stream management.

use super::*;

impl ProtocolSession {
    pub(in crate::xmpp) async fn fence_c2s_socket_write(
        &self,
        delivery: northstar_stream::outbound::DurableDelivery,
    ) -> Result<northstar_stream::outbound::DurableDelivery> {
        self.host
            .replay_service()
            .fence_socket_write(delivery)
            .await
    }

    pub(in crate::xmpp) async fn fence_mix_socket_write(
        &self,
        delivery: northstar_stream::outbound::MixDelivery,
    ) -> Result<northstar_stream::outbound::MixDelivery> {
        self.host
            .mix_service()
            .fence_mix_socket_write(delivery)
            .await
    }

    pub(in crate::xmpp) async fn acknowledge_c2s_socket_write(
        &self,
        request: &northstar_delivery_core::native_write::AckRequest,
    ) -> Result<()> {
        let northstar_stream::outbound::TransportOwnershipSource::C2s(delivery) = request.source()
        else {
            anyhow::bail!("native C2S acknowledgement source mismatch");
        };
        self.host
            .replay_service()
            .acknowledge_socket_write_observed(delivery, Some(request))
            .await
    }

    pub(in crate::xmpp) async fn acknowledge_mix_socket_write(
        &self,
        request: &northstar_delivery_core::native_write::AckRequest,
    ) -> Result<bool> {
        self.host
            .mix_service()
            .acknowledge_mix_socket_write(request)
            .await
    }

    pub(in crate::xmpp) fn route_connection_id(&self) -> uuid::Uuid {
        self.connection_id
    }

    pub async fn record_outbound(&mut self, stanza: &str) -> Result<()> {
        self.record_outbound_with_source(stanza, None).await
    }

    pub fn record_replayed(&self) {
        self.host.outbound_stanza_telemetry().recorded();
    }

    pub(super) fn sm_snapshot_view(&self) -> sm_owner::SmSnapshotView<'_> {
        sm_owner::SmSnapshotView {
            available: &self.available,
            carbons: &self.carbons,
            priority: &self.priority,
            blocklist_requested: &self.blocklist_requested,
            roster_requested: &self.roster_requested,
            privacy_active: &self.privacy_active,
            privacy_requested: &self.privacy_requested,
            peer_ip: &self.peer_ip,
            user_agent_id: &self.user_agent_id,
            joined_rooms: &self.joined_rooms,
            directed_presence: &self.directed_presence,
            last_presence: &self.last_presence,
        }
    }

    pub(super) fn sm_transport_turn(
        &mut self,
    ) -> sm_owner::SmTransportTurn<'_, impl sm_owner::SmOwnerPort + '_> {
        // Constructing the borrowed view performs no atomic reads or cloning.
        // Snapshot/accounting sampling remains at its original call sites.
        sm_owner::SmTransportTurn {
            sm: &mut self.sm,
            view: sm_owner::SmSnapshotView {
                available: &self.available,
                carbons: &self.carbons,
                priority: &self.priority,
                blocklist_requested: &self.blocklist_requested,
                roster_requested: &self.roster_requested,
                privacy_active: &self.privacy_active,
                privacy_requested: &self.privacy_requested,
                peer_ip: &self.peer_ip,
                user_agent_id: &self.user_agent_id,
                joined_rooms: &self.joined_rooms,
                directed_presence: &self.directed_presence,
                last_presence: &self.last_presence,
            },
            policy: &self.sm_runtime_policy,
            connection_id: self.connection_id,
            port: sm_owner::RealSmPort {
                service: self.host.sm_service(),
                governor: self.host.sm_memory_governor(),
                telemetry: self.host.outbound_stanza_telemetry(),
            },
        }
    }

    pub(crate) fn sm_snapshot(&self) -> northstar_session_application::sm::SmSessionSnapshot {
        self.sm_snapshot_with_unacked(self.sm.unacked.iter().cloned().collect())
    }

    pub(super) fn sm_snapshot_with_unacked(
        &self,
        unacked: Vec<northstar_stream::outbound::SmUnackedStanza>,
    ) -> northstar_session_application::sm::SmSessionSnapshot {
        self.sm_snapshot_view().snapshot(&self.sm, unacked)
    }

    /// Transfer the large replay FIFO into cleanup ownership. Finalization
    /// must not clone a full per-stream snapshot while the live actor still
    /// owns the same bytes; all remaining metadata is independently bounded.
    pub(super) fn take_sm_snapshot(
        &mut self,
    ) -> northstar_session_application::sm::SmSessionSnapshot {
        let unacked = std::mem::take(&mut self.sm.unacked).into();
        self.sm_snapshot_with_unacked(unacked)
    }

    /// Resident charge of the live SM state without cloning its replay FIFO.
    /// This mirrors `SmSessionSnapshot::resident_bytes` and is used to reserve
    /// both retained growth and short-lived snapshot clones before allocation.
    pub(crate) fn sm_resident_bytes(&self) -> Option<usize> {
        self.sm_snapshot_view().resident_bytes(&self.sm)
    }

    pub(crate) fn apply_sm_ownership_resolution(
        &mut self,
        resolution: &northstar_session_application::sm::SmQueueOwnershipResolution,
    ) {
        Self::apply_sm_ownership_resolution_to_unacked(&mut self.sm.unacked, resolution);
    }

    pub(crate) fn apply_sm_ownership_resolution_to_unacked(
        stanzas: &mut VecDeque<northstar_stream::outbound::SmUnackedStanza>,
        resolution: &northstar_session_application::sm::SmQueueOwnershipResolution,
    ) {
        for stanza in stanzas {
            stanza.source = resolution.resolve_source(stanza.source);
        }
    }
}

pub(super) fn durable_delivery_managed_by_sm(
    sm_enabled: bool,
    stanza: &str,
    has_durable_delivery: bool,
) -> bool {
    sm_enabled && has_durable_delivery && is_counted_stanza(stanza)
}
