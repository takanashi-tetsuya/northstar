//! Account resume payloads, fence transport delivery and support session stream management.

use super::*;

/// Transport-owned XEP-0198 replay payload. The capacity leases are acquired
/// before the replay strings are cloned and remain attached until a transport
/// has written, queued for ordered HTTP delivery, or discarded the complete
/// action. This prevents many simultaneous resumes from bypassing the process
/// SM memory governor with an otherwise short-lived `Vec<String>` clone.
pub struct ResumePayload {
    pub(super) control: String,
    /// Ordered nonzas which must follow the resume control before any replayed
    /// stanza. SASL2 uses this for the mandatory post-success stream features.
    pub(super) post_control: Vec<String>,
    pub(super) replay: Vec<String>,
    pub(super) activate_route: bool,
    pub(super) auth_publication: Option<super::super::auth_publication::AuthControlHolder>,
    pub(super) transient_capacity: Vec<crate::services::sm_capacity::SmCapacityLease>,
}

pub(crate) struct ResumeTransportParts {
    pub(crate) control: String,
    pub(crate) post_control: Vec<String>,
    pub(crate) replay: Vec<String>,
    pub(crate) activate_route: bool,
    pub(crate) auth_publication: Option<super::super::auth_publication::AuthControlHolder>,
    pub(crate) transient_capacity: Vec<crate::services::sm_capacity::SmCapacityLease>,
}

impl ResumePayload {
    pub(crate) fn from_sm_unacked(
        governor: &Arc<crate::services::sm_capacity::SmMemoryGovernor>,
        control: String,
        post_control: Vec<String>,
        replay_source: &VecDeque<crate::xmpp::outbound::SmUnackedStanza>,
        activate_route: bool,
    ) -> Result<Self> {
        let requested_bytes = resume_payload_requested_bytes(
            &control,
            &post_control,
            replay_source.iter().map(|entry| entry.stanza.len()),
            replay_source.len(),
        )
        .context("XEP-0198 transport replay allocation overflow")?;
        let transient_capacity = governor
            .try_reserve_transient(requested_bytes)
            .context("XEP-0198 transport replay memory capacity reached")?;

        // Allocate every clone only after the complete process reservation.
        // Explicit capacities make the preflight and actual resident charge
        // identical rather than relying on `collect` growth heuristics.
        let mut replay = Vec::with_capacity(replay_source.len());
        for entry in replay_source {
            let mut stanza = String::with_capacity(entry.stanza.len());
            stanza.push_str(&entry.stanza);
            replay.push(stanza);
        }
        let actual_bytes = resume_payload_actual_bytes(&control, &post_control, &replay)
            .context("XEP-0198 transport replay allocation overflow")?;
        anyhow::ensure!(
            actual_bytes <= requested_bytes,
            "XEP-0198 transport replay allocation exceeded its reservation"
        );
        Ok(Self {
            control,
            post_control,
            replay,
            activate_route,
            auth_publication: None,
            transient_capacity,
        })
    }

    pub(crate) fn control(&self) -> &str {
        &self.control
    }

    pub(crate) fn replace_envelope(
        &mut self,
        control: String,
        post_control: Vec<String>,
        reserved_bytes: usize,
        mut capacity: Vec<crate::services::sm_capacity::SmCapacityLease>,
    ) -> Result<()> {
        anyhow::ensure!(
            self.auth_publication.is_none(),
            "cannot replace a sealed authentication envelope"
        );
        let actual = control
            .capacity()
            .checked_add(
                post_control
                    .capacity()
                    .checked_mul(std::mem::size_of::<String>())
                    .context("SASL2 resume post-control allocation overflow")?,
            )
            .and_then(|bytes| {
                post_control
                    .iter()
                    .try_fold(bytes, |bytes, stanza| bytes.checked_add(stanza.capacity()))
            })
            .context("SASL2 resume transport envelope allocation overflow")?;
        anyhow::ensure!(
            actual <= reserved_bytes,
            "SASL2 resume transport envelope exceeded its reservation"
        );
        self.control = control;
        self.post_control = post_control;
        self.transient_capacity.append(&mut capacity);
        Ok(())
    }

    pub(crate) fn into_transport_parts(self) -> ResumeTransportParts {
        ResumeTransportParts {
            control: self.control,
            post_control: self.post_control,
            replay: self.replay,
            activate_route: self.activate_route,
            auth_publication: self.auth_publication,
            transient_capacity: self.transient_capacity,
        }
    }
}

pub(super) fn resume_payload_requested_bytes(
    control: &String,
    post_control: &Vec<String>,
    mut replay_lengths: impl Iterator<Item = usize>,
    replay_count: usize,
) -> Option<usize> {
    let bytes = control.capacity().checked_add(
        post_control
            .capacity()
            .checked_mul(std::mem::size_of::<String>())?,
    )?;
    let bytes = post_control
        .iter()
        .try_fold(bytes, |bytes, stanza| bytes.checked_add(stanza.capacity()))?;
    let bytes = bytes.checked_add(replay_count.checked_mul(std::mem::size_of::<String>())?)?;
    replay_lengths.try_fold(bytes, usize::checked_add)
}

pub(super) fn resume_payload_actual_bytes(
    control: &String,
    post_control: &Vec<String>,
    replay: &Vec<String>,
) -> Option<usize> {
    let bytes = control
        .capacity()
        .checked_add(
            post_control
                .capacity()
                .checked_mul(std::mem::size_of::<String>())?,
        )?
        .checked_add(
            replay
                .capacity()
                .checked_mul(std::mem::size_of::<String>())?,
        )?;
    let bytes = post_control
        .iter()
        .chain(replay)
        .try_fold(bytes, |bytes, stanza| bytes.checked_add(stanza.capacity()))?;
    Some(bytes)
}

impl ProtocolSession {
    pub(in crate::xmpp) async fn fence_c2s_socket_write(
        &self,
        delivery: crate::xmpp::outbound::DurableDelivery,
    ) -> Result<crate::xmpp::outbound::DurableDelivery> {
        self.state
            .replay_service()
            .fence_socket_write(delivery)
            .await
    }

    pub(in crate::xmpp) async fn fence_mix_socket_write(
        &self,
        delivery: crate::xmpp::outbound::MixDelivery,
    ) -> Result<crate::xmpp::outbound::MixDelivery> {
        self.state
            .mix_service()
            .fence_mix_socket_write(delivery)
            .await
    }

    pub(in crate::xmpp) async fn acknowledge_c2s_socket_write(
        &self,
        request: &northstar_delivery_core::native_write::AckRequest,
    ) -> Result<()> {
        let crate::xmpp::outbound::TransportOwnershipSource::C2s(delivery) = request.source()
        else {
            anyhow::bail!("native C2S acknowledgement source mismatch");
        };
        self.state
            .replay_service()
            .acknowledge_socket_write_observed(delivery, Some(request))
            .await
    }

    pub(in crate::xmpp) async fn acknowledge_mix_socket_write(
        &self,
        request: &northstar_delivery_core::native_write::AckRequest,
    ) -> Result<bool> {
        self.state
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
        self.state.outbound_stanza_telemetry().recorded();
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
                service: self.state.sm_service(),
                governor: self.state.sm_memory_governor(),
                telemetry: self.state.outbound_stanza_telemetry(),
            },
        }
    }

    pub(crate) fn sm_snapshot(&self) -> crate::services::sm::SmSessionSnapshot {
        self.sm_snapshot_with_unacked(self.sm.unacked.iter().cloned().collect())
    }

    pub(super) fn sm_snapshot_with_unacked(
        &self,
        unacked: Vec<crate::xmpp::outbound::SmUnackedStanza>,
    ) -> crate::services::sm::SmSessionSnapshot {
        self.sm_snapshot_view().snapshot(&self.sm, unacked)
    }

    /// Transfer the large replay FIFO into cleanup ownership. Finalization
    /// must not clone a full per-stream snapshot while the live actor still
    /// owns the same bytes; all remaining metadata is independently bounded.
    pub(super) fn take_sm_snapshot(&mut self) -> crate::services::sm::SmSessionSnapshot {
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
        resolution: &crate::services::sm::SmQueueOwnershipResolution,
    ) {
        Self::apply_sm_ownership_resolution_to_unacked(&mut self.sm.unacked, resolution);
    }

    pub(crate) fn apply_sm_ownership_resolution_to_unacked(
        stanzas: &mut VecDeque<crate::xmpp::outbound::SmUnackedStanza>,
        resolution: &crate::services::sm::SmQueueOwnershipResolution,
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
