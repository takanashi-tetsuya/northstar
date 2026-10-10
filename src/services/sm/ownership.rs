//! Borrowed, immutable SM preparation shared by the protocol and repository.
//! The existing service-to-database DTO conversion is checked without cloning
//! another stanza or resampling live session metadata.
use super::{SmMucMembership, SmSessionSnapshot};
use crate::outbound::{SmUnackedStanza, TransportOwnershipSource};
use northstar_delivery_core::sm_ownership::{Binding, Observation, Request};
use std::{collections::VecDeque, net::IpAddr};
use uuid::Uuid;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CheckpointPolicy {
    pub(crate) ttl_seconds: u64,
    pub(crate) live_lease_seconds: u64,
    pub(crate) max_stanzas: usize,
    pub(crate) max_bytes: usize,
}

#[derive(Eq, PartialEq)]
pub(crate) struct SnapshotProjection<'a> {
    pub(crate) inbound_h: u32,
    pub(crate) outbound_h: u32,
    pub(crate) acked_h: u32,
    pub(crate) available: bool,
    pub(crate) carbons: bool,
    pub(crate) priority: i16,
    pub(crate) blocklist_requested: bool,
    pub(crate) roster_requested: bool,
    pub(crate) active_privacy_list: &'a Option<String>,
    pub(crate) privacy_requested: bool,
    pub(crate) peer_ip: IpAddr,
    pub(crate) user_agent_id: Option<Uuid>,
    pub(crate) joined_rooms: &'a [SmMucMembership],
    pub(crate) directed_presence: &'a [String],
    pub(crate) last_presence: &'a Option<String>,
    pub(crate) unacked: &'a [SmUnackedStanza],
}
impl<'a> From<&'a SmSessionSnapshot> for SnapshotProjection<'a> {
    fn from(snapshot: &'a SmSessionSnapshot) -> Self {
        let SmSessionSnapshot {
            inbound_h,
            outbound_h,
            acked_h,
            available,
            carbons,
            priority,
            blocklist_requested,
            roster_requested,
            active_privacy_list,
            privacy_requested,
            peer_ip,
            user_agent_id,
            joined_rooms,
            directed_presence,
            last_presence,
            unacked,
        } = snapshot;
        Self {
            inbound_h: *inbound_h,
            outbound_h: *outbound_h,
            acked_h: *acked_h,
            available: *available,
            carbons: *carbons,
            priority: *priority,
            blocklist_requested: *blocklist_requested,
            roster_requested: *roster_requested,
            active_privacy_list,
            privacy_requested: *privacy_requested,
            peer_ip: *peer_ip,
            user_agent_id: *user_agent_id,
            joined_rooms,
            directed_presence,
            last_presence,
            unacked,
        }
    }
}

pub(crate) struct PreparedCheckpoint<'a> {
    request: Request,
    snapshot: &'a SmSessionSnapshot,
    acknowledged: &'a [SmUnackedStanza],
    policy: CheckpointPolicy,
}
impl std::fmt::Debug for PreparedCheckpoint<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PreparedSmCheckpoint { immutable views: [redacted] }")
    }
}
impl<'a> PreparedCheckpoint<'a> {
    pub(crate) fn bind(
        observation: &Observation,
        session_id: Uuid,
        connection_id: Uuid,
        whole: &VecDeque<SmUnackedStanza>,
        snapshot: &'a SmSessionSnapshot,
        acknowledged: &'a [SmUnackedStanza],
        policy: CheckpointPolicy,
    ) -> anyhow::Result<Self> {
        anyhow::ensure!(
            whole
                .iter()
                .eq(acknowledged.iter().chain(&snapshot.unacked)),
            "SM prepared FIFO cut changed its ordered stanzas"
        );
        let request = observation.bind(Binding {
            session_id: Some(session_id),
            connection_id,
            inbound_h: snapshot.inbound_h,
            outbound_h: snapshot.outbound_h,
            acked_h: snapshot.acked_h,
            whole: whole.iter().map(|entry| entry.source).collect(),
            acknowledged: acknowledged.iter().map(|entry| entry.source).collect(),
            remaining: snapshot.unacked.iter().map(|entry| entry.source).collect(),
        })?;
        Ok(Self {
            request,
            snapshot,
            acknowledged,
            policy,
        })
    }
    pub(crate) fn request(&self) -> &Request {
        &self.request
    }
    pub(crate) fn snapshot(&self) -> &SmSessionSnapshot {
        self.snapshot
    }
    pub(crate) fn acknowledged(&self) -> &[SmUnackedStanza] {
        self.acknowledged
    }
    pub(crate) fn policy(&self) -> CheckpointPolicy {
        self.policy
    }
    pub(crate) fn session_id(&self) -> Uuid {
        self.request
            .binding()
            .session_id
            .expect("prepared persisted SM checkpoint")
    }
    pub(crate) fn connection_id(&self) -> Uuid {
        self.request.binding().connection_id
    }
    pub(crate) fn validate_projection(
        &self,
        session_id: Uuid,
        connection_id: Uuid,
        snapshot: SnapshotProjection<'_>,
        acknowledged: &[SmUnackedStanza],
        policy: CheckpointPolicy,
    ) -> anyhow::Result<()> {
        anyhow::ensure!(
            session_id == self.session_id()
                && connection_id == self.connection_id()
                && snapshot == SnapshotProjection::from(self.snapshot)
                && acknowledged == self.acknowledged
                && policy == self.policy,
            "SM persistence projection differs from its prepared command"
        );
        self.request.validate_binding(self.request.binding())?;
        Ok(())
    }
}

pub(crate) struct PreparedBatch<'a> {
    request: Request,
    sources: &'a [TransportOwnershipSource],
}
impl std::fmt::Debug for PreparedBatch<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PreparedSmBatch { immutable source cut: [redacted] }")
    }
}
impl<'a> PreparedBatch<'a> {
    pub(crate) fn bind(
        observation: &Observation,
        binding: Binding,
        whole: &VecDeque<SmUnackedStanza>,
        acknowledged: &[SmUnackedStanza],
        remaining: &VecDeque<SmUnackedStanza>,
        sources: &'a [TransportOwnershipSource],
    ) -> anyhow::Result<Self> {
        anyhow::ensure!(
            whole.iter().eq(acknowledged.iter().chain(remaining))
                && sources
                    .iter()
                    .copied()
                    .eq(acknowledged.iter().filter_map(|entry| entry.source))
                && binding
                    .whole
                    .iter()
                    .copied()
                    .eq(whole.iter().map(|entry| entry.source))
                && binding
                    .acknowledged
                    .iter()
                    .copied()
                    .eq(acknowledged.iter().map(|entry| entry.source))
                && binding
                    .remaining
                    .iter()
                    .copied()
                    .eq(remaining.iter().map(|entry| entry.source)),
            "SM unpersisted acknowledgement cut changed"
        );
        Ok(Self {
            request: observation.bind(binding)?,
            sources,
        })
    }
    pub(crate) fn request(&self) -> &Request {
        &self.request
    }
    pub(crate) fn sources(&self) -> &[TransportOwnershipSource] {
        self.sources
    }
    pub(crate) fn validate_sources(
        &self,
        sources: &[TransportOwnershipSource],
    ) -> anyhow::Result<()> {
        anyhow::ensure!(
            sources == self.sources,
            "SM unpersisted acknowledgement sources changed"
        );
        self.request.validate_binding(self.request.binding())?;
        Ok(())
    }
}
