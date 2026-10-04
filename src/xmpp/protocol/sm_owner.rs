//! The existing SM record/checkpoint/ACK operations over the real session
//! substate. Only the current persistence/capacity capabilities are injected.
use super::{SmSubstate, SmRuntimePolicy, ProtocolSession};
use crate::{outbound::{OutboundItem, SmUnackedStanza, TransportOwnershipSource}, services::{sm::{SmCheckpointOutcome, SmService, SmSessionSnapshot, ownership::{CheckpointPolicy, PreparedCheckpoint, PreparedBatch}}, sm_capacity::{SmCapacityLease, SmMemoryGovernor}}, state::JoinedMucMembership};
use anyhow::{Context, Result};
use northstar_delivery_core::sm_ownership::{self, Observation, Purpose, Scope, Terminal};
use std::{collections::VecDeque, future::Future, net::IpAddr, pin::Pin, sync::{Arc, RwLock, atomic::{AtomicBool, AtomicI16, Ordering}}, task::{Context as TaskContext, Poll}};
use uuid::Uuid;

pub(super) struct SmSnapshotView<'a> {
    pub(super) available: &'a Option<Arc<AtomicBool>>,
    pub(super) carbons: &'a AtomicBool,
    pub(super) priority: &'a AtomicI16,
    pub(super) blocklist_requested: &'a AtomicBool,
    pub(super) roster_requested: &'a AtomicBool,
    pub(super) privacy_active: &'a RwLock<Option<String>>,
    pub(super) privacy_requested: &'a AtomicBool,
    pub(super) peer_ip: &'a IpAddr,
    pub(super) user_agent_id: &'a Option<Uuid>,
    pub(super) joined_rooms: &'a dashmap::DashMap<String, JoinedMucMembership>,
    pub(super) directed_presence: &'a dashmap::DashSet<String>,
    pub(super) last_presence: &'a RwLock<Option<String>>,
}
impl SmSnapshotView<'_> {
    pub(super) fn snapshot(&self, sm: &SmSubstate, unacked: Vec<SmUnackedStanza>) -> SmSessionSnapshot {
        crate::services::sm::SmSessionSnapshot {
            inbound_h: sm.inbound_h,
            outbound_h: sm.outbound_h,
            acked_h: sm.acked_h,
            available: self
                .available
                .as_ref()
                .is_some_and(|available| available.load(Ordering::Relaxed)),
            carbons: self.carbons.load(Ordering::Acquire),
            priority: self.priority.load(Ordering::Relaxed),
            blocklist_requested: self.blocklist_requested.load(Ordering::Relaxed),
            roster_requested: self.roster_requested.load(Ordering::Relaxed),
            active_privacy_list: self
                .privacy_active
                .read()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .clone(),
            privacy_requested: self.privacy_requested.load(Ordering::Relaxed),
            peer_ip: *self.peer_ip,
            user_agent_id: *self.user_agent_id,
            joined_rooms: self
                .joined_rooms
                .iter()
                .map(|membership| crate::services::sm::SmMucMembership {
                    room_jid: membership.key().clone(),
                    nick: membership.nick.clone(),
                })
                .collect(),
            directed_presence: self
                .directed_presence
                .iter()
                .map(|jid| jid.key().clone())
                .collect(),
            last_presence: self
                .last_presence
                .read()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .clone(),
            unacked,
        }
    }
    pub(super) fn resident_bytes(&self, sm: &SmSubstate) -> Option<usize> {
        let mut bytes = std::mem::size_of::<crate::services::sm::SmSessionSnapshot>();
        let mut add = |value: usize| {
            bytes = bytes.checked_add(value)?;
            Some(())
        };
        if let Some(value) = self
            .privacy_active
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .as_ref()
        {
            add(value.len())?;
        }
        if let Some(value) = self
            .last_presence
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .as_ref()
        {
            add(value.len())?;
        }
        add(self
            .joined_rooms
            .len()
            .checked_mul(std::mem::size_of::<crate::services::sm::SmMucMembership>())?)?;
        for membership in self.joined_rooms.iter() {
            add(membership.key().len())?;
            add(membership.nick.len())?;
        }
        add(self
            .directed_presence
            .len()
            .checked_mul(std::mem::size_of::<String>())?)?;
        for jid in self.directed_presence.iter() {
            add(jid.key().len())?;
        }
        add(sm
            .unacked
            .len()
            .checked_mul(std::mem::size_of::<crate::outbound::SmUnackedStanza>())?)?;
        for stanza in &sm.unacked {
            add(stanza.stanza.len())?;
        }
        Some(bytes)
    }
}

pub(super) trait SmOwnerPort {
    fn recorded(&self);
    fn reserve_snapshot(&self, bytes: usize) -> Result<SmCapacityLease>;
    fn grow(&self, lease: &SmCapacityLease, bytes: usize) -> Result<()>;
    fn shrink(&self, lease: &SmCapacityLease, bytes: usize) -> Result<()>;
    fn checkpoint(&self, prepared: &PreparedCheckpoint<'_>) -> impl Future<Output = Result<SmCheckpointOutcome>> + Send;
    fn acknowledge_batch(&self, prepared: &PreparedBatch<'_>) -> impl Future<Output = Result<()>> + Send;
}
pub(super) struct RealSmPort<'a> {
    pub(super) service: &'a SmService<crate::db::sm_repository::PostgresSmRepository>,
    pub(super) governor: &'a Arc<SmMemoryGovernor>,
    pub(super) telemetry: crate::xmpp::capabilities::OutboundStanzaTelemetry<'a>,
}
impl SmOwnerPort for RealSmPort<'_> {
    fn recorded(&self) { self.telemetry.recorded(); }
    fn reserve_snapshot(&self, bytes: usize) -> Result<SmCapacityLease> { Ok(self.governor.try_reserve_live(bytes)?) }
    fn grow(&self, lease: &SmCapacityLease, bytes: usize) -> Result<()> { Ok(lease.try_grow_to(bytes)?) }
    fn shrink(&self, lease: &SmCapacityLease, bytes: usize) -> Result<()> { Ok(lease.shrink_to(bytes)?) }
    async fn checkpoint(&self, prepared: &PreparedCheckpoint<'_>) -> Result<SmCheckpointOutcome> {
        let policy = prepared.policy();
        if matches!(prepared.request().purpose(), Purpose::Acknowledge { .. }) {
            self.service.checkpoint_and_acknowledge(prepared.session_id(), prepared.connection_id(), prepared.snapshot(), prepared.acknowledged(), policy.ttl_seconds, policy.live_lease_seconds, policy.max_stanzas, policy.max_bytes, Some(prepared)).await
        } else {
            self.service.checkpoint_session(prepared.session_id(), prepared.connection_id(), prepared.snapshot(), policy.ttl_seconds, policy.live_lease_seconds, policy.max_stanzas, policy.max_bytes, Some(prepared)).await
        }
    }
    async fn acknowledge_batch(&self, prepared: &PreparedBatch<'_>) -> Result<()> {
        self.service.acknowledge_delivery_batch(prepared.sources(), Some(prepared)).await
    }
}

struct ObservationGuard { observation: Observation, finished: bool }
impl ObservationGuard {
    fn finish(&mut self, terminal: Terminal) {
        if self.finished { return; } self.finished = true;
        let summary = self.observation.retire(terminal);
        tracing::debug!(target: "rust_xmpp_server::xmpp::sm_ownership", ?summary, "SM turn retired");
    }
}
impl Drop for ObservationGuard {
    fn drop(&mut self) { self.finish(if std::thread::panicking() { Terminal::Panicked } else { Terminal::Cancelled }); }
}
pub(super) struct SmTurnRunner<F> { child: Option<Pin<Box<F>>>, observation: ObservationGuard, poll_in_progress: bool }
impl<F: Future> SmTurnRunner<F> {
    pub(super) fn new(observation: Observation, child: F) -> Self { Self { child: Some(Box::pin(child)), observation: ObservationGuard { observation, finished: false }, poll_in_progress: false } }
}
impl<F: Future> Future for SmTurnRunner<F> {
    type Output = F::Output;
    fn poll(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<Self::Output> {
        let this = self.get_mut(); this.poll_in_progress = true;
        let result = match this.child.as_mut().expect("SM turn polled after completion").as_mut().poll(cx) {
            Poll::Pending => { this.poll_in_progress = false; return Poll::Pending; }
            Poll::Ready(result) => result,
        };
        drop(this.child.take()); this.poll_in_progress = false; this.observation.finish(Terminal::Returned); Poll::Ready(result)
    }
}
impl<F> Drop for SmTurnRunner<F> {
    fn drop(&mut self) { drop(self.child.take()); if self.poll_in_progress { self.observation.finish(Terminal::Panicked); } }
}

pub(super) struct SmTransportTurn<'a, P> {
    pub(super) sm: &'a mut SmSubstate,
    pub(super) view: SmSnapshotView<'a>,
    pub(super) policy: &'a SmRuntimePolicy,
    pub(super) connection_id: Uuid,
    pub(super) port: P,
}
impl<P: SmOwnerPort> SmTransportTurn<'_, P> {
    pub(super) fn start(&mut self, purpose: Purpose) -> Observation {
        let observation = Observation::new(Scope { purpose, session_id: self.sm.db_id, connection_id: self.connection_id,
            inbound_h: self.sm.inbound_h, outbound_h: self.sm.outbound_h, acked_h: self.sm.acked_h, queued: self.sm.unacked.len() });
        self.sm.current_operation = Some(observation.clone()); observation
    }
    fn checkpoint_policy(&self) -> CheckpointPolicy {
        CheckpointPolicy { ttl_seconds: self.sm.resume_timeout_seconds, live_lease_seconds: self.policy.session.live_lease_seconds, max_stanzas: self.policy.buffer.max_unacked_stanzas, max_bytes: self.policy.buffer.max_unacked_bytes }
    }
    pub(super) async fn record_item(&mut self, item: &OutboundItem, observation: &Observation) -> Result<bool> {
        anyhow::ensure!(item.validate_durable_source_shape(), "outbound item has an invalid durable source/hand-off shape");
        let managed_by_sm = super::durable_delivery_managed_by_sm(self.sm.enabled && self.sm.db_id.is_some(), &item.stanza, item.durable_source.is_some());
        self.record_source(&item.stanza, item.durable_source, observation).await?;
        if managed_by_sm {
            if item.mix_delivery().is_some() {
                let session_id = self.sm.db_id.context("XEP-0198 MIX ownership was not persisted")?;
                item.complete_mix_handoff(crate::outbound::MixTransportCompletion::SmPersisted { session_id });
            } else { item.confirm_transport_ownership(); }
            observation.notified();
        }
        Ok(managed_by_sm)
    }
    pub(super) async fn record_source(&mut self, stanza: &str, source: Option<TransportOwnershipSource>, observation: &Observation) -> Result<()> {
        self.port.recorded();
        if self.sm.enabled && super::is_counted_stanza(stanza) {
            let next_bytes = self.sm.unacked.iter().map(|entry| entry.stanza.len()).sum::<usize>().saturating_add(stanza.len());
            if self.sm.unacked.len() >= self.policy.buffer.max_unacked_stanzas || next_bytes > self.policy.buffer.max_unacked_bytes {
                self.sm.resume_allowed = false; anyhow::bail!("XEP-0198 unacknowledged queue capacity reached");
            }
            let projected = self.view.resident_bytes(self.sm).and_then(|bytes| bytes.checked_add(std::mem::size_of::<SmUnackedStanza>()).and_then(|bytes| bytes.checked_add(stanza.len()))).context("XEP-0198 projected resident-size overflow")?;
            if projected > self.policy.buffer.max_snapshot_bytes || self.sm.capacity.as_ref().is_none_or(|lease| self.port.grow(lease, projected).is_err()) {
                self.sm.resume_allowed = false; anyhow::bail!("XEP-0198 process memory capacity reached");
            }
            self.sm.outbound_h = self.sm.outbound_h.wrapping_add(1);
            self.sm.unacked.push_back(SmUnackedStanza::with_source(stanza.to_owned(), source));
            observation.appended();
            if let Err(error) = self.checkpoint_in_turn(observation).await {
                if error.downcast_ref::<crate::outbound::DurableDeliverySuperseded>().is_some() {
                    self.sm.unacked.pop_back(); self.sm.outbound_h = self.sm.outbound_h.wrapping_sub(1); observation.restored();
                    if let (Some(bytes), Some(capacity)) = (self.view.resident_bytes(self.sm), self.sm.capacity.as_ref()) {
                        let result = self.port.shrink(capacity, bytes); observation.capacity_completed(result.is_ok());
                        result.context("restore SM capacity after superseded delivery")?;
                    }
                }
                return Err(error);
            }
        } else if source.is_some() { debug_assert!(!self.sm.enabled || !super::is_counted_stanza(stanza)); }
        Ok(())
    }
    pub(super) async fn checkpoint_in_turn(&mut self, observation: &Observation) -> Result<()> {
        let Some(id) = self.sm.db_id else { return Ok(()); };
        let live_bytes = self.view.resident_bytes(self.sm).context("XEP-0198 live resident-size overflow")?;
        let _snapshot_clone_capacity = self.port.reserve_snapshot(live_bytes).context("XEP-0198 transient snapshot capacity reached")?;
        let snapshot = self.view.snapshot(self.sm, self.sm.unacked.iter().cloned().collect());
        let snapshot_bytes = snapshot.resident_bytes().context("XEP-0198 snapshot resident-size overflow")?;
        if snapshot_bytes > self.policy.buffer.max_snapshot_bytes || self.sm.capacity.as_ref().is_none_or(|lease| self.port.grow(lease, snapshot_bytes).is_err()) {
            self.sm.resume_allowed = false; anyhow::bail!("XEP-0198 process memory capacity reached");
        }
        let prepared = PreparedCheckpoint::bind(observation, id, self.connection_id, &self.sm.unacked, &snapshot, &[], self.checkpoint_policy())?;
        let outcome = tokio::time::timeout(std::time::Duration::from_secs(5), self.port.checkpoint(&prepared)).await.context("XEP-0198 checkpoint database operation timed out")??;
        let rotations = outcome.ownership.mix_rotations.iter().map(|rotation| sm_ownership::MixRotation { previous: rotation.previous, current: rotation.current }).collect::<Vec<_>>();
        prepared.request().validate_checkpoint_return(outcome.updated, &rotations)?;
        anyhow::ensure!(outcome.updated, "durable XEP-0198 stream lease was lost");
        ProtocolSession::apply_sm_ownership_resolution_to_unacked(&mut self.sm.unacked, &outcome.ownership); observation.ownership_applied();
        Ok(())
    }
    pub(super) async fn acknowledge(&mut self, h: u32, observation: &Observation) -> Result<bool> {
        let Some(delta) = northstar_xep_0198::acknowledgement_delta(self.sm.acked_h, h, self.sm.unacked.len()) else { observation.h_decision(None); return Ok(false); };
        observation.h_decision(Some(delta));
        // Preserve these prefix/suffix clones before the existing full-snapshot
        // reservation. The governor is not claimed to precharge every clone.
        let acknowledged = self.sm.unacked.iter().take(delta).cloned().collect::<Vec<_>>();
        let mut remaining = self.sm.unacked.iter().skip(delta).cloned().collect::<VecDeque<_>>();
        if let Some(id) = self.sm.db_id {
            let clone_bytes = self.view.resident_bytes(self.sm).ok_or_else(|| anyhow::anyhow!("XEP-0198 live resident-size overflow"))?;
            let _snapshot_clone_capacity = self.port.reserve_snapshot(clone_bytes)?;
            let mut snapshot = self.view.snapshot(self.sm, self.sm.unacked.iter().cloned().collect());
            snapshot.acked_h = h; snapshot.unacked = remaining.iter().cloned().collect();
            let prepared = PreparedCheckpoint::bind(observation, id, self.connection_id, &self.sm.unacked, &snapshot, &acknowledged, self.checkpoint_policy())?;
            let outcome = tokio::time::timeout(std::time::Duration::from_secs(5), self.port.checkpoint(&prepared)).await.map_err(|_| anyhow::anyhow!("XEP-0198 acknowledgement database operation timed out"))??;
            let rotations = outcome.ownership.mix_rotations.iter().map(|rotation| sm_ownership::MixRotation { previous: rotation.previous, current: rotation.current }).collect::<Vec<_>>();
            prepared.request().validate_checkpoint_return(outcome.updated, &rotations)?;
            anyhow::ensure!(outcome.updated, "durable XEP-0198 stream lease was lost");
            ProtocolSession::apply_sm_ownership_resolution_to_unacked(&mut remaining, &outcome.ownership); observation.ownership_applied();
        } else {
            let sources = acknowledged.iter().filter_map(|entry| entry.source).collect::<Vec<_>>();
            let binding = sm_ownership::Binding { session_id: None, connection_id: self.connection_id, inbound_h: self.sm.inbound_h, outbound_h: self.sm.outbound_h, acked_h: h,
                whole: self.sm.unacked.iter().map(|entry| entry.source).collect(), acknowledged: acknowledged.iter().map(|entry| entry.source).collect(), remaining: remaining.iter().map(|entry| entry.source).collect() };
            let prepared = PreparedBatch::bind(observation, binding, &self.sm.unacked, &acknowledged, &remaining, &sources)?;
            tokio::time::timeout(std::time::Duration::from_secs(5), self.port.acknowledge_batch(&prepared)).await.map_err(|_| anyhow::anyhow!("delivery acknowledgement database operation timed out"))??;
            prepared.request().validate_batch_return()?;
        }
        self.sm.unacked = remaining; self.sm.acked_h = h; observation.ack_applied(h);
        let live_bytes = self.view.resident_bytes(self.sm).ok_or_else(|| anyhow::anyhow!("XEP-0198 live resident-size overflow"))?;
        if let Some(capacity) = &self.sm.capacity {
            let result = self.port.shrink(capacity, live_bytes); observation.capacity_completed(result.is_ok()); result?;
        }
        Ok(true)
    }
}
