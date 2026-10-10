//! The saved entry's single SM recorder. Native and BOSH recording borrow the
//! same real substate/governor/turn; only existing persistence ports are fake.
use super::{next, wire, Sequence, SmMetadata, TransportOwnershipSource};
use crate::{
    outbound::OutboundItem,
    services::{
        sm::{
            ownership::{PreparedBatch, PreparedCheckpoint, SnapshotProjection},
            SmCheckpointOutcome, SmQueueOwnershipResolution,
        },
        sm_capacity::{SmCapacityLease, SmCapacityMetrics, SmMemoryGovernor},
    },
    xmpp::protocol::{
        sm_owner::{SmOwnerPort, SmTransportTurn, SmTurnRunner},
        SmRuntimePolicy, SmSubstate,
    },
};
use anyhow::{Context, Result};
use northstar_delivery_core::sm_ownership as core;
use std::{
    collections::VecDeque,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
};
use uuid::Uuid;

fn sources(values: &[Option<TransportOwnershipSource>]) -> Vec<Option<wire::Source>> {
    values.iter().map(|source| source.map(Into::into)).collect()
}
fn fact(value: &core::CommitFact) -> wire::SmFact {
    match value {
        core::CommitFact::Checkpoint { rotations, settled } => wire::SmFact::Checkpoint {
            rotations: rotations
                .iter()
                .map(|rotation| wire::Rotation {
                    previous: TransportOwnershipSource::Mix(rotation.previous).into(),
                    current: TransportOwnershipSource::Mix(rotation.current).into(),
                })
                .collect(),
            settled: settled.iter().copied().map(Into::into).collect(),
        },
        core::CommitFact::UnpersistedAck {
            deleted,
            absent_unclaimed,
        } => wire::SmFact::UnpersistedAck {
            deleted: deleted.iter().copied().map(Into::into).collect(),
            absent_unclaimed: absent_unclaimed
                .iter()
                .copied()
                .map(|source| TransportOwnershipSource::C2s(source).into())
                .collect(),
        },
    }
}
fn state(observation: &core::Observation, managed: Option<bool>) -> wire::SmState {
    let snapshot = observation.snapshot();
    let scope = snapshot.scope;
    wire::SmState {
        scope: wire::SmScope {
            purpose: match scope.purpose {
                core::Purpose::Record => wire::SmPurpose::Record,
                core::Purpose::Checkpoint => wire::SmPurpose::Checkpoint,
                core::Purpose::Acknowledge { h } => wire::SmPurpose::Acknowledge { h },
            },
            session_id: scope.session_id.map(wire::Id),
            connection_id: wire::Id(scope.connection_id),
            inbound_h: scope.inbound_h,
            outbound_h: scope.outbound_h,
            acked_h: scope.acked_h,
            queued: u32::try_from(scope.queued).expect("bounded SM queue"),
        },
        binding: snapshot.binding.as_ref().map(|binding| wire::SmBinding {
            session_id: binding.session_id.map(wire::Id),
            connection_id: wire::Id(binding.connection_id),
            inbound_h: binding.inbound_h,
            outbound_h: binding.outbound_h,
            acked_h: binding.acked_h,
            whole: sources(&binding.whole),
            acknowledged: sources(&binding.acknowledged),
            remaining: sources(&binding.remaining),
        }),
        h_decision: match snapshot.h_decision {
            core::HDecision::NotRequested => wire::SmHDecision::NotRequested,
            core::HDecision::Invalid => wire::SmHDecision::Invalid,
            core::HDecision::Prefix(count) => wire::SmHDecision::Prefix {
                count: u32::try_from(count).expect("bounded SM prefix"),
            },
        },
        knowledge: match &snapshot.knowledge {
            core::Knowledge::NotRequested => wire::SmKnowledge::NotRequested,
            core::Knowledge::NoCommitRequested => wire::SmKnowledge::NoCommitRequested,
            core::Knowledge::NoPersistence => wire::SmKnowledge::NoPersistence,
            core::Knowledge::RollbackCallEntered => wire::SmKnowledge::RollbackCallEntered,
            core::Knowledge::RollbackKnown => wire::SmKnowledge::RollbackKnown,
            core::Knowledge::CommitCallEntered(value) => {
                wire::SmKnowledge::CommitCallEntered { fact: fact(value) }
            }
            core::Knowledge::ReceiptKnown(value) => {
                wire::SmKnowledge::ReceiptKnown { fact: fact(value) }
            }
        },
        appended: snapshot.appended,
        restored: snapshot.restored,
        ownership_applied: snapshot.ownership_applied,
        acknowledged_h_applied: snapshot.acknowledged_h_applied,
        notification_attempted: snapshot.notification_attempted,
        capacity_completed: snapshot.capacity_completed,
        returned_updated: snapshot.returned_updated,
        returned_error: snapshot.returned_error,
        record_managed_by_sm: managed,
        terminal: snapshot.terminal.map(|terminal| match terminal {
            core::Terminal::Returned => "Returned",
            core::Terminal::Cancelled => "Cancelled",
            core::Terminal::Panicked => "Panicked",
        }),
    }
}
struct TurnLog {
    observation: core::Observation,
    sequence: Sequence,
    capture: bool,
    prefixes: Mutex<Vec<wire::SmPrefix>>,
    polls: Mutex<Vec<wire::DriverPoll>>,
    managed: Mutex<Option<bool>>,
    final_captured: AtomicBool,
}
impl TurnLog {
    fn new(observation: core::Observation, sequence: Sequence, capture: bool) -> Self {
        Self {
            observation,
            sequence,
            capture,
            prefixes: Mutex::new(vec![]),
            polls: Mutex::new(vec![]),
            managed: Mutex::new(None),
            final_captured: AtomicBool::new(false),
        }
    }
    fn prefix(&self) {
        if !self.capture {
            return;
        }
        let state = state(&self.observation, *self.managed.lock().unwrap());
        if state.terminal.is_some() {
            self.final_captured.store(true, Ordering::SeqCst);
        }
        self.prefixes.lock().unwrap().push(wire::SmPrefix {
            seq: next(&self.sequence),
            state,
        });
    }
    fn final_prefix(&self) {
        if !self.final_captured.load(Ordering::SeqCst)
            && self.observation.snapshot().terminal.is_some()
        {
            self.prefix();
        }
    }
    fn evidence(&self) -> wire::SmEvidence {
        wire::SmEvidence {
            state: state(&self.observation, *self.managed.lock().unwrap()),
            prefixes: self.prefixes.lock().unwrap().clone(),
            polls: self.polls.lock().unwrap().clone(),
        }
    }
}
struct Port {
    governor: Option<Arc<SmMemoryGovernor>>,
    replies: Arc<Mutex<VecDeque<wire::CheckpointReply>>>,
    log: Option<Arc<TurnLog>>,
    pending: Arc<AtomicBool>,
}
impl Port {
    fn log(&self) -> &TurnLog {
        self.log
            .as_deref()
            .expect("SM owner retained before child poll")
    }
    async fn completion(&self, cut: wire::CommitCut) -> std::io::Result<()> {
        self.log().prefix();
        match cut {
            wire::CommitCut::Complete => Ok(()),
            wire::CommitCut::Error => Err(std::io::Error::other("controlled SM COMMIT error")),
            wire::CommitCut::Pending => {
                self.pending.store(true, Ordering::SeqCst);
                std::future::pending().await
            }
        }
    }
}
impl SmOwnerPort for Port {
    fn recorded(&self) {
        self.log().prefix();
    }
    fn reserve_snapshot(&self, bytes: usize) -> Result<SmCapacityLease> {
        Ok(self
            .governor
            .as_ref()
            .context("disabled SM requested capacity")?
            .try_reserve_live(bytes)?)
    }
    fn grow(&self, lease: &SmCapacityLease, bytes: usize) -> Result<()> {
        Ok(lease.try_grow_to(bytes)?)
    }
    fn shrink(&self, lease: &SmCapacityLease, bytes: usize) -> Result<()> {
        Ok(lease.shrink_to(bytes)?)
    }
    async fn checkpoint(&self, prepared: &PreparedCheckpoint<'_>) -> Result<SmCheckpointOutcome> {
        prepared.validate_projection(
            prepared.session_id(),
            prepared.connection_id(),
            SnapshotProjection::from(prepared.snapshot()),
            prepared.acknowledged(),
            prepared.policy(),
        )?;
        let reply = self
            .replies
            .lock()
            .unwrap()
            .pop_front()
            .context("unexpected SM persistence invocation")?;
        if !reply.updated {
            core::rollback_observed(self.completion(reply.commit), prepared.request()).await?;
            self.log().prefix();
            return Ok(SmCheckpointOutcome {
                updated: false,
                ownership: SmQueueOwnershipResolution::default(),
            });
        }
        let rotations = reply
            .rotations
            .iter()
            .map(|rotation| {
                Ok(core::MixRotation {
                    previous: rotation
                        .previous
                        .actual()
                        .mix()
                        .context("SM rotation previous family")?,
                    current: rotation
                        .current
                        .actual()
                        .mix()
                        .context("SM rotation current family")?,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let settled = prepared
            .acknowledged()
            .iter()
            .filter_map(|entry| entry.source)
            .collect();
        core::commit_observed(
            self.completion(reply.commit),
            prepared.request(),
            core::CommitFact::Checkpoint {
                rotations: rotations.clone(),
                settled,
            },
        )
        .await?;
        self.log().prefix();
        Ok(SmCheckpointOutcome {
            updated: true,
            ownership: SmQueueOwnershipResolution {
                mix_rotations: rotations
                    .into_iter()
                    .map(|rotation| crate::services::sm::SmMixLeaseRotation {
                        previous: rotation.previous,
                        current: rotation.current,
                    })
                    .collect(),
            },
        })
    }
    async fn acknowledge_batch(&self, _: &PreparedBatch<'_>) -> Result<()> {
        anyhow::bail!("saved profile does not contain an unpersisted SM ACK")
    }
}

/// One receiving stream's actual state. Its observation handles remain valid
/// after the current-operation slot is replaced by later records or ACK.
pub(super) struct Recorder {
    pub(super) sm: SmSubstate,
    metadata: SmMetadata,
    policy: SmRuntimePolicy,
    connection_id: Uuid,
    governor: Option<Arc<SmMemoryGovernor>>,
    replies: Arc<Mutex<VecDeque<wire::CheckpointReply>>>,
    sequence: Sequence,
    capture: bool,
    logs: Vec<Arc<TurnLog>>,
    pending: Arc<AtomicBool>,
}
impl Recorder {
    pub(super) fn new(
        connection_id: Uuid,
        config: Option<&wire::SmConfig>,
        replies: &[wire::CheckpointReply],
        sequence: Sequence,
    ) -> Result<Self> {
        let mut metadata = SmMetadata::default();
        let mut sm = SmSubstate::default();
        let mut policy = SmRuntimePolicy {
            session: crate::state::SmSessionPolicy {
                require_same_device: true,
                resume_timeout_seconds: 60,
                live_lease_seconds: 30,
                claim_lease_seconds: 10,
                max_per_account: 4,
                max_global: 100,
            },
            buffer: crate::state::SmBufferLimits {
                max_unacked_stanzas: 32,
                max_unacked_bytes: 16_384,
                max_snapshot_bytes: 32_768,
            },
            ip_binding: "none".into(),
        };
        let governor = if let Some(config) = config {
            metadata.peer_ip = Some(config.peer_ip.parse()?);
            sm.enabled = config.enabled;
            sm.db_id = config.session_id.get().map(|id| id.0);
            sm.resume_allowed = config.resume_allowed;
            sm.resume_timeout_seconds = config.resume_timeout_seconds;
            sm.inbound_h = config.inbound_h;
            sm.outbound_h = config.outbound_h;
            sm.acked_h = config.acked_h;
            *sm.session_id_shared.write().unwrap() = sm.db_id;
            policy = SmRuntimePolicy {
                session: crate::state::SmSessionPolicy {
                    require_same_device: config.require_same_device,
                    resume_timeout_seconds: config.resume_timeout_seconds,
                    live_lease_seconds: config.live_lease_seconds,
                    claim_lease_seconds: config.claim_lease_seconds,
                    max_per_account: config.max_per_account as usize,
                    max_global: config.max_global as usize,
                },
                buffer: crate::state::SmBufferLimits {
                    max_unacked_stanzas: config.max_unacked_stanzas as usize,
                    max_unacked_bytes: config.max_unacked_bytes as usize,
                    max_snapshot_bytes: config.max_snapshot_bytes as usize,
                },
                ip_binding: config.ip_binding.clone(),
            };
            let value = &config.governor;
            let governor = SmMemoryGovernor::new(
                value.max_bytes as usize,
                value.max_recovery_bytes as usize,
                value.max_recovery_jobs as usize,
                value.max_snapshot_bytes as usize,
                Arc::new(SmCapacityMetrics::default()),
            )?;
            if sm.enabled {
                sm.capacity = Some(
                    governor.try_reserve_live(
                        metadata
                            .view()
                            .resident_bytes(&sm)
                            .context("SM initial resident size")?,
                    )?,
                );
            }
            Some(governor)
        } else {
            None
        };
        Ok(Self {
            sm,
            metadata,
            policy,
            connection_id,
            governor,
            replies: Arc::new(Mutex::new(replies.iter().cloned().collect())),
            sequence,
            capture: config.is_some(),
            logs: vec![],
            pending: Arc::new(AtomicBool::new(false)),
        })
    }
    pub(super) async fn record(&mut self, item: &OutboundItem) -> Result<bool> {
        self.pending.store(false, Ordering::SeqCst);
        let mut turn = SmTransportTurn {
            sm: &mut self.sm,
            view: self.metadata.view(),
            policy: &self.policy,
            connection_id: self.connection_id,
            port: Port {
                governor: self.governor.clone(),
                replies: self.replies.clone(),
                log: None,
                pending: self.pending.clone(),
            },
        };
        let observation = turn.start(core::Purpose::Record);
        let log = Arc::new(TurnLog::new(
            observation.clone(),
            self.sequence.clone(),
            self.capture,
        ));
        turn.port.log = Some(log.clone());
        self.logs.push(log.clone());
        // Only the enclosing native/BOSH driver polls this nested runner.
        let result = SmTurnRunner::new(observation.clone(), async move {
            let result = turn.record_item(item, &observation).await;
            if result.is_err() {
                observation.returned_error();
            }
            result
        })
        .await;
        *log.managed.lock().unwrap() = result.as_ref().ok().copied();
        log.final_prefix();
        result
    }
    pub(super) async fn acknowledge(&mut self, ack: &wire::SmAck) -> Result<()> {
        let mut turn = SmTransportTurn {
            sm: &mut self.sm,
            view: self.metadata.view(),
            policy: &self.policy,
            connection_id: self.connection_id,
            port: Port {
                governor: self.governor.clone(),
                replies: Arc::new(Mutex::new(VecDeque::from([ack.reply.clone()]))),
                log: None,
                pending: self.pending.clone(),
            },
        };
        let observation = turn.start(core::Purpose::Acknowledge { h: ack.h });
        let log = Arc::new(TurnLog::new(
            observation.clone(),
            self.sequence.clone(),
            true,
        ));
        turn.port.log = Some(log.clone());
        self.logs.push(log.clone());
        let child = async move {
            let result = turn.acknowledge(ack.h, &observation).await;
            if result.is_err() {
                observation.returned_error();
            }
            result
        };
        let mut runner = Box::pin(SmTurnRunner::new(log.observation.clone(), child));
        let actual = futures::poll!(&mut runner);
        log.polls
            .lock()
            .unwrap()
            .push(self.sequence.lock().unwrap().polled(&actual));
        drop(runner);
        log.final_prefix();
        match actual {
            std::task::Poll::Ready(Ok(true)) => Ok(()),
            std::task::Poll::Ready(Ok(false)) => anyhow::bail!("saved SM ACK h was not accepted"),
            std::task::Poll::Ready(Err(error)) => Err(error),
            std::task::Poll::Pending => anyhow::bail!("unexpected pending saved SM ACK"),
        }
    }
    pub(super) fn governor(&self) -> Option<Arc<SmMemoryGovernor>> {
        self.governor.clone()
    }
    pub(super) fn pending_marker(&self) -> Arc<AtomicBool> {
        self.pending.clone()
    }
    pub(super) fn capture_retired(&self) {
        for log in &self.logs {
            log.final_prefix();
        }
    }
    pub(super) fn evidence(&self) -> Vec<wire::SmEvidence> {
        self.logs
            .iter()
            .filter(|log| log.capture)
            .map(|log| log.evidence())
            .collect()
    }
    pub(super) fn fifo(&self) -> Vec<wire::Slot> {
        self.sm
            .unacked
            .iter()
            .map(|entry| wire::Slot {
                xml: entry.stanza.clone(),
                source: entry.source.map(Into::into),
            })
            .collect()
    }
    pub(super) fn replies_exhausted(&self) -> bool {
        self.replies.lock().unwrap().is_empty()
    }
}
impl crate::bosh::BoshRecordPort for Recorder {
    async fn record(&mut self, item: &OutboundItem) -> Result<bool> {
        Recorder::record(self, item).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn config() -> wire::SmConfig {
        wire::SmConfig {
            session_id: wire::Nullable::Value(wire::Id(Uuid::from_u128(4))),
            enabled: true,
            resume_allowed: true,
            inbound_h: 2,
            outbound_h: 0,
            acked_h: 0,
            resume_timeout_seconds: 60,
            live_lease_seconds: 30,
            claim_lease_seconds: 10,
            require_same_device: true,
            max_per_account: 4,
            max_global: 100,
            max_unacked_stanzas: 32,
            max_unacked_bytes: 16_384,
            max_snapshot_bytes: 32_768,
            ip_binding: "none".into(),
            peer_ip: "127.0.0.1".into(),
            governor: wire::Governor {
                max_bytes: 65_536,
                max_recovery_bytes: 32_768,
                max_recovery_jobs: 4,
                max_snapshot_bytes: 32_768,
            },
        }
    }
    fn reply(commit: wire::CommitCut) -> wire::CheckpointReply {
        wire::CheckpointReply {
            commit,
            updated: true,
            rotations: vec![],
        }
    }

    #[test]
    fn shared_governor_keeps_existing_live_charge_during_response_reservation() {
        let recorder = Recorder::new(
            Uuid::from_u128(3),
            Some(&config()),
            &[],
            Arc::new(Mutex::new(wire::Sequence::default())),
        )
        .unwrap();
        let governor = recorder.governor().unwrap();
        assert!(Arc::ptr_eq(&governor, recorder.governor.as_ref().unwrap()));
        let live_bytes = recorder.sm.capacity.as_ref().unwrap().reserved_bytes();
        assert!(live_bytes > 0);
        assert_eq!(
            governor.metrics().reserved_bytes.load(Ordering::SeqCst),
            live_bytes as u64
        );
        let response = governor.try_reserve_transient(4096).unwrap();
        assert_eq!(
            governor.metrics().reserved_bytes.load(Ordering::SeqCst),
            (live_bytes + 4096) as u64
        );
        drop(response);
        assert_eq!(
            governor.metrics().reserved_bytes.load(Ordering::SeqCst),
            live_bytes as u64
        );
        drop(recorder);
        assert_eq!(governor.metrics().reserved_bytes.load(Ordering::SeqCst), 0);
    }

    // Isolated recorder/governor regression, not an ordinary alias for a saved
    // original/application/router/native/BOSH case or the ignored entry.
    #[tokio::test]
    async fn initial_live_charge_and_retired_record_handles_use_actual_sm_state() {
        let sequence = Arc::new(Mutex::new(wire::Sequence::default()));
        let mut recorder = Recorder::new(
            Uuid::from_u128(3),
            Some(&config()),
            &[
                reply(wire::CommitCut::Complete),
                reply(wire::CommitCut::Complete),
            ],
            sequence,
        )
        .unwrap();
        assert_eq!(
            recorder.sm.capacity.as_ref().unwrap().reserved_bytes(),
            recorder
                .metadata
                .view()
                .resident_bytes(&recorder.sm)
                .unwrap()
        );
        assert!(!recorder
            .record(&OutboundItem::plain("<message id='one'/>".into()))
            .await
            .unwrap());
        let old = recorder.logs[0].observation.clone();
        let before = old.snapshot();
        assert_eq!(before.terminal, Some(core::Terminal::Returned));
        assert!(matches!(before.knowledge, core::Knowledge::ReceiptKnown(_)));
        assert!(!recorder
            .record(&OutboundItem::plain("<message id='two'/>".into()))
            .await
            .unwrap());
        assert_eq!(old.snapshot(), before);
        assert_eq!(
            (
                recorder.sm.outbound_h,
                recorder.sm.acked_h,
                recorder.sm.unacked.len()
            ),
            (2, 0, 2)
        );
        assert!(recorder.sm.unacked.iter().all(|item| item.source.is_none()));
        assert_eq!(
            recorder.sm.capacity.as_ref().unwrap().reserved_bytes(),
            recorder
                .metadata
                .view()
                .resident_bytes(&recorder.sm)
                .unwrap()
        );
        let evidence = recorder.evidence();
        assert_eq!(evidence.len(), 2);
        for turn in evidence {
            assert!(turn.polls.is_empty());
            assert_eq!(turn.state.record_managed_by_sm, Some(false));
            let entered = turn
                .prefixes
                .iter()
                .position(|prefix| {
                    matches!(
                        prefix.state.knowledge,
                        wire::SmKnowledge::CommitCallEntered { .. }
                    )
                })
                .unwrap();
            let receipt = turn
                .prefixes
                .iter()
                .position(|prefix| {
                    matches!(
                        prefix.state.knowledge,
                        wire::SmKnowledge::ReceiptKnown { .. }
                    )
                })
                .unwrap();
            assert!(entered < receipt);
            assert_eq!(
                turn.prefixes.last().unwrap().state.terminal,
                Some("Returned")
            );
            assert!(turn.prefixes[receipt].state.terminal.is_none());
        }
    }

    #[tokio::test]
    async fn cancelled_record_keeps_actual_checkpoint_entry_and_no_nested_poll() {
        let sequence = Arc::new(Mutex::new(wire::Sequence::default()));
        let mut recorder = Recorder::new(
            Uuid::from_u128(3),
            Some(&config()),
            &[reply(wire::CommitCut::Pending)],
            sequence,
        )
        .unwrap();
        let marker = recorder.pending_marker();
        let item = OutboundItem::plain("<message id='pending'/>".into());
        let mut future = Box::pin(recorder.record(&item));
        assert!(futures::poll!(&mut future).is_pending());
        assert!(marker.load(Ordering::SeqCst));
        drop(future);
        recorder.capture_retired();
        assert_eq!((recorder.sm.outbound_h, recorder.sm.acked_h), (1, 0));
        assert_eq!(recorder.sm.unacked.front().unwrap().stanza, item.stanza);
        let evidence = recorder.evidence();
        assert_eq!(evidence.len(), 1);
        assert!(evidence[0].polls.is_empty());
        assert!(matches!(
            evidence[0].state.knowledge,
            wire::SmKnowledge::CommitCallEntered { .. }
        ));
        assert_eq!(evidence[0].state.record_managed_by_sm, None);
        assert_eq!(evidence[0].state.terminal, Some("Cancelled"));
        assert_eq!(
            evidence[0].prefixes.last().unwrap().state.terminal,
            Some("Cancelled")
        );
        assert!(!evidence[0].state.restored);
    }
}
