//! Single ignored, bounded saved-input composition entry. Repository effects
//! and writer responses are controlled; production preparation and owners run.
//! This first checkpoint supports only None/native recipients, not full Stage3.
use super::*;
use crate::direct_replay as wire;
use crate::outbound::{
    DurableDelivery, OutboundItem, OutboundSender, RouteEnqueue, RouteSendError,
    TransportOwnershipSource,
};
use crate::services::message_admission::{
    self,
    witness::{self, AdmissionWitness},
    MessageAdmissionRepository, MessageAdmissionService,
};
use crate::services::messaging::{
    DirectMessageRoutePort, FullJidFallbackPort, OnlineRoutePort, OnlineRouteResult,
};
use northstar_abuse_policy::{
    admission_execution as admission, admission_transaction::FinalizeDecision,
};
use northstar_message_application::{
    direct_commit, direct_handoff, direct_lifecycle, MessageApplication,
    PersonalMessageCommitRepository,
};
use std::{
    collections::VecDeque,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
};
use uuid::Uuid;

type Sequence = Arc<Mutex<wire::Sequence>>;
fn next(sequence: &Sequence) -> u32 {
    sequence.lock().unwrap().next()
}
fn actual_mode(mode: DirectPostCommitMode) -> wire::Mode {
    match mode {
        DirectPostCommitMode::Live => wire::Mode::Live,
        DirectPostCommitMode::SpoolOnly => wire::Mode::SpoolOnly,
        DirectPostCommitMode::Rejected => panic!("unexpected rejected returned mode"),
    }
}
fn transaction(value: &direct_commit::TransactionOutcome) -> wire::Transaction {
    match value {
        direct_commit::TransactionOutcome::Stored {
            recipient_id,
            delivery_id,
            archive_ids,
            live_claim_id,
        } => wire::Transaction::Stored {
            recipient_id: wire::Id(*recipient_id),
            delivery_id: wire::Id(*delivery_id),
            archive_ids: archive_ids.iter().copied().map(wire::Id).collect(),
            live_claim_id: live_claim_id.map_or(wire::Nullable::Null(()), |id| {
                wire::Nullable::Value(wire::Id(id))
            }),
        },
        direct_commit::TransactionOutcome::Replay { archive_ids } => wire::Transaction::Replay {
            archive_ids: archive_ids.iter().copied().map(wire::Id).collect(),
        },
        direct_commit::TransactionOutcome::AccountUnavailable => {
            wire::Transaction::AccountUnavailable {}
        }
    }
}
fn direct_prepared(value: &direct_commit::PreparedCommit) -> wire::DirectPrepared {
    wire::DirectPrepared {
        correlation: value.correlation.into(),
        transaction: transaction(&value.outcome),
        admitted_mode: actual_mode(value.admitted_mode),
    }
}
fn admission_commit(
    correlation: admission::Correlation,
    scope: admission::TransactionScope,
    fact: &admission::CommitFact,
) -> wire::AdmissionCommit {
    let scope = match scope {
        admission::TransactionScope::RatedBegin(admission::BeginCommitPurpose::NewReservation) => {
            "RatedBeginNewReservation"
        }
        admission::TransactionScope::AdmissionFinalize => "AdmissionFinalize",
        _ => panic!("unexpected admission scope"),
    };
    let fact = match fact {
        admission::CommitFact::Reserved(fence) => wire::AdmissionFact::Reserved {
            fence: fence.into(),
        },
        admission::CommitFact::Finalized {
            fence,
            result: admission::FinalizeSuccess::PendingAccepted,
        } => wire::AdmissionFact::Finalized {
            fence: fence.into(),
            result: "PendingAccepted",
        },
        _ => panic!("unexpected admission fact"),
    };
    wire::AdmissionCommit {
        correlation: correlation.into(),
        scope,
        fact,
    }
}
fn admission_state(value: direct_lifecycle::AdmissionSnapshot) -> wire::AdmissionEvidence {
    let knowledge = match value.witness.knowledge() {
        admission::Knowledge::NoCommitRequested => wire::AdmissionKnowledge::NoCommitRequested,
        admission::Knowledge::CommitCallEntered(prepared) => {
            wire::AdmissionKnowledge::CommitCallEntered {
                prepared: admission_commit(prepared.correlation, prepared.scope, &prepared.fact),
            }
        }
        admission::Knowledge::ReceiptKnown(receipt) => wire::AdmissionKnowledge::ReceiptKnown {
            receipt: admission_commit(receipt.correlation, receipt.scope, &receipt.fact),
        },
    };
    let returned = match value.state {
        admission::ExecutionState::Waiting(_) => None,
        admission::ExecutionState::Finished(admission::ExecutionOutcome::Completed {
            result: admission::EffectResult::Begin(admission::BeginResult::Reserved(fence)),
            ..
        }) => Some(wire::AdmissionReturned::Proceed {
            fence: (&fence).into(),
        }),
        admission::ExecutionState::Finished(admission::ExecutionOutcome::Completed {
            result: admission::EffectResult::Finalize(FinalizeDecision::AcceptPending),
            ..
        }) => Some(wire::AdmissionReturned::AcceptPending),
        admission::ExecutionState::Finished(_) => Some(wire::AdmissionReturned::Error),
    };
    wire::AdmissionEvidence {
        correlation: value.effect.correlation.into(),
        started: value.effect_started,
        knowledge,
        returned,
    }
}
fn handoff(value: direct_handoff::Snapshot) -> wire::Handoff {
    wire::Handoff {
        correlation: value.correlation.into(),
        source: TransportOwnershipSource::C2s(value.source).into(),
        local_call: match value.local_call {
            direct_handoff::LocalKnowledge::NotRequested => "NotRequested",
            direct_handoff::LocalKnowledge::CallEntered => "CallEntered",
            direct_handoff::LocalKnowledge::Refused => "Refused",
            direct_handoff::LocalKnowledge::Accepted => "Accepted",
        },
        local_accepted: value.local_accepted,
        last_local_refusal: value.last_local_refusal.map(|value| match value {
            direct_handoff::Refusal::Full => "Full",
            direct_handoff::Refusal::Closed => "Closed",
        }),
        remote: match value.remote {
            direct_handoff::RemoteKnowledge::NotRequested => "NotRequested",
            direct_handoff::RemoteKnowledge::CallEntered => "CallEntered",
            direct_handoff::RemoteKnowledge::NoPositiveReceipt => "NoPositiveReceipt",
            direct_handoff::RemoteKnowledge::AcceptanceReported => "AcceptanceReported",
        },
        prior_remote_uncertain: value.prior_remote_uncertain,
        rearm: match value.rearm {
            direct_handoff::RearmKnowledge::NotRequested => "NotRequested",
            direct_handoff::RearmKnowledge::CallEntered => "CallEntered",
            direct_handoff::RearmKnowledge::CallReturned => "CallReturned",
        },
        route_end: match value.route_end {
            direct_handoff::RouteEnd::NotStarted => "NotStarted",
            direct_handoff::RouteEnd::Running => "Running",
            direct_handoff::RouteEnd::Returned => "Returned",
            direct_handoff::RouteEnd::Dropped => "Dropped",
        },
        retired: value.retired,
    }
}
fn original_state(owner: &DirectOperationHandle) -> wire::OriginalState {
    let value = owner.snapshot();
    let direct = value.direct.map(|value| {
        let knowledge = match &value.knowledge {
            direct_commit::Knowledge::NoCommitRequested => wire::DirectKnowledge::NoCommitRequested,
            direct_commit::Knowledge::CommitCallEntered(prepared) => {
                wire::DirectKnowledge::CommitCallEntered {
                    prepared: direct_prepared(prepared),
                }
            }
            direct_commit::Knowledge::ReceiptKnown(receipt) => {
                wire::DirectKnowledge::ReceiptKnown {
                    receipt: wire::DirectReceipt {
                        prepared: direct_prepared(&receipt.prepared),
                    },
                }
            }
        };
        let returned = match &value.outcome {
            Some(direct_commit::ExecutionOutcome::Completed(returned)) => {
                Some(wire::DirectReturned {
                    commit: match &returned.commit {
                        northstar_message_core::MessageCommit::Stored {
                            archive_written,
                            post_commit:
                                MessagePostCommit::RouteLocalDelivery {
                                    recipient_id,
                                    delivery_id,
                                },
                        } => wire::CommitResult::Stored {
                            archive_written: *archive_written,
                            recipient_id: wire::Id(*recipient_id),
                            delivery_id: wire::Id(*delivery_id),
                        },
                        northstar_message_core::MessageCommit::Replay => wire::CommitResult::Replay,
                        northstar_message_core::MessageCommit::AccountUnavailable => {
                            wire::CommitResult::AccountUnavailable
                        }
                        _ => panic!("unexpected local direct result"),
                    },
                    mode: actual_mode(returned.mode),
                    live_claim_id: returned.live_claim_id.map(wire::Id),
                })
            }
            _ => None,
        };
        let preserved_transaction = match &value.outcome {
            Some(direct_commit::ExecutionOutcome::ReceiptPreserved(receipt)) => {
                Some(transaction(&receipt.prepared.outcome))
            }
            _ => None,
        };
        wire::DirectEvidence {
            correlation: value.effect.correlation().into(),
            started: value.started,
            knowledge,
            returned,
            preserved_transaction,
            application_error: value.outcome.is_some()
                && !matches!(
                    value.outcome,
                    Some(direct_commit::ExecutionOutcome::Completed(_))
                ),
        }
    });
    wire::OriginalState {
        begin: value.reservation.map(admission_state),
        finalize: value.finalization.map(admission_state),
        direct,
        handoff: value.handoff.map(handoff),
        terminal: value.terminal.map(|value| match value {
            direct_lifecycle::TerminalReason::Completed => "Completed",
            direct_lifecycle::TerminalReason::BackendFailure => "BackendFailure",
            direct_lifecycle::TerminalReason::TimedOut => "TimedOut",
            direct_lifecycle::TerminalReason::Cancelled => "Cancelled",
            direct_lifecycle::TerminalReason::Panicked => "Panicked",
        }),
    }
}

struct FrameLog {
    owner: DirectOperationHandle,
    sequence: Sequence,
    prefixes: Mutex<Vec<wire::OriginalPrefix>>,
    route: Mutex<wire::RouteEvidence>,
    routing: AtomicBool,
    direct_pending: AtomicBool,
    rearm_pending: AtomicBool,
}
impl FrameLog {
    fn prefix(&self) {
        let state = original_state(&self.owner);
        let seq = next(&self.sequence);
        self.prefixes
            .lock()
            .unwrap()
            .push(wire::OriginalPrefix { seq, state });
    }
}
struct AdmissionPort<'a> {
    plan: &'a wire::Admission,
    log: Arc<FrameLog>,
}
impl MessageAdmissionRepository for AdmissionPort<'_> {
    async fn begin(
        &self,
        _: &MessageAdmissionRequest<'_>,
        observation: &AdmissionWitness,
    ) -> Result<MessageAdmissionStart> {
        let wire::Admission::Reserved {
            fence,
            requirement,
            begin_commit,
            ..
        } = self.plan
        else {
            anyhow::bail!("unexpected rated admission call");
        };
        let lease = crate::abuse::MessageAdmissionLease::new(
            wire::unhex(&fence.admission_key_hex).map_err(|_| anyhow::anyhow!("invalid fence"))?,
            wire::unhex(&fence.payload_mac_hex).map_err(|_| anyhow::anyhow!("invalid fence"))?,
            fence.lease_token.0,
            crate::abuse::MessageDedupeIdentity {
                identity_digest: wire::unhex(&fence.dedupe_digest_hex)
                    .map_err(|_| anyhow::anyhow!("invalid dedupe binding"))?,
                candidates: vec![],
            },
        );
        let fact = admission::CommitFact::Reserved(message_admission::acceptance_fence(
            &lease.acceptance(),
        ));
        witness::saved_case_commit_observed(
            async {
                self.log.prefix();
                match begin_commit {
                    wire::CommitCut::Complete => Ok(()),
                    wire::CommitCut::Pending => std::future::pending().await,
                    wire::CommitCut::Error => anyhow::bail!("controlled admission COMMIT error"),
                }
            },
            observation,
            admission::TransactionScope::RatedBegin(admission::BeginCommitPurpose::NewReservation),
            fact,
        )
        .await?;
        self.log.prefix();
        Ok(MessageAdmissionStart::Proceed {
            lease: Some(lease),
            requirement: crate::abuse::WorkRequirement {
                action: requirement.action.clone(),
                step: requirement.step,
                work_factor: requirement.work_factor,
                max_work_factor: requirement.max_work_factor,
                hard_wait_seconds: requirement.hard_wait_seconds,
                retry_after_seconds: requirement.retry_after_seconds,
                cooldown_seconds: requirement.cooldown_seconds,
                approximate_max_device_seconds: requirement.approximate_max_device_seconds,
                notice: requirement.notice.clone(),
            },
        })
    }
    async fn accept(
        &self,
        acceptance: &crate::abuse::MessageAdmissionAcceptance<'_>,
        observation: &AdmissionWitness,
    ) -> Result<FinalizeDecision> {
        let wire::Admission::Reserved {
            finalize_commit, ..
        } = self.plan
        else {
            anyhow::bail!("unexpected finalization");
        };
        witness::saved_case_commit_observed(
            async {
                self.log.prefix();
                match finalize_commit {
                    wire::CommitCut::Complete => Ok(()),
                    wire::CommitCut::Pending => std::future::pending().await,
                    wire::CommitCut::Error => anyhow::bail!("controlled finalization COMMIT error"),
                }
            },
            observation,
            admission::TransactionScope::AdmissionFinalize,
            admission::CommitFact::Finalized {
                fence: message_admission::acceptance_fence(acceptance),
                result: admission::FinalizeSuccess::PendingAccepted,
            },
        )
        .await?;
        self.log.prefix();
        Ok(FinalizeDecision::AcceptPending)
    }
    async fn reconcile(&self, _: &admission::Effect) -> Result<admission::ReconcileResult> {
        anyhow::bail!("unexpected reconciliation")
    }
}
struct DirectPort<'a> {
    plan: &'a wire::DirectRepository,
    log: Arc<FrameLog>,
    row: Arc<Mutex<Option<DurableDelivery>>>,
}
impl PersonalMessageCommitRepository for DirectPort<'_> {
    type Error = anyhow::Error;
    async fn commit<'a>(
        &'a self,
        _: &'a ValidatedPersonalMessage<'a>,
    ) -> Result<northstar_message_core::MessageCommit> {
        anyhow::bail!("unexpected legacy application call")
    }
}
impl direct_commit::DirectCommitRepository for DirectPort<'_> {
    type Error = anyhow::Error;
    async fn commit_direct<'a>(
        &'a self,
        command: &'a ValidatedPersonalMessage<'a>,
        _: DirectSpoolEligibility,
        observer: Option<&'a dyn direct_commit::DirectCommitObserver>,
    ) -> Result<northstar_message_core::DirectPersonalMessageAdmission> {
        let outcome = match &self.plan.transaction {
            wire::Transaction::Stored {
                recipient_id,
                delivery_id,
                archive_ids,
                live_claim_id,
            } => direct_commit::TransactionOutcome::Stored {
                recipient_id: recipient_id.0,
                delivery_id: delivery_id.0,
                archive_ids: archive_ids.iter().map(|id| id.0).collect(),
                live_claim_id: live_claim_id.get().map(|id| id.0),
            },
            wire::Transaction::Replay { archive_ids } => {
                direct_commit::TransactionOutcome::Replay {
                    archive_ids: archive_ids.iter().map(|id| id.0).collect(),
                }
            }
            wire::Transaction::AccountUnavailable {} => {
                direct_commit::TransactionOutcome::AccountUnavailable
            }
        };
        crate::services::messaging::direct_workflow::commit_observed(
            async {
                self.log.prefix();
                match self.plan.commit {
                    wire::CommitCut::Pending => {
                        self.log.direct_pending.store(true, Ordering::SeqCst);
                        std::future::pending::<Result<()>>().await
                    }
                    wire::CommitCut::Error => anyhow::bail!("controlled direct COMMIT error"),
                    wire::CommitCut::Complete => {
                        if let direct_commit::TransactionOutcome::Stored {
                            recipient_id,
                            delivery_id,
                            live_claim_id,
                            ..
                        } = &outcome
                        {
                            *self.row.lock().unwrap() = Some(DurableDelivery {
                                recipient_id: *recipient_id,
                                message_id: *delivery_id,
                                claim_id: *live_claim_id,
                            });
                        }
                        Ok(())
                    }
                }
            },
            observer.ok_or_else(|| anyhow::anyhow!("missing prepared observer"))?,
            outcome.clone(),
            self.plan.admitted_mode.actual(),
        )
        .await?;
        self.log.prefix();
        let wire::Completion::Return { mode } = &self.plan.completion else {
            anyhow::bail!("controlled outer error after receipt");
        };
        let (commit, claim) = match outcome {
            direct_commit::TransactionOutcome::Stored {
                recipient_id,
                delivery_id,
                live_claim_id,
                ..
            } => (
                northstar_message_core::MessageCommit::Stored {
                    archive_written: !command.archives.is_empty(),
                    post_commit: MessagePostCommit::RouteLocalDelivery {
                        recipient_id,
                        delivery_id,
                    },
                },
                live_claim_id,
            ),
            direct_commit::TransactionOutcome::Replay { .. } => {
                (northstar_message_core::MessageCommit::Replay, None)
            }
            direct_commit::TransactionOutcome::AccountUnavailable => (
                northstar_message_core::MessageCommit::AccountUnavailable,
                None,
            ),
        };
        Ok(northstar_message_core::DirectPersonalMessageAdmission {
            commit,
            mode: mode.actual(),
            live_claim_id: claim,
        })
    }
}

struct RoutePort<'a> {
    plan: &'a wire::Route,
    clustered: bool,
    log: Arc<FrameLog>,
    health: Mutex<VecDeque<wire::Mode>>,
    remote: Mutex<VecDeque<bool>>,
}
impl OnlineRoutePort for RoutePort<'_> {
    type Session = OutboundSender;
    fn try_local(
        &self,
        session: &Self::Session,
        enqueue: RouteEnqueue,
    ) -> Result<(), RouteSendError> {
        let source = enqueue.item().durable_source.expect("direct item source");
        let xml = enqueue.item().stanza.clone();
        let result = session.try_send_route_item(enqueue);
        let label = match &result {
            Ok(()) => "Accepted",
            Err(RouteSendError::Full(_)) => "Full",
            Err(RouteSendError::Closed(_)) => "Closed",
            Err(RouteSendError::Binding(_)) => "BindingRejected",
        };
        let seq = next(&self.log.sequence);
        self.log.route.lock().unwrap().enqueue.push(wire::Enqueue {
            seq,
            source: source.into(),
            xml,
            result: label,
        });
        self.log.prefix();
        result
    }
    fn record_local_accept(&self, _: bool) {
        self.log.prefix();
    }
    async fn route_available_remote(
        &self,
        _: &str,
        _: &str,
        source: Option<DurableDelivery>,
    ) -> bool {
        let value = self
            .remote
            .lock()
            .unwrap()
            .pop_front()
            .expect("unexpected remote route");
        let seq = next(&self.log.sequence);
        self.log
            .route
            .lock()
            .unwrap()
            .remote_calls
            .push(wire::RemoteCall {
                seq,
                source: TransportOwnershipSource::C2s(source.expect("durable remote source"))
                    .into(),
                returned: Some(value),
            });
        value
    }
    async fn route_remote_primary(
        &self,
        jid: &str,
        stanza: &str,
        source: Option<DurableDelivery>,
    ) -> OnlineRouteResult {
        OnlineRouteResult {
            delivered: self.route_available_remote(jid, stanza, source).await,
            accepted_full_jid: None,
        }
    }
}
impl FullJidFallbackPort for RoutePort<'_> {
    fn fallback_sessions(&self, _: &str) -> Vec<(String, Self::Session)> {
        vec![]
    }
    fn available_priority(&self, _: &Self::Session) -> Option<i16> {
        Some(0)
    }
    fn priority(&self, _: &Self::Session) -> i16 {
        0
    }
    async fn privacy_allows_fallback(&self, _: &Self::Session, _: &str) -> Result<bool> {
        anyhow::bail!("unexpected fallback privacy query")
    }
    fn post_accept_failed(&self) {
        self.log.prefix();
    }
}
impl DirectMessageRoutePort for RoutePort<'_> {
    fn direct_route_mode(&self) -> DirectPostCommitMode {
        let mode = self
            .health
            .lock()
            .unwrap()
            .pop_front()
            .expect("unexpected health read");
        let seq = next(&self.log.sequence);
        self.log
            .route
            .lock()
            .unwrap()
            .health_reads
            .push(wire::HealthRead {
                seq,
                phase: if self.log.routing.load(Ordering::SeqCst) {
                    "Router"
                } else {
                    "PostFinalize"
                },
                mode,
            });
        mode.actual()
    }
    fn clustered_direct_routes(&self) -> bool {
        self.clustered
    }
    async fn rearm_direct_route(&self, source: DurableDelivery) {
        let seq = next(&self.log.sequence);
        let index = {
            let mut route = self.log.route.lock().unwrap();
            let index = route.rearm_calls.len();
            route.rearm_calls.push(wire::RearmCall {
                seq,
                source: TransportOwnershipSource::C2s(source).into(),
                returned: false,
            });
            index
        };
        self.log.prefix();
        if self.plan.rearm == wire::Rearm::Pending {
            self.log.rearm_pending.store(true, Ordering::SeqCst);
            std::future::pending::<()>().await;
        }
        self.log.route.lock().unwrap().rearm_calls[index].returned = true;
    }
}

fn native_state(
    observation: &northstar_delivery_core::native_write::Observation,
) -> wire::NativeState {
    use northstar_delivery_core::native_write as n;
    let state = observation.snapshot();
    let fact = |fact: n::AckFact| wire::NativeFact {
        source: fact.source.into(),
        disposition: match fact.disposition {
            n::AckDisposition::Deleted => "Deleted",
            n::AckDisposition::AbsentUnclaimed => "AbsentUnclaimed",
            n::AckDisposition::NoMatchingMix => "NoMatchingMix",
        },
    };
    wire::NativeState {
        original: state.original.map(Into::into),
        preparation: match state.preparation {
            n::Preparation::NotStarted => "NotStarted",
            n::Preparation::Recording => "Recording",
            n::Preparation::FenceCallEntered => "FenceCallEntered",
            n::Preparation::Prepared => "Prepared",
            n::Preparation::Superseded => "Superseded",
            n::Preparation::Failed => "Failed",
        },
        managed_by_sm: state.managed_by_sm,
        fence_entered: state.fence_entered,
        returned_fence: state.returned_fence.map(Into::into),
        writer_entered: state.writer_entered,
        writer_result: state.writer_result.map(|value| match value {
            n::WriterResult::FullWrite => "FullWrite",
            n::WriterResult::Failed => "Failed",
        }),
        write_decision: state.write_decision.map(|value| match value {
            n::WriteDecision::Written => "Written",
            n::WriteDecision::Withhold => "Withhold",
        }),
        ack: match state.ack {
            n::AckKnowledge::NotRequested => wire::NativeAckKnowledge::NotRequested,
            n::AckKnowledge::NoCommitRequested => wire::NativeAckKnowledge::NoCommitRequested,
            n::AckKnowledge::CommitCallEntered(value) => {
                wire::NativeAckKnowledge::CommitCallEntered { fact: fact(value) }
            }
            n::AckKnowledge::ReceiptKnown(value) => {
                wire::NativeAckKnowledge::ReceiptKnown { fact: fact(value) }
            }
        },
        ack_returned: state.ack_returned,
        terminal: state.terminal.map(|value| match value {
            n::Terminal::Returned => "Returned",
            n::Terminal::Cancelled => "Cancelled",
            n::Terminal::Panicked => "Panicked",
        }),
    }
}
struct NativeLog {
    observation: northstar_delivery_core::native_write::Observation,
    sequence: Sequence,
    prefixes: Mutex<Vec<wire::NativePrefix>>,
    writes: Mutex<Vec<wire::WriteCall>>,
    flushes: Mutex<Vec<wire::FlushCall>>,
    acks: Mutex<Vec<wire::AckCall>>,
    ack_pending: AtomicBool,
}
impl NativeLog {
    fn prefix(&self) {
        let state = native_state(&self.observation);
        let seq = next(&self.sequence);
        self.prefixes
            .lock()
            .unwrap()
            .push(wire::NativePrefix { seq, state });
    }
}

#[derive(Default)]
struct SmMetadata {
    available: Option<Arc<AtomicBool>>,
    carbons: AtomicBool,
    priority: std::sync::atomic::AtomicI16,
    blocklist: AtomicBool,
    roster: AtomicBool,
    privacy: std::sync::RwLock<Option<String>>,
    privacy_requested: AtomicBool,
    rooms: dashmap::DashMap<String, crate::state::JoinedMucMembership>,
    directed: dashmap::DashSet<String>,
    presence: std::sync::RwLock<Option<String>>,
}
impl SmMetadata {
    fn view(&self) -> crate::xmpp::protocol::sm_owner::SmSnapshotView<'_> {
        crate::xmpp::protocol::sm_owner::SmSnapshotView {
            available: &self.available,
            carbons: &self.carbons,
            priority: &self.priority,
            blocklist_requested: &self.blocklist,
            roster_requested: &self.roster,
            privacy_active: &self.privacy,
            privacy_requested: &self.privacy_requested,
            peer_ip: &std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            user_agent_id: &None,
            joined_rooms: &self.rooms,
            directed_presence: &self.directed,
            last_presence: &self.presence,
        }
    }
}
struct DisabledSmPort {
    log: Arc<NativeLog>,
}
impl crate::xmpp::protocol::sm_owner::SmOwnerPort for DisabledSmPort {
    fn recorded(&self) {
        self.log.prefix();
    }
    fn reserve_snapshot(&self, _: usize) -> Result<crate::services::sm_capacity::SmCapacityLease> {
        anyhow::bail!("disabled SM requested capacity")
    }
    fn grow(&self, _: &crate::services::sm_capacity::SmCapacityLease, _: usize) -> Result<()> {
        anyhow::bail!("disabled SM requested growth")
    }
    fn shrink(&self, _: &crate::services::sm_capacity::SmCapacityLease, _: usize) -> Result<()> {
        anyhow::bail!("disabled SM requested shrink")
    }
    async fn checkpoint(
        &self,
        _: &crate::services::sm::ownership::PreparedCheckpoint<'_>,
    ) -> Result<crate::services::sm::SmCheckpointOutcome> {
        anyhow::bail!("disabled SM requested persistence")
    }
    async fn acknowledge_batch(
        &self,
        _: &crate::services::sm::ownership::PreparedBatch<'_>,
    ) -> Result<()> {
        anyhow::bail!("disabled SM requested acknowledgement")
    }
}
struct NativePort<'a> {
    spec: &'a wire::NativeSpec,
    row: Arc<Mutex<Option<DurableDelivery>>>,
    log: Arc<NativeLog>,
    sm: crate::xmpp::protocol::SmSubstate,
    metadata: SmMetadata,
    policy: crate::xmpp::protocol::SmRuntimePolicy,
    sm_observations: Vec<northstar_delivery_core::sm_ownership::Observation>,
}
impl crate::xmpp::direct_delivery::DirectWritePort for NativePort<'_> {
    async fn record(&mut self, item: &OutboundItem) -> Result<bool> {
        use crate::xmpp::protocol::sm_owner::{SmTransportTurn, SmTurnRunner};
        let mut turn = SmTransportTurn {
            sm: &mut self.sm,
            view: self.metadata.view(),
            policy: &self.policy,
            connection_id: self.spec.connection_id.0,
            port: DisabledSmPort {
                log: self.log.clone(),
            },
        };
        let observation = turn.start(northstar_delivery_core::sm_ownership::Purpose::Record);
        self.sm_observations.push(observation.clone());
        SmTurnRunner::new(observation.clone(), async move {
            let result = turn.record_item(item, &observation).await;
            if result.is_err() {
                observation.returned_error();
            }
            result
        })
        .await
    }
    async fn fence_c2s(&self, source: DurableDelivery) -> Result<DurableDelivery> {
        self.log.prefix();
        let returned = self
            .spec
            .fence
            .returned_source
            .actual()
            .c2s()
            .ok_or_else(|| anyhow::anyhow!("wrong fence family"))?;
        let mut row = self.row.lock().unwrap();
        anyhow::ensure!(
            *row == Some(source),
            "controlled fence did not own current row"
        );
        *row = Some(returned);
        Ok(returned)
    }
    async fn fence_mix(
        &self,
        _: crate::outbound::MixDelivery,
    ) -> Result<crate::outbound::MixDelivery> {
        anyhow::bail!("unexpected native MIX fence")
    }
    async fn acknowledge_c2s(
        &self,
        request: &northstar_delivery_core::native_write::AckRequest,
    ) -> Result<()> {
        use northstar_delivery_core::native_write::{self, AckDisposition};
        request.validate_source(request.source())?;
        let source = request
            .source()
            .c2s()
            .ok_or_else(|| anyhow::anyhow!("wrong ACK source"))?;
        let seq = next(&self.log.sequence);
        let index = {
            let mut calls = self.log.acks.lock().unwrap();
            let index = calls.len();
            calls.push(wire::AckCall {
                seq,
                source: request.source().into(),
                returned: None,
            });
            index
        };
        self.log.prefix();
        let result: Result<()> = async {
            let current = (*self.row.lock().unwrap())
                .ok_or_else(|| anyhow::anyhow!("claimed row missing"))?;
            anyhow::ensure!(
                current.recipient_id == source.recipient_id
                    && current.message_id == source.message_id,
                "controlled ACK row key mismatch"
            );
            let expected = source
                .claim_id
                .ok_or_else(|| anyhow::anyhow!("native saved fixture requires a fenced claim"))?;
            anyhow::ensure!(
                native_write::claimed_c2s_ack_matches(expected, current.claim_id),
                "offline delivery claim was lost before acknowledgement"
            );
            native_write::commit_observed(
                async {
                    self.log.prefix();
                    match self.spec.ack.commit {
                        wire::CommitCut::Pending => {
                            self.log.ack_pending.store(true, Ordering::SeqCst);
                            std::future::pending::<std::io::Result<()>>().await
                        }
                        wire::CommitCut::Error => {
                            Err(std::io::Error::other("controlled native ACK COMMIT error"))
                        }
                        wire::CommitCut::Complete => {
                            *self.row.lock().unwrap() = None;
                            Ok(())
                        }
                    }
                },
                request,
                AckDisposition::Deleted,
            )
            .await
            .map_err(anyhow::Error::from)
        }
        .await;
        self.log.prefix();
        self.log.acks.lock().unwrap()[index].returned = Some(result.is_ok());
        result
    }
    async fn acknowledge_mix(
        &self,
        _: &northstar_delivery_core::native_write::AckRequest,
    ) -> Result<bool> {
        anyhow::bail!("unexpected native MIX ACK")
    }
    fn connection_id(&self) -> Uuid {
        self.spec.connection_id.0
    }
}

struct ScriptedWriter<'a> {
    script: &'a wire::WriteScript,
    accepted: usize,
    log: Arc<NativeLog>,
}
impl tokio::io::AsyncWrite for ScriptedWriter<'_> {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
        bytes: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let fail = self
            .script
            .fail_after_accepted_bytes
            .get()
            .map(|value| *value as usize);
        let seq = next(&self.log.sequence);
        if fail.is_some_and(|limit| self.accepted >= limit) {
            self.log.writes.lock().unwrap().push(wire::WriteCall {
                seq,
                offered_len: u32::try_from(bytes.len()).expect("bounded writer input"),
                offered_sha256: wire::digest(bytes),
                accepted_bytes_hex: String::new(),
                result: "Error",
            });
            return std::task::Poll::Ready(Err(std::io::Error::other("controlled write error")));
        }
        let count = bytes
            .len()
            .min(self.script.chunk_limit as usize)
            .min(fail.map_or(usize::MAX, |limit| limit - self.accepted));
        self.accepted += count;
        self.log.writes.lock().unwrap().push(wire::WriteCall {
            seq,
            offered_len: u32::try_from(bytes.len()).expect("bounded writer input"),
            offered_sha256: wire::digest(bytes),
            accepted_bytes_hex: wire::hex(&bytes[..count]),
            result: "Accepted",
        });
        std::task::Poll::Ready(Ok(count))
    }
    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let success = self.script.flush == wire::Flush::Ok;
        let seq = next(&self.log.sequence);
        self.log.flushes.lock().unwrap().push(wire::FlushCall {
            seq,
            result: if success { "Ok" } else { "Error" },
        });
        std::task::Poll::Ready(if success {
            Ok(())
        } else {
            Err(std::io::Error::other("controlled flush error"))
        })
    }
    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Err(std::io::Error::other("unexpected writer shutdown")))
    }
}

async fn run_native(
    case: &wire::Case,
    frame_id: wire::Id,
    spec: &wire::NativeSpec,
    item: OutboundItem,
    row: Arc<Mutex<Option<DurableDelivery>>>,
    sequence: Sequence,
) -> Result<(wire::NativeEvidence, bool)> {
    use crate::xmpp::direct_delivery::{DirectWriteLease, NativeWriteRunner};
    // This enclosing callback has now been polled. The real observation is
    // retained before its child prepare/write/ACK future receives a first poll.
    let observation = northstar_delivery_core::native_write::Observation::new(item.durable_source);
    let log = Arc::new(NativeLog {
        observation: observation.clone(),
        sequence,
        prefixes: Mutex::new(vec![]),
        writes: Mutex::new(vec![]),
        flushes: Mutex::new(vec![]),
        acks: Mutex::new(vec![]),
        ack_pending: AtomicBool::new(false),
    });
    let mut port = NativePort {
        spec,
        row,
        log: log.clone(),
        sm: crate::xmpp::protocol::SmSubstate::default(),
        metadata: SmMetadata::default(),
        sm_observations: vec![],
        policy: crate::xmpp::protocol::SmRuntimePolicy {
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
            ip_binding: "none".to_owned(),
        },
    };
    let mut writer = ScriptedWriter {
        script: &spec.write,
        accepted: 0,
        log: log.clone(),
    };
    let child = async {
        let lease = DirectWriteLease::prepare_with(&mut port, &item, &observation).await?;
        let written = lease
            .write(|stanza| crate::xmpp::send(&mut writer, stanza))
            .await?;
        written.settle_with(&port).await;
        Ok::<_, anyhow::Error>(())
    };
    let mut runner = Box::pin(NativeWriteRunner::new(observation.clone(), child));
    let dropped = matches!(&case.drive, wire::Drive::DropNativeAckCommit { frame_id: target } if *target == frame_id);
    let actual = futures::poll!(&mut runner);
    if dropped {
        anyhow::ensure!(
            actual.is_pending() && log.ack_pending.load(Ordering::SeqCst),
            "native ACK drop cut was not reached"
        );
    } else {
        // Write/flush errors are actual writer outcomes, not fixture failures.
        // All non-cut controlled ports are ready; unexpected Pending is not.
        anyhow::ensure!(actual.is_ready(), "unexpected pending native owner");
    }
    drop(runner);
    let state = native_state(&observation);
    // No receipts are fabricated for the actual direct router item.
    anyhow::ensure!(
        item.transport_receipt.is_none() && item.transport_write_receipt.is_none(),
        "unexpected routed-item receipt provenance"
    );
    let evidence = wire::NativeEvidence {
        frame_id,
        connection_id: spec.connection_id,
        state,
        write_calls: log.writes.lock().unwrap().clone(),
        flush_calls: log.flushes.lock().unwrap().clone(),
        ack_calls: log.acks.lock().unwrap().clone(),
        ownership_receipts: vec![],
        write_receipts: vec![],
        prefixes: log.prefixes.lock().unwrap().clone(),
    };
    Ok((evidence, dropped))
}

struct OriginalRun {
    evidence: wire::OriginalEvidence,
    target: Option<OutboundItem>,
    row: Arc<Mutex<Option<DurableDelivery>>>,
    cancelled: bool,
}

async fn run_original(case: &wire::Case, index: usize, sequence: Sequence) -> Result<OriginalRun> {
    use crate::services::messaging::direct_workflow::commit_prepared_application;
    use crate::xmpp::{frame_execution::FrameExecution, protocol::ClientTransport};
    let original = &case.originals[index];
    let ids = &case.identities.originals[index];
    let policy = &case.policy[index];
    let route_plan = &case.route[index];
    let frame =
        FrameExecution::for_saved_case(ClientTransport::Tcp, &original.xml, original.frame_id.0);
    let owner = frame.direct_operation();
    let log = Arc::new(FrameLog {
        owner: owner.clone(),
        sequence,
        prefixes: Mutex::new(vec![]),
        route: Mutex::new(wire::RouteEvidence::default()),
        routing: AtomicBool::new(false),
        direct_pending: AtomicBool::new(false),
        rearm_pending: AtomicBool::new(false),
    });
    let row = Arc::new(Mutex::new(None));
    let admission = MessageAdmissionService::new(AdmissionPort {
        plan: &case.admission[index],
        log: log.clone(),
    });
    let app = MessageApplication::new(DirectPort {
        plan: &case.direct_repository[index],
        log: log.clone(),
        row: row.clone(),
    });
    let port = RoutePort {
        plan: route_plan,
        clustered: policy.clustered,
        log: log.clone(),
        health: Mutex::new(route_plan.health_modes.iter().copied().collect()),
        remote: Mutex::new(route_plan.remote_primary_returns.iter().copied().collect()),
    };
    let (sender, mut receiver) = tokio::sync::mpsc::channel(1);
    let mut prefill_receivers = Vec::new();
    if let Some(wire::Item::Plain {
        xml,
        transport_receipt,
    }) = route_plan.prefill.get()
    {
        let item = if *transport_receipt {
            let (receipt, receiver) = tokio::sync::mpsc::unbounded_channel();
            prefill_receivers.push(receiver);
            OutboundItem::with_transport_receipt(xml.clone(), receipt)
        } else {
            OutboundItem::plain(xml.clone())
        };
        sender
            .try_send(item)
            .map_err(|_| anyhow::anyhow!("failed empty controlled queue prefill"))?;
    }
    let sender = OutboundSender::new(sender);
    let targets = route_plan
        .targets
        .iter()
        .map(|target| (target.jid.clone(), sender.clone()))
        .collect::<Vec<_>>();
    let mut projection = None;
    let mut prepared_evidence = None;
    let mut continuation = None;
    let child = async {
        let document = roxmltree::Document::parse(&original.xml)?;
        let root = document.root_element();
        let source = OriginalDirectMessage::capture(
            root,
            case.identities.actor_id.0,
            &original.sender_full,
            &original.target,
            &original.xml,
        );
        let mut lease = None;
        if let Some(payload) = source.rated_payload() {
            let request = MessageAdmissionRequest {
                actor_id: source.actor_id,
                account_bare: bare_jid(source.sender),
                normalized_target: source.target,
                origin_id: source.origin_id.as_deref(),
                normalized_payload: payload,
                pow_intent_payload: source.routed_raw,
                subject: "message",
                actors: &[],
                proof: None,
            };
            let retained = owner.begin(&request)?;
            frame.enter(Stage::MessageAdmission);
            let MessageAdmissionStart::Proceed {
                lease: returned, ..
            } = admission
                .begin_message_admission_retained(&request, &retained)
                .await?
            else {
                anyhow::bail!("unexpected controlled admission result");
            };
            lease = returned;
            log.prefix();
        }
        let local = source.project_local(
            LocalProjectionAuthority {
                recipient_id: case.identities.recipient_id.0,
                recipient_bare: &policy.recipient_bare,
                sender_stable_id: ids.sender_stable_id.0,
                recipient_stable_id: ids.recipient_stable_id.0,
                domain: &policy.domain,
            },
            policy.encrypted,
            None,
        );
        let eligibility =
            direct_spool_eligibility(policy.degraded_spool_eligible, policy.spool_privacy_permits);
        let applied = {
            let delayed = local.delayed(
                chrono::DateTime::parse_from_rfc3339(&original.at_utc)?.with_timezone(&chrono::Utc),
                LocalArchivePolicy {
                    sender_enabled: policy.sender_archive,
                    recipient_enabled: policy.recipient_archive,
                },
            );
            let mut archives = Vec::with_capacity(2);
            if policy.sender_archive {
                archives.push(ArchiveWrite {
                    id: ids.sender_stable_id.0,
                    owner_id: source.actor_id,
                    peer_jid: source.target,
                    stanza: &local.sender_archive_stanza,
                    encrypted: local.encrypted,
                    stanza_id: source.stanza_id,
                });
            }
            if policy.recipient_archive && case.identities.recipient_id.0 != source.actor_id {
                archives.push(ArchiveWrite {
                    id: ids.recipient_stable_id.0,
                    owner_id: case.identities.recipient_id.0,
                    peer_jid: source.sender,
                    stanza: &local.recipient_archive_stanza,
                    encrypted: local.encrypted,
                    stanza_id: source.stanza_id,
                });
            }
            let identity = source.origin_id.as_deref().map(|value| MessageIdentity {
                authority: IdentityAuthority::LocalOrigin,
                actor_scope_raw: bare_jid(source.sender),
                actor_scope: bare_jid(source.sender),
                target_scope: bare_jid(source.target),
                value,
                payload: &local.rewritten,
            });
            let command = ValidatedPersonalMessage {
                local_actor_id: Some(source.actor_id),
                identity,
                archives: &archives,
                destination: PersonalMessageDestination::Local(LocalDelivery {
                    delivery_id: ids.recipient_stable_id.0,
                    recipient_id: case.identities.recipient_id.0,
                    recipient_bare_jid: &policy.recipient_bare,
                    sender_jid: source.sender,
                    stanza: &delayed.stanza,
                    encrypted: local.encrypted,
                    mam_backed: policy.recipient_archive,
                }),
            };
            projection = Some(wire::Projection {
                message_type: source.message_type.to_owned(),
                origin_id: source.origin_id.clone(),
                rated: source.rated_payload().is_some(),
                normalized_payload: source.rated_payload().map(str::to_owned),
                live_xml: local.recipient_delivery.clone(),
                stored_xml: delayed.stanza.clone(),
                archives: command
                    .archives
                    .iter()
                    .map(|archive| wire::ArchiveEvidence {
                        archive_id: wire::Id(archive.id),
                        owner_id: wire::Id(archive.owner_id),
                        peer_jid: archive.peer_jid.to_owned(),
                        stanza_id: archive.stanza_id.map(str::to_owned),
                        encrypted: archive.encrypted,
                        xml: archive.stanza.to_owned(),
                    })
                    .collect(),
            });
            let PersonalMessageDestination::Local(destination) = command.destination else {
                unreachable!()
            };
            prepared_evidence = Some(wire::PreparedEvidence {
                actor_id: wire::Id(command.local_actor_id.expect("local actor")),
                recipient_id: wire::Id(destination.recipient_id),
                delivery_id: wire::Id(destination.delivery_id),
                eligibility: match eligibility {
                    DirectSpoolEligibility::Eligible => "Eligible",
                    DirectSpoolEligibility::LiveOnly => "LiveOnly",
                },
                encrypted: destination.encrypted,
                mam_backed: destination.mam_backed,
                archive_ids: command
                    .archives
                    .iter()
                    .map(|archive| wire::Id(archive.id))
                    .collect(),
                identity: command.identity.map(|identity| wire::IdentityEvidence {
                    authority: "LocalOrigin",
                    actor_scope_raw: identity.actor_scope_raw.to_owned(),
                    actor_scope: identity.actor_scope.to_owned(),
                    target_scope: identity.target_scope.to_owned(),
                    value: identity.value.to_owned(),
                    payload: identity.payload.to_owned(),
                }),
            });
            let prepared = delayed.bind(owner.clone(), command, eligibility)?;
            frame.enter(Stage::MessageAdmission);
            commit_prepared_application(&app, prepared).await
        };
        // The delayed command and archives have ended. The actual application
        // pair retains only the production continuation's immutable live view.
        log.prefix();
        match continue_prepared_local_direct(applied, &mut lease, &admission, &port, || {
            frame.enter(Stage::MessageFollowup)
        })
        .await
        {
            ContinuedLocalDirect::Accepted => {
                continuation = Some(wire::Continuation {
                    kind: "Accepted",
                    error_type: None,
                    error_condition: None,
                })
            }
            ContinuedLocalDirect::Reject(error) => {
                let (kind, condition) = error.stanza_error();
                continuation = Some(wire::Continuation {
                    kind: "Reject",
                    error_type: Some(kind),
                    error_condition: Some(condition),
                });
            }
            ContinuedLocalDirect::Live(live) => {
                continuation = Some(wire::Continuation {
                    kind: "Live",
                    error_type: None,
                    error_condition: None,
                });
                frame.enter(Stage::MessageRouting);
                log.routing.store(true, Ordering::SeqCst);
                live.route_with(&port, &targets)
                    .await
                    .map_err(|_| anyhow::anyhow!("prepared controlled route failed"))?;
            }
        }
        Ok(())
    };
    let mut runner = Box::pin(frame.run(child));
    let cancelled = matches!(&case.drive, wire::Drive::DropDirectCommit { frame_id } | wire::Drive::DropRearm { frame_id } if *frame_id == original.frame_id);
    let actual = futures::poll!(&mut runner);
    if cancelled {
        let reached = match &case.drive {
            wire::Drive::DropDirectCommit { .. } => log.direct_pending.load(Ordering::SeqCst),
            wire::Drive::DropRearm { .. } => log.rearm_pending.load(Ordering::SeqCst),
            _ => false,
        };
        anyhow::ensure!(
            actual.is_pending() && reached,
            "declared sender drop cut was not reached"
        );
        drop(runner);
    } else {
        // Every controlled non-cut port is immediately ready. An unexpected
        // pending state is a fixture failure, not a hidden unbounded wait.
        drop(runner);
        match actual {
            std::task::Poll::Ready(Ok(())) => {}
            std::task::Poll::Ready(Err(_)) => anyhow::bail!("controlled frame failed"),
            std::task::Poll::Pending => anyhow::bail!("unexpected pending controlled frame"),
        }
    }
    let state = original_state(&owner);
    let mut target = None;
    if state
        .handoff
        .as_ref()
        .is_some_and(|handoff| handoff.local_accepted)
    {
        let item = receiver
            .try_recv()
            .map_err(|_| anyhow::anyhow!("accepted queue item missing"))?;
        anyhow::ensure!(
            item.c2s_delivery().is_some_and(|source| source.recipient_id
                == case.identities.recipient_id.0
                && source.message_id == ids.recipient_stable_id.0),
            "accepted target item identity mismatch"
        );
        let seq = next(&log.sequence);
        log.route.lock().unwrap().dequeued.push(wire::Dequeue {
            seq,
            source: item.durable_source.map(Into::into),
            xml: item.stanza.clone(),
        });
        target = Some(item);
    }
    // Inventory consumes the remaining real receiver only after producer and
    // target-dequeue work ended. This cleanup is never a delivery observation.
    while let Ok(item) = receiver.try_recv() {
        log.route.lock().unwrap().queue_remaining.push(wire::Slot {
            xml: item.stanza,
            source: item.durable_source.map(Into::into),
        });
    }
    let mut route = log.route.lock().unwrap().clone();
    route.backpressure_disconnected = sender.backpressure_disconnect().is_cancelled();
    route.handoff = state.handoff;
    let prefixes = log.prefixes.lock().unwrap().clone();
    // A prefilled P does not acquire a synthetic delivery receipt on cleanup.
    for mut receiver in prefill_receivers {
        anyhow::ensure!(
            !matches!(receiver.try_recv(), Ok(())),
            "prefill cleanup acknowledged an item"
        );
    }
    Ok(OriginalRun {
        evidence: wire::OriginalEvidence {
            frame_id: original.frame_id,
            projection,
            prepared: prepared_evidence,
            begin: state.begin,
            finalize: state.finalize,
            direct: state.direct,
            continuation,
            route,
            terminal: state.terminal,
            prefixes,
        },
        target,
        row,
        cancelled,
    })
}

async fn run_case(case: &wire::Case, input: &[u8]) -> Result<wire::Envelope> {
    let sequence = Arc::new(Mutex::new(wire::Sequence::default()));
    let mut originals = Vec::new();
    let mut recipient = wire::RecipientEvidence::None;
    let mut cancelled = false;
    for index in 0..case.originals.len() {
        let mut run = run_original(case, index, sequence.clone()).await?;
        cancelled |= run.cancelled;
        if let wire::RecipientOwner::Native { frame_id, native } = &case.recipient_owner {
            if *frame_id == case.originals[index].frame_id {
                let item = run.target.take().ok_or_else(|| {
                    anyhow::anyhow!("declared native owner has no dequeued target")
                })?;
                let (evidence, dropped) =
                    run_native(case, *frame_id, native, item, run.row, sequence.clone()).await?;
                cancelled |= dropped;
                recipient = wire::RecipientEvidence::Native { native: evidence };
            }
        }
        anyhow::ensure!(
            run.target.is_none(),
            "dequeued item has no declared receiving owner"
        );
        originals.push(run.evidence);
    }
    Ok(wire::Envelope {
        schema: wire::EVIDENCE_SCHEMA,
        entry: wire::ENTRY,
        input_sha256: wire::digest(input),
        rejection: None,
        execution: Some(if cancelled {
            wire::Execution::Cancelled
        } else {
            wire::Execution::Complete
        }),
        originals,
        recipient: Some(recipient),
    })
}

#[tokio::test]
#[ignore = "requires the separately reviewed fixed saved-case profile; reads one JSON input from fd0"]
async fn replay_saved_case() -> Result<()> {
    let input = wire::read_input()?;
    let evidence = match wire::decode(&input) {
        Ok(case) => run_case(&case, &input).await?,
        Err(reason) => wire::Envelope::rejected(&input, reason),
    };
    wire::emit(&evidence)
}
