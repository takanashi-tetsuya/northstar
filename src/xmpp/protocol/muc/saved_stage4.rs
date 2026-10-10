//! Test-only MUC composition adapter over finite supplied replies.
//! Side observations cannot change owner results. Resource stops are independent.
//! Requires the accepted Stage4 wire module, reviewed raw frame observer, and
//! pending cfg(test) SessionExecutions::for_saved_frame constructor.
//! No SQL, AppState, spawned tasks, new timers, Stage3 adapter, or verdicts.
use super::{MucDiscussionLive, PreparedMucDiscussion};
use crate::abuse::{
    MessageAdmissionAcceptance, MessageAdmissionLease, MessageAdmissionRequest,
    MessageAdmissionStart, MessageDedupeIdentity, WorkRequirement,
};
use crate::outbound::{
    DurableDelivery, MixDelivery, OutboundItem, OutboundSender, RouteEnqueue,
    TransportOwnershipSource,
};
use crate::services::message_admission::{
    self,
    witness::{self, AdmissionWitness, DirectOperationHandle},
    MessageAdmissionRepository, MessageAdmissionService,
};
use crate::services::muc::fanout::{run_muc_discussion_fanout, MucFanoutPort, MucFanoutStage};
use crate::stage4_replay::{self as wire, driver};
use crate::xmpp::stage4_frame_capture::capture_frame;
use crate::xmpp::{
    direct_delivery::{DirectWriteLease, DirectWritePort, NativeWriteRunner},
    frame_execution::{FrameExecution, SessionExecutions, Stage},
};
use anyhow::{Context as _, Result};
use northstar_abuse_policy::{
    admission_execution as admission,
    admission_transaction::{AdmissionFence, FinalizeDecision},
};
use northstar_delivery_core::native_write as native;
use northstar_message_application::direct_lifecycle;
use northstar_room_application::{
    discussion as muc, MucDiscussionRepository, RepositoryFuture, RoomApplication,
};
use northstar_room_core::{
    ClusterMucOccupancyTarget, MucActorAuthority, MucActorPrincipal, MucDiscussion,
    MucDiscussionAdmission, MucRoom,
};
use sha2::{Digest, Sha256};
use std::{
    pin::Pin,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    task::{Context, Poll},
};
use tokio::{io::AsyncWrite, sync::mpsc};
use uuid::Uuid;

type Recorder = driver::Capture;
type E = wire::EvidenceId;
fn id(value: Uuid) -> E {
    E::observed(value)
}
fn nullable<T>(value: Option<T>) -> wire::Nullable<T> {
    value.map_or(wire::Nullable::Null(()), wire::Nullable::Value)
}
fn lost(recorder: &Recorder) {
    driver::lost(recorder);
}
fn capture(recorder: &Recorder, fact: wire::Fact) {
    driver::emit(recorder, fact);
}
fn capture_or_lose(recorder: &Recorder, fact: Result<wire::Fact>) {
    driver::emit_projected(recorder, move || fact);
}
fn hex_input(value: &wire::Hex<32>) -> Result<Vec<u8>> {
    // Hex intentionally has no raw getter. Use only its existing typed public
    // serialization; this is input material, not an evidence/expected DTO cast.
    let text: String = serde_json::from_str(&serde_json::to_string(value)?)?;
    text.as_bytes()
        .chunks_exact(2)
        .map(|pair| Ok(u8::from_str_radix(std::str::from_utf8(pair)?, 16)?))
        .collect()
}
fn fingerprint(bytes: &[u8]) -> Result<wire::Hex<32>> {
    Ok(wire::Hex::of(&Sha256::digest(bytes))?)
}
fn u32_len(value: usize) -> Result<u32> {
    Ok(u32::try_from(value)?)
}

fn source(value: TransportOwnershipSource) -> wire::Source<E> {
    match value {
        TransportOwnershipSource::C2s(x) => wire::Source::C2s(wire::C2sSource {
            recipient_id: id(x.recipient_id),
            message_id: id(x.message_id),
            claim_id: nullable(x.claim_id.map(id)),
        }),
        TransportOwnershipSource::Mix(x) => wire::Source::Mix(wire::MixSource {
            delivery_id: id(x.delivery_id),
            lease_token: id(x.lease_token),
        }),
    }
}
fn fence(x: &AdmissionFence) -> Result<wire::FenceEvidence<E>> {
    Ok(wire::FenceEvidence {
        admission_key: wire::Hex::of(&x.admission_key)?,
        payload_mac: wire::Hex::of(&x.payload_mac)?,
        lease_token: id(x.lease_token),
    })
}
fn correlation(x: admission::Correlation) -> wire::Correlation<E> {
    wire::Correlation {
        operation_id: id(x.operation),
        effect: x.effect,
        generation: x.generation,
        attempt: u64::from(x.attempt),
    }
}
fn admission_commit(
    c: admission::Correlation,
    s: admission::TransactionScope,
    f: &admission::CommitFact,
) -> Result<wire::AdmissionCommit<E>> {
    let scope = match s {
        admission::TransactionScope::RatedBegin(p) => match p {
            admission::BeginCommitPurpose::NewReservation => wire::EffectScope::NewReservation,
            admission::BeginCommitPurpose::Reclaim => wire::EffectScope::Reclaim,
            admission::BeginCommitPurpose::ReplayRead => wire::EffectScope::ReplayRead,
            admission::BeginCommitPurpose::PendingRequirement => {
                wire::EffectScope::PendingRequirement
            }
            admission::BeginCommitPurpose::GuardDenial => wire::EffectScope::GuardDenial,
        },
        admission::TransactionScope::AdmissionFinalize => wire::EffectScope::AdmissionFinalize,
        admission::TransactionScope::GuardOnlyVerification => {
            wire::EffectScope::GuardOnlyVerification
        }
    };
    let empty = || wire::Empty {};
    let fact = match f {
        admission::CommitFact::Reserved(x) => wire::AdmissionFact::Reserved(fence(x)?),
        admission::CommitFact::ReplayAccepted => wire::AdmissionFact::ReplayAccepted(empty()),
        admission::CommitFact::InProgress => wire::AdmissionFact::InProgress(empty()),
        admission::CommitFact::Denied => wire::AdmissionFact::Denied(empty()),
        admission::CommitFact::Finalized { fence: x, result } => {
            wire::AdmissionFact::Finalized(wire::FinalizedFact {
                fence: fence(x)?,
                result: match result {
                    admission::FinalizeSuccess::PendingAccepted => {
                        wire::FinalizeSuccess::PendingAccepted
                    }
                    admission::FinalizeSuccess::AlreadyAccepted => {
                        wire::FinalizeSuccess::AlreadyAccepted
                    }
                },
            })
        }
        admission::CommitFact::GuardOnly(x) => wire::AdmissionFact::GuardOnly(wire::GuardValue {
            decision: match x {
                admission::GuardDecision::Allowed => wire::GuardDecision::Allowed,
                admission::GuardDecision::Denied => wire::GuardDecision::Denied,
            },
        }),
    };
    Ok(wire::AdmissionCommit {
        correlation: correlation(c),
        scope,
        fact,
    })
}
fn admission_snapshot(
    x: direct_lifecycle::AdmissionSnapshot,
    returned: bool,
) -> Result<wire::AdmissionEvidence<E>> {
    let knowledge = match x.witness.knowledge() {
        admission::Knowledge::NoCommitRequested => {
            wire::AdmissionKnowledge::NoCommitRequested(wire::Empty {})
        }
        admission::Knowledge::CommitCallEntered(x) => wire::AdmissionKnowledge::CommitCallEntered(
            admission_commit(x.correlation, x.scope, &x.fact)?,
        ),
        admission::Knowledge::ReceiptKnown(x) => wire::AdmissionKnowledge::ReceiptKnown(
            admission_commit(x.correlation, x.scope, &x.fact)?,
        ),
    };
    // Retirement can finish a lifecycle with Unknown/ReceiptPreserved without
    // any service return. Never mistake that state for an observed return.
    let returned = if returned {
        Some(match x.state {
            admission::ExecutionState::Finished(admission::ExecutionOutcome::Completed {
                result: admission::EffectResult::Begin(admission::BeginResult::Reserved(x)),
                ..
            }) => wire::AdmissionReturned::Proceed(fence(&x)?),
            admission::ExecutionState::Finished(admission::ExecutionOutcome::Completed {
                result: admission::EffectResult::Finalize(FinalizeDecision::AcceptPending),
                ..
            }) => wire::AdmissionReturned::AcceptPending(wire::Empty {}),
            admission::ExecutionState::Finished(
                admission::ExecutionOutcome::PreCommitFailure(_)
                | admission::ExecutionOutcome::Unknown { .. }
                | admission::ExecutionOutcome::ReceiptPreserved { .. },
            ) => wire::AdmissionReturned::Error(wire::Empty {}),
            // Successful unrepresented service results are loss, never Error.
            _ => anyhow::bail!("unsupported observed admission return"),
        })
    } else {
        None
    };
    Ok(wire::AdmissionEvidence {
        correlation: correlation(x.witness.effect().correlation),
        started: x.effect_started,
        knowledge,
        returned: nullable(returned),
    })
}

fn accepted(x: muc::AcceptanceClass) -> wire::AcceptanceClass {
    match x {
        muc::AcceptanceClass::ArchiveAndIdentity => wire::AcceptanceClass::ArchiveAndIdentity,
        muc::AcceptanceClass::ArchiveOnly => wire::AcceptanceClass::ArchiveOnly,
        muc::AcceptanceClass::IdentityOnly => wire::AcceptanceClass::IdentityOnly,
        muc::AcceptanceClass::Volatile => wire::AcceptanceClass::Volatile,
    }
}
fn muc_outcome(x: MucDiscussionAdmission) -> wire::MucOutcome<E> {
    match x {
        MucDiscussionAdmission::Stored(x) => wire::MucOutcome::Stored(wire::OneId { id: id(x) }),
        MucDiscussionAdmission::Replay(x) => wire::MucOutcome::Replay(wire::OneId { id: id(x) }),
        MucDiscussionAdmission::Unauthorized => wire::MucOutcome::Unauthorized(wire::Empty {}),
        MucDiscussionAdmission::Stale => wire::MucOutcome::Stale(wire::Empty {}),
    }
}
fn muc_commit(x: muc::CommitFact) -> wire::MucCommitFact<E> {
    wire::MucCommitFact {
        outcome: muc_outcome(x.outcome()),
        fresh_class: nullable(x.fresh_class().map(accepted)),
    }
}
fn muc_snapshot(x: muc::Snapshot) -> Result<wire::MucSnapshot<E>> {
    let p = x.fanout;
    Ok(wire::MucSnapshot {
        request_issued: x.request_issued,
        repository_started: x.repository_started,
        knowledge: match x.knowledge {
            muc::Knowledge::NoCommitRequested => {
                wire::MucKnowledge::NoCommitRequested(wire::Empty {})
            }
            muc::Knowledge::CommitCallEntered(x) => {
                wire::MucKnowledge::CommitCallEntered(muc_commit(x))
            }
            muc::Knowledge::ReceiptKnown(x) => wire::MucKnowledge::ReceiptKnown(muc_commit(x)),
        },
        returned: nullable(x.returned.map(|x| match x {
            muc::Returned::Outcome(x) => wire::MucReturned::Outcome(muc_outcome(x)),
            muc::Returned::Error => wire::MucReturned::Error(wire::Empty {}),
        })),
        fanout: wire::FanoutPrefix {
            stage: match p.stage {
                muc::FanoutStage::Unavailable => wire::FanoutStage::Unavailable,
                muc::FanoutStage::Ready => wire::FanoutStage::Ready,
                muc::FanoutStage::Started => wire::FanoutStage::Started,
                muc::FanoutStage::ClusterEntered => wire::FanoutStage::ClusterEntered,
                muc::FanoutStage::ClusterReturned => wire::FanoutStage::ClusterReturned,
                muc::FanoutStage::PrivacyEntered => wire::FanoutStage::PrivacyEntered,
                muc::FanoutStage::Delivering => wire::FanoutStage::Delivering,
                muc::FanoutStage::Completed => wire::FanoutStage::Completed,
            },
            recipients: nullable(p.recipients.map(u32_len).transpose()?),
            next_recipient: u32_len(p.next_recipient)?,
            endpoint_pending: p.endpoint_pending,
            blocked: u32_len(p.blocked)?,
            accepted: u32_len(p.accepted)?,
            rejected: u32_len(p.rejected)?,
        },
        terminal: nullable(x.terminal.map(|x| match x {
            muc::TerminalReason::Completed => wire::OwnerTerminal::Completed,
            muc::TerminalReason::BackendFailure => wire::OwnerTerminal::BackendFailure,
            muc::TerminalReason::TimedOut => wire::OwnerTerminal::TimedOut,
            muc::TerminalReason::Cancelled => wire::OwnerTerminal::Cancelled,
            muc::TerminalReason::Panicked => wire::OwnerTerminal::Panicked,
        })),
    })
}

fn input_command(x: &wire::MucCommand<wire::Id>) -> MucDiscussion {
    let a = &x.authority;
    MucDiscussion {
        id: x.id.0,
        room_id: x.room_id.0,
        actor_scope: x.actor_scope.as_str().into(),
        origin_id: x.origin_id.get().map(|x| x.as_str().into()),
        sender_jid: x.sender_jid.as_str().into(),
        nick: x.nick.as_str().into(),
        stanza: x.stanza.as_str().into(),
        encrypted: x.encrypted,
        archive: x.archive,
        retention_days: x.retention_days,
        authority: MucActorAuthority {
            clustered: a.clustered,
            expected_room_epoch: a.expected_room_epoch.0,
            principal: match &a.principal {
                wire::MucPrincipal::Local(x) => MucActorPrincipal::Local {
                    user_id: x.user_id.0,
                    local_domain: x.local_domain.as_str().into(),
                },
                wire::MucPrincipal::Federated(x) => MucActorPrincipal::Federated {
                    bare_jid: x.bare_jid.as_str().into(),
                    authenticated_domain: x.authenticated_domain.as_str().into(),
                },
            },
            actor_scope: a.actor_scope.as_str().into(),
            full_jid: a.full_jid.as_str().into(),
            nick: a.nick.as_str().into(),
            occupant_incarnation: a.occupant_incarnation.0,
            connection_uuid: a.connection_uuid.0,
            expected_role: a.expected_role.as_str().into(),
            expected_affiliation: a.expected_affiliation.as_str().into(),
            cluster_target: a.cluster_target.get().map(|x| ClusterMucOccupancyTarget {
                room_id: x.room_id.0,
                room_epoch: x.room_epoch.0,
                occupant_incarnation: x.occupant_incarnation.0,
                occupancy_epoch: x.occupancy_epoch,
                full_jid: x.full_jid.as_str().into(),
                nick: x.nick.as_str().into(),
                connection_uuid: x.connection_uuid.0,
                connection_epoch: x.connection_epoch,
            }),
        },
    }
}
fn observed_command(x: &MucDiscussion) -> Result<wire::MucCommand<E>> {
    let a = &x.authority;
    Ok(wire::MucCommand {
        id: id(x.id),
        room_id: id(x.room_id),
        actor_scope: wire::Text::new(&x.actor_scope)?,
        origin_id: nullable(x.origin_id.as_ref().map(wire::Text::new).transpose()?),
        sender_jid: wire::Text::new(&x.sender_jid)?,
        nick: wire::Text::new(&x.nick)?,
        stanza: wire::Text::new(&x.stanza)?,
        encrypted: x.encrypted,
        archive: x.archive,
        retention_days: x.retention_days,
        authority: wire::Authority {
            clustered: a.clustered,
            expected_room_epoch: id(a.expected_room_epoch),
            principal: match &a.principal {
                MucActorPrincipal::Local {
                    user_id,
                    local_domain,
                } => wire::MucPrincipal::Local(wire::LocalPrincipal {
                    user_id: id(*user_id),
                    local_domain: wire::Text::new(local_domain)?,
                }),
                MucActorPrincipal::Federated {
                    bare_jid,
                    authenticated_domain,
                } => wire::MucPrincipal::Federated(wire::FederatedPrincipal {
                    bare_jid: wire::Text::new(bare_jid)?,
                    authenticated_domain: wire::Text::new(authenticated_domain)?,
                }),
            },
            actor_scope: wire::Text::new(&a.actor_scope)?,
            full_jid: wire::Text::new(&a.full_jid)?,
            nick: wire::Text::new(&a.nick)?,
            occupant_incarnation: id(a.occupant_incarnation),
            connection_uuid: id(a.connection_uuid),
            expected_role: wire::Text::new(&a.expected_role)?,
            expected_affiliation: wire::Text::new(&a.expected_affiliation)?,
            cluster_target: nullable(
                a.cluster_target
                    .as_ref()
                    .map(|x| -> Result<_> {
                        Ok(wire::ClusterTarget {
                            room_id: id(x.room_id),
                            room_epoch: id(x.room_epoch),
                            occupant_incarnation: id(x.occupant_incarnation),
                            occupancy_epoch: x.occupancy_epoch,
                            full_jid: wire::Text::new(&x.full_jid)?,
                            nick: wire::Text::new(&x.nick)?,
                            connection_uuid: id(x.connection_uuid),
                            connection_epoch: x.connection_epoch,
                        })
                    })
                    .transpose()?,
            ),
        },
    })
}
fn supplied_room(command: &MucDiscussion) -> Result<(MucRoom, String)> {
    let document = roxmltree::Document::parse(&command.stanza)?;
    let to = document
        .root_element()
        .attribute("to")
        .context("missing actual live room address")?;
    let jid = crate::jid::CanonicalJid::parse_bare(to)?;
    let localpart = jid
        .localpart()
        .context("MUC room address lacks localpart")?
        .to_owned();
    // PreparedMucDiscussion reads only id, room_epoch, localpart. The remaining
    // inert room fields are fixed supplied environment, never a real room lookup.
    Ok((
        MucRoom {
            id: command.room_id,
            room_epoch: command.authority.expected_room_epoch,
            config_version: 1,
            localpart,
            title: None,
            description: None,
            persistent: false,
            members_only: false,
            public: false,
            moderated: false,
            non_anonymous: false,
            max_occupants: 2,
            subject: None,
            subject_changed_at: None,
            allow_subject_change: false,
            allow_invites: false,
            allow_private_messages: false,
            logging_enabled: false,
            allow_registration: false,
            password_hash: None,
            occupant_id_secret: Vec::new(),
            configuration_owner_jid: None,
            configuration_expires_at: None,
        },
        to.to_owned(),
    ))
}

struct Observers {
    recorder: Recorder,
    frame: FrameExecution,
    admission: DirectOperationHandle,
    muc: muc::Observation,
    requested: muc::AcceptanceClass,
    repository_command: Mutex<Option<MucDiscussion>>,
    begin_returned: AtomicBool,
    finalize_returned: AtomicBool,
    commit_pending_polled: AtomicBool,
    endpoint_pending_polled: AtomicBool,
}
impl Observers {
    fn frame(&self, cut: wire::Cut) {
        // QUIESCENCE: one confined local poll stack; no spawned task, escaping
        // frame clone, background callback or other writer exists. Idle clones
        // belong only to SessionExecutions, this observer and the local runner.
        // Existing timeout timers can wake; they cannot write these atomics.
        let snapshot = self.admission.snapshot();
        let begin = snapshot.reservation.and_then(|x| {
            driver::project(&self.recorder, || {
                admission_snapshot(x, self.begin_returned.load(Ordering::Relaxed))
            })
        });
        let finalize = snapshot.finalization.and_then(|x| {
            driver::project(&self.recorder, || {
                admission_snapshot(x, self.finalize_returned.load(Ordering::Relaxed))
            })
        });
        capture_frame(&self.frame, cut, begin, finalize, &self.recorder);
    }
    fn muc_fact(&self, cut: wire::Cut) -> Result<wire::Fact> {
        let command = self.repository_command.lock().unwrap().clone();
        Ok(wire::Fact::Muc(wire::MucFact::Snapshot(wire::MucCapture {
            frame: id(self.frame.operation_id()),
            cut,
            command: nullable(command.as_ref().map(observed_command).transpose()?),
            requested_class: wire::Nullable::Value(accepted(self.requested)),
            snapshot: muc_snapshot(self.muc.snapshot())?,
        })))
    }
    fn muc(&self, cut: wire::Cut) {
        capture_or_lose(&self.recorder, self.muc_fact(cut));
    }
    fn both(&self, cut: wire::Cut) {
        self.frame(cut);
        self.muc(cut);
    }
    fn drop_cut(&self) {
        self.muc(wire::Cut::ChildDrop);
        self.frame(wire::Cut::ChildDrop);
    }
}
struct ChildDrop(Arc<Observers>);
impl Drop for ChildDrop {
    fn drop(&mut self) {
        self.0.drop_cut();
    }
}

struct DiscussionRepository {
    supplied: wire::MucRepository,
    recorder: Recorder,
    observation: Mutex<Option<Arc<Observers>>>,
}
impl MucDiscussionRepository for DiscussionRepository {
    type Error = anyhow::Error;
    fn admit_discussion<'a>(&'a self, _: &'a MucDiscussion) -> RepositoryFuture<'a, Self::Error> {
        Box::pin(async { anyhow::bail!("unobserved MUC repository entry is unsupported") })
    }
    fn admit_discussion_observed<'a>(
        &'a self,
        request: &'a muc::Request,
    ) -> RepositoryFuture<'a, Self::Error> {
        Box::pin(async move {
            let observed = self.observation.lock().unwrap().clone();
            if let Some(observed) = &observed {
                *observed.repository_command.lock().unwrap() = Some(request.command().clone());
                observed.muc(wire::Cut::PortEntry);
            } else {
                lost(&self.recorder);
            }
            let outcome = self.supplied.original_id.get().map_or_else(
                || MucDiscussionAdmission::Stored(request.command().id),
                |x| MucDiscussionAdmission::Replay(x.0),
            );
            // The reply is a supplied repository fact. The real observed COMMIT
            // helper binds it to this exact Request and RoomApplication derives
            // the real Completion/fanout permit after the repository returns.
            muc::commit_observed(
                async {
                    match self.supplied.commit {
                        wire::CommitCut::Complete => Ok(()),
                        wire::CommitCut::Pending => {
                            let _child = observed.as_ref().map(|x| ChildDrop(x.clone()));
                            std::future::poll_fn(|_| {
                                if let Some(observed) = &observed {
                                    observed
                                        .commit_pending_polled
                                        .store(true, Ordering::Relaxed);
                                }
                                Poll::<()>::Pending
                            })
                            .await;
                            Ok(())
                        }
                        wire::CommitCut::Error => {
                            anyhow::bail!("unsupported MUC repository error cut")
                        }
                    }
                },
                request,
                outcome,
            )
            .await
            .map_err(|error| match error {
                muc::CommitError::Observation(error) => anyhow::Error::from(error),
                muc::CommitError::Commit(error) => error,
            })?;
            if let Some(observed) = &observed {
                observed.muc(wire::Cut::PortReturn);
            }
            Ok(outcome)
        })
    }
}
// RoomApplication has no repository getter. An Arc wrapper retains the same
// concrete repository so registration can be wired before its first poll.
struct RepositoryHandle(Arc<DiscussionRepository>);
impl MucDiscussionRepository for RepositoryHandle {
    type Error = anyhow::Error;
    fn admit_discussion<'a>(
        &'a self,
        command: &'a MucDiscussion,
    ) -> RepositoryFuture<'a, Self::Error> {
        self.0.admit_discussion(command)
    }
    fn admit_discussion_observed<'a>(
        &'a self,
        request: &'a muc::Request,
    ) -> RepositoryFuture<'a, Self::Error> {
        self.0.admit_discussion_observed(request)
    }
}

struct AdmissionRepository {
    supplied: wire::RatedAdmission,
    observed: Arc<Observers>,
}
impl AdmissionRepository {
    fn lease(&self) -> Result<MessageAdmissionLease> {
        let x = &self.supplied.fence;
        Ok(MessageAdmissionLease::new(
            hex_input(&x.admission_key)?,
            hex_input(&x.payload_mac)?,
            x.lease_token.0,
            MessageDedupeIdentity {
                identity_digest: hex_input(&x.dedupe_digest)?,
                candidates: Vec::new(),
            },
        ))
    }
    fn requirement(&self) -> WorkRequirement {
        let x = &self.supplied.requirement;
        WorkRequirement {
            action: x.action.as_str().into(),
            step: x.step,
            work_factor: x.work_factor,
            max_work_factor: x.max_work_factor,
            hard_wait_seconds: x.hard_wait_seconds,
            retry_after_seconds: x.retry_after_seconds,
            cooldown_seconds: x.cooldown_seconds,
            approximate_max_device_seconds: x.approximate_max_device_seconds,
            notice: x.notice.as_str().into(),
        }
    }
}
impl MessageAdmissionRepository for AdmissionRepository {
    async fn begin(
        &self,
        _: &MessageAdmissionRequest<'_>,
        witness: &AdmissionWitness,
    ) -> Result<MessageAdmissionStart> {
        self.observed.frame(wire::Cut::PortEntry);
        let lease = self.lease()?;
        witness::saved_case_commit_observed(
            async {
                anyhow::ensure!(
                    self.supplied.begin_commit == wire::CommitCut::Complete,
                    "unsupported rated begin cut"
                );
                Ok(())
            },
            witness,
            admission::TransactionScope::RatedBegin(admission::BeginCommitPurpose::NewReservation),
            admission::CommitFact::Reserved(message_admission::acceptance_fence(
                &lease.acceptance(),
            )),
        )
        .await?;
        self.observed.frame(wire::Cut::PortReturn);
        Ok(MessageAdmissionStart::Proceed {
            lease: Some(lease),
            requirement: self.requirement(),
        })
    }
    async fn accept(
        &self,
        acceptance: &MessageAdmissionAcceptance<'_>,
        witness: &AdmissionWitness,
    ) -> Result<FinalizeDecision> {
        self.observed.frame(wire::Cut::PortEntry);
        witness::saved_case_commit_observed(
            async {
                anyhow::ensure!(
                    self.supplied.finalize_commit == wire::CommitCut::Complete,
                    "unsupported rated finalization cut"
                );
                Ok(())
            },
            witness,
            admission::TransactionScope::AdmissionFinalize,
            admission::CommitFact::Finalized {
                fence: message_admission::acceptance_fence(acceptance),
                result: admission::FinalizeSuccess::PendingAccepted,
            },
        )
        .await?;
        self.observed.frame(wire::Cut::PortReturn);
        Ok(FinalizeDecision::AcceptPending)
    }
    async fn reconcile(&self, _: &admission::Effect) -> Result<admission::ReconcileResult> {
        anyhow::bail!("reconciliation is outside finite MUC scope")
    }
}

#[derive(Clone)]
struct Endpoint {
    ordinal: u8,
    user: Uuid,
    jid: String,
    connection: Uuid,
    blocked: bool,
    cut: wire::EndpointCut,
    sender: OutboundSender,
    receiver: Arc<Mutex<mpsc::Receiver<OutboundItem>>>,
}
impl Endpoint {
    fn supplied(ordinal: u8, input: &wire::RecipientInput) -> Self {
        let (sender, receiver) = mpsc::channel(1);
        Self {
            ordinal,
            user: input.user_id.0,
            jid: input.full_jid.as_str().into(),
            connection: input.connection_id.0,
            blocked: input.blocked,
            cut: input.endpoint,
            sender: OutboundSender::new(sender),
            receiver: Arc::new(Mutex::new(receiver)),
        }
    }
    fn observation(&self) -> Result<wire::RecipientObservation<E>> {
        Ok(wire::RecipientObservation {
            user_id: id(self.user),
            full_jid: wire::Text::new(&self.jid)?,
            connection_id: id(self.connection),
        })
    }
}
fn queued_item(item: &OutboundItem, endpoint: &Endpoint) -> Result<wire::QueueItem<E>> {
    // This finite adapter has only plain MUC items. An unexpected auth marker
    // is unsupported observation, never silently serialized as no auth owner.
    anyhow::ensure!(
        !item.is_bosh_auth_control() && item.auth_publication().is_none(),
        "unexpected auth item at MUC queue"
    );
    Ok(wire::QueueItem {
        item_ordinal: endpoint.ordinal,
        connection_id: id(endpoint.connection),
        source: nullable(item.durable_source.map(source)),
        stanza: wire::Text::new(&item.stanza)?,
        auth_control: wire::Nullable::Null(()),
    })
}
struct FanoutPort {
    live: MucDiscussionLive,
    endpoints: Vec<Endpoint>,
    observed: Arc<Observers>,
}
impl FanoutPort {
    fn endpoint(
        &self,
        recipient: &Endpoint,
        privacy: Option<bool>,
        entered: bool,
        returned: Option<bool>,
        queued: Option<wire::QueueItem<E>>,
    ) -> Result<wire::Fact> {
        Ok(wire::Fact::Muc(wire::MucFact::Endpoint(
            wire::MucEndpoint {
                frame: id(self.observed.frame.operation_id()),
                ordinal: recipient.ordinal,
                recipient: recipient.observation()?,
                privacy_returned: nullable(privacy),
                entered,
                returned: nullable(returned),
                queued_item: nullable(queued),
            },
        )))
    }
}
impl MucFanoutPort for FanoutPort {
    type Recipient = Endpoint;
    type Blocked = Vec<bool>;
    fn enter(&self, stage: MucFanoutStage) {
        self.observed.frame.enter(match stage {
            MucFanoutStage::Cluster => Stage::MucClusterFanout,
            MucFanoutStage::Local => Stage::MucLocalFanout,
        });
    }
    async fn publish_cluster(&self) {
        // Closed input scope is local/nonclustered. The shared fanout still
        // enters and returns its cluster port; no cluster send is simulated.
    }
    fn recipients(&self) -> Vec<Self::Recipient> {
        let recipients = self.endpoints.clone();
        capture_or_lose(
            &self.observed.recorder,
            (|| -> Result<_> {
                Ok(wire::Fact::Muc(wire::MucFact::Recipients(
                    wire::MucRecipients {
                        frame: id(self.observed.frame.operation_id()),
                        recipients: wire::List::new(
                            recipients
                                .iter()
                                .map(Endpoint::observation)
                                .collect::<Result<Vec<_>>>()?,
                        )?,
                    },
                )))
            })(),
        );
        recipients
    }
    async fn blocked<'a>(&'a self, recipients: &'a [Endpoint]) -> Vec<bool> {
        recipients.iter().map(|x| x.blocked).collect()
    }
    fn is_blocked(&self, recipient: &Endpoint, blocked: &Vec<bool>) -> bool {
        let actual = blocked.get(usize::from(recipient.ordinal)).copied();
        if actual.is_none() {
            lost(&self.observed.recorder);
        }
        capture_or_lose(
            &self.observed.recorder,
            self.endpoint(recipient, actual, false, None, None),
        );
        actual.unwrap_or(true)
    }
    async fn deliver(&self, recipient: &Endpoint) -> bool {
        capture_or_lose(
            &self.observed.recorder,
            self.endpoint(recipient, None, true, None, None),
        );
        capture_or_lose(
            &self.observed.recorder,
            self.observed.muc_fact(wire::Cut::PortEntry),
        );
        if recipient.cut == wire::EndpointCut::Pending {
            let _child = ChildDrop(self.observed.clone());
            std::future::poll_fn(|_| {
                self.observed
                    .endpoint_pending_polled
                    .store(true, Ordering::Relaxed);
                Poll::<()>::Pending
            })
            .await;
        }
        let stanza = crate::xmpp::xml_util::set_to(&self.live.stanza, &recipient.jid);
        let item = OutboundItem::plain(stanza.clone());
        let actual_item = queued_item(&item, recipient);
        // No durable permit is fabricated. The real sender inserts this exact
        // moved item into the real bounded Tokio queue through its shared path.
        let actual = match RouteEnqueue::bind(item, None, &stanza) {
            Ok(enqueue) => recipient.sender.try_send_route_item(enqueue).is_ok(),
            Err(_) => false,
        };
        let queued = match actual_item {
            Ok(item) if actual => Some(item),
            Ok(_) => None,
            Err(_) => {
                lost(&self.observed.recorder);
                None
            }
        };
        capture_or_lose(
            &self.observed.recorder,
            self.endpoint(recipient, None, true, Some(actual), queued),
        );
        actual
    }
    fn record_failure(&self, _: &Endpoint) {
        // Actual endpoint false was already recorded. No retry or metric-backed
        // AppState is supplied, and a failed effect cannot undo the receipt.
    }
}

fn native_snapshot(x: native::Snapshot) -> wire::NativeSnapshot<E> {
    let ack_fact = |x: native::AckFact| wire::NativeAckFact {
        source: source(x.source),
        disposition: match x.disposition {
            native::AckDisposition::Deleted => wire::AckDisposition::Deleted,
            native::AckDisposition::AbsentUnclaimed => wire::AckDisposition::AbsentUnclaimed,
            native::AckDisposition::NoMatchingMix => wire::AckDisposition::NoMatchingMix,
        },
    };
    wire::NativeSnapshot {
        original: nullable(x.original.map(source)),
        preparation: match x.preparation {
            native::Preparation::NotStarted => wire::NativePreparation::NotStarted,
            native::Preparation::Recording => wire::NativePreparation::Recording,
            native::Preparation::FenceCallEntered => wire::NativePreparation::FenceCallEntered,
            native::Preparation::Prepared => wire::NativePreparation::Prepared,
            native::Preparation::Superseded => wire::NativePreparation::Superseded,
            native::Preparation::Failed => wire::NativePreparation::Failed,
        },
        managed_by_sm: nullable(x.managed_by_sm),
        fence_entered: x.fence_entered,
        returned_fence: nullable(x.returned_fence.map(source)),
        writer_entered: x.writer_entered,
        writer_result: nullable(x.writer_result.map(|x| match x {
            native::WriterResult::FullWrite => wire::WriterResult::FullWrite,
            native::WriterResult::Failed => wire::WriterResult::Failed,
        })),
        write_decision: nullable(x.write_decision.map(|x| match x {
            native::WriteDecision::Withhold => wire::WriteDecision::Withhold,
            native::WriteDecision::Written => wire::WriteDecision::Written,
        })),
        ack: match x.ack {
            native::AckKnowledge::NotRequested => {
                wire::NativeAckKnowledge::NotRequested(wire::Empty {})
            }
            native::AckKnowledge::NoCommitRequested => {
                wire::NativeAckKnowledge::NoCommitRequested(wire::Empty {})
            }
            native::AckKnowledge::CommitCallEntered(x) => {
                wire::NativeAckKnowledge::CommitCallEntered(ack_fact(x))
            }
            native::AckKnowledge::ReceiptKnown(x) => {
                wire::NativeAckKnowledge::ReceiptKnown(ack_fact(x))
            }
        },
        ack_returned: nullable(x.ack_returned),
        terminal: nullable(x.terminal.map(|x| match x {
            native::Terminal::Returned => wire::CallTerminal::Returned,
            native::Terminal::Cancelled => wire::CallTerminal::Cancelled,
            native::Terminal::Panicked => wire::CallTerminal::Panicked,
        })),
    }
}
fn item_owner(frame: &FrameExecution, endpoint: &Endpoint) -> wire::ItemOwner<E> {
    wire::ItemOwner::Muc(wire::MucItemOwner {
        frame: id(frame.operation_id()),
        recipient_ordinal: endpoint.ordinal,
    })
}
struct NativeCapture {
    recorder: Recorder,
    frame: Uuid,
    connection: Uuid,
    ordinal: u8,
    observation: native::Observation,
}
impl NativeCapture {
    fn capture(&self, cut: wire::Cut) {
        capture(
            &self.recorder,
            wire::Fact::Native(wire::NativeFact::Snapshot(wire::NativeCapture {
                connection: id(self.connection),
                item_ordinal: self.ordinal,
                owner: wire::ItemOwner::Muc(wire::MucItemOwner {
                    frame: id(self.frame),
                    recipient_ordinal: self.ordinal,
                }),
                cut,
                snapshot: wire::Nullable::Value(native_snapshot(self.observation.snapshot())),
            })),
        );
    }
}
struct NativeChildDrop(Arc<NativeCapture>);
impl Drop for NativeChildDrop {
    fn drop(&mut self) {
        self.0.capture(wire::Cut::ChildDrop);
    }
}
struct PlainPort {
    connection: Uuid,
    recorder: Recorder,
}
impl PlainPort {
    fn unsupported<T>(&self) -> Result<T> {
        lost(&self.recorder);
        anyhow::bail!("durable native operation on plain MUC item")
    }
}
impl DirectWritePort for PlainPort {
    async fn record(&mut self, item: &OutboundItem) -> Result<bool> {
        if item.durable_source.is_some()
            || item.auth_publication().is_some()
            || item.is_bosh_auth_control()
        {
            return self.unsupported();
        }
        Ok(false) // supplied native environment has no SM retention
    }
    async fn fence_c2s(&self, _: DurableDelivery) -> Result<DurableDelivery> {
        self.unsupported()
    }
    async fn fence_mix(&self, _: MixDelivery) -> Result<MixDelivery> {
        self.unsupported()
    }
    async fn acknowledge_c2s(&self, _: &native::AckRequest) -> Result<()> {
        self.unsupported()
    }
    async fn acknowledge_mix(&self, _: &native::AckRequest) -> Result<bool> {
        self.unsupported()
    }
    fn connection_id(&self) -> Uuid {
        self.connection
    }
}
struct NativeAfterRunnerDrop(Arc<NativeCapture>);
impl Drop for NativeAfterRunnerDrop {
    fn drop(&mut self) {
        self.0.capture(wire::Cut::AfterRunnerDrop);
    }
}
fn stop_native_write(recorder: &Recorder, ordinal: u8, admitted: u8) -> wire::BudgetStop {
    // Ordinal is validated before its owner; this local counter never exceeds32.
    driver::latch_resource_stop(
        recorder,
        wire::ResourceStop::NativeWrite(wire::NativeResourceStop {
            item_ordinal: ordinal,
            admitted_calls: admitted,
        }),
    )
    .expect("validated finite native write resource stop")
}
fn stop_native_flush(recorder: &Recorder, ordinal: u8, admitted: u8) -> wire::BudgetStop {
    driver::latch_resource_stop(
        recorder,
        wire::ResourceStop::NativeFlush(wire::NativeResourceStop {
            item_ordinal: ordinal,
            admitted_calls: admitted,
        }),
    )
    .expect("validated finite native flush resource stop")
}
fn required_write_calls(length: usize, script: &wire::WriteScript) -> Option<usize> {
    let chunk = usize::try_from(script.chunk_limit).ok()?;
    if chunk == 0 {
        return None;
    }
    match script.fail_after_accepted_bytes.get().map(|n| *n as usize) {
        Some(fail_after) if fail_after < length => fail_after.div_ceil(chunk).checked_add(1),
        _ => Some(length.div_ceil(chunk)),
    }
}
fn native_preflight(
    item: &OutboundItem,
    script: &wire::WriteScript,
    ordinal: u8,
    recorder: &Recorder,
) -> Option<wire::BudgetStop> {
    // Check the actual set_to-transformed item after actual dequeue. The source
    // template length is not the byte length consumed by the native writer.
    let length = item.stanza.len();
    if !matches!(required_write_calls(length, script), Some(n) if n <= 32) {
        Some(stop_native_write(recorder, ordinal, 0))
    } else {
        None
    }
}
struct Writer {
    script: wire::WriteScript,
    accepted: usize,
    materialized_len: usize,
    ordinal: u8,
    recorder: Recorder,
    // Independent execution counters: no Recorder capture result changes them.
    write_calls: u8,
    flush_calls: u8,
    stopped: bool,
}
impl Writer {
    fn observe_write(&self, offered: &[u8], accepted: &[u8], result: wire::IoResult) {
        capture_or_lose(
            &self.recorder,
            (|| -> Result<_> {
                Ok(wire::Fact::Native(wire::NativeFact::Write(
                    wire::WriteCall {
                        item_ordinal: self.ordinal,
                        offered_len: u32_len(offered.len())?,
                        offered_sha256: fingerprint(offered)?,
                        accepted_bytes_hex: wire::Bytes::of(accepted)?,
                        result,
                    },
                )))
            })(),
        );
    }
}
impl AsyncWrite for Writer {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        offered: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        if this.stopped || driver::resource_stop(&this.recorder).is_some() {
            return Poll::Pending;
        }
        if this.write_calls == 32 {
            this.stopped = true;
            stop_native_write(&this.recorder, this.ordinal, this.write_calls);
            return Poll::Pending;
        }
        this.write_calls += 1;
        let remaining = this
            .script
            .fail_after_accepted_bytes
            .get()
            .map(|limit| (*limit as usize).saturating_sub(this.accepted));
        let failure = remaining == Some(0);
        let accepted = if failure {
            0
        } else {
            offered
                .len()
                .min(this.script.chunk_limit as usize)
                .min(remaining.unwrap_or(usize::MAX))
        };
        let terminal = failure || this.accepted.saturating_add(accepted) >= this.materialized_len;
        if this.write_calls == 32 && !terminal {
            // This admitted call returns Pending with no accepted bytes. It
            // does not pretend the prospective accepted prefix was written.
            // The enclosing poll_once sees the latch immediately, and its
            // caller drops the retained stack without allowing call33.
            this.stopped = true;
            stop_native_write(&this.recorder, this.ordinal, this.write_calls);
            this.observe_write(offered, &[], wire::IoResult::Pending);
            return Poll::Pending;
        }
        this.observe_write(
            offered,
            &offered[..accepted],
            if failure {
                wire::IoResult::Error
            } else {
                wire::IoResult::Ok
            },
        );
        if failure {
            Poll::Ready(Err(std::io::Error::other("supplied native write error")))
        } else {
            this.accepted += accepted;
            Poll::Ready(Ok(accepted))
        }
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if this.stopped || driver::resource_stop(&this.recorder).is_some() {
            return Poll::Pending;
        }
        if this.flush_calls == 1 {
            this.stopped = true;
            stop_native_flush(&this.recorder, this.ordinal, this.flush_calls);
            return Poll::Pending;
        }
        this.flush_calls += 1;
        let ok = this.script.flush == wire::FlushReply::Ok;
        capture(
            &this.recorder,
            wire::Fact::Native(wire::NativeFact::Flush(wire::FlushCall {
                item_ordinal: this.ordinal,
                result: if ok {
                    wire::IoResult::Ok
                } else {
                    wire::IoResult::Error
                },
            })),
        );
        Poll::Ready(if ok {
            Ok(())
        } else {
            Err(std::io::Error::other("supplied native flush error"))
        })
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        lost(&self.get_mut().recorder);
        Poll::Ready(Err(std::io::Error::other(
            "native shutdown outside finite MUC scope",
        )))
    }
}
async fn native_item(
    spec: &wire::PlainNative,
    endpoint: &Endpoint,
    observed: &Arc<Observers>,
) -> Result<()> {
    let site = wire::PollSite::new(wire::DriverOwner::Native, endpoint.ordinal)
        .expect("validated finite native endpoint ordinal");
    let item = endpoint
        .receiver
        .lock()
        .unwrap()
        .try_recv()
        .context("actual MUC queue has no native item")?;
    capture_or_lose(
        &observed.recorder,
        (|| -> Result<_> {
            Ok(wire::Fact::Native(wire::NativeFact::Dequeue(
                wire::NativeDequeue {
                    owner: item_owner(&observed.frame, endpoint),
                    item: queued_item(&item, endpoint)?,
                },
            )))
        })(),
    );
    anyhow::ensure!(
        spec.connection_id.0 == endpoint.connection,
        "native connection mismatch"
    );
    if native_preflight(&item, &spec.write, endpoint.ordinal, &observed.recorder).is_some() {
        // This helper is inside the actual frame. A resource cut is one Pending
        // for its enclosing poll_once, not a backend/FrameFailure conversion.
        return std::future::pending::<Result<()>>().await;
    }
    let observation = native::Observation::new(item.durable_source);
    let snapshots = Arc::new(NativeCapture {
        recorder: observed.recorder.clone(),
        frame: observed.frame.operation_id(),
        connection: endpoint.connection,
        ordinal: endpoint.ordinal,
        observation: observation.clone(),
    });
    snapshots.capture(wire::Cut::Introduction);
    let mut port = PlainPort {
        connection: endpoint.connection,
        recorder: observed.recorder.clone(),
    };
    let mut writer = Writer {
        script: spec.write.clone(),
        accepted: 0,
        materialized_len: item.stanza.len(),
        ordinal: endpoint.ordinal,
        recorder: observed.recorder.clone(),
        write_calls: 0,
        flush_calls: 0,
        stopped: false,
    };
    let child_drop = NativeChildDrop(snapshots.clone());
    let child = async {
        let _child_drop = child_drop;
        let lease = DirectWriteLease::prepare_with(&mut port, &item, &observation).await?;
        snapshots.capture(wire::Cut::PortReturn);
        let written = lease
            .write(|stanza| crate::xmpp::send(&mut writer, stanza))
            .await?;
        written.settle_with(&port).await;
        Ok::<_, anyhow::Error>(())
    };
    // Reverse local drop order is intentional: the native runner is destroyed
    // first, then this guard captures actual native retirement, even when the
    // enclosing FrameRunner drops the suspended helper on a resource latch.
    let terminal = NativeAfterRunnerDrop(snapshots.clone());
    let mut runner = Box::pin(NativeWriteRunner::new(observation.clone(), child));
    let actual = std::future::poll_fn(|cx| {
        Poll::Ready(driver::poll_once(
            &observed.recorder,
            site,
            runner.as_mut(),
            cx,
        ))
    })
    .await;
    let result = match actual {
        Ok(Poll::Ready(result)) => result,
        Ok(Poll::Pending) => {
            // Unsupported Pending is observation loss, not a fabricated IO
            // error. Retain this native stack until the outer frame drops it.
            lost(&observed.recorder);
            return std::future::pending::<Result<()>>().await;
        }
        Err(_) => return std::future::pending::<Result<()>>().await,
    };
    drop(runner);
    drop(terminal);
    result
}

/// Accept only a MucInput taken from the root's successfully decoded and
/// validated Case. The root owns the Recorder and envelope and must not call
/// this concurrently with another bridge using the same Recorder.
///
/// Returns the actual runner result. Fixture/outcome matching belongs to the
/// independent reader. No handles with frame mutation authority escape.
pub(crate) async fn run(
    input: wire::MucInput,
    recorder: Recorder,
) -> std::result::Result<wire::Execution, wire::BudgetStop> {
    match run_inner(input, recorder.clone()).await {
        Ok(execution) => execution,
        Err(_) => {
            lost(&recorder);
            Ok(wire::Execution::Failed)
        }
    }
}
async fn run_inner(
    input: wire::MucInput,
    recorder: Recorder,
) -> Result<std::result::Result<wire::Execution, wire::BudgetStop>> {
    let site = wire::PollSite::new(wire::DriverOwner::Muc, 0).expect("fixed MUC poll metadata");
    if let Some(stop) = driver::resource_stop(&recorder) {
        return Ok(Err(stop));
    }
    let command = input_command(&input.command);
    let (room, room_jid) = supplied_room(&command)?;
    let actor = match &command.authority.principal {
        MucActorPrincipal::Local { user_id, .. } => *user_id,
        MucActorPrincipal::Federated { .. } => {
            anyhow::bail!("federated MUC outside accepted scope")
        }
    };
    let repository = Arc::new(DiscussionRepository {
        supplied: input.repository.clone(),
        recorder: recorder.clone(),
        observation: Mutex::new(None),
    });
    let application = RoomApplication::new(
        RepositoryHandle(repository.clone()),
        input.configured_domain.as_str(),
    );
    let prepared = application.prepare_discussion(command.clone());
    let requested = prepared.requested_class();
    let prepared =
        PreparedMucDiscussion::new(prepared, &room, room_jid.clone(), command.stanza.clone())?;
    let frame = FrameExecution::for_saved_case(
        crate::xmpp::protocol::ClientTransport::Tcp,
        input.frame.input.as_str(),
        input.frame.frame_id.0,
    );
    // Reuse the supplied frame's actual MUC and admission owner slots.
    let sessions = SessionExecutions::for_saved_frame(frame.clone());
    let observation = sessions
        .muc_discussion(&prepared.prepared)?
        .context("fixed frame did not register a MUC observation")?;
    let observed = Arc::new(Observers {
        recorder,
        frame: frame.clone(),
        admission: frame.direct_operation(),
        muc: observation,
        requested,
        repository_command: Mutex::new(None),
        begin_returned: AtomicBool::new(false),
        finalize_returned: AtomicBool::new(false),
        commit_pending_polled: AtomicBool::new(false),
        endpoint_pending_polled: AtomicBool::new(false),
    });
    *repository.observation.lock().unwrap() = Some(observed.clone());
    let admission = MessageAdmissionService::new(AdmissionRepository {
        supplied: input.admission.clone(),
        observed: observed.clone(),
    });
    let endpoints = input
        .recipients
        .as_slice()
        .iter()
        .enumerate()
        .map(|(ordinal, x)| Ok(Endpoint::supplied(u8::try_from(ordinal)?, x)))
        .collect::<Result<Vec<_>>>()?;
    observed.both(wire::Cut::Introduction);
    let child_drop = ChildDrop(observed.clone());
    let child = async {
        let _child_drop = child_drop;
        frame.enter(Stage::Handler);
        let request = MessageAdmissionRequest {
            actor_id: actor,
            account_bare: &command.actor_scope,
            normalized_target: &room_jid,
            origin_id: command.origin_id.as_deref(),
            normalized_payload: &command.stanza,
            pow_intent_payload: input.frame.input.as_str(),
            subject: "message",
            actors: &[],
            proof: None,
        };
        frame.enter(Stage::MessageAdmission);
        let retained = observed.admission.begin(&request)?;
        let begin = admission
            .begin_message_admission_retained(&request, &retained)
            .await;
        observed.begin_returned.store(true, Ordering::Relaxed);
        observed.frame(wire::Cut::PortReturn);
        let mut lease = match begin? {
            MessageAdmissionStart::Proceed {
                lease: Some(lease), ..
            } => Some(lease),
            _ => anyhow::bail!("unexpected finite rated admission result"),
        };
        frame.enter(Stage::MucAdmission);
        let bound = prepared.bind(observed.muc.clone())?;
        let completion = application
            .admit_discussion_observed(&bound.request)
            .await
            .map_err(|error| match error {
                muc::AdmissionError::Observation(error) => anyhow::Error::from(error),
                muc::AdmissionError::Repository(error) => error,
            })?;
        observed.muc(wire::Cut::PortReturn);
        // This is the same private bound/live envelope and consuming permit
        // used by the production protocol. Replay produces no accepted envelope.
        if let Some(accepted) = bound.finish(completion)? {
            let port = FanoutPort {
                live: accepted.live,
                endpoints: endpoints.clone(),
                observed: observed.clone(),
            };
            run_muc_discussion_fanout(&port, accepted.permit).await?;
            if let Some(spec) = input.native.get() {
                let endpoint = endpoints.first().context("no MUC native endpoint")?;
                native_item(spec, endpoint, &observed).await?;
            }
        }
        message_admission::finalize_message_admission_with(
            &admission,
            &mut lease,
            "muc",
            || Some(observed.admission.clone()),
            || frame.enter(Stage::MessageFollowup),
            || {},
        )
        .await;
        observed.finalize_returned.store(true, Ordering::Relaxed);
        observed.frame(wire::Cut::PortReturn);
        Ok::<_, anyhow::Error>(())
    };
    let mut runner = Box::pin(frame.run(child));
    let actual = std::future::poll_fn(|cx| {
        Poll::Ready(driver::poll_once(
            &observed.recorder,
            site,
            runner.as_mut(),
            cx,
        ))
    })
    .await;
    observed.both(wire::Cut::AfterPoll);
    let allowed_pending_cut = match input.drive {
        wire::MucDrive::Complete => false,
        wire::MucDrive::DropCommit => observed.commit_pending_polled.load(Ordering::Relaxed),
        wire::MucDrive::DropSecondEndpoint => {
            observed.endpoint_pending_polled.load(Ordering::Relaxed)
        }
    };
    // BudgetStop is deliberately not an anyhow error. Drop the real complete
    // frame stack first, including any nested pending native runner, then take
    // side-only terminal snapshots. Never translate it into FrameFailure.
    drop(runner);
    observed.both(wire::Cut::AfterRunnerDrop);
    let result = match actual {
        Err(stop) => Err(stop),
        Ok(Poll::Ready(Ok(()))) => Ok(wire::Execution::Complete),
        Ok(Poll::Ready(Err(_))) => Ok(wire::Execution::Failed),
        Ok(Poll::Pending) => {
            if !allowed_pending_cut {
                lost(&observed.recorder);
            }
            Ok(wire::Execution::Cancelled)
        }
    };
    // Keep the actual S03 queued prefix alive through the terminal capture.
    // Teardown simply destroys the remaining local queues; it never retries,
    // writes a native item without a native plan, or invokes COMMIT on Drop.
    drop(endpoints);
    drop(sessions);
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixed(n: u128) -> wire::Id {
        wire::Id(Uuid::from_u128(n))
    }
    fn text<const N: usize>(s: &str) -> wire::Text<N> {
        wire::Text::new(s).unwrap()
    }
    fn list<T, const N: usize>(xs: Vec<T>) -> wire::List<T, N> {
        wire::List::new(xs).unwrap()
    }
    fn input(drive: wire::MucDrive, original: Option<wire::Id>) -> wire::MucInput {
        let volatile = drive == wire::MucDrive::DropSecondEndpoint;
        let stanza = format!("<message xmlns='jabber:client' from='room@conference.example.test/a' to='room@conference.example.test' type='groupchat'><body>hi</body><stanza-id xmlns='urn:xmpp:sid:0' by='room@conference.example.test' id='{}'/></message>", fixed(63).0);
        let mut recipients = vec![wire::RecipientInput {
            user_id: fixed(4),
            full_jid: text("a@example.test/one"),
            connection_id: fixed(2),
            blocked: false,
            endpoint: wire::EndpointCut::Return,
        }];
        if volatile {
            recipients.push(wire::RecipientInput {
                user_id: fixed(6),
                full_jid: text("b@example.test/two"),
                connection_id: fixed(7),
                blocked: false,
                endpoint: wire::EndpointCut::Pending,
            });
        }
        if original.is_some() || drive == wire::MucDrive::DropCommit {
            recipients.clear();
        }
        wire::MucInput {
            frame: wire::Frame { frame_id: fixed(1), connection_id: fixed(2), transport: wire::TransportKind::Tcp,
                input: text("<message xmlns='jabber:client' to='room@conference.example.test' type='groupchat'><body>hi</body></message>") },
            configured_domain: text("example.test"),
            command: wire::MucCommand { id: fixed(63), room_id: fixed(60), actor_scope: text("a@example.test"),
                origin_id: if volatile { wire::Nullable::Null(()) } else { wire::Nullable::Value(text("origin")) },
                sender_jid: text("a@example.test/one"), nick: text("a"), stanza: text(&stanza), encrypted: false,
                archive: !volatile, retention_days: 7,
                authority: wire::Authority { clustered: false, expected_room_epoch: fixed(61),
                    principal: wire::MucPrincipal::Local(wire::LocalPrincipal { user_id: fixed(4), local_domain: text("example.test") }),
                    actor_scope: text("a@example.test"), full_jid: text("a@example.test/one"), nick: text("a"),
                    occupant_incarnation: fixed(62), connection_uuid: fixed(2), expected_role: text("participant"),
                    expected_affiliation: text("member"), cluster_target: wire::Nullable::Null(()) } },
            admission: wire::RatedAdmission { fence: wire::AdmissionFenceInput {
                admission_key: wire::Hex::of(&[0; 32]).unwrap(), payload_mac: wire::Hex::of(&[1; 32]).unwrap(),
                lease_token: fixed(64), dedupe_digest: wire::Hex::of(&[2; 32]).unwrap() },
                requirement: wire::AdmissionRequirement { action: text("message"), step: 0, work_factor: 1,
                    max_work_factor: 1, hard_wait_seconds: 0, retry_after_seconds: 0, cooldown_seconds: 0,
                    approximate_max_device_seconds: 0, notice: text("synthetic") },
                begin_commit: wire::CommitCut::Complete, finalize_commit: wire::CommitCut::Complete },
            repository: wire::MucRepository { original_id: nullable(original),
                commit: if drive == wire::MucDrive::DropCommit { wire::CommitCut::Pending } else { wire::CommitCut::Complete } },
            recipients: list(recipients),
            native: if drive == wire::MucDrive::Complete && original.is_none() { wire::Nullable::Value(wire::PlainNative {
                connection_id: fixed(2), write: wire::WriteScript { chunk_limit: 4096,
                    fail_after_accepted_bytes: wire::Nullable::Null(()), flush: wire::FlushReply::Ok } }) }
                else { wire::Nullable::Null(()) }, drive,
        }
    }
    fn case(input: wire::MucInput, name: &str) -> wire::Case {
        wire::Case {
            schema: text(wire::CASE_SCHEMA),
            case_id: text(name),
            adapter_contract: text(wire::ADAPTER_CONTRACT),
            composition: wire::Composition::Muc(input),
        }
    }
    async fn execute(input: wire::MucInput, name: &str) -> wire::Envelope {
        let bytes = serde_json::to_vec(&case(input, name)).unwrap();
        let validated = wire::decode(&bytes).unwrap();
        let wire::Composition::Muc(input) = &validated.case().composition else {
            unreachable!()
        };
        let recorder = Arc::new(Mutex::new(wire::Recorder::new(&validated)));
        let actual = run(input.clone(), recorder.clone()).await;
        let recorder = match Arc::try_unwrap(recorder) {
            Ok(x) => x,
            Err(_) => panic!("recorder escaped adapter"),
        };
        let recorder = recorder.into_inner().unwrap();
        let envelope = match actual {
            Ok(execution) => recorder.finish(execution).unwrap(),
            Err(_) => recorder.finish_resource_stopped().unwrap(),
        };
        wire::validate_envelope(&envelope, &bytes, Some(&validated)).unwrap();
        envelope
    }
    fn frames(e: &wire::Envelope) -> Vec<(u32, &wire::FrameCapture<E>)> {
        e.facts
            .as_slice()
            .iter()
            .filter_map(|x| match &x.fact {
                wire::Fact::Frame(f) => Some((x.seq, f)),
                _ => None,
            })
            .collect()
    }
    fn mucs(e: &wire::Envelope) -> Vec<(u32, &wire::MucCapture<E>)> {
        e.facts
            .as_slice()
            .iter()
            .filter_map(|x| match &x.fact {
                wire::Fact::Muc(wire::MucFact::Snapshot(f)) => Some((x.seq, f)),
                _ => None,
            })
            .collect()
    }
    fn endpoints(e: &wire::Envelope) -> Vec<(u32, &wire::MucEndpoint<E>)> {
        e.facts
            .as_slice()
            .iter()
            .filter_map(|x| match &x.fact {
                wire::Fact::Muc(wire::MucFact::Endpoint(f)) => Some((x.seq, f)),
                _ => None,
            })
            .collect()
    }
    fn complete(e: &wire::Envelope) {
        assert!(matches!(
            e.observation_status,
            wire::ObservationStatus::Complete(_)
        ));
    }
    fn fixed_e(n: u128) -> E {
        E::Encoded(wire::IdentityLabel::Fixed(wire::FixedIdentity {
            uuid: fixed(n),
        }))
    }
    fn assert_child_before_retirement(e: &wire::Envelope, terminal: wire::OwnerTerminal) {
        let muc = mucs(e);
        let terminal_cut = muc
            .iter()
            .find(|(_, f)| f.cut == wire::Cut::AfterRunnerDrop)
            .unwrap();
        assert_eq!(terminal_cut.1.snapshot.terminal.get(), Some(&terminal));
        let drops: Vec<_> = muc
            .iter()
            .filter(|(_, f)| f.cut == wire::Cut::ChildDrop)
            .collect();
        assert!(!drops.is_empty());
        for (seq, f) in drops {
            assert!(*seq < terminal_cut.0);
            assert!(f.snapshot.terminal.get().is_none());
        }
    }
    #[tokio::test]
    async fn stored_receipt_exact_queue_native_flush_and_finalize_are_observed() {
        let e = execute(input(wire::MucDrive::Complete, None), "ordinary-muc-stored").await;
        complete(&e);
        assert_eq!(e.execution.get(), Some(&wire::Execution::Complete));
        let frames = frames(&e);
        let final_frame = frames.last().unwrap().1;
        assert_eq!(final_frame.frame, fixed_e(1));
        assert_eq!(
            final_frame.outcome.get(),
            Some(&wire::FrameOutcome::Completed)
        );
        assert!(matches!(
            final_frame.admission_begin.get().unwrap().knowledge,
            wire::AdmissionKnowledge::ReceiptKnown(_)
        ));
        assert!(matches!(
            final_frame.admission_finalize.get().unwrap().knowledge,
            wire::AdmissionKnowledge::ReceiptKnown(_)
        ));
        let muc = mucs(&e);
        let final_muc = muc.last().unwrap().1;
        assert!(
            matches!(&final_muc.snapshot.knowledge, wire::MucKnowledge::ReceiptKnown(x)
            if matches!(&x.outcome, wire::MucOutcome::Stored(y) if y.id == fixed_e(63))
                && x.fresh_class.get() == Some(&wire::AcceptanceClass::ArchiveAndIdentity))
        );
        assert_eq!(final_muc.snapshot.fanout.accepted, 1);
        let endpoints = endpoints(&e);
        let queued = endpoints
            .iter()
            .find(|(_, x)| x.queued_item.get().is_some())
            .unwrap();
        let (dequeue_seq, dequeued) = e
            .facts
            .as_slice()
            .iter()
            .find_map(|x| match &x.fact {
                wire::Fact::Native(wire::NativeFact::Dequeue(d)) => Some((x.seq, d)),
                _ => None,
            })
            .unwrap();
        assert!(queued.0 < dequeue_seq);
        assert_eq!(queued.1.queued_item.get(), Some(&dequeued.item));
        assert!(dequeued.item.source.get().is_none());
        let flush_seq = e
            .facts
            .as_slice()
            .iter()
            .find_map(|x| match &x.fact {
                wire::Fact::Native(wire::NativeFact::Flush(f))
                    if f.result == wire::IoResult::Ok =>
                {
                    Some(x.seq)
                }
                _ => None,
            })
            .unwrap();
        let finalize_seq = frames
            .iter()
            .find(|(_, f)| f.admission_finalize.get().is_some())
            .unwrap()
            .0;
        assert!(flush_seq < finalize_seq);
        assert_child_before_retirement(&e, wire::OwnerTerminal::Completed);
    }
    #[tokio::test]
    async fn replay_retains_original_identity_and_never_enters_fanout_or_native() {
        let e = execute(
            input(wire::MucDrive::Complete, Some(fixed(65))),
            "ordinary-muc-replay",
        )
        .await;
        complete(&e);
        assert_eq!(e.execution.get(), Some(&wire::Execution::Complete));
        let muc = mucs(&e);
        assert!(matches!(&muc.last().unwrap().1.snapshot.returned,
            wire::Nullable::Value(wire::MucReturned::Outcome(wire::MucOutcome::Replay(x))) if x.id == fixed_e(65)));
        assert_eq!(
            muc.last().unwrap().1.snapshot.fanout.stage,
            wire::FanoutStage::Unavailable
        );
        assert!(endpoints(&e).is_empty());
        assert!(!e.facts.as_slice().iter().any(|x| matches!(
            &x.fact,
            wire::Fact::Native(_) | wire::Fact::Muc(wire::MucFact::Recipients(_))
        )));
        assert!(frames(&e)
            .last()
            .unwrap()
            .1
            .admission_finalize
            .get()
            .is_some());
    }
    #[tokio::test]
    async fn volatile_second_endpoint_is_polled_pending_and_actual_drop_preserves_prefix() {
        let e = execute(
            input(wire::MucDrive::DropSecondEndpoint, None),
            "ordinary-muc-endpoint-drop",
        )
        .await;
        complete(&e);
        assert_eq!(e.execution.get(), Some(&wire::Execution::Cancelled));
        let endpoints = endpoints(&e);
        let first = endpoints
            .iter()
            .find(|(_, x)| x.ordinal == 0 && x.returned.get() == Some(&true))
            .unwrap();
        let second = endpoints
            .iter()
            .find(|(_, x)| x.ordinal == 1 && x.entered)
            .unwrap();
        assert!(first.0 < second.0);
        assert!(first.1.queued_item.get().is_some());
        assert!(endpoints
            .iter()
            .filter(|(_, x)| x.ordinal == 1)
            .all(|(_, x)| x.returned.get().is_none() && x.queued_item.get().is_none()));
        let muc = mucs(&e);
        let final_muc = muc.last().unwrap().1;
        assert!(
            matches!(&final_muc.snapshot.knowledge, wire::MucKnowledge::ReceiptKnown(x)
            if x.fresh_class.get() == Some(&wire::AcceptanceClass::Volatile))
        );
        assert_eq!(final_muc.snapshot.fanout.next_recipient, 1);
        assert_eq!(final_muc.snapshot.fanout.accepted, 1);
        assert!(final_muc.snapshot.fanout.endpoint_pending);
        assert!(frames(&e)
            .last()
            .unwrap()
            .1
            .admission_finalize
            .get()
            .is_none());
        assert_child_before_retirement(&e, wire::OwnerTerminal::Cancelled);
        assert_eq!(e.facts.as_slice().iter().filter(|x| matches!(&x.fact,
            wire::Fact::Driver(p) if p.owner == wire::DriverOwner::Muc && p.result == wire::PollResult::Pending)).count(), 1);
        assert!(
            muc.iter()
                .filter(|(_, x)| x.cut == wire::Cut::ChildDrop)
                .count()
                >= 2
        );
    }
    #[tokio::test]
    async fn commit_is_polled_pending_without_receipt_and_drop_keeps_unknown() {
        let e = execute(
            input(wire::MucDrive::DropCommit, None),
            "ordinary-muc-commit-drop",
        )
        .await;
        complete(&e);
        assert_eq!(e.execution.get(), Some(&wire::Execution::Cancelled));
        let muc = mucs(&e);
        let before = muc
            .iter()
            .find(|(_, x)| x.cut == wire::Cut::AfterPoll)
            .unwrap()
            .1;
        let after = muc.last().unwrap().1;
        assert!(matches!(
            before.snapshot.knowledge,
            wire::MucKnowledge::CommitCallEntered(_)
        ));
        assert_eq!(before.snapshot.knowledge, after.snapshot.knowledge);
        assert!(after.snapshot.returned.get().is_none());
        assert_eq!(after.snapshot.fanout.stage, wire::FanoutStage::Unavailable);
        assert!(endpoints(&e).is_empty());
        let frame = frames(&e).last().unwrap().1;
        assert!(matches!(
            frame.admission_begin.get().unwrap().knowledge,
            wire::AdmissionKnowledge::ReceiptKnown(_)
        ));
        assert!(frame.admission_finalize.get().is_none());
        assert_eq!(frame.outcome.get(), Some(&wire::FrameOutcome::Cancelled));
        assert_child_before_retirement(&e, wire::OwnerTerminal::Cancelled);
        assert_eq!(e.facts.as_slice().iter().filter(|x| matches!(&x.fact,
            wire::Fact::Driver(p) if p.owner == wire::DriverOwner::Muc && p.result == wire::PollResult::Pending)).count(), 1);
        assert!(
            muc.iter()
                .filter(|(_, x)| x.cut == wire::Cut::ChildDrop)
                .count()
                >= 2
        );
    }
    // The draft1 raw_frame_mapping_is_exhaustive_without_unknown_fallback
    // control moved with its only real implementation to shared frame capture:
    // every_actual_stage_discriminant_has_its_exact_closed_projection,
    // outcome_mapping_is_closed_and_never_defaults_unknown_to_pending, and
    // actual_publication_outcomes_project_without_boolean_collapse.
    #[tokio::test]
    async fn partial_native_calls_report_exact_accepted_bytes_before_one_flush() {
        let mut i = input(wire::MucDrive::Complete, None);
        let wire::Nullable::Value(native) = &mut i.native else {
            unreachable!()
        };
        native.write.chunk_limit = 32;
        let e = execute(i, "ordinary-muc-partial-write").await;
        complete(&e);
        let stanza = e
            .facts
            .as_slice()
            .iter()
            .find_map(|x| match &x.fact {
                wire::Fact::Native(wire::NativeFact::Dequeue(d)) => Some(d.item.stanza.as_str()),
                _ => None,
            })
            .unwrap();
        let mut accepted = Vec::new();
        let mut writes = 0;
        let mut flushes = 0;
        for x in e.facts.as_slice() {
            match &x.fact {
                wire::Fact::Native(wire::NativeFact::Write(w)) => {
                    assert_eq!(w.result, wire::IoResult::Ok);
                    let hex: String = serde_json::from_str(
                        &serde_json::to_string(&w.accepted_bytes_hex).unwrap(),
                    )
                    .unwrap();
                    accepted.extend(
                        hex.as_bytes().chunks_exact(2).map(|b| {
                            u8::from_str_radix(std::str::from_utf8(b).unwrap(), 16).unwrap()
                        }),
                    );
                    writes += 1;
                }
                wire::Fact::Native(wire::NativeFact::Flush(f)) => {
                    assert_eq!(f.result, wire::IoResult::Ok);
                    flushes += 1;
                }
                _ => {}
            }
        }
        assert!(writes > 1);
        assert_eq!(accepted, stanza.as_bytes());
        assert_eq!(flushes, 1);
    }
    #[tokio::test]
    async fn short_parser_xml_is_explicit_loss_instead_of_synthesized_live_output() {
        let mut i = input(wire::MucDrive::Complete, None);
        i.command.stanza = text("<message type='groupchat'><body>hi</body></message>");
        let e = execute(i, "ordinary-missing-live-envelope").await;
        assert_eq!(e.execution.get(), Some(&wire::Execution::Failed));
        assert!(matches!(
            e.observation_status,
            wire::ObservationStatus::Lost(_)
        ));
        assert!(e.facts.is_empty());
    }
    #[tokio::test]
    async fn case_label_does_not_select_behavior_or_seed_observed_facts() {
        let a = execute(input(wire::MucDrive::DropSecondEndpoint, None), "label-one").await;
        let b = execute(input(wire::MucDrive::DropSecondEndpoint, None), "label-two").await;
        complete(&a);
        complete(&b);
        assert_ne!(a.input_sha256, b.input_sha256);
        assert_eq!(a.facts, b.facts);
        assert_eq!(a.identity_map, b.identity_map);
    }

    fn recorder_for(input: wire::MucInput) -> Recorder {
        let bytes = serde_json::to_vec(&case(input, "ordinary-r2-control")).unwrap();
        Arc::new(Mutex::new(wire::Recorder::new(
            &wire::decode(&bytes).unwrap(),
        )))
    }
    fn take_recorder(recorder: Recorder) -> wire::Recorder {
        match Arc::try_unwrap(recorder) {
            Ok(recorder) => recorder.into_inner().unwrap(),
            Err(_) => panic!("test owner retained recorder"),
        }
    }
    fn script(chunk: u32, fail: Option<u32>) -> wire::WriteScript {
        wire::WriteScript {
            chunk_limit: chunk,
            fail_after_accepted_bytes: nullable(fail),
            flush: wire::FlushReply::Ok,
        }
    }
    struct NativeResult {
        actual: std::result::Result<Poll<Result<()>>, wire::BudgetStop>,
        snapshot: native::Snapshot,
        accepted: usize,
        writes: u8,
        flushes: u8,
    }
    // Deliberately starts below adapter preflight to exercise the independent
    // runtime backstop. This is an ordinary control, never a saved input route.
    async fn native_backstop(
        item: OutboundItem,
        script: wire::WriteScript,
        recorder: Recorder,
    ) -> NativeResult {
        let site = wire::PollSite::new(wire::DriverOwner::Native, 0).unwrap();
        let observation = native::Observation::new(item.durable_source);
        let mut port = PlainPort {
            connection: fixed(2).0,
            recorder: recorder.clone(),
        };
        let mut writer = Writer {
            script,
            accepted: 0,
            materialized_len: item.stanza.len(),
            ordinal: 0,
            recorder: recorder.clone(),
            write_calls: 0,
            flush_calls: 0,
            stopped: false,
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
        let actual = std::future::poll_fn(|cx| {
            Poll::Ready(driver::poll_once(&recorder, site, runner.as_mut(), cx))
        })
        .await;
        drop(runner);
        NativeResult {
            actual,
            snapshot: observation.snapshot(),
            accepted: writer.accepted,
            writes: writer.write_calls,
            flushes: writer.flush_calls,
        }
    }
    fn observed_fixture(
        i: &wire::MucInput,
        command: MucDiscussion,
        recorder: Recorder,
    ) -> (
        FrameExecution,
        SessionExecutions,
        Arc<Observers>,
        RoomApplication<RepositoryHandle>,
        PreparedMucDiscussion,
    ) {
        let (room, room_jid) = supplied_room(&command).unwrap();
        let repository = Arc::new(DiscussionRepository {
            supplied: i.repository.clone(),
            recorder: recorder.clone(),
            observation: Mutex::new(None),
        });
        let application = RoomApplication::new(
            RepositoryHandle(repository.clone()),
            i.configured_domain.as_str(),
        );
        let prepared = application.prepare_discussion(command.clone());
        let requested = prepared.requested_class();
        let prepared =
            PreparedMucDiscussion::new(prepared, &room, room_jid, command.stanza).unwrap();
        let frame = FrameExecution::for_saved_case(
            crate::xmpp::protocol::ClientTransport::Tcp,
            i.frame.input.as_str(),
            i.frame.frame_id.0,
        );
        let sessions = SessionExecutions::for_saved_frame(frame.clone());
        let muc = sessions
            .muc_discussion(&prepared.prepared)
            .unwrap()
            .unwrap();
        let observed = Arc::new(Observers {
            recorder,
            frame: frame.clone(),
            admission: frame.direct_operation(),
            muc,
            requested,
            repository_command: Mutex::new(None),
            begin_returned: AtomicBool::new(false),
            finalize_returned: AtomicBool::new(false),
            commit_pending_polled: AtomicBool::new(false),
            endpoint_pending_polled: AtomicBool::new(false),
        });
        *repository.observation.lock().unwrap() = Some(observed.clone());
        (frame, sessions, observed, application, prepared)
    }
    #[tokio::test]
    async fn sticky_lost_recorder_does_not_change_any_finite_muc_owner_result() {
        for (i, expected, polls) in [
            (
                input(wire::MucDrive::Complete, None),
                wire::Execution::Complete,
                2,
            ),
            (
                input(wire::MucDrive::Complete, Some(fixed(65))),
                wire::Execution::Complete,
                1,
            ),
            (
                input(wire::MucDrive::DropSecondEndpoint, None),
                wire::Execution::Cancelled,
                1,
            ),
            (
                input(wire::MucDrive::DropCommit, None),
                wire::Execution::Cancelled,
                1,
            ),
        ] {
            let recorder = recorder_for(i.clone());
            driver::lost(&recorder);
            assert_eq!(run(i, recorder.clone()).await.unwrap(), expected);
            assert_eq!(recorder.lock().unwrap().admitted_owner_polls(), polls);
            assert!(driver::resource_stop(&recorder).is_none());
            let e = take_recorder(recorder).finish(expected).unwrap();
            assert!(matches!(
                e.observation_status,
                wire::ObservationStatus::Lost(_)
            ));
            assert_eq!(e.execution.get(), Some(&expected));
            assert!(e.resource_stop.get().is_none());
        }
    }
    #[tokio::test]
    async fn lost_recorder_preserves_actual_native_write_flush_and_retirement() {
        let recorder = recorder_for(input(wire::MucDrive::Complete, None));
        driver::lost(&recorder);
        let result = native_backstop(
            OutboundItem::plain("abcdef".into()),
            script(2, None),
            recorder.clone(),
        )
        .await;
        assert!(matches!(result.actual, Ok(Poll::Ready(Ok(())))));
        assert_eq!((result.accepted, result.writes, result.flushes), (6, 3, 1));
        assert_eq!(
            result.snapshot.writer_result,
            Some(native::WriterResult::FullWrite)
        );
        assert_eq!(
            result.snapshot.write_decision,
            Some(native::WriteDecision::Written)
        );
        assert_eq!(result.snapshot.terminal, Some(native::Terminal::Returned));
        assert!(driver::resource_stop(&recorder).is_none());
    }
    #[tokio::test]
    async fn failed_muc_command_projection_does_not_turn_actual_commit_into_backend_failure() {
        let i = input(wire::MucDrive::Complete, None);
        let recorder = recorder_for(i.clone());
        let mut command = input_command(&i.command);
        command.stanza = command.stanza.replace(
            "<body>hi</body>",
            &format!("<body>{}</body>", "x".repeat(5000)),
        );
        let (frame, _sessions, observed, application, prepared) =
            observed_fixture(&i, command, recorder.clone());
        let child = async {
            let _drop = ChildDrop(observed.clone());
            let bound = prepared.bind(observed.muc.clone())?;
            let completion = application
                .admit_discussion_observed(&bound.request)
                .await
                .map_err(|e| match e {
                    muc::AdmissionError::Observation(e) => anyhow::Error::from(e),
                    muc::AdmissionError::Repository(e) => e,
                })?;
            let returned = completion.outcome();
            assert!(bound.finish(completion)?.is_some());
            Ok::<_, anyhow::Error>(returned)
        };
        let mut runner = Box::pin(frame.run(child));
        let site = wire::PollSite::new(wire::DriverOwner::Muc, 0).unwrap();
        let result = std::future::poll_fn(|cx| {
            Poll::Ready(driver::poll_once(&recorder, site, runner.as_mut(), cx))
        })
        .await;
        drop(runner);
        assert!(
            matches!(result, Ok(Poll::Ready(Ok(MucDiscussionAdmission::Stored(x)))) if x == fixed(63).0)
        );
        assert!(matches!(
            observed.muc.snapshot().knowledge,
            muc::Knowledge::ReceiptKnown(_)
        ));
        assert_eq!(
            observed.muc.snapshot().terminal,
            Some(muc::TerminalReason::Completed)
        );
        assert_eq!(frame.observation_for_saved_case().outcome_raw, 1);
        assert!(driver::resource_stop(&recorder).is_none());
        drop(application);
        drop(observed);
        drop(_sessions);
        drop(frame);
        let e = take_recorder(recorder)
            .finish(wire::Execution::Complete)
            .unwrap();
        assert!(matches!(
            e.observation_status,
            wire::ObservationStatus::Lost(_)
        ));
    }
    #[tokio::test]
    async fn queue_projection_bound_is_loss_and_not_a_new_native_byte_limit() {
        let i = input(wire::MucDrive::Complete, None);
        let recorder = recorder_for(i.clone());
        let (frame, _sessions, observed, _application, _prepared) =
            observed_fixture(&i, input_command(&i.command), recorder.clone());
        let endpoint = Endpoint::supplied(0, &i.recipients.as_slice()[0]);
        let actual_bytes = "x".repeat(20_000);
        endpoint.sender.try_send(actual_bytes).unwrap();
        let spec = wire::PlainNative {
            connection_id: fixed(2),
            write: script(4096, None),
        };
        let mut runner = Box::pin(frame.run(native_item(&spec, &endpoint, &observed)));
        let site = wire::PollSite::new(wire::DriverOwner::Muc, 0).unwrap();
        let actual = std::future::poll_fn(|cx| {
            Poll::Ready(driver::poll_once(&recorder, site, runner.as_mut(), cx))
        })
        .await;
        drop(runner);
        assert!(matches!(actual, Ok(Poll::Ready(Ok(())))));
        assert_eq!(frame.observation_for_saved_case().outcome_raw, 1);
        assert!(driver::resource_stop(&recorder).is_none());
        assert!(endpoint.receiver.lock().unwrap().try_recv().is_err());
        drop(_application);
        drop(_prepared);
        drop(observed);
        drop(_sessions);
        drop(frame);
        let e = take_recorder(recorder)
            .finish(wire::Execution::Complete)
            .unwrap();
        assert!(matches!(
            e.observation_status,
            wire::ObservationStatus::Lost(_)
        ));
        assert!(e.resource_stop.get().is_none());
    }
    #[test]
    fn native_required_calls_count_the_scripted_failure_and_zero_length_exactly() {
        assert_eq!(required_write_calls(33, &script(1, Some(31))), Some(32));
        assert_eq!(required_write_calls(33, &script(1, Some(32))), Some(33));
        assert_eq!(required_write_calls(33, &script(1, Some(0))), Some(1));
        assert_eq!(required_write_calls(33, &script(2, Some(33))), Some(17));
        assert_eq!(required_write_calls(33, &script(2, Some(100))), Some(17));
        assert_eq!(required_write_calls(33, &script(2, None)), Some(17));
        assert_eq!(required_write_calls(0, &script(1, Some(0))), Some(0));
        assert_eq!(required_write_calls(0, &script(1, None)), Some(0));
        assert_eq!(required_write_calls(33, &script(0, None)), None);
    }
    #[tokio::test]
    async fn thirty_second_scripted_failure_remains_genuine_error_and_thirty_third_is_stopped_before_poll(
    ) {
        let item = OutboundItem::plain("x".repeat(33));
        let recorder = recorder_for(input(wire::MucDrive::Complete, None));
        assert!(native_preflight(&item, &script(1, Some(31)), 0, &recorder).is_none());
        let result = native_backstop(item, script(1, Some(31)), recorder.clone()).await;
        assert!(matches!(result.actual, Ok(Poll::Ready(Err(_)))));
        assert_eq!(
            (result.accepted, result.writes, result.flushes),
            (31, 32, 0)
        );
        assert_eq!(
            result.snapshot.writer_result,
            Some(native::WriterResult::Failed)
        );
        assert_eq!(result.snapshot.terminal, Some(native::Terminal::Returned));
        assert!(driver::resource_stop(&recorder).is_none());
        let stop = native_preflight(
            &OutboundItem::plain("x".repeat(33)),
            &script(1, Some(32)),
            0,
            &recorder,
        )
        .unwrap();
        assert!(
            matches!(stop.resource_stop, wire::ResourceStop::NativeWrite(x) if x.admitted_calls == 0)
        );
    }
    #[tokio::test]
    async fn actual_set_to_expansion_drives_preflight_and_keeps_actual_frame_cancelled() {
        let mut i = input(wire::MucDrive::Complete, None);
        let original_len = i.command.stanza.as_str().len();
        let chunk = original_len.div_ceil(32) as u32;
        let wire::Nullable::Value(native) = &mut i.native else {
            unreachable!()
        };
        native.write.chunk_limit = chunk;
        let mut recipients = i.recipients.as_slice().to_vec();
        recipients[0].full_jid = text(&format!("a@example.test/{}", "r".repeat(700)));
        let actual = crate::xmpp::xml_util::set_to(
            i.command.stanza.as_str(),
            recipients[0].full_jid.as_str(),
        );
        assert!(required_write_calls(original_len, &script(chunk, None)).unwrap() <= 32);
        assert!(required_write_calls(actual.len(), &script(chunk, None)).unwrap() > 32);
        i.recipients = list(recipients);
        let e = execute(i, "ordinary-rendered-call-budget").await;
        assert!(e.execution.get().is_none() && e.rejection.get().is_none());
        assert!(
            matches!(e.resource_stop.get(), Some(wire::ResourceStop::NativeWrite(x)) if x.admitted_calls == 0)
        );
        assert_eq!(
            frames(&e).last().unwrap().1.outcome.get(),
            Some(&wire::FrameOutcome::Cancelled)
        );
        assert!(matches!(
            mucs(&e).last().unwrap().1.snapshot.knowledge,
            wire::MucKnowledge::ReceiptKnown(_)
        ));
        assert!(!e
            .facts
            .as_slice()
            .iter()
            .any(|x| matches!(x.fact, wire::Fact::Native(wire::NativeFact::Write(_)))));
        assert_child_before_retirement(&e, wire::OwnerTerminal::Cancelled);
    }
    #[tokio::test]
    async fn lost_observation_does_not_disable_independent_native_write_stop() {
        let recorder = recorder_for(input(wire::MucDrive::Complete, None));
        driver::lost(&recorder);
        let result = native_backstop(
            OutboundItem::plain("x".repeat(33)),
            script(1, None),
            recorder.clone(),
        )
        .await;
        assert!(
            matches!(result.actual, Err(wire::BudgetStop { resource_stop: wire::ResourceStop::NativeWrite(x) })
            if x.admitted_calls == 32)
        );
        assert_eq!(
            (result.accepted, result.writes, result.flushes),
            (31, 32, 0)
        );
        assert!(result.snapshot.writer_result.is_none());
        assert_eq!(result.snapshot.terminal, Some(native::Terminal::Cancelled));
        let e = take_recorder(recorder).finish_resource_stopped().unwrap();
        assert!(e.execution.get().is_none() && e.rejection.get().is_none());
        assert!(matches!(
            e.observation_status,
            wire::ObservationStatus::Lost(_)
        ));
        assert!(e.resource_stop.get().is_some());
    }
    #[tokio::test]
    async fn second_flush_is_resource_pending_without_a_scripted_io_error() {
        use tokio::io::AsyncWriteExt as _;
        let recorder = recorder_for(input(wire::MucDrive::Complete, None));
        let item = OutboundItem::plain("abc".into());
        let observation = native::Observation::new(None);
        let mut port = PlainPort {
            connection: fixed(2).0,
            recorder: recorder.clone(),
        };
        let mut writer = Writer {
            script: script(3, None),
            accepted: 0,
            materialized_len: 3,
            ordinal: 0,
            recorder: recorder.clone(),
            write_calls: 0,
            flush_calls: 0,
            stopped: false,
        };
        let child = async {
            let lease = DirectWriteLease::prepare_with(&mut port, &item, &observation).await?;
            let written = lease
                .write(|stanza| async {
                    crate::xmpp::send(&mut writer, stanza).await?;
                    writer.flush().await?;
                    Ok::<_, anyhow::Error>(())
                })
                .await?;
            written.settle_with(&port).await;
            Ok::<_, anyhow::Error>(())
        };
        let mut runner = Box::pin(NativeWriteRunner::new(observation.clone(), child));
        let site = wire::PollSite::new(wire::DriverOwner::Native, 0).unwrap();
        let actual = std::future::poll_fn(|cx| {
            Poll::Ready(driver::poll_once(&recorder, site, runner.as_mut(), cx))
        })
        .await;
        drop(runner);
        assert!(
            matches!(actual, Err(wire::BudgetStop { resource_stop: wire::ResourceStop::NativeFlush(x) })
            if x.admitted_calls == 1)
        );
        assert_eq!(writer.flush_calls, 1);
        assert!(observation.snapshot().writer_result.is_none());
        assert_eq!(
            observation.snapshot().terminal,
            Some(native::Terminal::Cancelled)
        );
    }
    #[tokio::test]
    async fn nested_native_backstop_drops_children_before_frame_without_backend_failure() {
        let i = input(wire::MucDrive::Complete, None);
        let recorder = recorder_for(i.clone());
        let (frame, sessions, observed, application, prepared) =
            observed_fixture(&i, input_command(&i.command), recorder.clone());
        let item = OutboundItem::plain("x".repeat(33));
        // Preflight originally fits; an ordinary-only stale-script fault below
        // demonstrates the runtime backstop without adding any saved selector.
        assert!(native_preflight(&item, &script(2, None), 0, &recorder).is_none());
        let observation = native::Observation::new(None);
        let snapshots = Arc::new(NativeCapture {
            recorder: recorder.clone(),
            frame: frame.operation_id(),
            connection: fixed(2).0,
            ordinal: 0,
            observation: observation.clone(),
        });
        let mut port = PlainPort {
            connection: fixed(2).0,
            recorder: recorder.clone(),
        };
        let mut writer = Writer {
            script: script(1, None),
            accepted: 0,
            materialized_len: 33,
            ordinal: 0,
            recorder: recorder.clone(),
            write_calls: 0,
            flush_calls: 0,
            stopped: false,
        };
        let frame_child = async {
            let _frame_child_drop = ChildDrop(observed.clone());
            let bound = prepared.bind(observed.muc.clone())?;
            let completion = application
                .admit_discussion_observed(&bound.request)
                .await
                .map_err(|e| match e {
                    muc::AdmissionError::Observation(e) => anyhow::Error::from(e),
                    muc::AdmissionError::Repository(e) => e,
                })?;
            let _accepted = bound.finish(completion)?.unwrap();
            let native_child = async {
                let _native_child_drop = NativeChildDrop(snapshots.clone());
                let lease = DirectWriteLease::prepare_with(&mut port, &item, &observation).await?;
                let written = lease
                    .write(|stanza| crate::xmpp::send(&mut writer, stanza))
                    .await?;
                written.settle_with(&port).await;
                Ok::<_, anyhow::Error>(())
            };
            let terminal = NativeAfterRunnerDrop(snapshots.clone());
            let mut native_runner =
                Box::pin(NativeWriteRunner::new(observation.clone(), native_child));
            let site = wire::PollSite::new(wire::DriverOwner::Native, 0).unwrap();
            let actual = std::future::poll_fn(|cx| {
                Poll::Ready(driver::poll_once(
                    &recorder,
                    site,
                    native_runner.as_mut(),
                    cx,
                ))
            })
            .await;
            let result = match actual {
                Err(_) => return std::future::pending::<Result<()>>().await,
                Ok(Poll::Ready(result)) => result,
                Ok(Poll::Pending) => return std::future::pending::<Result<()>>().await,
            };
            drop(native_runner);
            drop(terminal);
            result
        };
        let mut runner = Box::pin(frame.run(frame_child));
        let site = wire::PollSite::new(wire::DriverOwner::Muc, 0).unwrap();
        let actual = std::future::poll_fn(|cx| {
            Poll::Ready(driver::poll_once(&recorder, site, runner.as_mut(), cx))
        })
        .await;
        assert!(
            matches!(actual, Err(wire::BudgetStop { resource_stop: wire::ResourceStop::NativeWrite(x) })
            if x.admitted_calls == 32)
        );
        drop(runner);
        observed.both(wire::Cut::AfterRunnerDrop);
        assert_eq!((writer.accepted, writer.write_calls), (31, 32));
        assert_eq!(
            observation.snapshot().terminal,
            Some(native::Terminal::Cancelled)
        );
        assert!(observation.snapshot().writer_result.is_none());
        assert_eq!(frame.observation_for_saved_case().outcome_raw, 4);
        assert_eq!(
            observed.muc.snapshot().terminal,
            Some(muc::TerminalReason::Cancelled)
        );
        drop(writer);
        drop(port);
        drop(snapshots);
        drop(application);
        drop(observed);
        drop(sessions);
        drop(frame);
        let e = take_recorder(recorder).finish_resource_stopped().unwrap();
        assert!(e.execution.get().is_none() && e.rejection.get().is_none());
        assert_child_before_retirement(&e, wire::OwnerTerminal::Cancelled);
        let cuts: Vec<_> = e
            .facts
            .as_slice()
            .iter()
            .filter_map(|x| match &x.fact {
                wire::Fact::Native(wire::NativeFact::Snapshot(n)) => Some((x.seq, n)),
                _ => None,
            })
            .collect();
        let child = cuts
            .iter()
            .find(|(_, n)| n.cut == wire::Cut::ChildDrop)
            .unwrap();
        let terminal = cuts
            .iter()
            .find(|(_, n)| n.cut == wire::Cut::AfterRunnerDrop)
            .unwrap();
        assert!(child.0 < terminal.0);
        assert!(child.1.snapshot.get().unwrap().terminal.get().is_none());
        assert_eq!(
            terminal.1.snapshot.get().unwrap().terminal.get(),
            Some(&wire::CallTerminal::Cancelled)
        );
        let frame_terminal = frames(&e).last().unwrap().0;
        assert!(terminal.0 < frame_terminal);
    }

    #[tokio::test]
    async fn thirty_second_terminal_write_still_succeeds_and_flushes_once() {
        let recorder = recorder_for(input(wire::MucDrive::Complete, None));
        let item = OutboundItem::plain("x".repeat(32));
        assert!(native_preflight(&item, &script(1, None), 0, &recorder).is_none());
        let result = native_backstop(item, script(1, None), recorder.clone()).await;
        assert!(matches!(result.actual, Ok(Poll::Ready(Ok(())))));
        assert_eq!(
            (result.accepted, result.writes, result.flushes),
            (32, 32, 1)
        );
        assert_eq!(
            result.snapshot.writer_result,
            Some(native::WriterResult::FullWrite)
        );
        assert!(driver::resource_stop(&recorder).is_none());
    }
    #[tokio::test]
    async fn expanded_native_item_above_4096_within_call_budget_retains_real_success() {
        let mut i = input(wire::MucDrive::Complete, None);
        let old = i.command.stanza.as_str();
        let body_len = 4090 - (old.len() - 2);
        i.command.stanza = text(&old.replace(
            "<body>hi</body>",
            &format!("<body>{}</body>", "x".repeat(body_len)),
        ));
        assert_eq!(i.command.stanza.as_str().len(), 4090);
        let mut recipients = i.recipients.as_slice().to_vec();
        recipients[0].full_jid = text(&format!("a@example.test/{}", "r".repeat(700)));
        let materialized = crate::xmpp::xml_util::set_to(
            i.command.stanza.as_str(),
            recipients[0].full_jid.as_str(),
        );
        assert!(materialized.len() > 4096);
        assert!(required_write_calls(materialized.len(), &script(512, None)).unwrap() <= 32);
        i.recipients = list(recipients);
        let wire::Nullable::Value(native) = &mut i.native else {
            unreachable!()
        };
        native.write.chunk_limit = 512;
        let e = execute(i, "ordinary-large-transformed-item").await;
        complete(&e);
        assert_eq!(e.execution.get(), Some(&wire::Execution::Complete));
        assert!(e.resource_stop.get().is_none());
        let dequeued = e
            .facts
            .as_slice()
            .iter()
            .find_map(|x| match &x.fact {
                wire::Fact::Native(wire::NativeFact::Dequeue(d)) => Some(d),
                _ => None,
            })
            .unwrap();
        assert_eq!(dequeued.item.stanza.as_str(), materialized);
    }

    #[tokio::test]
    async fn sixty_fifth_nested_owner_poll_never_runs_and_outer_frame_is_really_cancelled() {
        let i = input(wire::MucDrive::Complete, None);
        let recorder = recorder_for(i.clone());
        let site = wire::PollSite::new(wire::DriverOwner::Worker, 0).unwrap();
        // Ordinary-only budget priming. Each admitted ready future really is
        // polled; these are not synthesized Driver facts or a saved case input.
        for _ in 0..63 {
            let mut ready = Box::pin(std::future::ready(()));
            let result = std::future::poll_fn(|cx| {
                Poll::Ready(driver::poll_once(&recorder, site, ready.as_mut(), cx))
            })
            .await;
            assert!(matches!(result, Ok(Poll::Ready(()))));
        }
        let actual = run(i, recorder.clone()).await;
        assert!(
            matches!(actual, Err(wire::BudgetStop { resource_stop: wire::ResourceStop::DriverPoll(x) })
            if x.owner == wire::DriverOwner::Native && x.admitted_calls == 64)
        );
        assert_eq!(recorder.lock().unwrap().admitted_owner_polls(), 64);
        let e = take_recorder(recorder).finish_resource_stopped().unwrap();
        assert!(e.execution.get().is_none() && e.rejection.get().is_none());
        assert_eq!(
            e.facts
                .as_slice()
                .iter()
                .filter(|x| matches!(x.fact, wire::Fact::Driver(_)))
                .count(),
            64
        );
        assert!(!e.facts.as_slice().iter().any(|x| matches!(
            x.fact,
            wire::Fact::Native(wire::NativeFact::Write(_) | wire::NativeFact::Flush(_))
        )));
        assert_eq!(
            frames(&e).last().unwrap().1.outcome.get(),
            Some(&wire::FrameOutcome::Cancelled)
        );
        assert_child_before_retirement(&e, wire::OwnerTerminal::Cancelled);
        let terminal = e
            .facts
            .as_slice()
            .iter()
            .find_map(|x| match &x.fact {
                wire::Fact::Native(wire::NativeFact::Snapshot(n))
                    if n.cut == wire::Cut::AfterRunnerDrop =>
                {
                    n.snapshot.get()
                }
                _ => None,
            })
            .unwrap();
        assert_eq!(terminal.preparation, wire::NativePreparation::NotStarted);
        assert_eq!(
            terminal.terminal.get(),
            Some(&wire::CallTerminal::Cancelled)
        );
    }
}
