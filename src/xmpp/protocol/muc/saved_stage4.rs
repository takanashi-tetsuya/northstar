//! Test-only MUC composition adapter over finite supplied replies.
//! Side observations cannot change owner results. Resource stops are independent.
//! Requires the accepted Stage4 wire module, reviewed raw frame observer, and
//! pending cfg(test) SessionExecutions::for_saved_frame constructor.
//! No SQL, AppState, spawned tasks, new timers, Stage3 adapter, or verdicts.
use super::{MucDiscussionLive, PreparedMucDiscussion};
use crate::security::abuse::{
    MessageAdmissionAcceptance, MessageAdmissionLease, MessageAdmissionRequest,
    MessageAdmissionStart, MessageDedupeIdentity, WorkRequirement,
};
use crate::services::message_admission::{
    self,
    witness::{self, AdmissionWitness, DirectOperationHandle},
    MessageAdmissionRepository, MessageAdmissionService,
};
use crate::services::muc::fanout::{run_muc_discussion_fanout, MucFanoutPort, MucFanoutStage};
use crate::stage4_replay::{self as wire, driver};
use crate::xmpp::outbound::{
    DurableDelivery, MixDelivery, OutboundItem, OutboundSender, RouteEnqueue,
    TransportOwnershipSource,
};
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
mod tests;
