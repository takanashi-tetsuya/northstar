//! Canonical, payload-free observation and budget boundary for inbound C2S work.
//!
//! Transport framing and delivery acknowledgements stay in their adapters. The
//! policy table intentionally preserves the existing native/BOSH five-second
//! frame budget and WebSocket's eight-second SASL2-inline exception. BOSH also
//! retains its enclosing request budget. Dropping this runner, including when
//! that outer budget expires, records cancellation and the last reached stage.
//!
//! `elapsed_ms` is cumulative from the start of the ephemeral operation, so
//! publication includes the preceding frame and transport continuation time.
//!
//! Post-write publication is observed separately under the same ephemeral
//! operation identity. It has no new deadline: introducing one would change
//! authentication recovery after bytes have already reached the client.

use super::protocol::ClientTransport;
use crate::services::message_admission::witness::DirectOperationHandle;
use crate::services::mix::foreground::{self, MixForegroundSlot};
use crate::services::muc::discussion::{self, MucDiscussionSlot};
use northstar_auth_application::authentication::publication;
use northstar_message_application::direct_lifecycle::TerminalReason;
use std::{
    future::Future,
    pin::Pin,
    sync::{
        atomic::{AtomicU64, AtomicU8, Ordering},
        Arc,
    },
    task::{Context, Poll},
    time::Duration,
};
use uuid::Uuid;

const FRAME_BUDGET: Duration = Duration::from_secs(5);
const INLINE_AUTH_BUDGET: Duration = Duration::from_secs(8);
static NEXT_SEQUENCE: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(super) enum Stage {
    Validation,
    Handler,
    SmCheckpoint,
    AuthPublication,
    CapsPublication,
    ReplacementNotification,
    MessagePolicy,
    MessageAdmission,
    MessageRouting,
    MessageFollowup,
    MucPolicy,
    MucGateWait,
    MucAuthority,
    MucAdmission,
    MucClusterFanout,
    MucLocalFanout,
    MixPolicy,
    MixAdmission,
}

impl Stage {
    fn label(self) -> &'static str {
        match self {
            Self::Validation => "validation",
            Self::Handler => "handler",
            Self::SmCheckpoint => "sm_checkpoint",
            Self::AuthPublication => "auth_publication",
            Self::CapsPublication => "caps_publication",
            Self::ReplacementNotification => "replacement_notification",
            Self::MessagePolicy => "message_policy",
            Self::MessageAdmission => "message_admission",
            Self::MessageRouting => "message_routing",
            Self::MessageFollowup => "message_followup",
            Self::MucPolicy => "muc_policy",
            Self::MucGateWait => "muc_gate_wait",
            Self::MucAuthority => "muc_authority",
            Self::MucAdmission => "muc_admission",
            Self::MucClusterFanout => "muc_cluster_fanout",
            Self::MucLocalFanout => "muc_local_fanout",
            Self::MixPolicy => "mix_policy",
            Self::MixAdmission => "mix_admission",
        }
    }

    fn from_raw(raw: u8) -> Self {
        match raw {
            1 => Self::Handler,
            2 => Self::SmCheckpoint,
            3 => Self::AuthPublication,
            4 => Self::CapsPublication,
            5 => Self::ReplacementNotification,
            6 => Self::MessagePolicy,
            7 => Self::MessageAdmission,
            8 => Self::MessageRouting,
            9 => Self::MessageFollowup,
            10 => Self::MucPolicy,
            11 => Self::MucGateWait,
            12 => Self::MucAuthority,
            13 => Self::MucAdmission,
            14 => Self::MucClusterFanout,
            15 => Self::MucLocalFanout,
            16 => Self::MixPolicy,
            17 => Self::MixAdmission,
            _ => Self::Validation,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
enum Outcome {
    Pending,
    Completed,
    BackendFailure,
    TimedOut,
    Cancelled,
    Panicked,
    IntegrityRejected,
    CredentialRejected,
    RouteRejected,
    CompletedWithDeferredNotification,
}

impl Outcome {
    fn label(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Completed => "completed",
            Self::BackendFailure => "backend_failure",
            Self::TimedOut => "timed_out",
            Self::Cancelled => "cancelled",
            Self::Panicked => "panicked",
            Self::IntegrityRejected => "integrity_rejected",
            Self::CredentialRejected => "credential_rejected",
            Self::RouteRejected => "route_rejected",
            Self::CompletedWithDeferredNotification => "completed_with_deferred_notification",
        }
    }
}

/// Sanitized publication facts, not new authentication or recovery policy.
/// Transport adapters retain the existing boolean decision: a notification
/// left for maintenance does not turn already-published authentication into a
/// failed login. Rejections contain no credentials, route identity or errors.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum PublicationResult {
    Completed,
    BackendFailure,
    IntegrityRejected,
    CredentialRejected,
    RouteRejected,
    CompletedWithDeferredNotification,
}

impl PublicationResult {
    pub(super) const fn transport_succeeded(self) -> bool {
        matches!(
            self,
            Self::Completed | Self::CompletedWithDeferredNotification
        )
    }

    const fn outcome(self) -> Outcome {
        match self {
            Self::Completed => Outcome::Completed,
            Self::BackendFailure => Outcome::BackendFailure,
            Self::IntegrityRejected => Outcome::IntegrityRejected,
            Self::CredentialRejected => Outcome::CredentialRejected,
            Self::RouteRejected => Outcome::RouteRejected,
            Self::CompletedWithDeferredNotification => Outcome::CompletedWithDeferredNotification,
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct Policy {
    transport: &'static str,
    operation: &'static str,
    budget: Duration,
}

impl Policy {
    fn for_frame(transport: ClientTransport, frame: &str) -> Self {
        let inline = transport == ClientTransport::WebSocket && is_inline_auth(frame);
        Self {
            transport: match transport {
                ClientTransport::Tcp => "tcp",
                ClientTransport::WebSocket => "websocket",
                ClientTransport::Bosh => "bosh",
            },
            operation: if inline {
                "sasl2_inline_auth"
            } else {
                "stream_frame"
            },
            budget: if inline {
                INLINE_AUTH_BUDGET
            } else {
                FRAME_BUDGET
            },
        }
    }
}

fn is_inline_auth(frame: &str) -> bool {
    let Some(root_name) = frame
        .strip_prefix('<')
        .and_then(|xml| xml.split([' ', '\t', '\r', '\n', '>', '/']).next())
    else {
        return false;
    };
    if root_name != "authenticate" && !root_name.ends_with(":authenticate") {
        return false;
    }
    let Ok(document) = roxmltree::Document::parse(frame) else {
        return false;
    };
    let root = document.root_element();
    root.tag_name().name() == "authenticate"
        && root.tag_name().namespace() == Some(super::protocol::sasl2::SASL2_NS)
        && root.children().any(|child| {
            child.is_element()
                && matches!(
                    (child.tag_name().name(), child.tag_name().namespace()),
                    ("bind", Some("urn:xmpp:bind:0")) | ("resume", Some("urn:xmpp:sm:3"))
                )
        })
}

#[derive(Default)]
struct CredentialAttempts {
    closed: bool,
    slots: [Option<publication::CredentialObservation>; 3],
}

struct Progress {
    operation_id: Uuid,
    direct_operation: DirectOperationHandle,
    muc_discussion: MucDiscussionSlot,
    mix_foreground: MixForegroundSlot,
    auth_receipt: std::sync::Mutex<Option<publication::Observation>>,
    credential_attempts: std::sync::Mutex<CredentialAttempts>,
    sequence: u64,
    policy: Policy,
    stage: AtomicU8,
    started: tokio::time::Instant,
    outcome: AtomicU8,
}

#[derive(Clone)]
pub(super) struct FrameExecution(Arc<Progress>);

/// Copied raw facts only; this value retains no frame owner or mutation authority.
#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct FrameObservation {
    pub(super) operation_id: Uuid,
    pub(super) stage_raw: u8,
    pub(super) outcome_raw: u8,
}

/// Observation ownership only. A BOSH response can defer publication while
/// later payloads replace the current frame; the originating context survives.
#[derive(Default)]
pub(super) struct SessionExecutions {
    current: Option<FrameExecution>,
}

impl SessionExecutions {
    /// Retains exactly the supplied frame and its existing lifecycle state.
    #[cfg(test)]
    pub(super) fn for_saved_frame(frame: FrameExecution) -> Self {
        Self {
            current: Some(frame),
        }
    }

    pub(super) fn begin(&mut self, transport: ClientTransport, frame: &str) -> FrameExecution {
        let execution = FrameExecution::new(transport, frame);
        self.current = Some(execution.clone());
        execution
    }

    pub(super) fn auth_origin(&self) -> Option<FrameExecution> {
        self.current
            .as_ref()
            .filter(|execution| {
                execution.0.outcome.load(Ordering::Relaxed) == Outcome::Pending as u8
            })
            .cloned()
    }

    pub(super) fn enter(&self, stage: Stage) {
        if let Some(execution) = &self.current {
            execution.enter(stage);
        }
    }

    pub(super) fn direct_operation(&self) -> Option<DirectOperationHandle> {
        self.current
            .as_ref()
            .filter(|execution| {
                execution.0.outcome.load(Ordering::Relaxed) == Outcome::Pending as u8
            })
            .map(FrameExecution::direct_operation)
    }

    pub(super) fn muc_discussion(
        &self,
        prepared: &discussion::PreparedDiscussion,
    ) -> Result<Option<discussion::Observation>, discussion::Rejected> {
        let Some(execution) = &self.current else {
            return Ok(None);
        };
        if execution.0.outcome.load(Ordering::Relaxed) != Outcome::Pending as u8 {
            return Err(discussion::Rejected::Retired);
        }
        execution.0.muc_discussion.register(prepared).map(Some)
    }

    pub(super) fn mix_foreground(
        &self,
        prepare: impl FnOnce() -> Result<foreground::PreparedIngress, foreground::Rejected>,
    ) -> Result<Option<foreground::Observation>, foreground::Rejected> {
        let Some(execution) = &self.current else {
            return Ok(None);
        };
        if execution.0.outcome.load(Ordering::Relaxed) != Outcome::Pending as u8 {
            return Err(foreground::Rejected::Retired);
        }
        let prepared = prepare()?;
        execution.0.mix_foreground.register(&prepared).map(Some)
    }
}

#[derive(Debug)]
pub(crate) enum FrameFailure {
    Backend(anyhow::Error),
    TimedOut,
}

impl FrameExecution {
    pub(super) fn new(transport: ClientTransport, frame: &str) -> Self {
        Self::initialize(transport, frame, Uuid::new_v4())
    }

    fn initialize(transport: ClientTransport, frame: &str, operation_id: Uuid) -> Self {
        Self(Arc::new(Progress {
            operation_id,
            direct_operation: DirectOperationHandle::new(operation_id),
            muc_discussion: MucDiscussionSlot::default(),
            mix_foreground: MixForegroundSlot::default(),
            auth_receipt: std::sync::Mutex::new(None),
            credential_attempts: std::sync::Mutex::new(CredentialAttempts::default()),
            sequence: NEXT_SEQUENCE.fetch_add(1, Ordering::Relaxed),
            policy: Policy::for_frame(transport, frame),
            stage: AtomicU8::new(Stage::Validation as u8),
            started: tokio::time::Instant::now(),
            outcome: AtomicU8::new(Outcome::Pending as u8),
        }))
    }

    #[cfg(test)]
    pub(super) fn for_saved_case(
        transport: ClientTransport,
        frame: &str,
        operation_id: Uuid,
    ) -> Self {
        Self::initialize(transport, frame, operation_id)
    }

    /// Copies actual stored facts without interpreting unknown raw values.
    ///
    /// The two Relaxed loads are not a linearizable multi-field snapshot. A
    /// saved adapter must prove that no retained task, runner, or frame clone
    /// can mutate these fields at its actual quiescent capture cut. Returning
    /// from a manual poll or completing synchronous destruction alone does not
    /// prove that other retained owners are quiescent. Without that proof the
    /// adapter must report missing facts and observation loss, not infer them.
    #[cfg(test)]
    pub(super) fn observation_for_saved_case(&self) -> FrameObservation {
        FrameObservation {
            operation_id: self.0.operation_id,
            stage_raw: self.0.stage.load(Ordering::Relaxed),
            outcome_raw: self.0.outcome.load(Ordering::Relaxed),
        }
    }

    pub(super) fn direct_operation(&self) -> DirectOperationHandle {
        self.0.direct_operation.clone()
    }

    pub(super) fn operation_id(&self) -> Uuid {
        self.0.operation_id
    }

    pub(super) fn prepare_credential(
        &self,
        kind: publication::CredentialKind,
        connection: Uuid,
    ) -> anyhow::Result<publication::PreparedCredential> {
        let mut attempts = self.0.credential_attempts.lock().unwrap();
        anyhow::ensure!(!attempts.closed, "credential frame already retired");
        // Source-bound to one of each kind: inline resume may fall through to
        // one binding or unbound FAST attempt. Never replace an earlier Unknown.
        anyhow::ensure!(
            attempts.slots[kind.index()].is_none(),
            "credential kind already attempted in this frame"
        );
        let ordinal = attempts.slots.iter().flatten().count() as u8;
        let prepared =
            publication::PreparedCredential::new(self.operation_id(), connection, ordinal, kind);
        attempts.slots[kind.index()] = Some(prepared.observation());
        Ok(prepared)
    }

    pub(super) fn retain_auth_receipt(
        &self,
        observation: publication::Observation,
    ) -> anyhow::Result<()> {
        anyhow::ensure!(
            observation.snapshot().frame == Some(self.0.operation_id),
            "auth receipt belongs to another frame"
        );
        let mut slot = self.0.auth_receipt.lock().unwrap();
        anyhow::ensure!(
            slot.is_none(),
            "frame already returned a credential receipt"
        );
        *slot = Some(observation);
        Ok(())
    }

    pub(super) fn enter(&self, stage: Stage) {
        let previous = self.0.stage.swap(stage as u8, Ordering::Relaxed);
        if previous == stage as u8 {
            return;
        }
        let progress = &self.0;
        let publication = matches!(
            stage,
            Stage::AuthPublication | Stage::CapsPublication | Stage::ReplacementNotification
        );
        tracing::debug!(target: "rust_xmpp_server::xmpp::frame_execution",
            operation_id = %progress.operation_id,
            sequence = progress.sequence,
            transport = progress.policy.transport,
            operation = progress.policy.operation,
            phase = if publication { "publication" } else { "frame" },
            stage = stage.label(),
            outcome = "pending",
            elapsed_ms = progress.started.elapsed().as_millis().min(u64::MAX as u128) as u64,
            bounded = !publication,
            budget_ms = if publication { 0 } else { progress.policy.budget.as_millis() as u64 },
            "C2S execution advanced"
        );
    }

    pub(super) fn run<T>(
        &self,
        future: impl Future<Output = anyhow::Result<T>>,
    ) -> impl Future<Output = Result<T, FrameFailure>> {
        // Construct the observation before the child is first polled, so
        // dropping even an unpolled runner retires its already-owned operation.
        let observation = Observation::new(self.clone(), "frame", Some(self.0.policy.budget));
        let budget = self.0.policy.budget;
        FrameRunner {
            child: Some(Box::pin(async move {
                tokio::time::timeout(budget, future).await
            })),
            observation,
            poll_in_progress: false,
        }
    }

    pub(super) async fn observe_publication(
        &self,
        future: impl Future<Output = PublicationResult>,
    ) -> bool {
        self.0
            .stage
            .store(Stage::AuthPublication as u8, Ordering::Relaxed);
        let mut observation = Observation::new(self.clone(), "publication", None);
        let result = future.await;
        observation.finish(result.outcome());
        result.transport_succeeded()
    }
}

/// Explicit destruction order: the entire child/timeout future is dropped
/// before the outer observation snapshots and retires admission ownership.
/// This also applies when the returned runner has never been polled.
struct FrameRunner<F> {
    child: Option<Pin<Box<F>>>,
    observation: Observation,
    // Normal exits clear this only after child polling and ready destruction.
    // Unwinding leaves the fact available even after an outer catch_unwind.
    poll_in_progress: bool,
}

impl<F, T> Future for FrameRunner<F>
where
    F: Future<Output = Result<anyhow::Result<T>, tokio::time::error::Elapsed>>,
{
    type Output = Result<T, FrameFailure>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        this.poll_in_progress = true;
        let result = match this
            .child
            .as_mut()
            .expect("frame polled after completion")
            .as_mut()
            .poll(cx)
        {
            Poll::Pending => {
                this.poll_in_progress = false;
                return Poll::Pending;
            }
            Poll::Ready(result) => result,
        };
        // A ready child's destructor may still release operation-local state.
        // Complete that destruction before emitting the terminal snapshot.
        drop(this.child.take());
        this.poll_in_progress = false;
        Poll::Ready(match result {
            Ok(Ok(value)) => {
                this.observation.finish(Outcome::Completed);
                Ok(value)
            }
            Ok(Err(error)) => {
                this.observation.finish(Outcome::BackendFailure);
                Err(FrameFailure::Backend(error))
            }
            Err(_) => {
                this.observation.finish(Outcome::TimedOut);
                Err(FrameFailure::TimedOut)
            }
        })
    }
}

impl<F> Drop for FrameRunner<F> {
    fn drop(&mut self) {
        drop(self.child.take());
        if self.poll_in_progress {
            // Preserve a child poll/destructor panic even when a caller caught
            // its original payload before finally destroying this runner.
            self.observation.finish(Outcome::Panicked);
        }
        // Observation's ordinary field destructor now runs with no child.
    }
}

/// Owned by the executing future, so abort/timeout of an enclosing operation
/// cannot silently erase its final stage. No guard or mutex crosses an await.
struct Observation {
    execution: FrameExecution,
    phase: &'static str,
    budget: Option<Duration>,
    finished: bool,
}

impl Observation {
    fn new(execution: FrameExecution, phase: &'static str, budget: Option<Duration>) -> Self {
        let progress = &execution.0;
        tracing::debug!(target: "rust_xmpp_server::xmpp::frame_execution",
            operation_id = %progress.operation_id,
            sequence = progress.sequence,
            transport = progress.policy.transport,
            operation = progress.policy.operation,
            phase,
            stage = Stage::from_raw(progress.stage.load(Ordering::Relaxed)).label(),
            outcome = "pending",
            elapsed_ms = progress.started.elapsed().as_millis().min(u64::MAX as u128) as u64,
            bounded = budget.is_some(),
            budget_ms = budget.map_or(0, |value| value.as_millis() as u64),
            "C2S execution started"
        );
        Self {
            execution,
            phase,
            budget,
            finished: false,
        }
    }

    fn finish(&mut self, outcome: Outcome) {
        if self.finished {
            return;
        }
        self.finished = true;
        let progress = &self.execution.0;
        if self.phase == "frame" {
            let reason = match outcome {
                Outcome::Completed => TerminalReason::Completed,
                Outcome::TimedOut => TerminalReason::TimedOut,
                Outcome::Cancelled => TerminalReason::Cancelled,
                Outcome::Panicked => TerminalReason::Panicked,
                _ => TerminalReason::BackendFailure,
            };
            let snapshot = progress.direct_operation.retire(reason);
            if snapshot.reservation.is_some()
                || snapshot.finalization.is_some()
                || snapshot.direct.is_some()
            {
                // Never print the snapshot, command, payload, fence, or lease.
                // Reservation, direct SQL, and queue facts remain independent;
                // none implies a transport write or settlement.
                tracing::debug!(target: "rust_xmpp_server::xmpp::direct_lifecycle",
                    operation_id = %snapshot.operation,
                    classification = ?snapshot.classification(),
                    reservation = ?snapshot.reservation,
                    finalization = ?snapshot.finalization,
                    direct = ?snapshot.direct,
                    handoff = ?snapshot.handoff,
                    terminal = ?snapshot.terminal,
                    "frame admission ownership retired"
                );
            }
            let muc_reason = match reason {
                TerminalReason::Completed => discussion::TerminalReason::Completed,
                TerminalReason::BackendFailure => discussion::TerminalReason::BackendFailure,
                TerminalReason::TimedOut => discussion::TerminalReason::TimedOut,
                TerminalReason::Cancelled => discussion::TerminalReason::Cancelled,
                TerminalReason::Panicked => discussion::TerminalReason::Panicked,
            };
            if let Some(summary) = progress.muc_discussion.retire(muc_reason) {
                tracing::debug!(target: "rust_xmpp_server::xmpp::muc_discussion",
                    operation_id = %progress.operation_id,
                    repository_started = summary.repository_started,
                    knowledge = ?summary.knowledge,
                    receipt_class = ?summary.receipt_class,
                    returned = ?summary.returned,
                    fanout = ?summary.fanout,
                    terminal = ?summary.terminal,
                    "frame MUC discussion ownership retired"
                );
            }
        }
        if self.phase == "frame" {
            let reason = match outcome {
                Outcome::Completed => foreground::TerminalReason::Completed,
                Outcome::TimedOut => foreground::TerminalReason::TimedOut,
                Outcome::Cancelled => foreground::TerminalReason::Cancelled,
                Outcome::Panicked => foreground::TerminalReason::Panicked,
                _ => foreground::TerminalReason::BackendFailure,
            };
            if let Some(summary) = progress.mix_foreground.retire(reason) {
                tracing::debug!(target: "rust_xmpp_server::xmpp::mix_foreground",
                    operation_id = %progress.operation_id,
                    replay_started = summary.replay_started,
                    replay_returned = ?summary.replay_returned,
                    raw_existing = summary.raw_existing,
                    identity_classified = summary.identity_classified,
                    repository_started = summary.repository_started,
                    knowledge = ?summary.knowledge,
                    returned = ?summary.returned,
                    wake = ?summary.wake,
                    terminal = ?summary.terminal,
                    "frame MIX foreground ownership retired"
                );
            }
        }
        if self.phase == "frame" {
            let returned = match outcome {
                Outcome::Completed => publication::HandlerReturn::Completed,
                Outcome::TimedOut => publication::HandlerReturn::TimedOut,
                Outcome::Cancelled => publication::HandlerReturn::Cancelled,
                Outcome::Panicked => publication::HandlerReturn::Panicked,
                _ => publication::HandlerReturn::Failed,
            };
            let attempts = {
                let mut attempts = progress.credential_attempts.lock().unwrap();
                attempts.closed = true;
                attempts.slots.clone()
            };
            for attempt in attempts.into_iter().flatten() {
                attempt.handler_returned(returned);
                let snapshot = attempt.snapshot();
                tracing::debug!(target: "rust_xmpp_server::xmpp::auth_credential",
                    operation_id = %snapshot.frame, attempt = %snapshot.attempt,
                    ordinal = snapshot.ordinal, kind = ?snapshot.kind,
                    begin = ?snapshot.begin, eligibility = ?snapshot.eligibility,
                    rollback = ?snapshot.rollback, commit = ?snapshot.commit,
                    returned = ?snapshot.returned, return_matches = snapshot.return_matches,
                    transferred = snapshot.transferred, call_terminal = ?snapshot.call_terminal,
                    handler = ?snapshot.handler, integrity_failure = snapshot.integrity_failure,
                    "frame credential observation retained"
                );
            }
            let auth = progress.auth_receipt.lock().unwrap().clone();
            if let Some(auth) = auth {
                auth.handler_returned(returned);
            }
        }
        progress.outcome.store(outcome as u8, Ordering::Relaxed);
        let stage = Stage::from_raw(progress.stage.load(Ordering::Relaxed)).label();
        let elapsed_ms = progress.started.elapsed().as_millis().min(u64::MAX as u128) as u64;
        let budget_ms = self.budget.map_or(0, |value| value.as_millis() as u64);
        macro_rules! emit {
            ($level:expr) => {
                tracing::event!(target: "rust_xmpp_server::xmpp::frame_execution", $level,
                    operation_id = %progress.operation_id,
                    sequence = progress.sequence,
                    transport = progress.policy.transport,
                    operation = progress.policy.operation,
                    phase = self.phase,
                    stage,
                    outcome = outcome.label(),
                    elapsed_ms,
                    bounded = self.budget.is_some(),
                    budget_ms,
                    "C2S execution finished"
                );
            };
        }
        if outcome == Outcome::Completed {
            emit!(tracing::Level::DEBUG);
        } else {
            emit!(tracing::Level::WARN);
        }
    }
}

impl Drop for Observation {
    fn drop(&mut self) {
        if !self.finished {
            self.finish(if std::thread::panicking() {
                Outcome::Panicked
            } else {
                Outcome::Cancelled
            });
        }
    }
}

#[cfg(test)]
mod tests;
