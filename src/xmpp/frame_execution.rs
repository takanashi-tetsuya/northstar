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

struct Progress {
    operation_id: Uuid,
    direct_operation: DirectOperationHandle,
    muc_discussion: MucDiscussionSlot,
    mix_foreground: MixForegroundSlot,
    sequence: u64,
    policy: Policy,
    stage: AtomicU8,
    started: tokio::time::Instant,
    outcome: AtomicU8,
}

#[derive(Clone)]
pub(super) struct FrameExecution(Arc<Progress>);

/// Observation ownership only. A BOSH response can defer publication while
/// later payloads replace the current frame; the originating context survives.
#[derive(Default)]
pub(super) struct SessionExecutions {
    current: Option<FrameExecution>,
    publication: Option<FrameExecution>,
}

impl SessionExecutions {
    pub(super) fn begin(&mut self, transport: ClientTransport, frame: &str) -> FrameExecution {
        let execution = FrameExecution::new(transport, frame);
        self.current = Some(execution.clone());
        execution
    }

    pub(super) fn defer_publication(&mut self, execution: FrameExecution) {
        self.publication = Some(execution);
    }

    pub(super) fn take_publication(&mut self) -> Option<FrameExecution> {
        let execution = self.publication.take()?;
        self.current = Some(execution.clone());
        Some(execution)
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

    pub(super) fn direct_operation(&self) -> DirectOperationHandle {
        self.0.direct_operation.clone()
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
mod tests {
    use super::*;
    use futures::FutureExt;
    use std::{future::pending, io::Write, panic::AssertUnwindSafe, sync::Mutex, task::Poll};

    #[tokio::test]
    async fn supplied_frame_identity_preserves_initial_policy_and_actual_runner_retirement() {
        let id = Uuid::from_u128(101);
        let raw = "<message type='chat'/>";
        let frame = FrameExecution::for_saved_case(ClientTransport::Tcp, raw, id);
        let policy = Policy::for_frame(ClientTransport::Tcp, raw);
        assert_eq!(frame.0.operation_id, id);
        assert_eq!(frame.0.policy.budget, policy.budget);
        assert_eq!(frame.0.policy.transport, policy.transport);
        assert_eq!(frame.0.policy.operation, policy.operation);
        assert_eq!(
            frame.0.stage.load(Ordering::Relaxed),
            Stage::Validation as u8
        );
        assert_eq!(
            frame.0.outcome.load(Ordering::Relaxed),
            Outcome::Pending as u8
        );
        let retained = frame.direct_operation();
        let mut runner = Box::pin(frame.run(async {
            let request = crate::abuse::MessageAdmissionRequest {
                actor_id: Uuid::from_u128(1),
                account_bare: "alice@example.test",
                normalized_target: "bob@example.test",
                origin_id: None,
                normalized_payload: raw,
                pow_intent_payload: raw,
                subject: "message",
                actors: &[],
                proof: None,
            };
            let _issued = retained.begin(&request).unwrap();
            pending::<()>().await;
            Ok(())
        }));
        assert!(retained.snapshot().reservation.is_none());
        assert!(futures::poll!(&mut runner).is_pending());
        drop(runner);
        let snapshot = retained.snapshot();
        assert_eq!(snapshot.terminal, Some(TerminalReason::Cancelled));
        let begin = snapshot.reservation.unwrap();
        assert_eq!(begin.witness.effect().correlation.operation, id);
        assert!(!begin.effect_started);
        assert!(matches!(
            begin.witness.knowledge(),
            northstar_abuse_policy::admission_execution::Knowledge::NoCommitRequested
        ));
    }

    #[derive(Clone, Default)]
    struct TraceCapture(Arc<Mutex<Vec<u8>>>);

    impl Write for TraceCapture {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl TraceCapture {
        fn install() -> (Self, tracing::subscriber::DefaultGuard) {
            Self::install_with_filter("off,rust_xmpp_server::xmpp::frame_execution=debug")
        }

        fn install_with_filter(filter: &str) -> (Self, tracing::subscriber::DefaultGuard) {
            let capture = Self::default();
            let writer = capture.clone();
            let subscriber = tracing_subscriber::fmt()
                .without_time()
                .json()
                .with_ansi(false)
                .with_target(true)
                .with_env_filter(filter)
                .with_writer(move || writer.clone())
                .finish();
            // These tests use Tokio's current-thread runtime. The subscriber
            // is local to this test thread, including its awaited futures.
            let guard = tracing::subscriber::set_default(subscriber);
            (capture, guard)
        }

        fn events(&self) -> Vec<serde_json::Value> {
            let bytes = self.0.lock().unwrap();
            std::str::from_utf8(&bytes)
                .unwrap()
                .lines()
                .map(|line| serde_json::from_str(line).unwrap())
                .collect()
        }
    }

    fn assert_one_trace_pair(
        events: &[serde_json::Value],
        operation_id: Uuid,
        phase: &str,
        expected_outcome: &str,
        expected_stage: &str,
    ) -> serde_json::Value {
        let operation_id = operation_id.to_string();
        let phase_events = events
            .iter()
            .filter(|event| {
                event["fields"]["operation_id"] == operation_id && event["fields"]["phase"] == phase
            })
            .collect::<Vec<_>>();
        let starts = phase_events
            .iter()
            .filter(|event| event["fields"]["message"] == "C2S execution started")
            .collect::<Vec<_>>();
        let terminals = phase_events
            .iter()
            .filter(|event| event["fields"]["message"] == "C2S execution finished")
            .collect::<Vec<_>>();
        assert_eq!(starts.len(), 1, "one start for {operation_id}/{phase}");
        assert_eq!(
            terminals.len(),
            1,
            "one terminal for {operation_id}/{phase}"
        );
        let terminal = terminals[0];
        assert_eq!(terminal["fields"]["outcome"], expected_outcome);
        assert_eq!(terminal["fields"]["stage"], expected_stage);
        assert_eq!(
            terminal["level"],
            if expected_outcome == "completed" {
                "DEBUG"
            } else {
                "WARN"
            }
        );
        assert_eq!(
            starts[0]["fields"]["sequence"],
            terminal["fields"]["sequence"]
        );
        assert_eq!(starts[0]["fields"]["outcome"], "pending");
        for event in &phase_events {
            assert_eq!(event["target"], "rust_xmpp_server::xmpp::frame_execution");
            let fields = event["fields"].as_object().unwrap();
            assert_eq!(fields.len(), 11, "bounded event field allowlist");
            for name in [
                "message",
                "operation_id",
                "sequence",
                "transport",
                "operation",
                "phase",
                "stage",
                "outcome",
                "elapsed_ms",
                "bounded",
                "budget_ms",
            ] {
                assert!(fields.contains_key(name), "missing event field {name}");
            }
        }
        (**terminal).clone()
    }

    fn execution() -> FrameExecution {
        FrameExecution::new(ClientTransport::Tcp, "<message/>")
    }

    fn outcome(execution: &FrameExecution) -> u8 {
        execution.0.outcome.load(Ordering::Relaxed)
    }

    struct MixChildDropMarker {
        owner: foreground::Observation,
        dropped: Arc<std::sync::atomic::AtomicBool>,
    }
    impl Drop for MixChildDropMarker {
        fn drop(&mut self) {
            assert_eq!(
                self.owner.snapshot().terminal,
                None,
                "MIX owner retired before child destruction"
            );
            self.dropped.store(true, Ordering::Relaxed);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn mix_foreground_receipt_survives_actual_frame_boundaries_without_generic_finalize() {
        use crate::services::mix::foreground::fixture::{self, Calls, Cut};
        use northstar_room_application::mix::{KnowledgeClass, ReturnClass, Wake};
        for cut in 0..9 {
            let effect_cut = match cut {
                1 => Cut::BeforeCommit,
                2 => Cut::DuringCommit,
                3 | 7 => Cut::AfterReceipt,
                5 => Cut::PanicAfterReceipt,
                8 => Cut::FailAfterReceipt,
                _ => Cut::Return,
            };
            let prepared = fixture::prepared(false);
            let mut sessions = SessionExecutions::default();
            let execution = sessions.begin(ClientTransport::Tcp, "<message type='groupchat'/>");
            let owner = sessions
                .mix_foreground(|| Ok(prepared.clone()))
                .unwrap()
                .unwrap();
            let request = owner.store_request(fixture::command(false)).unwrap();
            let dropped = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let marker = MixChildDropMarker {
                owner: owner.clone(),
                dropped: dropped.clone(),
            };
            let calls = Arc::new(Calls::default());
            let child_calls = calls.clone();
            let gate = Arc::new(tokio::sync::Mutex::new(()));
            let child_gate = gate.clone();
            let mut runner = Box::pin(execution.run(async move {
                let _marker = marker;
                let _admission = child_gate.lock().await;
                let completion = fixture::admit(&request, effect_cut, true, &child_calls).await?;
                if cut == 4 {
                    pending::<()>().await;
                }
                let (_, wake) = completion.into_wake(request.observation())?;
                if let Some(wake) = wake {
                    wake.invoke(|| {
                        child_calls.wake.fetch_add(1, Ordering::Relaxed);
                    })?;
                }
                Ok(())
            }));
            match cut {
                0 => {}
                5 => {
                    let payload = AssertUnwindSafe(&mut runner)
                        .catch_unwind()
                        .await
                        .unwrap_err();
                    assert_eq!(
                        payload.downcast_ref::<&str>(),
                        Some(&"MIX receipt-before-return panic")
                    );
                }
                6 => assert!(matches!(futures::poll!(&mut runner), Poll::Ready(Ok(())))),
                8 => assert!(matches!(
                    futures::poll!(&mut runner),
                    Poll::Ready(Err(FrameFailure::Backend(_)))
                )),
                _ => {
                    assert!(futures::poll!(&mut runner).is_pending());
                    assert!(gate.try_lock().is_err());
                    if cut == 7 {
                        tokio::time::advance(FRAME_BUDGET).await;
                        assert!(matches!(
                            futures::poll!(&mut runner),
                            Poll::Ready(Err(FrameFailure::TimedOut))
                        ));
                    }
                }
            }
            drop(runner);
            assert!(dropped.load(Ordering::Relaxed));
            assert!(gate.try_lock().is_ok());
            assert_eq!(
                calls.repository.load(Ordering::Relaxed),
                usize::from(cut != 0)
            );
            assert_eq!(calls.commit.load(Ordering::Relaxed), usize::from(cut >= 2));
            assert_eq!(calls.wake.load(Ordering::Relaxed), usize::from(cut == 6));
            let summary = owner.snapshot().summary();
            assert_eq!(
                summary.knowledge,
                match cut {
                    0 | 1 => KnowledgeClass::NoCommitRequested,
                    2 => KnowledgeClass::CommitCallEntered,
                    _ => KnowledgeClass::ReceiptKnown,
                }
            );
            assert_eq!(
                summary.returned,
                match cut {
                    4 | 6 => ReturnClass::Stored,
                    8 => ReturnClass::Error,
                    _ => ReturnClass::NotReturned,
                }
            );
            assert_eq!(
                summary.wake,
                match cut {
                    4 => Wake::Ready,
                    6 => Wake::Invoked,
                    _ => Wake::Unavailable,
                }
            );
            assert_eq!(
                summary.terminal,
                Some(match cut {
                    5 => foreground::TerminalReason::Panicked,
                    6 => foreground::TerminalReason::Completed,
                    7 => foreground::TerminalReason::TimedOut,
                    8 => foreground::TerminalReason::BackendFailure,
                    _ => foreground::TerminalReason::Cancelled,
                })
            );
            assert!(execution
                .direct_operation()
                .snapshot()
                .finalization
                .is_none());
            assert!(matches!(
                sessions.mix_foreground(|| Ok(prepared.clone())),
                Err(foreground::Rejected::Retired)
            ));
        }
    }

    #[tokio::test]
    async fn mix_foreground_slot_rejects_conflicts_and_retirement_without_legacy_fallback() {
        use crate::services::mix::foreground::fixture;
        let prepared = fixture::prepared(false);
        let copied_input = fixture::prepared(false);
        let mut sessions = SessionExecutions::default();
        assert!(sessions
            .mix_foreground(|| Ok(prepared.clone()))
            .unwrap()
            .is_none());
        let preparation_calls = std::cell::Cell::new(0);
        assert!(sessions
            .mix_foreground(|| {
                preparation_calls.set(preparation_calls.get() + 1);
                Err(foreground::Rejected::Input)
            })
            .unwrap()
            .is_none());
        assert_eq!(
            preparation_calls.get(),
            0,
            "absent frame must not validate observed ingress"
        );
        let first = sessions.begin(ClientTransport::Bosh, "<message/>");
        let owner = sessions
            .mix_foreground(|| Ok(prepared.clone()))
            .unwrap()
            .unwrap();
        assert!(matches!(
            sessions.mix_foreground(|| Ok(copied_input.clone())),
            Err(foreground::Rejected::Input)
        ));
        drop(first.run(async { pending::<anyhow::Result<()>>().await }));
        let frozen = owner.snapshot();
        assert!(matches!(
            sessions.mix_foreground(|| Ok(prepared.clone())),
            Err(foreground::Rejected::Retired)
        ));
        assert!(matches!(
            sessions.mix_foreground(|| {
                preparation_calls.set(preparation_calls.get() + 1);
                Ok(prepared.clone())
            }),
            Err(foreground::Rejected::Retired)
        ));
        assert_eq!(
            preparation_calls.get(),
            0,
            "retired frame must reject before preparation"
        );
        assert!(matches!(
            first.0.mix_foreground.register(&prepared),
            Err(foreground::Rejected::Retired)
        ));
        let next = sessions.begin(ClientTransport::Bosh, "<message/>");
        let next_owner = sessions
            .mix_foreground(|| Ok(copied_input.clone()))
            .unwrap()
            .unwrap();
        next.run(async { Ok(()) }).await.unwrap();
        assert_eq!(owner.snapshot(), frozen);
        assert_eq!(
            next_owner.snapshot().terminal,
            Some(foreground::TerminalReason::Completed)
        );
        let empty = sessions.begin(ClientTransport::Bosh, "<iq/>");
        empty.run(async { Ok(()) }).await.unwrap();
        assert!(matches!(
            empty.0.mix_foreground.register(&prepared),
            Err(foreground::Rejected::Retired)
        ));
    }

    struct MucChildDropMarker {
        owner: discussion::Observation,
        dropped: Arc<std::sync::atomic::AtomicBool>,
    }

    impl Drop for MucChildDropMarker {
        fn drop(&mut self) {
            assert_eq!(
                self.owner.snapshot().terminal,
                None,
                "MUC owner retired before child destruction"
            );
            self.dropped.store(true, Ordering::Relaxed);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn muc_receipt_return_and_terminal_survive_actual_frame_drop_timeout_and_panic() {
        use crate::services::muc::discussion::fixture::{self, Cut};
        use northstar_room_application::discussion::{
            AcceptanceClass, AdmissionError, KnowledgeClass, ReturnClass,
        };
        for cut in 0..9 {
            let application = fixture::application(match cut {
                1 => Cut::BeforeCommit,
                2 => Cut::DuringCommit,
                3 | 7 => Cut::AfterReceipt,
                5 => Cut::PanicAfterReceipt,
                8 => Cut::FailAfterReceipt,
                _ => Cut::Return,
            });
            let prepared = application.prepare_discussion(fixture::command(false, false));
            let mut sessions = SessionExecutions::default();
            let execution = sessions.begin(ClientTransport::Tcp, "<message type='groupchat'/>");
            let owner = sessions.muc_discussion(&prepared).unwrap().unwrap();
            let request = owner.request().unwrap();
            let dropped = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let marker = MucChildDropMarker {
                owner: owner.clone(),
                dropped: dropped.clone(),
            };
            let gate = Arc::new(tokio::sync::Mutex::new(()));
            let child_gate = gate.clone();
            let mut runner = Box::pin(execution.run(async move {
                let _marker = marker;
                let _authority = child_gate.lock().await;
                let _completion = application
                    .admit_discussion_observed(&request)
                    .await
                    .map_err(|error| match error {
                        AdmissionError::Observation(error) => anyhow::Error::from(error),
                        AdmissionError::Repository(error) => error,
                    })?;
                if cut == 4 {
                    pending::<()>().await;
                }
                Ok(())
            }));
            match cut {
                0 => {}
                5 => {
                    let payload = AssertUnwindSafe(&mut runner)
                        .catch_unwind()
                        .await
                        .unwrap_err();
                    assert_eq!(
                        payload.downcast_ref::<&str>(),
                        Some(&"MUC receipt-before-return panic")
                    );
                }
                6 => assert!(matches!(futures::poll!(&mut runner), Poll::Ready(Ok(())))),
                8 => assert!(matches!(
                    futures::poll!(&mut runner),
                    Poll::Ready(Err(FrameFailure::Backend(_)))
                )),
                _ => {
                    assert!(futures::poll!(&mut runner).is_pending());
                    assert!(gate.try_lock().is_err());
                    if cut == 7 {
                        tokio::time::advance(FRAME_BUDGET).await;
                        assert!(matches!(
                            futures::poll!(&mut runner),
                            Poll::Ready(Err(FrameFailure::TimedOut))
                        ));
                    }
                }
            }
            drop(runner);
            assert!(dropped.load(Ordering::Relaxed));
            assert!(gate.try_lock().is_ok());
            let summary = owner.snapshot().summary();
            assert_eq!(
                summary.knowledge,
                match cut {
                    0 | 1 => KnowledgeClass::NoCommitRequested,
                    2 => KnowledgeClass::CommitCallEntered,
                    _ => KnowledgeClass::ReceiptKnown,
                }
            );
            assert_eq!(
                summary.receipt_class,
                (cut >= 3).then_some(AcceptanceClass::Volatile)
            );
            assert_eq!(
                summary.returned,
                match cut {
                    4 | 6 => ReturnClass::Stored,
                    8 => ReturnClass::Error,
                    _ => ReturnClass::NotReturned,
                }
            );
            assert_eq!(
                summary.terminal,
                Some(match cut {
                    5 => discussion::TerminalReason::Panicked,
                    6 => discussion::TerminalReason::Completed,
                    7 => discussion::TerminalReason::TimedOut,
                    8 => discussion::TerminalReason::BackendFailure,
                    _ => discussion::TerminalReason::Cancelled,
                })
            );
            assert!(matches!(
                sessions.muc_discussion(&prepared),
                Err(discussion::Rejected::Retired)
            ));
        }
    }

    #[tokio::test]
    async fn muc_slot_distinguishes_legacy_absence_conflict_and_retired_frames() {
        use crate::services::muc::discussion::fixture::{self, Cut};
        let application = fixture::application(Cut::Return);
        let prepared = application.prepare_discussion(fixture::command(true, true));
        let conflicting = application.prepare_discussion(fixture::command(true, true));
        let mut sessions = SessionExecutions::default();
        assert!(sessions.muc_discussion(&prepared).unwrap().is_none());
        let original = sessions.begin(ClientTransport::Bosh, "<message/>");
        let owner = sessions.muc_discussion(&prepared).unwrap().unwrap();
        assert!(matches!(
            sessions.muc_discussion(&conflicting),
            Err(discussion::Rejected::Input)
        ));
        assert!(!owner.snapshot().repository_started);
        drop(original.run(async { pending::<anyhow::Result<()>>().await }));
        let before = owner.snapshot();
        assert!(matches!(
            sessions.muc_discussion(&prepared),
            Err(discussion::Rejected::Retired)
        ));
        assert!(matches!(
            original.0.muc_discussion.register(&prepared),
            Err(discussion::Rejected::Retired)
        ));
        let next = sessions.begin(ClientTransport::Bosh, "<message/>");
        let next_owner = sessions.muc_discussion(&conflicting).unwrap().unwrap();
        next.run(async { Ok(()) }).await.unwrap();
        assert_eq!(owner.snapshot(), before);
        assert_eq!(
            next_owner.snapshot().terminal,
            Some(discussion::TerminalReason::Completed)
        );
        assert!(matches!(
            sessions.muc_discussion(&conflicting),
            Err(discussion::Rejected::Retired)
        ));
        let empty = sessions.begin(ClientTransport::Bosh, "<iq/>");
        empty.run(async { Ok(()) }).await.unwrap();
        assert!(matches!(
            empty.0.muc_discussion.register(&prepared),
            Err(discussion::Rejected::Retired)
        ));
    }

    struct ChildDropMarker {
        owner: DirectOperationHandle,
        dropped: Arc<std::sync::atomic::AtomicBool>,
    }

    impl Drop for ChildDropMarker {
        fn drop(&mut self) {
            assert_eq!(
                self.owner.snapshot().terminal,
                None,
                "owner retired before child destruction"
            );
            self.dropped.store(true, Ordering::Relaxed);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn outer_owner_retires_after_child_drop_at_every_runner_boundary() {
        for cut in 0..5 {
            let execution = execution();
            let owner = execution.direct_operation();
            let dropped = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let marker = ChildDropMarker {
                owner: owner.clone(),
                dropped: dropped.clone(),
            };
            let child = async move {
                let _marker = marker;
                if cut == 4 {
                    std::panic::panic_any("frame-child-original-panic");
                }
                if cut != 3 {
                    pending::<()>().await;
                }
                Ok(())
            };
            let mut runner = Box::pin(execution.run(child));
            if cut == 1 {
                assert!(futures::poll!(&mut runner).is_pending());
            } else if cut == 2 {
                assert!(futures::poll!(&mut runner).is_pending());
                tokio::time::advance(FRAME_BUDGET).await;
                assert!(matches!(
                    futures::poll!(&mut runner),
                    Poll::Ready(Err(FrameFailure::TimedOut))
                ));
            } else if cut == 3 {
                assert!(matches!(futures::poll!(&mut runner), Poll::Ready(Ok(()))));
            } else if cut == 4 {
                let payload = AssertUnwindSafe(&mut runner)
                    .catch_unwind()
                    .await
                    .unwrap_err();
                assert_eq!(
                    payload.downcast_ref::<&str>(),
                    Some(&"frame-child-original-panic")
                );
            }
            drop(runner);
            assert!(dropped.load(Ordering::Relaxed));
            assert_eq!(
                owner.snapshot().terminal,
                Some(match cut {
                    0 | 1 => TerminalReason::Cancelled,
                    2 => TerminalReason::TimedOut,
                    3 => TerminalReason::Completed,
                    4 => TerminalReason::Panicked,
                    _ => unreachable!(),
                })
            );
        }
    }

    #[tokio::test]
    async fn single_child_destructor_panic_keeps_order_and_original_payload() {
        struct PanickingChild {
            owner: DirectOperationHandle,
            dropped: Arc<std::sync::atomic::AtomicBool>,
        }
        impl Future for PanickingChild {
            type Output = Result<anyhow::Result<()>, tokio::time::error::Elapsed>;
            fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Self::Output> {
                Poll::Ready(Ok(Ok(())))
            }
        }
        impl Drop for PanickingChild {
            fn drop(&mut self) {
                assert_eq!(self.owner.snapshot().terminal, None);
                self.dropped.store(true, Ordering::Relaxed);
                std::panic::panic_any("frame-drop-original-panic");
            }
        }
        let execution = execution();
        let owner = execution.direct_operation();
        let dropped = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let mut runner = Box::pin(FrameRunner {
            child: Some(Box::pin(PanickingChild {
                owner: owner.clone(),
                dropped: dropped.clone(),
            })),
            observation: Observation::new(execution, "frame", Some(FRAME_BUDGET)),
            poll_in_progress: false,
        });
        let payload = AssertUnwindSafe(&mut runner)
            .catch_unwind()
            .await
            .unwrap_err();
        assert_eq!(
            payload.downcast_ref::<&str>(),
            Some(&"frame-drop-original-panic")
        );
        assert!(dropped.load(Ordering::Relaxed));
        assert_eq!(
            owner.snapshot().terminal,
            None,
            "outer runner has not been destroyed"
        );
        drop(runner);
        assert_eq!(owner.snapshot().terminal, Some(TerminalReason::Panicked));
    }

    #[tokio::test]
    async fn replacing_current_frame_preserves_the_old_retained_owner_and_terminal() {
        let mut executions = SessionExecutions::default();
        let original = executions.begin(ClientTransport::Bosh, "<message/>");
        let old_owner = original.direct_operation();
        let request = crate::abuse::MessageAdmissionRequest {
            actor_id: Uuid::from_u128(100),
            account_bare: "alice@example.test",
            normalized_target: "bob@example.test/resource",
            origin_id: Some("origin"),
            normalized_payload: "<message/>",
            pow_intent_payload: "<message/>",
            subject: "message",
            actors: &[],
            proof: None,
        };
        let _effect = old_owner.begin(&request).unwrap();
        let runner = original.run(async { pending::<anyhow::Result<()>>().await });
        drop(runner);
        let old_snapshot = old_owner.snapshot();
        let later = executions.begin(ClientTransport::Bosh, "<iq/>");
        later.run(async { Ok(()) }).await.unwrap();
        assert_eq!(old_owner.snapshot(), old_snapshot);
        assert_eq!(old_snapshot.terminal, Some(TerminalReason::Cancelled));
        assert!(!old_snapshot.reservation.unwrap().effect_started);
        assert_ne!(
            old_snapshot.operation,
            later.direct_operation().snapshot().operation
        );
        drop(executions);
        assert_eq!(
            old_owner.snapshot().terminal,
            Some(TerminalReason::Cancelled)
        );
    }

    #[tokio::test]
    async fn completed_frame_leaves_convenience_calls_without_a_retired_owner() {
        let mut executions = SessionExecutions::default();
        let original = executions.begin(ClientTransport::Tcp, "<message/>");
        let retained = executions.direct_operation().expect("active frame owner");
        original.run(async { Ok(()) }).await.unwrap();
        let terminal = retained.snapshot();
        // ProtocolSession::message_operation uses this exact selector. A
        // direct handle() call after process_frame() therefore keeps using the
        // convenience service path instead of attaching the retired operation.
        assert!(executions.direct_operation().is_none());
        let later = executions.begin(ClientTransport::Tcp, "<message/>");
        assert!(executions.direct_operation().is_some());
        later.run(async { Ok(()) }).await.unwrap();
        assert!(executions.direct_operation().is_none());
        assert_eq!(retained.snapshot(), terminal);
    }

    #[test]
    fn websocket_inline_sasl2_has_a_separate_bounded_handler_budget() {
        for frame in [
            "<authenticate xmlns='urn:xmpp:sasl:2'><bind xmlns='urn:xmpp:bind:0'/></authenticate>",
            "<s:authenticate xmlns:s='urn:xmpp:sasl:2'><resume xmlns='urn:xmpp:sm:3'/></s:authenticate>",
        ] {
            assert_eq!(
                (Policy::for_frame(ClientTransport::WebSocket, frame).budget, Policy::for_frame(ClientTransport::WebSocket, frame).operation),
                (INLINE_AUTH_BUDGET, "sasl2_inline_auth")
            );
        }
        for frame in [
            "<message xmlns='jabber:client'><body>authenticate</body></message>",
            "<authenticate xmlns='urn:xmpp:sasl:2'/>",
            "<authenticate xmlns='urn:other'><bind xmlns='urn:xmpp:bind:0'/></authenticate>",
            "<s:authenticate xmlns:s='urn:other'><bind xmlns='urn:xmpp:bind:0'/></s:authenticate>",
            "<authenticate xmlns='urn:xmpp:sasl:2'><bind xmlns='urn:other'/></authenticate>",
            "<authenticate xmlns='urn:xmpp:sasl:2'><bind",
        ] {
            assert_eq!(
                (
                    Policy::for_frame(ClientTransport::WebSocket, frame).budget,
                    Policy::for_frame(ClientTransport::WebSocket, frame).operation
                ),
                (FRAME_BUDGET, "stream_frame")
            );
        }
    }

    #[test]
    fn policy_preserves_transport_specific_inline_auth_budget() {
        let inline =
            "<authenticate xmlns='urn:xmpp:sasl:2'><bind xmlns='urn:xmpp:bind:0'/></authenticate>";
        for transport in [ClientTransport::Tcp, ClientTransport::Bosh] {
            assert_eq!(Policy::for_frame(transport, inline).budget, FRAME_BUDGET);
        }
        let websocket = Policy::for_frame(ClientTransport::WebSocket, inline);
        assert_eq!(websocket.budget, INLINE_AUTH_BUDGET);
        assert_eq!(websocket.operation, "sasl2_inline_auth");
        for ordinary in ["<message/>", "<authenticate/>", "not XML"] {
            assert_eq!(
                Policy::for_frame(ClientTransport::WebSocket, ordinary).budget,
                FRAME_BUDGET
            );
        }
    }

    #[tokio::test]
    async fn deferred_publication_retains_origin_after_later_bosh_frame() {
        let mut executions = SessionExecutions::default();
        let origin = executions.begin(ClientTransport::Bosh, "<authenticate/>");
        origin.run(async { Ok(()) }).await.unwrap();
        executions.defer_publication(origin.clone());
        let later = executions.begin(ClientTransport::Bosh, "<iq/>");
        later.run(async { Ok(()) }).await.unwrap();
        assert_ne!(origin.0.operation_id, later.0.operation_id);

        let publication = executions.take_publication().unwrap();
        assert_eq!(publication.0.operation_id, origin.0.operation_id);
        assert_eq!(publication.0.sequence, origin.0.sequence);
        assert!(
            publication
                .observe_publication(async {
                    executions.enter(Stage::CapsPublication);
                    PublicationResult::Completed
                })
                .await
        );
        assert_eq!(
            Stage::from_raw(origin.0.stage.load(Ordering::Relaxed)),
            Stage::CapsPublication
        );
        assert_eq!(
            Stage::from_raw(later.0.stage.load(Ordering::Relaxed)),
            Stage::Validation
        );
        assert!(executions.take_publication().is_none());
    }

    #[tokio::test]
    async fn successful_and_failed_frames_keep_typed_outcomes_and_stage() {
        let execution = execution();
        let value = execution
            .run(async {
                execution.enter(Stage::Handler);
                Ok(42)
            })
            .await
            .unwrap();
        assert_eq!(value, 42);
        assert_eq!(outcome(&execution), Outcome::Completed as u8);
        let failed = execution
            .run(async {
                execution.enter(Stage::SmCheckpoint);
                Err::<(), _>(anyhow::anyhow!("injected failure"))
            })
            .await;
        assert!(matches!(failed, Err(FrameFailure::Backend(_))));
        assert_eq!(outcome(&execution), Outcome::BackendFailure as u8);
        assert_eq!(
            Stage::from_raw(execution.0.stage.load(Ordering::Relaxed)),
            Stage::SmCheckpoint
        );
    }

    #[tokio::test(start_paused = true)]
    async fn pending_frame_times_out_at_its_policy_budget() {
        let execution = execution();
        let started = tokio::time::Instant::now();
        let result = execution
            .run(async {
                execution.enter(Stage::Handler);
                pending::<anyhow::Result<()>>().await
            })
            .await;
        assert!(matches!(result, Err(FrameFailure::TimedOut)));
        assert_eq!(started.elapsed(), FRAME_BUDGET);
        assert_eq!(outcome(&execution), Outcome::TimedOut as u8);
    }

    #[tokio::test]
    async fn enclosing_cancellation_observes_last_stage_once() {
        let execution = execution();
        let mut future = Box::pin(execution.run(async {
            execution.enter(Stage::SmCheckpoint);
            pending::<anyhow::Result<()>>().await
        }));
        assert!(matches!(futures::poll!(&mut future), Poll::Pending));
        drop(future);
        assert_eq!(outcome(&execution), Outcome::Cancelled as u8);
        assert_eq!(
            Stage::from_raw(execution.0.stage.load(Ordering::Relaxed)),
            Stage::SmCheckpoint
        );
    }

    #[tokio::test(start_paused = true)]
    async fn publication_is_observed_without_introducing_a_deadline() {
        let execution = execution();
        assert!(
            execution
                .observe_publication(async {
                    execution.enter(Stage::CapsPublication);
                    tokio::time::sleep(FRAME_BUDGET * 2).await;
                    PublicationResult::Completed
                })
                .await
        );
        assert_eq!(outcome(&execution), Outcome::Completed as u8);
        assert!(
            !execution
                .observe_publication(async { PublicationResult::RouteRejected })
                .await
        );
        assert_eq!(outcome(&execution), Outcome::RouteRejected as u8);
    }
    #[tokio::test(start_paused = true)]
    async fn actual_trace_terminal_cardinality_and_privacy_cover_every_exit() {
        let (capture, _subscriber) = TraceCapture::install();
        let private_jid = "private-trace-user@secret.example/resource";
        let private_secret = "DO_NOT_LOG_TRACE_SECRET_61f64";
        let private_xml =
            format!("<message to='{private_jid}'><body>{private_secret}</body></message>");
        let mut expected = Vec::new();

        let completed = FrameExecution::new(ClientTransport::WebSocket, &private_xml);
        expected.push((completed.0.operation_id, "completed", "handler"));
        completed
            .run(async {
                completed.enter(Stage::Handler);
                Ok(())
            })
            .await
            .unwrap();
        // Dropping an already completed observation must not emit cancellation.
        drop(completed);

        let failed = FrameExecution::new(ClientTransport::WebSocket, &private_xml);
        expected.push((
            failed.0.operation_id,
            "backend_failure",
            "message_admission",
        ));
        assert!(matches!(
            failed
                .run(async {
                    failed.enter(Stage::MessageAdmission);
                    Err::<(), _>(anyhow::anyhow!(
                        "backend rejected {private_jid}: {private_secret}"
                    ))
                })
                .await,
            Err(FrameFailure::Backend(_))
        ));
        drop(failed);

        let timed_out = FrameExecution::new(ClientTransport::WebSocket, &private_xml);
        expected.push((timed_out.0.operation_id, "timed_out", "message_routing"));
        assert!(matches!(
            timed_out
                .run(async {
                    timed_out.enter(Stage::MessageRouting);
                    pending::<anyhow::Result<()>>().await
                })
                .await,
            Err(FrameFailure::TimedOut)
        ));
        drop(timed_out);

        let cancelled = FrameExecution::new(ClientTransport::WebSocket, &private_xml);
        expected.push((cancelled.0.operation_id, "cancelled", "sm_checkpoint"));
        let mut unfinished = Box::pin(cancelled.run(async {
            cancelled.enter(Stage::SmCheckpoint);
            pending::<anyhow::Result<()>>().await
        }));
        assert!(matches!(futures::poll!(&mut unfinished), Poll::Pending));
        drop(unfinished);
        drop(cancelled);

        let panicked = FrameExecution::new(ClientTransport::WebSocket, &private_xml);
        expected.push((panicked.0.operation_id, "panicked", "handler"));
        let caught = AssertUnwindSafe(panicked.run(async {
            panicked.enter(Stage::Handler);
            panic!("injected frame panic");
            #[allow(unreachable_code)]
            Ok::<(), anyhow::Error>(())
        }))
        .catch_unwind()
        .await;
        assert!(caught.is_err());
        drop(panicked);

        let events = capture.events();
        for (operation_id, terminal_outcome, stage) in expected {
            let terminal =
                assert_one_trace_pair(&events, operation_id, "frame", terminal_outcome, stage);
            assert_eq!(terminal["fields"]["bounded"], true);
            assert_eq!(terminal["fields"]["budget_ms"], 5000);
        }
        assert_eq!(
            events
                .iter()
                .filter(|event| event["fields"]["message"] == "C2S execution finished")
                .count(),
            5
        );
        let serialized = serde_json::to_string(&events).unwrap();
        for private_value in [private_xml.as_str(), private_jid, private_secret] {
            assert!(
                !serialized.contains(private_value),
                "dedicated trace leaked private input"
            );
        }
    }

    #[tokio::test]
    async fn actual_trace_pairs_deferred_bosh_publication_with_its_origin() {
        let (capture, _subscriber) = TraceCapture::install();
        let mut executions = SessionExecutions::default();
        let origin = executions.begin(ClientTransport::Bosh, "<authenticate/>");
        origin
            .run(async {
                executions.enter(Stage::Handler);
                Ok(())
            })
            .await
            .unwrap();
        executions.defer_publication(origin.clone());
        let later = executions.begin(ClientTransport::Bosh, "<iq/>");
        later.run(async { Ok(()) }).await.unwrap();
        let publication = executions.take_publication().unwrap();
        assert!(
            publication
                .observe_publication(async {
                    executions.enter(Stage::CapsPublication);
                    PublicationResult::Completed
                })
                .await
        );
        drop(publication);
        drop(executions);

        let events = capture.events();
        assert_one_trace_pair(
            &events,
            origin.0.operation_id,
            "frame",
            "completed",
            "handler",
        );
        let terminal = assert_one_trace_pair(
            &events,
            origin.0.operation_id,
            "publication",
            "completed",
            "caps_publication",
        );
        assert_eq!(terminal["fields"]["bounded"], false);
        assert_eq!(terminal["fields"]["budget_ms"], 0);
        assert_one_trace_pair(
            &events,
            later.0.operation_id,
            "frame",
            "completed",
            "validation",
        );
        assert!(!events.iter().any(|event| event["fields"]["operation_id"]
            == later.0.operation_id.to_string()
            && event["fields"]["phase"] == "publication"));
        assert_eq!(
            events
                .iter()
                .filter(|event| event["fields"]["message"] == "C2S execution finished")
                .count(),
            3
        );
    }
    #[tokio::test(start_paused = true)]
    async fn pending_publication_outlives_frame_budget_until_owner_cancels() {
        let (capture, _subscriber) = TraceCapture::install();
        let execution = execution();
        let mut publication = Box::pin(execution.observe_publication(async {
            execution.enter(Stage::CapsPublication);
            pending::<PublicationResult>().await
        }));
        assert!(matches!(futures::poll!(&mut publication), Poll::Pending));
        tokio::time::advance(FRAME_BUDGET * 2).await;
        assert!(matches!(futures::poll!(&mut publication), Poll::Pending));
        assert_eq!(outcome(&execution), Outcome::Pending as u8);
        assert!(!capture
            .events()
            .iter()
            .any(|event| { event["fields"]["message"] == "C2S execution finished" }));
        drop(publication);
        let terminal = assert_one_trace_pair(
            &capture.events(),
            execution.0.operation_id,
            "publication",
            "cancelled",
            "caps_publication",
        );
        assert_eq!(terminal["fields"]["bounded"], false);
        assert_eq!(terminal["fields"]["budget_ms"], 0);
        assert_eq!(terminal["fields"]["elapsed_ms"], 10000);
    }

    #[tokio::test]
    async fn actual_publication_trace_classifies_transport_results_without_payload() {
        let (capture, _subscriber) = TraceCapture::install();
        let secret = "PUBLICATION_PRIVATE_PAYLOAD_04cf";
        let private_jid = "publication-private@secret.example/resource";
        let xml = format!("<authenticate xmlns='urn:xmpp:sasl:2'><secret>{secret}:{private_jid}</secret></authenticate>");
        let cases = [
            (PublicationResult::Completed, "completed", true),
            (PublicationResult::BackendFailure, "backend_failure", false),
            (
                PublicationResult::IntegrityRejected,
                "integrity_rejected",
                false,
            ),
            (
                PublicationResult::CredentialRejected,
                "credential_rejected",
                false,
            ),
            (PublicationResult::RouteRejected, "route_rejected", false),
            (
                PublicationResult::CompletedWithDeferredNotification,
                "completed_with_deferred_notification",
                true,
            ),
        ];
        let mut expected = Vec::new();
        for transport in [
            ClientTransport::Tcp,
            ClientTransport::WebSocket,
            ClientTransport::Bosh,
        ] {
            for (result, label, transport_succeeded) in cases {
                let execution = FrameExecution::new(transport, &xml);
                execution.run(async { Ok(()) }).await.unwrap();
                let stage = if result == PublicationResult::CompletedWithDeferredNotification {
                    Stage::ReplacementNotification
                } else {
                    Stage::AuthPublication
                };
                assert_eq!(
                    execution
                        .observe_publication(async {
                            execution.enter(stage);
                            result
                        })
                        .await,
                    transport_succeeded
                );
                expected.push((execution.0.operation_id, label, stage));
            }
        }
        let events = capture.events();
        for (operation_id, label, stage) in expected {
            assert_one_trace_pair(&events, operation_id, "frame", "completed", "validation");
            let terminal =
                assert_one_trace_pair(&events, operation_id, "publication", label, stage.label());
            assert_eq!(terminal["fields"]["bounded"], false);
            assert_eq!(terminal["fields"]["budget_ms"], 0);
        }
        let serialized = serde_json::to_string(&events).unwrap();
        for private in [secret, private_jid, xml.as_str()] {
            assert!(!serialized.contains(private));
        }
    }

    #[tokio::test]
    async fn actual_publication_cancel_and_panic_keep_exact_last_stage() {
        let (capture, _subscriber) = TraceCapture::install();
        let mut expected = Vec::new();
        for transport in [
            ClientTransport::Tcp,
            ClientTransport::WebSocket,
            ClientTransport::Bosh,
        ] {
            for stage in [
                Stage::AuthPublication,
                Stage::CapsPublication,
                Stage::ReplacementNotification,
            ] {
                let cancelled = FrameExecution::new(transport, "<authenticate/>");
                let mut future = Box::pin(cancelled.observe_publication(async {
                    cancelled.enter(stage);
                    pending::<PublicationResult>().await
                }));
                assert!(matches!(futures::poll!(&mut future), Poll::Pending));
                drop(future);
                expected.push((cancelled.0.operation_id, "cancelled", stage));
                let panicked = FrameExecution::new(transport, "<authenticate/>");
                let caught = AssertUnwindSafe(panicked.observe_publication(async {
                    panicked.enter(stage);
                    panic!("injected publication panic");
                    #[allow(unreachable_code)]
                    PublicationResult::Completed
                }))
                .catch_unwind()
                .await;
                assert!(caught.is_err());
                expected.push((panicked.0.operation_id, "panicked", stage));
            }
        }
        let events = capture.events();
        for (operation_id, label, stage) in expected {
            let terminal =
                assert_one_trace_pair(&events, operation_id, "publication", label, stage.label());
            assert_eq!(terminal["fields"]["bounded"], false);
            assert_eq!(terminal["fields"]["budget_ms"], 0);
        }
    }

    #[tokio::test]
    async fn actual_room_stage_traces_retain_failure_and_cancel_without_payload() {
        let (capture, _subscriber) = TraceCapture::install();
        let secret = "ROOM_PRIVATE_PAYLOAD_87dc";
        let xml =
            format!("<message to='private-room@secret.example'><body>{secret}</body></message>");
        let mut expected = Vec::new();
        for stage in [
            Stage::MucPolicy,
            Stage::MucGateWait,
            Stage::MucAuthority,
            Stage::MucAdmission,
            Stage::MucClusterFanout,
            Stage::MucLocalFanout,
            Stage::MixPolicy,
            Stage::MixAdmission,
        ] {
            assert_eq!(Stage::from_raw(stage as u8), stage);
            let failed = FrameExecution::new(ClientTransport::WebSocket, &xml);
            assert!(matches!(
                failed
                    .run(async {
                        failed.enter(stage);
                        Err::<(), _>(anyhow::anyhow!("{secret}"))
                    })
                    .await,
                Err(FrameFailure::Backend(_))
            ));
            expected.push((failed.0.operation_id, "backend_failure", stage));
            let cancelled = FrameExecution::new(ClientTransport::WebSocket, &xml);
            let mut future = Box::pin(cancelled.run(async {
                cancelled.enter(stage);
                pending::<anyhow::Result<()>>().await
            }));
            assert!(matches!(futures::poll!(&mut future), Poll::Pending));
            drop(future);
            expected.push((cancelled.0.operation_id, "cancelled", stage));
        }
        let events = capture.events();
        for (operation_id, label, stage) in expected {
            assert_one_trace_pair(&events, operation_id, "frame", label, stage.label());
        }
        let serialized = serde_json::to_string(&events).unwrap();
        for private in [secret, "private-room@secret.example", xml.as_str()] {
            assert!(!serialized.contains(private));
        }
    }

    #[tokio::test]
    async fn abnormal_terminal_remains_visible_under_existing_crate_info_filter() {
        let (capture, _subscriber) = TraceCapture::install_with_filter("rust_xmpp_server=info");
        let execution = execution();
        assert!(matches!(
            execution
                .run(async {
                    execution.enter(Stage::MessageRouting);
                    Err::<(), _>(anyhow::anyhow!("private backend details"))
                })
                .await,
            Err(FrameFailure::Backend(_))
        ));
        drop(execution);
        let events = capture.events();
        assert_eq!(
            events.len(),
            1,
            "success/progress observations remain opt-in"
        );
        assert_eq!(
            events[0]["target"],
            "rust_xmpp_server::xmpp::frame_execution"
        );
        assert_eq!(events[0]["level"], "WARN");
        assert_eq!(events[0]["fields"]["message"], "C2S execution finished");
        assert_eq!(events[0]["fields"]["outcome"], "backend_failure");
        assert!(!serde_json::to_string(&events)
            .unwrap()
            .contains("private backend details"));
    }
}
