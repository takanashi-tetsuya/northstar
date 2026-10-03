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
use std::{
    future::Future,
    sync::{
        atomic::{AtomicU64, AtomicU8, Ordering},
        Arc,
    },
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
}

#[derive(Debug)]
pub(crate) enum FrameFailure {
    Backend(anyhow::Error),
    TimedOut,
}

impl FrameExecution {
    pub(super) fn new(transport: ClientTransport, frame: &str) -> Self {
        Self(Arc::new(Progress {
            operation_id: Uuid::new_v4(),
            sequence: NEXT_SEQUENCE.fetch_add(1, Ordering::Relaxed),
            policy: Policy::for_frame(transport, frame),
            stage: AtomicU8::new(Stage::Validation as u8),
            started: tokio::time::Instant::now(),
            outcome: AtomicU8::new(Outcome::Pending as u8),
        }))
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

    pub(super) async fn run<T>(
        &self,
        future: impl Future<Output = anyhow::Result<T>>,
    ) -> Result<T, FrameFailure> {
        let mut observation = Observation::new(self.clone(), "frame", Some(self.0.policy.budget));
        match tokio::time::timeout(self.0.policy.budget, future).await {
            Ok(Ok(value)) => {
                observation.finish(Outcome::Completed);
                Ok(value)
            }
            Ok(Err(error)) => {
                observation.finish(Outcome::BackendFailure);
                Err(FrameFailure::Backend(error))
            }
            Err(_) => {
                observation.finish(Outcome::TimedOut);
                Err(FrameFailure::TimedOut)
            }
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
