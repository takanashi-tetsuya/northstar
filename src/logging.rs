//! Console logging never waits for its output device on a protocol worker.
//!
//! Keep complete formatted events: an oversized event is dropped, never cut
//! into invalid JSON or an ambiguous fragment. The rolling file sink retains
//! its existing policy. Main owns both appender guards until service teardown.

use std::io::{self, Write};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex, OnceLock};
use std::time::Duration;
use tracing_appender::non_blocking::{ErrorCounter, NonBlocking, NonBlockingBuilder, WorkerGuard};
use tracing_subscriber::fmt::MakeWriter;

pub(crate) const CONSOLE_QUEUE_EVENTS: usize = 256;
pub(crate) const CONSOLE_EVENT_BYTES: usize = 64 * 1024;
const LOG_SHUTDOWN_TIMEOUT: Duration = Duration::from_millis(2500);
static CONSOLE_COUNTERS: OnceLock<ConsoleCounters> = OnceLock::new();
static SHUTDOWN_TIMEOUTS: AtomicU64 = AtomicU64::new(0);
static SHUTDOWN_SPAWN_FAILURES: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Debug)]
struct ConsoleCounters {
    queue: ErrorCounter,
    oversized: Arc<AtomicU64>,
}

#[derive(Clone)]
pub(crate) struct ConsoleWriter {
    writer: NonBlocking,
    counters: ConsoleCounters,
    event_bytes: usize,
}

pub(crate) struct ConsoleEventWriter {
    sink: ConsoleWriter,
    bytes: Vec<u8>,
    oversized: bool,
}

impl<'a> MakeWriter<'a> for ConsoleWriter {
    type Writer = ConsoleEventWriter;

    fn make_writer(&'a self) -> Self::Writer {
        ConsoleEventWriter {
            sink: self.clone(),
            bytes: Vec::new(),
            oversized: false,
        }
    }
}

impl Write for ConsoleEventWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if !self.oversized {
            if bytes.len() > self.sink.event_bytes.saturating_sub(self.bytes.len()) {
                self.oversized = true;
                self.bytes.clear();
            } else {
                self.bytes.extend_from_slice(bytes);
            }
        }
        // A full or oversized console sink must not turn into backpressure or
        // a formatter error that could itself synchronously log to stderr.
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Drop for ConsoleEventWriter {
    fn drop(&mut self) {
        if self.oversized {
            increment(&self.sink.counters.oversized);
        } else if !self.bytes.is_empty() {
            // One channel entry is exactly one complete formatter event.
            let _ = self.sink.writer.write_all(&self.bytes);
        }
    }
}

fn increment(counter: &AtomicU64) {
    let _ = counter.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
        Some(value.saturating_add(1))
    });
}

fn console_with_writer(
    output: impl Write + Send + 'static,
    queue_events: usize,
    event_bytes: usize,
) -> (ConsoleWriter, WorkerGuard) {
    let (writer, guard) = NonBlockingBuilder::default()
        .buffered_lines_limit(queue_events)
        .lossy(true)
        .thread_name("northstar-console-log")
        .finish(output);
    let counters = ConsoleCounters {
        queue: writer.error_counter(),
        oversized: Arc::new(AtomicU64::new(0)),
    };
    (
        ConsoleWriter {
            writer,
            counters,
            event_bytes,
        },
        guard,
    )
}

pub(crate) fn console(output: impl Write + Send + 'static) -> (ConsoleWriter, WorkerGuard) {
    let (writer, guard) = console_with_writer(output, CONSOLE_QUEUE_EVENTS, CONSOLE_EVENT_BYTES);
    CONSOLE_COUNTERS
        .set(writer.counters.clone())
        .expect("console logging is initialized once per process");
    (writer, guard)
}

/// Match Result's terminal Debug error report without invoking its synchronous
/// stderr writer after the runtime's logger guards have already been dropped.
/// This final sink does not install a subscriber, touch OnceLock, or read config.
pub(crate) fn report_result(result: anyhow::Result<()>) -> std::process::ExitCode {
    match result {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            let (writer, guard) = console_with_writer(io::stderr(), 1, CONSOLE_EVENT_BYTES);
            enqueue_terminal_error(&writer, &error);
            drop(LogGuards::new(vec![guard]));
            std::process::ExitCode::FAILURE
        }
    }
}

fn enqueue_terminal_error(writer: &ConsoleWriter, error: &anyhow::Error) {
    let mut event = writer.make_writer();
    let _ = writeln!(event, "Error: {error:?}");
    let oversized = event.oversized;
    drop(event);
    if oversized {
        // Never publish an unterminated fragment of an arbitrary diagnostic.
        let _ = writer
            .make_writer()
            .write_all(b"Error: final diagnostic exceeded the console event size limit\n");
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct ConsoleLoggingMetrics {
    pub queue_dropped_events: u64,
    pub oversized_events: u64,
    pub shutdown_timeouts: u64,
    pub shutdown_spawn_failures: u64,
}

pub(crate) fn metrics() -> ConsoleLoggingMetrics {
    ConsoleLoggingMetrics {
        queue_dropped_events: CONSOLE_COUNTERS.get().map_or(0, |counters| {
            u64::try_from(counters.queue.dropped_lines()).unwrap_or(u64::MAX)
        }),
        oversized_events: CONSOLE_COUNTERS
            .get()
            .map_or(0, |counters| counters.oversized.load(Ordering::Relaxed)),
        shutdown_timeouts: SHUTDOWN_TIMEOUTS.load(Ordering::Relaxed),
        shutdown_spawn_failures: SHUTDOWN_SPAWN_FAILURES.load(Ordering::Relaxed),
    }
}

pub(crate) fn render_metrics() -> String {
    render_snapshot(metrics())
}

fn render_snapshot(snapshot: ConsoleLoggingMetrics) -> String {
    format!(concat!(
        "# HELP xmpp_console_log_dropped_events_total Complete console events dropped by the bounded writer.\n",
        "# TYPE xmpp_console_log_dropped_events_total counter\n",
        "xmpp_console_log_dropped_events_total{{reason=\"queue_full_or_closed\"}} {}\n",
        "xmpp_console_log_dropped_events_total{{reason=\"oversized\"}} {}\n",
        "# TYPE xmpp_logging_shutdown_failures_total counter\n",
        "xmpp_logging_shutdown_failures_total{{reason=\"timeout\"}} {}\n",
        "xmpp_logging_shutdown_failures_total{{reason=\"thread_spawn\"}} {}\n",
        "# TYPE xmpp_console_log_queue_capacity_events gauge\n",
        "xmpp_console_log_queue_capacity_events {}\n",
        "# TYPE xmpp_console_log_event_limit_bytes gauge\n",
        "xmpp_console_log_event_limit_bytes {}\n",
    ), snapshot.queue_dropped_events, snapshot.oversized_events,
       snapshot.shutdown_timeouts, snapshot.shutdown_spawn_failures,
       CONSOLE_QUEUE_EVENTS, CONSOLE_EVENT_BYTES)
}

/// One process-lifetime owner; no per-event task or shutdown thread is created.
/// At final teardown, at most one helper drops both existing appender guards.
#[must_use]
pub(crate) struct LogGuards {
    guards: Option<Vec<WorkerGuard>>,
}

impl LogGuards {
    pub(crate) fn new(guards: Vec<WorkerGuard>) -> Self {
        Self {
            guards: Some(guards),
        }
    }
}

impl Drop for LogGuards {
    fn drop(&mut self) {
        let Some(guards) = self.guards.take() else {
            return;
        };
        // tracing-appender 0.2.5 bounds channel waits, but its full-queue drop
        // path uses println!, which can itself block. Keep that path off the
        // caller and bound the wait even when either stdio device is stalled.
        let owned = Arc::new(Mutex::new(Some(guards)));
        let worker_owned = Arc::clone(&owned);
        let (done_tx, done_rx) = mpsc::sync_channel(1);
        let spawned = std::thread::Builder::new()
            .name("northstar-log-shutdown".into())
            .spawn(move || {
                let guards = worker_owned
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .take();
                drop(guards);
                let _ = done_tx.send(());
            });
        match spawned {
            Ok(worker) => {
                if done_rx.recv_timeout(LOG_SHUTDOWN_TIMEOUT).is_ok() {
                    if worker.is_finished() {
                        let _ = worker.join();
                    }
                } else {
                    increment(&SHUTDOWN_TIMEOUTS);
                    // A blocked OS write cannot safely be cancelled. Detach
                    // only this final, counted helper; process exit ends it.
                    drop(worker);
                }
            }
            Err(_) => {
                increment(&SHUTDOWN_SPAWN_FAILURES);
                // Dropping the guards on this thread would reintroduce the
                // unbounded stdio path. This fixed allocation lives only until
                // the process exits after main's teardown has finished.
                std::mem::forget(owned);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::{Command, Stdio};
    use std::time::Instant;

    #[derive(Clone, Default)]
    struct Capture(Arc<Mutex<Vec<u8>>>);

    impl Write for Capture {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl<'a> MakeWriter<'a> for Capture {
        type Writer = Capture;
        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    fn emit(writer: &ConsoleWriter, bytes: &[u8]) {
        writer.make_writer().write_all(bytes).unwrap();
    }

    #[test]
    fn oversized_fragmented_events_are_dropped_whole_and_counted() {
        let capture = Capture::default();
        let (writer, guard) = console_with_writer(capture.clone(), 8, 64);
        emit(&writer, b"{\"message\":\"before\"}\n");
        {
            let mut event = writer.make_writer();
            event.write_all(b"{\"message\":\"").unwrap();
            event.write_all(&[b'x'; 64]).unwrap();
            event.write_all(b"\"}\n").unwrap();
        }
        emit(&writer, b"{\"message\":\"after\"}\n");
        drop(LogGuards::new(vec![guard]));
        assert_eq!(writer.counters.oversized.load(Ordering::Relaxed), 1);
        assert_eq!(writer.counters.queue.dropped_lines(), 0);
        let output = capture.0.lock().unwrap().clone();
        let events = String::from_utf8(output)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0]["message"], "before");
        assert_eq!(events[1]["message"], "after");
    }

    #[test]
    fn formatted_json_events_and_exact_byte_boundary_stay_complete() {
        let capture = Capture::default();
        let (writer, guard) = console_with_writer(capture.clone(), 8, 128);
        let counter = Arc::clone(&writer.counters.oversized);
        let subscriber = tracing_subscriber::fmt()
            .without_time()
            .with_target(false)
            .json()
            .with_ansi(false)
            .with_writer(writer.clone())
            .finish();
        tracing::subscriber::with_default(subscriber, || {
            tracing::info!(message = "kept");
            tracing::info!(message = "x".repeat(1024));
        });
        let boundary = [b'x'; 128];
        emit(&writer, &boundary);
        drop(LogGuards::new(vec![guard]));
        assert_eq!(counter.load(Ordering::Relaxed), 1);
        let output = capture.0.lock().unwrap();
        let newline = output.iter().position(|byte| *byte == b'\n').unwrap();
        let event: serde_json::Value = serde_json::from_slice(&output[..newline]).unwrap();
        assert_eq!(event["fields"]["message"], "kept");
        assert_eq!(&output[newline + 1..], &boundary);
    }

    #[test]
    fn logging_metrics_identify_loss_reasons_and_fixed_limits() {
        let rendered = render_snapshot(ConsoleLoggingMetrics {
            queue_dropped_events: 98,
            oversized_events: 1,
            shutdown_timeouts: 2,
            shutdown_spawn_failures: 3,
        });
        for expected in [
            "xmpp_console_log_dropped_events_total{reason=\"queue_full_or_closed\"} 98\n",
            "xmpp_console_log_dropped_events_total{reason=\"oversized\"} 1\n",
            "xmpp_logging_shutdown_failures_total{reason=\"timeout\"} 2\n",
            "xmpp_logging_shutdown_failures_total{reason=\"thread_spawn\"} 3\n",
            "xmpp_console_log_queue_capacity_events 256\n",
            "xmpp_console_log_event_limit_bytes 65536\n",
        ] {
            assert!(rendered.contains(expected), "missing {expected}");
        }
    }

    #[test]
    fn console_preserves_complete_text_json_ansi_and_filter_output() {
        for json in [false, true] {
            let direct = Capture::default();
            let buffered = Capture::default();
            let (writer, guard) = console_with_writer(buffered.clone(), 8, CONSOLE_EVENT_BYTES);
            let event = || {
                tracing::info!(answer = 42, message = "hello \"world\" 日本語");
                tracing::debug!(message = "filtered event");
            };
            if json {
                let original = tracing_subscriber::fmt()
                    .without_time()
                    .with_target(false)
                    .with_max_level(tracing::Level::INFO)
                    .json()
                    .with_ansi(false)
                    .with_writer(direct.clone())
                    .finish();
                tracing::subscriber::with_default(original, event);
                let replacement = tracing_subscriber::fmt()
                    .without_time()
                    .with_target(false)
                    .with_max_level(tracing::Level::INFO)
                    .json()
                    .with_ansi(false)
                    .with_writer(writer)
                    .finish();
                tracing::subscriber::with_default(replacement, event);
            } else {
                let original = tracing_subscriber::fmt()
                    .without_time()
                    .with_target(false)
                    .with_max_level(tracing::Level::INFO)
                    .with_ansi(true)
                    .with_writer(direct.clone())
                    .finish();
                tracing::subscriber::with_default(original, event);
                let replacement = tracing_subscriber::fmt()
                    .without_time()
                    .with_target(false)
                    .with_max_level(tracing::Level::INFO)
                    .with_ansi(true)
                    .with_writer(writer)
                    .finish();
                tracing::subscriber::with_default(replacement, event);
            }
            drop(LogGuards::new(vec![guard]));
            assert_eq!(*direct.0.lock().unwrap(), *buffered.0.lock().unwrap());
            assert!(!direct.0.lock().unwrap().is_empty());
        }
    }

    #[test]
    fn terminal_error_retains_debug_content_and_omits_oversized_fragments() {
        let capture = Capture::default();
        let error = anyhow::anyhow!("inner failure").context("outer failure");
        let expected = format!("Error: {error:?}\n");
        // Debug may include a backtrace under the caller's environment.
        let event_limit = expected.len().max(128);
        let (writer, guard) = console_with_writer(capture.clone(), 8, event_limit);
        enqueue_terminal_error(&writer, &error);
        enqueue_terminal_error(
            &writer,
            &anyhow::anyhow!("private-fragment-{}", "x".repeat(event_limit)),
        );
        drop(LogGuards::new(vec![guard]));
        let output = String::from_utf8(capture.0.lock().unwrap().clone()).unwrap();
        assert!(output.starts_with(&expected));
        assert!(output.ends_with("Error: final diagnostic exceeded the console event size limit\n"));
        assert!(!output.contains("private-fragment"));
        assert_eq!(writer.counters.oversized.load(Ordering::Relaxed), 1);
        assert_eq!(report_result(Ok(())), std::process::ExitCode::SUCCESS);
    }

    #[test]
    fn stalled_consumer_does_not_block_runtime_and_queue_is_bounded() {
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = mpsc::sync_channel(1);
        struct Stalled {
            entered: Option<tokio::sync::oneshot::Sender<()>>,
            release: mpsc::Receiver<()>,
        }
        impl Write for Stalled {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                if let Some(entered) = self.entered.take() {
                    let _ = entered.send(());
                    // Independent hard bound: a failing regression cannot
                    // leave the test logger blocked indefinitely.
                    let _ = self.release.recv_timeout(Duration::from_secs(3));
                }
                Ok(bytes.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let (writer, guard) = console_with_writer(
            Stalled {
                entered: Some(entered_tx),
                release: release_rx,
            },
            2,
            64,
        );
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap();
        runtime.block_on(async {
            emit(&writer, b"first\n");
            tokio::time::timeout(Duration::from_secs(1), entered_rx)
                .await
                .unwrap()
                .unwrap();
            let started = Instant::now();
            for _ in 0..100 {
                emit(&writer, b"queued\n");
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
            assert!(started.elapsed() < Duration::from_millis(500));
            assert_eq!(writer.counters.queue.dropped_lines(), 98);
        });
        release_tx.send(()).unwrap();
        drop(LogGuards::new(vec![guard]));
    }

    #[test]
    fn stalled_stdio_shutdown_is_bounded_in_an_isolated_process() {
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "logging::tests::stalled_stdio_child",
                "--nocapture",
            ])
            .env("NORTHSTAR_LOGGING_STALL_CHILD", "1")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(8);
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                assert_eq!(
                    status.code(),
                    Some(1),
                    "terminal Err must retain its failure exit: {status}"
                );
                break;
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                panic!("stalled logging exceeded the process teardown deadline");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    #[test]
    fn stalled_stdio_child() {
        if std::env::var("NORTHSTAR_LOGGING_STALL_CHILD").as_deref() != Ok("1") {
            return;
        }
        let (held_tx, held_rx) = mpsc::sync_channel(1);
        // Hold stdout's synchronous lock too: appender's queue-full shutdown
        // diagnostic must not become a second blocking exit path.
        std::thread::spawn(move || {
            let stdout = io::stdout();
            let mut locked = stdout.lock();
            held_tx.send(()).unwrap();
            // The parent never reads this real pipe. Its hard deadline owns
            // termination if a regression prevents the child from exiting.
            for _ in 0..1024 {
                if locked.write_all(&[b'y'; 16 * 1024]).is_err() {
                    break;
                }
            }
        });
        held_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        let (writer, guard) = console_with_writer(io::stderr(), 2, 8192);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap();
        runtime.block_on(async {
            let started = Instant::now();
            for _ in 0..250 {
                emit(&writer, &[b'x'; 4096]);
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
            assert!(started.elapsed() < Duration::from_secs(1));
            assert!(writer.counters.queue.dropped_lines() > 0);
        });
        let started = Instant::now();
        drop(LogGuards::new(vec![guard]));
        assert!(started.elapsed() >= LOG_SHUTDOWN_TIMEOUT);
        assert!(started.elapsed() < Duration::from_millis(3500));
        assert_eq!(metrics().shutdown_timeouts, 1);
        // Exercise the same Err -> bounded final Debug report -> ExitCode
        // path used by main. Do not bypass it with a successful process exit.
        let final_started = Instant::now();
        let exit_code = report_result(Err(anyhow::anyhow!("stalled final error")));
        assert_eq!(exit_code, std::process::ExitCode::FAILURE);
        assert!(final_started.elapsed() < Duration::from_millis(3500));
        // libtest otherwise writes its own unrelated summary to held stdout.
        // Bridge the asserted production ExitCode to this isolated test child.
        std::process::exit(1);
    }
}
