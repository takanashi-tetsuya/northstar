//! The bounded post-action supervisor of one session. Work a protocol action
//! defers starts only after that action reaches its transport, and session
//! shutdown aborts and drains whatever is still running.

use anyhow::Result;
use std::{
    collections::VecDeque,
    future::Future,
    pin::Pin,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};

pub struct PostActionTelemetry<'a> {
    started: &'a AtomicU64,
    completed: &'a AtomicU64,
    panicked: &'a AtomicU64,
    aborted: &'a AtomicU64,
    capacity_rejected: &'a AtomicU64,
}

impl<'a> PostActionTelemetry<'a> {
    pub fn new(
        started: &'a AtomicU64,
        completed: &'a AtomicU64,
        panicked: &'a AtomicU64,
        aborted: &'a AtomicU64,
        capacity_rejected: &'a AtomicU64,
    ) -> Self {
        Self {
            started,
            completed,
            panicked,
            aborted,
            capacity_rejected,
        }
    }

    pub fn started(&self) {
        self.started.fetch_add(1, Ordering::Relaxed);
    }

    pub fn completed(&self) {
        self.completed.fetch_add(1, Ordering::Relaxed);
    }

    pub fn panicked(&self) {
        self.panicked.fetch_add(1, Ordering::Relaxed);
    }

    pub fn aborted(&self, count: usize) {
        self.aborted.fetch_add(count as u64, Ordering::Relaxed);
    }

    pub fn capacity_rejected(&self) {
        self.capacity_rejected.fetch_add(1, Ordering::Relaxed);
    }
}

const MAX_POST_ACTION_TASKS_PER_SESSION: usize = 16;

const POST_ACTION_DRAIN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(1);

type PostActionFuture = Pin<Box<dyn Future<Output = ()> + Send + 'static>>;

struct PendingPostAction {
    name: &'static str,
    future: PostActionFuture,
}

pub struct PostActionSupervisor {
    pending: VecDeque<PendingPostAction>,
    running: tokio::task::JoinSet<&'static str>,
    transport_ready: bool,
    closed: bool,
}

impl Default for PostActionSupervisor {
    fn default() -> Self {
        Self {
            pending: VecDeque::new(),
            running: tokio::task::JoinSet::new(),
            transport_ready: true,
            closed: false,
        }
    }
}

impl PostActionSupervisor {
    pub fn defer<F>(
        &mut self,
        name: &'static str,
        task: F,
        telemetry: &PostActionTelemetry<'_>,
    ) -> Result<()>
    where
        F: Future<Output = ()> + Send + 'static,
    {
        anyhow::ensure!(!self.closed, "session post-action supervisor is closed");
        self.reap(telemetry);
        if self.pending.len().saturating_add(self.running.len())
            >= MAX_POST_ACTION_TASKS_PER_SESSION
        {
            telemetry.capacity_rejected();
            anyhow::bail!("per-session post-action task capacity was exhausted");
        }
        self.pending.push_back(PendingPostAction {
            name,
            future: Box::pin(task),
        });
        Ok(())
    }

    pub fn start(&mut self, telemetry: &PostActionTelemetry<'_>) {
        if self.closed {
            return;
        }
        self.transport_ready = true;
        self.reap(telemetry);
        while let Some(task) = self.pending.pop_front() {
            telemetry.started();
            self.running.spawn(async move {
                task.future.await;
                task.name
            });
        }
    }

    pub fn reap(&mut self, telemetry: &PostActionTelemetry<'_>) {
        while let Some(result) = self.running.try_join_next() {
            observe_post_action_join(result, telemetry);
        }
    }

    pub async fn abort_and_drain(&mut self, telemetry: &PostActionTelemetry<'_>) {
        self.reap(telemetry);
        let aborted = self.pending.len().saturating_add(self.running.len());
        self.pending.clear();
        self.running.abort_all();
        telemetry.aborted(aborted);
        let drain = async {
            while let Some(result) = self.running.join_next().await {
                observe_post_action_join(result, telemetry);
            }
        };
        if tokio::time::timeout(POST_ACTION_DRAIN_TIMEOUT, drain)
            .await
            .is_err()
        {
            tracing::error!(
                remaining = self.running.len(),
                "aborted post-action tasks did not drain within the shutdown budget"
            );
        }
    }

    pub fn abort_now(&mut self, telemetry: &PostActionTelemetry<'_>) {
        self.reap(telemetry);
        let aborted = self.pending.len().saturating_add(self.running.len());
        self.pending.clear();
        self.running.abort_all();
        telemetry.aborted(aborted);
    }
}

/// Shared with the exact local route so cluster recovery can request a
/// bounded offline replay without racing an in-progress presence action.
/// The transport opens the gate only after its current action reaches the
/// socket or BOSH response FIFO.
#[derive(Clone, Default)]
pub struct PostActionHandle(Arc<std::sync::Mutex<PostActionSupervisor>>);

impl PostActionHandle {
    pub fn begin_action(&self) {
        self.0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .transport_ready = false;
    }

    pub fn defer<F>(
        &self,
        name: &'static str,
        task: F,
        telemetry: &PostActionTelemetry<'_>,
    ) -> Result<()>
    where
        F: Future<Output = ()> + Send + 'static,
    {
        self.0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .defer(name, task, telemetry)
    }

    pub fn defer_recovery<F>(
        &self,
        name: &'static str,
        task: F,
        telemetry: &PostActionTelemetry<'_>,
    ) -> Result<()>
    where
        F: Future<Output = ()> + Send + 'static,
    {
        let mut supervisor = self
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        supervisor.defer(name, task, telemetry)?;
        if supervisor.transport_ready {
            supervisor.start(telemetry);
        }
        Ok(())
    }

    pub fn start(&self, telemetry: &PostActionTelemetry<'_>) {
        self.0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .start(telemetry);
    }

    pub fn take_for_shutdown(&self) -> PostActionSupervisor {
        let mut supervisor = self
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        supervisor.closed = true;
        let mut owned = std::mem::take(&mut *supervisor);
        supervisor.closed = true;
        owned.closed = true;
        owned
    }

    pub fn abort_now(&self, telemetry: &PostActionTelemetry<'_>) {
        let mut supervisor = self
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        supervisor.closed = true;
        supervisor.abort_now(telemetry);
    }
}

fn observe_post_action_join(
    result: std::result::Result<&'static str, tokio::task::JoinError>,
    telemetry: &PostActionTelemetry<'_>,
) {
    match result {
        Ok(name) => {
            telemetry.completed();
            tracing::trace!(task = name, "C2S post-action task completed");
        }
        Err(error) if error.is_cancelled() => {}
        Err(error) => {
            telemetry.panicked();
            tracing::error!(?error, "C2S post-action task panicked");
        }
    }
}

#[cfg(test)]
mod tests;
