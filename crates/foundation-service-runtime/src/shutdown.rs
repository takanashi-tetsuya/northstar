//! Graceful shutdown coordination with bounded drain timeouts.

use std::time::Duration;
use tokio::sync::broadcast;
use tokio::time::timeout;

pub struct ShutdownCoordinator {
    shutdown_tx: broadcast::Sender<()>,
    drain_timeout: Duration,
}

impl ShutdownCoordinator {
    pub fn new(drain_timeout: Duration) -> Self {
        let (shutdown_tx, _) = broadcast::channel(16);
        Self {
            shutdown_tx,
            drain_timeout,
        }
    }

    pub fn subscribe(&self) -> broadcast::Receiver<()> {
        self.shutdown_tx.subscribe()
    }

    pub fn trigger(&self) {
        let _ = self.shutdown_tx.send(());
    }

    pub async fn run_with_drain<F, Fut>(&self, drain_task: F) -> bool
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = ()>,
    {
        self.trigger();
        match timeout(self.drain_timeout, drain_task()).await {
            Ok(()) => {
                tracing::info!("All in-flight tasks drained successfully within budget");
                true
            }
            Err(_) => {
                tracing::warn!("Drain timeout exceeded; forcing process exit");
                false
            }
        }
    }
}
