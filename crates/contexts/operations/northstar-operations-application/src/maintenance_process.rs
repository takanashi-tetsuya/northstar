//! Ownership monitoring and shutdown of the maintenance process.

use anyhow::Context;
use northstar_runtime::workers::WorkerRegistry;
use std::{future::Future, time::Duration};
use tokio_util::sync::CancellationToken;

/// The exact ownership connection of the maintenance process. Probing must use that same physical
/// connection; closing releases the session advisory lock, then the pool.
pub trait MaintenanceOwnership: Send {
    fn probe(&mut self) -> impl Future<Output = anyhow::Result<()>> + Send;
    fn close(self) -> impl Future<Output = anyhow::Result<()>> + Send;
}

pub async fn supervise_maintenance<O: MaintenanceOwnership, S: Future<Output = ()>>(
    mut ownership: O,
    workers: &WorkerRegistry,
    cancel: &CancellationToken,
    mut health: tokio::task::JoinHandle<anyhow::Result<()>>,
    shutdown: S,
) -> anyhow::Result<()> {
    let mut interval = tokio::time::interval(Duration::from_secs(5));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    tokio::pin!(shutdown);
    let outcome = loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => break Err(anyhow::anyhow!("maintenance worker authority failed")),
            _ = &mut shutdown => break Ok(()),
            result = &mut health => break match result {
                Ok(Err(error)) => Err(error).context("maintenance health listener failed"),
                Ok(Ok(())) => Err(anyhow::anyhow!("maintenance health listener stopped unexpectedly")),
                Err(error) => Err(error).context("maintenance health listener panicked"),
            },
            _ = interval.tick() => {
                // The exact locked connection is probed; substituting a pool
                // connection would conceal loss of exclusive ownership.
                let probe = tokio::time::timeout(
                    Duration::from_secs(3),
                    ownership.probe(),
                ).await;
                if !matches!(probe, Ok(Ok(()))) {
                    workers.observer_error("maintenance-ownership", "database ownership connection failed");
                    break Err(anyhow::anyhow!("maintenance database ownership connection failed"));
                }
                workers.observer_ok("maintenance-ownership");
            }
        }
    };
    cancel.cancel();
    let report = workers
        .shutdown_and_join(cancel, Duration::from_secs(15))
        .await;
    if !health.is_finished()
        && tokio::time::timeout(Duration::from_secs(1), &mut health)
            .await
            .is_err()
    {
        health.abort();
        let _ = health.await;
    }
    // Closing the physical connection releases the session-level advisory
    // lock; returning it to a live pool would retain the lock invisibly.
    ownership.close().await?;
    anyhow::ensure!(
        report.is_clean(),
        "maintenance worker shutdown was incomplete"
    );
    outcome
}

#[cfg(test)]
mod tests;
