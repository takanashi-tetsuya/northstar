//! Process shutdown ordering over runtime owners and context-provided effects.

use crate::connection_actors::ConnectionActorRegistry;
use crate::service_tasks::{
    await_shutdown_notification_window, drain_service_tasks, unexpected_service_task_exit,
    ServiceTaskExit, ShutdownNotificationWindow, SERVICE_TASK_ABORT_DRAIN_TIMEOUT,
    SERVICE_TASK_DRAIN_TIMEOUT,
};
use crate::workers::WorkerRegistry;
use std::{future::Future, time::Duration};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

/// What the process shutdown needs from contexts the runtime cannot name.
pub trait ProcessShutdownPorts {
    /// Built when called (on the graceful path only) and polled inside the notification window.
    fn muc_shutdown_notifications(&self) -> impl Future<Output = usize> + '_;
    fn begin_cluster_shutdown(&self);
    fn release_cluster_after_publication_quiescence(
        &self,
        quiesce_timeout: Duration,
    ) -> impl Future<Output = Option<anyhow::Result<()>>> + '_;
}

pub async fn supervise_process_shutdown<P: ProcessShutdownPorts, S: Future<Output = ()>>(
    ports: &P,
    cancel: &CancellationToken,
    worker_registry: &WorkerRegistry,
    actors: &ConnectionActorRegistry,
    service_tasks: &mut JoinSet<ServiceTaskExit>,
    shutdown_signal: S,
) -> anyhow::Result<()> {
    let mut shutdown_error = None;
    let graceful_signal = tokio::select! {
        biased;
        _ = cancel.cancelled() => {
            shutdown_error = worker_registry
                .critical_failure()
                .map(anyhow::Error::msg);
            false
        },
        _ = shutdown_signal => {
            tracing::info!("shutdown signal received; stopping listeners and draining HTTP requests");
            true
        },
        result = service_tasks.join_next() => {
            shutdown_error = Some(unexpected_service_task_exit(result));
            false
        },
    };

    // Close connection admission before signalling any child. Every accepted
    // transport is now owned by the bounded registry and must finalize before
    // the abort-and-reap deadline below.
    actors.close_admission();
    if graceful_signal {
        match await_shutdown_notifications(
            cancel,
            service_tasks,
            ports.muc_shutdown_notifications(),
            tokio::time::Instant::now() + std::time::Duration::from_secs(2),
        )
        .await
        {
            Ok(Some(notified_muc_occupants)) if notified_muc_occupants > 0 => {
                tracing::info!(notified_muc_occupants, "confirmed XEP-0045 shutdown notification transport writes or BOSH response acknowledgements");
            }
            Ok(_) => {}
            Err(error) => {
                shutdown_error.get_or_insert(error);
            }
        }
        if let Some(error) = worker_registry.critical_failure() {
            shutdown_error.get_or_insert_with(|| anyhow::Error::msg(error));
        }
    }
    ports.begin_cluster_shutdown();
    actors.begin_shutdown();
    cancel.cancel();
    match ports
        .release_cluster_after_publication_quiescence(std::time::Duration::from_secs(15))
        .await
    {
        Some(Ok(())) => {}
        Some(Err(error)) => tracing::warn!(
            ?error,
            "could not audit the final cluster node-instance lease release"
        ),
        None => tracing::error!(
            "signed cluster publications did not drain; leaving the instance fenced until its database lease expires"
        ),
    }
    let (worker_report, service_report, connection_report) = tokio::join!(
        worker_registry.shutdown_and_join(cancel, SERVICE_TASK_DRAIN_TIMEOUT),
        drain_service_tasks(service_tasks, SERVICE_TASK_DRAIN_TIMEOUT),
        actors.join_or_abort(SERVICE_TASK_DRAIN_TIMEOUT, SERVICE_TASK_ABORT_DRAIN_TIMEOUT,),
    );
    if !worker_report.is_clean() {
        let error = anyhow::anyhow!("background worker shutdown was incomplete: {worker_report:?}");
        tracing::error!(?error);
        shutdown_error.get_or_insert(error);
    }
    if service_report.aborted > 0 || !service_report.failures.is_empty() {
        let error = anyhow::anyhow!("listener shutdown was incomplete: {service_report:?}");
        tracing::error!(?error);
        shutdown_error.get_or_insert(error);
    }
    if connection_report.remaining > 0 {
        let error =
            anyhow::anyhow!("connection actor shutdown was incomplete: {connection_report:?}");
        tracing::error!(?error);
        shutdown_error.get_or_insert(error);
    }
    tracing::info!(
        worker_supervisors_joined = worker_report.joined,
        service_tasks_joined = service_report.joined,
        connection_actors_aborted = connection_report.aborted,
        "shutdown complete"
    );

    if let Some(error) = worker_registry.critical_failure() {
        shutdown_error.get_or_insert_with(|| anyhow::Error::msg(error));
    }
    match shutdown_error {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

async fn await_shutdown_notifications<F>(
    cancel: &CancellationToken,
    tasks: &mut JoinSet<ServiceTaskExit>,
    notifications: F,
    deadline: tokio::time::Instant,
) -> anyhow::Result<Option<usize>>
where
    F: std::future::Future<Output = usize>,
{
    match await_shutdown_notification_window(cancel, tasks, notifications, deadline).await? {
        ShutdownNotificationWindow::Cancelled => Ok(None),
        ShutdownNotificationWindow::Confirmed(confirmed) => Ok(Some(confirmed)),
        ShutdownNotificationWindow::Expired => {
            tracing::warn!("MUC shutdown notification window expired; unconfirmed endpoints will close without a write guarantee");
            Ok(None)
        }
    }
}

#[cfg(test)]
mod tests;
