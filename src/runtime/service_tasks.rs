//! Top-level service task supervision: panic-catching spawn, unexpected exits, the shutdown
//! notification window and the bounded shutdown drain.

use anyhow::Result;
use futures::FutureExt;
use std::{any::Any, future::Future, panic::AssertUnwindSafe, time::Duration};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

pub(crate) const SERVICE_TASK_DRAIN_TIMEOUT: Duration = Duration::from_secs(15);
pub(crate) const SERVICE_TASK_ABORT_DRAIN_TIMEOUT: Duration = Duration::from_secs(1);

pub(crate) enum ServiceTaskExit {
    Finished {
        name: &'static str,
        result: Result<()>,
    },
    Panicked {
        name: &'static str,
        message: String,
    },
}

#[derive(Debug, Default)]
pub(crate) struct ServiceTaskDrainReport {
    pub(crate) joined: usize,
    pub(crate) aborted: usize,
    pub(crate) failures: Vec<String>,
}

pub(crate) fn spawn_service_task<F>(
    tasks: &mut JoinSet<ServiceTaskExit>,
    name: &'static str,
    future: F,
) where
    F: Future<Output = Result<()>> + Send + 'static,
{
    tasks.spawn(async move {
        match AssertUnwindSafe(future).catch_unwind().await {
            Ok(result) => ServiceTaskExit::Finished { name, result },
            Err(panic) => ServiceTaskExit::Panicked {
                name,
                message: panic_payload(panic),
            },
        }
    });
}

pub(crate) fn unexpected_service_task_exit(
    result: Option<std::result::Result<ServiceTaskExit, tokio::task::JoinError>>,
) -> anyhow::Error {
    match result {
        Some(Ok(ServiceTaskExit::Finished {
            name,
            result: Ok(()),
        })) => anyhow::anyhow!("{name} task exited unexpectedly before service shutdown"),
        Some(Ok(ServiceTaskExit::Finished {
            name,
            result: Err(error),
        })) => error.context(format!("{name} task failed")),
        Some(Ok(ServiceTaskExit::Panicked { name, message })) => {
            anyhow::anyhow!("{name} task panicked: {message}")
        }
        Some(Err(error)) => anyhow::Error::from(error).context("unnamed service task failed"),
        None => anyhow::anyhow!("every service task exited unexpectedly"),
    }
}

pub(crate) async fn await_shutdown_notifications<F>(
    cancel: &CancellationToken,
    tasks: &mut JoinSet<ServiceTaskExit>,
    notifications: F,
    deadline: tokio::time::Instant,
) -> anyhow::Result<Option<usize>>
where
    F: std::future::Future<Output = usize>,
{
    tokio::select! {
        biased;
        _ = cancel.cancelled() => Ok(None),
        result = tasks.join_next() => Err(unexpected_service_task_exit(result)),
        result = tokio::time::timeout_at(deadline, notifications) => {
            match result {
                Ok(confirmed) => Ok(Some(confirmed)),
                Err(_) => {
                    tracing::warn!("MUC shutdown notification window expired; unconfirmed endpoints will close without a write guarantee");
                    Ok(None)
                }
            }
        }
    }
}

pub(crate) async fn drain_service_tasks(
    tasks: &mut JoinSet<ServiceTaskExit>,
    grace: Duration,
) -> ServiceTaskDrainReport {
    let mut report = ServiceTaskDrainReport::default();
    let deadline = tokio::time::Instant::now() + grace;
    while !tasks.is_empty() {
        match tokio::time::timeout_at(deadline, tasks.join_next()).await {
            Ok(Some(Ok(ServiceTaskExit::Finished { result: Ok(()), .. }))) => report.joined += 1,
            Ok(Some(Ok(ServiceTaskExit::Finished {
                name,
                result: Err(error),
            }))) => {
                report.joined += 1;
                report
                    .failures
                    .push(format!("{name} task failed during shutdown: {error:#}"));
            }
            Ok(Some(Ok(ServiceTaskExit::Panicked { name, message }))) => {
                report.joined += 1;
                report
                    .failures
                    .push(format!("{name} task panicked during shutdown: {message}"));
            }
            Ok(Some(Err(error))) => report
                .failures
                .push(format!("service task join failed during shutdown: {error}")),
            Ok(None) => break,
            Err(_) => {
                report.aborted = tasks.len();
                tasks.abort_all();
                break;
            }
        }
    }
    if !tasks.is_empty() {
        let deadline = tokio::time::Instant::now() + SERVICE_TASK_ABORT_DRAIN_TIMEOUT;
        while !tasks.is_empty() {
            match tokio::time::timeout_at(deadline, tasks.join_next()).await {
                Ok(Some(Ok(_))) => {}
                Ok(Some(Err(error))) if error.is_cancelled() => {}
                Ok(Some(Err(error))) => report
                    .failures
                    .push(format!("service task failed after abort: {error}")),
                Ok(None) => break,
                Err(_) => {
                    report.failures.push(format!(
                        "{} service tasks did not terminate after abort",
                        tasks.len()
                    ));
                    tasks.abort_all();
                    break;
                }
            }
        }
    }
    report
}

fn panic_payload(payload: Box<dyn Any + Send>) -> String {
    if let Some(message) = payload.downcast_ref::<&str>() {
        (*message).to_owned()
    } else if let Some(message) = payload.downcast_ref::<String>() {
        message.clone()
    } else {
        "non-string panic payload".to_owned()
    }
}

#[cfg(test)]
mod shutdown_notification_tests;

#[cfg(test)]
mod tests {
    use super::{drain_service_tasks, spawn_service_task};
    use anyhow::{Context, Result};

    async fn unexpected_task_exit(
        name: &'static str,
        task: tokio::task::JoinHandle<Result<()>>,
    ) -> Result<()> {
        match task.await {
            Ok(Ok(())) => anyhow::bail!("{name} task exited unexpectedly before service shutdown"),
            Ok(Err(error)) => Err(error).with_context(|| format!("{name} task failed")),
            Err(error) => Err(error).with_context(|| format!("{name} task panicked")),
        }
    }

    #[tokio::test]
    async fn successful_service_task_exit_is_an_error_with_its_name() {
        let error = unexpected_task_exit("test listener", tokio::spawn(async { Ok(()) }))
            .await
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("test listener task exited unexpectedly"),
            "unexpected error: {error:#}"
        );
    }

    #[tokio::test]
    async fn failed_service_task_preserves_its_error_and_context() {
        let error = unexpected_task_exit(
            "test listener",
            tokio::spawn(async { anyhow::bail!("injected listener failure") }),
        )
        .await
        .unwrap_err();
        let rendered = format!("{error:#}");
        assert!(rendered.contains("test listener task failed"), "{rendered}");
        assert!(rendered.contains("injected listener failure"), "{rendered}");
    }

    #[tokio::test]
    async fn panicked_service_task_preserves_join_error_and_context() {
        let error = unexpected_task_exit(
            "test listener",
            tokio::spawn(async { panic!("injected listener panic") }),
        )
        .await
        .unwrap_err();
        let rendered = format!("{error:#}");
        assert!(
            rendered.contains("test listener task panicked"),
            "{rendered}"
        );
        assert!(rendered.contains("injected listener panic"), "{rendered}");
    }

    #[tokio::test]
    async fn service_task_drain_joins_completed_tasks_without_leaking_handles() {
        let mut tasks = tokio::task::JoinSet::new();
        spawn_service_task(&mut tasks, "test listener", async { Ok(()) });

        let report = drain_service_tasks(&mut tasks, std::time::Duration::from_secs(1)).await;

        assert_eq!(report.joined, 1);
        assert_eq!(report.aborted, 0);
        assert!(report.failures.is_empty(), "{report:?}");
        assert!(tasks.is_empty());
    }

    #[tokio::test]
    async fn service_task_drain_aborts_and_reaps_a_non_cooperative_task() {
        let mut tasks = tokio::task::JoinSet::new();
        spawn_service_task(&mut tasks, "stuck listener", async {
            std::future::pending::<anyhow::Result<()>>().await
        });

        let report = drain_service_tasks(&mut tasks, std::time::Duration::from_millis(10)).await;

        assert_eq!(report.joined, 0);
        assert_eq!(report.aborted, 1);
        assert!(report.failures.is_empty(), "{report:?}");
        assert!(tasks.is_empty());
    }
}
