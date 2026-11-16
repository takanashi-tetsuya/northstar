//! Top-level service task supervision: panic-catching spawn, unexpected exits, the shutdown
//! notification window and the bounded shutdown drain.

use anyhow::Result;
use futures::FutureExt;
use std::{any::Any, future::Future, panic::AssertUnwindSafe, time::Duration};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

pub const SERVICE_TASK_DRAIN_TIMEOUT: Duration = Duration::from_secs(15);
pub const SERVICE_TASK_ABORT_DRAIN_TIMEOUT: Duration = Duration::from_secs(1);

pub enum ServiceTaskExit {
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
pub struct ServiceTaskDrainReport {
    pub joined: usize,
    pub aborted: usize,
    pub failures: Vec<String>,
}

pub fn spawn_service_task<F>(tasks: &mut JoinSet<ServiceTaskExit>, name: &'static str, future: F)
where
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

pub fn unexpected_service_task_exit(
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

/// How the shutdown notification window ended.
#[derive(Debug, PartialEq, Eq)]
pub enum ShutdownNotificationWindow {
    Cancelled,
    Confirmed(usize),
    Expired,
}

pub async fn await_shutdown_notification_window<F>(
    cancel: &CancellationToken,
    tasks: &mut JoinSet<ServiceTaskExit>,
    notifications: F,
    deadline: tokio::time::Instant,
) -> anyhow::Result<ShutdownNotificationWindow>
where
    F: std::future::Future<Output = usize>,
{
    tokio::select! {
        biased;
        _ = cancel.cancelled() => Ok(ShutdownNotificationWindow::Cancelled),
        result = tasks.join_next() => Err(unexpected_service_task_exit(result)),
        result = tokio::time::timeout_at(deadline, notifications) => {
            match result {
                Ok(confirmed) => Ok(ShutdownNotificationWindow::Confirmed(confirmed)),
                Err(_) => Ok(ShutdownNotificationWindow::Expired),
            }
        }
    }
}

pub async fn drain_service_tasks(
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
mod tests {
    use super::{
        await_shutdown_notification_window, drain_service_tasks, spawn_service_task,
        ServiceTaskExit, ShutdownNotificationWindow,
    };
    use anyhow::{Context, Result};
    use std::time::Duration;

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

    #[tokio::test]
    async fn cancelled_shutdown_window_does_not_poll_notifications_or_consume_service_failure() {
        let cancel = tokio_util::sync::CancellationToken::new();
        cancel.cancel();
        let mut tasks = tokio::task::JoinSet::new();
        tasks.spawn(async {
            ServiceTaskExit::Finished {
                name: "retained-service",
                result: Err(anyhow::anyhow!("retained failure cause")),
            }
        });
        let polled = std::sync::atomic::AtomicBool::new(false);
        let notifications = async {
            polled.store(true, std::sync::atomic::Ordering::SeqCst);
            1
        };
        let result = await_shutdown_notification_window(
            &cancel,
            &mut tasks,
            notifications,
            tokio::time::Instant::now() + Duration::from_secs(2),
        )
        .await
        .unwrap();
        assert_eq!(result, ShutdownNotificationWindow::Cancelled);
        assert!(!polled.load(std::sync::atomic::Ordering::SeqCst));
        let error = super::unexpected_service_task_exit(tasks.join_next().await);
        assert!(format!("{error:#}").contains("retained failure cause"));
    }

    #[tokio::test]
    async fn ready_service_failure_preempts_notifications_and_preserves_its_cause() {
        let cancel = tokio_util::sync::CancellationToken::new();
        let mut tasks = tokio::task::JoinSet::new();
        let task = tasks.spawn(async {
            ServiceTaskExit::Finished {
                name: "failed-listener",
                result: Err(anyhow::anyhow!("specific listener failure")),
            }
        });
        tokio::time::timeout(Duration::from_secs(2), async {
            while !task.is_finished() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        let polled = std::sync::atomic::AtomicBool::new(false);
        let notifications = async {
            polled.store(true, std::sync::atomic::Ordering::SeqCst);
            1
        };
        let error = await_shutdown_notification_window(
            &cancel,
            &mut tasks,
            notifications,
            tokio::time::Instant::now() + Duration::from_secs(2),
        )
        .await
        .unwrap_err();
        let diagnostic = format!("{error:#}");
        assert!(diagnostic.contains("failed-listener"));
        assert!(diagnostic.contains("specific listener failure"));
        assert!(!polled.load(std::sync::atomic::Ordering::SeqCst));
        assert!(tasks.is_empty());
    }

    #[tokio::test]
    async fn expired_notification_deadline_is_not_reset_by_the_waiter() {
        let cancel = tokio_util::sync::CancellationToken::new();
        let mut tasks = tokio::task::JoinSet::new();
        tasks.spawn(std::future::pending::<ServiceTaskExit>());
        let deadline = tokio::time::Instant::now() - Duration::from_secs(1);
        let result = tokio::time::timeout(
            Duration::from_secs(1),
            await_shutdown_notification_window(
                &cancel,
                &mut tasks,
                std::future::pending::<usize>(),
                deadline,
            ),
        )
        .await
        .expect("an elapsed absolute deadline must not receive a fresh two-second window")
        .unwrap();
        assert_eq!(result, ShutdownNotificationWindow::Expired);
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
    }
}
