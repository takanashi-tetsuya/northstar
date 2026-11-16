//! The MUC shutdown notification window as the composition root reports it; the window itself
//! is northstar_runtime::service_tasks::await_shutdown_notification_window.

use northstar_runtime::service_tasks::{
    await_shutdown_notification_window, ServiceTaskExit, ShutdownNotificationWindow,
};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

pub(crate) async fn await_shutdown_notifications<F>(
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
mod shutdown_notification_tests;
