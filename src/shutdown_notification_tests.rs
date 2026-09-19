use crate::connection_actors::{
    ConnectionActorKind, ConnectionActorRegistry, ConnectionActorSpawnError,
};
use crate::outbound::{MixDelivery, MixTransportCompletion, OutboundItem, OutboundSender};
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};
use uuid::Uuid;

use super::{await_shutdown_notifications, ServiceTaskExit};

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
    let result = await_shutdown_notifications(
        &cancel,
        &mut tasks,
        notifications,
        tokio::time::Instant::now() + Duration::from_secs(2),
    )
    .await
    .unwrap();
    assert_eq!(result, None);
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
    let error = await_shutdown_notifications(
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
        await_shutdown_notifications(
            &cancel,
            &mut tasks,
            std::future::pending::<usize>(),
            deadline,
        ),
    )
    .await
    .expect("an elapsed absolute deadline must not receive a fresh two-second window")
    .unwrap();
    assert_eq!(result, None);
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
}

#[tokio::test]
async fn closed_admission_keeps_existing_actor_alive_until_explicit_shutdown() {
    let registry = ConnectionActorRegistry::new(2);
    let shutdown = registry.shutdown_token();
    let (started_tx, started_rx) = oneshot::channel();
    let (notify_tx, notify_rx) = oneshot::channel();
    let (written_tx, written_rx) = oneshot::channel();
    let (finished_tx, finished_rx) = oneshot::channel();
    registry
        .try_spawn(ConnectionActorKind::C2sWebSocket, None, async move {
            let _ = started_tx.send(());
            notify_rx
                .await
                .expect("existing actor receives its notification");
            let _ = written_tx.send(!shutdown.is_cancelled());
            shutdown.cancelled().await;
            let _ = finished_tx.send(());
        })
        .unwrap();
    tokio::time::timeout(Duration::from_secs(2), started_rx)
        .await
        .unwrap()
        .unwrap();

    registry.close_admission();
    registry.close_admission();
    assert!(!registry.is_accepting());
    assert!(!registry.shutdown_token().is_cancelled());
    assert_eq!(
        registry.try_spawn(ConnectionActorKind::C2sWebSocket, None, async {}),
        Err(ConnectionActorSpawnError::AdmissionClosed)
    );
    notify_tx.send(()).unwrap();
    assert!(tokio::time::timeout(Duration::from_secs(2), written_rx)
        .await
        .unwrap()
        .unwrap());
    assert_eq!(registry.active_count(), 1);

    registry.begin_shutdown();
    let report = registry
        .join_or_abort(Duration::from_secs(2), Duration::from_secs(2))
        .await;
    assert!(report.graceful);
    assert_eq!(report.aborted, 0);
    assert_eq!(report.remaining, 0);
    finished_rx.await.unwrap();
    assert_eq!(registry.active_count(), 0);
}

#[test]
fn shutdown_write_receipt_is_not_completed_by_recoverable_ownership() {
    let (written_tx, mut written_rx) = mpsc::unbounded_channel();
    let item = OutboundItem::with_transport_write_receipt(
        "<presence type='unavailable'/>".to_owned(),
        written_tx,
    );
    assert!(item.durable_source.is_none());
    assert!(item.mix_handoff.is_none());
    assert!(item.transport_receipt.is_none());
    let queued_copy = item.clone();
    item.confirm_transport_ownership();
    queued_copy.confirm_transport_ownership();
    assert_eq!(written_rx.try_recv(), Err(mpsc::error::TryRecvError::Empty));

    queued_copy.confirm_transport_write();
    assert_eq!(written_rx.try_recv(), Ok(()));
    drop(queued_copy);
    drop(item);
    assert_eq!(
        written_rx.try_recv(),
        Err(mpsc::error::TryRecvError::Disconnected)
    );
}

#[test]
fn dropping_all_unwritten_copies_does_not_fabricate_a_write_receipt() {
    let (written_tx, mut written_rx) = mpsc::unbounded_channel();
    let item = OutboundItem::with_transport_write_receipt("shutdown".to_owned(), written_tx);
    let queued_copy = item.clone();
    drop(item);
    assert_eq!(written_rx.try_recv(), Err(mpsc::error::TryRecvError::Empty));
    drop(queued_copy);
    assert_eq!(
        written_rx.try_recv(),
        Err(mpsc::error::TryRecvError::Disconnected)
    );
}

#[test]
fn write_confirmation_does_not_replace_generic_or_typed_mix_ownership() {
    let (owned_tx, mut owned_rx) = mpsc::unbounded_channel();
    let generic = OutboundItem::with_transport_receipt("policy".to_owned(), owned_tx);
    generic.confirm_transport_write();
    assert_eq!(owned_rx.try_recv(), Err(mpsc::error::TryRecvError::Empty));
    generic.confirm_transport_ownership();
    assert_eq!(owned_rx.try_recv(), Ok(()));

    let delivery = MixDelivery {
        delivery_id: Uuid::from_u128(31),
        lease_token: Uuid::from_u128(32),
    };
    let (mix, mut completion) = OutboundItem::durable_mix("durable".to_owned(), delivery);
    mix.confirm_transport_write();
    mix.confirm_transport_ownership();
    assert_eq!(
        completion.try_recv(),
        Err(oneshot::error::TryRecvError::Empty)
    );
    let expected = MixTransportCompletion::SmPersisted {
        session_id: Uuid::from_u128(33),
    };
    mix.complete_mix_handoff(expected);
    mix.clone()
        .complete_mix_handoff(MixTransportCompletion::SocketFenced {
            connection_id: Uuid::from_u128(34),
        });
    assert_eq!(completion.try_recv(), Ok(expected));
}

#[test]
fn saturated_shutdown_notification_queue_keeps_the_ordered_transport_fence() {
    let (inner, mut receiver) = mpsc::channel(1);
    let sender = OutboundSender::new(inner);
    sender.try_send("older".to_owned()).unwrap();
    let (written_tx, mut written_rx) = mpsc::unbounded_channel();
    assert!(matches!(
        sender.try_send_with_transport_write_receipt("shutdown".to_owned(), written_tx),
        Err(mpsc::error::TrySendError::Full(stanza)) if stanza == "shutdown"
    ));
    assert!(sender.backpressure_disconnect().is_cancelled());
    assert_eq!(
        written_rx.try_recv(),
        Err(mpsc::error::TryRecvError::Disconnected)
    );
    assert_eq!(receiver.try_recv().unwrap().stanza, "older");
    assert!(matches!(
        sender.try_send("newer".to_owned()),
        Err(mpsc::error::TrySendError::Closed(stanza)) if stanza == "newer"
    ));
}

struct NotificationDropCount(std::sync::Arc<std::sync::atomic::AtomicUsize>);

impl Drop for NotificationDropCount {
    fn drop(&mut self) {
        self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }
}

#[tokio::test]
async fn slow_notification_does_not_block_fast_peers_and_cancellation_drops_pending_work() {
    let started = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let dropped = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let (fast_tx, fast_rx) = oneshot::channel();
    let mut completions = Box::pin(crate::state::count_shutdown_notification_completions(
        [None, Some(fast_tx)].into_iter().map(|fast_tx| {
            let started = std::sync::Arc::clone(&started);
            let dropped = std::sync::Arc::clone(&dropped);
            async move {
                started.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let _drop_count = NotificationDropCount(dropped);
                if let Some(fast_tx) = fast_tx {
                    let _ = fast_tx.send(());
                    true
                } else {
                    std::future::pending::<bool>().await
                }
            }
        }),
    ));
    tokio::time::timeout(Duration::from_secs(2), async {
        tokio::select! {
            result = &mut completions => panic!("slow notification completed unexpectedly: {result}"),
            result = fast_rx => result.expect("a fast peer must finish while the first remains blocked"),
        }
    })
    .await
    .unwrap();
    assert_eq!(started.load(std::sync::atomic::Ordering::SeqCst), 2);
    assert_eq!(dropped.load(std::sync::atomic::Ordering::SeqCst), 1);
    drop(completions);
    assert_eq!(dropped.load(std::sync::atomic::Ordering::SeqCst), 2);
}

#[tokio::test]
async fn notification_concurrency_remains_bounded_when_all_peers_are_slow() {
    use std::future::Future;
    let started = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let dropped = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let mut completions = Box::pin(crate::state::count_shutdown_notification_completions(
        (0..17).map(|_| {
            let started = std::sync::Arc::clone(&started);
            let dropped = std::sync::Arc::clone(&dropped);
            async move {
                started.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let _drop_count = NotificationDropCount(dropped);
                std::future::pending::<bool>().await
            }
        }),
    ));
    std::future::poll_fn(|context| {
        assert!(completions.as_mut().poll(context).is_pending());
        std::task::Poll::Ready(())
    })
    .await;
    assert_eq!(started.load(std::sync::atomic::Ordering::SeqCst), 16);
    assert_eq!(dropped.load(std::sync::atomic::Ordering::SeqCst), 0);
    drop(completions);
    assert_eq!(dropped.load(std::sync::atomic::Ordering::SeqCst), 16);
}
