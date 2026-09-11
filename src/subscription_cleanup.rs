//! Physical PubSub subscription garbage collection owned by maintenance.
//!
//! Expiry remains an authorization predicate in the PubSub repository. This
//! worker only removes durable garbage; it never uses delivery admission or
//! receives protocol state, routing capabilities, or a separate database pool.

use crate::{
    db, metrics::SubscriptionCleanupMetrics, retention::RetentionReadiness,
    workers::WorkerHeartbeat,
};
use std::sync::{atomic::Ordering, Arc};
use std::time::Duration;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

pub(crate) const CLEANUP_BATCH_SIZE: i64 = 1_000;
pub(crate) const CLEANUP_INTERVAL: Duration = Duration::from_secs(60);
// The existing repository permits 2 seconds to acquire a connection and
// 15 seconds per DELETE. Bound the entire pass, including SETs and COMMIT,
// without borrowing the delivery worker's unrelated five-second heartbeat.
pub(crate) const CLEANUP_BUDGET: Duration = Duration::from_secs(40);
pub(crate) const MAX_SILENCE: Duration = Duration::from_secs(110);

pub(crate) struct SubscriptionCleanupContext {
    pool: sqlx::PgPool,
    metrics: Arc<SubscriptionCleanupMetrics>,
    readiness: RetentionReadiness,
}

impl SubscriptionCleanupContext {
    pub(crate) fn new(pool: sqlx::PgPool, metrics: Arc<SubscriptionCleanupMetrics>) -> Self {
        Self {
            pool,
            metrics,
            readiness: RetentionReadiness::default(),
        }
    }

    pub(crate) fn readiness(&self) -> RetentionReadiness {
        self.readiness.clone()
    }
}

// Even cancellation or a panic between passes invalidates the independently
// published cleanup health. Archive-retention health is never written here.
struct ClearReadinessOnDrop(RetentionReadiness);

impl Drop for ClearReadinessOnDrop {
    fn drop(&mut self) {
        self.0.begin_pass();
    }
}

pub(crate) async fn serve_context(
    context: Arc<SubscriptionCleanupContext>,
    cancel: CancellationToken,
    heartbeat: WorkerHeartbeat,
) -> anyhow::Result<()> {
    serve_with(
        &context.readiness,
        &context.metrics,
        || db::cleanup_expired_subscriptions(&context.pool, CLEANUP_BATCH_SIZE),
        cancel,
        heartbeat,
    )
    .await
}

async fn run_once_with<F, Fut>(
    readiness: &RetentionReadiness,
    metrics: &SubscriptionCleanupMetrics,
    cancel: &CancellationToken,
    deadline: Instant,
    cleanup: F,
) -> anyhow::Result<Option<u64>>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = anyhow::Result<u64>>,
{
    readiness.begin_pass();
    let result = tokio::select! {
        biased;
        _ = cancel.cancelled() => return Ok(None),
        result = tokio::time::timeout_at(deadline, async { cleanup().await }) => {
            result.map_err(|_| anyhow::anyhow!("subscription cleanup exceeded its total pass budget"))?
        }
    };
    // An operator's cancellation must never publish a new successful pass.
    if cancel.is_cancelled() {
        return Ok(None);
    }
    // timeout_at polls its inner future before the timer. A result already
    // ready when this task resumes still cannot publish health after expiry.
    anyhow::ensure!(
        Instant::now() < deadline,
        "subscription cleanup exceeded its total pass budget"
    );
    match result {
        Ok(deleted) => {
            metrics.deleted_total.fetch_add(deleted, Ordering::Relaxed);
            readiness.complete_pass();
            Ok(Some(deleted))
        }
        Err(error) => Err(error),
    }
}

async fn serve_with<F, Fut>(
    readiness: &RetentionReadiness,
    metrics: &SubscriptionCleanupMetrics,
    mut cleanup: F,
    cancel: CancellationToken,
    heartbeat: WorkerHeartbeat,
) -> anyhow::Result<()>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = anyhow::Result<u64>>,
{
    readiness.begin_pass();
    let _clear_readiness = ClearReadinessOnDrop(readiness.clone());
    let mut interval = tokio::time::interval(CLEANUP_INTERVAL);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => return Ok(()),
            _ = interval.tick() => {}
        }
        match run_once_with(
            readiness,
            metrics,
            &cancel,
            Instant::now() + CLEANUP_BUDGET,
            &mut cleanup,
        )
        .await
        {
            Ok(Some(deleted)) => {
                heartbeat.ok();
                if deleted > 0 {
                    tracing::info!(deleted, "expired PubSub subscription cleanup completed");
                }
            }
            Ok(None) => return Ok(()),
            Err(error) => {
                metrics.failures_total.fetch_add(1, Ordering::Relaxed);
                heartbeat.error(&error);
                tracing::error!(?error, "expired PubSub subscription cleanup failed");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::workers::{WorkerCriticality, WorkerMode, WorkerRegistry};
    use std::future::Future;
    use std::sync::atomic::{AtomicBool, AtomicUsize};
    use tokio::sync::oneshot;

    struct Dropped(Arc<AtomicBool>);

    impl Drop for Dropped {
        fn drop(&mut self) {
            self.0.store(true, Ordering::Release);
        }
    }

    #[tokio::test]
    async fn expired_total_budget_drops_pending_work_and_never_reports_success() {
        let readiness = RetentionReadiness::for_test(true);
        let metrics = SubscriptionCleanupMetrics::default();
        let cancelled = CancellationToken::new();
        let dropped = Arc::new(AtomicBool::new(false));
        let entered = Arc::new(AtomicBool::new(false));
        let result = run_once_with(&readiness, &metrics, &cancelled, Instant::now(), || async {
            let _dropped = Dropped(Arc::clone(&dropped));
            entered.store(true, Ordering::Release);
            std::future::pending::<anyhow::Result<u64>>().await
        })
        .await;
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("total pass budget"));
        assert!(entered.load(Ordering::Acquire));
        assert!(dropped.load(Ordering::Acquire));
        assert!(!readiness.is_ready());
        assert_eq!(metrics.deleted_total.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn expired_ready_result_does_not_publish_cleanup_health_or_success_metrics() {
        let readiness = RetentionReadiness::for_test(true);
        let metrics = SubscriptionCleanupMetrics::default();
        let cancel = CancellationToken::new();
        let entered = AtomicBool::new(false);
        let result = run_once_with(&readiness, &metrics, &cancel, Instant::now(), || async {
            entered.store(true, Ordering::Release);
            Ok(9)
        })
        .await;
        assert!(entered.load(Ordering::Acquire));
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("total pass budget"));
        assert!(!readiness.is_ready());
        assert_eq!(metrics.deleted_total.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn cancellation_drops_started_cleanup_without_overwriting_archive_health() {
        let readiness = RetentionReadiness::for_test(true);
        let archive_readiness = RetentionReadiness::for_test(false);
        let metrics = SubscriptionCleanupMetrics::default();
        let cancel = CancellationToken::new();
        let dropped = Arc::new(AtomicBool::new(false));
        let cleanup = run_once_with(
            &readiness,
            &metrics,
            &cancel,
            Instant::now() + CLEANUP_BUDGET,
            || async {
                let _dropped = Dropped(Arc::clone(&dropped));
                std::future::pending::<anyhow::Result<u64>>().await
            },
        );
        tokio::pin!(cleanup);
        std::future::poll_fn(|cx| {
            assert!(cleanup.as_mut().poll(cx).is_pending());
            std::task::Poll::Ready(())
        })
        .await;
        assert!(!readiness.is_ready());
        cancel.cancel();
        assert!(cleanup.await.unwrap().is_none());
        assert!(dropped.load(Ordering::Acquire));
        assert!(!archive_readiness.is_ready());
        assert!(!readiness.is_ready());
        assert_eq!(metrics.deleted_total.load(Ordering::Relaxed), 0);
        assert_eq!(metrics.failures_total.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn independent_delivery_progresses_while_maintenance_cleanup_is_pending() {
        assert_eq!(CLEANUP_BUDGET, Duration::from_secs(40));
        assert_eq!(CLEANUP_INTERVAL, Duration::from_secs(60));
        assert_eq!(MAX_SILENCE, Duration::from_secs(110));
        let workers = WorkerRegistry::new();
        let cancel = CancellationToken::new();
        let readiness = RetentionReadiness::default();
        let metrics = Arc::new(SubscriptionCleanupMetrics::default());
        let calls = Arc::new(AtomicUsize::new(0));
        let (started_tx, started_rx) = oneshot::channel();
        let (complete_tx, complete_rx) = oneshot::channel();
        let controls = Arc::new(std::sync::Mutex::new(Some((started_tx, complete_rx))));
        let cleanup_readiness = readiness.clone();
        let cleanup_metrics = Arc::clone(&metrics);
        let cleanup_calls = Arc::clone(&calls);
        let cleanup_cancel = cancel.clone();
        workers.supervise(
            "test-subscription-cleanup",
            WorkerCriticality::Restartable,
            WorkerMode::Continuous,
            Some(MAX_SILENCE),
            cancel.clone(),
            move |heartbeat| {
                let readiness = cleanup_readiness.clone();
                let metrics = Arc::clone(&cleanup_metrics);
                let calls = Arc::clone(&cleanup_calls);
                let controls = Arc::clone(&controls);
                let cancel = cleanup_cancel.clone();
                async move {
                    serve_with(
                        &readiness,
                        &metrics,
                        move || {
                            calls.fetch_add(1, Ordering::Relaxed);
                            let (started, complete) = controls.lock().unwrap().take().unwrap();
                            async move {
                                started.send(()).unwrap();
                                complete.await.map_err(anyhow::Error::from)?;
                                Ok(7)
                            }
                        },
                        cancel,
                        heartbeat,
                    )
                    .await
                }
            },
        );
        tokio::time::timeout(Duration::from_secs(2), started_rx)
            .await
            .unwrap()
            .unwrap();
        assert!(!readiness.is_ready());
        let (delivered_tx, delivered_rx) = oneshot::channel();
        let delivered = Arc::new(std::sync::Mutex::new(Some(delivered_tx)));
        workers.supervise(
            "test-delivery",
            WorkerCriticality::Restartable,
            WorkerMode::Continuous,
            Some(Duration::from_secs(5)),
            cancel.clone(),
            move |heartbeat| {
                let delivered = Arc::clone(&delivered);
                async move {
                    heartbeat.ok();
                    delivered.lock().unwrap().take().unwrap().send(()).unwrap();
                    std::future::pending::<anyhow::Result<()>>().await
                }
            },
        );
        tokio::time::timeout(Duration::from_secs(2), delivered_rx)
            .await
            .unwrap()
            .unwrap();
        assert!(!readiness.is_ready());
        complete_tx.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(2), async {
            while !readiness.is_ready() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(metrics.deleted_total.load(Ordering::Relaxed), 7);
        assert_eq!(calls.load(Ordering::Relaxed), 1);
        assert!(workers.readiness_error().is_none());
        let report = workers
            .shutdown_and_join(&cancel, Duration::from_secs(1))
            .await;
        assert!(report.is_clean());
        assert!(!readiness.is_ready());
    }

    #[tokio::test]
    #[ignore = "requires an isolated TEST_DATABASE_URL PostgreSQL database"]
    async fn postgres_cleanup_preserves_live_subscriptions_and_event_snapshots_and_is_bounded() {
        let url = std::env::var("TEST_DATABASE_URL")
            .expect("set TEST_DATABASE_URL to an isolated PostgreSQL database");
        // A single ordinary connection owns all temporary fixtures. Any
        // replacement connection is pinned away from persistent relations.
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .after_connect(|connection, _| {
                Box::pin(async move {
                    sqlx::query("SET search_path TO pg_temp, pg_catalog")
                        .execute(connection)
                        .await?;
                    Ok(())
                })
            })
            .connect(&url)
            .await
            .unwrap();
        sqlx::raw_sql(
            "CREATE TEMP TABLE pubsub_subscriptions (
                node_id UUID NOT NULL, jid TEXT NOT NULL, expire TIMESTAMPTZ,
                PRIMARY KEY(node_id,jid));
             CREATE TEMP TABLE pubsub_digest_queue (
                id UUID PRIMARY KEY, subscription_node_id UUID NOT NULL,
                subscriber_jid TEXT NOT NULL, source_delivery_id UUID);
             INSERT INTO pubsub_subscriptions(node_id,jid,expire)
                SELECT md5(sequence::text)::uuid, 'expired@example.test',
                       NOW()-INTERVAL '1 hour'
                  FROM generate_series(1,1001) sequence;
             INSERT INTO pubsub_subscriptions(node_id,jid,expire) VALUES
                (md5('future')::uuid,'future@example.test',NOW()+INTERVAL '1 hour'),
                (md5('permanent')::uuid,'permanent@example.test',NULL);
             INSERT INTO pubsub_digest_queue(id,subscription_node_id,subscriber_jid,source_delivery_id)
                SELECT md5('legacy')::uuid,node_id,jid,NULL
                  FROM pubsub_subscriptions WHERE expire<NOW()
                 ORDER BY expire,node_id,jid LIMIT 1;
             INSERT INTO pubsub_digest_queue(id,subscription_node_id,subscriber_jid,source_delivery_id)
                SELECT md5('snapshot')::uuid,node_id,jid,md5('delivery')::uuid
                  FROM pubsub_subscriptions WHERE expire<NOW()
                 ORDER BY expire,node_id,jid LIMIT 1;"
        ).execute(&pool).await.unwrap();
        let context = SubscriptionCleanupContext::new(
            pool.clone(),
            Arc::new(SubscriptionCleanupMetrics::default()),
        );
        let readiness = context.readiness();
        let cancel = CancellationToken::new();
        assert!(!readiness.is_ready());
        let first = run_once_with(
            &context.readiness,
            &context.metrics,
            &cancel,
            Instant::now() + CLEANUP_BUDGET,
            || db::cleanup_expired_subscriptions(&context.pool, CLEANUP_BATCH_SIZE),
        )
        .await
        .unwrap();
        assert_eq!(first, Some(1_000));
        assert!(readiness.is_ready());
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT count(*) FROM pubsub_subscriptions WHERE expire<NOW()"
            )
            .fetch_one(&pool)
            .await
            .unwrap(),
            1
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT count(*) FROM pubsub_subscriptions WHERE expire IS NULL OR expire>NOW()"
            )
            .fetch_one(&pool)
            .await
            .unwrap(),
            2
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT count(*) FROM pubsub_digest_queue WHERE source_delivery_id IS NULL"
            )
            .fetch_one(&pool)
            .await
            .unwrap(),
            0
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT count(*) FROM pubsub_digest_queue WHERE source_delivery_id IS NOT NULL"
            )
            .fetch_one(&pool)
            .await
            .unwrap(),
            1,
            "committed event snapshots survive physical subscription removal"
        );
        let second = run_once_with(
            &context.readiness,
            &context.metrics,
            &cancel,
            Instant::now() + CLEANUP_BUDGET,
            || db::cleanup_expired_subscriptions(&context.pool, CLEANUP_BATCH_SIZE),
        )
        .await
        .unwrap();
        assert_eq!(second, Some(1));
        assert_eq!(context.metrics.deleted_total.load(Ordering::Relaxed), 1_001);
        // A prior successful cleanup cannot conceal a later repository error.
        sqlx::query("DROP TABLE pubsub_digest_queue")
            .execute(&pool)
            .await
            .unwrap();
        let failure = run_once_with(
            &context.readiness,
            &context.metrics,
            &cancel,
            Instant::now() + CLEANUP_BUDGET,
            || db::cleanup_expired_subscriptions(&context.pool, CLEANUP_BATCH_SIZE),
        )
        .await;
        assert!(failure.is_err());
        assert!(!readiness.is_ready());
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT count(*) FROM pubsub_subscriptions")
                .fetch_one(&pool)
                .await
                .unwrap(),
            2
        );
        pool.close().await;
    }
}
