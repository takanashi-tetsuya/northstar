//! Ordered once-per-minute maintenance with only its cleanup capabilities.

use crate::background_housekeeping::BackgroundHousekeepingCounters;
use anyhow::Result;
use northstar_runtime::workers::WorkerHeartbeat;
use std::{future::Future, sync::Arc, time::Duration};
use tokio_util::sync::CancellationToken;

/// The cleanup capabilities of the once-per-minute maintenance pass, in the order it runs them.
pub trait BackgroundMaintenancePorts: Send + Sync {
    fn cleanup_challenges(&self) -> impl Future<Output = Result<()>> + Send;
    fn sweep_database(&self) -> impl Future<Output = ()> + Send;
    fn cleanup_admin_sessions(&self) -> impl Future<Output = Result<u64>> + Send;
    fn cleanup_expired_sm(&self) -> impl Future<Output = Result<usize>> + Send;
    fn sweep_caps_cache(&self, now: std::time::Instant);
    fn maintenance_counters(&self) -> &BackgroundHousekeepingCounters;
}

pub async fn serve_background_maintenance(
    ports: Arc<impl BackgroundMaintenancePorts>,
    cancel: CancellationToken,
    heartbeat: WorkerHeartbeat,
) -> Result<()> {
    let mut interval = tokio::time::interval(Duration::from_secs(60));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            _ = cancel.cancelled() => return Ok(()),
            _ = interval.tick() => {
                let failures_before = ports.maintenance_counters().failures_total();
                if let Err(error) = ports.cleanup_challenges().await {
                    tracing::warn!(?error, "anti-abuse cleanup failed");
                    ports.maintenance_counters().record_failure();
                }
                ports.sweep_database().await;
                if let Err(error) = ports.cleanup_admin_sessions().await {
                    tracing::error!("failed to cleanup expired admin command sessions: {error}");
                    ports.maintenance_counters().record_failure();
                }
                match ports.cleanup_expired_sm().await {
                    Ok(expired) if expired > 0 => {
                        tracing::info!(expired, "tore down expired SM resume sessions");
                    }
                    Ok(_) => {}
                    Err(error) => {
                        tracing::error!("failed to cleanup expired SM resume sessions: {error}");
                        ports.maintenance_counters().record_failure();
                    }
                }
                ports.sweep_caps_cache(std::time::Instant::now());
                if ports.maintenance_counters().failures_total() == failures_before {
                    heartbeat.ok();
                } else {
                    heartbeat.error("one or more background maintenance operations failed");
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use northstar_runtime::workers::{WorkerCriticality, WorkerMode, WorkerRegistry};
    use std::{
        collections::BTreeSet,
        pin::Pin,
        sync::{atomic::AtomicU64, Mutex},
        task::Poll,
    };

    const CLEANUP_ORDER: [&str; 5] = ["challenges", "database", "admin", "sm", "caps"];

    struct RecordingPorts {
        calls: Mutex<Vec<&'static str>>,
        failures: BTreeSet<&'static str>,
        counters: BackgroundHousekeepingCounters,
    }

    impl RecordingPorts {
        fn new(failures: BTreeSet<&'static str>) -> Self {
            Self {
                calls: Mutex::new(Vec::new()),
                failures,
                counters: BackgroundHousekeepingCounters::new(
                    Arc::new(AtomicU64::new(0)),
                    Arc::new(AtomicU64::new(0)),
                ),
            }
        }

        fn record(&self, step: &'static str) -> Result<()> {
            self.calls.lock().unwrap().push(step);
            if self.failures.contains(step) {
                anyhow::bail!("{step} failed");
            }
            Ok(())
        }
    }

    impl BackgroundMaintenancePorts for RecordingPorts {
        async fn cleanup_challenges(&self) -> Result<()> {
            self.record("challenges")
        }

        async fn sweep_database(&self) {
            if self.record("database").is_err() {
                self.counters.record_failure();
            }
        }

        async fn cleanup_admin_sessions(&self) -> Result<u64> {
            self.record("admin")?;
            Ok(1)
        }

        async fn cleanup_expired_sm(&self) -> Result<usize> {
            self.record("sm")?;
            Ok(2)
        }

        fn sweep_caps_cache(&self, now: std::time::Instant) {
            assert!(now <= std::time::Instant::now());
            self.record("caps").unwrap();
        }

        fn maintenance_counters(&self) -> &BackgroundHousekeepingCounters {
            &self.counters
        }
    }

    async fn worker_heartbeat() -> (Arc<WorkerRegistry>, CancellationToken, WorkerHeartbeat) {
        let registry = WorkerRegistry::new();
        let cancel = CancellationToken::new();
        let (sender, mut receiver) = tokio::sync::mpsc::unbounded_channel();
        registry.supervise(
            "test-maintenance-heartbeat",
            WorkerCriticality::Critical,
            WorkerMode::Continuous,
            None,
            cancel.clone(),
            move |heartbeat| {
                assert!(sender.send(heartbeat).is_ok());
                std::future::pending::<Result<()>>()
            },
        );
        let heartbeat = receiver.recv().await.unwrap();
        (registry, cancel, heartbeat)
    }

    async fn poll_worker(
        mut worker: Pin<&mut impl Future<Output = Result<()>>>,
    ) -> Poll<Result<()>> {
        std::future::poll_fn(|cx| Poll::Ready(worker.as_mut().poll(cx))).await
    }

    #[tokio::test(start_paused = true)]
    async fn maintenance_runs_every_cleanup_in_order_and_reports_ok() {
        let (registry, registry_cancel, heartbeat) = worker_heartbeat().await;
        let ports = Arc::new(RecordingPorts::new(BTreeSet::new()));
        let cancel = CancellationToken::new();
        heartbeat.error("prior failure");
        heartbeat.error("prior failure");
        let worker =
            serve_background_maintenance(Arc::clone(&ports), cancel.clone(), heartbeat.clone());
        tokio::pin!(worker);
        assert!(poll_worker(worker.as_mut()).await.is_pending());
        assert_eq!(*ports.calls.lock().unwrap(), CLEANUP_ORDER);
        assert_eq!(ports.counters.failures_total(), 0);
        heartbeat.error("health check");
        assert!(registry.readiness_error().is_none());

        ports.calls.lock().unwrap().clear();
        tokio::time::advance(Duration::from_secs(59)).await;
        assert!(poll_worker(worker.as_mut()).await.is_pending());
        assert!(ports.calls.lock().unwrap().is_empty());
        tokio::time::advance(Duration::from_secs(1)).await;
        assert!(poll_worker(worker.as_mut()).await.is_pending());
        assert_eq!(*ports.calls.lock().unwrap(), CLEANUP_ORDER);
        heartbeat.error("health check");
        heartbeat.error("health check");
        assert!(registry.readiness_error().is_none());

        cancel.cancel();
        worker.await.unwrap();
        assert!(registry
            .shutdown_and_join(&registry_cancel, Duration::from_secs(1))
            .await
            .is_clean());
    }

    #[tokio::test(start_paused = true)]
    async fn maintenance_failure_is_counted_and_reported_but_later_cleanups_still_run() {
        for failures in [
            BTreeSet::from(["challenges"]),
            BTreeSet::from(["database"]),
            BTreeSet::from(["admin"]),
            BTreeSet::from(["sm"]),
            BTreeSet::from(["challenges", "database", "admin", "sm"]),
        ] {
            let (registry, registry_cancel, heartbeat) = worker_heartbeat().await;
            let failure_count = failures.len() as u64;
            let ports = Arc::new(RecordingPorts::new(failures));
            let cancel = CancellationToken::new();
            heartbeat.error("prior failure");
            heartbeat.error("prior failure");
            let worker =
                serve_background_maintenance(Arc::clone(&ports), cancel.clone(), heartbeat);
            tokio::pin!(worker);
            assert!(poll_worker(worker.as_mut()).await.is_pending());
            assert_eq!(*ports.calls.lock().unwrap(), CLEANUP_ORDER);
            assert_eq!(ports.counters.failures_total(), failure_count);
            assert!(registry
                .readiness_error()
                .unwrap()
                .contains("one or more background maintenance operations failed"));
            cancel.cancel();
            worker.await.unwrap();
            assert!(registry
                .shutdown_and_join(&registry_cancel, Duration::from_secs(1))
                .await
                .is_clean());
        }
    }

    #[tokio::test(start_paused = true)]
    async fn maintenance_cancel_returns_ok() {
        let (registry, registry_cancel, heartbeat) = worker_heartbeat().await;
        let ports = Arc::new(RecordingPorts::new(BTreeSet::new()));
        let cancel = CancellationToken::new();
        let worker = serve_background_maintenance(Arc::clone(&ports), cancel.clone(), heartbeat);
        tokio::pin!(worker);
        assert!(poll_worker(worker.as_mut()).await.is_pending());
        assert_eq!(*ports.calls.lock().unwrap(), CLEANUP_ORDER);
        ports.calls.lock().unwrap().clear();
        cancel.cancel();
        worker.await.unwrap();
        assert!(ports.calls.lock().unwrap().is_empty());
        assert!(registry
            .shutdown_and_join(&registry_cancel, Duration::from_secs(1))
            .await
            .is_clean());
    }
}
