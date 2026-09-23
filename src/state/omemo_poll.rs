//! Bounded public completion polling, independent of account session authority.
use super::{admit_bounded_omemo_poll_ip, OMEMO_POLL_CONCURRENCY, OMEMO_POLL_MAX_ACTIVE_IPS};
use crate::{
    metrics::Metrics,
    services::omemo_recovery::{
        OmemoRecoveryPollRepository, OmemoRecoveryPollService, OmemoRecoveryPollStatus,
    },
};
use dashmap::DashMap;
use std::{
    collections::VecDeque,
    net::IpAddr,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::Instant,
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use uuid::Uuid;

#[derive(Clone)]
pub(crate) struct OmemoRecoveryPollContext<R> {
    inner: Arc<OmemoRecoveryPollRuntime<R>>,
}

struct OmemoRecoveryPollRuntime<R> {
    service: OmemoRecoveryPollService<R>,
    domain: String,
    trusted_proxies: Vec<IpAddr>,
    counters: OmemoRecoveryPollCounters,
    requests: Arc<Semaphore>,
    requests_by_ip: DashMap<IpAddr, VecDeque<Instant>>,
    ip_admission: Mutex<()>,
    request_checks: AtomicU64,
}

#[derive(Clone)]
pub(crate) struct OmemoRecoveryPollCounters {
    requests: Arc<AtomicU64>,
    not_found: Arc<AtomicU64>,
    rate_limited: Arc<AtomicU64>,
    concurrency_rejected: Arc<AtomicU64>,
}

impl OmemoRecoveryPollCounters {
    pub(crate) fn from_metrics(metrics: &Metrics) -> Self {
        Self {
            requests: Arc::clone(&metrics.omemo_recovery_poll_requests_total),
            not_found: Arc::clone(&metrics.omemo_recovery_poll_not_found_total),
            rate_limited: Arc::clone(&metrics.omemo_recovery_poll_rate_limited_total),
            concurrency_rejected: Arc::clone(
                &metrics.omemo_recovery_poll_concurrency_rejected_total,
            ),
        }
    }
}

impl<R: OmemoRecoveryPollRepository> OmemoRecoveryPollContext<R> {
    pub(super) fn new(
        service: OmemoRecoveryPollService<R>,
        domain: String,
        trusted_proxies: Vec<IpAddr>,
        counters: OmemoRecoveryPollCounters,
    ) -> Self {
        Self {
            inner: Arc::new(OmemoRecoveryPollRuntime {
                service,
                domain,
                trusted_proxies,
                counters,
                requests: Arc::new(Semaphore::new(OMEMO_POLL_CONCURRENCY)),
                requests_by_ip: DashMap::new(),
                ip_admission: Mutex::new(()),
                request_checks: AtomicU64::new(0),
            }),
        }
    }
    pub(crate) fn trusted_proxies(&self) -> &[IpAddr] {
        &self.inner.trusted_proxies
    }
    pub(crate) fn record_request(&self) {
        self.inner.counters.requests.fetch_add(1, Ordering::Relaxed);
    }
    pub(crate) fn record_not_found(&self) {
        self.inner
            .counters
            .not_found
            .fetch_add(1, Ordering::Relaxed);
    }
    pub(crate) async fn poll(
        &self,
        transfer_id: Uuid,
        secret: &[u8; 32],
    ) -> anyhow::Result<Option<OmemoRecoveryPollStatus>> {
        self.inner
            .service
            .poll(&self.inner.domain, transfer_id, secret)
            .await
    }
    pub(crate) fn acquire(&self, ip: std::net::IpAddr) -> Option<OwnedSemaphorePermit> {
        let now = Instant::now();
        let check = self.inner.request_checks.fetch_add(1, Ordering::Relaxed);
        if !admit_bounded_omemo_poll_ip(
            &self.inner.requests_by_ip,
            &self.inner.ip_admission,
            ip,
            now,
            check.is_multiple_of(256),
            OMEMO_POLL_MAX_ACTIVE_IPS,
        ) {
            self.inner
                .counters
                .rate_limited
                .fetch_add(1, Ordering::Relaxed);
            return None;
        }
        match Arc::clone(&self.inner.requests).try_acquire_owned() {
            Ok(permit) => Some(permit),
            Err(_) => {
                self.inner
                    .counters
                    .concurrency_rejected
                    .fetch_add(1, Ordering::Relaxed);
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone)]
    struct UnusedRepository;
    impl OmemoRecoveryPollRepository for UnusedRepository {
        async fn poll(
            &self,
            _: &str,
            _: Uuid,
            _: &[u8; 32],
        ) -> anyhow::Result<Option<OmemoRecoveryPollStatus>> {
            panic!("admission must not call persistence");
        }
    }

    #[test]
    fn extracted_contexts_share_concurrency_and_ip_windows() {
        let metrics = Arc::new(Metrics::default());
        let context = OmemoRecoveryPollContext::new(
            OmemoRecoveryPollService::new(UnusedRepository),
            "localhost".into(),
            Vec::new(),
            OmemoRecoveryPollCounters::from_metrics(&metrics),
        );
        let extracted = context.clone();
        let mut permits = Vec::new();
        for octet in 1..=OMEMO_POLL_CONCURRENCY as u8 {
            permits.push(context.acquire(IpAddr::from([192, 0, 2, octet])).unwrap());
        }
        let caller = IpAddr::from([198, 51, 100, 1]);
        assert!(extracted.acquire(caller).is_none());
        drop(permits.pop());
        assert!(extracted.acquire(caller).is_some());
        drop(permits);
        let caller = IpAddr::from([198, 51, 100, 2]);
        for index in 0..super::super::OMEMO_POLL_IP_REQUESTS_PER_MINUTE {
            let active = if index % 2 == 0 { &context } else { &extracted };
            assert!(active.acquire(caller).is_some());
        }
        assert!(extracted.acquire(caller).is_none());
        assert_eq!(
            metrics
                .omemo_recovery_poll_concurrency_rejected_total
                .load(Ordering::Relaxed),
            1
        );
        assert_eq!(
            metrics
                .omemo_recovery_poll_rate_limited_total
                .load(Ordering::Relaxed),
            1
        );
    }
}
