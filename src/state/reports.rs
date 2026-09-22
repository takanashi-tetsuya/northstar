//! Identity lookup and submission capabilities for report and appeal handlers.
use crate::{
    metrics::Metrics,
    services::{
        api_queries::{ApiPrincipal, ApiQueryRepository, ApiQueryService},
        reports::{ReportEffect, ReportRepository, ReportService},
    },
};
use std::{
    net::IpAddr,
    sync::{atomic::Ordering, Arc},
};

#[derive(Clone)]
pub(crate) struct ReportContext<R, Q> {
    reports: ReportService<R>,
    queries: ApiQueryService<Q>,
    metrics: Arc<Metrics>,
    trusted_proxies: Vec<IpAddr>,
}

impl<R: ReportRepository, Q: ApiQueryRepository> ReportContext<R, Q> {
    pub(super) fn new(
        reports: ReportService<R>,
        queries: ApiQueryService<Q>,
        metrics: Arc<Metrics>,
        trusted_proxies: Vec<IpAddr>,
    ) -> Self {
        Self {
            reports,
            queries,
            metrics,
            trusted_proxies,
        }
    }

    pub(crate) fn report_service(&self) -> &ReportService<R> {
        &self.reports
    }

    pub(crate) fn trusted_proxies(&self) -> &[IpAddr] {
        &self.trusted_proxies
    }

    pub(crate) async fn principal(&self, token: &str) -> anyhow::Result<Option<ApiPrincipal>> {
        let _authentication = self.metrics.authentication_duration_seconds.start_timer();
        let _database = self
            .metrics
            .database_operation_duration_seconds
            .start_timer();
        self.queries.principal(token).await
    }

    pub(crate) fn record_commit(&self, effect: ReportEffect) {
        let counter = match effect {
            ReportEffect::ReportCreated => Some(&self.metrics.reports_total),
            ReportEffect::AppealCreated => Some(&self.metrics.appeals_total),
            ReportEffect::RateLimited => Some(&self.metrics.rate_limited_total),
            ReportEffect::None => None,
        };
        if let Some(counter) = counter {
            counter.fetch_add(1, Ordering::Relaxed);
        }
    }
}
